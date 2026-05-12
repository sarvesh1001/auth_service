package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
	"auth-service/internal/inventory/events"
	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models"
	"auth-service/internal/inventory/repository"
)

// allowedWarehouseTypes defines the valid values for warehouse_type.
var allowedWarehouseTypes = map[string]bool{
	"finished_goods": true,
	"raw_material":   true,
	"distribution":   true,
	// Add any other valid types your domain uses.
}

type WarehouseService interface {
	CreateWarehouse(ctx context.Context, req CreateWarehouseRequest, idempotencyKey string) (*models.Warehouse, error)
	BulkCreateWarehouses(ctx context.Context, reqs []CreateWarehouseRequest, idempotencyKey string) ([]*models.Warehouse, error)
	GetWarehouseByID(ctx context.Context, companyID, warehouseID uuid.UUID) (*models.Warehouse, error)
	GetWarehouseByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.Warehouse, error)
	ListWarehouses(ctx context.Context, filter repository.WarehouseFilter, page, pageSize int) ([]*models.Warehouse, int64, error)
	UpdateWarehouse(ctx context.Context, req UpdateWarehouseRequest, idempotencyKey string) (*models.Warehouse, error)
	DeleteWarehouse(ctx context.Context, companyID, warehouseID uuid.UUID, deletedBy *uuid.UUID, idempotencyKey string) error
	SetWarehouseStatus(ctx context.Context, companyID, warehouseID uuid.UUID, isActive bool, updatedBy *uuid.UUID, idempotencyKey string) error
}

// CreateWarehouseRequest includes the new fields for location hierarchy, warehouse type, and negative stock allowance
type CreateWarehouseRequest struct {
	CompanyID          uuid.UUID
	Code               string
	Name               string
	Location           *string
	IsActive           bool
	CreatedBy          *uuid.UUID
	LocationID         *uuid.UUID // FK to inventory_locations
	WarehouseType      *string    // e.g., 'finished_goods', 'raw_material', 'distribution'
	AllowNegativeStock bool       // override item-level negative stock setting
}

// UpdateWarehouseRequest includes the new fields
type UpdateWarehouseRequest struct {
	WarehouseID        uuid.UUID
	CompanyID          uuid.UUID
	Code               *string
	Name               *string
	Location           *string
	IsActive           *bool
	UpdatedBy          *uuid.UUID
	LocationID         *uuid.UUID
	WarehouseType      *string
	AllowNegativeStock *bool
}

type warehouseService struct {
	warehouseRepo    repository.WarehouseRepository
	locationRepo     repository.InventoryLocationRepository // added for validation
	pgClient         *client.PostgresClient
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	logger           *zap.Logger
}

func NewWarehouseService(
	warehouseRepo repository.WarehouseRepository,
	locationRepo repository.InventoryLocationRepository,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) WarehouseService {
	return &warehouseService{
		warehouseRepo:    warehouseRepo,
		locationRepo:     locationRepo,
		pgClient:         pgClient,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		logger:           logger.Named("warehouse_service"),
	}
}

// validateCreateWarehouse now includes warehouse_type validation.
func (s *warehouseService) validateCreateWarehouse(req CreateWarehouseRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", inventory_errors.ErrInvalidInput)
	}
	if req.Code == "" {
		return fmt.Errorf("%w: code required", inventory_errors.ErrInvalidInput)
	}
	if req.Name == "" {
		return fmt.Errorf("%w: name required", inventory_errors.ErrInvalidInput)
	}
	if req.WarehouseType != nil && *req.WarehouseType != "" {
		if !allowedWarehouseTypes[*req.WarehouseType] {
			return fmt.Errorf("%w: warehouse_type must be one of: finished_goods, raw_material, distribution",
				inventory_errors.ErrInvalidInput)
		}
	}
	return nil
}

// CreateWarehouse validates LocationID if provided and stores new fields.
func (s *warehouseService) CreateWarehouse(ctx context.Context, req CreateWarehouseRequest, idempotencyKey string) (*models.Warehouse, error) {
	logger := s.logger.With(zap.String("method", "CreateWarehouse"), zap.String("idempotency_key", idempotencyKey))

	if err := s.validateCreateWarehouse(req); err != nil {
		return nil, err
	}

	// Validate location if provided
	if req.LocationID != nil {
		if _, err := s.locationRepo.GetByID(ctx, s.pgClient.DB, *req.LocationID); err != nil {
			return nil, fmt.Errorf("invalid location_id: %w", err)
		}
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *models.Warehouse
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent request – returning cached warehouse")
		return cached, nil
	}

	exists, err := s.warehouseRepo.CodeExists(ctx, tx, req.CompanyID, req.Code, nil)
	if err != nil {
		return nil, fmt.Errorf("check code exists: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("%w: warehouse code %s already exists", inventory_errors.ErrDuplicate, req.Code)
	}

	warehouse := &models.Warehouse{
		WarehouseID:        uuid.New(),
		CompanyID:          req.CompanyID,
		Code:               req.Code,
		Name:               req.Name,
		Location:           req.Location,
		IsActive:           req.IsActive,
		CreatedBy:          req.CreatedBy,
		UpdatedBy:          req.CreatedBy,
		LocationID:         req.LocationID,
		WarehouseType:      req.WarehouseType,
		AllowNegativeStock: req.AllowNegativeStock,
	}

	if err := s.warehouseRepo.Create(ctx, tx, warehouse); err != nil {
		return nil, fmt.Errorf("create warehouse: %w", err)
	}

	if err := s.emitWarehouseEvent(ctx, tx, warehouse, events.EventWarehouseCreated); err != nil {
		logger.Warn("failed to emit warehouse created event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, warehouse)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "create_warehouse", "warehouse",
			&warehouse.WarehouseID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"code": warehouse.Code,
			})
	}

	logger.Info("warehouse created", zap.String("warehouse_id", warehouse.WarehouseID.String()))
	return warehouse, nil
}

// BulkCreateWarehouses now also validates warehouse_type for each request.
func (s *warehouseService) BulkCreateWarehouses(ctx context.Context, reqs []CreateWarehouseRequest, idempotencyKey string) ([]*models.Warehouse, error) {
	logger := s.logger.With(zap.String("method", "BulkCreateWarehouses"), zap.String("idempotency_key", idempotencyKey))
	if len(reqs) == 0 {
		return nil, fmt.Errorf("%w: no warehouses provided", inventory_errors.ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached []*models.Warehouse
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached warehouses")
		return cached, nil
	}

	warehouses := make([]*models.Warehouse, 0, len(reqs))
	for _, req := range reqs {
		if err := s.validateCreateWarehouse(req); err != nil {
			return nil, err
		}
		if req.LocationID != nil {
			if _, err := s.locationRepo.GetByID(ctx, tx, *req.LocationID); err != nil {
				return nil, fmt.Errorf("invalid location_id for warehouse %s: %w", req.Code, err)
			}
		}
		exists, err := s.warehouseRepo.CodeExists(ctx, tx, req.CompanyID, req.Code, nil)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, fmt.Errorf("%w: warehouse code %s already exists", inventory_errors.ErrDuplicate, req.Code)
		}
		wh := &models.Warehouse{
			WarehouseID:        uuid.New(),
			CompanyID:          req.CompanyID,
			Code:               req.Code,
			Name:               req.Name,
			Location:           req.Location,
			IsActive:           req.IsActive,
			CreatedBy:          req.CreatedBy,
			UpdatedBy:          req.CreatedBy,
			LocationID:         req.LocationID,
			WarehouseType:      req.WarehouseType,
			AllowNegativeStock: req.AllowNegativeStock,
		}
		warehouses = append(warehouses, wh)
	}

	if err := s.warehouseRepo.BulkCreate(ctx, tx, warehouses); err != nil {
		return nil, fmt.Errorf("bulk create warehouses: %w", err)
	}

	for _, wh := range warehouses {
		_ = s.emitWarehouseEvent(ctx, tx, wh, events.EventWarehouseCreated)
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, warehouses)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		for _, wh := range warehouses {
			_ = s.auditService.LogAction(ctx, nil, &wh.CompanyID, "inventory", "bulk_create_warehouse", "warehouse",
				&wh.WarehouseID, "user", wh.CreatedBy, nil, nil, map[string]interface{}{
					"code": wh.Code,
				})
		}
	}
	return warehouses, nil
}

// GetWarehouseByID, GetWarehouseByCode, ListWarehouses remain unchanged.
func (s *warehouseService) GetWarehouseByID(ctx context.Context, companyID, warehouseID uuid.UUID) (*models.Warehouse, error) {
	if companyID == uuid.Nil || warehouseID == uuid.Nil {
		return nil, inventory_errors.ErrInvalidInput
	}
	return s.warehouseRepo.GetByID(ctx, s.pgClient.DB, companyID, warehouseID)
}

func (s *warehouseService) GetWarehouseByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.Warehouse, error) {
	if companyID == uuid.Nil || code == "" {
		return nil, inventory_errors.ErrInvalidInput
	}
	return s.warehouseRepo.GetByCode(ctx, s.pgClient.DB, companyID, code)
}

func (s *warehouseService) ListWarehouses(ctx context.Context, filter repository.WarehouseFilter, page, pageSize int) ([]*models.Warehouse, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	pagination := repository.Pagination{
		Limit:  pageSize,
		Offset: (page - 1) * pageSize,
	}
	sort := repository.Sort{Field: "name", Direction: "ASC"}
	warehouses, err := s.warehouseRepo.List(ctx, s.pgClient.DB, filter, pagination, sort)
	if err != nil {
		return nil, 0, err
	}
	total, err := s.warehouseRepo.Count(ctx, s.pgClient.DB, filter)
	if err != nil {
		return nil, 0, err
	}
	return warehouses, total, nil
}

// UpdateWarehouse now validates warehouse_type when changed.
func (s *warehouseService) UpdateWarehouse(ctx context.Context, req UpdateWarehouseRequest, idempotencyKey string) (*models.Warehouse, error) {
	logger := s.logger.With(zap.String("method", "UpdateWarehouse"), zap.String("idempotency_key", idempotencyKey))

	if req.WarehouseID == uuid.Nil || req.CompanyID == uuid.Nil {
		return nil, inventory_errors.ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *models.Warehouse
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached warehouse")
		return cached, nil
	}

	warehouse, err := s.warehouseRepo.GetByID(ctx, tx, req.CompanyID, req.WarehouseID)
	if err != nil {
		return nil, err
	}

	// Validate new location if provided
	if req.LocationID != nil {
		if _, err := s.locationRepo.GetByID(ctx, tx, *req.LocationID); err != nil {
			return nil, fmt.Errorf("invalid location_id: %w", err)
		}
	}

	// Check code uniqueness if changed
	if req.Code != nil && *req.Code != warehouse.Code {
		exists, err := s.warehouseRepo.CodeExists(ctx, tx, req.CompanyID, *req.Code, &req.WarehouseID)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, fmt.Errorf("%w: warehouse code %s already exists", inventory_errors.ErrDuplicate, *req.Code)
		}
	}

	// Validate warehouse_type if provided
	if req.WarehouseType != nil && *req.WarehouseType != "" {
		if !allowedWarehouseTypes[*req.WarehouseType] {
			return nil, fmt.Errorf("%w: warehouse_type must be one of: finished_goods, raw_material, distribution",
				inventory_errors.ErrInvalidInput)
		}
	}

	if req.Code != nil {
		warehouse.Code = *req.Code
	}
	if req.Name != nil {
		warehouse.Name = *req.Name
	}
	if req.Location != nil {
		warehouse.Location = req.Location
	}
	if req.IsActive != nil {
		warehouse.IsActive = *req.IsActive
	}
	if req.LocationID != nil {
		warehouse.LocationID = req.LocationID
	}
	if req.WarehouseType != nil {
		warehouse.WarehouseType = req.WarehouseType
	}
	if req.AllowNegativeStock != nil {
		warehouse.AllowNegativeStock = *req.AllowNegativeStock
	}
	warehouse.UpdatedBy = req.UpdatedBy

	if err := s.warehouseRepo.Update(ctx, tx, warehouse); err != nil {
		return nil, fmt.Errorf("update warehouse: %w", err)
	}

	if err := s.emitWarehouseEvent(ctx, tx, warehouse, events.EventWarehouseUpdated); err != nil {
		logger.Warn("failed to emit warehouse updated event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, warehouse)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "update_warehouse", "warehouse",
			&req.WarehouseID, "user", req.UpdatedBy, nil, nil, nil)
	}
	return warehouse, nil
}

func (s *warehouseService) DeleteWarehouse(ctx context.Context, companyID, warehouseID uuid.UUID, deletedBy *uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "DeleteWarehouse"), zap.String("idempotency_key", idempotencyKey))

	if companyID == uuid.Nil || warehouseID == uuid.Nil {
		return inventory_errors.ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – already deleted")
		return nil
	}

	_, err = s.warehouseRepo.GetByID(ctx, tx, companyID, warehouseID)
	if err != nil {
		return err
	}

	if err := s.warehouseRepo.SoftDelete(ctx, tx, companyID, warehouseID); err != nil {
		return fmt.Errorf("soft delete warehouse: %w", err)
	}

	if err := s.emitWarehouseEvent(ctx, tx, &models.Warehouse{WarehouseID: warehouseID, CompanyID: companyID}, events.EventWarehouseDeleted); err != nil {
		logger.Warn("failed to emit warehouse deleted event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "inventory", "delete_warehouse", "warehouse",
			&warehouseID, "user", deletedBy, nil, nil, nil)
	}
	return nil
}

func (s *warehouseService) SetWarehouseStatus(ctx context.Context, companyID, warehouseID uuid.UUID, isActive bool, updatedBy *uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "SetWarehouseStatus"), zap.String("idempotency_key", idempotencyKey))

	if companyID == uuid.Nil || warehouseID == uuid.Nil {
		return inventory_errors.ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – already processed")
		return nil
	}

	wh, err := s.warehouseRepo.GetByID(ctx, tx, companyID, warehouseID)
	if err != nil {
		return err
	}

	wh.IsActive = isActive
	wh.UpdatedBy = updatedBy

	if err := s.warehouseRepo.Update(ctx, tx, wh); err != nil {
		return fmt.Errorf("update warehouse status: %w", err)
	}

	if err := s.emitWarehouseEvent(ctx, tx, wh, events.EventWarehouseUpdated); err != nil {
		logger.Warn("failed to emit status change event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "inventory", "set_warehouse_status", "warehouse",
			&warehouseID, "user", updatedBy, nil, nil, map[string]interface{}{
				"is_active": isActive,
			})
	}
	return nil
}

// emitWarehouseEvent remains unchanged.
func (s *warehouseService) emitWarehouseEvent(ctx context.Context, tx *sql.Tx, warehouse *models.Warehouse, eventType string) error {
	payload := map[string]interface{}{
		"warehouse_id":         warehouse.WarehouseID.String(),
		"company_id":           warehouse.CompanyID.String(),
		"code":                 warehouse.Code,
		"name":                 warehouse.Name,
		"is_active":            warehouse.IsActive,
		"allow_negative_stock": warehouse.AllowNegativeStock,
	}
	if warehouse.Location != nil {
		payload["location"] = *warehouse.Location
	}
	if warehouse.LocationID != nil {
		payload["location_id"] = warehouse.LocationID.String()
	}
	if warehouse.WarehouseType != nil {
		payload["warehouse_type"] = *warehouse.WarehouseType
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "warehouse",
		AggregateID:   warehouse.WarehouseID.String(),
		EventType:     eventType,
		Topic:         events.TopicInventoryEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}
