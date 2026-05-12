package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

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

// InventoryLocationService manages warehouse location hierarchy.
type InventoryLocationService interface {
	CreateLocation(ctx context.Context, req CreateLocationRequest, idempotencyKey string) (*models.InventoryLocation, error)
	UpdateLocation(ctx context.Context, req UpdateLocationRequest, idempotencyKey string) (*models.InventoryLocation, error)
	DeleteLocation(ctx context.Context, companyID, locationID uuid.UUID, deletedBy *uuid.UUID, idempotencyKey string) error
	GetLocationTree(ctx context.Context, companyID uuid.UUID) ([]*LocationNode, error)
	GetLocationByID(ctx context.Context, companyID, locationID uuid.UUID) (*models.InventoryLocation, error)
	ListLocations(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.InventoryLocation, error)
	AssignWarehouseToLocation(ctx context.Context, req AssignWarehouseRequest, idempotencyKey string) error
}

// CreateLocationRequest defines input for creating a location.
type CreateLocationRequest struct {
	CompanyID        uuid.UUID
	Code             string
	Name             string
	LocationType     *string
	ParentLocationID *uuid.UUID
	CreatedBy        *uuid.UUID
}

// UpdateLocationRequest defines input for updating a location.
type UpdateLocationRequest struct {
	LocationID       uuid.UUID
	CompanyID        uuid.UUID
	Code             *string
	Name             *string
	LocationType     *string
	ParentLocationID *uuid.UUID // nil means no change; empty uuid means set to NULL
	IsActive         *bool
	UpdatedBy        *uuid.UUID
}

// AssignWarehouseRequest assigns a warehouse to a location.
type AssignWarehouseRequest struct {
	CompanyID   uuid.UUID
	WarehouseID uuid.UUID
	LocationID  uuid.UUID
	UpdatedBy   *uuid.UUID
}

// LocationNode represents a location with its children for tree view.
type LocationNode struct {
	models.InventoryLocation
	Children []*LocationNode `json:"children,omitempty"`
}

type inventoryLocationService struct {
	locationRepo     repository.InventoryLocationRepository
	warehouseRepo    repository.WarehouseRepository
	pgClient         *client.PostgresClient
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	logger           *zap.Logger
}

// NewInventoryLocationService creates a new instance.
func NewInventoryLocationService(
	locationRepo repository.InventoryLocationRepository,
	warehouseRepo repository.WarehouseRepository,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) InventoryLocationService {
	return &inventoryLocationService{
		locationRepo:     locationRepo,
		warehouseRepo:    warehouseRepo,
		pgClient:         pgClient,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		logger:           logger.Named("inventory_location_service"),
	}
}

// CreateLocation creates a new inventory location.
func (s *inventoryLocationService) CreateLocation(ctx context.Context, req CreateLocationRequest, idempotencyKey string) (*models.InventoryLocation, error) {
	logger := s.logger.With(zap.String("method", "CreateLocation"), zap.String("idempotency_key", idempotencyKey))

	if err := validateCreateLocation(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check
	var cached *models.InventoryLocation
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent request – returning cached location")
		return cached, nil
	}

	// Check code uniqueness
	exists, err := s.locationRepo.ExistsByCode(ctx, tx, req.CompanyID, req.Code, nil)
	if err != nil {
		return nil, fmt.Errorf("check code exists: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("%w: location code %s already exists", inventory_errors.ErrDuplicate, req.Code)
	}

	// Validate parent exists if provided
	if req.ParentLocationID != nil {
		parent, err := s.locationRepo.GetByID(ctx, tx, *req.ParentLocationID)
		if err != nil {
			return nil, fmt.Errorf("parent location not found: %w", err)
		}
		if parent.CompanyID != req.CompanyID {
			return nil, inventory_errors.ErrPermissionDenied
		}
	}

	location := &models.InventoryLocation{
		LocationID:       uuid.New(),
		CompanyID:        req.CompanyID,
		Code:             req.Code,
		Name:             req.Name,
		LocationType:     req.LocationType,
		ParentLocationID: req.ParentLocationID,
		IsActive:         true,
		CreatedAt:        time.Now(),
	}

	if err := s.locationRepo.Create(ctx, tx, location); err != nil {
		return nil, fmt.Errorf("create location: %w", err)
	}

	// Emit event
	if err := s.emitLocationEvent(ctx, tx, location, events.EventLocationCreated); err != nil {
		logger.Warn("failed to emit location created event", zap.Error(err))
	}

	// Store idempotency
	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, location)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "create_location", "inventory_location",
			&location.LocationID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"code": location.Code,
				"name": location.Name,
			})
	}

	logger.Info("location created", zap.String("location_id", location.LocationID.String()))
	return location, nil
}

// UpdateLocation updates an existing inventory location.
func (s *inventoryLocationService) UpdateLocation(ctx context.Context, req UpdateLocationRequest, idempotencyKey string) (*models.InventoryLocation, error) {
	logger := s.logger.With(zap.String("method", "UpdateLocation"), zap.String("idempotency_key", idempotencyKey))

	if req.LocationID == uuid.Nil || req.CompanyID == uuid.Nil {
		return nil, inventory_errors.ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *models.InventoryLocation
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached location")
		return cached, nil
	}

	location, err := s.locationRepo.GetByID(ctx, tx, req.LocationID)
	if err != nil {
		return nil, err
	}
	if location.CompanyID != req.CompanyID {
		return nil, inventory_errors.ErrPermissionDenied
	}

	// Check code uniqueness if code is being changed
	if req.Code != nil && *req.Code != location.Code {
		exists, err := s.locationRepo.ExistsByCode(ctx, tx, req.CompanyID, *req.Code, &req.LocationID)
		if err != nil {
			return nil, fmt.Errorf("check code exists: %w", err)
		}
		if exists {
			return nil, fmt.Errorf("%w: location code %s already exists", inventory_errors.ErrDuplicate, *req.Code)
		}
		location.Code = *req.Code
	}

	if req.Name != nil {
		location.Name = *req.Name
	}
	if req.LocationType != nil {
		location.LocationType = req.LocationType
	}
	// Handle parent update (nil means no change, but we need to differentiate between "no change" and "set to NULL")
	if req.ParentLocationID != nil {
		if *req.ParentLocationID == uuid.Nil {
			location.ParentLocationID = nil
		} else {
			// Validate parent exists and belongs to same company
			parent, err := s.locationRepo.GetByID(ctx, tx, *req.ParentLocationID)
			if err != nil {
				return nil, fmt.Errorf("parent location not found: %w", err)
			}
			if parent.CompanyID != req.CompanyID {
				return nil, inventory_errors.ErrPermissionDenied
			}
			location.ParentLocationID = req.ParentLocationID
		}
	}
	if req.IsActive != nil {
		location.IsActive = *req.IsActive
	}

	if err := s.locationRepo.Update(ctx, tx, location); err != nil {
		return nil, fmt.Errorf("update location: %w", err)
	}

	if err := s.emitLocationEvent(ctx, tx, location, events.EventLocationUpdated); err != nil {
		logger.Warn("failed to emit location updated event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, location)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "update_location", "inventory_location",
			&location.LocationID, "user", req.UpdatedBy, nil, nil, nil)
	}

	return location, nil
}

// DeleteLocation soft-deletes a location (sets is_active = false).
func (s *inventoryLocationService) DeleteLocation(ctx context.Context, companyID, locationID uuid.UUID, deletedBy *uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "DeleteLocation"), zap.String("idempotency_key", idempotencyKey))

	if companyID == uuid.Nil || locationID == uuid.Nil {
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

	location, err := s.locationRepo.GetByID(ctx, tx, locationID)
	if err != nil {
		return err
	}
	if location.CompanyID != companyID {
		return inventory_errors.ErrPermissionDenied
	}

	if err := s.locationRepo.SoftDelete(ctx, tx, locationID); err != nil {
		return fmt.Errorf("soft delete location: %w", err)
	}

	if err := s.emitLocationEvent(ctx, tx, location, events.EventLocationDeleted); err != nil {
		logger.Warn("failed to emit location deleted event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "inventory", "delete_location", "inventory_location",
			&locationID, "user", deletedBy, nil, nil, nil)
	}

	return nil
}

// GetLocationTree returns the hierarchical tree of locations for a company.
func (s *inventoryLocationService) GetLocationTree(ctx context.Context, companyID uuid.UUID) ([]*LocationNode, error) {
	locations, err := s.locationRepo.GetTree(ctx, s.pgClient.DB, companyID)
	if err != nil {
		return nil, fmt.Errorf("get location tree: %w", err)
	}

	// Build map of locationID -> node
	nodeMap := make(map[uuid.UUID]*LocationNode)
	for _, loc := range locations {
		nodeMap[loc.LocationID] = &LocationNode{
			InventoryLocation: *loc,
			Children:          []*LocationNode{},
		}
	}

	var roots []*LocationNode
	for _, node := range nodeMap {
		if node.ParentLocationID == nil {
			roots = append(roots, node)
		} else {
			if parent, ok := nodeMap[*node.ParentLocationID]; ok {
				parent.Children = append(parent.Children, node)
			} else {
				// Parent not found in same company – treat as root
				roots = append(roots, node)
			}
		}
	}
	return roots, nil
}

// GetLocationByID retrieves a single location by ID (with company check).
func (s *inventoryLocationService) GetLocationByID(ctx context.Context, companyID, locationID uuid.UUID) (*models.InventoryLocation, error) {
	loc, err := s.locationRepo.GetByID(ctx, s.pgClient.DB, locationID)
	if err != nil {
		return nil, err
	}
	if loc.CompanyID != companyID {
		return nil, inventory_errors.ErrPermissionDenied
	}
	return loc, nil
}

// ListLocations lists all locations for a company, optionally only active ones.
func (s *inventoryLocationService) ListLocations(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.InventoryLocation, error) {
	var parentID *uuid.UUID = nil
	locations, err := s.locationRepo.List(ctx, s.pgClient.DB, companyID, parentID, activeOnly)
	if err != nil {
		return nil, fmt.Errorf("list locations: %w", err)
	}
	return locations, nil
}

// AssignWarehouseToLocation updates the location_id of a warehouse.
func (s *inventoryLocationService) AssignWarehouseToLocation(ctx context.Context, req AssignWarehouseRequest, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "AssignWarehouseToLocation"), zap.String("idempotency_key", idempotencyKey))

	if req.CompanyID == uuid.Nil || req.WarehouseID == uuid.Nil || req.LocationID == uuid.Nil {
		return inventory_errors.ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – already assigned")
		return nil
	}

	// Verify warehouse exists and belongs to company
	warehouse, err := s.warehouseRepo.GetByID(ctx, tx, req.CompanyID, req.WarehouseID)
	if err != nil {
		return err
	}
	// Verify location exists and belongs to company
	location, err := s.locationRepo.GetByID(ctx, tx, req.LocationID)
	if err != nil {
		return err
	}
	if location.CompanyID != req.CompanyID {
		return inventory_errors.ErrPermissionDenied
	}

	// Update warehouse
	warehouse.LocationID = &req.LocationID
	warehouse.UpdatedBy = req.UpdatedBy
	if err := s.warehouseRepo.Update(ctx, tx, warehouse); err != nil {
		return fmt.Errorf("update warehouse location: %w", err)
	}

	// Emit event (optional – could be a warehouse updated event)
	// We'll reuse warehouse updated event or create a new one. For simplicity, emit warehouse updated.
	// But we need a warehouse service to emit events? We'll emit directly here.
	if err := s.emitWarehouseLocationEvent(ctx, tx, warehouse); err != nil {
		logger.Warn("failed to emit warehouse location change event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "assign_warehouse_to_location", "warehouse",
			&req.WarehouseID, "user", req.UpdatedBy, nil, nil, map[string]interface{}{
				"location_id": req.LocationID.String(),
			})
	}

	return nil
}

// ----------------------------------------------------------------------
// Helper functions
// ----------------------------------------------------------------------

func validateCreateLocation(req CreateLocationRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", inventory_errors.ErrInvalidInput)
	}
	if req.Code == "" {
		return fmt.Errorf("%w: code required", inventory_errors.ErrInvalidInput)
	}
	if req.Name == "" {
		return fmt.Errorf("%w: name required", inventory_errors.ErrInvalidInput)
	}
	return nil
}

// emitLocationEvent publishes location-related outbox events.
func (s *inventoryLocationService) emitLocationEvent(ctx context.Context, tx *sql.Tx, loc *models.InventoryLocation, eventType string) error {
	payload := map[string]interface{}{
		"location_id":   loc.LocationID.String(),
		"company_id":    loc.CompanyID.String(),
		"code":          loc.Code,
		"name":          loc.Name,
		"location_type": loc.LocationType,
		"parent_id":     nil,
		"is_active":     loc.IsActive,
	}
	if loc.ParentLocationID != nil {
		payload["parent_id"] = loc.ParentLocationID.String()
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "inventory_location",
		AggregateID:   loc.LocationID.String(),
		EventType:     eventType,
		Topic:         events.TopicInventoryEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}

// emitWarehouseLocationEvent emits a warehouse updated event when location is assigned.
func (s *inventoryLocationService) emitWarehouseLocationEvent(ctx context.Context, tx *sql.Tx, warehouse *models.Warehouse) error {
	payload := map[string]interface{}{
		"warehouse_id":   warehouse.WarehouseID.String(),
		"company_id":     warehouse.CompanyID.String(),
		"code":           warehouse.Code,
		"name":           warehouse.Name,
		"location_id":    nil,
		"warehouse_type": warehouse.WarehouseType,
	}
	if warehouse.LocationID != nil {
		payload["location_id"] = warehouse.LocationID.String()
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "warehouse",
		AggregateID:   warehouse.WarehouseID.String(),
		EventType:     events.EventWarehouseUpdated,
		Topic:         events.TopicInventoryEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}
