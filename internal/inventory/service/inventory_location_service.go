package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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

// Allowed location types
var allowedLocationTypes = map[string]bool{
	"region": true,
	"zone":   true,
	"aisle":  true,
	"bin":    true,
}

// InventoryLocationService manages warehouse location hierarchy.
type InventoryLocationService interface {
	CreateLocation(ctx context.Context, req CreateLocationRequest, idempotencyKey string) (*models.InventoryLocation, error)
	UpdateLocation(ctx context.Context, req UpdateLocationRequest, idempotencyKey string) (*models.InventoryLocation, error)
	DeleteLocation(ctx context.Context, companyID, locationID uuid.UUID, deletedBy *uuid.UUID, idempotencyKey string) error
	GetLocationTree(ctx context.Context, companyID, warehouseID uuid.UUID) ([]*LocationNode, error)
	GetLocationByID(ctx context.Context, companyID, locationID uuid.UUID) (*models.InventoryLocation, error)
	ListLocations(ctx context.Context, companyID, warehouseID uuid.UUID, parentID *uuid.UUID, activeOnly bool) ([]*models.InventoryLocation, error)
}

// CreateLocationRequest defines input for creating a location.
type CreateLocationRequest struct {
	CompanyID        uuid.UUID
	WarehouseID      uuid.UUID
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
	WarehouseID      *uuid.UUID
	Code             *string
	Name             *string
	LocationType     *string
	ParentLocationID *uuid.UUID // nil = no change; empty uuid = set to NULL
	IsActive         *bool
	UpdatedBy        *uuid.UUID
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

// ----------------------------------------------------------------------
// Validation helpers
// ----------------------------------------------------------------------

func validateLocationType(locationType *string) error {
	if locationType == nil {
		return nil // optional field
	}
	if !allowedLocationTypes[*locationType] {
		return fmt.Errorf("%w: location_type must be one of: region, zone, aisle, bin", inventory_errors.ErrInvalidInput)
	}
	return nil
}

func validateCreateLocation(req CreateLocationRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", inventory_errors.ErrInvalidInput)
	}
	if req.WarehouseID == uuid.Nil {
		return fmt.Errorf("%w: warehouse_id required", inventory_errors.ErrInvalidInput)
	}
	if req.Code == "" {
		return fmt.Errorf("%w: code required", inventory_errors.ErrInvalidInput)
	}
	if req.Name == "" {
		return fmt.Errorf("%w: name required", inventory_errors.ErrInvalidInput)
	}
	if err := validateLocationType(req.LocationType); err != nil {
		return err
	}
	return nil
}

// ----------------------------------------------------------------------
// CreateLocation
// ----------------------------------------------------------------------

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

	// Validate warehouse exists and belongs to company
	_, err = s.warehouseRepo.GetByID(ctx, tx, req.CompanyID, req.WarehouseID)
	if err != nil {
		return nil, fmt.Errorf("warehouse validation failed: %w", err)
	}

	// Check code uniqueness per company + warehouse
	exists, err := s.locationRepo.ExistsByCode(ctx, tx, req.CompanyID, req.WarehouseID, req.Code, nil)
	if err != nil {
		return nil, fmt.Errorf("check code exists: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("%w: location code %s already exists in this warehouse", inventory_errors.ErrDuplicate, req.Code)
	}

	// Validate parent location belongs to the same warehouse
	if req.ParentLocationID != nil {
		parent, err := s.locationRepo.GetByID(ctx, tx, *req.ParentLocationID)
		if err != nil {
			return nil, fmt.Errorf("parent location not found: %w", err)
		}
		if parent.CompanyID != req.CompanyID || parent.WarehouseID != req.WarehouseID {
			return nil, inventory_errors.ErrParentWarehouseMismatch
		}
	}

	location := &models.InventoryLocation{
		LocationID:       uuid.New(),
		CompanyID:        req.CompanyID,
		WarehouseID:      req.WarehouseID,
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

// ----------------------------------------------------------------------
// UpdateLocation
// ----------------------------------------------------------------------

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

	// Validate location_type if provided
	if req.LocationType != nil {
		if err := validateLocationType(req.LocationType); err != nil {
			return nil, err
		}
	}

	// 1. Prevent setting parent to itself
	if req.ParentLocationID != nil && *req.ParentLocationID == req.LocationID {
		return nil, fmt.Errorf("%w: cannot set parent to itself", inventory_errors.ErrInvalidInput)
	}

	// 2. Prevent creating a circular reference (location cannot become ancestor of itself)
	if req.ParentLocationID != nil && *req.ParentLocationID != uuid.Nil {
		isDescendant, err := s.isDescendant(ctx, tx, *req.ParentLocationID, req.LocationID)
		if err != nil {
			return nil, fmt.Errorf("circular reference check failed: %w", err)
		}
		if isDescendant {
			return nil, fmt.Errorf("%w: setting parent would create a circular reference", inventory_errors.ErrInvalidInput)
		}
	}

	// If warehouse is being changed, validate new warehouse exists and belongs to company
	if req.WarehouseID != nil && *req.WarehouseID != location.WarehouseID {
		_, err := s.warehouseRepo.GetByID(ctx, tx, req.CompanyID, *req.WarehouseID)
		if err != nil {
			return nil, fmt.Errorf("new warehouse validation failed: %w", err)
		}
		location.WarehouseID = *req.WarehouseID
	}

	// Check code uniqueness if code is being changed
	if req.Code != nil && *req.Code != location.Code {
		whID := location.WarehouseID
		if req.WarehouseID != nil {
			whID = *req.WarehouseID
		}
		exists, err := s.locationRepo.ExistsByCode(ctx, tx, req.CompanyID, whID, *req.Code, &req.LocationID)
		if err != nil {
			return nil, fmt.Errorf("check code exists: %w", err)
		}
		if exists {
			return nil, fmt.Errorf("%w: location code %s already exists in target warehouse", inventory_errors.ErrDuplicate, *req.Code)
		}
		location.Code = *req.Code
	}

	if req.Name != nil {
		location.Name = *req.Name
	}
	if req.LocationType != nil {
		location.LocationType = req.LocationType
	}
	// Handle parent update
	if req.ParentLocationID != nil {
		if *req.ParentLocationID == uuid.Nil {
			location.ParentLocationID = nil
		} else {
			// Validate parent exists and belongs to same company+warehouse
			parent, err := s.locationRepo.GetByID(ctx, tx, *req.ParentLocationID)
			if err != nil {
				return nil, fmt.Errorf("parent location not found: %w", err)
			}
			if parent.CompanyID != req.CompanyID || parent.WarehouseID != location.WarehouseID {
				return nil, inventory_errors.ErrParentWarehouseMismatch
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

// isDescendant checks whether candidate is a descendant of ancestor.
func (s *inventoryLocationService) isDescendant(ctx context.Context, tx *sql.Tx, candidate, ancestor uuid.UUID) (bool, error) {
	if candidate == ancestor {
		return true, nil
	}
	currentID := candidate
	for {
		loc, err := s.locationRepo.GetByID(ctx, tx, currentID)
		if err != nil {
			if errors.Is(err, inventory_errors.ErrNotFound) {
				return false, nil
			}
			return false, err
		}
		if loc.ParentLocationID == nil {
			return false, nil
		}
		if *loc.ParentLocationID == ancestor {
			return true, nil
		}
		currentID = *loc.ParentLocationID
	}
}

// ----------------------------------------------------------------------
// DeleteLocation
// ----------------------------------------------------------------------

// DeleteLocation soft-deletes a location (sets is_active = false).
// If the location is already inactive, returns ErrNotFound.
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
	// If already inactive, treat as not found
	if !location.IsActive {
		return inventory_errors.ErrNotFound
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

// ----------------------------------------------------------------------
// GetLocationTree, GetLocationByID, ListLocations
// ----------------------------------------------------------------------

// GetLocationTree returns the hierarchical tree of locations for a company+warehouse.
func (s *inventoryLocationService) GetLocationTree(ctx context.Context, companyID, warehouseID uuid.UUID) ([]*LocationNode, error) {
	locations, err := s.locationRepo.GetTree(ctx, s.pgClient.DB, companyID, warehouseID)
	if err != nil {
		return nil, fmt.Errorf("get location tree: %w", err)
	}

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
				roots = append(roots, node)
			}
		}
	}
	return roots, nil
}

// GetLocationByID retrieves a single location by ID (with company check).
// Inactive locations are still returned (with isActive false).
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

// ListLocations lists all locations for a company and warehouse, optionally only active ones and filtering by parent.
func (s *inventoryLocationService) ListLocations(ctx context.Context, companyID, warehouseID uuid.UUID, parentID *uuid.UUID, activeOnly bool) ([]*models.InventoryLocation, error) {
	locations, err := s.locationRepo.List(ctx, s.pgClient.DB, companyID, warehouseID, parentID, activeOnly)
	if err != nil {
		return nil, fmt.Errorf("list locations: %w", err)
	}
	return locations, nil
}

// ----------------------------------------------------------------------
// Event emission
// ----------------------------------------------------------------------

// emitLocationEvent publishes location-related outbox events.
func (s *inventoryLocationService) emitLocationEvent(ctx context.Context, tx *sql.Tx, loc *models.InventoryLocation, eventType string) error {
	payload := map[string]interface{}{
		"location_id":   loc.LocationID.String(),
		"company_id":    loc.CompanyID.String(),
		"warehouse_id":  loc.WarehouseID.String(),
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
