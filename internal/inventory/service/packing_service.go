package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
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

// PackingService defines operations for packing lists and packing items.
type PackingService interface {
	// GeneratePackingList creates a packing list for a shipment.
	GeneratePackingList(ctx context.Context, req GeneratePackingListRequest, idempotencyKey string) (*models.PackingList, error)

	// GetPackingListByID retrieves a packing list by ID.
	GetPackingListByID(ctx context.Context, packingListID uuid.UUID) (*models.PackingList, error)

	// GetPackingListsByShipment retrieves all packing lists for a shipment.
	GetPackingListsByShipment(ctx context.Context, shipmentID uuid.UUID) ([]*models.PackingList, error)

	// PackItem updates the packed quantity for a specific packing list item.
	PackItem(ctx context.Context, req PackItemRequest, idempotencyKey string) error

	// BulkPackItems updates multiple packing list items in one transaction.
	BulkPackItems(ctx context.Context, req BulkPackItemsRequest, idempotencyKey string) error

	// VerifyPacking marks a packing list as verified (quality check).
	VerifyPacking(ctx context.Context, req VerifyPackingRequest, idempotencyKey string) error

	// CompletePacking marks a packing list as completed (ready for shipping).
	CompletePacking(ctx context.Context, packingListID uuid.UUID, completedBy *uuid.UUID, idempotencyKey string) error

	// ListPackingLists returns paginated packing lists with optional filters.
	ListPackingLists(ctx context.Context, filter repository.PackingListFilter, page, pageSize int) ([]*models.PackingList, int64, error)

	// GetPackingListItems retrieves all items for a packing list.
	GetPackingListItems(ctx context.Context, packingListID uuid.UUID) ([]*models.PackingListItem, error)
}

// GeneratePackingListRequest defines input for creating a packing list.
type GeneratePackingListRequest struct {
	CompanyID  uuid.UUID
	ShipmentID uuid.UUID
	CreatedBy  *uuid.UUID
}

// PackItemRequest updates a single packing list item.
type PackItemRequest struct {
	CompanyID     uuid.UUID
	PackingItemID uuid.UUID
	PackedQty     decimal.Decimal
	PackedBy      *uuid.UUID
}

// BulkPackItemsRequest updates multiple packing items.
type BulkPackItemsRequest struct {
	CompanyID uuid.UUID
	Items     []PackItemRequest
	PackedBy  *uuid.UUID
}

// VerifyPackingRequest marks packing as verified.
type VerifyPackingRequest struct {
	CompanyID     uuid.UUID
	PackingListID uuid.UUID
	VerifiedBy    *uuid.UUID
}

type packingService struct {
	packingListRepo     repository.PackingListRepository
	packingListItemRepo repository.PackingListItemRepository
	shipmentItemRepo    repository.ShipmentItemRepository
	shipmentRepo        repository.ShipmentRepository
	warehouseRepo       repository.WarehouseRepository
	pgClient            *client.PostgresClient
	outboxRepo          outbox.Repository
	idempotencyStore    idempotency.Store
	auditService        *audit.AuditService
	logger              *zap.Logger
}

// NewPackingService creates a new packing service instance.
func NewPackingService(
	packingListRepo repository.PackingListRepository,
	packingListItemRepo repository.PackingListItemRepository,
	shipmentItemRepo repository.ShipmentItemRepository,
	shipmentRepo repository.ShipmentRepository,
	warehouseRepo repository.WarehouseRepository,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) PackingService {
	return &packingService{
		packingListRepo:     packingListRepo,
		packingListItemRepo: packingListItemRepo,
		shipmentItemRepo:    shipmentItemRepo,
		shipmentRepo:        shipmentRepo,
		warehouseRepo:       warehouseRepo,
		pgClient:            pgClient,
		outboxRepo:          outboxRepo,
		idempotencyStore:    idempotencyStore,
		auditService:        auditService,
		logger:              logger.Named("packing_service"),
	}
}

// ============================================================================
// GeneratePackingList
// ============================================================================

func (s *packingService) GeneratePackingList(ctx context.Context, req GeneratePackingListRequest, idempotencyKey string) (*models.PackingList, error) {
	logger := s.logger.With(zap.String("method", "GeneratePackingList"), zap.String("idempotency_key", idempotencyKey))

	if err := s.validateGeneratePackingList(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check
	var cached *models.PackingList
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent request – returning cached packing list")
		return cached, nil
	}

	// Validate shipment exists and belongs to company
	shipment, err := s.shipmentRepo.GetByID(ctx, tx, req.ShipmentID)
	if err != nil {
		return nil, fmt.Errorf("get shipment: %w", err)
	}
	if shipment.CompanyID != req.CompanyID {
		return nil, inventory_errors.ErrPermissionDenied
	}

	// Check if a packing list already exists for this shipment
	existing, err := s.packingListRepo.GetByShipment(ctx, tx, req.ShipmentID)
	if err != nil && err != inventory_errors.ErrNotFound {
		return nil, fmt.Errorf("check existing packing list: %w", err)
	}
	if len(existing) > 0 {
		return nil, fmt.Errorf("%w: packing list already exists for shipment %s", inventory_errors.ErrDuplicate, req.ShipmentID)
	}

	// Fetch shipment items
	shipmentItems, err := s.shipmentItemRepo.GetByShipmentID(ctx, tx, req.ShipmentID)
	if err != nil {
		return nil, fmt.Errorf("get shipment items: %w", err)
	}
	if len(shipmentItems) == 0 {
		return nil, fmt.Errorf("%w: no items found in shipment %s", inventory_errors.ErrInvalidInput, req.ShipmentID)
	}

	// Create packing list
	packingList := &models.PackingList{
		PackingListID: uuid.New(),
		CompanyID:     req.CompanyID,
		ShipmentID:    req.ShipmentID,
		Status:        "created",
		PackedBy:      req.CreatedBy,
		CreatedAt:     time.Now(),
	}
	if err := s.packingListRepo.Create(ctx, tx, packingList); err != nil {
		return nil, fmt.Errorf("create packing list: %w", err)
	}

	// Create packing items for each shipment item
	packingItems := make([]*models.PackingListItem, 0, len(shipmentItems))
	for _, si := range shipmentItems {
		packingItems = append(packingItems, &models.PackingListItem{
			PackingItemID:  uuid.New(),
			PackingListID:  packingList.PackingListID,
			ShipmentItemID: si.ShipmentItemID,
			PackedQty:      decimal.Zero,
			CreatedAt:      time.Now(),
		})
	}
	if err := s.packingListItemRepo.BulkCreate(ctx, tx, packingItems); err != nil {
		return nil, fmt.Errorf("create packing items: %w", err)
	}

	// Emit event
	if err := s.emitPackingEvent(ctx, tx, packingList, events.EventPackingListCreated); err != nil {
		logger.Warn("failed to emit packing list created event", zap.Error(err))
	}

	// Store idempotency result
	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, packingList)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "generate_packing_list", "packing_list",
			&packingList.PackingListID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"shipment_id": req.ShipmentID.String(),
				"items_count": len(packingItems),
			})
	}

	logger.Info("packing list generated", zap.String("packing_list_id", packingList.PackingListID.String()))
	return packingList, nil
}

func (s *packingService) validateGeneratePackingList(req GeneratePackingListRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", inventory_errors.ErrInvalidInput)
	}
	if req.ShipmentID == uuid.Nil {
		return fmt.Errorf("%w: shipment_id required", inventory_errors.ErrInvalidInput)
	}
	return nil
}

// ============================================================================
// PackItem
// ============================================================================

func (s *packingService) PackItem(ctx context.Context, req PackItemRequest, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "PackItem"), zap.String("idempotency_key", idempotencyKey))

	if err := s.validatePackItem(req); err != nil {
		return err
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

	// Get packing list item
	packingItem, err := s.packingListItemRepo.GetByID(ctx, tx, req.PackingItemID)
	if err != nil {
		return err
	}

	// Verify ownership via packing list -> shipment -> company
	packingList, err := s.packingListRepo.GetByID(ctx, tx, packingItem.PackingListID)
	if err != nil {
		return err
	}
	if packingList.CompanyID != req.CompanyID {
		return inventory_errors.ErrPermissionDenied
	}

	// Get shipment item to know max allowed packed quantity
	shipmentItem, err := s.shipmentItemRepo.GetByID(ctx, tx, packingItem.ShipmentItemID)
	if err != nil {
		return err
	}

	// Calculate new total packed quantity (incremental)
	newTotal := packingItem.PackedQty.Add(req.PackedQty)
	if newTotal.GreaterThan(shipmentItem.QuantityShipped) {
		return fmt.Errorf("%w: packed quantity would exceed shipment quantity %s (current %s + %s)",
			inventory_errors.ErrInvalidInput, shipmentItem.QuantityShipped.String(),
			packingItem.PackedQty.String(), req.PackedQty.String())
	}

	// Increment packed quantity using the delta
	if err := s.packingListItemRepo.AddPackedQty(ctx, tx, req.PackingItemID, req.PackedQty); err != nil {
		return fmt.Errorf("add packed qty: %w", err)
	}

	// After update, check if all items in the packing list are now fully packed
	allPacked, err := s.isFullyPacked(ctx, tx, packingList.PackingListID)
	if err != nil {
		return fmt.Errorf("check if fully packed: %w", err)
	}
	if allPacked && packingList.Status == "created" {
		packedAt := time.Now()
		if err := s.packingListRepo.UpdateStatusToPacked(ctx, tx, packingList.PackingListID, req.PackedBy, packedAt); err != nil {
			return fmt.Errorf("failed to update packing list status to packed: %w", err)
		}
		// Update local object for event emission
		packingList.Status = "packed"
		packingList.PackedAt = &packedAt
		packingList.PackedBy = req.PackedBy
		if err := s.emitPackingEvent(ctx, tx, packingList, events.EventPackingListPacked); err != nil {
			logger.Warn("failed to emit packing list packed event", zap.Error(err))
		}
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "pack_item", "packing_list_item",
			&req.PackingItemID, "user", req.PackedBy, nil, nil, map[string]interface{}{
				"packed_qty_added": req.PackedQty.String(),
				"new_total":        newTotal.String(),
			})
	}

	logger.Info("packing item updated",
		zap.String("packing_item_id", req.PackingItemID.String()),
		zap.String("added_qty", req.PackedQty.String()),
		zap.String("new_total", newTotal.String()))
	return nil
}
func (s *packingService) validatePackItem(req PackItemRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", inventory_errors.ErrInvalidInput)
	}
	if req.PackingItemID == uuid.Nil {
		return fmt.Errorf("%w: packing_item_id required", inventory_errors.ErrInvalidInput)
	}
	if req.PackedQty.LessThan(decimal.Zero) {
		return fmt.Errorf("%w: packed_qty cannot be negative", inventory_errors.ErrInvalidInput)
	}
	return nil
}

// ============================================================================
// BulkPackItems
// ============================================================================

func (s *packingService) BulkPackItems(ctx context.Context, req BulkPackItemsRequest, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "BulkPackItems"), zap.String("idempotency_key", idempotencyKey))

	if len(req.Items) == 0 {
		return fmt.Errorf("%w: at least one item required", inventory_errors.ErrInvalidInput)
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

	// Track which packing lists are affected for status updates
	affectedListIDs := make(map[uuid.UUID]bool)

	for _, item := range req.Items {
		if err := s.validatePackItem(item); err != nil {
			return err
		}

		packingItem, err := s.packingListItemRepo.GetByID(ctx, tx, item.PackingItemID)
		if err != nil {
			return err
		}

		packingList, err := s.packingListRepo.GetByID(ctx, tx, packingItem.PackingListID)
		if err != nil {
			return err
		}
		if packingList.CompanyID != req.CompanyID {
			return inventory_errors.ErrPermissionDenied
		}

		shipmentItem, err := s.shipmentItemRepo.GetByID(ctx, tx, packingItem.ShipmentItemID)
		if err != nil {
			return err
		}

		// Calculate new total packed quantity (incremental)
		newTotal := packingItem.PackedQty.Add(item.PackedQty)
		if newTotal.GreaterThan(shipmentItem.QuantityShipped) {
			return fmt.Errorf("%w: packed quantity would exceed shipment quantity %s for item %s (current %s + %s)",
				inventory_errors.ErrInvalidInput,
				shipmentItem.QuantityShipped.String(),
				packingItem.PackingItemID.String(),
				packingItem.PackedQty.String(),
				item.PackedQty.String())
		}

		// Increment packed quantity using AddPackedQty (delta)
		if err := s.packingListItemRepo.AddPackedQty(ctx, tx, item.PackingItemID, item.PackedQty); err != nil {
			return fmt.Errorf("add packed qty: %w", err)
		}

		affectedListIDs[packingList.PackingListID] = true
	}

	// Check and update status for each affected packing list
	for listID := range affectedListIDs {
		allPacked, err := s.isFullyPacked(ctx, tx, listID)
		if err != nil {
			return fmt.Errorf("check if fully packed for list %s: %w", listID, err)
		}
		if allPacked {
			list, err := s.packingListRepo.GetByID(ctx, tx, listID)
			if err != nil {
				return fmt.Errorf("get packing list %s: %w", listID, err)
			}
			if list.Status == "created" {
				packedAt := time.Now()
				if err := s.packingListRepo.UpdateStatusToPacked(ctx, tx, listID, req.PackedBy, packedAt); err != nil {
					return fmt.Errorf("failed to update packing list %s status to packed: %w", listID, err)
				}
				list.Status = "packed"
				list.PackedAt = &packedAt
				list.PackedBy = req.PackedBy
				if err := s.emitPackingEvent(ctx, tx, list, events.EventPackingListPacked); err != nil {
					logger.Warn("failed to emit packing list packed event", zap.String("list_id", listID.String()), zap.Error(err))
				}
			}
		}
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "bulk_pack_items", "packing_list",
			nil, "user", req.PackedBy, nil, nil, map[string]interface{}{
				"items_count": len(req.Items),
			})
	}

	logger.Info("bulk pack items completed", zap.Int("count", len(req.Items)))
	return nil
}

// ============================================================================
// VerifyPacking
// ============================================================================

func (s *packingService) VerifyPacking(ctx context.Context, req VerifyPackingRequest, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "VerifyPacking"), zap.String("idempotency_key", idempotencyKey))

	if req.CompanyID == uuid.Nil || req.PackingListID == uuid.Nil {
		return inventory_errors.ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – already verified")
		return nil
	}

	packingList, err := s.packingListRepo.GetByID(ctx, tx, req.PackingListID)
	if err != nil {
		return err
	}
	if packingList.CompanyID != req.CompanyID {
		return inventory_errors.ErrPermissionDenied
	}

	if packingList.Status != "packed" {
		return fmt.Errorf("%w: cannot verify packing list in status %s", inventory_errors.ErrInvalidTransition, packingList.Status)
	}

	verifiedAt := time.Now()
	if err := s.packingListRepo.VerifyPacking(ctx, tx, req.PackingListID, req.VerifiedBy, verifiedAt); err != nil {
		return fmt.Errorf("verify packing: %w", err)
	}

	packingList.Status = "verified"
	packingList.VerifiedAt = &verifiedAt
	packingList.PackedBy = req.VerifiedBy // set packer as the verifier (or keep separate field)

	if err := s.emitPackingEvent(ctx, tx, packingList, events.EventPackingListVerified); err != nil {
		logger.Warn("failed to emit verification event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "verify_packing", "packing_list",
			&req.PackingListID, "user", req.VerifiedBy, nil, nil, nil)
	}

	logger.Info("packing list verified", zap.String("packing_list_id", req.PackingListID.String()))
	return nil
}

// ============================================================================
// CompletePacking
// ============================================================================

func (s *packingService) CompletePacking(ctx context.Context, packingListID uuid.UUID, completedBy *uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "CompletePacking"), zap.String("idempotency_key", idempotencyKey))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – already completed")
		return nil
	}

	packingList, err := s.packingListRepo.GetByID(ctx, tx, packingListID)
	if err != nil {
		return err
	}

	if packingList.Status != "verified" {
		return fmt.Errorf("%w: cannot complete packing list in status %s (must be verified)", inventory_errors.ErrInvalidTransition, packingList.Status)
	}

	completedAt := time.Now()
	if err := s.packingListRepo.UpdateStatus(ctx, tx, packingListID, "completed", nil, &completedAt); err != nil {
		return fmt.Errorf("complete packing: %w", err)
	}

	packingList.Status = "completed"
	packingList.CompletedAt = &completedAt

	if err := s.emitPackingEvent(ctx, tx, packingList, events.EventPackingListCompleted); err != nil {
		logger.Warn("failed to emit completion event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &packingList.CompanyID, "inventory", "complete_packing", "packing_list",
			&packingListID, "user", completedBy, nil, nil, nil)
	}

	logger.Info("packing list completed", zap.String("packing_list_id", packingListID.String()))
	return nil
}

// ============================================================================
// Query Methods
// ============================================================================

func (s *packingService) GetPackingListByID(ctx context.Context, packingListID uuid.UUID) (*models.PackingList, error) {
	return s.packingListRepo.GetByID(ctx, s.pgClient.DB, packingListID)
}

func (s *packingService) GetPackingListsByShipment(ctx context.Context, shipmentID uuid.UUID) ([]*models.PackingList, error) {
	return s.packingListRepo.GetByShipment(ctx, s.pgClient.DB, shipmentID)
}

func (s *packingService) GetPackingListItems(ctx context.Context, packingListID uuid.UUID) ([]*models.PackingListItem, error) {
	return s.packingListItemRepo.GetByPackingList(ctx, s.pgClient.DB, packingListID)
}

func (s *packingService) ListPackingLists(ctx context.Context, filter repository.PackingListFilter, page, pageSize int) ([]*models.PackingList, int64, error) {
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
	sort := repository.Sort{Field: "created_at", Direction: "DESC"}
	return s.packingListRepo.List(ctx, s.pgClient.DB, filter, pagination, sort)
}

// ============================================================================
// Helper Methods
// ============================================================================

func (s *packingService) isFullyPacked(ctx context.Context, tx *sql.Tx, packingListID uuid.UUID) (bool, error) {
	items, err := s.packingListItemRepo.GetByPackingList(ctx, tx, packingListID)
	if err != nil {
		return false, err
	}
	if len(items) == 0 {
		return false, nil
	}
	for _, item := range items {
		shipmentItem, err := s.shipmentItemRepo.GetByID(ctx, tx, item.ShipmentItemID)
		if err != nil {
			return false, err
		}
		if item.PackedQty.LessThan(shipmentItem.QuantityShipped) {
			return false, nil
		}
	}
	return true, nil
}

// ============================================================================
// Event Emission
// ============================================================================

func (s *packingService) emitPackingEvent(ctx context.Context, tx *sql.Tx, packingList *models.PackingList, eventType string) error {
	payload := map[string]interface{}{
		"packing_list_id": packingList.PackingListID.String(),
		"company_id":      packingList.CompanyID.String(),
		"shipment_id":     packingList.ShipmentID.String(),
		"status":          packingList.Status,
		"packed_at":       packingList.PackedAt,
		"verified_at":     packingList.VerifiedAt,
		"completed_at":    packingList.CompletedAt,
	}
	if packingList.PackedBy != nil {
		payload["packed_by"] = packingList.PackedBy.String()
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "packing_list",
		AggregateID:   packingList.PackingListID.String(),
		EventType:     eventType,
		Topic:         events.TopicInventoryEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}

// ============================================================================
// Utility
// ============================================================================

func timePtr(t time.Time) *time.Time {
	return &t
}
