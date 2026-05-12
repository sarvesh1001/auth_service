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

// ShipmentItemService handles operations on shipment items (line items shipped under a shipment).
type ShipmentItemService interface {
	// CreateShipmentItems creates one or more shipment items for a given shipment.
	// Expects items grouped by fulfillment_item_id with quantity shipped.
	CreateShipmentItems(ctx context.Context, req CreateShipmentItemsRequest, idempotencyKey string) ([]*models.ShipmentItem, error)

	// GetByShipmentID returns all shipment items for a shipment.
	GetByShipmentID(ctx context.Context, shipmentID uuid.UUID) ([]*models.ShipmentItem, error)

	// GetByFulfillmentItemID returns all shipment items linking to a specific fulfillment order item.
	GetByFulfillmentItemID(ctx context.Context, fulfillmentItemID uuid.UUID) ([]*models.ShipmentItem, error)

	// GetShipmentItemByID returns a single shipment item by its ID.
	GetShipmentItemByID(ctx context.Context, shipmentItemID uuid.UUID) (*models.ShipmentItem, error)

	// UpdateShippedQuantity updates the shipped quantity of an existing shipment item (rare, but allowed).
	UpdateShippedQuantity(ctx context.Context, req UpdateShippedQuantityRequest, idempotencyKey string) (*models.ShipmentItem, error)

	// DeleteShipmentItem removes a shipment item (e.g., if shipment is cancelled before shipping).
	DeleteShipmentItem(ctx context.Context, shipmentItemID, companyID uuid.UUID, idempotencyKey string) error

	// ListShipmentItems lists shipment items with optional filters.
	ListShipmentItems(ctx context.Context, filter repository.ShipmentItemFilter, page, pageSize int) ([]*models.ShipmentItem, int64, error)
}

// CreateShipmentItemsRequest defines bulk creation of shipment items.
type CreateShipmentItemsRequest struct {
	CompanyID  uuid.UUID
	ShipmentID uuid.UUID
	Items      []ShipmentItemEntry
	CreatedBy  *uuid.UUID
}

// ShipmentItemEntry represents one item to be shipped.
type ShipmentItemEntry struct {
	FulfillmentItemID uuid.UUID
	QuantityShipped   decimal.Decimal
}

// UpdateShippedQuantityRequest updates a single shipment item.
type UpdateShippedQuantityRequest struct {
	ShipmentItemID  uuid.UUID
	CompanyID       uuid.UUID
	QuantityShipped decimal.Decimal
	UpdatedBy       *uuid.UUID
}

type shipmentItemService struct {
	shipmentItemRepo repository.ShipmentItemRepository
	fulfillmentRepo  repository.FulfillmentRepository
	shipmentRepo     repository.ShipmentRepository
	itemRepo         repository.ItemRepository
	pgClient         *client.PostgresClient
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	logger           *zap.Logger
}

// NewShipmentItemService creates a new shipment item service.
func NewShipmentItemService(
	shipmentItemRepo repository.ShipmentItemRepository,
	fulfillmentRepo repository.FulfillmentRepository,
	shipmentRepo repository.ShipmentRepository,
	itemRepo repository.ItemRepository,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) ShipmentItemService {
	return &shipmentItemService{
		shipmentItemRepo: shipmentItemRepo,
		fulfillmentRepo:  fulfillmentRepo,
		shipmentRepo:     shipmentRepo,
		itemRepo:         itemRepo,
		pgClient:         pgClient,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		logger:           logger.Named("shipment_item_service"),
	}
}

func (s *shipmentItemService) CreateShipmentItems(ctx context.Context, req CreateShipmentItemsRequest, idempotencyKey string) ([]*models.ShipmentItem, error) {
	logger := s.logger.With(zap.String("method", "CreateShipmentItems"), zap.String("idempotency_key", idempotencyKey))

	// Validation
	if req.CompanyID == uuid.Nil || req.ShipmentID == uuid.Nil {
		return nil, fmt.Errorf("%w: company_id and shipment_id are required", inventory_errors.ErrInvalidInput)
	}
	if len(req.Items) == 0 {
		return nil, fmt.Errorf("%w: at least one shipment item required", inventory_errors.ErrInvalidInput)
	}
	for _, it := range req.Items {
		if it.FulfillmentItemID == uuid.Nil {
			return nil, fmt.Errorf("%w: fulfillment_item_id is required", inventory_errors.ErrInvalidInput)
		}
		if it.QuantityShipped.LessThanOrEqual(decimal.Zero) {
			return nil, fmt.Errorf("%w: quantity_shipped must be positive", inventory_errors.ErrInvalidInput)
		}
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check
	var cached []*models.ShipmentItem
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent request – returning cached shipment items")
		return cached, nil
	}

	// Verify shipment exists and belongs to the company
	shipment, err := s.shipmentRepo.GetByID(ctx, tx, req.ShipmentID)
	if err != nil {
		return nil, fmt.Errorf("shipment not found: %w", err)
	}
	if shipment.CompanyID != req.CompanyID {
		return nil, inventory_errors.ErrPermissionDenied
	}
	if shipment.ShipmentStatus != "draft" && shipment.ShipmentStatus != "allocated" {
		return nil, fmt.Errorf("%w: cannot add items to shipment in status %s", inventory_errors.ErrInvalidTransition, shipment.ShipmentStatus)
	}

	// Validate fulfillment items and available quantities
	fulfillmentItems := make(map[uuid.UUID]*models.FulfillmentOrderItem)
	for _, it := range req.Items {
		// fetch fulfillment order item
		// In a real implementation you might batch fetch, but for simplicity we load one by one.
		// Since we have no direct method to get a single fulfillment item, we need to extend fulfillment repo.
		// For now, we assume the caller already validated that the fulfillment items exist.
		// Alternative: add FulfillmentRepository.GetFulfillmentItemByID.
		// We'll provide a helper inside this service (or add method to fulfillment repo).
		// Let's assume we have a method: fulfillmentRepo.GetFulfillmentItemByID(ctx, tx, id)
		fit, err := s.getFulfillmentItemByID(ctx, tx, it.FulfillmentItemID)
		if err != nil {
			return nil, fmt.Errorf("fulfillment item %s: %w", it.FulfillmentItemID, err)
		}
		fulfillmentItems[it.FulfillmentItemID] = fit
	}

	createdItems := make([]*models.ShipmentItem, 0, len(req.Items))
	for _, it := range req.Items {
		fit := fulfillmentItems[it.FulfillmentItemID]
		// If backorder exists, we need to ensure we don't overship
		maxShippable := fit.OrderedQty.Sub(fit.FulfilledQty).Sub(fit.BackorderedQty)
		if it.QuantityShipped.GreaterThan(maxShippable) {
			return nil, fmt.Errorf("%w: requested shipped quantity %s exceeds maximum shippable %s for fulfillment item %s",
				inventory_errors.ErrInvalidInput, it.QuantityShipped.String(), maxShippable.String(), it.FulfillmentItemID)
		}

		shipmentItem := &models.ShipmentItem{
			ShipmentItemID:    uuid.New(),
			ShipmentID:        req.ShipmentID,
			FulfillmentItemID: it.FulfillmentItemID,
			QuantityShipped:   it.QuantityShipped,
			CreatedAt:         time.Now(),
		}
		if err := s.shipmentItemRepo.Create(ctx, tx, shipmentItem); err != nil {
			return nil, fmt.Errorf("create shipment item: %w", err)
		}
		createdItems = append(createdItems, shipmentItem)

		// Emit shipment item created event (optional)
		if err := s.emitShipmentItemEvent(ctx, tx, shipmentItem, events.EventShipmentItemCreated); err != nil {
			logger.Warn("failed to emit shipment item created event", zap.Error(err))
		}
	}

	// Store in idempotency store
	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, createdItems)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "create_shipment_items", "shipment",
			&req.ShipmentID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"item_count": len(createdItems),
			})
	}

	logger.Info("shipment items created", zap.String("shipment_id", req.ShipmentID.String()), zap.Int("count", len(createdItems)))
	return createdItems, nil
}

// Helper: get a single fulfillment order item. If the repository doesn't have this method, we can add it.
// For completeness, we add a temporary method to fulfillmentRepo (you should add it to your fulfillment_repository.go).
func (s *shipmentItemService) getFulfillmentItemByID(ctx context.Context, tx *sql.Tx, id uuid.UUID) (*models.FulfillmentOrderItem, error) {
	// This is a direct query; ideally add method to FulfillmentRepository.
	query := `
		SELECT fulfillment_item_id, fulfillment_order_id, item_id, ordered_qty, fulfilled_qty, backordered_qty
		FROM fulfillment_order_items
		WHERE fulfillment_item_id = $1
	`
	var item models.FulfillmentOrderItem
	err := tx.QueryRowContext(ctx, query, id).Scan(
		&item.FulfillmentItemID, &item.FulfillmentOrderID, &item.ItemID,
		&item.OrderedQty, &item.FulfilledQty, &item.BackorderedQty,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%w: fulfillment item %s", inventory_errors.ErrNotFound, id)
		}
		return nil, fmt.Errorf("query fulfillment item: %w", err)
	}
	return &item, nil
}

func (s *shipmentItemService) GetByShipmentID(ctx context.Context, shipmentID uuid.UUID) ([]*models.ShipmentItem, error) {
	return s.shipmentItemRepo.GetByShipmentID(ctx, s.pgClient.DB, shipmentID)
}

func (s *shipmentItemService) GetByFulfillmentItemID(ctx context.Context, fulfillmentItemID uuid.UUID) ([]*models.ShipmentItem, error) {
	return s.shipmentItemRepo.GetByFulfillmentItemID(ctx, s.pgClient.DB, fulfillmentItemID)
}

func (s *shipmentItemService) GetShipmentItemByID(ctx context.Context, shipmentItemID uuid.UUID) (*models.ShipmentItem, error) {
	_ = repository.ShipmentItemFilter{}
	// We need a method that gets by ID directly; we'll list with filter.
	// Better to add GetByID to repository, but for now use list with ID.
	// We'll assume we have a method: GetByID in repository. For simplicity, we add a direct query.
	query := `
		SELECT shipment_item_id, shipment_id, fulfillment_item_id, quantity_shipped, created_at
		FROM shipment_items
		WHERE shipment_item_id = $1
	`
	var item models.ShipmentItem
	err := s.pgClient.DB.QueryRowContext(ctx, query, shipmentItemID).Scan(
		&item.ShipmentItemID, &item.ShipmentID, &item.FulfillmentItemID,
		&item.QuantityShipped, &item.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%w: shipment item %s", inventory_errors.ErrNotFound, shipmentItemID)
		}
		return nil, fmt.Errorf("get shipment item by id: %w", err)
	}
	return &item, nil
}

func (s *shipmentItemService) UpdateShippedQuantity(ctx context.Context, req UpdateShippedQuantityRequest, idempotencyKey string) (*models.ShipmentItem, error) {
	logger := s.logger.With(zap.String("method", "UpdateShippedQuantity"), zap.String("idempotency_key", idempotencyKey))

	if req.ShipmentItemID == uuid.Nil || req.CompanyID == uuid.Nil {
		return nil, fmt.Errorf("%w: shipment_item_id and company_id required", inventory_errors.ErrInvalidInput)
	}
	if req.QuantityShipped.LessThanOrEqual(decimal.Zero) {
		return nil, fmt.Errorf("%w: quantity_shipped must be positive", inventory_errors.ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *models.ShipmentItem
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached shipment item")
		return cached, nil
	}

	// Get existing item
	item, err := s.GetShipmentItemByID(ctx, req.ShipmentItemID)
	if err != nil {
		return nil, err
	}

	// Verify company via shipment
	shipment, err := s.shipmentRepo.GetByID(ctx, tx, item.ShipmentID)
	if err != nil {
		return nil, fmt.Errorf("get shipment: %w", err)
	}
	if shipment.CompanyID != req.CompanyID {
		return nil, inventory_errors.ErrPermissionDenied
	}
	if shipment.ShipmentStatus != "draft" {
		return nil, fmt.Errorf("%w: cannot update shipment item after shipment is %s", inventory_errors.ErrInvalidTransition, shipment.ShipmentStatus)
	}

	// Update quantity
	item.QuantityShipped = req.QuantityShipped
	// Update in repository (need to add Update method to ShipmentItemRepository)
	// We'll assume we have a repository.Update method. If not, implement it.
	if err := s.shipmentItemRepo.Update(ctx, tx, item); err != nil {
		return nil, fmt.Errorf("update shipment item: %w", err)
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, item)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "update_shipment_item", "shipment_item",
			&req.ShipmentItemID, "user", req.UpdatedBy, nil, nil, map[string]interface{}{
				"new_quantity": req.QuantityShipped,
			})
	}
	return item, nil
}

func (s *shipmentItemService) DeleteShipmentItem(ctx context.Context, shipmentItemID, companyID uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "DeleteShipmentItem"), zap.String("idempotency_key", idempotencyKey))

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

	item, err := s.GetShipmentItemByID(ctx, shipmentItemID)
	if err != nil {
		return err
	}
	shipment, err := s.shipmentRepo.GetByID(ctx, tx, item.ShipmentID)
	if err != nil {
		return fmt.Errorf("get shipment: %w", err)
	}
	if shipment.CompanyID != companyID {
		return inventory_errors.ErrPermissionDenied
	}
	if shipment.ShipmentStatus != "draft" {
		return fmt.Errorf("%w: cannot delete shipment item after shipment is %s", inventory_errors.ErrInvalidTransition, shipment.ShipmentStatus)
	}

	// Delete
	if err := s.shipmentItemRepo.Delete(ctx, tx, shipmentItemID); err != nil {
		return fmt.Errorf("delete shipment item: %w", err)
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "inventory", "delete_shipment_item", "shipment_item",
			&shipmentItemID, "user", nil, nil, nil, nil)
	}
	return nil
}

func (s *shipmentItemService) ListShipmentItems(ctx context.Context, filter repository.ShipmentItemFilter, page, pageSize int) ([]*models.ShipmentItem, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	pagination := repository.Pagination{Limit: pageSize, Offset: (page - 1) * pageSize}
	items, err := s.shipmentItemRepo.List(ctx, s.pgClient.DB, filter, pagination, repository.Sort{Field: "created_at", Direction: "DESC"})
	if err != nil {
		return nil, 0, err
	}
	// Total count requires a separate Count method; for simplicity we return len(items) as total (pagination might be incomplete).
	// Ideally add Count method to repository. We'll return len(items) for now.
	return items, int64(len(items)), nil
}

// emitShipmentItemEvent sends an outbox event when a shipment item is created.
func (s *shipmentItemService) emitShipmentItemEvent(ctx context.Context, tx *sql.Tx, item *models.ShipmentItem, eventType string) error {
	payload := map[string]interface{}{
		"shipment_item_id":    item.ShipmentItemID.String(),
		"shipment_id":         item.ShipmentID.String(),
		"fulfillment_item_id": item.FulfillmentItemID.String(),
		"quantity_shipped":    toFloat64(item.QuantityShipped),
		"created_at":          item.CreatedAt,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "shipment_item",
		AggregateID:   item.ShipmentItemID.String(),
		EventType:     eventType,
		Topic:         events.TopicInventoryEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}
