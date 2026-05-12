package service

import (
	"auth-service/internal/inventory/models/enums"
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

// FulfillmentService orchestrates fulfillment from order to shipment,
// respecting each item's fulfillment policy and behavior flags.
type FulfillmentService interface {
	CreateFulfillmentOrder(ctx context.Context, req CreateFulfillmentOrderRequest, idempotencyKey string) (*models.FulfillmentOrder, error)
	AddFulfillmentItems(ctx context.Context, fulfillmentOrderID uuid.UUID, items []FulfillmentOrderItemRequest, idempotencyKey string) error
	ProcessFulfillmentOrder(ctx context.Context, fulfillmentOrderID uuid.UUID, idempotencyKey string) error
	AllocateStockToFulfillment(ctx context.Context, fulfillmentOrderID uuid.UUID, idempotencyKey string) error
	CreateShipment(ctx context.Context, req CreateShipmentRequest, idempotencyKey string) (*models.Shipment, error)
	Ship(ctx context.Context, shipmentID uuid.UUID, idempotencyKey string) error
	Deliver(ctx context.Context, shipmentID uuid.UUID, idempotencyKey string) error
	GetFulfillmentOrder(ctx context.Context, fulfillmentOrderID uuid.UUID) (*models.FulfillmentOrder, error)
	GetFulfillmentOrderItems(ctx context.Context, fulfillmentOrderID uuid.UUID) ([]*models.FulfillmentOrderItem, error)
}

type CreateFulfillmentOrderRequest struct {
	CompanyID     uuid.UUID
	ReferenceType string
	ReferenceID   uuid.UUID
	WarehouseID   uuid.UUID
	Status        string
	CreatedBy     *uuid.UUID
}

type FulfillmentOrderItemRequest struct {
	ItemID         uuid.UUID
	OrderedQty     decimal.Decimal
	FulfilledQty   decimal.Decimal
	BackorderedQty decimal.Decimal
}

type fulfillmentService struct {
	fulfillmentRepo  repository.FulfillmentRepository
	shipmentRepo     repository.ShipmentRepository
	reservationSvc   ReservationService
	inventorySvc     InventoryService
	productionSvc    ProductionService
	itemRepo         repository.ItemRepository
	warehouseRepo    repository.WarehouseRepository
	balanceRepo      repository.StockBalanceRepository
	pgClient         *client.PostgresClient
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	logger           *zap.Logger
}

func NewFulfillmentService(
	fulfillmentRepo repository.FulfillmentRepository,
	shipmentRepo repository.ShipmentRepository,
	reservationSvc ReservationService,
	inventorySvc InventoryService,
	productionSvc ProductionService,
	itemRepo repository.ItemRepository,
	warehouseRepo repository.WarehouseRepository,
	balanceRepo repository.StockBalanceRepository,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) FulfillmentService {
	return &fulfillmentService{
		fulfillmentRepo:  fulfillmentRepo,
		shipmentRepo:     shipmentRepo,
		reservationSvc:   reservationSvc,
		inventorySvc:     inventorySvc,
		productionSvc:    productionSvc,
		itemRepo:         itemRepo,
		warehouseRepo:    warehouseRepo,
		balanceRepo:      balanceRepo,
		pgClient:         pgClient,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		logger:           logger.Named("fulfillment_service"),
	}
}

// getAvailableStock returns the total available quantity for an item in a warehouse.
func (s *fulfillmentService) getAvailableStock(ctx context.Context, tx *sql.Tx, companyID, warehouseID, itemID uuid.UUID, batchID *uuid.UUID) (decimal.Decimal, error) {
	balance, err := s.balanceRepo.GetByItemWarehouse(ctx, tx, companyID, warehouseID, itemID, batchID)
	if err != nil {
		if err == inventory_errors.ErrNotFound {
			return decimal.Zero, nil
		}
		return decimal.Zero, err
	}
	return balance.AvailableQty, nil
}

func (s *fulfillmentService) CreateFulfillmentOrder(ctx context.Context, req CreateFulfillmentOrderRequest, idempotencyKey string) (*models.FulfillmentOrder, error) {
	logger := s.logger.With(zap.String("method", "CreateFulfillmentOrder"), zap.String("idempotency_key", idempotencyKey))

	if err := s.validateCreateFulfillmentOrder(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *models.FulfillmentOrder
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached fulfillment order")
		return cached, nil
	}

	order := &models.FulfillmentOrder{
		FulfillmentOrderID: uuid.New(),
		CompanyID:          req.CompanyID,
		ReferenceType:      req.ReferenceType,
		ReferenceID:        req.ReferenceID,
		WarehouseID:        req.WarehouseID,
		Status:             req.Status,
		CreatedAt:          time.Now(),
	}
	if order.Status == "" {
		order.Status = "pending"
	}

	if err := s.fulfillmentRepo.CreateOrder(ctx, tx, order); err != nil {
		return nil, fmt.Errorf("create fulfillment order: %w", err)
	}

	if err := s.emitFulfillmentEvent(ctx, tx, order, events.EventFulfillmentOrderCreated); err != nil {
		logger.Warn("failed to emit fulfillment order created event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, order)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "create_fulfillment_order", "fulfillment_order",
			&order.FulfillmentOrderID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"reference_type": req.ReferenceType,
				"reference_id":   req.ReferenceID.String(),
			})
	}

	logger.Info("fulfillment order created", zap.String("order_id", order.FulfillmentOrderID.String()))
	return order, nil
}

func (s *fulfillmentService) AddFulfillmentItems(ctx context.Context, fulfillmentOrderID uuid.UUID, items []FulfillmentOrderItemRequest, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "AddFulfillmentItems"), zap.String("idempotency_key", idempotencyKey))

	if len(items) == 0 {
		return fmt.Errorf("%w: at least one item required", inventory_errors.ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – already added")
		return nil
	}

	order, err := s.fulfillmentRepo.GetOrderByID(ctx, tx, fulfillmentOrderID)
	if err != nil {
		return err
	}

	modelItems := make([]*models.FulfillmentOrderItem, 0, len(items))
	for _, it := range items {
		if it.OrderedQty.LessThanOrEqual(decimal.Zero) {
			return fmt.Errorf("%w: ordered_qty must be positive for item %s", inventory_errors.ErrInvalidInput, it.ItemID)
		}
		modelItems = append(modelItems, &models.FulfillmentOrderItem{
			FulfillmentItemID:  uuid.New(),
			FulfillmentOrderID: fulfillmentOrderID,
			ItemID:             it.ItemID,
			OrderedQty:         it.OrderedQty,
			FulfilledQty:       it.FulfilledQty,
			BackorderedQty:     it.BackorderedQty,
		})
	}

	if err := s.fulfillmentRepo.AddOrderItems(ctx, tx, modelItems); err != nil {
		return fmt.Errorf("add fulfillment items: %w", err)
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &order.CompanyID, "inventory", "add_fulfillment_items", "fulfillment_order",
			&fulfillmentOrderID, "system", nil, nil, nil, map[string]interface{}{
				"items_count": len(items),
			})
	}

	logger.Info("fulfillment items added", zap.String("order_id", fulfillmentOrderID.String()), zap.Int("count", len(items)))
	return nil
}

func (s *fulfillmentService) ProcessFulfillmentOrder(ctx context.Context, fulfillmentOrderID uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "ProcessFulfillmentOrder"), zap.String("idempotency_key", idempotencyKey))

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

	order, err := s.fulfillmentRepo.GetOrderByID(ctx, tx, fulfillmentOrderID)
	if err != nil {
		return err
	}
	items, err := s.fulfillmentRepo.GetOrderItems(ctx, tx, fulfillmentOrderID)
	if err != nil {
		return fmt.Errorf("get fulfillment items: %w", err)
	}

	for _, item := range items {
		remaining := item.OrderedQty.Sub(item.FulfilledQty).Sub(item.BackorderedQty)
		if remaining.LessThanOrEqual(decimal.Zero) {
			continue
		}

		itm, err := s.itemRepo.GetByID(ctx, tx, item.ItemID)
		if err != nil {
			return fmt.Errorf("get item %s: %w", item.ItemID, err)
		}

		// If item does not track inventory, treat as service (immediately fulfill)
		if !itm.TrackInventory {
			if err := s.handleServiceOnly(ctx, tx, order, item, remaining, idempotencyKey); err != nil {
				return err
			}
			continue
		}

		switch itm.FulfillmentPolicy {
		case enums.FulfillmentInventoryRequired:
			if err := s.handleInventoryRequired(ctx, tx, order, item, remaining, idempotencyKey); err != nil {
				return err
			}
		case enums.FulfillmentAllowBackorder:
			if err := s.handleAllowBackorder(ctx, tx, order, item, remaining, idempotencyKey); err != nil {
				return err
			}
		case enums.FulfillmentMadeToOrder:
			if err := s.handleMadeToOrder(ctx, tx, order, item, remaining, idempotencyKey); err != nil {
				return err
			}
		case enums.FulfillmentDropship:
			if err := s.handleDropship(ctx, tx, order, item, remaining, idempotencyKey); err != nil {
				return err
			}
		case enums.FulfillmentServiceOnly:
			if err := s.handleServiceOnly(ctx, tx, order, item, remaining, idempotencyKey); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: unknown fulfillment policy %s", inventory_errors.ErrInvalidInput, itm.FulfillmentPolicy)
		}
	}

	if err := s.fulfillmentRepo.UpdateOrderStatus(ctx, tx, fulfillmentOrderID, "allocated"); err != nil {
		logger.Warn("failed to update order status", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("fulfillment order processed", zap.String("order_id", fulfillmentOrderID.String()))
	return nil
}

func (s *fulfillmentService) handleInventoryRequired(ctx context.Context, tx *sql.Tx, order *models.FulfillmentOrder, item *models.FulfillmentOrderItem, remaining decimal.Decimal, idempotencyKey string) error {
	expiresAt := time.Now().Add(48 * time.Hour)
	reservationReq := CreateReservationRequest{
		CompanyID:       order.CompanyID,
		ReservationType: "fulfillment",
		ReferenceID:     order.FulfillmentOrderID,
		WarehouseID:     order.WarehouseID,
		ItemID:          item.ItemID,
		BatchID:         nil,
		Quantity:        remaining,
		ExpiresAt:       &expiresAt,
		CreatedBy:       nil,
	}
	_, err := s.reservationSvc.CreateReservation(ctx, tx, reservationReq, idempotencyKey+":invreq:"+item.ItemID.String())
	return err
}

func (s *fulfillmentService) handleAllowBackorder(ctx context.Context, tx *sql.Tx, order *models.FulfillmentOrder, item *models.FulfillmentOrderItem, remaining decimal.Decimal, idempotencyKey string) error {
	available, err := s.getAvailableStock(ctx, tx, order.CompanyID, order.WarehouseID, item.ItemID, nil)
	if err != nil {
		return fmt.Errorf("get available stock for %s: %w", item.ItemID, err)
	}
	toReserve := decimal.Min(remaining, available)
	backorderQty := remaining.Sub(toReserve)

	if toReserve.GreaterThan(decimal.Zero) {
		expiresAt := time.Now().Add(48 * time.Hour)
		reservationReq := CreateReservationRequest{
			CompanyID:       order.CompanyID,
			ReservationType: "fulfillment",
			ReferenceID:     order.FulfillmentOrderID,
			WarehouseID:     order.WarehouseID,
			ItemID:          item.ItemID,
			BatchID:         nil,
			Quantity:        toReserve,
			ExpiresAt:       &expiresAt,
			CreatedBy:       nil,
		}
		if _, err := s.reservationSvc.CreateReservation(ctx, tx, reservationReq, idempotencyKey+":reserve:"+item.ItemID.String()); err != nil {
			return err
		}
	}

	if backorderQty.GreaterThan(decimal.Zero) {
		newBackorder := item.BackorderedQty.Add(backorderQty)
		if err := s.fulfillmentRepo.UpdateFulfilledQty(ctx, tx, item.FulfillmentItemID, item.FulfilledQty, newBackorder); err != nil {
			return fmt.Errorf("update backorder qty: %w", err)
		}
		s.emitBackorderEvent(ctx, tx, order, item.ItemID, backorderQty)
	}
	return nil
}

func (s *fulfillmentService) handleMadeToOrder(ctx context.Context, tx *sql.Tx, order *models.FulfillmentOrder, item *models.FulfillmentOrderItem, remaining decimal.Decimal, idempotencyKey string) error {
	// In a real implementation, you would fetch the active BOM ID for the product.
	// Here we use a placeholder – you must replace with actual BOM lookup.
	bomID, err := s.getActiveBOMForProduct(ctx, tx, order.CompanyID, item.ItemID)
	if err != nil {
		return fmt.Errorf("get active BOM for product %s: %w", item.ItemID, err)
	}

	prodOrderReq := CreateProductionOrderRequest{
		CompanyID:           order.CompanyID,
		OrderNumber:         fmt.Sprintf("MTO-%s-%s", order.FulfillmentOrderID.String()[:8], item.ItemID.String()[:8]),
		ProductItemID:       item.ItemID,
		BOMID:               bomID,
		PlannedQuantity:     remaining,
		PlannedStartDate:    nil,
		PlannedEndDate:      nil,
		WarehouseID:         order.WarehouseID,
		CreatedBy:           nil,
		SourceReferenceType: stringPtr("fulfillment"),
		SourceReferenceID:   &order.FulfillmentOrderID,
	}
	_, err = s.productionSvc.CreateProductionOrder(ctx, prodOrderReq, idempotencyKey+":mto:"+item.ItemID.String())
	if err != nil {
		return fmt.Errorf("create production order for MTO item %s: %w", item.ItemID, err)
	}
	return nil
}

// getActiveBOMForProduct is a placeholder – replace with actual BOM repository call.
func (s *fulfillmentService) getActiveBOMForProduct(ctx context.Context, tx *sql.Tx, companyID, productItemID uuid.UUID) (uuid.UUID, error) {
	// This should query the BOM repository for the active BOM.
	// For now, return uuid.Nil (you must implement).
	return uuid.Nil, nil
}

func (s *fulfillmentService) handleDropship(ctx context.Context, tx *sql.Tx, order *models.FulfillmentOrder, item *models.FulfillmentOrderItem, remaining decimal.Decimal, idempotencyKey string) error {
	payload := map[string]interface{}{
		"fulfillment_order_id": order.FulfillmentOrderID.String(),
		"company_id":           order.CompanyID.String(),
		"item_id":              item.ItemID.String(),
		"quantity":             remaining,
		"ship_to_address":      nil, // would come from reference document
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "fulfillment_order",
		AggregateID:   order.FulfillmentOrderID.String(),
		EventType:     events.EventDropshipRequired,
		Topic:         events.TopicInventoryEvents,
		Payload:       data,
	}
	if err := s.outboxRepo.Store(ctx, tx, event); err != nil {
		return fmt.Errorf("store dropship event: %w", err)
	}
	if err := s.fulfillmentRepo.UpdateFulfilledQty(ctx, tx, item.FulfillmentItemID, item.FulfilledQty.Add(remaining), item.BackorderedQty); err != nil {
		return fmt.Errorf("update fulfilled qty for dropship: %w", err)
	}
	return nil
}

func (s *fulfillmentService) handleServiceOnly(ctx context.Context, tx *sql.Tx, order *models.FulfillmentOrder, item *models.FulfillmentOrderItem, remaining decimal.Decimal, idempotencyKey string) error {
	if err := s.fulfillmentRepo.UpdateFulfilledQty(ctx, tx, item.FulfillmentItemID, item.FulfilledQty.Add(remaining), item.BackorderedQty); err != nil {
		return fmt.Errorf("update fulfilled qty for service: %w", err)
	}
	return nil
}

func (s *fulfillmentService) AllocateStockToFulfillment(ctx context.Context, fulfillmentOrderID uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "AllocateStockToFulfillment"), zap.String("idempotency_key", idempotencyKey))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – allocation already done")
		return nil
	}

	order, err := s.fulfillmentRepo.GetOrderByID(ctx, tx, fulfillmentOrderID)
	if err != nil {
		return err
	}
	items, err := s.fulfillmentRepo.GetOrderItems(ctx, tx, fulfillmentOrderID)
	if err != nil {
		return fmt.Errorf("get fulfillment items: %w", err)
	}

	for _, item := range items {
		remainingToAllocate := item.OrderedQty.Sub(item.FulfilledQty).Sub(item.BackorderedQty)
		if remainingToAllocate.LessThanOrEqual(decimal.Zero) {
			continue
		}

		// For items that do not track inventory, skip reservation
		itm, getErr := s.itemRepo.GetByID(ctx, tx, item.ItemID)
		if getErr != nil {
			return fmt.Errorf("get item %s: %w", item.ItemID, getErr)
		}
		if !itm.TrackInventory {
			// Immediately mark as fulfilled
			if err := s.fulfillmentRepo.UpdateFulfilledQty(ctx, tx, item.FulfillmentItemID, item.FulfilledQty.Add(remainingToAllocate), item.BackorderedQty); err != nil {
				return fmt.Errorf("update fulfilled qty for non-tracked item %s: %w", item.ItemID, err)
			}
			continue
		}

		expiresAt := time.Now().Add(48 * time.Hour)
		reservationReq := CreateReservationRequest{
			CompanyID:       order.CompanyID,
			ReservationType: "fulfillment",
			ReferenceID:     fulfillmentOrderID,
			WarehouseID:     order.WarehouseID,
			ItemID:          item.ItemID,
			BatchID:         nil,
			Quantity:        remainingToAllocate,
			ExpiresAt:       &expiresAt,
			CreatedBy:       nil,
		}
		itemKey := fmt.Sprintf("%s:item:%s", idempotencyKey, item.ItemID.String())
		_, err := s.reservationSvc.CreateReservation(ctx, tx, reservationReq, itemKey)
		if err != nil {
			return fmt.Errorf("create reservation for item %s: %w", item.ItemID, err)
		}
	}

	if err := s.fulfillmentRepo.UpdateOrderStatus(ctx, tx, fulfillmentOrderID, "allocated"); err != nil {
		logger.Warn("failed to update order status to allocated", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("stock allocated for fulfillment", zap.String("order_id", fulfillmentOrderID.String()))
	return nil
}
func (s *fulfillmentService) CreateShipment(ctx context.Context, req CreateShipmentRequest, idempotencyKey string) (*models.Shipment, error) {
	logger := s.logger.With(zap.String("method", "CreateShipment"), zap.String("idempotency_key", idempotencyKey))

	if err := s.validateCreateShipment(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *models.Shipment
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached shipment")
		return cached, nil
	}

	order, err := s.fulfillmentRepo.GetOrderByID(ctx, tx, req.FulfillmentOrderID)
	if err != nil {
		return nil, err
	}
	if order.CompanyID != req.CompanyID {
		return nil, inventory_errors.ErrPermissionDenied
	}

	exists, err := s.shipmentRepo.ExistsByShipmentNumber(ctx, tx, req.CompanyID, req.ShipmentNumber)
	if err != nil {
		return nil, fmt.Errorf("check shipment number: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("%w: shipment number %s already exists", inventory_errors.ErrDuplicate, req.ShipmentNumber)
	}

	shipment := &models.Shipment{
		ShipmentID:         uuid.New(),
		CompanyID:          req.CompanyID,
		FulfillmentOrderID: req.FulfillmentOrderID,
		WarehouseID:        req.WarehouseID,
		ShipmentNumber:     req.ShipmentNumber,
		ShipmentStatus:     req.ShipmentStatus,
		ShippedAt:          req.ShippedAt,
		DeliveredAt:        req.DeliveredAt,
		CreatedAt:          time.Now(),
	}
	if shipment.ShipmentStatus == "" {
		shipment.ShipmentStatus = "draft"
	}

	if err := s.shipmentRepo.Create(ctx, tx, shipment); err != nil {
		return nil, fmt.Errorf("create shipment: %w", err)
	}

	if err := s.emitShipmentEvent(ctx, tx, shipment, events.EventShipmentCreated); err != nil {
		logger.Warn("failed to emit shipment created event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, shipment)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "create_shipment", "shipment",
			&shipment.ShipmentID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"shipment_number":   req.ShipmentNumber,
				"fulfillment_order": req.FulfillmentOrderID.String(),
			})
	}

	logger.Info("shipment created", zap.String("shipment_id", shipment.ShipmentID.String()))
	return shipment, nil
}

func (s *fulfillmentService) Ship(ctx context.Context, shipmentID uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "Ship"), zap.String("idempotency_key", idempotencyKey))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – already shipped")
		return nil
	}

	shipment, err := s.shipmentRepo.GetByID(ctx, tx, shipmentID)
	if err != nil {
		return err
	}
	if shipment.ShipmentStatus != "draft" && shipment.ShipmentStatus != "allocated" {
		return fmt.Errorf("%w: cannot ship from status %s", inventory_errors.ErrInvalidTransition, shipment.ShipmentStatus)
	}

	order, err := s.fulfillmentRepo.GetOrderByID(ctx, tx, shipment.FulfillmentOrderID)
	if err != nil {
		return err
	}
	items, err := s.fulfillmentRepo.GetOrderItems(ctx, tx, order.FulfillmentOrderID)
	if err != nil {
		return fmt.Errorf("get fulfillment items: %w", err)
	}

	for _, item := range items {
		remainingToShip := item.OrderedQty.Sub(item.FulfilledQty).Sub(item.BackorderedQty)
		if remainingToShip.LessThanOrEqual(decimal.Zero) {
			continue
		}

		itm, err := s.itemRepo.GetByID(ctx, tx, item.ItemID)
		if err != nil {
			logger.Warn("failed to fetch item, skipping movement", zap.Error(err))
			continue
		}

		// If item does not require shipping (e.g., digital goods, services), just mark as fulfilled
		if !itm.RequiresShipping {
			newFulfilled := item.FulfilledQty.Add(remainingToShip)
			if err := s.fulfillmentRepo.UpdateFulfilledQty(ctx, tx, item.FulfillmentItemID, newFulfilled, item.BackorderedQty); err != nil {
				logger.Warn("failed to update fulfilled_qty for non-shippable item", zap.Error(err))
			}
			continue
		}

		// If item does not track inventory, mark as fulfilled (already handled in process, but double‑check)
		if !itm.TrackInventory {
			newFulfilled := item.FulfilledQty.Add(remainingToShip)
			if err := s.fulfillmentRepo.UpdateFulfilledQty(ctx, tx, item.FulfillmentItemID, newFulfilled, item.BackorderedQty); err != nil {
				logger.Warn("failed to update fulfilled_qty for non-tracked item", zap.Error(err))
			}
			continue
		}

		reservation, err := s.reservationSvc.GetActiveReservationByReference(
			ctx, tx, order.CompanyID, "fulfillment", order.FulfillmentOrderID, item.ItemID,
		)
		if err != nil && err != inventory_errors.ErrNotFound {
			return fmt.Errorf("get active reservation for item %s: %w", item.ItemID, err)
		}
		if err == inventory_errors.ErrNotFound {
			// No reservation – check available stock directly
			available, err := s.getAvailableStock(ctx, tx, order.CompanyID, shipment.WarehouseID, item.ItemID, nil)
			if err != nil {
				return fmt.Errorf("check available stock for item %s: %w", item.ItemID, err)
			}
			if available.LessThan(remainingToShip) {
				return fmt.Errorf("%w: insufficient stock for item %s (available %s, need %s)", inventory_errors.ErrInsufficientStock, item.ItemID, available.String(), remainingToShip.String())
			}
			reservation = nil // no reservation to link
		}

		unitCost := decimal.Zero
		if itm.StandardCost != nil {
			unitCost = *itm.StandardCost
		}

		movementReq := CreateMovementRequest{
			CompanyID:     order.CompanyID,
			MovementType:  enums.MovementTypeSalesOut,
			MovementDate:  time.Now(),
			WarehouseID:   shipment.WarehouseID,
			ItemID:        item.ItemID,
			QuantityOut:   remainingToShip,
			UnitCost:      unitCost,
			Reason:        stringPtr(fmt.Sprintf("Shipment %s", shipment.ShipmentNumber)),
			ReferenceType: stringPtr("shipment"),
			ReferenceID:   &shipment.ShipmentID,
			CreatedBy:     nil,
		}
		if reservation != nil {
			movementReq.ReservationID = &reservation.ReservationID
		}
		_, err = s.inventorySvc.CreateMovement(ctx, movementReq, idempotencyKey+":movement:"+item.ItemID.String())
		if err != nil {
			return fmt.Errorf("create movement for item %s: %w", item.ItemID, err)
		}

		if reservation != nil {
			if err := s.reservationSvc.PartialFulfillReservation(ctx, tx, reservation.ReservationID, order.CompanyID, remainingToShip, idempotencyKey+":partial:"+reservation.ReservationID.String()); err != nil {
				return fmt.Errorf("partial fulfill reservation for item %s: %w", item.ItemID, err)
			}
		}

		newFulfilled := item.FulfilledQty.Add(remainingToShip)
		if err := s.fulfillmentRepo.UpdateFulfilledQty(ctx, tx, item.FulfillmentItemID, newFulfilled, item.BackorderedQty); err != nil {
			logger.Warn("failed to update fulfilled_qty", zap.Error(err))
		}
	}

	now := time.Now()
	if err := s.shipmentRepo.UpdateStatus(ctx, tx, shipmentID, "shipped", &now, nil); err != nil {
		return fmt.Errorf("update shipment status to shipped: %w", err)
	}
	shipment.ShipmentStatus = "shipped"
	shipment.ShippedAt = &now

	allFulfilled := true
	for _, item := range items {
		if item.FulfilledQty.LessThan(item.OrderedQty) {
			allFulfilled = false
			break
		}
	}
	if allFulfilled {
		if err := s.fulfillmentRepo.UpdateOrderStatus(ctx, tx, order.FulfillmentOrderID, "shipped"); err != nil {
			logger.Warn("failed to update fulfillment order status to shipped", zap.Error(err))
		}
	}

	if err := s.emitShipmentEvent(ctx, tx, shipment, events.EventShipmentShipped); err != nil {
		logger.Warn("failed to emit shipment shipped event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &shipment.CompanyID, "inventory", "ship_shipment", "shipment",
			&shipmentID, "system", nil, nil, nil, nil)
	}

	logger.Info("shipment shipped", zap.String("shipment_id", shipmentID.String()))
	return nil
}

func (s *fulfillmentService) Deliver(ctx context.Context, shipmentID uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "Deliver"), zap.String("idempotency_key", idempotencyKey))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – already delivered")
		return nil
	}

	shipment, err := s.shipmentRepo.GetByID(ctx, tx, shipmentID)
	if err != nil {
		return err
	}
	if shipment.ShipmentStatus != "shipped" {
		return fmt.Errorf("%w: cannot deliver from status %s", inventory_errors.ErrInvalidTransition, shipment.ShipmentStatus)
	}

	now := time.Now()
	if err := s.shipmentRepo.UpdateStatus(ctx, tx, shipmentID, "delivered", nil, &now); err != nil {
		return fmt.Errorf("update shipment status to delivered: %w", err)
	}

	if err := s.emitShipmentEvent(ctx, tx, shipment, events.EventShipmentDelivered); err != nil {
		logger.Warn("failed to emit shipment delivered event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("shipment delivered", zap.String("shipment_id", shipmentID.String()))
	return nil
}

func (s *fulfillmentService) GetFulfillmentOrder(ctx context.Context, fulfillmentOrderID uuid.UUID) (*models.FulfillmentOrder, error) {
	return s.fulfillmentRepo.GetOrderByID(ctx, s.pgClient.DB, fulfillmentOrderID)
}

func (s *fulfillmentService) GetFulfillmentOrderItems(ctx context.Context, fulfillmentOrderID uuid.UUID) ([]*models.FulfillmentOrderItem, error) {
	return s.fulfillmentRepo.GetOrderItems(ctx, s.pgClient.DB, fulfillmentOrderID)
}

// Validation helpers

func (s *fulfillmentService) validateCreateFulfillmentOrder(req CreateFulfillmentOrderRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", inventory_errors.ErrInvalidInput)
	}
	if req.ReferenceType == "" {
		return fmt.Errorf("%w: reference_type required", inventory_errors.ErrInvalidInput)
	}
	if req.ReferenceID == uuid.Nil {
		return fmt.Errorf("%w: reference_id required", inventory_errors.ErrInvalidInput)
	}
	if req.WarehouseID == uuid.Nil {
		return fmt.Errorf("%w: warehouse_id required", inventory_errors.ErrInvalidInput)
	}
	return nil
}

func (s *fulfillmentService) validateCreateShipment(req CreateShipmentRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", inventory_errors.ErrInvalidInput)
	}
	if req.FulfillmentOrderID == uuid.Nil {
		return fmt.Errorf("%w: fulfillment_order_id required", inventory_errors.ErrInvalidInput)
	}
	if req.WarehouseID == uuid.Nil {
		return fmt.Errorf("%w: warehouse_id required", inventory_errors.ErrInvalidInput)
	}
	if req.ShipmentNumber == "" {
		return fmt.Errorf("%w: shipment_number required", inventory_errors.ErrInvalidInput)
	}
	return nil
}

// Event emission helpers

func (s *fulfillmentService) emitFulfillmentEvent(ctx context.Context, tx *sql.Tx, order *models.FulfillmentOrder, eventType string) error {
	payload := map[string]interface{}{
		"fulfillment_order_id": order.FulfillmentOrderID.String(),
		"company_id":           order.CompanyID.String(),
		"reference_type":       order.ReferenceType,
		"reference_id":         order.ReferenceID.String(),
		"warehouse_id":         order.WarehouseID.String(),
		"status":               order.Status,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "fulfillment_order",
		AggregateID:   order.FulfillmentOrderID.String(),
		EventType:     eventType,
		Topic:         events.TopicInventoryEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}

func (s *fulfillmentService) emitShipmentEvent(ctx context.Context, tx *sql.Tx, shipment *models.Shipment, eventType string) error {
	payload := map[string]interface{}{
		"shipment_id":          shipment.ShipmentID.String(),
		"company_id":           shipment.CompanyID.String(),
		"fulfillment_order_id": shipment.FulfillmentOrderID.String(),
		"warehouse_id":         shipment.WarehouseID.String(),
		"shipment_number":      shipment.ShipmentNumber,
		"shipment_status":      shipment.ShipmentStatus,
		"shipped_at":           shipment.ShippedAt,
		"delivered_at":         shipment.DeliveredAt,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "shipment",
		AggregateID:   shipment.ShipmentID.String(),
		EventType:     eventType,
		Topic:         events.TopicInventoryEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}

func (s *fulfillmentService) emitBackorderEvent(ctx context.Context, tx *sql.Tx, order *models.FulfillmentOrder, itemID uuid.UUID, qty decimal.Decimal) {
	payload := map[string]interface{}{
		"fulfillment_order_id": order.FulfillmentOrderID.String(),
		"company_id":           order.CompanyID.String(),
		"item_id":              itemID.String(),
		"backordered_qty":      qty,
	}
	data, _ := json.Marshal(payload)
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "fulfillment_order",
		AggregateID:   order.FulfillmentOrderID.String(),
		EventType:     events.EventFulfillmentBackorder,
		Topic:         events.TopicInventoryEvents,
		Payload:       data,
	}
	_ = s.outboxRepo.Store(ctx, tx, event)
}
