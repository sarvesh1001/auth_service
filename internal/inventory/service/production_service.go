package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
	"auth-service/internal/inventory/models/enums"
	"auth-service/internal/inventory/repository"
)

// allowed status transitions
var allowedTransitions = map[string][]string{
	"draft":     {"released", "cancelled"},
	"released":  {"started", "cancelled"},
	"started":   {"completed", "cancelled"},
	"completed": {},
	"cancelled": {},
}

func isValidStatusTransition(current, next string) bool {
	allowed, ok := allowedTransitions[current]
	if !ok {
		return false
	}
	for _, s := range allowed {
		if s == next {
			return true
		}
	}
	return false
}

// ProductionService defines all production order operations
type ProductionService interface {
	CreateProductionOrder(ctx context.Context, req CreateProductionOrderRequest, idempotencyKey string) (*models.ProductionOrder, error)
	ReleaseProductionOrder(ctx context.Context, orderID, companyID uuid.UUID, releasedBy *uuid.UUID, idempotencyKey string) error
	StartProduction(ctx context.Context, orderID, companyID uuid.UUID, startedBy *uuid.UUID, idempotencyKey string) error
	CompleteProduction(ctx context.Context, req CompleteProductionRequest, idempotencyKey string) error
	CancelProductionOrder(ctx context.Context, req CancelProductionOrderRequest, idempotencyKey string) error
	ConsumeComponent(ctx context.Context, req ConsumeComponentRequest, idempotencyKey string) error
	RecordScrap(ctx context.Context, req RecordScrapRequest, idempotencyKey string) error
	GetProductionOrder(ctx context.Context, orderID, companyID uuid.UUID) (*models.ProductionOrder, error)
	ListProductionOrders(ctx context.Context, filter repository.ProductionOrderFilter, page, pageSize int) ([]*models.ProductionOrder, int64, error)
}

// CreateMovementRequest is used internally to call InventoryService
type CreateMovementRequest struct {
	CompanyID       uuid.UUID
	MovementType    enums.MovementType
	MovementDate    time.Time
	WarehouseID     uuid.UUID
	FromWarehouseID *uuid.UUID
	ItemID          uuid.UUID
	BatchID         *uuid.UUID
	QuantityIn      decimal.Decimal
	QuantityOut     decimal.Decimal
	UnitCost        decimal.Decimal
	Reason          *string
	ReferenceType   *string
	ReferenceID     *uuid.UUID
	CreatedBy       *uuid.UUID
	Status          string
	ReservationID   *uuid.UUID
	ShipmentID      *uuid.UUID
	TransferOrderID *uuid.UUID
}

func stringPtr(s string) *string {
	return &s
}

// ---------- Request structs ----------
type CreateProductionOrderRequest struct {
	CompanyID           uuid.UUID
	OrderNumber         string
	ProductItemID       uuid.UUID
	BOMID               uuid.UUID
	PlannedQuantity     decimal.Decimal
	PlannedStartDate    *time.Time
	PlannedEndDate      *time.Time
	WarehouseID         uuid.UUID
	CreatedBy           *uuid.UUID
	SourceReferenceType *string
	SourceReferenceID   *uuid.UUID
}

type CompleteProductionRequest struct {
	ProductionOrderID uuid.UUID
	CompanyID         uuid.UUID
	ProducedQuantity  decimal.Decimal
	CompletedBy       *uuid.UUID
}

type CancelProductionOrderRequest struct {
	ProductionOrderID uuid.UUID
	CompanyID         uuid.UUID
	Reason            string
	CancelledBy       *uuid.UUID
}

type ConsumeComponentRequest struct {
	ProductionOrderID uuid.UUID
	CompanyID         uuid.UUID
	ComponentID       uuid.UUID // from production_order_components
	Quantity          decimal.Decimal
	BatchID           *uuid.UUID // optional, if batch-tracked
	ConsumedBy        *uuid.UUID
	Notes             string
}

type RecordScrapRequest struct {
	ProductionOrderID uuid.UUID
	CompanyID         uuid.UUID
	ComponentID       *uuid.UUID // may be nil if scrapping finished good
	ItemID            uuid.UUID
	BatchID           *uuid.UUID
	ScrapQuantity     decimal.Decimal
	Reason            string
	RecordedBy        *uuid.UUID
}

// ---------- Service implementation ----------
type productionService struct {
	prodRepo        repository.ProductionOrderRepository
	bomRepo         repository.BOMRepository
	itemRepo        repository.ItemRepository
	batchRepo       repository.BatchRepository
	consumptionRepo repository.ProductionOrderConsumptionRepository
	scrapRepo       repository.ProductionOrderScrapRepository
	stockService    StockService
	inventorySvc    InventoryService
	outboxRepo      outbox.Repository
	idempotency     idempotency.Store
	audit           *audit.AuditService
	pgClient        *client.PostgresClient
	logger          *zap.Logger
}

func NewProductionService(
	prodRepo repository.ProductionOrderRepository,
	bomRepo repository.BOMRepository,
	itemRepo repository.ItemRepository,
	batchRepo repository.BatchRepository,
	consumptionRepo repository.ProductionOrderConsumptionRepository,
	scrapRepo repository.ProductionOrderScrapRepository,
	stockService StockService,
	inventorySvc InventoryService,
	outboxRepo outbox.Repository,
	idempotency idempotency.Store,
	audit *audit.AuditService,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) ProductionService {
	return &productionService{
		prodRepo:        prodRepo,
		bomRepo:         bomRepo,
		itemRepo:        itemRepo,
		batchRepo:       batchRepo,
		consumptionRepo: consumptionRepo,
		scrapRepo:       scrapRepo,
		stockService:    stockService,
		inventorySvc:    inventorySvc,
		outboxRepo:      outboxRepo,
		idempotency:     idempotency,
		audit:           audit,
		pgClient:        pgClient,
		logger:          logger.Named("production_service"),
	}
}

// ---------- Create ----------
func (s *productionService) CreateProductionOrder(ctx context.Context, req CreateProductionOrderRequest, idempotencyKey string) (*models.ProductionOrder, error) {
	logger := s.logger.With(zap.String("method", "CreateProductionOrder"), zap.String("key", idempotencyKey))

	if err := s.validateCreateOrder(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *models.ProductionOrder
	if err := s.idempotency.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent request – returning cached order")
		return cached, nil
	}

	existing, _ := s.prodRepo.GetByOrderNumber(ctx, tx, req.CompanyID, req.OrderNumber)
	if existing != nil {
		return nil, fmt.Errorf("%w: order number %s already exists", inventory_errors.ErrDuplicate, req.OrderNumber)
	}

	bom, err := s.bomRepo.GetBOMByIDAndCompany(ctx, tx, req.BOMID, req.CompanyID)
	if err != nil {
		if errors.Is(err, inventory_errors.ErrNotFound) {
			return nil, fmt.Errorf("%w: BOM not found", inventory_errors.ErrInvalidInput)
		}
		return nil, fmt.Errorf("get BOM: %w", err)
	}
	if !bom.IsActive {
		return nil, fmt.Errorf("%w: BOM %s is inactive", inventory_errors.ErrInactiveBOM, bom.BOMID)
	}

	order := &models.ProductionOrder{
		ProductionOrderID:   uuid.New(),
		CompanyID:           req.CompanyID,
		OrderNumber:         req.OrderNumber,
		ProductItemID:       req.ProductItemID,
		BOMID:               req.BOMID,
		PlannedQuantity:     req.PlannedQuantity,
		ProducedQuantity:    decimal.Zero,
		Status:              "draft",
		PlannedStartDate:    req.PlannedStartDate,
		PlannedEndDate:      req.PlannedEndDate,
		WarehouseID:         req.WarehouseID,
		CreatedBy:           req.CreatedBy,
		SourceReferenceType: req.SourceReferenceType,
		SourceReferenceID:   req.SourceReferenceID,
	}
	if err := s.prodRepo.Create(ctx, tx, order); err != nil {
		return nil, fmt.Errorf("create order: %w", err)
	}
	if err := s.createPlannedComponents(ctx, tx, order); err != nil {
		logger.Warn("failed to store planned components", zap.Error(err))
	}
	if err := s.emitProductionEvent(ctx, tx, order, events.EventProductionOrderCreated); err != nil {
		logger.Warn("failed to emit creation event", zap.Error(err))
	}
	_ = s.idempotency.Store(ctx, tx, idempotencyKey, order)
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	if s.audit != nil {
		_ = s.audit.LogAction(ctx, nil, &req.CompanyID, "inventory", "create_production_order", "production_order",
			&order.ProductionOrderID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"order_number": order.OrderNumber,
				"planned_qty":  order.PlannedQuantity,
			})
	}
	return order, nil
}

func (s *productionService) createPlannedComponents(ctx context.Context, tx *sql.Tx, order *models.ProductionOrder) error {
	bomItems, err := s.bomRepo.GetBOMItems(ctx, tx, order.BOMID)
	if err != nil {
		return err
	}
	for _, bi := range bomItems {
		plannedQty := bi.Quantity.Mul(order.PlannedQuantity)
		comp := &models.ProductionOrderComponent{
			ComponentID:       uuid.New(),
			ProductionOrderID: order.ProductionOrderID,
			ItemID:            bi.ComponentItemID,
			PlannedQuantity:   plannedQty,
		}
		if err := s.prodRepo.AddComponent(ctx, tx, comp); err != nil {
			return err
		}
	}
	return nil
}

// ---------- Status transitions ----------
func (s *productionService) ReleaseProductionOrder(ctx context.Context, orderID, companyID uuid.UUID, releasedBy *uuid.UUID, idempotencyKey string) error {
	return s.updateOrderStatus(ctx, orderID, companyID, "released", releasedBy, idempotencyKey, events.EventProductionOrderReleased)
}

func (s *productionService) StartProduction(ctx context.Context, orderID, companyID uuid.UUID, startedBy *uuid.UUID, idempotencyKey string) error {
	s.logger.Info("StartProduction called", zap.String("order_id", orderID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotency.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		s.logger.Info("Idempotent start request, skipping")
		return nil
	}

	order, err := s.prodRepo.GetByID(ctx, tx, orderID, companyID)
	if err != nil {
		return err
	}
	if !isValidStatusTransition(order.Status, "started") {
		return fmt.Errorf("%w: cannot transition from %s to started", inventory_errors.ErrInvalidTransition, order.Status)
	}

	// Validate component availability using remaining to consume
	components, err := s.prodRepo.GetComponents(ctx, tx, orderID)
	if err != nil {
		return fmt.Errorf("get components: %w", err)
	}
	for _, comp := range components {
		remaining, err := s.prodRepo.GetRemainingToConsume(ctx, tx, comp.ComponentID)
		if err != nil {
			return fmt.Errorf("check remaining for component %s: %w", comp.ComponentID, err)
		}
		if remaining.GreaterThan(decimal.Zero) {
			// Check stock on hand
			var available decimal.Decimal
			query := `SELECT COALESCE(SUM(quantity_on_hand), 0) FROM stock_balances
                      WHERE company_id = $1 AND warehouse_id = $2 AND item_id = $3`
			err := tx.QueryRowContext(ctx, query, companyID, order.WarehouseID, comp.ItemID).Scan(&available)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("get stock for item %s: %w", comp.ItemID, err)
			}
			if available.LessThan(remaining) {
				return fmt.Errorf("%w: component %s requires %s, only %s available",
					inventory_errors.ErrInsufficientStock, comp.ItemID, remaining.String(), available.String())
			}
		}
	}

	order.Status = "started"
	now := time.Now()
	order.ActualStartTime = &now
	if err := s.prodRepo.Update(ctx, tx, order); err != nil {
		return err
	}
	if err := s.emitProductionEvent(ctx, tx, order, events.EventProductionOrderStarted); err != nil {
		s.logger.Warn("failed to emit started event", zap.Error(err))
	}
	_ = s.idempotency.Store(ctx, tx, idempotencyKey, true)
	return tx.Commit()
}

// ---------- ConsumeComponent (partial consumption) ----------
func (s *productionService) ConsumeComponent(ctx context.Context, req ConsumeComponentRequest, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "ConsumeComponent"), zap.String("order_id", req.ProductionOrderID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotency.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – consumption already processed")
		return nil
	}

	order, err := s.prodRepo.GetByID(ctx, tx, req.ProductionOrderID, req.CompanyID)
	if err != nil {
		return err
	}
	if order.Status != "started" {
		return fmt.Errorf("%w: consumption only allowed for started orders (current: %s)", inventory_errors.ErrInvalidTransition, order.Status)
	}

	component, err := s.prodRepo.GetComponentByID(ctx, tx, req.ComponentID)
	if err != nil {
		return err
	}
	if component.ProductionOrderID != req.ProductionOrderID {
		return fmt.Errorf("component does not belong to the production order")
	}

	remaining, err := s.prodRepo.GetRemainingToConsume(ctx, tx, req.ComponentID)
	if err != nil {
		return err
	}
	if req.Quantity.GreaterThan(remaining) {
		return fmt.Errorf("%w: cannot consume %s, only %s remaining", inventory_errors.ErrInvalidQuantity, req.Quantity.String(), remaining.String())
	}

	item, err := s.itemRepo.GetByID(ctx, tx, component.ItemID)
	if err != nil {
		return err
	}

	// Determine batch if batch-tracked
	var batchID *uuid.UUID
	if item.IsBatchTracked {
		if req.BatchID == nil {
			return fmt.Errorf("batch-tracked component requires batch_id")
		}
		batchID = req.BatchID
		// Verify batch has enough quantity
		var batchQty decimal.Decimal
		query := `SELECT remaining_qty FROM batches WHERE batch_id = $1 AND company_id = $2`
		err = tx.QueryRowContext(ctx, query, *batchID, req.CompanyID).Scan(&batchQty)
		if err != nil {
			return fmt.Errorf("get batch: %w", err)
		}
		if batchQty.LessThan(req.Quantity) {
			return fmt.Errorf("%w: batch %s has only %s available", inventory_errors.ErrInsufficientStock, batchID.String(), batchQty.String())
		}
	} else {
		if req.BatchID != nil {
			return fmt.Errorf("non-batch-tracked component must not provide batch_id")
		}
	}

	// Create consumption record first (to get its ID)
	consumption := &models.ProductionOrderComponentConsumption{
		ConsumptionID:     uuid.New(),
		CompanyID:         req.CompanyID,
		ComponentID:       req.ComponentID,
		ProductionOrderID: req.ProductionOrderID,
		ItemID:            component.ItemID,
		BatchID:           batchID,
		QuantityConsumed:  req.Quantity,
		ConsumedAt:        time.Now(),
		CreatedBy:         req.ConsumedBy,
		Notes:             &req.Notes,
	}
	// We'll fill MovementID after movement creation
	// So first create movement with reference to consumption ID
	reason := fmt.Sprintf("Production consumption for %s", order.OrderNumber)
	movementReq := CreateMovementRequest{
		CompanyID:     req.CompanyID,
		MovementType:  enums.MovementTypeProductionOut, // use dedicated type for consumption
		MovementDate:  time.Now(),
		WarehouseID:   order.WarehouseID,
		ItemID:        component.ItemID,
		BatchID:       batchID,
		QuantityOut:   req.Quantity,
		UnitCost:      decimal.Zero, // TODO: fetch actual cost
		Reason:        &reason,
		ReferenceType: stringPtr("production_consumption"),
		ReferenceID:   &consumption.ConsumptionID, // unique per consumption
		CreatedBy:     req.ConsumedBy,
		Status:        "posted",
	}
	movement, err := s.inventorySvc.CreateMovement(ctx, movementReq, idempotencyKey+":consume")
	if err != nil {
		return fmt.Errorf("create movement: %w", err)
	}
	consumption.MovementID = movement.MovementID

	if err := s.consumptionRepo.Create(ctx, tx, consumption); err != nil {
		return fmt.Errorf("save consumption: %w", err)
	}

	_ = s.idempotency.Store(ctx, tx, idempotencyKey, true)
	if err := tx.Commit(); err != nil {
		return err
	}

	s.logger.Info("component consumed", zap.String("component_id", req.ComponentID.String()), zap.String("qty", req.Quantity.String()))
	if s.audit != nil {
		_ = s.audit.LogAction(ctx, nil, &req.CompanyID, "inventory", "consume_component", "production_order",
			&order.ProductionOrderID, "user", req.ConsumedBy, nil, nil, map[string]interface{}{
				"component_id": req.ComponentID.String(),
				"quantity":     req.Quantity,
			})
	}
	return nil
}

// ---------- RecordScrap (waste) ----------
func (s *productionService) RecordScrap(ctx context.Context, req RecordScrapRequest, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "RecordScrap"), zap.String("order_id", req.ProductionOrderID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotency.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – scrap already recorded")
		return nil
	}

	order, err := s.prodRepo.GetByID(ctx, tx, req.ProductionOrderID, req.CompanyID)
	if err != nil {
		return err
	}
	if order.Status != "started" {
		return fmt.Errorf("%w: scrap only allowed for started orders (current: %s)", inventory_errors.ErrInvalidTransition, order.Status)
	}

	item, err := s.itemRepo.GetByID(ctx, tx, req.ItemID)
	if err != nil {
		return err
	}
	if item.IsBatchTracked && req.BatchID == nil {
		return fmt.Errorf("batch-tracked item requires batch_id")
	}

	// Create scrap record first (to get its ID)
	scrap := &models.ProductionOrderScrap{
		ScrapID:           uuid.New(),
		CompanyID:         req.CompanyID,
		ProductionOrderID: req.ProductionOrderID,
		ComponentID:       req.ComponentID,
		ItemID:            req.ItemID,
		BatchID:           req.BatchID,
		ScrapQuantity:     req.ScrapQuantity,
		Reason:            &req.Reason,
		RecordedAt:        time.Now(),
		CreatedBy:         req.RecordedBy,
	}
	// MovementID will be set after movement creation

	// Create stock movement for scrap
	reason := fmt.Sprintf("Production scrap on %s: %s", order.OrderNumber, req.Reason)
	movementReq := CreateMovementRequest{
		CompanyID:     req.CompanyID,
		MovementType:  enums.MovementTypeProductionScrap, // dedicated type
		MovementDate:  time.Now(),
		WarehouseID:   order.WarehouseID,
		ItemID:        req.ItemID,
		BatchID:       req.BatchID,
		QuantityOut:   req.ScrapQuantity,
		UnitCost:      decimal.Zero,
		Reason:        &reason,
		ReferenceType: stringPtr("production_scrap"),
		ReferenceID:   &scrap.ScrapID, // unique per scrap
		CreatedBy:     req.RecordedBy,
		Status:        "posted",
	}
	movement, err := s.inventorySvc.CreateMovement(ctx, movementReq, idempotencyKey+":scrap")
	if err != nil {
		return fmt.Errorf("create scrap movement: %w", err)
	}
	scrap.MovementID = movement.MovementID

	if err := s.scrapRepo.Create(ctx, tx, scrap); err != nil {
		return fmt.Errorf("save scrap: %w", err)
	}

	_ = s.idempotency.Store(ctx, tx, idempotencyKey, true)
	if err := tx.Commit(); err != nil {
		return err
	}

	s.logger.Info("scrap recorded", zap.String("item_id", req.ItemID.String()), zap.String("qty", req.ScrapQuantity.String()))
	if s.audit != nil {
		_ = s.audit.LogAction(ctx, nil, &req.CompanyID, "inventory", "record_scrap", "production_order",
			&order.ProductionOrderID, "user", req.RecordedBy, nil, nil, map[string]interface{}{
				"item_id":  req.ItemID.String(),
				"quantity": req.ScrapQuantity,
				"reason":   req.Reason,
			})
	}
	return nil
}

// ---------- CompleteProduction (using aggregated consumptions) ----------
func (s *productionService) CompleteProduction(ctx context.Context, req CompleteProductionRequest, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "CompleteProduction"), zap.String("order_id", req.ProductionOrderID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotency.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – completion already processed")
		return nil
	}

	order, err := s.prodRepo.GetByID(ctx, tx, req.ProductionOrderID, req.CompanyID)
	if err != nil {
		return err
	}
	if !isValidStatusTransition(order.Status, "completed") {
		return fmt.Errorf("%w: cannot transition from %s to completed", inventory_errors.ErrInvalidTransition, order.Status)
	}
	if req.ProducedQuantity.GreaterThan(order.PlannedQuantity) {
		return fmt.Errorf("%w: produced quantity %s exceeds planned %s",
			inventory_errors.ErrInvalidProductionCompletion, req.ProducedQuantity.String(), order.PlannedQuantity.String())
	}
	if req.ProducedQuantity.IsZero() {
		return fmt.Errorf("produced quantity cannot be zero")
	}

	// Verify all components are fully consumed (remaining = 0)
	canComplete, err := s.prodRepo.CanCompleteOrder(ctx, tx, req.ProductionOrderID)
	if err != nil {
		return fmt.Errorf("check completion readiness: %w", err)
	}
	if !canComplete {
		return fmt.Errorf("%w: cannot complete order – some components still have remaining quantity", inventory_errors.ErrInvalidTransition)
	}

	// Create finished good inbound movement
	inboundMovementReq := CreateMovementRequest{
		CompanyID:     req.CompanyID,
		MovementType:  enums.MovementTypeProductionIn,
		MovementDate:  time.Now(),
		WarehouseID:   order.WarehouseID,
		ItemID:        order.ProductItemID,
		QuantityIn:    req.ProducedQuantity,
		UnitCost:      decimal.Zero,
		Reason:        stringPtr(fmt.Sprintf("Production of %s", order.OrderNumber)),
		ReferenceType: stringPtr("production"),
		ReferenceID:   &order.ProductionOrderID,
		CreatedBy:     req.CompletedBy,
		Status:        "posted",
	}
	if _, err := s.inventorySvc.CreateMovement(ctx, inboundMovementReq, idempotencyKey+":fg"); err != nil {
		return fmt.Errorf("create finished good movement: %w", err)
	}

	order.ProducedQuantity = req.ProducedQuantity
	order.Status = "completed"
	now := time.Now()
	order.ActualEndTime = &now
	if err := s.prodRepo.Update(ctx, tx, order); err != nil {
		return err
	}
	if err := s.emitProductionEvent(ctx, tx, order, events.EventProductionOrderCompleted); err != nil {
		logger.Warn("failed to emit completion event", zap.Error(err))
	}
	_ = s.idempotency.Store(ctx, tx, idempotencyKey, true)
	if err := tx.Commit(); err != nil {
		return err
	}
	if s.audit != nil {
		_ = s.audit.LogAction(ctx, nil, &req.CompanyID, "inventory", "complete_production", "production_order",
			&order.ProductionOrderID, "user", req.CompletedBy, nil, nil, map[string]interface{}{
				"produced_qty": req.ProducedQuantity,
			})
	}
	return nil
}

// ---------- Cancel ----------
func (s *productionService) CancelProductionOrder(ctx context.Context, req CancelProductionOrderRequest, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "CancelProductionOrder"), zap.String("order_id", req.ProductionOrderID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotency.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		return nil
	}
	order, err := s.prodRepo.GetByID(ctx, tx, req.ProductionOrderID, req.CompanyID)
	if err != nil {
		return err
	}
	if !isValidStatusTransition(order.Status, "cancelled") {
		return fmt.Errorf("%w: cannot transition from %s to cancelled", inventory_errors.ErrInvalidTransition, order.Status)
	}
	order.Status = "cancelled"
	if err := s.prodRepo.Update(ctx, tx, order); err != nil {
		return err
	}
	if err := s.emitProductionEvent(ctx, tx, order, events.EventProductionOrderCancelled); err != nil {
		logger.Warn("failed to emit cancellation event", zap.Error(err))
	}
	_ = s.idempotency.Store(ctx, tx, idempotencyKey, true)
	if err := tx.Commit(); err != nil {
		return err
	}
	if s.audit != nil {
		_ = s.audit.LogAction(ctx, nil, &req.CompanyID, "inventory", "cancel_production", "production_order",
			&req.ProductionOrderID, "user", req.CancelledBy, nil, nil, map[string]interface{}{
				"reason": req.Reason,
			})
	}
	return nil
}

// ---------- Queries ----------
func (s *productionService) GetProductionOrder(ctx context.Context, orderID, companyID uuid.UUID) (*models.ProductionOrder, error) {
	return s.prodRepo.GetByID(ctx, s.pgClient.DB, orderID, companyID)
}

func (s *productionService) ListProductionOrders(ctx context.Context, filter repository.ProductionOrderFilter, page, pageSize int) ([]*models.ProductionOrder, int64, error) {
	p := repository.Pagination{Limit: pageSize, Offset: (page - 1) * pageSize}
	items, err := s.prodRepo.List(ctx, s.pgClient.DB, filter, p, repository.Sort{Field: "created_at", Direction: "DESC"})
	if err != nil {
		return nil, 0, err
	}
	total, err := s.prodRepo.Count(ctx, s.pgClient.DB, filter)
	return items, total, err
}

// ---------- Helpers ----------
func (s *productionService) validateCreateOrder(req CreateProductionOrderRequest) error {
	if req.CompanyID == uuid.Nil || req.ProductItemID == uuid.Nil || req.BOMID == uuid.Nil || req.WarehouseID == uuid.Nil {
		return fmt.Errorf("%w: missing required fields", inventory_errors.ErrInvalidInput)
	}
	if req.OrderNumber == "" {
		return fmt.Errorf("%w: order_number required", inventory_errors.ErrInvalidInput)
	}
	if req.PlannedQuantity.LessThanOrEqual(decimal.Zero) {
		return fmt.Errorf("%w: planned_quantity must be positive", inventory_errors.ErrInvalidInput)
	}
	return nil
}

func (s *productionService) updateOrderStatus(ctx context.Context, orderID, companyID uuid.UUID, newStatus string, actor *uuid.UUID, idempotencyKey, eventType string) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var processed bool
	if err := s.idempotency.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		return nil
	}
	order, err := s.prodRepo.GetByID(ctx, tx, orderID, companyID)
	if err != nil {
		return err
	}
	if !isValidStatusTransition(order.Status, newStatus) {
		return fmt.Errorf("%w: cannot transition from %s to %s", inventory_errors.ErrInvalidTransition, order.Status, newStatus)
	}
	order.Status = newStatus
	if err := s.prodRepo.Update(ctx, tx, order); err != nil {
		return err
	}
	if err := s.emitProductionEvent(ctx, tx, order, eventType); err != nil {
		s.logger.Warn("failed to emit status event", zap.Error(err))
	}
	_ = s.idempotency.Store(ctx, tx, idempotencyKey, true)
	return tx.Commit()
}

func (s *productionService) emitProductionEvent(ctx context.Context, tx *sql.Tx, order *models.ProductionOrder, eventType string) error {
	payload := events.ProductionOrderPayload{
		ProductionOrderID: order.ProductionOrderID.String(),
		CompanyID:         order.CompanyID.String(),
		OrderNumber:       order.OrderNumber,
		ProductItemID:     order.ProductItemID.String(),
		BOMID:             order.BOMID.String(),
		PlannedQuantity:   toFloat64(order.PlannedQuantity),
		ProducedQuantity:  toFloat64(order.ProducedQuantity),
		Status:            order.Status,
		WarehouseID:       order.WarehouseID.String(),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "production_order",
		AggregateID:   order.ProductionOrderID.String(),
		EventType:     eventType,
		Topic:         events.TopicInventoryEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}
