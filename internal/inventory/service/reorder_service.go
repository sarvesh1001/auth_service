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
	"auth-service/internal/inventory/repository"
)

type ReorderService interface {
	CheckAndCreateReorderOrders(ctx context.Context, companyID, itemID, warehouseID uuid.UUID, _ decimal.Decimal) error
	ProcessPendingOrders(ctx context.Context, companyID uuid.UUID) (int, error)
	UpdateOrderStatus(ctx context.Context, orderID uuid.UUID, newStatus string) error
}

type reorderService struct {
	itemRepo         repository.ItemRepository
	warehouseRepo    repository.WarehouseRepository
	reorderRepo      repository.ReorderOrderRepository
	balanceRepo      repository.StockBalanceRepository
	pgClient         *client.PostgresClient
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	logger           *zap.Logger
}

func NewReorderService(
	itemRepo repository.ItemRepository,
	warehouseRepo repository.WarehouseRepository,
	reorderRepo repository.ReorderOrderRepository,
	balanceRepo repository.StockBalanceRepository,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) ReorderService {
	return &reorderService{
		itemRepo:         itemRepo,
		warehouseRepo:    warehouseRepo,
		reorderRepo:      reorderRepo,
		balanceRepo:      balanceRepo,
		pgClient:         pgClient,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		logger:           logger.Named("reorder_service"),
	}
}

func (s *reorderService) CheckAndCreateReorderOrders(
	ctx context.Context,
	companyID, itemID, warehouseID uuid.UUID,
	_ decimal.Decimal, // client value ignored – we use actual stock from DB
) error {
	logger := s.logger.With(
		zap.String("company_id", companyID.String()),
		zap.String("item_id", itemID.String()),
		zap.String("warehouse_id", warehouseID.String()),
	)

	// 1. Validate item
	item, err := s.itemRepo.GetByID(ctx, s.pgClient.DB, itemID)
	if err != nil {
		if err == inventory_errors.ErrNotFound {
			return fmt.Errorf("item not found: %w", err)
		}
		return fmt.Errorf("get item: %w", err)
	}
	if item.CompanyID != companyID {
		return inventory_errors.ErrPermissionDenied
	}

	// 2. Validate warehouse
	warehouse, err := s.warehouseRepo.GetByID(ctx, s.pgClient.DB, companyID, warehouseID)
	if err != nil {
		if err == inventory_errors.ErrNotFound {
			return fmt.Errorf("warehouse not found: %w", err)
		}
		return fmt.Errorf("get warehouse: %w", err)
	}
	if warehouse.CompanyID != companyID {
		return inventory_errors.ErrPermissionDenied
	}

	// 3. Check reorder configuration
	if item.ReorderLevel == nil || item.ReorderQuantity == nil {
		logger.Debug("no reorder configuration, skipping")
		return nil // no error, no order, but not a skip reason? return nil means success with no order
	}
	reorderLevel := *item.ReorderLevel
	reorderQty := *item.ReorderQuantity

	// 4. Get actual available stock from DB
	availableQty, err := s.balanceRepo.GetByWarehouseAndItem(ctx, s.pgClient.DB, companyID, warehouseID, itemID)
	if err != nil {
		// If no stock balance record, treat as zero
		if errors.Is(err, inventory_errors.ErrNotFound) {
			availableQty = decimal.Zero
		} else {
			return fmt.Errorf("get stock balance: %w", err)
		}
	}

	// 5. Compare with reorder level
	if availableQty.GreaterThan(reorderLevel) {
		logger.Debug("available stock above reorder level",
			zap.Float64("available", toFloat64(availableQty)),
			zap.Float64("reorder_level", toFloat64(reorderLevel)))
		return inventory_errors.ErrReorderLevelNotMet
	}

	// 6. Check for existing open reorder order (pending or approved)
	openExists, err := s.reorderRepo.ExistsOpenForItem(ctx, s.pgClient.DB, companyID, itemID, warehouseID)
	if err != nil {
		return fmt.Errorf("check open reorder: %w", err)
	}
	if openExists {
		logger.Info("open reorder order already exists, skipping")
		return inventory_errors.ErrOpenReorderExists
	}

	// 7. Idempotency (optional, keep)
	idempotencyKey := fmt.Sprintf("reorder:%s:%s:%s:%d",
		companyID.String(), itemID.String(), warehouseID.String(), time.Now().Unix()/3600)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent reorder creation, skipping")
		return nil
	}

	// 8. Create reorder order
	reorderOrder := &models.ReorderOrder{
		ReorderOrderID: uuid.New(),
		CompanyID:      companyID,
		ItemID:         itemID,
		WarehouseID:    warehouseID,
		RequestedQty:   reorderQty,
		Status:         "pending",
		Source:         "auto",
		GeneratedAt:    time.Now(),
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		CreatedBy:      nil,
	}
	if err := s.reorderRepo.Create(ctx, tx, reorderOrder); err != nil {
		return fmt.Errorf("create reorder order: %w", err)
	}

	// 9. No cooldown – do NOT update item.LastReorderedAt

	// 10. Emit event
	if err := s.emitReorderEvent(ctx, tx, reorderOrder); err != nil {
		logger.Warn("failed to emit reorder event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	// 11. Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(
			ctx, nil, &companyID, "inventory", "create_reorder", "reorder_order",
			&reorderOrder.ReorderOrderID, "system", nil, nil, nil,
			map[string]interface{}{
				"item_id":       itemID.String(),
				"warehouse_id":  warehouseID.String(),
				"requested_qty": toFloat64(reorderQty),
				"available_qty": toFloat64(availableQty),
				"reorder_level": toFloat64(reorderLevel),
			},
		)
	}

	logger.Info("reorder order created", zap.String("reorder_order_id", reorderOrder.ReorderOrderID.String()))
	return nil
}

func (s *reorderService) UpdateOrderStatus(ctx context.Context, orderID uuid.UUID, newStatus string) error {
	order, err := s.reorderRepo.GetByID(ctx, s.pgClient.DB, orderID)
	if err != nil {
		return err
	}

	allowedStatuses := map[string]bool{
		"pending":   true,
		"approved":  true,
		"ordered":   true,
		"cancelled": true,
		"received":  true,
	}
	if !allowedStatuses[newStatus] {
		return fmt.Errorf("%w: %s", inventory_errors.ErrInvalidStatus, newStatus)
	}

	validTransitions := map[string][]string{
		"pending":   {"approved", "cancelled"},
		"approved":  {"ordered", "cancelled"},
		"ordered":   {"received", "cancelled"},
		"received":  {},
		"cancelled": {},
	}
	allowedNext, ok := validTransitions[order.Status]
	if !ok {
		return fmt.Errorf("%w: unknown current status %s", inventory_errors.ErrInvalidTransition, order.Status)
	}
	transitionAllowed := false
	for _, next := range allowedNext {
		if next == newStatus {
			transitionAllowed = true
			break
		}
	}
	if !transitionAllowed {
		return fmt.Errorf("%w: cannot transition from %s to %s", inventory_errors.ErrInvalidTransition, order.Status, newStatus)
	}

	return s.reorderRepo.UpdateStatus(ctx, s.pgClient.DB, orderID, newStatus)
}

func (s *reorderService) ProcessPendingOrders(ctx context.Context, companyID uuid.UUID) (int, error) {
	orders, err := s.reorderRepo.ListPending(ctx, s.pgClient.DB, companyID)
	if err != nil {
		return 0, fmt.Errorf("list pending: %w", err)
	}
	for _, order := range orders {
		// Here you would implement actual processing, e.g., create purchase order
		s.logger.Info("processing pending order", zap.String("order_id", order.ReorderOrderID.String()))
	}
	return len(orders), nil
}

func (s *reorderService) emitReorderEvent(ctx context.Context, tx *sql.Tx, order *models.ReorderOrder) error {
	payload := events.ReorderPayload{
		ReorderOrderID: order.ReorderOrderID.String(),
		CompanyID:      order.CompanyID.String(),
		ItemID:         order.ItemID.String(),
		WarehouseID:    order.WarehouseID.String(),
		RequestedQty:   toFloat64(order.RequestedQty),
		Status:         order.Status,
		Source:         order.Source,
		GeneratedAt:    order.GeneratedAt,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "reorder_order",
		AggregateID:   order.ReorderOrderID.String(),
		EventType:     events.EventReorderCreated,
		Topic:         events.TopicInventoryEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}
