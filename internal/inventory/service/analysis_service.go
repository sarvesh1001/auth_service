package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/inventory/events"
	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models"
	"auth-service/internal/inventory/repository"
)

// InventoryAnalyticsService processes events and updates analysis tables
type InventoryAnalyticsService interface {
	ProcessInventoryEvent(ctx context.Context, eventType string, payload []byte) error
}

type inventoryAnalyticsService struct {
	snapshotRepo repository.InventoryAnalysisRepository
	movementRepo repository.MovementRepository
	balanceRepo  repository.StockBalanceRepository
	ledgerRepo   repository.StockLedgerRepository
	reorderSvc   ReorderService
	pgClient     *client.PostgresClient
	logger       *zap.Logger
}

func NewInventoryAnalyticsService(
	snapshotRepo repository.InventoryAnalysisRepository,
	movementRepo repository.MovementRepository,
	balanceRepo repository.StockBalanceRepository,
	ledgerRepo repository.StockLedgerRepository,
	reorderSvc ReorderService,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) InventoryAnalyticsService {
	return &inventoryAnalyticsService{
		snapshotRepo: snapshotRepo,
		movementRepo: movementRepo,
		balanceRepo:  balanceRepo,
		ledgerRepo:   ledgerRepo,
		reorderSvc:   reorderSvc,
		pgClient:     pgClient,
		logger:       logger.Named("inventory_analytics"),
	}
}

// ProcessInventoryEvent handles all inventory domain events
func (s *inventoryAnalyticsService) ProcessInventoryEvent(ctx context.Context, eventType string, payload []byte) error {
	switch eventType {
	// Movement events
	case events.EventMovementCreated, events.EventMovementCancelled:
		var movPayload events.MovementPayload
		if err := json.Unmarshal(payload, &movPayload); err != nil {
			return fmt.Errorf("unmarshal movement: %w", err)
		}
		return s.onMovementEvent(ctx, movPayload, eventType)

	// Stock change events
	case events.EventStockChanged:
		var stockPayload events.StockChangePayload
		if err := json.Unmarshal(payload, &stockPayload); err != nil {
			return err
		}
		return s.onStockChanged(ctx, stockPayload)

	// Item events
	case events.EventItemCreated, events.EventItemUpdated:
		var itemPayload events.ItemPayload
		if err := json.Unmarshal(payload, &itemPayload); err != nil {
			return err
		}
		return s.onItemEvent(ctx, itemPayload)

	// Production events
	case events.EventProductionOrderCompleted:
		var prodPayload events.ProductionOrderPayload
		if err := json.Unmarshal(payload, &prodPayload); err != nil {
			return fmt.Errorf("unmarshal production order: %w", err)
		}
		return s.onProductionCompleted(ctx, prodPayload)

	// Optional: also handle other production state changes if needed
	case events.EventProductionOrderCreated, events.EventProductionOrderReleased,
		events.EventProductionOrderStarted, events.EventProductionOrderCancelled:
		var prodPayload events.ProductionOrderPayload
		if err := json.Unmarshal(payload, &prodPayload); err != nil {
			return fmt.Errorf("unmarshal production order: %w", err)
		}
		s.logger.Info("production order state changed",
			zap.String("order_id", prodPayload.ProductionOrderID),
			zap.String("status", prodPayload.Status))
		return nil

	default:
		s.logger.Debug("ignored inventory event", zap.String("event_type", eventType))
		return nil
	}
}

// onMovementEvent updates daily snapshot and movement daily summary (KPI)
func (s *inventoryAnalyticsService) onMovementEvent(ctx context.Context, mov events.MovementPayload, eventType string) error {
	date := mov.MovementDate.Truncate(24 * time.Hour)

	companyID, err := uuid.Parse(mov.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company ID: %w", err)
	}
	itemID, err := uuid.Parse(mov.ItemID)
	if err != nil {
		return fmt.Errorf("invalid item ID: %w", err)
	}
	warehouseID, err := uuid.Parse(mov.WarehouseID)
	if err != nil {
		return fmt.Errorf("invalid warehouse ID: %w", err)
	}

	// Get current stock balance after movement
	balance, err := s.balanceRepo.GetByItemWarehouse(ctx, s.pgClient.DB, companyID, warehouseID, itemID, nil)
	if err != nil && err != inventory_errors.ErrNotFound {
		return err
	}

	var available decimal.Decimal
	if balance != nil {
		available = balance.AvailableQty
	}

	// 1. Daily snapshot - construct with correct types
	snapshot := &models.DailyInventorySnapshot{
		SnapshotID:     uuid.New(),
		CompanyID:      companyID,
		SnapshotDate:   date,
		WarehouseID:    &warehouseID,
		ItemID:         itemID,
		QuantityOnHand: available,
		AvailableQty:   available,
		UnitCost:       decimal.NewFromFloat(mov.UnitCost),
		CreatedAt:      time.Now(),
	}
	if err := s.snapshotRepo.BulkInsertSnapshots(ctx, s.pgClient.DB, []*models.DailyInventorySnapshot{snapshot}); err != nil {
		s.logger.Warn("failed to insert daily snapshot", zap.Error(err))
	}

	// 2. Movement daily summary – WarehouseID is *uuid.UUID, use &warehouseID
	summary := &models.MovementDailySummary{
		SummaryID:        uuid.New(),
		CompanyID:        companyID,
		Date:             date,
		WarehouseID:      &warehouseID,
		ItemID:           itemID,
		MovementType:     mov.MovementType,
		TotalQuantityIn:  decimal.NewFromFloat(mov.QuantityIn),
		TotalQuantityOut: decimal.NewFromFloat(mov.QuantityOut),
		TransactionCount: 1,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
	if err := s.snapshotRepo.UpsertMovementSummary(ctx, s.pgClient.DB, summary); err != nil {
		s.logger.Warn("failed to upsert movement summary", zap.String("event_type", eventType), zap.Error(err))
	}
	return nil
}

// onStockChanged updates turnover metrics and triggers reorder check
func (s *inventoryAnalyticsService) onStockChanged(ctx context.Context, stock events.StockChangePayload) error {
	// Only negative delta (outbound) counts for consumption
	if stock.Delta >= 0 {
		return nil
	}

	date := stock.Timestamp.Truncate(24 * time.Hour)
	monthStart := time.Date(date.Year(), date.Month(), 1, 0, 0, 0, 0, time.UTC)
	consumedQty := decimal.NewFromFloat(-stock.Delta) // positive consumption

	companyID, err := uuid.Parse(stock.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company ID: %w", err)
	}
	warehouseID, err := uuid.Parse(stock.WarehouseID)
	if err != nil {
		return fmt.Errorf("invalid warehouse ID: %w", err)
	}
	itemID, err := uuid.Parse(stock.ItemID)
	if err != nil {
		return fmt.Errorf("invalid item ID: %w", err)
	}

	metrics := &models.InventoryTurnoverMetrics{
		TurnoverID:         uuid.New(),
		CompanyID:          companyID,
		YearMonth:          monthStart,
		WarehouseID:        &warehouseID,
		ItemID:             itemID,
		TotalConsumedQty:   consumedQty,
		TotalConsumedValue: decimal.Zero,
		AvgInventoryQty:    decimal.Zero,
		CreatedAt:          time.Now(),
	}
	if err := s.snapshotRepo.UpsertTurnoverMetrics(ctx, s.pgClient.DB, metrics); err != nil {
		s.logger.Warn("failed to upsert turnover metrics", zap.Error(err))
		// Continue execution – reorder check is still valuable
	}

	// ----- Reorder check -----
	newAvailableQty := decimal.NewFromFloat(stock.NewAvailable)

	if err := s.reorderSvc.CheckAndCreateReorderOrders(ctx, companyID, itemID, warehouseID, newAvailableQty); err != nil {
		s.logger.Error("reorder check failed", zap.Error(err))
		// Do not fail the whole event processing; just log.
	}
	return nil
}

// onItemEvent maintains item reference in analytics (e.g., item name cache)
func (s *inventoryAnalyticsService) onItemEvent(ctx context.Context, item events.ItemPayload) error {
	s.logger.Info("item event received", zap.String("item_id", item.ItemID), zap.String("event_type", "item_event"))
	return nil
}

// onProductionCompleted updates production metrics when an order is completed
func (s *inventoryAnalyticsService) onProductionCompleted(ctx context.Context, payload events.ProductionOrderPayload) error {
	date := time.Now().Truncate(24 * time.Hour)

	var efficiency *decimal.Decimal
	if payload.PlannedQuantity > 0 {
		eff := decimal.NewFromFloat((payload.ProducedQuantity / payload.PlannedQuantity) * 100)
		efficiency = &eff
	}

	companyID, err := uuid.Parse(payload.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company ID: %w", err)
	}
	productItemID, err := uuid.Parse(payload.ProductItemID)
	if err != nil {
		return fmt.Errorf("invalid product item ID: %w", err)
	}

	metric := &models.ProductionMetric{
		MetricID:            uuid.New(),
		CompanyID:           companyID,
		Date:                date,
		ProductItemID:       productItemID,
		TotalProducedQty:    decimal.NewFromFloat(payload.ProducedQuantity),
		TotalConsumedRawQty: decimal.Zero,
		Efficiency:          efficiency,
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}

	if err := s.snapshotRepo.UpsertProductionMetric(ctx, s.pgClient.DB, metric); err != nil {
		s.logger.Error("failed to upsert production metric",
			zap.String("order_id", payload.ProductionOrderID),
			zap.Error(err))
		return err
	}

	if efficiency != nil {
		s.logger.Info("production metric updated",
			zap.String("product_id", payload.ProductItemID),
			zap.Float64("produced_qty", payload.ProducedQuantity),
			zap.String("efficiency", efficiency.String()))
	} else {
		s.logger.Info("production metric updated",
			zap.String("product_id", payload.ProductItemID),
			zap.Float64("produced_qty", payload.ProducedQuantity))
	}
	return nil
}
