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

// CycleCountService handles inventory cycle counting workflows.
type CycleCountService interface {
	CreateCycleCount(ctx context.Context, req CreateCycleCountRequest, idempotencyKey string) (*models.InventoryCycleCount, error)
	StartCycleCount(ctx context.Context, cycleCountID, companyID uuid.UUID, startedBy *uuid.UUID, idempotencyKey string) error
	CompleteCycleCount(ctx context.Context, req CompleteCycleCountRequest, idempotencyKey string) error
	CancelCycleCount(ctx context.Context, cycleCountID, companyID uuid.UUID, cancelledBy *uuid.UUID, reason string, idempotencyKey string) error
	GetCycleCount(ctx context.Context, cycleCountID, companyID uuid.UUID) (*models.InventoryCycleCount, error)
	ListCycleCounts(ctx context.Context, filter repository.CycleCountFilter, page, pageSize int) ([]*models.InventoryCycleCount, int64, error)
}

type CreateCycleCountRequest struct {
	CompanyID        uuid.UUID
	WarehouseID      uuid.UUID
	ItemID           *uuid.UUID
	LocationID       *uuid.UUID
	CountType        string
	ScheduledDate    *time.Time
	ExpectedQuantity decimal.Decimal
	CreatedBy        *uuid.UUID
}

type CompleteCycleCountRequest struct {
	CycleCountID   uuid.UUID
	CompanyID      uuid.UUID
	ActualQuantity decimal.Decimal
	CountedBy      *uuid.UUID
	Notes          string
}

type cycleCountService struct {
	cycleCountRepo   repository.InventoryCycleCountRepository
	stockService     StockService
	itemRepo         repository.ItemRepository
	warehouseRepo    repository.WarehouseRepository
	balanceRepo      repository.StockBalanceRepository
	pgClient         *client.PostgresClient
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	logger           *zap.Logger
}

func NewCycleCountService(
	cycleCountRepo repository.InventoryCycleCountRepository,
	stockService StockService,
	itemRepo repository.ItemRepository,
	warehouseRepo repository.WarehouseRepository,
	balanceRepo repository.StockBalanceRepository,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) CycleCountService {
	return &cycleCountService{
		cycleCountRepo:   cycleCountRepo,
		stockService:     stockService,
		itemRepo:         itemRepo,
		warehouseRepo:    warehouseRepo,
		balanceRepo:      balanceRepo,
		pgClient:         pgClient,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		logger:           logger.Named("cycle_count_service"),
	}
}

func (s *cycleCountService) validateCreate(req CreateCycleCountRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", inventory_errors.ErrInvalidInput)
	}
	if req.WarehouseID == uuid.Nil {
		return fmt.Errorf("%w: warehouse_id required", inventory_errors.ErrInvalidInput)
	}
	if req.CountType == "" {
		return fmt.Errorf("%w: count_type required (full, random, abc)", inventory_errors.ErrInvalidInput)
	}
	if req.CountType != "full" && req.CountType != "random" && req.CountType != "abc" {
		return fmt.Errorf("%w: count_type must be 'full', 'random', or 'abc'", inventory_errors.ErrInvalidInput)
	}
	if req.ExpectedQuantity.LessThan(decimal.Zero) {
		return fmt.Errorf("%w: expected_quantity cannot be negative", inventory_errors.ErrInvalidInput)
	}
	if req.ItemID != nil {
		item, err := s.itemRepo.GetByID(context.Background(), s.pgClient.DB, *req.ItemID)
		if err != nil {
			return fmt.Errorf("item validation: %w", err)
		}
		if item.CompanyID != req.CompanyID {
			return inventory_errors.ErrPermissionDenied
		}
	}
	wh, err := s.warehouseRepo.GetByID(context.Background(), s.pgClient.DB, req.CompanyID, req.WarehouseID)
	if err != nil {
		return fmt.Errorf("warehouse validation: %w", err)
	}
	if wh.CompanyID != req.CompanyID {
		return inventory_errors.ErrPermissionDenied
	}
	return nil
}

func (s *cycleCountService) CreateCycleCount(ctx context.Context, req CreateCycleCountRequest, idempotencyKey string) (*models.InventoryCycleCount, error) {
	logger := s.logger.With(zap.String("method", "CreateCycleCount"), zap.String("idempotency_key", idempotencyKey))
	if err := s.validateCreate(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *models.InventoryCycleCount
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached cycle count")
		return cached, nil
	}

	// Check for duplicate (same company, warehouse, item, scheduled date)
	existing, err := s.cycleCountRepo.GetByUnique(ctx, tx, req.CompanyID, req.WarehouseID, req.ItemID, req.ScheduledDate)
	if err != nil && !errors.Is(err, inventory_errors.ErrNotFound) {
		return nil, fmt.Errorf("duplicate check: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("%w: cycle count already exists for this warehouse, item, and scheduled date", inventory_errors.ErrDuplicate)
	}

	expectedQty := req.ExpectedQuantity
	if expectedQty.IsZero() && req.ItemID != nil {
		balance, err := s.balanceRepo.GetTotalOnHand(ctx, tx, req.CompanyID, *req.ItemID, &req.WarehouseID)
		if err != nil {
			logger.Warn("failed to get current stock for expected quantity, using zero", zap.Error(err))
		} else {
			expectedQty = balance
		}
	}

	cycleCount := &models.InventoryCycleCount{
		CycleCountID:     uuid.New(),
		CompanyID:        req.CompanyID,
		WarehouseID:      req.WarehouseID,
		ItemID:           req.ItemID,
		LocationID:       req.LocationID,
		CountType:        req.CountType,
		Status:           "planned",
		ScheduledDate:    req.ScheduledDate,
		ExpectedQuantity: expectedQty,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
	// Note: InventoryCycleCount model currently lacks CreatedBy field.
	// If you need to store the creator, add `CreatedBy *uuid.UUID` to the model and database table.

	if err := s.cycleCountRepo.Create(ctx, tx, cycleCount); err != nil {
		return nil, fmt.Errorf("create cycle count: %w", err)
	}

	if err := s.emitCycleCountEvent(ctx, tx, cycleCount, events.EventCycleCountCreated); err != nil {
		logger.Warn("failed to emit cycle count created event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, cycleCount)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "create_cycle_count", "cycle_count",
			&cycleCount.CycleCountID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"warehouse_id": req.WarehouseID.String(),
				"count_type":   req.CountType,
			})
	}

	logger.Info("cycle count created", zap.String("cycle_count_id", cycleCount.CycleCountID.String()))
	return cycleCount, nil
}

func (s *cycleCountService) StartCycleCount(ctx context.Context, cycleCountID, companyID uuid.UUID, startedBy *uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "StartCycleCount"), zap.String("idempotency_key", idempotencyKey))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – already started")
		return nil
	}

	cc, err := s.cycleCountRepo.GetByID(ctx, tx, cycleCountID)
	if err != nil {
		return err
	}
	if cc.CompanyID != companyID {
		return inventory_errors.ErrPermissionDenied
	}
	if cc.Status != "planned" {
		return fmt.Errorf("%w: cannot start cycle count with status %s", inventory_errors.ErrInvalidTransition, cc.Status)
	}

	if err := s.cycleCountRepo.UpdateStatus(ctx, tx, cycleCountID, "in_progress", time.Now()); err != nil {
		return err
	}

	if err := s.emitCycleCountEvent(ctx, tx, cc, events.EventCycleCountStarted); err != nil {
		logger.Warn("failed to emit start event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "inventory", "start_cycle_count", "cycle_count",
			&cycleCountID, "user", startedBy, nil, nil, nil)
	}
	return nil
}

func (s *cycleCountService) CompleteCycleCount(ctx context.Context, req CompleteCycleCountRequest, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "CompleteCycleCount"), zap.String("idempotency_key", idempotencyKey))
	if req.CycleCountID == uuid.Nil || req.CompanyID == uuid.Nil {
		return inventory_errors.ErrInvalidInput
	}
	if req.ActualQuantity.LessThan(decimal.Zero) {
		return fmt.Errorf("%w: actual_quantity cannot be negative", inventory_errors.ErrInvalidInput)
	}

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

	cc, err := s.cycleCountRepo.GetByID(ctx, tx, req.CycleCountID)
	if err != nil {
		return err
	}
	if cc.CompanyID != req.CompanyID {
		return inventory_errors.ErrPermissionDenied
	}
	if cc.Status != "in_progress" {
		return fmt.Errorf("%w: cannot complete cycle count with status %s", inventory_errors.ErrInvalidTransition, cc.Status)
	}

	variance := req.ActualQuantity.Sub(cc.ExpectedQuantity)
	var adjustmentMovementID *uuid.UUID
	if !variance.IsZero() {
		if cc.ItemID == nil {
			return fmt.Errorf("%w: cannot adjust stock for cycle count without item_id", inventory_errors.ErrInvalidInput)
		}
		adjustReq := AdjustStockRequest{
			CompanyID:      cc.CompanyID,
			WarehouseID:    cc.WarehouseID,
			ItemID:         *cc.ItemID,
			BatchID:        nil,
			Delta:          variance,
			Reason:         fmt.Sprintf("Cycle count adjustment: %s", cc.CycleCountID.String()),
			AdjustmentDate: time.Now(),
			CreatedBy:      req.CountedBy,
		}
		movement, err := s.stockService.AdjustStock(ctx, adjustReq, idempotencyKey+":adj:"+cc.CycleCountID.String())
		if err != nil {
			return fmt.Errorf("failed to create adjustment movement: %w", err)
		}
		adjustmentMovementID = &movement.MovementID
	}

	if err := s.cycleCountRepo.CompleteCount(ctx, tx, req.CycleCountID, *req.CountedBy, req.ActualQuantity, adjustmentMovementID); err != nil {
		return fmt.Errorf("complete count: %w", err)
	}

	if err := s.emitCycleCountEvent(ctx, tx, cc, events.EventCycleCountCompleted); err != nil {
		logger.Warn("failed to emit completion event", zap.Error(err))
	}
	if adjustmentMovementID != nil {
		_ = s.emitCycleCountAdjustmentEvent(ctx, tx, cc, variance, *adjustmentMovementID)
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "complete_cycle_count", "cycle_count",
			&req.CycleCountID, "user", req.CountedBy, nil, nil, map[string]interface{}{
				"actual_quantity": req.ActualQuantity.String(),
				"expected":        cc.ExpectedQuantity.String(),
				"variance":        variance.String(),
			})
	}
	logger.Info("cycle count completed", zap.String("cycle_count_id", req.CycleCountID.String()), zap.String("variance", variance.String()))
	return nil
}

func (s *cycleCountService) CancelCycleCount(ctx context.Context, cycleCountID, companyID uuid.UUID, cancelledBy *uuid.UUID, reason string, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "CancelCycleCount"), zap.String("idempotency_key", idempotencyKey))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – already cancelled")
		return nil
	}

	cc, err := s.cycleCountRepo.GetByID(ctx, tx, cycleCountID)
	if err != nil {
		return err
	}
	if cc.CompanyID != companyID {
		return inventory_errors.ErrPermissionDenied
	}
	if cc.Status != "planned" && cc.Status != "in_progress" {
		return fmt.Errorf("%w: cannot cancel cycle count in status %s", inventory_errors.ErrInvalidTransition, cc.Status)
	}

	if err := s.cycleCountRepo.UpdateStatus(ctx, tx, cycleCountID, "cancelled", time.Now()); err != nil {
		return err
	}

	if err := s.emitCycleCountEvent(ctx, tx, cc, events.EventCycleCountCancelled); err != nil {
		logger.Warn("failed to emit cancellation event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "inventory", "cancel_cycle_count", "cycle_count",
			&cycleCountID, "user", cancelledBy, nil, nil, map[string]interface{}{
				"reason": reason,
			})
	}
	return nil
}

func (s *cycleCountService) GetCycleCount(ctx context.Context, cycleCountID, companyID uuid.UUID) (*models.InventoryCycleCount, error) {
	cc, err := s.cycleCountRepo.GetByID(ctx, s.pgClient.DB, cycleCountID)
	if err != nil {
		return nil, err
	}
	if cc.CompanyID != companyID {
		return nil, inventory_errors.ErrPermissionDenied
	}
	return cc, nil
}

func (s *cycleCountService) ListCycleCounts(ctx context.Context, filter repository.CycleCountFilter, page, pageSize int) ([]*models.InventoryCycleCount, int64, error) {
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
	sort := repository.Sort{Field: "scheduled_date", Direction: "DESC"}

	// Ensure filter has WarehouseID, otherwise the repo's ListByWarehouse will fail.
	if filter.WarehouseID == nil {
		return nil, 0, fmt.Errorf("%w: warehouse_id is required for listing", inventory_errors.ErrInvalidInput)
	}
	return s.cycleCountRepo.ListByWarehouse(ctx, s.pgClient.DB, filter.CompanyID, *filter.WarehouseID, filter, pagination, sort)
}

func (s *cycleCountService) emitCycleCountEvent(ctx context.Context, tx *sql.Tx, cc *models.InventoryCycleCount, eventType string) error {
	payload := map[string]interface{}{
		"cycle_count_id":    cc.CycleCountID.String(),
		"company_id":        cc.CompanyID.String(),
		"warehouse_id":      cc.WarehouseID.String(),
		"count_type":        cc.CountType,
		"status":            cc.Status,
		"scheduled_date":    cc.ScheduledDate,
		"expected_quantity": cc.ExpectedQuantity.String(),
		"actual_quantity":   cc.ActualQuantity.String(),
	}
	if cc.ItemID != nil {
		payload["item_id"] = cc.ItemID.String()
	}
	if cc.LocationID != nil {
		payload["location_id"] = cc.LocationID.String()
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "inventory_cycle_count",
		AggregateID:   cc.CycleCountID.String(),
		EventType:     eventType,
		Topic:         events.TopicInventoryEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}

func (s *cycleCountService) emitCycleCountAdjustmentEvent(ctx context.Context, tx *sql.Tx, cc *models.InventoryCycleCount, variance decimal.Decimal, movementID uuid.UUID) error {
	payload := map[string]interface{}{
		"cycle_count_id":         cc.CycleCountID.String(),
		"variance":               variance.String(),
		"adjustment_movement_id": movementID.String(),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "inventory_cycle_count",
		AggregateID:   cc.CycleCountID.String(),
		EventType:     events.EventCycleCountAdjusted,
		Topic:         events.TopicInventoryEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}
