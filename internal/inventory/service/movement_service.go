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
	"auth-service/internal/inventory/models/enums"
	"auth-service/internal/inventory/repository"
)

// MovementService defines the public interface for movement operations.
type MovementService interface {
	CreateMovement(ctx context.Context, req CreateMovementRequest, idempotencyKey string) (*models.StockMovement, error)
	CancelMovement(ctx context.Context, req CancelMovementRequest, idempotencyKey string) error
	GetMovement(ctx context.Context, movementID uuid.UUID) (*models.StockMovement, error)
	ListMovements(ctx context.Context, filter repository.MovementFilter, page, pageSize int) ([]*models.StockMovement, int64, error)
}

type movementService struct {
	movementRepo    repository.MovementRepository
	balanceRepo     repository.StockBalanceRepository
	ledgerRepo      repository.StockLedgerRepository
	reservationRepo repository.ReservationRepository
	reservationSvc  ReservationService
	batchRepo       repository.BatchRepository
	itemRepo        repository.ItemRepository
	warehouseRepo   repository.WarehouseRepository
	pgClient        *client.PostgresClient
	outboxRepo      outbox.Repository
	idempotency     idempotency.Store
	audit           *audit.AuditService
	logger          *zap.Logger
}

// NewMovementService creates a new movement service.
func NewMovementService(
	movementRepo repository.MovementRepository,
	balanceRepo repository.StockBalanceRepository,
	ledgerRepo repository.StockLedgerRepository,
	reservationRepo repository.ReservationRepository,
	reservationSvc ReservationService,
	batchRepo repository.BatchRepository,
	itemRepo repository.ItemRepository,
	warehouseRepo repository.WarehouseRepository,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotency idempotency.Store,
	audit *audit.AuditService,
	logger *zap.Logger,
) MovementService {
	return &movementService{
		movementRepo:    movementRepo,
		balanceRepo:     balanceRepo,
		ledgerRepo:      ledgerRepo,
		reservationRepo: reservationRepo,
		reservationSvc:  reservationSvc,
		batchRepo:       batchRepo,
		itemRepo:        itemRepo,
		warehouseRepo:   warehouseRepo,
		pgClient:        pgClient,
		outboxRepo:      outboxRepo,
		idempotency:     idempotency,
		audit:           audit,
		logger:          logger.Named("movement_service"),
	}
}

// CreateMovement creates a stock movement and updates inventory.
func (s *movementService) CreateMovement(ctx context.Context, req CreateMovementRequest, idempotencyKey string) (*models.StockMovement, error) {
	logger := s.logger.With(zap.String("method", "CreateMovement"), zap.String("key", idempotencyKey))

	if err := validateMovement(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *models.StockMovement
	if err := s.idempotency.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached movement")
		return cached, nil
	}

	item, err := s.itemRepo.GetByID(ctx, tx, req.ItemID)
	if err != nil {
		return nil, fmt.Errorf("get item: %w", err)
	}
	if item.CompanyID != req.CompanyID {
		return nil, inventory_errors.ErrPermissionDenied
	}

	if req.MovementType == enums.MovementTypePurchaseIn || req.MovementType == enums.MovementTypeReturnIn {
		if !item.IsPurchasable {
			return nil, fmt.Errorf("%w: item %s is not purchasable", inventory_errors.ErrInvalidInput, item.SKU)
		}
	}
	if req.MovementType == enums.MovementTypeSalesOut || req.MovementType == enums.MovementTypeReturnOut {
		if !item.IsSellable {
			return nil, fmt.Errorf("%w: item %s is not sellable", inventory_errors.ErrInvalidInput, item.SKU)
		}
	}

	skipInventory := !item.TrackInventory

	movement := &models.StockMovement{
		MovementID:      uuid.New(),
		CompanyID:       req.CompanyID,
		MovementType:    req.MovementType,
		MovementDate:    req.MovementDate,
		WarehouseID:     req.WarehouseID,
		FromWarehouseID: req.FromWarehouseID,
		ItemID:          req.ItemID,
		BatchID:         req.BatchID,
		QuantityIn:      req.QuantityIn,
		QuantityOut:     req.QuantityOut,
		UnitCost:        req.UnitCost,
		Reason:          req.Reason,
		ReferenceType:   req.ReferenceType,
		ReferenceID:     req.ReferenceID,
		CreatedBy:       req.CreatedBy,
		Status:          "posted",
	}

	if err := s.movementRepo.CreateMovement(ctx, tx, movement); err != nil {
		return nil, fmt.Errorf("store movement: %w", err)
	}

	var oldAvailable, newAvailable float64
	if !skipInventory {
		if req.QuantityIn.GreaterThan(decimal.Zero) {
			oldAvailable, newAvailable, err = s.processInbound(ctx, tx, movement)
		} else {
			oldAvailable, newAvailable, err = s.processOutbound(ctx, tx, movement)
		}
		if err != nil {
			return nil, err
		}
	} else {
		logger.Info("inventory tracking disabled, skipping stock/ledger updates",
			zap.String("item_id", item.ItemID.String()),
			zap.String("sku", item.SKU))
		oldAvailable, newAvailable = 0, 0
	}

	if !skipInventory && req.QuantityOut.GreaterThan(decimal.Zero) &&
		req.ReferenceType != nil && *req.ReferenceType == "sales_order" &&
		req.ReferenceID != nil {
		reservation, err := s.reservationRepo.GetActiveByReference(ctx, tx, req.CompanyID, "sales_order", *req.ReferenceID)
		if err == nil {
			fulfillKey := idempotencyKey + ":fulfill:" + reservation.ReservationID.String()
			if err := s.reservationSvc.FulfillReservation(ctx, tx, reservation.ReservationID, req.CompanyID, fulfillKey); err != nil {
				logger.Warn("failed to auto-fulfill reservation", zap.Error(err))
			}
		} else if err != inventory_errors.ErrNotFound {
			logger.Warn("error fetching reservation by reference", zap.Error(err))
		}
	}

	_ = s.emitMovementEvent(ctx, tx, movement, events.EventMovementCreated)
	_ = s.emitStockChangeEvent(ctx, tx, movement, oldAvailable, newAvailable)
	_ = s.idempotency.Store(ctx, tx, idempotencyKey, movement)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.audit != nil {
		_ = s.audit.LogAction(ctx, nil, &req.CompanyID, "inventory", "create_movement", "movement",
			&movement.MovementID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"type": movement.MovementType,
				"in":   movement.QuantityIn,
				"out":  movement.QuantityOut,
			})
	}

	return movement, nil
}

// CancelMovementRequest defines input for cancelling a movement.
type CancelMovementRequest struct {
	MovementID  uuid.UUID
	CompanyID   uuid.UUID
	Reason      string
	CancelledBy *uuid.UUID
}

// CancelMovement reverses a previously created movement.
func (s *movementService) CancelMovement(ctx context.Context, req CancelMovementRequest, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "CancelMovement"), zap.String("movement_id", req.MovementID.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotency.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – cancellation already processed")
		return nil
	}

	original, err := s.movementRepo.GetByID(ctx, tx, req.MovementID)
	if err != nil {
		return err
	}
	if original.CompanyID != req.CompanyID {
		return inventory_errors.ErrPermissionDenied
	}

	alreadyCancelled, err := s.movementRepo.IsCancelled(ctx, tx, req.MovementID)
	if err != nil {
		return fmt.Errorf("check cancel status: %w", err)
	}
	if alreadyCancelled {
		return fmt.Errorf("%w: movement %s is already cancelled", inventory_errors.ErrConflict, req.MovementID)
	}

	item, err := s.itemRepo.GetByID(ctx, tx, original.ItemID)
	if err != nil {
		return fmt.Errorf("get item for compensation: %w", err)
	}
	skipInventory := !item.TrackInventory

	compensating := &models.StockMovement{
		MovementID:      uuid.New(),
		CompanyID:       original.CompanyID,
		MovementType:    getReverseMovementType(original.MovementType),
		MovementDate:    time.Now(),
		WarehouseID:     original.WarehouseID,
		FromWarehouseID: original.FromWarehouseID,
		ItemID:          original.ItemID,
		BatchID:         original.BatchID,
		UnitCost:        original.UnitCost,
		Reason:          stringPtr(fmt.Sprintf("Cancellation of %s: %s", original.MovementID, req.Reason)),
		ReferenceType:   stringPtr("cancellation"),
		ReferenceID:     &original.MovementID,
		CreatedBy:       req.CancelledBy,
		Status:          "posted",
	}

	if original.QuantityIn.GreaterThan(decimal.Zero) {
		compensating.QuantityOut = original.QuantityIn
	} else {
		compensating.QuantityIn = original.QuantityOut
	}

	if err := s.movementRepo.CreateMovement(ctx, tx, compensating); err != nil {
		return fmt.Errorf("create compensating movement: %w", err)
	}

	var oldAvail, newAvail float64
	if !skipInventory {
		if compensating.QuantityIn.GreaterThan(decimal.Zero) {
			oldAvail, newAvail, err = s.processInbound(ctx, tx, compensating)
		} else {
			oldAvail, newAvail, err = s.processOutbound(ctx, tx, compensating)
		}
		if err != nil {
			return err
		}
	} else {
		logger.Info("inventory tracking disabled for compensation, skipping stock/ledger updates")
	}

	_ = s.emitMovementEvent(ctx, tx, original, events.EventMovementCancelled)
	_ = s.emitStockChangeEvent(ctx, tx, compensating, oldAvail, newAvail)
	_ = s.idempotency.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.audit != nil {
		_ = s.audit.LogAction(ctx, nil, &req.CompanyID, "inventory", "cancel_movement", "movement",
			&req.MovementID, "user", req.CancelledBy, nil, nil, map[string]interface{}{
				"reason": req.Reason,
			})
	}

	return nil
}

// GetMovement retrieves a single movement by ID.
func (s *movementService) GetMovement(ctx context.Context, movementID uuid.UUID) (*models.StockMovement, error) {
	return s.movementRepo.GetByID(ctx, s.pgClient.DB, movementID)
}

// ListMovements returns paginated movements based on filter.
func (s *movementService) ListMovements(ctx context.Context, filter repository.MovementFilter, page, pageSize int) ([]*models.StockMovement, int64, error) {
	p := repository.Pagination{Limit: pageSize, Offset: (page - 1) * pageSize}
	items, err := s.movementRepo.List(ctx, s.pgClient.DB, filter, p, repository.Sort{Field: "movement_date", Direction: "DESC"})
	if err != nil {
		return nil, 0, err
	}
	total, err := s.movementRepo.Count(ctx, s.pgClient.DB, filter)
	return items, total, err
}

// ---------- validation ----------
func validateMovement(req CreateMovementRequest) error {
	// Required fields
	if req.CompanyID == uuid.Nil || req.ItemID == uuid.Nil || req.WarehouseID == uuid.Nil {
		return fmt.Errorf("%w: company_id, item_id, warehouse_id required", inventory_errors.ErrInvalidInput)
	}
	// Quantity direction
	if req.QuantityIn.IsZero() && req.QuantityOut.IsZero() {
		return fmt.Errorf("%w: quantity_in or quantity_out must be >0", inventory_errors.ErrInvalidInput)
	}
	if !req.QuantityIn.IsZero() && !req.QuantityOut.IsZero() {
		return fmt.Errorf("%w: cannot have both quantity_in and quantity_out", inventory_errors.ErrInvalidInput)
	}
	if !req.MovementType.IsValid() {
		return fmt.Errorf("%w: invalid movement_type", inventory_errors.ErrInvalidInput)
	}

	// movement_date validation
	if req.MovementDate.IsZero() {
		return fmt.Errorf("%w: movement_date is required", inventory_errors.ErrInvalidInput)
	}
	now := time.Now().UTC()
	// Disallow dates more than 7 days in the future (adjust as needed)
	if req.MovementDate.After(now.Add(7 * 24 * time.Hour)) {
		return fmt.Errorf("%w: movement_date cannot be more than 7 days in the future", inventory_errors.ErrInvalidInput)
	}
	// Optional: reject extremely old dates (e.g., before year 2000)
	if req.MovementDate.Before(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)) {
		return fmt.Errorf("%w: movement_date is too far in the past", inventory_errors.ErrInvalidInput)
	}

	// Unit cost validation – movement type specific
	switch req.MovementType {
	case enums.MovementTypePurchaseIn,
		enums.MovementTypeSalesOut,
		enums.MovementTypeReturnIn,
		enums.MovementTypeProductionIn:
		if req.UnitCost.LessThanOrEqual(decimal.Zero) {
			return fmt.Errorf("%w: unit_cost must be greater than zero for %s", inventory_errors.ErrInvalidInput, req.MovementType)
		}
	case enums.MovementTypeAdjustmentIn,
		enums.MovementTypeAdjustmentOut,
		enums.MovementTypeTransfer:
		// any cost allowed (including zero)
	case enums.MovementTypeReturnOut:
		if req.UnitCost.LessThan(decimal.Zero) {
			return fmt.Errorf("%w: unit_cost cannot be negative for %s", inventory_errors.ErrInvalidInput, req.MovementType)
		}
	default:
		if req.UnitCost.LessThanOrEqual(decimal.Zero) {
			return fmt.Errorf("%w: unit_cost must be greater than zero", inventory_errors.ErrInvalidInput)
		}
	}

	// from_warehouse_id rules
	switch req.MovementType {
	case enums.MovementTypePurchaseIn, enums.MovementTypeReturnIn, enums.MovementTypeAdjustmentIn, enums.MovementTypeProductionIn:
		if req.FromWarehouseID != nil {
			return fmt.Errorf("%w: from_warehouse_id must be null for %s", inventory_errors.ErrInvalidInput, req.MovementType)
		}
	case enums.MovementTypeTransfer:
		if req.FromWarehouseID == nil {
			return fmt.Errorf("%w: from_warehouse_id is required for transfer", inventory_errors.ErrInvalidInput)
		}
		if req.FromWarehouseID != nil && *req.FromWarehouseID == req.WarehouseID {
			return fmt.Errorf("%w: source and destination warehouses must be different for transfer", inventory_errors.ErrInvalidInput)
		}
	case enums.MovementTypeSalesOut, enums.MovementTypeAdjustmentOut, enums.MovementTypeReturnOut:
		if req.FromWarehouseID != nil {
			return fmt.Errorf("%w: from_warehouse_id must be null for %s", inventory_errors.ErrInvalidInput, req.MovementType)
		}
	}
	return nil
}

// ---------- stock processing helpers ----------
func (s *movementService) adjustBatchRemainingQty(ctx context.Context, tx *sql.Tx, movement *models.StockMovement) error {
	if movement.BatchID == nil {
		return nil
	}
	var delta float64
	if movement.QuantityIn.GreaterThan(decimal.Zero) {
		delta = toFloat64(movement.QuantityIn)
	} else {
		delta = -toFloat64(movement.QuantityOut)
	}
	return s.batchRepo.AdjustBatchQuantity(ctx, tx, *movement.BatchID, delta)
}

// processInbound handles addition of stock (purchase, production, return, adjustment_in)
func (s *movementService) processInbound(ctx context.Context, tx *sql.Tx, movement *models.StockMovement) (oldAvail, newAvail float64, err error) {
	qty, _ := movement.QuantityIn.Float64()

	balance, err := s.balanceRepo.GetByItemWarehouse(ctx, tx, movement.CompanyID, movement.WarehouseID, movement.ItemID, movement.BatchID)
	if err != nil && err != inventory_errors.ErrNotFound {
		return 0, 0, err
	}
	if balance != nil {
		oldAvail, _ = balance.AvailableQty.Float64()
	}

	if err := s.balanceRepo.IncreaseStock(ctx, tx, movement.CompanyID, movement.WarehouseID, movement.ItemID, movement.BatchID, qty); err != nil {
		return 0, 0, err
	}
	newAvail = oldAvail + qty

	ledger := &models.StockLedger{
		LedgerID:        uuid.New(),
		CompanyID:       movement.CompanyID,
		WarehouseID:     &movement.WarehouseID,
		ItemID:          movement.ItemID,
		BatchID:         movement.BatchID,
		MovementID:      movement.MovementID,
		TransactionDate: movement.MovementDate,
		QuantityIn:      movement.QuantityIn,
		UnitCost:        movement.UnitCost,
		RunningBalance:  decimal.NewFromFloat(newAvail),
		CreatedAt:       time.Now(),
	}
	if err := s.ledgerRepo.Create(ctx, tx, ledger); err != nil {
		return 0, 0, err
	}

	if err := s.adjustBatchRemainingQty(ctx, tx, movement); err != nil {
		return 0, 0, fmt.Errorf("adjust batch remaining_qty: %w", err)
	}

	return oldAvail, newAvail, nil
}

// processOutbound handles removal of stock with FIFO allocation.
// Negative stock is allowed only if BOTH item and warehouse permit it (AND logic).
func (s *movementService) processOutbound(ctx context.Context, tx *sql.Tx, movement *models.StockMovement) (oldAvail, newAvail float64, err error) {
	qtyNeeded := movement.QuantityOut
	if qtyNeeded.IsZero() {
		return 0, 0, fmt.Errorf("outbound quantity is zero")
	}

	item, err := s.itemRepo.GetByID(ctx, tx, movement.ItemID)
	if err != nil {
		return 0, 0, fmt.Errorf("get item: %w", err)
	}
	warehouse, err := s.warehouseRepo.GetByID(ctx, tx, movement.CompanyID, movement.WarehouseID)
	if err != nil {
		return 0, 0, fmt.Errorf("get warehouse: %w", err)
	}
	// ✅ FIX: require BOTH item AND warehouse to allow negative stock
	allowNegative := item.AllowNegativeStock && warehouse.AllowNegativeStock

	balance, err := s.balanceRepo.GetByItemWarehouse(ctx, tx, movement.CompanyID, movement.WarehouseID, movement.ItemID, movement.BatchID)
	if err != nil && err != inventory_errors.ErrNotFound {
		return 0, 0, err
	}
	if balance != nil {
		oldAvail, _ = balance.AvailableQty.Float64()
	} else {
		oldAvail = 0
	}

	if !allowNegative && oldAvail < toFloat64(qtyNeeded) {
		return 0, 0, fmt.Errorf("%w: required %.4f, available %.4f", inventory_errors.ErrInsufficientStock, toFloat64(qtyNeeded), oldAvail)
	}

	// Batch‑specific handling
	if movement.BatchID != nil {
		if err := s.balanceRepo.DecreaseStock(ctx, tx, movement.CompanyID, movement.WarehouseID, movement.ItemID, movement.BatchID, toFloat64(qtyNeeded)); err != nil {
			return 0, 0, fmt.Errorf("decrease stock for specific batch: %w", err)
		}
		newAvail = oldAvail - toFloat64(qtyNeeded)
		if err := s.batchRepo.AdjustBatchQuantity(ctx, tx, *movement.BatchID, -toFloat64(qtyNeeded)); err != nil {
			return 0, 0, fmt.Errorf("adjust batch remaining qty: %w", err)
		}
		ledgerEntry := &models.StockLedger{
			LedgerID:        uuid.New(),
			CompanyID:       movement.CompanyID,
			WarehouseID:     &movement.WarehouseID,
			ItemID:          movement.ItemID,
			BatchID:         movement.BatchID,
			MovementID:      movement.MovementID,
			TransactionDate: movement.MovementDate,
			QuantityOut:     movement.QuantityOut,
			UnitCost:        movement.UnitCost,
			RunningBalance:  decimal.NewFromFloat(newAvail),
			CreatedAt:       time.Now(),
		}
		if err := s.ledgerRepo.Create(ctx, tx, ledgerEntry); err != nil {
			return 0, 0, fmt.Errorf("create ledger entry: %w", err)
		}
		return oldAvail, newAvail, nil
	}

	// --- No batch: FIFO layer allocation ---
	remaining := qtyNeeded
	layers, err := s.ledgerRepo.GetAvailableLayersFIFO(ctx, tx, movement.CompanyID, movement.ItemID, &movement.WarehouseID)
	if err != nil {
		return 0, 0, fmt.Errorf("get FIFO layers: %w", err)
	}

	if len(layers) == 0 && !allowNegative {
		return 0, 0, fmt.Errorf("%w: no available stock layers", inventory_errors.ErrInsufficientStock)
	}

	// If no layers but negative allowed, just reduce balance and write a negative ledger entry
	if len(layers) == 0 && allowNegative {
		if err := s.balanceRepo.DecreaseStock(ctx, tx, movement.CompanyID, movement.WarehouseID, movement.ItemID, nil, toFloat64(remaining)); err != nil {
			return 0, 0, fmt.Errorf("decrease stock (negative allowed): %w", err)
		}
		newAvail = oldAvail - toFloat64(remaining)
		ledgerEntry := &models.StockLedger{
			LedgerID:        uuid.New(),
			CompanyID:       movement.CompanyID,
			WarehouseID:     &movement.WarehouseID,
			ItemID:          movement.ItemID,
			BatchID:         nil,
			MovementID:      movement.MovementID,
			TransactionDate: movement.MovementDate,
			QuantityOut:     movement.QuantityOut,
			UnitCost:        movement.UnitCost,
			RunningBalance:  decimal.NewFromFloat(newAvail),
			CreatedAt:       time.Now(),
		}
		if err := s.ledgerRepo.Create(ctx, tx, ledgerEntry); err != nil {
			return 0, 0, fmt.Errorf("create ledger entry: %w", err)
		}
		return oldAvail, newAvail, nil
	}

	// Consume layers – accumulate allocated quantity
	allocatedQty := decimal.Zero
	for _, layer := range layers {
		if remaining.IsZero() {
			break
		}
		avail := layer.RemainingQuantity
		if avail == nil {
			availDec := layer.QuantityIn.Sub(layer.QuantityOut)
			avail = &availDec
		}
		if avail.LessThanOrEqual(decimal.Zero) {
			continue
		}
		allocQty := decimal.Min(remaining, *avail)
		remaining = remaining.Sub(allocQty)
		allocatedQty = allocatedQty.Add(allocQty)

		allocation := &models.StockAllocation{
			AllocationID:   uuid.New(),
			CompanyID:      movement.CompanyID,
			MovementID:     movement.MovementID,
			SourceLedgerID: layer.LedgerID,
			Quantity:       allocQty,
			UnitCost:       layer.UnitCost,
			CreatedAt:      time.Now(),
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO stock_allocations (allocation_id, company_id, movement_id, source_ledger_id, quantity, unit_cost, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, allocation.AllocationID, allocation.CompanyID, allocation.MovementID, allocation.SourceLedgerID,
			allocQty, layer.UnitCost, allocation.CreatedAt)
		if err != nil {
			return 0, 0, fmt.Errorf("create allocation: %w", err)
		}

		newRemaining := avail.Sub(allocQty)
		if err := s.ledgerRepo.UpdateRemainingQuantity(ctx, tx, layer.LedgerID, newRemaining); err != nil {
			return 0, 0, fmt.Errorf("update remaining quantity: %w", err)
		}
	}

	// Decrease stock by the quantity covered by layers (if any)
	if allocatedQty.GreaterThan(decimal.Zero) {
		if err := s.balanceRepo.DecreaseStock(ctx, tx, movement.CompanyID, movement.WarehouseID, movement.ItemID, nil, toFloat64(allocatedQty)); err != nil {
			return 0, 0, fmt.Errorf("decrease stock for allocated quantity: %w", err)
		}
	}

	// Handle remaining quantity (negative stock) if allowed
	if remaining.GreaterThan(decimal.Zero) {
		if !allowNegative {
			return 0, 0, fmt.Errorf("%w: insufficient stock after FIFO allocation", inventory_errors.ErrInsufficientStock)
		}
		if err := s.balanceRepo.DecreaseStock(ctx, tx, movement.CompanyID, movement.WarehouseID, movement.ItemID, nil, toFloat64(remaining)); err != nil {
			return 0, 0, fmt.Errorf("decrease stock for negative remainder: %w", err)
		}
	}

	newAvail = oldAvail - toFloat64(qtyNeeded)

	// Create a summary ledger entry for the whole outbound movement (running balance)
	ledgerEntry := &models.StockLedger{
		LedgerID:        uuid.New(),
		CompanyID:       movement.CompanyID,
		WarehouseID:     &movement.WarehouseID,
		ItemID:          movement.ItemID,
		BatchID:         nil,
		MovementID:      movement.MovementID,
		TransactionDate: movement.MovementDate,
		QuantityOut:     movement.QuantityOut,
		UnitCost:        movement.UnitCost,
		RunningBalance:  decimal.NewFromFloat(newAvail),
		CreatedAt:       time.Now(),
	}
	if err := s.ledgerRepo.Create(ctx, tx, ledgerEntry); err != nil {
		return 0, 0, fmt.Errorf("create ledger entry: %w", err)
	}

	return oldAvail, newAvail, nil
}

// ---------- event emission ----------
func (s *movementService) emitMovementEvent(ctx context.Context, tx *sql.Tx, m *models.StockMovement, eventType string) error {
	payload := events.MovementPayload{
		MovementID:   m.MovementID.String(),
		CompanyID:    m.CompanyID.String(),
		MovementType: string(m.MovementType),
		ItemID:       m.ItemID.String(),
		WarehouseID:  m.WarehouseID.String(),
		QuantityIn:   toFloat64(m.QuantityIn),
		QuantityOut:  toFloat64(m.QuantityOut),
		UnitCost:     toFloat64(m.UnitCost),
		MovementDate: m.MovementDate,
	}
	data, _ := json.Marshal(payload)
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "stock_movement",
		AggregateID:   m.MovementID.String(),
		EventType:     eventType,
		Topic:         events.TopicInventoryEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}

func (s *movementService) emitStockChangeEvent(ctx context.Context, tx *sql.Tx, m *models.StockMovement, oldAvail, newAvail float64) error {
	delta := newAvail - oldAvail
	var batchIDStr *string
	if m.BatchID != nil {
		s := m.BatchID.String()
		batchIDStr = &s
	}
	payload := events.StockChangePayload{
		CompanyID:    m.CompanyID.String(),
		ItemID:       m.ItemID.String(),
		WarehouseID:  m.WarehouseID.String(),
		BatchID:      batchIDStr,
		OldAvailable: oldAvail,
		NewAvailable: newAvail,
		Delta:        delta,
		Timestamp:    time.Now(),
	}
	data, _ := json.Marshal(payload)
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "stock_balance",
		AggregateID:   m.ItemID.String(),
		EventType:     events.EventStockChanged,
		Topic:         events.TopicInventoryEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}

// getReverseMovementType returns the natural accounting opposite for a movement type.
func getReverseMovementType(original enums.MovementType) enums.MovementType {
	switch original {
	case enums.MovementTypePurchaseIn:
		return enums.MovementTypeReturnOut
	case enums.MovementTypeSalesOut:
		return enums.MovementTypeReturnIn
	case enums.MovementTypeAdjustmentIn:
		return enums.MovementTypeAdjustmentOut
	case enums.MovementTypeAdjustmentOut:
		return enums.MovementTypeAdjustmentIn
	case enums.MovementTypeReturnIn:
		return enums.MovementTypeAdjustmentOut // fallback – rare
	case enums.MovementTypeReturnOut:
		return enums.MovementTypeAdjustmentIn
	case enums.MovementTypeTransfer:
		return enums.MovementTypeAdjustmentOut
	case enums.MovementTypeProductionIn:
		return enums.MovementTypeAdjustmentOut
	default:
		return enums.MovementTypeAdjustmentOut
	}
}
