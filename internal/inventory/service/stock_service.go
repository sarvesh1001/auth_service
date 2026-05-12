package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models"
	"auth-service/internal/inventory/models/enums"
	"auth-service/internal/inventory/repository"
)

// StockService handles stock operations (excluding reservations)
type StockService interface {
	GetAvailableStock(ctx context.Context, companyID, warehouseID, itemID uuid.UUID, batchID *uuid.UUID) (decimal.Decimal, error)
	GetStockLevels(ctx context.Context, filter StockFilter) ([]*models.StockBalance, error)
	AdjustStock(ctx context.Context, req AdjustStockRequest, idempotencyKey string) (*models.StockMovement, error)
	GetBatchPicking(ctx context.Context, companyID, itemID, warehouseID uuid.UUID, requiredQty decimal.Decimal, strategy PickingStrategy) ([]BatchAllocation, error)
}

type PickingStrategy string

const (
	PickingStrategyFIFO PickingStrategy = "FIFO"
	PickingStrategyFEFO PickingStrategy = "FEFO"
)

type BatchAllocation struct {
	BatchID      uuid.UUID       `json:"batchId"`
	BatchNumber  string          `json:"batchNumber"`
	ExpiryDate   *time.Time      `json:"expiryDate,omitempty"`
	AllocatedQty decimal.Decimal `json:"allocatedQty"`
	UnitCost     decimal.Decimal `json:"unitCost"`
}

type StockFilter struct {
	CompanyID   uuid.UUID
	WarehouseID *uuid.UUID
	ItemID      *uuid.UUID
	BatchID     *uuid.UUID
	MinOnHand   *decimal.Decimal
	MinAvail    *decimal.Decimal
}

type AdjustStockRequest struct {
	CompanyID      uuid.UUID
	WarehouseID    uuid.UUID
	ItemID         uuid.UUID
	BatchID        *uuid.UUID
	Delta          decimal.Decimal
	Reason         string
	AdjustmentDate time.Time
	CreatedBy      *uuid.UUID
}

type stockService struct {
	balanceRepo      repository.StockBalanceRepository
	ledgerRepo       repository.StockLedgerRepository
	batchRepo        repository.BatchRepository
	movementRepo     repository.MovementRepository
	itemRepo         repository.ItemRepository
	warehouseRepo    repository.WarehouseRepository
	inventoryService InventoryService // New dependency
	pgClient         *client.PostgresClient
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	logger           *zap.Logger
}

func NewStockService(
	balanceRepo repository.StockBalanceRepository,
	ledgerRepo repository.StockLedgerRepository,
	batchRepo repository.BatchRepository,
	movementRepo repository.MovementRepository,
	itemRepo repository.ItemRepository,
	warehouseRepo repository.WarehouseRepository,
	inventoryService InventoryService, // Added
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) StockService {
	return &stockService{
		balanceRepo:      balanceRepo,
		ledgerRepo:       ledgerRepo,
		batchRepo:        batchRepo,
		movementRepo:     movementRepo,
		itemRepo:         itemRepo,
		warehouseRepo:    warehouseRepo,
		inventoryService: inventoryService,
		pgClient:         pgClient,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		logger:           logger.Named("stock_service"),
	}
}

func (s *stockService) toFloat64(d decimal.Decimal) float64 {
	f, _ := d.Float64()
	return f
}

// GetAvailableStock returns the available quantity for a specific item/warehouse/batch.
func (s *stockService) GetAvailableStock(ctx context.Context, companyID, warehouseID, itemID uuid.UUID, batchID *uuid.UUID) (decimal.Decimal, error) {
	balance, err := s.balanceRepo.GetByItemWarehouse(ctx, s.pgClient.DB, companyID, warehouseID, itemID, batchID)
	if err != nil {
		if err == inventory_errors.ErrNotFound {
			return decimal.Zero, nil
		}
		return decimal.Zero, fmt.Errorf("get available stock: %w", err)
	}
	return balance.AvailableQty, nil
}

// GetStockLevels returns stock balances based on filter.
func (s *stockService) GetStockLevels(ctx context.Context, filter StockFilter) ([]*models.StockBalance, error) {
	if filter.WarehouseID == nil && filter.ItemID == nil && filter.BatchID == nil {
		return nil, inventory_errors.ErrInsufficientFilter
	}
	repoFilter := repository.StockBalanceFilter{
		CompanyID:   filter.CompanyID,
		WarehouseID: filter.WarehouseID,
		ItemID:      filter.ItemID,
		BatchID:     filter.BatchID,
		MinOnHand:   filter.MinOnHand,
		MinAvail:    filter.MinAvail,
	}
	balances, err := s.balanceRepo.GetByFilters(ctx, s.pgClient.DB, repoFilter)
	if err != nil {
		return nil, fmt.Errorf("get stock levels: %w", err)
	}
	return balances, nil
}

// AdjustStock increases or decreases stock (adjustment movement) by delegating to InventoryService.
func (s *stockService) AdjustStock(ctx context.Context, req AdjustStockRequest, idempotencyKey string) (*models.StockMovement, error) {
	logger := s.logger.With(zap.String("method", "AdjustStock"), zap.String("idempotency_key", idempotencyKey))
	if req.Delta.IsZero() {
		return nil, fmt.Errorf("%w: delta must be non-zero", inventory_errors.ErrInvalidInput)
	}

	var movementType enums.MovementType
	var quantityIn, quantityOut decimal.Decimal
	if req.Delta.GreaterThan(decimal.Zero) {
		movementType = enums.MovementTypeAdjustmentIn
		quantityIn = req.Delta
	} else {
		movementType = enums.MovementTypeAdjustmentOut
		quantityOut = req.Delta.Neg()
	}

	// Get latest unit cost for this item/warehouse (for the movement record)
	latestCost, err := s.movementRepo.GetLatestUnitCost(ctx, s.pgClient.DB, req.CompanyID, req.ItemID, req.WarehouseID)
	if err != nil {
		logger.Warn("failed to get latest cost, using zero", zap.Error(err))
		latestCost = 0
	}

	// Prepare the movement request for InventoryService
	refType := "adjustment"
	reason := req.Reason
	movementReq := CreateMovementRequest{
		CompanyID:       req.CompanyID,
		MovementType:    movementType,
		MovementDate:    req.AdjustmentDate,
		WarehouseID:     req.WarehouseID,
		FromWarehouseID: nil,
		ItemID:          req.ItemID,
		BatchID:         req.BatchID,
		QuantityIn:      quantityIn,
		QuantityOut:     quantityOut,
		UnitCost:        decimal.NewFromFloat(latestCost),
		Reason:          &reason,
		ReferenceType:   &refType,
		ReferenceID:     nil,
		CreatedBy:       req.CreatedBy,
		Status:          "posted",
		ReservationID:   nil,
		ShipmentID:      nil,
		TransferOrderID: nil,
	}

	// Delegate to InventoryService – it will handle negative stock checks, FIFO, ledger, and allocations
	movement, err := s.inventoryService.CreateMovement(ctx, movementReq, idempotencyKey)
	if err != nil {
		return nil, fmt.Errorf("adjustment failed: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "adjust_stock", "stock_movement",
			&movement.MovementID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"delta":  req.Delta,
				"reason": req.Reason,
			})
	}
	logger.Info("stock adjusted via InventoryService", zap.String("movement_id", movement.MovementID.String()))
	return movement, nil
}

// GetBatchPicking suggests batch allocations for a given required quantity using FIFO/FEFO.
func (s *stockService) GetBatchPicking(ctx context.Context, companyID, itemID, warehouseID uuid.UUID, requiredQty decimal.Decimal, strategy PickingStrategy) ([]BatchAllocation, error) {
	if requiredQty.LessThanOrEqual(decimal.Zero) {
		return nil, fmt.Errorf("%w: required quantity must be positive", inventory_errors.ErrInvalidInput)
	}
	reqFloat := s.toFloat64(requiredQty)
	var candidates []*repository.BatchAllocationCandidate
	var err error
	switch strategy {
	case PickingStrategyFIFO:
		candidates, err = s.batchRepo.GetAvailableBatchesFIFO(ctx, s.pgClient.DB, companyID, itemID, warehouseID, reqFloat)
	case PickingStrategyFEFO:
		candidates, err = s.batchRepo.GetAvailableBatchesFEFO(ctx, s.pgClient.DB, companyID, itemID, warehouseID, reqFloat)
	default:
		return nil, fmt.Errorf("%w: unknown picking strategy", inventory_errors.ErrInvalidInput)
	}
	if err != nil {
		return nil, fmt.Errorf("get picking candidates: %w", err)
	}
	var result []BatchAllocation
	remaining := requiredQty
	for _, cand := range candidates {
		if remaining.LessThanOrEqual(decimal.Zero) {
			break
		}
		avail := decimal.NewFromFloat(cand.AvailableQty)
		alloc := decimal.Min(remaining, avail)
		result = append(result, BatchAllocation{
			BatchID:      cand.BatchID,
			BatchNumber:  cand.BatchNumber,
			ExpiryDate:   cand.ExpiryDate,
			AllocatedQty: alloc,
			UnitCost:     decimal.NewFromFloat(cand.CostPerUnit),
		})
		remaining = remaining.Sub(alloc)
	}
	if remaining.GreaterThan(decimal.Zero) {
		return nil, fmt.Errorf("%w: insufficient total available stock for required quantity", inventory_errors.ErrInsufficientStock)
	}
	return result, nil
}
