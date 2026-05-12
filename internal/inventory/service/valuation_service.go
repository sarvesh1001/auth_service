package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models/enums"
	"auth-service/internal/inventory/repository"
)

type ValuationRequest struct {
	CompanyID   uuid.UUID
	ItemID      uuid.UUID
	WarehouseID *uuid.UUID
	AsOfDate    time.Time
	Method      enums.ValuationMethod
}

type ValuationResult struct {
	ItemID      uuid.UUID             `json:"itemId"`
	WarehouseID *uuid.UUID            `json:"warehouseId,omitempty"`
	Quantity    decimal.Decimal       `json:"quantity"`
	UnitCost    decimal.Decimal       `json:"unitCost"`
	TotalValue  decimal.Decimal       `json:"totalValue"`
	MethodUsed  enums.ValuationMethod `json:"methodUsed"`
}

type ValuationService interface {
	GetItemValuation(ctx context.Context, req ValuationRequest) (*ValuationResult, error)
	GetCompanyValuation(ctx context.Context, companyID uuid.UUID, asOfDate time.Time) ([]*ValuationResult, error)
	GetCOGS(ctx context.Context, companyID, itemID uuid.UUID, from, to time.Time) (decimal.Decimal, error)
	CreateValuationSnapshot(ctx context.Context, companyID uuid.UUID, valuationDate time.Time) error
}

type valuationService struct {
	itemRepo     repository.ItemRepository
	balanceRepo  repository.StockBalanceRepository
	ledgerRepo   repository.StockLedgerRepository
	movementRepo repository.MovementRepository
	batchRepo    repository.BatchRepository
	pgClient     *client.PostgresClient
	logger       *zap.Logger
}

func NewValuationService(
	itemRepo repository.ItemRepository,
	balanceRepo repository.StockBalanceRepository,
	ledgerRepo repository.StockLedgerRepository,
	movementRepo repository.MovementRepository,
	batchRepo repository.BatchRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) ValuationService {
	return &valuationService{
		itemRepo:     itemRepo,
		balanceRepo:  balanceRepo,
		ledgerRepo:   ledgerRepo,
		movementRepo: movementRepo,
		batchRepo:    batchRepo,
		pgClient:     pgClient,
		logger:       logger.Named("valuation_service"),
	}
}

func (s *valuationService) GetItemValuation(ctx context.Context, req ValuationRequest) (*ValuationResult, error) {
	if req.CompanyID == uuid.Nil || req.ItemID == uuid.Nil {
		return nil, fmt.Errorf("%w: company_id and item_id are required", inventory_errors.ErrInvalidInput)
	}
	if req.AsOfDate.IsZero() {
		req.AsOfDate = time.Now().UTC()
	}

	var method enums.ValuationMethod
	if req.Method != "" && req.Method.IsValid() {
		method = req.Method
	} else {
		item, err := s.itemRepo.GetByID(ctx, s.pgClient.DB, req.ItemID)
		if err != nil {
			return nil, fmt.Errorf("get item for method: %w", err)
		}
		method = item.ValuationMethod
	}

	totalQty, err := s.balanceRepo.GetTotalOnHand(ctx, s.pgClient.DB, req.CompanyID, req.ItemID, req.WarehouseID)
	if err != nil {
		return nil, fmt.Errorf("get total on-hand: %w", err)
	}

	if totalQty.IsZero() {
		return &ValuationResult{
			ItemID:      req.ItemID,
			WarehouseID: req.WarehouseID,
			Quantity:    decimal.Zero,
			UnitCost:    decimal.Zero,
			TotalValue:  decimal.Zero,
			MethodUsed:  method,
		}, nil
	}

	var unitCost decimal.Decimal
	switch method {
	case enums.ValuationMethodFIFO:
		unitCost, err = s.calcFIFOUnitCost(ctx, req)
	case enums.ValuationMethodWeightedAverage:
		unitCost, err = s.calcWeightedAverageUnitCost(ctx, req)
	case enums.ValuationMethodStandardCost:
		unitCost, err = s.getStandardCost(ctx, req.ItemID)
	default:
		return nil, fmt.Errorf("unsupported valuation method: %s", method)
	}
	if err != nil {
		return nil, err
	}

	totalValue := totalQty.Mul(unitCost)
	s.logger.Debug("valuation computed",
		zap.String("item_id", req.ItemID.String()),
		zap.String("method", string(method)),
		zap.String("quantity", totalQty.String()),
		zap.String("unit_cost", unitCost.String()),
	)

	return &ValuationResult{
		ItemID:      req.ItemID,
		WarehouseID: req.WarehouseID,
		Quantity:    totalQty,
		UnitCost:    unitCost,
		TotalValue:  totalValue,
		MethodUsed:  method,
	}, nil
}

func (s *valuationService) GetCompanyValuation(ctx context.Context, companyID uuid.UUID, asOfDate time.Time) ([]*ValuationResult, error) {
	items, err := s.itemRepo.GetAllActiveItems(ctx, s.pgClient.DB, companyID)
	if err != nil {
		return nil, fmt.Errorf("get active items: %w", err)
	}

	results := make([]*ValuationResult, 0, len(items))
	for _, item := range items {
		req := ValuationRequest{
			CompanyID: companyID,
			ItemID:    item.ItemID,
			AsOfDate:  asOfDate,
			Method:    item.ValuationMethod,
		}
		res, err := s.GetItemValuation(ctx, req)
		if err != nil {
			s.logger.Warn("failed to value item, skipping",
				zap.String("item_id", item.ItemID.String()),
				zap.Error(err))
			continue
		}
		results = append(results, res)
	}
	return results, nil
}

func (s *valuationService) GetCOGS(ctx context.Context, companyID, itemID uuid.UUID, from, to time.Time) (decimal.Decimal, error) {
	return s.movementRepo.GetCOGSByPeriod(ctx, s.pgClient.DB, companyID, itemID, from, to)
}

// CreateValuationSnapshot creates a snapshot of inventory valuations for a given company and date.
// Returns ErrConflict if a snapshot already exists for that company and date.
func (s *valuationService) CreateValuationSnapshot(ctx context.Context, companyID uuid.UUID, valuationDate time.Time) error {
	// Check if snapshot already exists
	var exists bool
	checkQuery := `SELECT EXISTS(SELECT 1 FROM inventory_valuations WHERE company_id = $1 AND valuation_date = $2)`
	err := s.pgClient.DB.QueryRowContext(ctx, checkQuery, companyID, valuationDate).Scan(&exists)
	if err != nil {
		return fmt.Errorf("check existing snapshot: %w", err)
	}
	if exists {
		return fmt.Errorf("%w: snapshot already exists for company %s on %s",
			inventory_errors.ErrConflict, companyID, valuationDate.Format("2006-01-02"))
	}

	results, err := s.GetCompanyValuation(ctx, companyID, valuationDate)
	if err != nil {
		return fmt.Errorf("get company valuation: %w", err)
	}
	if len(results) == 0 {
		s.logger.Info("no active items to snapshot", zap.String("company_id", companyID.String()))
		return nil
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Delete any old snapshots (safety, though we already checked existence)
	_, err = tx.ExecContext(ctx, `
        DELETE FROM inventory_valuations
        WHERE company_id = $1 AND valuation_date = $2
    `, companyID, valuationDate)
	if err != nil {
		return fmt.Errorf("delete old snapshots: %w", err)
	}

	stmt, err := tx.PrepareContext(ctx, `
        INSERT INTO inventory_valuations (
            valuation_id, company_id, valuation_date, item_id, warehouse_id,
            quantity, unit_cost, valuation_method, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
    `)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, res := range results {
		_, err = stmt.ExecContext(ctx,
			uuid.New(), companyID, valuationDate, res.ItemID, res.WarehouseID,
			res.Quantity, res.UnitCost, string(res.MethodUsed),
		)
		if err != nil {
			return fmt.Errorf("insert snapshot for item %s: %w", res.ItemID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit snapshot tx: %w", err)
	}

	s.logger.Info("valuation snapshot created",
		zap.String("company_id", companyID.String()),
		zap.Time("date", valuationDate),
		zap.Int("items", len(results)))
	return nil
}

func (s *valuationService) calcFIFOUnitCost(ctx context.Context, req ValuationRequest) (decimal.Decimal, error) {
	layers, err := s.ledgerRepo.GetFIFOLayers(ctx, s.pgClient.DB, req.CompanyID, req.ItemID, req.WarehouseID, req.AsOfDate)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get FIFO layers: %w", err)
	}
	if len(layers) == 0 {
		return s.getAverageCostFromBatches(ctx, req)
	}

	var totalQty, totalCost decimal.Decimal
	for _, l := range layers {
		totalQty = totalQty.Add(l.RemainingQty)
		totalCost = totalCost.Add(l.RemainingQty.Mul(l.UnitCost))
	}
	if totalQty.IsZero() {
		return decimal.Zero, nil
	}
	return totalCost.Div(totalQty), nil
}

func (s *valuationService) calcWeightedAverageUnitCost(ctx context.Context, req ValuationRequest) (decimal.Decimal, error) {
	query := `
        SELECT COALESCE(SUM(quantity_in * unit_cost), 0), COALESCE(SUM(quantity_in), 0)
        FROM stock_movements
        WHERE company_id = $1
          AND item_id = $2
          AND ($3::uuid IS NULL OR warehouse_id = $3)
          AND movement_date <= $4
          AND quantity_in > 0
    `
	var totalCost, totalQty float64
	err := s.pgClient.DB.QueryRowContext(ctx, query, req.CompanyID, req.ItemID, req.WarehouseID, req.AsOfDate).Scan(&totalCost, &totalQty)
	if err != nil {
		return decimal.Zero, fmt.Errorf("weighted avg query: %w", err)
	}
	if totalQty == 0 {
		return decimal.Zero, nil
	}
	unitCost := decimal.NewFromFloat(totalCost).Div(decimal.NewFromFloat(totalQty))
	return unitCost, nil
}

func (s *valuationService) getStandardCost(ctx context.Context, itemID uuid.UUID) (decimal.Decimal, error) {
	item, err := s.itemRepo.GetByID(ctx, s.pgClient.DB, itemID)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get item for standard cost: %w", err)
	}
	if item.StandardCost == nil {
		return decimal.Zero, nil
	}
	return *item.StandardCost, nil
}

func (s *valuationService) getAverageCostFromBatches(ctx context.Context, req ValuationRequest) (decimal.Decimal, error) {
	batches, err := s.batchRepo.GetBatchesWithStock(ctx, s.pgClient.DB, req.CompanyID, req.ItemID, req.WarehouseID)
	if err != nil {
		return decimal.Zero, err
	}
	var totalQty, totalCost decimal.Decimal
	for _, b := range batches {
		qty := decimal.NewFromFloat(b.AvailableQty)
		cost := decimal.NewFromFloat(b.CostPerUnit)
		totalQty = totalQty.Add(qty)
		totalCost = totalCost.Add(qty.Mul(cost))
	}
	if totalQty.IsZero() {
		return decimal.Zero, nil
	}
	return totalCost.Div(totalQty), nil
}
