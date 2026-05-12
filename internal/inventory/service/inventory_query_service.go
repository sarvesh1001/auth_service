package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models"
	"auth-service/internal/inventory/models/enums"
	"auth-service/internal/inventory/repository"
)

// StockLevel represents current stock for a specific item/warehouse/batch combination.
type StockLevel struct {
	WarehouseID    uuid.UUID       `json:"warehouseId"`
	WarehouseName  string          `json:"warehouseName"`
	ItemID         uuid.UUID       `json:"itemId"`
	ItemSKU        string          `json:"itemSku"`
	ItemName       string          `json:"itemName"`
	BatchID        *uuid.UUID      `json:"batchId,omitempty"`
	BatchNumber    *string         `json:"batchNumber,omitempty"`
	QuantityOnHand decimal.Decimal `json:"quantityOnHand"`
	ReservedQty    decimal.Decimal `json:"reservedQty"`
	AvailableQty   decimal.Decimal `json:"availableQty"`
	LastMovementAt *time.Time      `json:"lastMovementAt,omitempty"`
}

// MovementSummary is a simplified view of a stock movement for listing.
type MovementSummary struct {
	MovementID    uuid.UUID          `json:"movementId"`
	MovementType  enums.MovementType `json:"movementType"`
	ItemID        uuid.UUID          `json:"itemId"`
	ItemSKU       string             `json:"itemSku"`
	ItemName      string             `json:"itemName"`
	WarehouseID   uuid.UUID          `json:"warehouseId"`
	WarehouseName string             `json:"warehouseName"`
	Quantity      decimal.Decimal    `json:"quantity"`
	Direction     string             `json:"direction"`
	UnitCost      decimal.Decimal    `json:"unitCost"`
	MovementDate  time.Time          `json:"movementDate"`
	ReferenceType *string            `json:"referenceType,omitempty"`
	ReferenceID   *uuid.UUID         `json:"referenceId,omitempty"`
	Reason        *string            `json:"reason,omitempty"`
}

// PaginatedResult wraps a list of results with total count.
type PaginatedResult[T any] struct {
	Data       []T   `json:"data"`
	TotalCount int64 `json:"totalCount"`
	Page       int   `json:"page"`
	PageSize   int   `json:"pageSize"`
}

// InventoryQueryService defines read‑only operations for inventory data.
type InventoryQueryService interface {
	// Stock levels
	GetCurrentStock(ctx context.Context, companyID, warehouseID, itemID uuid.UUID, batchID *uuid.UUID) (*StockLevel, error)
	GetAllStockByWarehouse(ctx context.Context, companyID, warehouseID uuid.UUID) ([]*StockLevel, error)
	GetAllStockByItem(ctx context.Context, companyID, itemID uuid.UUID) ([]*StockLevel, error)
	GetAllStockByBatch(ctx context.Context, companyID uuid.UUID, batchID uuid.UUID) (*StockLevel, error)

	// Movements
	GetMovements(ctx context.Context, filter repository.MovementFilter, page, pageSize int) (*PaginatedResult[MovementSummary], error)

	// Low stock & reorder
	GetLowStockItems(ctx context.Context, companyID uuid.UUID) ([]*repository.ReorderItem, error)

	// Expiring batches
	GetExpiringBatches(ctx context.Context, companyID uuid.UUID, daysThreshold int) ([]*models.Batch, error)

	// Reservation summary for a reference (e.g., sales order)
	GetReservationsByReference(ctx context.Context, companyID uuid.UUID, reservationType string, referenceID uuid.UUID) ([]*models.Reservation, error)
}

type inventoryQueryService struct {
	db              repository.DBTX
	balanceRepo     repository.StockBalanceRepository
	movementRepo    repository.MovementRepository
	itemRepo        repository.ItemRepository
	batchRepo       repository.BatchRepository
	warehouseRepo   repository.WarehouseRepository
	reservationRepo repository.ReservationRepository
	logger          *zap.Logger
}

func NewInventoryQueryService(
	db repository.DBTX,
	balanceRepo repository.StockBalanceRepository,
	movementRepo repository.MovementRepository,
	itemRepo repository.ItemRepository,
	batchRepo repository.BatchRepository,
	warehouseRepo repository.WarehouseRepository,
	reservationRepo repository.ReservationRepository,
	logger *zap.Logger,
) InventoryQueryService {
	return &inventoryQueryService{
		db:              db,
		balanceRepo:     balanceRepo,
		movementRepo:    movementRepo,
		itemRepo:        itemRepo,
		batchRepo:       batchRepo,
		warehouseRepo:   warehouseRepo,
		reservationRepo: reservationRepo,
		logger:          logger.Named("inventory_query_service"),
	}
}

// ---------------------------------------------------------------------
// Stock level implementations
// ---------------------------------------------------------------------

func (s *inventoryQueryService) GetCurrentStock(ctx context.Context, companyID, warehouseID, itemID uuid.UUID, batchID *uuid.UUID) (*StockLevel, error) {
	balance, err := s.balanceRepo.GetByItemWarehouse(ctx, s.db, companyID, warehouseID, itemID, batchID)
	if err != nil {
		if errors.Is(err, inventory_errors.ErrNotFound) {
			return &StockLevel{
				WarehouseID:    warehouseID,
				ItemID:         itemID,
				QuantityOnHand: decimal.Zero,
				ReservedQty:    decimal.Zero,
				AvailableQty:   decimal.Zero,
			}, nil
		}
		return nil, fmt.Errorf("get current stock: %w", err)
	}

	warehouse, _ := s.warehouseRepo.GetByID(ctx, s.db, companyID, balance.WarehouseID)
	item, _ := s.itemRepo.GetByID(ctx, s.db, balance.ItemID)

	stock := &StockLevel{
		WarehouseID:    balance.WarehouseID,
		ItemID:         balance.ItemID,
		BatchID:        balance.BatchID,
		QuantityOnHand: balance.QuantityOnHand,
		ReservedQty:    balance.ReservedQty,
		AvailableQty:   balance.AvailableQty,
		LastMovementAt: balance.LastMovementAt,
	}
	if warehouse != nil {
		stock.WarehouseName = warehouse.Name
	}
	if item != nil {
		stock.ItemSKU = item.SKU
		stock.ItemName = item.Name
	}
	if balance.BatchID != nil {
		batch, err := s.batchRepo.GetByID(ctx, s.db, *balance.BatchID)
		if err == nil && batch != nil {
			stock.BatchNumber = &batch.BatchNumber
		}
	}
	return stock, nil
}

func (s *inventoryQueryService) GetAllStockByWarehouse(ctx context.Context, companyID, warehouseID uuid.UUID) ([]*StockLevel, error) {
	balances, err := s.balanceRepo.GetByWarehouse(ctx, s.db, companyID, warehouseID)
	if err != nil {
		return nil, fmt.Errorf("get stock by warehouse: %w", err)
	}
	return s.enrichStockLevels(ctx, companyID, balances)
}

func (s *inventoryQueryService) GetAllStockByItem(ctx context.Context, companyID, itemID uuid.UUID) ([]*StockLevel, error) {
	balances, err := s.balanceRepo.GetByItem(ctx, s.db, companyID, itemID)
	if err != nil {
		return nil, fmt.Errorf("get stock by item: %w", err)
	}
	return s.enrichStockLevels(ctx, companyID, balances)
}

func (s *inventoryQueryService) GetAllStockByBatch(ctx context.Context, companyID uuid.UUID, batchID uuid.UUID) (*StockLevel, error) {
	batch, err := s.batchRepo.GetByID(ctx, s.db, batchID)
	if err != nil {
		return nil, fmt.Errorf("batch not found: %w", err)
	}
	if batch.CompanyID != companyID {
		return nil, inventory_errors.ErrPermissionDenied
	}
	balances, err := s.balanceRepo.GetByItem(ctx, s.db, companyID, batch.ItemID)
	if err != nil {
		return nil, err
	}
	for _, bal := range balances {
		if bal.BatchID != nil && *bal.BatchID == batchID {
			stock, err := s.enrichStockLevels(ctx, companyID, []*models.StockBalance{bal})
			if err != nil {
				return nil, err
			}
			if len(stock) > 0 {
				return stock[0], nil
			}
		}
	}
	return nil, inventory_errors.ErrNotFound
}

func (s *inventoryQueryService) enrichStockLevels(ctx context.Context, companyID uuid.UUID, balances []*models.StockBalance) ([]*StockLevel, error) {
	if len(balances) == 0 {
		return []*StockLevel{}, nil
	}
	warehouseIDs := make(map[uuid.UUID]bool)
	itemIDs := make(map[uuid.UUID]bool)
	for _, bal := range balances {
		warehouseIDs[bal.WarehouseID] = true
		itemIDs[bal.ItemID] = true
	}
	whList := make([]uuid.UUID, 0, len(warehouseIDs))
	for id := range warehouseIDs {
		whList = append(whList, id)
	}
	warehouses, err := s.warehouseRepo.GetByIDs(ctx, s.db, companyID, whList)
	if err != nil {
		s.logger.Warn("failed to fetch warehouses", zap.Error(err))
	}
	whMap := make(map[uuid.UUID]*models.Warehouse)
	for _, w := range warehouses {
		whMap[w.WarehouseID] = w
	}
	itemList := make([]uuid.UUID, 0, len(itemIDs))
	for id := range itemIDs {
		itemList = append(itemList, id)
	}
	items, err := s.itemRepo.GetByIDs(ctx, s.db, itemList)
	if err != nil {
		s.logger.Warn("failed to fetch items", zap.Error(err))
	}
	itemMap := make(map[uuid.UUID]*models.Item)
	for _, it := range items {
		itemMap[it.ItemID] = it
	}
	batchIDs := make([]uuid.UUID, 0)
	for _, bal := range balances {
		if bal.BatchID != nil {
			batchIDs = append(batchIDs, *bal.BatchID)
		}
	}
	var batchMap map[uuid.UUID]string
	if len(batchIDs) > 0 {
		batches, err := s.batchRepo.GetByIDs(ctx, s.db, batchIDs)
		if err == nil {
			batchMap = make(map[uuid.UUID]string, len(batches))
			for _, b := range batches {
				batchMap[b.BatchID] = b.BatchNumber
			}
		}
	}
	result := make([]*StockLevel, 0, len(balances))
	for _, bal := range balances {
		stock := &StockLevel{
			WarehouseID:    bal.WarehouseID,
			ItemID:         bal.ItemID,
			BatchID:        bal.BatchID,
			QuantityOnHand: bal.QuantityOnHand,
			ReservedQty:    bal.ReservedQty,
			AvailableQty:   bal.AvailableQty,
			LastMovementAt: bal.LastMovementAt,
		}
		if w, ok := whMap[bal.WarehouseID]; ok {
			stock.WarehouseName = w.Name
		}
		if it, ok := itemMap[bal.ItemID]; ok {
			stock.ItemSKU = it.SKU
			stock.ItemName = it.Name
		}
		if bal.BatchID != nil && batchMap != nil {
			if bn, ok := batchMap[*bal.BatchID]; ok {
				stock.BatchNumber = &bn
			}
		}
		result = append(result, stock)
	}
	return result, nil
}

// ---------------------------------------------------------------------
// Movement listing
// ---------------------------------------------------------------------

func (s *inventoryQueryService) GetMovements(ctx context.Context, filter repository.MovementFilter, page, pageSize int) (*PaginatedResult[MovementSummary], error) {
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
	sort := repository.Sort{Field: "movement_date", Direction: "DESC"}
	movements, err := s.movementRepo.List(ctx, s.db, filter, pagination, sort)
	if err != nil {
		return nil, fmt.Errorf("list movements: %w", err)
	}
	total, err := s.movementRepo.Count(ctx, s.db, filter)
	if err != nil {
		return nil, fmt.Errorf("count movements: %w", err)
	}

	summaries := make([]MovementSummary, 0, len(movements))
	for _, m := range movements {
		var quantity decimal.Decimal
		direction := "in"
		if m.QuantityIn.GreaterThan(decimal.Zero) {
			quantity = m.QuantityIn
			direction = "in"
		} else {
			quantity = m.QuantityOut
			direction = "out"
		}
		summary := MovementSummary{
			MovementID:    m.MovementID,
			MovementType:  m.MovementType,
			ItemID:        m.ItemID,
			WarehouseID:   m.WarehouseID,
			Quantity:      quantity,
			Direction:     direction,
			UnitCost:      m.UnitCost,
			MovementDate:  m.MovementDate,
			ReferenceType: m.ReferenceType,
			ReferenceID:   m.ReferenceID,
			Reason:        m.Reason,
		}
		item, err := s.itemRepo.GetByID(ctx, s.db, m.ItemID)
		if err == nil && item != nil {
			summary.ItemSKU = item.SKU
			summary.ItemName = item.Name
		}
		warehouse, err := s.warehouseRepo.GetByID(ctx, s.db, filter.CompanyID, m.WarehouseID)
		if err == nil && warehouse != nil {
			summary.WarehouseName = warehouse.Name
		}
		summaries = append(summaries, summary)
	}
	return &PaginatedResult[MovementSummary]{
		Data:       summaries,
		TotalCount: total,
		Page:       page,
		PageSize:   pageSize,
	}, nil
}

// ---------------------------------------------------------------------
// Low stock & reorder
// ---------------------------------------------------------------------

func (s *inventoryQueryService) GetLowStockItems(ctx context.Context, companyID uuid.UUID) ([]*repository.ReorderItem, error) {
	items, err := s.itemRepo.GetLowStockItems(ctx, s.db, companyID)
	if err != nil {
		return nil, fmt.Errorf("get low stock items: %w", err)
	}
	return items, nil
}

// ---------------------------------------------------------------------
// Expiring batches
// ---------------------------------------------------------------------

func (s *inventoryQueryService) GetExpiringBatches(ctx context.Context, companyID uuid.UUID, daysThreshold int) ([]*models.Batch, error) {
	batches, err := s.batchRepo.GetExpiringBatches(ctx, s.db, companyID, daysThreshold)
	if err != nil {
		return nil, fmt.Errorf("get expiring batches: %w", err)
	}
	return batches, nil
}

// ---------------------------------------------------------------------
// Reservations by reference
// ---------------------------------------------------------------------

func (s *inventoryQueryService) GetReservationsByReference(ctx context.Context, companyID uuid.UUID, reservationType string, referenceID uuid.UUID) ([]*models.Reservation, error) {
	filter := repository.ReservationFilter{
		CompanyID:       companyID,
		ReservationType: reservationType,
		ReferenceID:     &referenceID,
	}
	reservations, err := s.reservationRepo.List(ctx, s.db, filter, repository.Pagination{Limit: 1000}, repository.Sort{Field: "created_at", Direction: "ASC"})
	if err != nil {
		return nil, fmt.Errorf("get reservations by reference: %w", err)
	}
	return reservations, nil
}
