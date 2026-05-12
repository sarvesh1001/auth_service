// package service – inventory_service.go
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

// InventoryService defines core inventory operations
type InventoryService interface {
	// Item operations
	CreateItem(ctx context.Context, req CreateItemRequest, idempotencyKey string) (*models.Item, error)
	UpdateItem(ctx context.Context, req UpdateItemRequest, idempotencyKey string) (*models.Item, error)
	DeleteItem(ctx context.Context, companyID, itemID uuid.UUID, deletedBy *uuid.UUID, idempotencyKey string) error

	// Stock movement (core transactional)
	CreateMovement(ctx context.Context, req CreateMovementRequest, idempotencyKey string) (*models.StockMovement, error)

	// Batch operations
	CreateBatch(ctx context.Context, req CreateBatchRequest, idempotencyKey string) (*models.Batch, error)
	AdjustBatch(ctx context.Context, req AdjustBatchRequest, idempotencyKey string) error
}

type inventoryService struct {
	itemRepo         repository.ItemRepository
	movementRepo     repository.MovementRepository
	balanceRepo      repository.StockBalanceRepository
	ledgerRepo       repository.StockLedgerRepository
	batchRepo        repository.BatchRepository
	warehouseRepo    repository.WarehouseRepository
	pgClient         *client.PostgresClient
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	logger           *zap.Logger
}

func NewInventoryService(
	itemRepo repository.ItemRepository,
	movementRepo repository.MovementRepository,
	balanceRepo repository.StockBalanceRepository,
	ledgerRepo repository.StockLedgerRepository,
	batchRepo repository.BatchRepository,
	warehouseRepo repository.WarehouseRepository,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) InventoryService {
	return &inventoryService{
		itemRepo:         itemRepo,
		movementRepo:     movementRepo,
		balanceRepo:      balanceRepo,
		ledgerRepo:       ledgerRepo,
		batchRepo:        batchRepo,
		warehouseRepo:    warehouseRepo,
		pgClient:         pgClient,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		logger:           logger.Named("inventory_service"),
	}
}

// ----------------------------------------------------------------------
// Fulfillment policy compatibility helpers
// ----------------------------------------------------------------------
// isValidFulfillmentForItemType checks if a fulfillment policy is allowed for a given item type.
// NOTE: Replace string literals with proper enum constants (e.g., enums.FulfillmentPolicyServiceOnly)
// when those constants are defined in the enums package.
func isValidFulfillmentForItemType(ft enums.FulfillmentPolicy, it enums.ItemType) bool {
	switch it {
	case enums.ItemTypeRawMaterial, enums.ItemTypeFinishedGood, enums.ItemTypeSubAssembly, enums.ItemTypeConsumable:
		// Physical items cannot be service_only or digital_delivery
		return ft != "service_only" && ft != "digital_delivery"
	case enums.ItemTypeService:
		return ft == "service_only"
	default:
		return ft.IsValid()
	}
}

func (s *inventoryService) validateFulfillmentPolicyCompatibility(itemType enums.ItemType, policy enums.FulfillmentPolicy) error {
	if !isValidFulfillmentForItemType(policy, itemType) {
		return fmt.Errorf("%w: fulfillment_policy %s is not allowed for item_type %s",
			inventory_errors.ErrInvalidInput, policy, itemType)
	}
	return nil
}

// ----------------------------------------------------------------------
// CreateItem – extended with behavior flags
// ----------------------------------------------------------------------
type CreateItemRequest struct {
	CompanyID       uuid.UUID
	SKU             string
	Name            string
	Description     *string
	ItemType        enums.ItemType
	UnitOfMeasure   string
	ValuationMethod enums.ValuationMethod
	StandardCost    *decimal.Decimal
	SellingPrice    *decimal.Decimal
	ReorderLevel    *decimal.Decimal
	ReorderQuantity *decimal.Decimal
	IsActive        bool
	CreatedBy       *uuid.UUID

	TrackInventory     bool
	AllowNegativeStock bool
	IsSellable         bool
	IsPurchasable      bool
	RequiresShipping   bool
	IsBatchTracked     bool
	IsSerialTracked    bool
	FulfillmentPolicy  enums.FulfillmentPolicy
}

func (s *inventoryService) CreateItem(ctx context.Context, req CreateItemRequest, idempotencyKey string) (*models.Item, error) {
	logger := s.logger.With(zap.String("method", "CreateItem"), zap.String("idempotency_key", idempotencyKey))
	if err := s.validateCreateItem(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *models.Item
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent request – returning cached item")
		return cached, nil
	}

	exists, err := s.itemRepo.ExistsBySKU(ctx, tx, req.CompanyID, req.SKU)
	if err != nil {
		return nil, fmt.Errorf("check SKU exists: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("%w: SKU %s already exists", inventory_errors.ErrDuplicate, req.SKU)
	}

	item := &models.Item{
		ItemID:             uuid.New(),
		CompanyID:          req.CompanyID,
		SKU:                req.SKU,
		Name:               req.Name,
		Description:        req.Description,
		ItemType:           req.ItemType,
		UnitOfMeasure:      req.UnitOfMeasure,
		ValuationMethod:    req.ValuationMethod,
		StandardCost:       req.StandardCost,
		SellingPrice:       req.SellingPrice,
		ReorderLevel:       req.ReorderLevel,
		ReorderQuantity:    req.ReorderQuantity,
		IsActive:           req.IsActive,
		CreatedBy:          req.CreatedBy,
		UpdatedBy:          req.CreatedBy,
		TrackInventory:     req.TrackInventory,
		AllowNegativeStock: req.AllowNegativeStock,
		IsSellable:         req.IsSellable,
		IsPurchasable:      req.IsPurchasable,
		RequiresShipping:   req.RequiresShipping,
		IsBatchTracked:     req.IsBatchTracked,
		IsSerialTracked:    req.IsSerialTracked,
		FulfillmentPolicy:  req.FulfillmentPolicy,
	}

	if err := s.itemRepo.Create(ctx, tx, item); err != nil {
		return nil, fmt.Errorf("create item: %w", err)
	}

	if err := s.emitItemEvent(ctx, tx, item, events.EventItemCreated); err != nil {
		logger.Warn("failed to emit item created event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, item)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "create_item", "item",
			&item.ItemID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"sku": item.SKU,
			})
	}

	logger.Info("item created", zap.String("item_id", item.ItemID.String()))
	return item, nil
}

func (s *inventoryService) validateCreateItem(req CreateItemRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", inventory_errors.ErrInvalidInput)
	}
	if req.SKU == "" {
		return fmt.Errorf("%w: SKU required", inventory_errors.ErrInvalidInput)
	}
	if req.Name == "" {
		return fmt.Errorf("%w: name required", inventory_errors.ErrInvalidInput)
	}
	if req.UnitOfMeasure == "" {
		return fmt.Errorf("%w: unit_of_measure required", inventory_errors.ErrInvalidInput)
	}
	if !req.ItemType.IsValid() {
		return fmt.Errorf("%w: invalid item_type", inventory_errors.ErrInvalidInput)
	}
	if !req.ValuationMethod.IsValid() {
		return fmt.Errorf("%w: invalid valuation_method", inventory_errors.ErrInvalidInput)
	}
	if !req.FulfillmentPolicy.IsValid() {
		return fmt.Errorf("%w: invalid fulfillment_policy", inventory_errors.ErrInvalidInput)
	}
	// New: validate compatibility between item_type and fulfillment_policy
	if err := s.validateFulfillmentPolicyCompatibility(req.ItemType, req.FulfillmentPolicy); err != nil {
		return err
	}
	return nil
}

// ----------------------------------------------------------------------
// UpdateItem – extended with behavior flags and SKU update
// ----------------------------------------------------------------------
type UpdateItemRequest struct {
	ItemID          uuid.UUID
	CompanyID       uuid.UUID
	SKU             *string // allow SKU update
	Name            *string
	Description     *string
	ItemType        *enums.ItemType
	UnitOfMeasure   *string
	ValuationMethod *enums.ValuationMethod
	StandardCost    *decimal.Decimal
	SellingPrice    *decimal.Decimal
	ReorderLevel    *decimal.Decimal
	ReorderQuantity *decimal.Decimal
	IsActive        *bool
	UpdatedBy       *uuid.UUID

	TrackInventory     *bool
	AllowNegativeStock *bool
	IsSellable         *bool
	IsPurchasable      *bool
	RequiresShipping   *bool
	IsBatchTracked     *bool
	IsSerialTracked    *bool
	FulfillmentPolicy  *enums.FulfillmentPolicy
}

func (s *inventoryService) UpdateItem(ctx context.Context, req UpdateItemRequest, idempotencyKey string) (*models.Item, error) {
	logger := s.logger.With(zap.String("method", "UpdateItem"), zap.String("idempotency_key", idempotencyKey))
	if req.ItemID == uuid.Nil || req.CompanyID == uuid.Nil {
		return nil, inventory_errors.ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *models.Item
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached item")
		return cached, nil
	}

	item, err := s.itemRepo.GetByID(ctx, tx, req.ItemID)
	if err != nil {
		return nil, err
	}
	if item.CompanyID != req.CompanyID {
		return nil, inventory_errors.ErrPermissionDenied
	}

	// ---- FIXED: SKU change uniqueness check (exclude current item) ----
	if req.SKU != nil && *req.SKU != item.SKU {
		exists, err := s.itemRepo.ExistsBySKUExcludingID(ctx, tx, req.CompanyID, *req.SKU, item.ItemID)
		if err != nil {
			return nil, fmt.Errorf("check SKU existence: %w", err)
		}
		if exists {
			return nil, fmt.Errorf("%w: SKU %s already exists", inventory_errors.ErrDuplicate, *req.SKU)
		}
		item.SKU = *req.SKU
	}

	// ---- basic field updates ----
	if req.Name != nil {
		item.Name = *req.Name
	}
	if req.Description != nil {
		item.Description = req.Description
	}
	if req.ItemType != nil {
		// Validate fulfillment policy compatibility with new item type
		currentPolicy := item.FulfillmentPolicy
		if req.FulfillmentPolicy != nil {
			currentPolicy = *req.FulfillmentPolicy
		}
		if err := s.validateFulfillmentPolicyCompatibility(*req.ItemType, currentPolicy); err != nil {
			return nil, err
		}
		item.ItemType = *req.ItemType
	}
	if req.UnitOfMeasure != nil {
		item.UnitOfMeasure = *req.UnitOfMeasure
	}
	if req.ValuationMethod != nil {
		item.ValuationMethod = *req.ValuationMethod
	}
	if req.StandardCost != nil {
		item.StandardCost = req.StandardCost
	}
	if req.SellingPrice != nil {
		item.SellingPrice = req.SellingPrice
	}
	if req.ReorderLevel != nil {
		item.ReorderLevel = req.ReorderLevel
	}
	if req.ReorderQuantity != nil {
		item.ReorderQuantity = req.ReorderQuantity
	}
	if req.IsActive != nil {
		item.IsActive = *req.IsActive
	}
	// ---- behavior flags ----
	if req.TrackInventory != nil {
		item.TrackInventory = *req.TrackInventory
	}
	if req.AllowNegativeStock != nil {
		item.AllowNegativeStock = *req.AllowNegativeStock
	}
	if req.IsSellable != nil {
		item.IsSellable = *req.IsSellable
	}
	if req.IsPurchasable != nil {
		item.IsPurchasable = *req.IsPurchasable
	}
	if req.RequiresShipping != nil {
		item.RequiresShipping = *req.RequiresShipping
	}
	if req.IsBatchTracked != nil {
		item.IsBatchTracked = *req.IsBatchTracked
	}
	if req.IsSerialTracked != nil {
		item.IsSerialTracked = *req.IsSerialTracked
	}
	if req.FulfillmentPolicy != nil {
		// validate compatibility with current item type
		if err := s.validateFulfillmentPolicyCompatibility(item.ItemType, *req.FulfillmentPolicy); err != nil {
			return nil, err
		}
		item.FulfillmentPolicy = *req.FulfillmentPolicy
	}

	item.UpdatedBy = req.UpdatedBy

	if err := s.itemRepo.Update(ctx, tx, item); err != nil {
		return nil, fmt.Errorf("update item: %w", err)
	}

	if err := s.emitItemEvent(ctx, tx, item, events.EventItemUpdated); err != nil {
		logger.Warn("failed to emit item updated event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, item)
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "update_item", "item",
			&item.ItemID, "user", req.UpdatedBy, nil, nil, nil)
	}
	return item, nil
}

// ----------------------------------------------------------------------
// DeleteItem – now returns 404 if already inactive
// ----------------------------------------------------------------------
func (s *inventoryService) DeleteItem(ctx context.Context, companyID, itemID uuid.UUID, deletedBy *uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "DeleteItem"), zap.String("idempotency_key", idempotencyKey))
	if itemID == uuid.Nil || companyID == uuid.Nil {
		return inventory_errors.ErrInvalidInput
	}

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

	item, err := s.itemRepo.GetByID(ctx, tx, itemID)
	if err != nil {
		return err
	}
	if item.CompanyID != companyID {
		return inventory_errors.ErrPermissionDenied
	}
	// If already inactive, treat as not found
	if !item.IsActive {
		return inventory_errors.ErrNotFound
	}

	if err := s.itemRepo.Delete(ctx, tx, itemID); err != nil {
		return fmt.Errorf("delete item: %w", err)
	}

	if err := s.emitItemEvent(ctx, tx, item, events.EventItemDeleted); err != nil {
		logger.Warn("failed to emit delete event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "inventory", "delete_item", "item",
			&itemID, "user", deletedBy, nil, nil, nil)
	}
	return nil
}

// ----------------------------------------------------------------------
// CreateMovement – unchanged (already validates sellable/purchasable)
// ----------------------------------------------------------------------

func (s *inventoryService) CreateMovement(ctx context.Context, req CreateMovementRequest, idempotencyKey string) (*models.StockMovement, error) {
	logger := s.logger.With(zap.String("method", "CreateMovement"), zap.String("idempotency_key", idempotencyKey))
	if err := s.validateMovement(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *models.StockMovement
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
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

	if req.MovementType == enums.MovementTypePurchaseIn && !item.IsPurchasable {
		return nil, fmt.Errorf("%w: item %s is not purchasable", inventory_errors.ErrInvalidInput, item.SKU)
	}
	if req.MovementType == enums.MovementTypeSalesOut && !item.IsSellable {
		return nil, fmt.Errorf("%w: item %s is not sellable", inventory_errors.ErrInvalidInput, item.SKU)
	}

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
		Status:          req.Status,
		ReservationID:   req.ReservationID,
		ShipmentID:      req.ShipmentID,
		TransferOrderID: req.TransferOrderID,
	}
	if movement.Status == "" {
		movement.Status = "posted"
	}

	// Always create the movement record first (for both tracked and non-tracked items)
	if err := s.movementRepo.CreateMovement(ctx, tx, movement); err != nil {
		return nil, fmt.Errorf("create movement record: %w", err)
	}

	var oldAvailable float64
	var newAvailable float64

	if !item.TrackInventory {
		logger.Debug("item does not track inventory; skipping stock/ledger updates", zap.String("item_id", item.ItemID.String()))
		if err := s.emitMovementEvent(ctx, tx, movement, events.EventMovementCreated); err != nil {
			logger.Warn("failed to emit movement event", zap.Error(err))
		}
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, movement)
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit tx: %w", err)
		}
		logger.Info("non‑inventory movement created", zap.String("movement_id", movement.MovementID.String()))
		return movement, nil
	}

	// For inventory‑tracked items, process stock changes *after* movement is created
	if req.QuantityIn.GreaterThan(decimal.Zero) {
		oldAvailable, newAvailable, err = s.processInbound(ctx, tx, movement)
	} else {
		oldAvailable, newAvailable, err = s.processOutboundWithAllocation(ctx, tx, movement)
	}
	if err != nil {
		return nil, err
	}

	// Emit events after successful stock updates
	if err := s.emitMovementEvent(ctx, tx, movement, events.EventMovementCreated); err != nil {
		logger.Warn("failed to emit movement event", zap.Error(err))
	}
	if err := s.emitStockChangeEvent(ctx, tx, movement, oldAvailable, newAvailable); err != nil {
		logger.Warn("failed to emit stock change event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, movement)
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "create_movement", "stock_movement",
			&movement.MovementID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"movement_type": movement.MovementType,
				"item_id":       movement.ItemID.String(),
				"quantity_in":   movement.QuantityIn,
				"quantity_out":  movement.QuantityOut,
			})
	}

	logger.Info("movement created", zap.String("movement_id", movement.MovementID.String()))
	return movement, nil
}

func (s *inventoryService) validateMovement(req CreateMovementRequest) error {
	if req.CompanyID == uuid.Nil || req.ItemID == uuid.Nil || req.WarehouseID == uuid.Nil {
		return fmt.Errorf("%w: company_id, item_id, warehouse_id required", inventory_errors.ErrInvalidInput)
	}
	if req.QuantityIn.IsZero() && req.QuantityOut.IsZero() {
		return fmt.Errorf("%w: quantity_in or quantity_out must be >0", inventory_errors.ErrInvalidInput)
	}
	if !req.QuantityIn.IsZero() && !req.QuantityOut.IsZero() {
		return fmt.Errorf("%w: cannot have both quantity_in and quantity_out", inventory_errors.ErrInvalidInput)
	}
	if !req.MovementType.IsValid() {
		return fmt.Errorf("%w: invalid movement_type", inventory_errors.ErrInvalidInput)
	}
	return nil
}

// processInbound (no negative stock needed for inbound)
func (s *inventoryService) processInbound(ctx context.Context, tx *sql.Tx, movement *models.StockMovement) (oldAvailable, newAvailable float64, err error) {
	qty, _ := movement.QuantityIn.Float64()
	oldBalance, err := s.balanceRepo.GetByItemWarehouse(ctx, tx, movement.CompanyID, movement.WarehouseID, movement.ItemID, movement.BatchID)
	if err != nil && err != inventory_errors.ErrNotFound {
		return 0, 0, err
	}
	if oldBalance != nil {
		oldAvailable, _ = oldBalance.AvailableQty.Float64()
	} else {
		oldAvailable = 0
	}

	if err := s.balanceRepo.IncreaseStock(ctx, tx, movement.CompanyID, movement.WarehouseID, movement.ItemID, movement.BatchID, qty); err != nil {
		return 0, 0, fmt.Errorf("increase stock: %w", err)
	}
	newAvailable = oldAvailable + qty

	ledgerEntry := &models.StockLedger{
		LedgerID:        uuid.New(),
		CompanyID:       movement.CompanyID,
		WarehouseID:     &movement.WarehouseID,
		ItemID:          movement.ItemID,
		BatchID:         movement.BatchID,
		MovementID:      movement.MovementID,
		TransactionDate: movement.MovementDate,
		QuantityIn:      movement.QuantityIn,
		UnitCost:        movement.UnitCost,
		RunningBalance:  decimal.NewFromFloat(newAvailable),
		CreatedAt:       time.Now(),
	}
	if err := s.ledgerRepo.Create(ctx, tx, ledgerEntry); err != nil {
		return 0, 0, fmt.Errorf("create ledger entry: %w", err)
	}
	return oldAvailable, newAvailable, nil
}

// processOutboundWithAllocation – respects item/warehouse allow_negative_stock,
// uses FIFO layers from stock_ledger, updates remaining_quantity.
func (s *inventoryService) processOutboundWithAllocation(ctx context.Context, tx *sql.Tx, movement *models.StockMovement) (oldAvailable, newAvailable float64, err error) {
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
	allowNegative := item.AllowNegativeStock || warehouse.AllowNegativeStock

	balance, err := s.balanceRepo.GetByItemWarehouse(ctx, tx, movement.CompanyID, movement.WarehouseID, movement.ItemID, movement.BatchID)
	if err != nil && err != inventory_errors.ErrNotFound {
		return 0, 0, err
	}
	if balance != nil {
		oldAvailable, _ = balance.AvailableQty.Float64()
	} else {
		oldAvailable = 0
	}

	if !allowNegative && oldAvailable < toFloat64(qtyNeeded) {
		return 0, 0, fmt.Errorf("%w: required %.4f, available %.4f", inventory_errors.ErrInsufficientStock, toFloat64(qtyNeeded), oldAvailable)
	}

	if movement.BatchID != nil {
		if err := s.balanceRepo.DecreaseStock(ctx, tx, movement.CompanyID, movement.WarehouseID, movement.ItemID, movement.BatchID, toFloat64(qtyNeeded)); err != nil {
			return 0, 0, fmt.Errorf("decrease stock for specific batch: %w", err)
		}
		newAvailable = oldAvailable - toFloat64(qtyNeeded)

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
			RunningBalance:  decimal.NewFromFloat(newAvailable),
			CreatedAt:       time.Now(),
		}
		if err := s.ledgerRepo.Create(ctx, tx, ledgerEntry); err != nil {
			return 0, 0, fmt.Errorf("create ledger entry: %w", err)
		}
		return oldAvailable, newAvailable, nil
	}

	remaining := qtyNeeded
	layers, err := s.ledgerRepo.GetAvailableLayersFIFO(ctx, tx, movement.CompanyID, movement.ItemID, &movement.WarehouseID)
	if err != nil {
		return 0, 0, fmt.Errorf("get FIFO layers: %w", err)
	}

	if len(layers) == 0 && !allowNegative {
		return 0, 0, fmt.Errorf("%w: no available stock layers", inventory_errors.ErrInsufficientStock)
	}

	if len(layers) == 0 && allowNegative {
		if err := s.balanceRepo.DecreaseStock(ctx, tx, movement.CompanyID, movement.WarehouseID, movement.ItemID, nil, toFloat64(remaining)); err != nil {
			return 0, 0, fmt.Errorf("decrease stock (negative allowed): %w", err)
		}
		newAvailable = oldAvailable - toFloat64(remaining)
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
			RunningBalance:  decimal.NewFromFloat(newAvailable),
			CreatedAt:       time.Now(),
		}
		if err := s.ledgerRepo.Create(ctx, tx, ledgerEntry); err != nil {
			return 0, 0, fmt.Errorf("create ledger entry: %w", err)
		}
		return oldAvailable, newAvailable, nil
	}

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

	if remaining.GreaterThan(decimal.Zero) && !allowNegative {
		return 0, 0, fmt.Errorf("%w: insufficient stock after FIFO allocation", inventory_errors.ErrInsufficientStock)
	}

	if remaining.GreaterThan(decimal.Zero) && allowNegative {
		if err := s.balanceRepo.DecreaseStock(ctx, tx, movement.CompanyID, movement.WarehouseID, movement.ItemID, nil, toFloat64(remaining)); err != nil {
			return 0, 0, fmt.Errorf("decrease stock (negative remainder): %w", err)
		}
		newAvailable = oldAvailable - toFloat64(qtyNeeded)
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
			RunningBalance:  decimal.NewFromFloat(newAvailable),
			CreatedAt:       time.Now(),
		}
		if err := s.ledgerRepo.Create(ctx, tx, ledgerEntry); err != nil {
			return 0, 0, fmt.Errorf("create ledger entry for negative remainder: %w", err)
		}
	} else {
		newAvailable = oldAvailable - toFloat64(qtyNeeded)
	}

	if err := s.balanceRepo.DecreaseStock(ctx, tx, movement.CompanyID, movement.WarehouseID, movement.ItemID, nil, toFloat64(qtyNeeded)); err != nil {
		return 0, 0, fmt.Errorf("decrease stock balance: %w", err)
	}

	return oldAvailable, newAvailable, nil
}

// ----------------------------------------------------------------------
// Batch operations (unchanged)
// ----------------------------------------------------------------------
type CreateBatchRequest struct {
	CompanyID        uuid.UUID
	ItemID           uuid.UUID
	BatchNumber      string
	SupplierBatch    *string
	ManufacturedDate *time.Time
	ExpiryDate       *time.Time
	ReceivedDate     *time.Time
	Quantity         decimal.Decimal
	CostPerUnit      decimal.Decimal
	CreatedBy        *uuid.UUID
}

func (s *inventoryService) CreateBatch(ctx context.Context, req CreateBatchRequest, idempotencyKey string) (*models.Batch, error) {
	logger := s.logger.With(zap.String("method", "CreateBatch"), zap.String("idempotency_key", idempotencyKey))
	if req.CompanyID == uuid.Nil || req.ItemID == uuid.Nil || req.BatchNumber == "" {
		return nil, inventory_errors.ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	exists, err := s.batchRepo.ExistsByBatchNumber(ctx, tx, req.CompanyID, req.ItemID, req.BatchNumber)
	if err != nil {
		return nil, fmt.Errorf("check duplicate batch: %w", err)
	}
	if exists {
		logger.Warn("batch already exists", zap.String("batch_number", req.BatchNumber))
		return nil, fmt.Errorf("%w: batch number %s already exists for this item", inventory_errors.ErrDuplicate, req.BatchNumber)
	}

	var cached *models.Batch
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent request – returning cached batch")
		return cached, nil
	}

	batch := &models.Batch{
		BatchID:          uuid.New(),
		CompanyID:        req.CompanyID,
		ItemID:           req.ItemID,
		BatchNumber:      req.BatchNumber,
		SupplierBatch:    req.SupplierBatch,
		ManufacturedDate: req.ManufacturedDate,
		ExpiryDate:       req.ExpiryDate,
		ReceivedDate:     req.ReceivedDate,
		Quantity:         req.Quantity,
		RemainingQty:     req.Quantity,
		CostPerUnit:      req.CostPerUnit,
		IsActive:         true,
		CreatedBy:        req.CreatedBy,
		UpdatedBy:        req.CreatedBy,
	}

	if err := s.batchRepo.Create(ctx, tx, batch); err != nil {
		logger.Error("failed to create batch", zap.Error(err))
		return nil, fmt.Errorf("create batch: %w", err)
	}

	if err := s.emitBatchEvent(ctx, tx, batch, events.EventBatchCreated); err != nil {
		logger.Warn("failed to emit batch created event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, batch)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "create_batch", "batch",
			&batch.BatchID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"batch_number": batch.BatchNumber,
			})
	}

	logger.Info("batch created successfully", zap.String("batch_id", batch.BatchID.String()))
	return batch, nil
}

type AdjustBatchRequest struct {
	BatchID    uuid.UUID
	CompanyID  uuid.UUID
	Delta      decimal.Decimal
	Reason     string
	AdjustedBy *uuid.UUID
}

func (s *inventoryService) AdjustBatch(ctx context.Context, req AdjustBatchRequest, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "AdjustBatch"), zap.String("idempotency_key", idempotencyKey))
	if req.BatchID == uuid.Nil || req.CompanyID == uuid.Nil {
		return inventory_errors.ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – already adjusted")
		return nil
	}

	batch, err := s.batchRepo.GetByID(ctx, tx, req.BatchID)
	if err != nil {
		return err
	}
	if batch.CompanyID != req.CompanyID {
		return inventory_errors.ErrPermissionDenied
	}

	if err := s.batchRepo.AdjustBatchQuantity(ctx, tx, req.BatchID, toFloat64(req.Delta)); err != nil {
		return fmt.Errorf("adjust batch quantity: %w", err)
	}

	if err := s.emitBatchEvent(ctx, tx, batch, events.EventBatchAdjusted); err != nil {
		logger.Warn("failed to emit batch adjusted event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "adjust_batch", "batch",
			&req.BatchID, "user", req.AdjustedBy, nil, nil, map[string]interface{}{
				"delta":  req.Delta,
				"reason": req.Reason,
			})
	}
	return nil
}

// ----------------------------------------------------------------------
// Event helpers
// ----------------------------------------------------------------------
func (s *inventoryService) emitItemEvent(ctx context.Context, tx *sql.Tx, item *models.Item, eventType string) error {
	payload := events.ItemPayload{
		ItemID:    item.ItemID.String(),
		CompanyID: item.CompanyID.String(),
		SKU:       item.SKU,
		Name:      item.Name,
		ItemType:  string(item.ItemType),
		IsActive:  item.IsActive,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "item",
		AggregateID:   item.ItemID.String(),
		EventType:     eventType,
		Topic:         events.TopicInventoryEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}

func (s *inventoryService) emitBatchEvent(ctx context.Context, tx *sql.Tx, batch *models.Batch, eventType string) error {
	payload := map[string]interface{}{
		"batch_id":      batch.BatchID.String(),
		"company_id":    batch.CompanyID.String(),
		"item_id":       batch.ItemID.String(),
		"batch_number":  batch.BatchNumber,
		"remaining_qty": toFloat64(batch.RemainingQty),
		"cost_per_unit": toFloat64(batch.CostPerUnit),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "batch",
		AggregateID:   batch.BatchID.String(),
		EventType:     eventType,
		Topic:         events.TopicInventoryEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}

func (s *inventoryService) emitMovementEvent(ctx context.Context, tx *sql.Tx, movement *models.StockMovement, eventType string) error {
	payload := events.MovementPayload{
		MovementID:   movement.MovementID.String(),
		CompanyID:    movement.CompanyID.String(),
		MovementType: string(movement.MovementType),
		ItemID:       movement.ItemID.String(),
		WarehouseID:  movement.WarehouseID.String(),
		QuantityIn:   toFloat64(movement.QuantityIn),
		QuantityOut:  toFloat64(movement.QuantityOut),
		UnitCost:     toFloat64(movement.UnitCost),
		MovementDate: movement.MovementDate,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "stock_movement",
		AggregateID:   movement.MovementID.String(),
		EventType:     eventType,
		Topic:         events.TopicInventoryEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}

func (s *inventoryService) emitStockChangeEvent(ctx context.Context, tx *sql.Tx, movement *models.StockMovement, oldAvailable, newAvailable float64) error {
	delta := newAvailable - oldAvailable
	var batchIDStr *string
	if movement.BatchID != nil {
		s := movement.BatchID.String()
		batchIDStr = &s
	}
	payload := events.StockChangePayload{
		CompanyID:    movement.CompanyID.String(),
		ItemID:       movement.ItemID.String(),
		WarehouseID:  movement.WarehouseID.String(),
		BatchID:      batchIDStr,
		OldAvailable: oldAvailable,
		NewAvailable: newAvailable,
		Delta:        delta,
		Timestamp:    time.Now(),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "stock_balance",
		AggregateID:   movement.ItemID.String(),
		EventType:     events.EventStockChanged,
		Topic:         events.TopicInventoryEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}

func toFloat64(d decimal.Decimal) float64 {
	f, _ := d.Float64()
	return f
}
