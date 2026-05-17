package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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

// PurchaseOrderService defines all purchase order related operations
type PurchaseOrderService interface {
	// Reorder integration
	CreatePurchaseOrderFromReorder(ctx context.Context, reorder *models.ReorderOrder, idempotencyKey string) (*models.PurchaseOrder, bool, error)

	// Receiving
	ReceivePurchaseOrder(ctx context.Context, req ReceivePurchaseOrderRequest, idempotencyKey string) (*models.PurchaseOrderReceipt, error)

	// Vendor CRUD
	CreateVendor(ctx context.Context, req CreateVendorRequest, idempotencyKey string) (*models.Vendor, error)
	GetVendor(ctx context.Context, vendorID uuid.UUID) (*models.Vendor, error)
	ListVendors(ctx context.Context, filter repository.VendorFilter, page, pageSize int) ([]*models.Vendor, int64, error)
	UpdateVendor(ctx context.Context, vendor *models.Vendor, idempotencyKey string) error
	DeleteVendor(ctx context.Context, vendorID uuid.UUID, idempotencyKey string) error

	// Purchase Order CRUD
	CreatePurchaseOrder(ctx context.Context, req CreatePurchaseOrderRequest, idempotencyKey string) (*models.PurchaseOrder, error)
	GetPurchaseOrder(ctx context.Context, poID uuid.UUID) (*models.PurchaseOrder, error)
	ListPurchaseOrders(ctx context.Context, filter repository.PurchaseOrderFilter, page, pageSize int) ([]*models.PurchaseOrder, int64, error)
	UpdatePurchaseOrderStatus(ctx context.Context, poID uuid.UUID, newStatus string, idempotencyKey string) error
	AddPurchaseOrderItems(ctx context.Context, poID uuid.UUID, items []PurchaseOrderItemInput, idempotencyKey string) error
	GetPurchaseOrderItems(ctx context.Context, poID uuid.UUID) ([]*models.PurchaseOrderItem, error)
}

// ---------- Request/Response DTOs ----------

type CreateVendorRequest struct {
	CompanyID       uuid.UUID
	VendorCode      string
	VendorName      string
	VendorType      *string
	ContactPerson   string
	Phone           string
	Email           string
	Address         string
	BankAccountNo   string
	BankRoutingCode string
	BankName        string
	IsActive        bool
	CreatedBy       *uuid.UUID
}

type CreatePurchaseOrderRequest struct {
	CompanyID            uuid.UUID
	PONumber             string
	VendorID             uuid.UUID
	OrderDate            time.Time
	ExpectedDeliveryDate *time.Time
	Items                []PurchaseOrderItemInput
	Notes                *string
	CreatedBy            *uuid.UUID
}

type PurchaseOrderItemInput struct {
	ItemID          uuid.UUID
	QuantityOrdered decimal.Decimal
	UnitCost        decimal.Decimal
}

type ReceivePurchaseOrderRequest struct {
	CompanyID       uuid.UUID
	PurchaseOrderID uuid.UUID
	ReceiptDate     time.Time
	Items           []ReceivePurchaseOrderItemInput
	WarehouseID     uuid.UUID
	CreatedBy       *uuid.UUID
}

type ReceivePurchaseOrderItemInput struct {
	POItemID         uuid.UUID
	QuantityReceived decimal.Decimal
	UnitCost         decimal.Decimal
}

// ---------- Service Implementation ----------

type purchaseOrderService struct {
	repo             repository.VendorPurchaseRepository
	stockService     StockService
	pgClient         *client.PostgresClient
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	logger           *zap.Logger
}

func NewPurchaseOrderService(
	repo repository.VendorPurchaseRepository,
	stockService StockService,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) PurchaseOrderService {
	return &purchaseOrderService{
		repo:             repo,
		stockService:     stockService,
		pgClient:         pgClient,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		logger:           logger.Named("purchase_order_service"),
	}
}

// ---------- Reorder Integration ----------

func (s *purchaseOrderService) CreatePurchaseOrderFromReorder(
	ctx context.Context,
	reorder *models.ReorderOrder,
	idempotencyKey string,
) (*models.PurchaseOrder, bool, error) {
	logger := s.logger.With(
		zap.String("reorder_id", reorder.ReorderOrderID.String()),
		zap.String("idempotency_key", idempotencyKey),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency: store PO ID as string
	var cachedPOIDStr string
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cachedPOIDStr); err == nil && cachedPOIDStr != "" {
		poID, err := uuid.Parse(cachedPOIDStr)
		if err == nil {
			po, err := s.repo.GetPurchaseOrderByID(ctx, tx, poID)
			if err != nil {
				return nil, false, err
			}
			logger.Info("idempotent – returning existing purchase order")
			return po, false, nil
		}
	}

	// Get the default vendor for the item
	itemVendor, err := s.repo.GetDefaultItemVendor(ctx, tx, reorder.ItemID)
	if err != nil {
		return nil, false, fmt.Errorf("get default vendor: %w", err)
	}
	if itemVendor == nil {
		return nil, false, fmt.Errorf("%w: no default vendor for item %s", inventory_errors.ErrInvalidInput, reorder.ItemID)
	}

	// Generate PO number
	poNumber, err := s.generatePONumber(ctx, tx, reorder.CompanyID)
	if err != nil {
		return nil, false, err
	}

	po := &models.PurchaseOrder{
		PurchaseOrderID: uuid.New(),
		CompanyID:       reorder.CompanyID,
		PONumber:        poNumber,
		VendorID:        itemVendor.VendorID,
		OrderDate:       time.Now(),
		Status:          "submitted",
		Currency:        "USD",
		CreatedBy:       nil, // system
		UpdatedBy:       nil,
	}
	if err := s.repo.CreatePurchaseOrder(ctx, tx, po); err != nil {
		return nil, false, fmt.Errorf("create purchase order: %w", err)
	}

	// Create purchase order item
	poItem := &models.PurchaseOrderItem{
		POItemID:        uuid.New(),
		PurchaseOrderID: po.PurchaseOrderID,
		ItemID:          reorder.ItemID,
		QuantityOrdered: reorder.RequestedQty,
		UnitCost:        itemVendor.UnitCost,
	}
	if err := s.repo.AddPurchaseOrderItem(ctx, tx, poItem); err != nil {
		return nil, false, fmt.Errorf("add purchase order item: %w", err)
	}

	// Update reorder order status and reference
	reorder.Status = "approved"
	refType := "purchase_order"
	reorder.ReferenceType = &refType
	reorder.ReferenceID = &po.PurchaseOrderID

	if err := s.updateReorderOrderWithReference(ctx, tx, reorder); err != nil {
		return nil, false, fmt.Errorf("update reorder order: %w", err)
	}

	// Emit event
	if err := s.emitPurchaseOrderCreatedEvent(ctx, tx, po, reorder); err != nil {
		logger.Warn("failed to emit event", zap.Error(err))
	}

	// Store idempotency result (PO ID as string)
	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, po.PurchaseOrderID.String())

	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &reorder.CompanyID, "purchasing", "create_purchase_order", "purchase_order",
			&po.PurchaseOrderID, "system", nil, nil, nil,
			map[string]interface{}{
				"reorder_id":    reorder.ReorderOrderID.String(),
				"po_number":     po.PONumber,
				"vendor_id":     po.VendorID.String(),
				"requested_qty": reorder.RequestedQty.String(),
			})
	}

	logger.Info("purchase order created from reorder", zap.String("po_id", po.PurchaseOrderID.String()))
	return po, true, nil
}

// Temporary helper – should be moved to ReorderOrderRepository
func (s *purchaseOrderService) updateReorderOrderWithReference(ctx context.Context, tx *sql.Tx, reorder *models.ReorderOrder) error {
	query := `
		UPDATE reorder_orders
		SET status = $2, reference_type = $3, reference_id = $4, updated_at = NOW()
		WHERE reorder_order_id = $1
	`
	_, err := tx.ExecContext(ctx, query,
		reorder.ReorderOrderID,
		reorder.Status,
		reorder.ReferenceType,
		reorder.ReferenceID,
	)
	return err
}

func (s *purchaseOrderService) generatePONumber(ctx context.Context, tx *sql.Tx, companyID uuid.UUID) (string, error) {
	// Example: PO-20260516-ABC123 (date + first 6 chars of company ID)
	dateStr := time.Now().Format("20060102")
	shortID := companyID.String()[:6]
	base := fmt.Sprintf("PO-%s-%s", dateStr, shortID)

	var count int
	query := `SELECT COUNT(*) FROM purchase_orders WHERE po_number LIKE $1`
	err := tx.QueryRowContext(ctx, query, base+"%").Scan(&count)
	if err != nil {
		return "", err
	}
	if count == 0 {
		return base, nil
	}
	return fmt.Sprintf("%s-%d", base, count+1), nil
}

// ---------- Receiving Purchase Order ----------

func (s *purchaseOrderService) ReceivePurchaseOrder(
	ctx context.Context,
	req ReceivePurchaseOrderRequest,
	idempotencyKey string,
) (*models.PurchaseOrderReceipt, error) {
	logger := s.logger.With(
		zap.String("po_id", req.PurchaseOrderID.String()),
		zap.String("idempotency_key", idempotencyKey),
	)

	if req.CompanyID == uuid.Nil {
		return nil, fmt.Errorf("%w: company_id required", inventory_errors.ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cachedReceiptIDStr string
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cachedReceiptIDStr); err == nil && cachedReceiptIDStr != "" {
		receiptID, err := uuid.Parse(cachedReceiptIDStr)
		if err == nil {
			receipt, err := s.repo.GetPurchaseOrderReceiptByID(ctx, tx, receiptID)
			if err != nil {
				return nil, err
			}
			logger.Info("idempotent – returning existing receipt")
			return receipt, nil
		}
	}

	var firstReceipt *models.PurchaseOrderReceipt
	for _, it := range req.Items {
		poItem, err := s.repo.GetPurchaseOrderItemByID(ctx, tx, it.POItemID)
		if err != nil {
			return nil, err
		}

		// --- FIX 1: Prevent over‑receipt ---
		remaining := poItem.QuantityOrdered.Sub(poItem.QuantityReceived)
		if it.QuantityReceived.GreaterThan(remaining) {
			return nil, fmt.Errorf("%w: received quantity %.2f exceeds remaining quantity %.2f for item %s",
				inventory_errors.ErrInvalidInput,
				toFloat64(it.QuantityReceived),
				toFloat64(remaining),
				poItem.POItemID)
		}

		// Create stock adjustment (positive delta = increase stock)
		adjustReq := AdjustStockRequest{
			CompanyID:      req.CompanyID,
			WarehouseID:    req.WarehouseID,
			ItemID:         poItem.ItemID,
			BatchID:        nil,
			Delta:          it.QuantityReceived,
			Reason:         fmt.Sprintf("Purchase order receipt: %s", req.PurchaseOrderID.String()),
			AdjustmentDate: req.ReceiptDate,
			CreatedBy:      req.CreatedBy,
		}
		movement, err := s.stockService.AdjustStock(ctx, adjustReq, idempotencyKey+":stock:"+it.POItemID.String())
		if err != nil {
			return nil, fmt.Errorf("stock adjustment failed: %w", err)
		}

		// Update PO item received quantity
		if err := s.repo.UpdatePurchaseOrderItemReceivedQty(ctx, tx, it.POItemID, it.QuantityReceived); err != nil {
			return nil, err
		}

		// Create receipt record
		receipt := &models.PurchaseOrderReceipt{
			ReceiptID:        uuid.New(),
			PurchaseOrderID:  req.PurchaseOrderID,
			POItemID:         it.POItemID,
			ReceiptDate:      req.ReceiptDate,
			QuantityReceived: it.QuantityReceived,
			UnitCost:         it.UnitCost,
			WarehouseID:      req.WarehouseID,
			MovementID:       &movement.MovementID,
			CreatedBy:        req.CreatedBy,
		}
		if err := s.repo.CreatePurchaseOrderReceipt(ctx, tx, receipt); err != nil {
			return nil, err
		}
		if firstReceipt == nil {
			firstReceipt = receipt
		}
	}

	// Update PO status (check if all items fully received – simplified)
	// For production, you should check if sum(received) >= sum(ordered)
	if err := s.repo.UpdatePurchaseOrderStatus(ctx, tx, req.PurchaseOrderID, "received"); err != nil {
		return nil, err
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, firstReceipt.ReceiptID.String())

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	return firstReceipt, nil
}

// ---------- Vendor CRUD ----------

func (s *purchaseOrderService) CreateVendor(ctx context.Context, req CreateVendorRequest, idempotencyKey string) (*models.Vendor, error) {
	// Validate required fields
	if req.VendorCode == "" {
		return nil, fmt.Errorf("%w: vendorCode is required", inventory_errors.ErrInvalidInput)
	}
	if req.VendorName == "" {
		return nil, fmt.Errorf("%w: vendorName is required", inventory_errors.ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cachedVendorIDStr string
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cachedVendorIDStr); err == nil && cachedVendorIDStr != "" {
		vendorID, err := uuid.Parse(cachedVendorIDStr)
		if err == nil {
			return s.repo.GetVendorByID(ctx, tx, vendorID)
		}
	}

	exists, err := s.repo.ExistsVendorByCode(ctx, tx, req.CompanyID, req.VendorCode)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("%w: vendor code %s already exists", inventory_errors.ErrDuplicate, req.VendorCode)
	}

	vendor := &models.Vendor{
		VendorID:        uuid.New(),
		CompanyID:       req.CompanyID,
		VendorCode:      req.VendorCode,
		VendorName:      req.VendorName,
		VendorType:      req.VendorType,
		ContactPerson:   req.ContactPerson,
		Phone:           req.Phone,
		Email:           req.Email,
		Address:         req.Address,
		BankAccountNo:   req.BankAccountNo,
		BankRoutingCode: req.BankRoutingCode,
		BankName:        req.BankName,
		IsActive:        req.IsActive,
		CreatedBy:       req.CreatedBy,
		UpdatedBy:       req.CreatedBy,
	}
	if err := s.repo.CreateVendor(ctx, tx, vendor); err != nil {
		return nil, err
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, vendor.VendorID.String())

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	return vendor, nil
}

func (s *purchaseOrderService) GetVendor(ctx context.Context, vendorID uuid.UUID) (*models.Vendor, error) {
	return s.repo.GetVendorByID(ctx, s.pgClient.DB, vendorID)
}

func (s *purchaseOrderService) ListVendors(ctx context.Context, filter repository.VendorFilter, page, pageSize int) ([]*models.Vendor, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	pagination := repository.Pagination{Limit: pageSize, Offset: (page - 1) * pageSize}
	sort := repository.Sort{Field: "vendor_code", Direction: "ASC"}

	vendors, err := s.repo.ListVendors(ctx, s.pgClient.DB, filter, pagination, sort)
	if err != nil {
		return nil, 0, err
	}
	total, err := s.repo.CountVendors(ctx, s.pgClient.DB, filter)
	if err != nil {
		return nil, 0, err
	}
	return vendors, total, nil
}

func (s *purchaseOrderService) UpdateVendor(ctx context.Context, vendor *models.Vendor, idempotencyKey string) error {
	return s.repo.UpdateVendor(ctx, s.pgClient.DB, vendor)
}

func (s *purchaseOrderService) DeleteVendor(ctx context.Context, vendorID uuid.UUID, idempotencyKey string) error {
	return s.repo.DeleteVendor(ctx, s.pgClient.DB, vendorID)
}

// ---------- Purchase Order CRUD ----------

func (s *purchaseOrderService) CreatePurchaseOrder(ctx context.Context, req CreatePurchaseOrderRequest, idempotencyKey string) (*models.PurchaseOrder, error) {
	// --- 1. Basic validations ---
	if req.PONumber == "" {
		return nil, fmt.Errorf("%w: poNumber is required", inventory_errors.ErrInvalidInput)
	}
	if req.VendorID == uuid.Nil {
		return nil, fmt.Errorf("%w: vendorId is required", inventory_errors.ErrInvalidInput)
	}
	if req.OrderDate.IsZero() {
		return nil, fmt.Errorf("%w: orderDate is required", inventory_errors.ErrInvalidInput)
	}
	if len(req.Items) == 0 {
		return nil, fmt.Errorf("%w: at least one item is required", inventory_errors.ErrInvalidInput)
	}
	for i, it := range req.Items {
		if it.ItemID == uuid.Nil {
			return nil, fmt.Errorf("%w: itemId is required in item %d", inventory_errors.ErrInvalidInput, i)
		}
		if it.QuantityOrdered.LessThanOrEqual(decimal.Zero) {
			return nil, fmt.Errorf("%w: quantityOrdered must be > 0 in item %d", inventory_errors.ErrInvalidInput, i)
		}
		if it.UnitCost.LessThanOrEqual(decimal.Zero) {
			return nil, fmt.Errorf("%w: unitCost must be > 0 in item %d", inventory_errors.ErrInvalidInput, i)
		}
	}

	// --- 2. Verify vendor exists ---
	vendor, err := s.repo.GetVendorByID(ctx, s.pgClient.DB, req.VendorID)
	if err != nil {
		if errors.Is(err, inventory_errors.ErrNotFound) {
			return nil, fmt.Errorf("%w: vendor %s not found", inventory_errors.ErrNotFound, req.VendorID)
		}
		return nil, fmt.Errorf("get vendor: %w", err)
	}
	if vendor.CompanyID != req.CompanyID {
		return nil, fmt.Errorf("%w: vendor does not belong to this company", inventory_errors.ErrPermissionDenied)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// --- 3. Idempotency check ---
	var cachedPOIDStr string
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cachedPOIDStr); err == nil && cachedPOIDStr != "" {
		poID, err := uuid.Parse(cachedPOIDStr)
		if err == nil {
			po, err := s.repo.GetPurchaseOrderByID(ctx, tx, poID)
			if err != nil {
				return nil, err
			}
			return po, nil
		}
	}

	// --- 4. Duplicate PO number ---
	exists, err := s.repo.ExistsPurchaseOrderNumber(ctx, tx, req.CompanyID, req.PONumber)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("%w: PO number %s already exists", inventory_errors.ErrDuplicate, req.PONumber)
	}

	// --- 5. Create PO header ---
	po := &models.PurchaseOrder{
		PurchaseOrderID:      uuid.New(),
		CompanyID:            req.CompanyID,
		PONumber:             req.PONumber,
		VendorID:             req.VendorID,
		OrderDate:            req.OrderDate,
		ExpectedDeliveryDate: req.ExpectedDeliveryDate,
		Status:               "draft",
		Currency:             "USD",
		Notes:                req.Notes,
		CreatedBy:            req.CreatedBy,
		UpdatedBy:            req.CreatedBy,
	}
	if err := s.repo.CreatePurchaseOrder(ctx, tx, po); err != nil {
		return nil, err
	}

	// --- 6. Create PO items (check duplicate items in same request) ---
	seenItems := make(map[uuid.UUID]bool)
	for _, it := range req.Items {
		if seenItems[it.ItemID] {
			return nil, fmt.Errorf("%w: duplicate item %s in request", inventory_errors.ErrInvalidInput, it.ItemID)
		}
		seenItems[it.ItemID] = true

		poItem := &models.PurchaseOrderItem{
			POItemID:        uuid.New(),
			PurchaseOrderID: po.PurchaseOrderID,
			ItemID:          it.ItemID,
			QuantityOrdered: it.QuantityOrdered,
			UnitCost:        it.UnitCost,
		}
		if err := s.repo.AddPurchaseOrderItem(ctx, tx, poItem); err != nil {
			if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
				return nil, fmt.Errorf("%w: item %s already exists in this purchase order", inventory_errors.ErrDuplicate, it.ItemID)
			}
			return nil, err
		}
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, po.PurchaseOrderID.String())

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	return po, nil
}

func (s *purchaseOrderService) GetPurchaseOrder(ctx context.Context, poID uuid.UUID) (*models.PurchaseOrder, error) {
	return s.repo.GetPurchaseOrderByID(ctx, s.pgClient.DB, poID)
}

func (s *purchaseOrderService) ListPurchaseOrders(ctx context.Context, filter repository.PurchaseOrderFilter, page, pageSize int) ([]*models.PurchaseOrder, int64, error) {
	// Validate status filter if provided
	if filter.Status != "" {
		allowed := map[string]bool{
			"draft": true, "submitted": true, "approved": true,
			"ordered": true, "partially_received": true, "received": true, "cancelled": true,
		}
		if !allowed[filter.Status] {
			return nil, 0, fmt.Errorf("%w: invalid status %s", inventory_errors.ErrInvalidStatus, filter.Status)
		}
	}

	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	pagination := repository.Pagination{Limit: pageSize, Offset: (page - 1) * pageSize}
	sort := repository.Sort{Field: "order_date", Direction: "DESC"}

	pos, err := s.repo.ListPurchaseOrders(ctx, s.pgClient.DB, filter, pagination, sort)
	if err != nil {
		return nil, 0, err
	}
	total, err := s.repo.CountPurchaseOrders(ctx, s.pgClient.DB, filter)
	if err != nil {
		return nil, 0, err
	}
	return pos, total, nil
}

// UpdatePurchaseOrderStatus updates the status of a purchase order with transition validation.
func (s *purchaseOrderService) UpdatePurchaseOrderStatus(ctx context.Context, poID uuid.UUID, newStatus string, idempotencyKey string) error {
	// Validate status value
	allowedStatuses := map[string]bool{
		"draft": true, "submitted": true, "approved": true,
		"ordered": true, "partially_received": true, "received": true, "cancelled": true,
	}
	if !allowedStatuses[newStatus] {
		return fmt.Errorf("%w: invalid status %s", inventory_errors.ErrInvalidStatus, newStatus)
	}

	// Get current purchase order
	po, err := s.repo.GetPurchaseOrderByID(ctx, s.pgClient.DB, poID)
	if err != nil {
		return err
	}

	// Define allowed transitions
	validTransitions := map[string][]string{
		"draft":              {"submitted", "cancelled"},
		"submitted":          {"approved", "cancelled"},
		"approved":           {"ordered", "cancelled"},
		"ordered":            {"partially_received", "received", "cancelled"},
		"partially_received": {"ordered", "received", "cancelled"},
		"received":           {},
		"cancelled":          {},
	}

	allowedNext, ok := validTransitions[po.Status]
	if !ok {
		return fmt.Errorf("%w: unknown current status %s", inventory_errors.ErrInvalidTransition, po.Status)
	}
	transitionAllowed := false
	for _, next := range allowedNext {
		if next == newStatus {
			transitionAllowed = true
			break
		}
	}
	if !transitionAllowed {
		return fmt.Errorf("%w: cannot transition from %s to %s", inventory_errors.ErrInvalidTransition, po.Status, newStatus)
	}

	// Update status
	return s.repo.UpdatePurchaseOrderStatus(ctx, s.pgClient.DB, poID, newStatus)
}

func (s *purchaseOrderService) AddPurchaseOrderItems(ctx context.Context, poID uuid.UUID, items []PurchaseOrderItemInput, idempotencyKey string) error {
	// --- 1. Validate items ---
	if len(items) == 0 {
		return fmt.Errorf("%w: at least one item required", inventory_errors.ErrInvalidInput)
	}
	for i, it := range items {
		if it.ItemID == uuid.Nil {
			return fmt.Errorf("%w: itemId required in item %d", inventory_errors.ErrInvalidInput, i)
		}
		if it.QuantityOrdered.LessThanOrEqual(decimal.Zero) {
			return fmt.Errorf("%w: quantityOrdered must be > 0 in item %d", inventory_errors.ErrInvalidInput, i)
		}
		if it.UnitCost.LessThanOrEqual(decimal.Zero) {
			return fmt.Errorf("%w: unitCost must be > 0 in item %d", inventory_errors.ErrInvalidInput, i)
		}
	}
	// Check duplicates within request
	seen := make(map[uuid.UUID]bool)
	for _, it := range items {
		if seen[it.ItemID] {
			return fmt.Errorf("%w: duplicate item %s in request", inventory_errors.ErrInvalidInput, it.ItemID)
		}
		seen[it.ItemID] = true
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// --- 2. Check if items already exist in PO ---
	existing, err := s.repo.GetPurchaseOrderItems(ctx, tx, poID)
	if err != nil {
		return err
	}
	existingMap := make(map[uuid.UUID]bool)
	for _, e := range existing {
		existingMap[e.ItemID] = true
	}
	for _, it := range items {
		if existingMap[it.ItemID] {
			return fmt.Errorf("%w: item %s already exists in this purchase order", inventory_errors.ErrDuplicate, it.ItemID)
		}
	}

	// --- 3. Insert new items ---
	for _, it := range items {
		poItem := &models.PurchaseOrderItem{
			POItemID:        uuid.New(),
			PurchaseOrderID: poID,
			ItemID:          it.ItemID,
			QuantityOrdered: it.QuantityOrdered,
			UnitCost:        it.UnitCost,
		}
		if err := s.repo.AddPurchaseOrderItem(ctx, tx, poItem); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *purchaseOrderService) GetPurchaseOrderItems(ctx context.Context, poID uuid.UUID) ([]*models.PurchaseOrderItem, error) {
	return s.repo.GetPurchaseOrderItems(ctx, s.pgClient.DB, poID)
}

// ---------- Event Emission ----------

func (s *purchaseOrderService) emitPurchaseOrderCreatedEvent(ctx context.Context, tx *sql.Tx, po *models.PurchaseOrder, reorder *models.ReorderOrder) error {
	payload := map[string]interface{}{
		"purchase_order_id": po.PurchaseOrderID.String(),
		"po_number":         po.PONumber,
		"vendor_id":         po.VendorID.String(),
		"order_date":        po.OrderDate,
		"status":            po.Status,
		"reorder_order_id":  reorder.ReorderOrderID.String(),
		"total_amount":      po.TotalAmount.String(),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "purchase_order",
		AggregateID:   po.PurchaseOrderID.String(),
		EventType:     "purchasing.purchase_order.created",
		Topic:         events.TopicInventoryEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}
