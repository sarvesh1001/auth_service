// package service
// filename: invoice_service.go

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
	salesErrors "auth-service/internal/sales/errors"
	salesEvents "auth-service/internal/sales/events"
	"auth-service/internal/sales/models"
	"auth-service/internal/sales/models/enums"
	"auth-service/internal/sales/repository"
)

// ------------------------ DTOs ------------------------

// ------------------------ Service Interface ------------------------

type InvoiceService interface {
	CreateDraftInvoice(ctx context.Context, req *CreateInvoiceRequest) (*models.Invoice, error)
	CreateInvoiceFromOrder(ctx context.Context, companyID, orderID uuid.UUID, req *CreateInvoiceFromOrderRequest) (*models.Invoice, error)
	CreateInvoiceFromQuote(ctx context.Context, companyID, quoteID uuid.UUID, req *CreateInvoiceFromQuoteRequest) (*models.Invoice, error)
	UpdateInvoice(ctx context.Context, companyID, invoiceID uuid.UUID, req *UpdateInvoiceRequest) (*models.Invoice, error)
	DeleteInvoice(ctx context.Context, companyID, invoiceID uuid.UUID, deletedBy uuid.UUID) error
	GetInvoiceByID(ctx context.Context, companyID, invoiceID uuid.UUID) (*models.Invoice, error)
	GetInvoiceByNumber(ctx context.Context, companyID uuid.UUID, invoiceNumber string) (*models.Invoice, error)
	ListInvoices(ctx context.Context, filter InvoiceListFilter, p Pagination, s Sort) ([]*models.Invoice, int64, error)
	SearchInvoices(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.Invoice, int64, error)
	GetInvoicesByCustomer(ctx context.Context, companyID, customerID uuid.UUID, p Pagination, s Sort) ([]*models.Invoice, int64, error)
	GetInvoicesByOrder(ctx context.Context, companyID, orderID uuid.UUID) ([]*models.Invoice, error)
	AddItems(ctx context.Context, companyID, invoiceID uuid.UUID, items []CreateInvoiceItemRequest, updatedBy uuid.UUID) error
	ReplaceItems(ctx context.Context, companyID, invoiceID uuid.UUID, items []CreateInvoiceItemRequest, updatedBy uuid.UUID) error
	RemoveItem(ctx context.Context, companyID, invoiceID, invoiceItemID uuid.UUID, updatedBy uuid.UUID) error
	GetInvoiceItems(ctx context.Context, companyID, invoiceID uuid.UUID) ([]*models.InvoiceItem, error)
	CalculatePricing(ctx context.Context, companyID, invoiceID uuid.UUID) error
	PreviewPricing(ctx context.Context, req *InvoicePricingPreviewRequest) (*InvoicePricingPreviewResult, error)
	RecalculateTotals(ctx context.Context, companyID, invoiceID uuid.UUID, updatedBy uuid.UUID) error
	GetInvoiceTotals(ctx context.Context, companyID, invoiceID uuid.UUID) (subtotal, discountTotal, taxTotal, grandTotal, amountPaid, amountDue decimal.Decimal, err error)
	ApplyManualDiscount(ctx context.Context, companyID, invoiceID uuid.UUID, discountAmount decimal.Decimal, reason string, updatedBy uuid.UUID) error
	RemoveManualDiscount(ctx context.Context, companyID, invoiceID uuid.UUID, updatedBy uuid.UUID) error
	UpdateStatus(ctx context.Context, companyID, invoiceID uuid.UUID, status enums.InvoiceStatus, updatedBy uuid.UUID) error
	IssueInvoice(ctx context.Context, companyID, invoiceID uuid.UUID, issuedBy uuid.UUID) error
	MarkAsPaid(ctx context.Context, companyID, invoiceID uuid.UUID, paidAt time.Time, updatedBy uuid.UUID) error
	MarkAsOverdue(ctx context.Context, companyID, invoiceID uuid.UUID, updatedBy uuid.UUID) error
	VoidInvoice(ctx context.Context, companyID, invoiceID uuid.UUID, reason string, voidedBy uuid.UUID) error
	RegisterPayment(ctx context.Context, req *RegisterInvoicePaymentRequest) error
	ApplyPayment(ctx context.Context, companyID, invoiceID, paymentID uuid.UUID, amount decimal.Decimal, appliedBy uuid.UUID) error
	RemovePayment(ctx context.Context, companyID, invoiceID, paymentID uuid.UUID, removedBy uuid.UUID) error
	GetInvoicePayments(ctx context.Context, companyID, invoiceID uuid.UUID) ([]*InvoicePayment, error)
	GetOutstandingAmount(ctx context.Context, companyID, invoiceID uuid.UUID) (decimal.Decimal, error)
	HasPartialPayments(ctx context.Context, companyID, invoiceID uuid.UUID) (bool, error)
	RefreshPaymentBalances(ctx context.Context, companyID, invoiceID uuid.UUID, updatedBy uuid.UUID) error
	UpdateDueDate(ctx context.Context, companyID, invoiceID uuid.UUID, dueDate time.Time, updatedBy uuid.UUID) error
	GetOverdueInvoices(ctx context.Context, companyID uuid.UUID, at time.Time) ([]*models.Invoice, error)
	GetInvoicesDueSoon(ctx context.Context, companyID uuid.UUID, before time.Time) ([]*models.Invoice, error)
	SendDueReminder(ctx context.Context, companyID, invoiceID uuid.UUID, triggeredBy uuid.UUID) error
	SendOverdueReminder(ctx context.Context, companyID, invoiceID uuid.UUID, triggeredBy uuid.UUID) error
	ValidateCustomerCredit(ctx context.Context, tx repository.DBTX, companyID, customerID uuid.UUID, invoiceAmount decimal.Decimal) error
	CanIssueInvoice(ctx context.Context, tx repository.DBTX, companyID, invoiceID uuid.UUID) error
	ValidateInvoice(ctx context.Context, invoice *models.Invoice, items []*models.InvoiceItem) error
	ValidateInvoiceStatusTransition(ctx context.Context, current, next enums.InvoiceStatus) error
	ValidateInvoiceItems(ctx context.Context, companyID uuid.UUID, items []CreateInvoiceItemRequest) error
	ValidatePricing(ctx context.Context, companyID, invoiceID uuid.UUID) error
	ValidatePayments(ctx context.Context, companyID, invoiceID uuid.UUID) error
	GetTotalInvoicedRevenue(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetCollectedRevenue(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetOutstandingReceivables(ctx context.Context, companyID uuid.UUID) (decimal.Decimal, error)
	GetAveragePaymentTime(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetTopOverdueInvoices(ctx context.Context, companyID uuid.UUID, limit int) ([]*models.Invoice, error)
	InvoiceExists(ctx context.Context, companyID, invoiceID uuid.UUID) (bool, error)
	InvoiceNumberExists(ctx context.Context, companyID uuid.UUID, invoiceNumber string) (bool, error)
	IsInvoicePaid(ctx context.Context, companyID, invoiceID uuid.UUID) (bool, error)
	IsInvoiceOverdue(ctx context.Context, companyID, invoiceID uuid.UUID, at time.Time) (bool, error)
	createDraftInvoiceInTx(ctx context.Context, tx repository.DBTX, req *CreateInvoiceRequest) (*models.Invoice, error)
}

// ------------------------ Implementation ------------------------

type invoiceService struct {
	invoiceRepo      repository.InvoiceRepository
	orderRepo        repository.OrderRepository
	productRepo      repository.ProductRepository
	customerSvc      CustomerService
	pricingRepo      repository.PricingRepository
	discountEngine   DiscountEngineService
	taxSnapshotRepo  repository.TaxSnapshotRepository
	paymentRepo      repository.PaymentRepository
	paymentTermRepo  repository.PaymentTermRepository
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	pgClient         *client.PostgresClient
	logger           *zap.Logger
}

func NewInvoiceService(
	invoiceRepo repository.InvoiceRepository,
	orderRepo repository.OrderRepository,
	productRepo repository.ProductRepository,
	customerSvc CustomerService,
	pricingRepo repository.PricingRepository,
	discountEngine DiscountEngineService,
	taxSnapshotRepo repository.TaxSnapshotRepository,
	paymentRepo repository.PaymentRepository,
	paymentTermRepo repository.PaymentTermRepository,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) InvoiceService {
	return &invoiceService{
		invoiceRepo:      invoiceRepo,
		orderRepo:        orderRepo,
		productRepo:      productRepo,
		customerSvc:      customerSvc,
		pricingRepo:      pricingRepo,
		discountEngine:   discountEngine,
		taxSnapshotRepo:  taxSnapshotRepo,
		paymentRepo:      paymentRepo,
		paymentTermRepo:  paymentTermRepo,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		pgClient:         pgClient,
		logger:           logger.Named("invoice_service"),
	}
}

// ------------------------ Helpers ------------------------

func (s *invoiceService) generateInvoiceNumber(tx repository.DBTX, companyID uuid.UUID) (string, error) {
	prefix := companyID.String()[:8]
	timestamp := time.Now().UnixMilli()
	invNumber := fmt.Sprintf("INV-%s-%d", prefix, timestamp)
	exists, err := s.invoiceRepo.ExistsByNumber(context.Background(), tx, companyID, invNumber)
	if err != nil {
		return "", err
	}
	if exists {
		return fmt.Sprintf("INV-%s-%d-1", prefix, timestamp), nil
	}
	return invNumber, nil
}

func (s *invoiceService) recalculateInvoiceTotals(ctx context.Context, tx repository.DBTX, companyID, invoiceID uuid.UUID) error {
	items, err := s.invoiceRepo.GetItems(ctx, tx, companyID, invoiceID)
	if err != nil {
		return fmt.Errorf("get invoice items: %w", err)
	}

	var subtotal, discountTotal, taxTotal decimal.Decimal
	for _, it := range items {
		lineSubtotal := it.UnitPrice.Mul(it.Quantity)
		subtotal = subtotal.Add(lineSubtotal)
		if it.DiscountAmount != nil {
			discountTotal = discountTotal.Add(*it.DiscountAmount)
		}
		taxable := lineSubtotal
		if it.DiscountAmount != nil {
			taxable = taxable.Sub(*it.DiscountAmount)
		}
		tax := decimal.Zero
		if it.ProductID != nil {
			tax, err = s.pricingRepo.CalculateLineTax(ctx, tx, companyID, *it.ProductID, taxable)
			if err != nil {
				s.logger.Warn("failed to calculate line tax", zap.Error(err), zap.String("item_id", it.InvoiceItemID.String()))
			}
		}
		it.TaxAmount = &tax
		taxTotal = taxTotal.Add(tax)

		updateQuery := `UPDATE sales.invoice_items SET tax_amount = $1 WHERE invoice_item_id = $2`
		if _, err := tx.ExecContext(ctx, updateQuery, tax, it.InvoiceItemID); err != nil {
			return fmt.Errorf("update item tax: %w", err)
		}
	}

	inv, err := s.invoiceRepo.GetByID(ctx, tx, companyID, invoiceID)
	if err != nil {
		return err
	}
	inv.Subtotal = subtotal
	inv.DiscountTotal = discountTotal
	inv.TaxTotal = taxTotal
	inv.GrandTotal = subtotal.Sub(discountTotal).Add(taxTotal)

	if err := s.invoiceRepo.Update(ctx, tx, inv); err != nil {
		return fmt.Errorf("update invoice totals: %w", err)
	}

	_ = s.taxSnapshotRepo.DeleteByEntity(ctx, tx, companyID, "invoice", invoiceID)

	for _, it := range items {
		taxAmount := decimal.Zero
		if it.TaxAmount != nil {
			taxAmount = *it.TaxAmount
		}
		taxable := it.UnitPrice.Mul(it.Quantity)
		if it.DiscountAmount != nil {
			taxable = taxable.Sub(*it.DiscountAmount)
		}
		snapshot := &models.TaxSnapshot{
			TaxSnapshotID: uuid.New(),
			CompanyID:     companyID,
			EntityType:    "invoice",
			EntityID:      invoiceID,
			LineID:        &it.InvoiceItemID,
			TaxableAmount: taxable,
			TaxAmount:     taxAmount,
		}
		if err := s.taxSnapshotRepo.Create(ctx, tx, snapshot); err != nil {
			s.logger.Warn("failed to store tax snapshot", zap.Error(err))
		}
	}
	return nil
}

func (s *invoiceService) emitInvoiceEvent(ctx context.Context, tx repository.DBTX, invoice *models.Invoice, eventType string, extra map[string]interface{}) error {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("tx is not a *sql.Tx")
	}
	payload := salesEvents.InvoicePayload{
		InvoiceID:            invoice.InvoiceID.String(),
		CompanyID:            invoice.CompanyID.String(),
		CustomerID:           invoice.CustomerID.String(),
		OrderID:              invoice.OrderID.String(),
		InvoiceNumber:        invoice.InvoiceNumber,
		Status:               invoice.Status.String(),
		GrandTotal:           invoice.GrandTotal.String(),
		AmountDue:            invoice.AmountDue.String(),
		DueDate:              invoice.DueDate.Format(time.RFC3339),
		InvoiceDate:          invoice.InvoiceDate.Format(time.RFC3339),
		PaymentTermID:        "",
		EarlyDiscountPercent: "",
		EarlyDiscountDays:    0,
	}
	if extra != nil {
		if termID, ok := extra["payment_term_id"].(string); ok {
			payload.PaymentTermID = termID
		}
		if discPct, ok := extra["early_discount_percent"].(string); ok {
			payload.EarlyDiscountPercent = discPct
		}
		if discDays, ok := extra["early_discount_days"].(int); ok {
			payload.EarlyDiscountDays = discDays
		}
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "invoice",
		AggregateID:   invoice.InvoiceID.String(),
		EventType:     eventType,
		Topic:         salesEvents.TopicSalesEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

func (s *invoiceService) validateStatusTransition(current, next enums.InvoiceStatus) error {
	transitions := map[enums.InvoiceStatus][]enums.InvoiceStatus{
		enums.InvoiceStatusDraft:     {enums.InvoiceStatusIssued, enums.InvoiceStatusCancelled},
		enums.InvoiceStatusIssued:    {enums.InvoiceStatusPaid, enums.InvoiceStatusOverdue, enums.InvoiceStatusCancelled, enums.InvoiceStatusCredited},
		enums.InvoiceStatusPaid:      {},
		enums.InvoiceStatusOverdue:   {enums.InvoiceStatusPaid, enums.InvoiceStatusCancelled},
		enums.InvoiceStatusCancelled: {},
		enums.InvoiceStatusCredited:  {},
	}
	allowed, ok := transitions[current]
	if !ok {
		return fmt.Errorf("%w: unknown status %s", salesErrors.ErrInvalidStatus, current)
	}
	for _, st := range allowed {
		if st == next {
			return nil
		}
	}
	return fmt.Errorf("%w: cannot transition from %s to %s", salesErrors.ErrInvalidTransition, current, next)
}

// ------------------------ Core Operations ------------------------

func (s *invoiceService) CreateDraftInvoice(ctx context.Context, req *CreateInvoiceRequest) (*models.Invoice, error) {
	logger := s.logger.With(zap.String("method", "CreateDraftInvoice"))
	if err := s.validateCreateInvoiceRequest(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = uuid.New().String()
	}

	var cached *models.Invoice
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached invoice")
		return cached, nil
	}

	invoiceNumber := req.InvoiceNumber
	if invoiceNumber == "" {
		invoiceNumber, err = s.generateInvoiceNumber(tx, req.CompanyID)
		if err != nil {
			return nil, fmt.Errorf("generate invoice number: %w", err)
		}
	}
	exists, err := s.invoiceRepo.ExistsByNumber(ctx, tx, req.CompanyID, invoiceNumber)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("%w: invoice number %s already exists", salesErrors.ErrDuplicate, invoiceNumber)
	}

	active, err := s.customerSvc.IsCustomerActive(ctx, req.CompanyID, req.CustomerID)
	if err != nil {
		return nil, err
	}
	if !active {
		return nil, salesErrors.ErrCustomerInactive
	}

	invItems := make([]*models.InvoiceItem, 0, len(req.Items))
	for _, it := range req.Items {
		prod, err := s.productRepo.GetByID(ctx, tx, req.CompanyID, it.ProductID)
		if err != nil {
			return nil, fmt.Errorf("product %s: %w", it.ProductID, err)
		}
		if !prod.IsActive {
			return nil, fmt.Errorf("%w: product %s is inactive", salesErrors.ErrProductInactive, prod.SKU)
		}
		unitPrice := prod.UnitPrice
		if it.UnitPrice != nil {
			unitPrice = *it.UnitPrice
		}
		invItem := &models.InvoiceItem{
			InvoiceItemID:       uuid.New(),
			InvoiceID:           uuid.Nil,
			ProductID:           &prod.ProductID,
			ProductNameSnapshot: prod.Name,
			Quantity:            it.Quantity,
			UnitPrice:           unitPrice,
			DiscountAmount:      it.Discount,
			TaxAmount:           nil,
			Metadata:            it.Metadata,
		}
		invItems = append(invItems, invItem)
	}

	invoice := &models.Invoice{
		InvoiceID:            uuid.New(),
		CompanyID:            req.CompanyID,
		CustomerID:           req.CustomerID,
		OrderID:              req.OrderID,
		InvoiceNumber:        invoiceNumber,
		ExternalRef:          req.ExternalRef,
		InvoiceDate:          req.InvoiceDate,
		DueDate:              req.DueDate,
		Status:               enums.InvoiceStatusDraft,
		Currency:             req.Currency,
		Notes:                req.Notes,
		AmountPaid:           decimal.Zero,
		AmountDue:            decimal.Zero,
		IsLocked:             false,
		CreatedBy:            req.CreatedBy,
		UpdatedBy:            req.CreatedBy,
		SalesRepID:           req.SalesRepID,
		PaymentTermName:      req.PaymentTermName,
		PaymentDueDays:       req.PaymentDueDays,
		EarlyDiscountPercent: req.EarlyDiscountPercent,
		EarlyDiscountDays:    req.EarlyDiscountDays,
	}
	if invoice.Currency == "" {
		invoice.Currency = "USD"
	}
	if invoice.InvoiceDate.IsZero() {
		invoice.InvoiceDate = time.Now().Truncate(24 * time.Hour)
	}
	if invoice.DueDate.IsZero() {
		invoice.DueDate = invoice.InvoiceDate.Add(30 * 24 * time.Hour)
	}

	if err := s.invoiceRepo.Create(ctx, tx, invoice, invItems); err != nil {
		return nil, fmt.Errorf("create invoice: %w", err)
	}
	if err := s.recalculateInvoiceTotals(ctx, tx, req.CompanyID, invoice.InvoiceID); err != nil {
		return nil, err
	}
	invoice, err = s.invoiceRepo.GetByID(ctx, tx, req.CompanyID, invoice.InvoiceID)
	if err != nil {
		return nil, err
	}
	if err := s.emitInvoiceEvent(ctx, tx, invoice, salesEvents.EventInvoiceCreated, nil); err != nil {
		logger.Warn("failed to emit invoice created event", zap.Error(err))
	}
	_ = s.idempotencyStore.Store(ctx, tx, idempKey, invoice)
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "sales", "create_invoice", "invoice",
			&invoice.InvoiceID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"invoice_number": invoice.InvoiceNumber,
			})
	}
	return invoice, nil
}

func (s *invoiceService) validateCreateInvoiceRequest(req *CreateInvoiceRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", salesErrors.ErrInvalidInput)
	}
	if req.CustomerID == uuid.Nil {
		return fmt.Errorf("%w: customer_id required", salesErrors.ErrInvalidInput)
	}
	if len(req.Items) == 0 {
		return fmt.Errorf("%w: at least one item required", salesErrors.ErrInvalidInput)
	}
	return s.ValidateInvoiceItems(context.Background(), req.CompanyID, req.Items)
}

func (s *invoiceService) CreateInvoiceFromOrder(ctx context.Context, companyID, orderID uuid.UUID, req *CreateInvoiceFromOrderRequest) (*models.Invoice, error) {
	logger := s.logger.With(zap.String("method", "CreateInvoiceFromOrder"), zap.String("order_id", orderID.String()))

	// Validate notes length (max 1000) – with logging
	if req.Notes != nil {
		notesLen := len(*req.Notes)
		logger.Info("notes length check", zap.Int("len", notesLen))
		if notesLen > 1000 {
			logger.Warn("notes too long", zap.Int("len", notesLen), zap.Int("max", 1000))
			return nil, fmt.Errorf("%w: notes must not exceed 1000 characters", salesErrors.ErrInvalidInput)
		}
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// 1. Get order (with lock)
	order, err := s.orderRepo.GetByIDForUpdate(ctx, tx, companyID, orderID)
	if err != nil {
		return nil, err
	}
	if order.CompanyID != companyID {
		return nil, fmt.Errorf("%w: order does not belong to this company", salesErrors.ErrInvalidInput)
	}
	// Only confirmed/processing/shipped orders can be invoiced
	if order.Status != enums.OrderStatusConfirmed && order.Status != enums.OrderStatusProcessing && order.Status != enums.OrderStatusShipped {
		return nil, fmt.Errorf("%w: only confirmed/processing/shipped orders can be invoiced", salesErrors.ErrInvalidStatus)
	}

	// 2. Get remaining quantities
	remainingMap, err := s.orderRepo.GetRemainingQuantities(ctx, tx, orderID)
	if err != nil {
		return nil, fmt.Errorf("get remaining quantities: %w", err)
	}
	if len(remainingMap) == 0 {
		return nil, fmt.Errorf("%w: order has no items", salesErrors.ErrInvalidInput)
	}

	// 3. Determine items to invoice
	var itemsToInvoice []PartialInvoiceItemInput
	if len(req.Items) == 0 {
		for orderItemID, remaining := range remainingMap {
			if remaining.GreaterThan(decimal.Zero) {
				itemsToInvoice = append(itemsToInvoice, PartialInvoiceItemInput{
					OrderItemID: orderItemID,
					Quantity:    remaining,
				})
			}
		}
	} else {
		itemsToInvoice = req.Items
	}

	if len(itemsToInvoice) == 0 {
		return nil, fmt.Errorf("%w: nothing to invoice (all items fully invoiced)", salesErrors.ErrInvalidInput)
	}

	// 4. Validate quantities against remaining
	for _, invItem := range itemsToInvoice {
		remaining, ok := remainingMap[invItem.OrderItemID]
		if !ok {
			return nil, fmt.Errorf("%w: order_item_id %s not found in order", salesErrors.ErrNotFound, invItem.OrderItemID)
		}
		if invItem.Quantity.LessThanOrEqual(decimal.Zero) {
			return nil, fmt.Errorf("%w: quantity must be positive for item %s", salesErrors.ErrInvalidInput, invItem.OrderItemID)
		}
		if invItem.Quantity.GreaterThan(remaining) {
			return nil, fmt.Errorf("%w: cannot invoice %s of item %s, only %s remaining",
				salesErrors.ErrInvalidAmount,
				invItem.Quantity.String(),
				invItem.OrderItemID.String(),
				remaining.String())
		}
	}

	// 5. Fetch customer and payment term info
	customer, err := s.customerSvc.GetCustomerByID(ctx, companyID, order.CustomerID)
	if err != nil {
		return nil, err
	}
	var paymentTermName *string
	var paymentDueDays *int
	var earlyDiscountPercent *decimal.Decimal
	var earlyDiscountDays *int
	if customer.PaymentTermID != nil {
		term, err := s.paymentTermRepo.GetByID(ctx, tx, companyID, *customer.PaymentTermID)
		if err == nil && term != nil {
			paymentTermName = &term.TermName
			paymentDueDays = &term.DueDays
			if term.DiscountPercent.GreaterThan(decimal.Zero) {
				earlyDiscountPercent = &term.DiscountPercent
				earlyDiscountDays = &term.DiscountDays
			}
		} else {
			logger.Warn("payment term not found", zap.String("term_id", customer.PaymentTermID.String()))
		}
	}

	// 6. Build invoice items
	orderItems, err := s.orderRepo.GetItems(ctx, tx, companyID, orderID)
	if err != nil {
		return nil, err
	}
	orderItemMap := make(map[uuid.UUID]*models.OrderItem)
	for _, oi := range orderItems {
		orderItemMap[oi.OrderItemID] = oi
	}

	invoiceItems := make([]CreateInvoiceItemRequest, 0, len(itemsToInvoice))
	for _, invItem := range itemsToInvoice {
		oi, ok := orderItemMap[invItem.OrderItemID]
		if !ok {
			return nil, fmt.Errorf("%w: order_item_id %s not found", salesErrors.ErrNotFound, invItem.OrderItemID)
		}
		unitPrice := oi.UnitPrice
		invoiceItems = append(invoiceItems, CreateInvoiceItemRequest{
			OrderItemID: &oi.OrderItemID,
			ProductID:   oi.ProductID,
			Quantity:    invItem.Quantity,
			UnitPrice:   &unitPrice,
			Discount:    oi.DiscountAmount,
			Metadata:    oi.Metadata,
		})
	}

	// 7. Prepare and validate invoice dates
	invoiceDate := time.Now()
	if req.InvoiceDate != "" {
		if d, err := time.Parse(time.RFC3339, req.InvoiceDate); err == nil {
			invoiceDate = d
		}
	}
	dueDate := invoiceDate.Add(30 * 24 * time.Hour)
	if req.DueDate != "" {
		if d, err := time.Parse(time.RFC3339, req.DueDate); err == nil {
			dueDate = d
		}
	}
	// due_date cannot be before invoice_date
	if dueDate.Before(invoiceDate) {
		return nil, fmt.Errorf("%w: due_date cannot be before invoice_date", salesErrors.ErrInvalidInput)
	}

	// 8. Create draft invoice using helper (within same tx)
	createReq := &CreateInvoiceRequest{
		CompanyID:            companyID,
		CustomerID:           order.CustomerID,
		OrderID:              &orderID,
		InvoiceDate:          invoiceDate,
		DueDate:              dueDate,
		Currency:             order.Currency,
		Notes:                req.Notes,
		Items:                invoiceItems,
		CreatedBy:            req.CreatedBy,
		SalesRepID:           order.SalesRepID,
		PaymentTermName:      paymentTermName,
		PaymentDueDays:       paymentDueDays,
		EarlyDiscountPercent: earlyDiscountPercent,
		EarlyDiscountDays:    earlyDiscountDays,
	}

	invoice, err := s.createDraftInvoiceInTx(ctx, tx, createReq)
	if err != nil {
		return nil, err
	}

	// 9. Update quantity_invoiced
	for _, invItem := range itemsToInvoice {
		if err := s.orderRepo.UpdateQuantityInvoiced(ctx, tx, invItem.OrderItemID, invItem.Quantity); err != nil {
			return nil, fmt.Errorf("update quantity_invoiced for %s: %w", invItem.OrderItemID, err)
		}
	}

	// 10. Commit
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// 11. Emit events (after commit)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "create_invoice_from_order", "invoice",
			&invoice.InvoiceID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"order_id": orderID.String(),
				"items":    itemsToInvoice,
			})
	}
	_ = s.emitInvoiceEvent(ctx, s.pgClient.DB, invoice, salesEvents.EventInvoiceCreated, nil)

	return invoice, nil
}

func (s *invoiceService) CreateInvoiceFromQuote(ctx context.Context, companyID, quoteID uuid.UUID, req *CreateInvoiceFromQuoteRequest) (*models.Invoice, error) {
	// TODO: implement when quote service is available
	return nil, fmt.Errorf("not implemented yet")
}

func (s *invoiceService) UpdateInvoice(ctx context.Context, companyID, invoiceID uuid.UUID, req *UpdateInvoiceRequest) (*models.Invoice, error) {
	logger := s.logger.With(zap.String("method", "UpdateInvoice"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := invoiceID.String()
	var cached *models.Invoice
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached invoice")
		return cached, nil
	}

	invoice, err := s.invoiceRepo.GetByIDForUpdate(ctx, tx, companyID, invoiceID)
	if err != nil {
		return nil, err
	}
	if invoice.Status != enums.InvoiceStatusDraft {
		return nil, fmt.Errorf("%w: only draft invoices can be updated", salesErrors.ErrInvalidStatus)
	}
	changes := make(map[string]interface{})
	if req.DueDate != nil {
		invoice.DueDate = *req.DueDate
		changes["due_date"] = req.DueDate
	}
	if req.Currency != nil {
		invoice.Currency = *req.Currency
		changes["currency"] = req.Currency
	}
	if req.Notes != nil {
		notesLen := len(*req.Notes)
		logger.Info("notes length check in update", zap.Int("len", notesLen))
		if notesLen > 1000 {
			logger.Warn("notes too long in update", zap.Int("len", notesLen), zap.Int("max", 1000))
			return nil, fmt.Errorf("%w: notes must not exceed 1000 characters", salesErrors.ErrInvalidInput)
		}
		invoice.Notes = req.Notes
		changes["notes"] = req.Notes
	}
	invoice.UpdatedBy = req.UpdatedBy
	if err := s.invoiceRepo.Update(ctx, tx, invoice); err != nil {
		return nil, fmt.Errorf("update invoice: %w", err)
	}
	if err := s.emitInvoiceEvent(ctx, tx, invoice, salesEvents.EventInvoiceUpdated, nil); err != nil {
		logger.Warn("failed to emit invoice updated event", zap.Error(err))
	}
	_ = s.idempotencyStore.Store(ctx, tx, idempKey, invoice)
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "update_invoice", "invoice",
			&invoiceID, "user", req.UpdatedBy, nil, nil, changes)
	}
	return invoice, nil
}

func (s *invoiceService) DeleteInvoice(ctx context.Context, companyID, invoiceID uuid.UUID, deletedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteInvoice"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := invoiceID.String()
	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – already deleted")
		return nil
	}

	invoice, err := s.invoiceRepo.GetByID(ctx, tx, companyID, invoiceID)
	if err != nil {
		return err
	}
	if invoice.Status != enums.InvoiceStatusDraft {
		return fmt.Errorf("%w: only draft invoices can be deleted", salesErrors.ErrInvalidStatus)
	}
	hasPayments, err := s.invoiceRepo.HasPayments(ctx, tx, companyID, invoiceID)
	if err != nil {
		return err
	}
	if hasPayments {
		return fmt.Errorf("%w: cannot delete invoice with payments", salesErrors.ErrConflict)
	}
	if err := s.invoiceRepo.Delete(ctx, tx, companyID, invoiceID); err != nil {
		return fmt.Errorf("delete invoice: %w", err)
	}
	_ = s.idempotencyStore.Store(ctx, tx, idempKey, true)
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "delete_invoice", "invoice",
			&invoiceID, "user", &deletedBy, nil, nil, nil)
	}
	return nil
}

// ------------------------ Retrieval (no idempotency) ------------------------

func (s *invoiceService) GetInvoiceByID(ctx context.Context, companyID, invoiceID uuid.UUID) (*models.Invoice, error) {
	return s.invoiceRepo.GetByID(ctx, s.pgClient.DB, companyID, invoiceID)
}

func (s *invoiceService) GetInvoiceByNumber(ctx context.Context, companyID uuid.UUID, invoiceNumber string) (*models.Invoice, error) {
	return s.invoiceRepo.GetByNumber(ctx, s.pgClient.DB, companyID, invoiceNumber)
}

func (s *invoiceService) ListInvoices(ctx context.Context, filter InvoiceListFilter, p Pagination, srt Sort) ([]*models.Invoice, int64, error) {
	repoFilter := repository.InvoiceFilter{
		CompanyID:       filter.CompanyID,
		CustomerID:      filter.CustomerID,
		OrderID:         filter.OrderID,
		InvoiceDateFrom: filter.FromDate,
		InvoiceDateTo:   filter.ToDate,
		MinGrandTotal:   filter.MinTotal,
		MaxGrandTotal:   filter.MaxTotal,
	}
	if filter.Status != nil {
		repoFilter.Statuses = []enums.InvoiceStatus{*filter.Status}
	}
	return s.invoiceRepo.List(ctx, s.pgClient.DB, repoFilter,
		repository.Pagination{Limit: p.Limit, Offset: p.Offset},
		repository.Sort{Field: srt.Field, Direction: srt.Direction})
}

func (s *invoiceService) SearchInvoices(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.Invoice, int64, error) {
	return s.invoiceRepo.Search(ctx, s.pgClient.DB, companyID, query, limit, offset)
}

func (s *invoiceService) GetInvoicesByCustomer(ctx context.Context, companyID, customerID uuid.UUID, p Pagination, srt Sort) ([]*models.Invoice, int64, error) {
	return s.invoiceRepo.GetByCustomer(ctx, s.pgClient.DB, companyID, customerID,
		repository.Pagination{Limit: p.Limit, Offset: p.Offset},
		repository.Sort{Field: srt.Field, Direction: srt.Direction})
}

func (s *invoiceService) GetInvoicesByOrder(ctx context.Context, companyID, orderID uuid.UUID) ([]*models.Invoice, error) {
	return s.invoiceRepo.GetByOrder(ctx, s.pgClient.DB, companyID, orderID)
}

// ------------------------ Items (no idempotency) ------------------------

func (s *invoiceService) AddItems(ctx context.Context, companyID, invoiceID uuid.UUID, items []CreateInvoiceItemRequest, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	invoice, err := s.invoiceRepo.GetByIDForUpdate(ctx, tx, companyID, invoiceID)
	if err != nil {
		return err
	}
	if invoice.Status != enums.InvoiceStatusDraft {
		return fmt.Errorf("%w: cannot add items to invoice with status %s", salesErrors.ErrInvalidStatus, invoice.Status)
	}
	invItems := make([]*models.InvoiceItem, 0, len(items))
	for _, it := range items {
		prod, err := s.productRepo.GetByID(ctx, tx, companyID, it.ProductID)
		if err != nil {
			return err
		}
		if !prod.IsActive {
			return fmt.Errorf("%w: product %s inactive", salesErrors.ErrProductInactive, prod.SKU)
		}
		unitPrice := prod.UnitPrice
		if it.UnitPrice != nil {
			unitPrice = *it.UnitPrice
		}
		invItems = append(invItems, &models.InvoiceItem{
			InvoiceItemID:       uuid.New(),
			InvoiceID:           invoiceID,
			ProductID:           &prod.ProductID,
			ProductNameSnapshot: prod.Name,
			Quantity:            it.Quantity,
			UnitPrice:           unitPrice,
			DiscountAmount:      it.Discount,
			TaxAmount:           nil,
			Metadata:            it.Metadata,
		})
	}
	if err := s.invoiceRepo.AddItems(ctx, tx, companyID, invoiceID, invItems); err != nil {
		return err
	}
	if err := s.recalculateInvoiceTotals(ctx, tx, companyID, invoiceID); err != nil {
		return err
	}
	invoice.UpdatedBy = &updatedBy
	if err := s.invoiceRepo.Update(ctx, tx, invoice); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *invoiceService) ReplaceItems(ctx context.Context, companyID, invoiceID uuid.UUID, items []CreateInvoiceItemRequest, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	invoice, err := s.invoiceRepo.GetByIDForUpdate(ctx, tx, companyID, invoiceID)
	if err != nil {
		return err
	}
	if invoice.Status != enums.InvoiceStatusDraft {
		return fmt.Errorf("%w: cannot replace items on invoice with status %s", salesErrors.ErrInvalidStatus, invoice.Status)
	}
	if err := s.invoiceRepo.ReplaceItems(ctx, tx, companyID, invoiceID, nil); err != nil {
		return err
	}
	if len(items) > 0 {
		invItems := make([]*models.InvoiceItem, 0, len(items))
		for _, it := range items {
			prod, err := s.productRepo.GetByID(ctx, tx, companyID, it.ProductID)
			if err != nil {
				return err
			}
			if !prod.IsActive {
				return fmt.Errorf("%w: product %s inactive", salesErrors.ErrProductInactive, prod.SKU)
			}
			unitPrice := prod.UnitPrice
			if it.UnitPrice != nil {
				unitPrice = *it.UnitPrice
			}
			invItems = append(invItems, &models.InvoiceItem{
				InvoiceItemID:       uuid.New(),
				InvoiceID:           invoiceID,
				ProductID:           &prod.ProductID,
				ProductNameSnapshot: prod.Name,
				Quantity:            it.Quantity,
				UnitPrice:           unitPrice,
				DiscountAmount:      it.Discount,
				TaxAmount:           nil,
				Metadata:            it.Metadata,
			})
		}
		if err := s.invoiceRepo.AddItems(ctx, tx, companyID, invoiceID, invItems); err != nil {
			return err
		}
	}
	if err := s.recalculateInvoiceTotals(ctx, tx, companyID, invoiceID); err != nil {
		return err
	}
	invoice.UpdatedBy = &updatedBy
	if err := s.invoiceRepo.Update(ctx, tx, invoice); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *invoiceService) RemoveItem(ctx context.Context, companyID, invoiceID, invoiceItemID uuid.UUID, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	invoice, err := s.invoiceRepo.GetByIDForUpdate(ctx, tx, companyID, invoiceID)
	if err != nil {
		return err
	}
	if invoice.Status != enums.InvoiceStatusDraft {
		return fmt.Errorf("%w: cannot remove item from invoice with status %s", salesErrors.ErrInvalidStatus, invoice.Status)
	}
	if err := s.invoiceRepo.DeleteItem(ctx, tx, companyID, invoiceID, invoiceItemID); err != nil {
		return err
	}
	if err := s.recalculateInvoiceTotals(ctx, tx, companyID, invoiceID); err != nil {
		return err
	}
	invoice.UpdatedBy = &updatedBy
	if err := s.invoiceRepo.Update(ctx, tx, invoice); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *invoiceService) GetInvoiceItems(ctx context.Context, companyID, invoiceID uuid.UUID) ([]*models.InvoiceItem, error) {
	return s.invoiceRepo.GetItems(ctx, s.pgClient.DB, companyID, invoiceID)
}

// ------------------------ Pricing (no idempotency) ------------------------

func (s *invoiceService) CalculatePricing(ctx context.Context, companyID, invoiceID uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.recalculateInvoiceTotals(ctx, tx, companyID, invoiceID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *invoiceService) PreviewPricing(ctx context.Context, req *InvoicePricingPreviewRequest) (*InvoicePricingPreviewResult, error) {
	var subtotal, discountTotal, taxTotal decimal.Decimal
	lineDetails := make([]InvoicePricingLineDetail, 0, len(req.Items))
	for _, it := range req.Items {
		prod, err := s.productRepo.GetByID(ctx, s.pgClient.DB, req.CompanyID, it.ProductID)
		if err != nil {
			return nil, err
		}
		unitPrice := prod.UnitPrice
		if it.UnitPrice != nil {
			unitPrice = *it.UnitPrice
		}
		lineSub := unitPrice.Mul(it.Quantity)
		subtotal = subtotal.Add(lineSub)
		discount := decimal.Zero
		if it.DiscountAmount != nil {
			discount = *it.DiscountAmount
			discountTotal = discountTotal.Add(discount)
		}
		taxable := lineSub.Sub(discount)
		tax, err := s.pricingRepo.CalculateLineTax(ctx, s.pgClient.DB, req.CompanyID, it.ProductID, taxable)
		if err != nil {
			return nil, err
		}
		taxTotal = taxTotal.Add(tax)
		lineDetails = append(lineDetails, InvoicePricingLineDetail{
			ProductID:      it.ProductID,
			Quantity:       it.Quantity,
			UnitPrice:      unitPrice,
			DiscountAmount: discount,
			TaxAmount:      tax,
			LineTotal:      lineSub.Sub(discount).Add(tax),
		})
	}
	grandTotal := subtotal.Sub(discountTotal).Add(taxTotal)
	return &InvoicePricingPreviewResult{
		Subtotal:      subtotal,
		DiscountTotal: discountTotal,
		TaxTotal:      taxTotal,
		GrandTotal:    grandTotal,
		LineDetails:   lineDetails,
	}, nil
}

func (s *invoiceService) RecalculateTotals(ctx context.Context, companyID, invoiceID uuid.UUID, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.recalculateInvoiceTotals(ctx, tx, companyID, invoiceID); err != nil {
		return err
	}
	invoice, err := s.invoiceRepo.GetByID(ctx, tx, companyID, invoiceID)
	if err != nil {
		return err
	}
	invoice.UpdatedBy = &updatedBy
	if err := s.invoiceRepo.Update(ctx, tx, invoice); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *invoiceService) GetInvoiceTotals(ctx context.Context, companyID, invoiceID uuid.UUID) (subtotal, discountTotal, taxTotal, grandTotal, amountPaid, amountDue decimal.Decimal, err error) {
	return s.invoiceRepo.GetTotals(ctx, s.pgClient.DB, companyID, invoiceID)
}

// ------------------------ Discounts (no idempotency) ------------------------

func (s *invoiceService) ApplyManualDiscount(ctx context.Context, companyID, invoiceID uuid.UUID, discountAmount decimal.Decimal, reason string, updatedBy uuid.UUID) error {
	if discountAmount.LessThanOrEqual(decimal.Zero) {
		return fmt.Errorf("%w: discount amount must be positive", salesErrors.ErrInvalidAmount)
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	invoice, err := s.invoiceRepo.GetByIDForUpdate(ctx, tx, companyID, invoiceID)
	if err != nil {
		return err
	}
	if invoice.Status != enums.InvoiceStatusDraft {
		return fmt.Errorf("%w: can only apply discount to draft invoice", salesErrors.ErrInvalidStatus)
	}
	invoice.DiscountTotal = invoice.DiscountTotal.Add(discountAmount)
	invoice.GrandTotal = invoice.Subtotal.Sub(invoice.DiscountTotal).Add(invoice.TaxTotal)
	if err := s.invoiceRepo.Update(ctx, tx, invoice); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *invoiceService) RemoveManualDiscount(ctx context.Context, companyID, invoiceID uuid.UUID, updatedBy uuid.UUID) error {
	return fmt.Errorf("not implemented")
}

// ------------------------ Status Transitions (no idempotency) ------------------------

func (s *invoiceService) UpdateStatus(ctx context.Context, companyID, invoiceID uuid.UUID, status enums.InvoiceStatus, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	invoice, err := s.invoiceRepo.GetByIDForUpdate(ctx, tx, companyID, invoiceID)
	if err != nil {
		return err
	}
	if err := s.validateStatusTransition(invoice.Status, status); err != nil {
		return err
	}
	if err := s.invoiceRepo.UpdateStatus(ctx, tx, companyID, invoiceID, status, &updatedBy); err != nil {
		return err
	}
	var eventType string
	switch status {
	case enums.InvoiceStatusIssued:
		eventType = salesEvents.EventInvoiceIssued
	case enums.InvoiceStatusPaid:
		eventType = salesEvents.EventInvoicePaid
	case enums.InvoiceStatusOverdue:
		eventType = salesEvents.EventInvoiceOverdue
	case enums.InvoiceStatusCancelled:
		eventType = salesEvents.EventInvoiceCancelled
	case enums.InvoiceStatusCredited:
		eventType = salesEvents.EventInvoiceCredited
	default:
		eventType = salesEvents.EventInvoiceUpdated
	}
	if err := s.emitInvoiceEvent(ctx, tx, invoice, eventType, nil); err != nil {
		s.logger.Warn("failed to emit invoice status event", zap.Error(err))
	}
	return tx.Commit()
}

func (s *invoiceService) IssueInvoice(ctx context.Context, companyID, invoiceID uuid.UUID, issuedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	invoice, err := s.invoiceRepo.GetByIDForUpdate(ctx, tx, companyID, invoiceID)
	if err != nil {
		return err
	}
	if invoice.Status != enums.InvoiceStatusDraft {
		return fmt.Errorf("%w: only draft invoices can be issued", salesErrors.ErrInvalidTransition)
	}
	if err := s.ValidateCustomerCredit(ctx, tx, companyID, invoice.CustomerID, invoice.GrandTotal); err != nil {
		return err
	}
	if err := s.ValidatePricing(ctx, companyID, invoiceID); err != nil {
		return err
	}
	if err := s.invoiceRepo.Issue(ctx, tx, companyID, invoiceID, time.Now(), &issuedBy); err != nil {
		return err
	}
	invoice.Status = enums.InvoiceStatusIssued
	if err := s.emitInvoiceEvent(ctx, tx, invoice, salesEvents.EventInvoiceIssued, nil); err != nil {
		s.logger.Warn("failed to emit invoice issued event", zap.Error(err))
	}
	return tx.Commit()
}

func (s *invoiceService) MarkAsPaid(ctx context.Context, companyID, invoiceID uuid.UUID, paidAt time.Time, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	invoice, err := s.invoiceRepo.GetByIDForUpdate(ctx, tx, companyID, invoiceID)
	if err != nil {
		return err
	}
	if invoice.Status != enums.InvoiceStatusIssued && invoice.Status != enums.InvoiceStatusOverdue {
		return fmt.Errorf("%w: only issued or overdue invoices can be marked paid", salesErrors.ErrInvalidTransition)
	}
	amountDue, err := s.invoiceRepo.GetAmountDue(ctx, tx, companyID, invoiceID)
	if err != nil {
		return err
	}
	if amountDue.GreaterThan(decimal.Zero) {
		return fmt.Errorf("%w: cannot mark as paid while amount_due > 0", salesErrors.ErrConflict)
	}
	if err := s.invoiceRepo.MarkPaid(ctx, tx, companyID, invoiceID, paidAt, &updatedBy); err != nil {
		return err
	}
	invoice.Status = enums.InvoiceStatusPaid
	if err := s.emitInvoiceEvent(ctx, tx, invoice, salesEvents.EventInvoicePaid, nil); err != nil {
		s.logger.Warn("failed to emit invoice paid event", zap.Error(err))
	}
	return tx.Commit()
}

func (s *invoiceService) MarkAsOverdue(ctx context.Context, companyID, invoiceID uuid.UUID, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	invoice, err := s.invoiceRepo.GetByIDForUpdate(ctx, tx, companyID, invoiceID)
	if err != nil {
		return err
	}
	if invoice.Status != enums.InvoiceStatusIssued {
		return fmt.Errorf("%w: only issued invoices can become overdue", salesErrors.ErrInvalidTransition)
	}
	if time.Now().Before(invoice.DueDate) {
		return fmt.Errorf("%w: invoice due date not yet passed", salesErrors.ErrInvalidTransition)
	}
	if err := s.invoiceRepo.MarkOverdue(ctx, tx, companyID, invoiceID, &updatedBy); err != nil {
		return err
	}
	invoice.Status = enums.InvoiceStatusOverdue
	if err := s.emitInvoiceEvent(ctx, tx, invoice, salesEvents.EventInvoiceOverdue, nil); err != nil {
		s.logger.Warn("failed to emit invoice overdue event", zap.Error(err))
	}
	return tx.Commit()
}

func (s *invoiceService) VoidInvoice(ctx context.Context, companyID, invoiceID uuid.UUID, reason string, voidedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	invoice, err := s.invoiceRepo.GetByIDForUpdate(ctx, tx, companyID, invoiceID)
	if err != nil {
		return err
	}

	if invoice.Status == enums.InvoiceStatusPaid {
		return fmt.Errorf("%w: cannot void a paid invoice", salesErrors.ErrInvalidTransition)
	}

	hasPayments, err := s.invoiceRepo.HasPayments(ctx, tx, companyID, invoiceID)
	if err != nil {
		return err
	}
	if hasPayments {
		return fmt.Errorf("%w: cannot void invoice with existing payments", salesErrors.ErrConflict)
	}

	items, err := s.invoiceRepo.GetItems(ctx, tx, companyID, invoiceID)
	if err != nil {
		return err
	}

	for _, item := range items {
		if item.OrderItemID != nil && item.Quantity.GreaterThan(decimal.Zero) {
			if err := s.orderRepo.DecreaseQuantityInvoiced(ctx, tx, *item.OrderItemID, item.Quantity); err != nil {
				return fmt.Errorf("failed to revert quantity for order item %s: %w", item.OrderItemID.String(), err)
			}
		}
	}

	if err := s.invoiceRepo.Cancel(ctx, tx, companyID, invoiceID, time.Now(), &voidedBy); err != nil {
		return err
	}

	invoice.Status = enums.InvoiceStatusCancelled
	if err := s.emitInvoiceEvent(ctx, tx, invoice, salesEvents.EventInvoiceCancelled, nil); err != nil {
		s.logger.Warn("failed to emit invoice cancelled event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "void_invoice", "invoice",
			&invoiceID, "user", &voidedBy, nil, nil, map[string]interface{}{
				"reason": reason,
			})
	}
	return nil
}

// ------------------------ Payments (no idempotency) ------------------------

func (s *invoiceService) RegisterPayment(ctx context.Context, req *RegisterInvoicePaymentRequest) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	payment, err := s.paymentRepo.GetByID(ctx, tx, req.CompanyID, req.PaymentID)
	if err != nil {
		return err
	}
	if payment.Status != enums.PaymentStatusCompleted {
		return fmt.Errorf("%w: payment not completed", salesErrors.ErrInvalidStatus)
	}
	existingAlloc, err := s.paymentRepo.GetAllocationsByInvoice(ctx, tx, req.CompanyID, req.InvoiceID)
	if err != nil {
		return err
	}
	for _, alloc := range existingAlloc {
		if alloc.PaymentID == req.PaymentID {
			return fmt.Errorf("%w: payment already allocated to this invoice", salesErrors.ErrDuplicate)
		}
	}
	alloc := &models.PaymentAllocation{
		AllocationID: uuid.New(),
		PaymentID:    req.PaymentID,
		InvoiceID:    req.InvoiceID,
		Amount:       req.Amount,
	}
	if err := s.paymentRepo.AddAllocations(ctx, tx, req.CompanyID, req.PaymentID, []*models.PaymentAllocation{alloc}); err != nil {
		return err
	}
	if err := s.invoiceRepo.UpdateAmounts(ctx, tx, req.CompanyID, req.InvoiceID, req.Amount, decimal.Zero, req.AllocatedBy); err != nil {
		return err
	}
	amountDue, err := s.invoiceRepo.GetAmountDue(ctx, tx, req.CompanyID, req.InvoiceID)
	if err != nil {
		return err
	}
	if amountDue.LessThanOrEqual(decimal.Zero) {
		if err := s.invoiceRepo.MarkPaid(ctx, tx, req.CompanyID, req.InvoiceID, time.Now(), req.AllocatedBy); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *invoiceService) ApplyPayment(ctx context.Context, companyID, invoiceID, paymentID uuid.UUID, amount decimal.Decimal, appliedBy uuid.UUID) error {
	return s.RegisterPayment(ctx, &RegisterInvoicePaymentRequest{
		CompanyID:   companyID,
		InvoiceID:   invoiceID,
		PaymentID:   paymentID,
		Amount:      amount,
		AllocatedBy: &appliedBy,
	})
}

func (s *invoiceService) RemovePayment(ctx context.Context, companyID, invoiceID, paymentID uuid.UUID, removedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	allocs, err := s.paymentRepo.GetAllocationsByInvoice(ctx, tx, companyID, invoiceID)
	if err != nil {
		return err
	}
	var allocToDelete *models.PaymentAllocation
	for _, a := range allocs {
		if a.PaymentID == paymentID {
			allocToDelete = a
			break
		}
	}
	if allocToDelete == nil {
		return fmt.Errorf("%w: payment allocation not found", salesErrors.ErrNotFound)
	}
	if err := s.paymentRepo.DeleteAllocation(ctx, tx, companyID, paymentID, allocToDelete.AllocationID); err != nil {
		return err
	}
	if err := s.invoiceRepo.UpdateAmounts(ctx, tx, companyID, invoiceID, decimal.Zero, decimal.Zero, &removedBy); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *invoiceService) GetInvoicePayments(ctx context.Context, companyID, invoiceID uuid.UUID) ([]*InvoicePayment, error) {
	allocs, err := s.paymentRepo.GetAllocationsByInvoice(ctx, s.pgClient.DB, companyID, invoiceID)
	if err != nil {
		return nil, err
	}
	result := make([]*InvoicePayment, 0, len(allocs))
	for _, a := range allocs {
		result = append(result, &InvoicePayment{
			PaymentID:   a.PaymentID,
			Amount:      a.Amount,
			AllocatedAt: a.CreatedAt,
		})
	}
	return result, nil
}

func (s *invoiceService) GetOutstandingAmount(ctx context.Context, companyID, invoiceID uuid.UUID) (decimal.Decimal, error) {
	return s.invoiceRepo.GetAmountDue(ctx, s.pgClient.DB, companyID, invoiceID)
}

func (s *invoiceService) HasPartialPayments(ctx context.Context, companyID, invoiceID uuid.UUID) (bool, error) {
	amountPaid, err := s.invoiceRepo.GetAmountPaid(ctx, s.pgClient.DB, companyID, invoiceID)
	if err != nil {
		return false, err
	}
	grandTotal, _, _, _, _, _, err := s.invoiceRepo.GetTotals(ctx, s.pgClient.DB, companyID, invoiceID)
	if err != nil {
		return false, err
	}
	return amountPaid.GreaterThan(decimal.Zero) && amountPaid.LessThan(grandTotal), nil
}

func (s *invoiceService) RefreshPaymentBalances(ctx context.Context, companyID, invoiceID uuid.UUID, updatedBy uuid.UUID) error {
	_, _, _, _, amountPaid, amountDue, err := s.invoiceRepo.GetTotals(ctx, s.pgClient.DB, companyID, invoiceID)
	if err != nil {
		return err
	}
	if err := s.invoiceRepo.UpdateAmounts(ctx, s.pgClient.DB, companyID, invoiceID, amountPaid, amountDue, &updatedBy); err != nil {
		return err
	}
	return nil
}

func (s *invoiceService) UpdateDueDate(ctx context.Context, companyID, invoiceID uuid.UUID, dueDate time.Time, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	invoice, err := s.invoiceRepo.GetByIDForUpdate(ctx, tx, companyID, invoiceID)
	if err != nil {
		return err
	}
	if invoice.Status != enums.InvoiceStatusDraft && invoice.Status != enums.InvoiceStatusIssued {
		return fmt.Errorf("%w: cannot change due date for invoice in status %s", salesErrors.ErrInvalidStatus, invoice.Status)
	}
	invoice.DueDate = dueDate
	invoice.UpdatedBy = &updatedBy
	if err := s.invoiceRepo.Update(ctx, tx, invoice); err != nil {
		return err
	}
	return tx.Commit()
}

// ------------------------ Reporting & Validation (no idempotency) ------------------------

func (s *invoiceService) GetOverdueInvoices(ctx context.Context, companyID uuid.UUID, at time.Time) ([]*models.Invoice, error) {
	return s.invoiceRepo.GetOverdueInvoices(ctx, s.pgClient.DB, companyID)
}

func (s *invoiceService) GetInvoicesDueSoon(ctx context.Context, companyID uuid.UUID, before time.Time) ([]*models.Invoice, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *invoiceService) SendDueReminder(ctx context.Context, companyID, invoiceID uuid.UUID, triggeredBy uuid.UUID) error {
	return nil
}

func (s *invoiceService) SendOverdueReminder(ctx context.Context, companyID, invoiceID uuid.UUID, triggeredBy uuid.UUID) error {
	return nil
}

func (s *invoiceService) ValidateCustomerCredit(ctx context.Context, tx repository.DBTX, companyID, customerID uuid.UUID, invoiceAmount decimal.Decimal) error {
	canPurchase, err := s.customerSvc.CanCustomerPurchaseAmount(ctx, companyID, customerID, invoiceAmount)
	if err != nil {
		return err
	}
	if !canPurchase {
		return fmt.Errorf("%w: customer credit limit would be exceeded", salesErrors.ErrInvalidAmount)
	}
	return nil
}

func (s *invoiceService) CanIssueInvoice(ctx context.Context, tx repository.DBTX, companyID, invoiceID uuid.UUID) error {
	db := tx
	if db == nil {
		db = s.pgClient.DB
	}
	invoice, err := s.invoiceRepo.GetByID(ctx, db, companyID, invoiceID)
	if err != nil {
		return err
	}
	if invoice.Status != enums.InvoiceStatusDraft {
		return fmt.Errorf("%w: invoice not in draft status", salesErrors.ErrInvalidStatus)
	}
	if invoice.GrandTotal.LessThanOrEqual(decimal.Zero) {
		return fmt.Errorf("%w: invoice total must be positive", salesErrors.ErrInvalidAmount)
	}
	return s.ValidateCustomerCredit(ctx, tx, companyID, invoice.CustomerID, invoice.GrandTotal)
}

func (s *invoiceService) ValidateInvoice(ctx context.Context, invoice *models.Invoice, items []*models.InvoiceItem) error {
	if invoice.InvoiceNumber == "" {
		return fmt.Errorf("%w: invoice number required", salesErrors.ErrInvalidInput)
	}
	if invoice.CustomerID == uuid.Nil {
		return fmt.Errorf("%w: customer_id required", salesErrors.ErrInvalidInput)
	}
	if len(items) == 0 {
		return fmt.Errorf("%w: invoice must have at least one item", salesErrors.ErrInvalidInput)
	}
	for _, it := range items {
		if it.Quantity.LessThanOrEqual(decimal.Zero) {
			return fmt.Errorf("%w: quantity must be positive", salesErrors.ErrInvalidInput)
		}
	}
	return nil
}

func (s *invoiceService) ValidateInvoiceStatusTransition(ctx context.Context, current, next enums.InvoiceStatus) error {
	return s.validateStatusTransition(current, next)
}

func (s *invoiceService) ValidateInvoiceItems(ctx context.Context, companyID uuid.UUID, items []CreateInvoiceItemRequest) error {
	for _, it := range items {
		if it.ProductID == uuid.Nil {
			return fmt.Errorf("%w: product_id required", salesErrors.ErrInvalidInput)
		}
		if it.Quantity.LessThanOrEqual(decimal.Zero) {
			return fmt.Errorf("%w: quantity must be positive", salesErrors.ErrInvalidInput)
		}
		exists, err := s.productRepo.Exists(ctx, s.pgClient.DB, companyID, it.ProductID)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("%w: product %s not found", salesErrors.ErrNotFound, it.ProductID)
		}
	}
	return nil
}

func (s *invoiceService) ValidatePricing(ctx context.Context, companyID, invoiceID uuid.UUID) error {
	items, err := s.invoiceRepo.GetItems(ctx, s.pgClient.DB, companyID, invoiceID)
	if err != nil {
		return err
	}
	var calcSubtotal, calcDiscount, calcTax decimal.Decimal
	for _, it := range items {
		lineSub := it.UnitPrice.Mul(it.Quantity)
		calcSubtotal = calcSubtotal.Add(lineSub)
		if it.DiscountAmount != nil {
			calcDiscount = calcDiscount.Add(*it.DiscountAmount)
		}
		if it.TaxAmount != nil {
			calcTax = calcTax.Add(*it.TaxAmount)
		}
	}
	calcGrand := calcSubtotal.Sub(calcDiscount).Add(calcTax)
	subtotal, discountTotal, taxTotal, grandTotal, _, _, err := s.invoiceRepo.GetTotals(ctx, s.pgClient.DB, companyID, invoiceID)
	if err != nil {
		return err
	}
	if !subtotal.Equal(calcSubtotal) || !discountTotal.Equal(calcDiscount) || !taxTotal.Equal(calcTax) || !grandTotal.Equal(calcGrand) {
		return fmt.Errorf("pricing validation failed: stored totals do not match line items")
	}
	return nil
}

func (s *invoiceService) ValidatePayments(ctx context.Context, companyID, invoiceID uuid.UUID) error {
	amountPaid, err := s.invoiceRepo.GetAmountPaid(ctx, s.pgClient.DB, companyID, invoiceID)
	if err != nil {
		return err
	}
	grandTotal, _, _, _, _, _, err := s.invoiceRepo.GetTotals(ctx, s.pgClient.DB, companyID, invoiceID)
	if err != nil {
		return err
	}
	if amountPaid.GreaterThan(grandTotal) {
		return fmt.Errorf("%w: total payments exceed invoice total", salesErrors.ErrPaymentOverAlloc)
	}
	return nil
}

func (s *invoiceService) GetTotalInvoicedRevenue(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	return s.invoiceRepo.GetInvoiceRevenue(ctx, s.pgClient.DB, companyID, from, to)
}

func (s *invoiceService) GetCollectedRevenue(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	return s.invoiceRepo.GetCollectedRevenue(ctx, s.pgClient.DB, companyID, from, to)
}

func (s *invoiceService) GetOutstandingReceivables(ctx context.Context, companyID uuid.UUID) (decimal.Decimal, error) {
	return s.invoiceRepo.GetOutstandingAmount(ctx, s.pgClient.DB, companyID)
}

func (s *invoiceService) GetAveragePaymentTime(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	return decimal.Zero, nil
}

func (s *invoiceService) GetTopOverdueInvoices(ctx context.Context, companyID uuid.UUID, limit int) ([]*models.Invoice, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *invoiceService) InvoiceExists(ctx context.Context, companyID, invoiceID uuid.UUID) (bool, error) {
	return s.invoiceRepo.Exists(ctx, s.pgClient.DB, companyID, invoiceID)
}

func (s *invoiceService) InvoiceNumberExists(ctx context.Context, companyID uuid.UUID, invoiceNumber string) (bool, error) {
	return s.invoiceRepo.ExistsByNumber(ctx, s.pgClient.DB, companyID, invoiceNumber)
}

func (s *invoiceService) IsInvoicePaid(ctx context.Context, companyID, invoiceID uuid.UUID) (bool, error) {
	inv, err := s.invoiceRepo.GetByID(ctx, s.pgClient.DB, companyID, invoiceID)
	if err != nil {
		return false, err
	}
	return inv.Status == enums.InvoiceStatusPaid, nil
}

func (s *invoiceService) IsInvoiceOverdue(ctx context.Context, companyID, invoiceID uuid.UUID, at time.Time) (bool, error) {
	inv, err := s.invoiceRepo.GetByID(ctx, s.pgClient.DB, companyID, invoiceID)
	if err != nil {
		return false, err
	}
	return inv.Status == enums.InvoiceStatusOverdue || (inv.Status == enums.InvoiceStatusIssued && at.After(inv.DueDate)), nil
}

// createDraftInvoiceInTx creates a draft invoice within an existing transaction.
// It does not start a new transaction and does not commit.
func (s *invoiceService) createDraftInvoiceInTx(ctx context.Context, tx repository.DBTX, req *CreateInvoiceRequest) (*models.Invoice, error) {
	// --- NEW validations with logging ---
	if req.Notes != nil {
		notesLen := len(*req.Notes)
		s.logger.Info("createDraftInvoiceInTx notes length", zap.Int("len", notesLen))
		if notesLen > 1000 {
			s.logger.Warn("notes too long in createDraft", zap.Int("len", notesLen), zap.Int("max", 1000))
			return nil, fmt.Errorf("%w: notes must not exceed 1000 characters", salesErrors.ErrInvalidInput)
		}
	}
	if req.DueDate.Before(req.InvoiceDate) {
		s.logger.Warn("due_date before invoice_date",
			zap.Time("due_date", req.DueDate),
			zap.Time("invoice_date", req.InvoiceDate))
		return nil, fmt.Errorf("%w: due_date cannot be before invoice_date", salesErrors.ErrInvalidInput)
	}
	// -----------------------

	// Generate invoice number if missing
	invoiceNumber := req.InvoiceNumber
	if invoiceNumber == "" {
		var err error
		invoiceNumber, err = s.generateInvoiceNumber(tx, req.CompanyID)
		if err != nil {
			return nil, fmt.Errorf("generate invoice number: %w", err)
		}
	}
	exists, err := s.invoiceRepo.ExistsByNumber(ctx, tx, req.CompanyID, invoiceNumber)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("%w: invoice number %s already exists", salesErrors.ErrDuplicate, invoiceNumber)
	}

	// Validate customer is active
	active, err := s.customerSvc.IsCustomerActive(ctx, req.CompanyID, req.CustomerID)
	if err != nil {
		return nil, err
	}
	if !active {
		return nil, salesErrors.ErrCustomerInactive
	}

	// Build invoice items
	invItems := make([]*models.InvoiceItem, 0, len(req.Items))
	for _, it := range req.Items {
		var productName string
		if it.ProductID != uuid.Nil {
			prod, err := s.productRepo.GetByID(ctx, tx, req.CompanyID, it.ProductID)
			if err != nil {
				return nil, fmt.Errorf("product %s: %w", it.ProductID, err)
			}
			if !prod.IsActive {
				return nil, fmt.Errorf("%w: product %s is inactive", salesErrors.ErrProductInactive, prod.SKU)
			}
			productName = prod.Name
		} else if it.OrderItemID != nil {
			orderItem, err := s.orderRepo.GetItemByID(ctx, tx, req.CompanyID, *req.OrderID, *it.OrderItemID)
			if err != nil {
				return nil, fmt.Errorf("order item %s: %w", it.OrderItemID, err)
			}
			productName = orderItem.ProductNameSnapshot
		} else {
			return nil, fmt.Errorf("%w: either product_id or order_item_id required", salesErrors.ErrInvalidInput)
		}

		unitPrice := decimal.Zero
		if it.UnitPrice != nil {
			unitPrice = *it.UnitPrice
		} else if it.OrderItemID != nil {
			orderItem, err := s.orderRepo.GetItemByID(ctx, tx, req.CompanyID, *req.OrderID, *it.OrderItemID)
			if err != nil {
				return nil, fmt.Errorf("order item %s: %w", it.OrderItemID, err)
			}
			unitPrice = orderItem.UnitPrice
		} else {
			return nil, fmt.Errorf("%w: unit_price required", salesErrors.ErrInvalidInput)
		}

		invItem := &models.InvoiceItem{
			InvoiceItemID:       uuid.New(),
			InvoiceID:           uuid.Nil,
			OrderItemID:         it.OrderItemID,
			ProductID:           &it.ProductID,
			ProductNameSnapshot: productName,
			Quantity:            it.Quantity,
			UnitPrice:           unitPrice,
			DiscountAmount:      it.Discount,
			TaxAmount:           nil,
			Metadata:            it.Metadata,
		}
		invItems = append(invItems, invItem)
	}

	invoice := &models.Invoice{
		InvoiceID:            uuid.New(),
		CompanyID:            req.CompanyID,
		CustomerID:           req.CustomerID,
		OrderID:              req.OrderID,
		InvoiceNumber:        invoiceNumber,
		ExternalRef:          req.ExternalRef,
		InvoiceDate:          req.InvoiceDate,
		DueDate:              req.DueDate,
		Status:               enums.InvoiceStatusDraft,
		Currency:             req.Currency,
		Notes:                req.Notes,
		AmountPaid:           decimal.Zero,
		AmountDue:            decimal.Zero,
		IsLocked:             false,
		CreatedBy:            req.CreatedBy,
		UpdatedBy:            req.CreatedBy,
		SalesRepID:           req.SalesRepID,
		PaymentTermName:      req.PaymentTermName,
		PaymentDueDays:       req.PaymentDueDays,
		EarlyDiscountPercent: req.EarlyDiscountPercent,
		EarlyDiscountDays:    req.EarlyDiscountDays,
	}
	if invoice.Currency == "" {
		invoice.Currency = "USD"
	}
	if invoice.InvoiceDate.IsZero() {
		invoice.InvoiceDate = time.Now().Truncate(24 * time.Hour)
	}
	if invoice.DueDate.IsZero() {
		invoice.DueDate = invoice.InvoiceDate.Add(30 * 24 * time.Hour)
	}
	// Re‑validate after defaults (though unlikely to cause issue, but safe)
	if invoice.DueDate.Before(invoice.InvoiceDate) {
		return nil, fmt.Errorf("%w: due_date cannot be before invoice_date", salesErrors.ErrInvalidInput)
	}

	if err := s.invoiceRepo.Create(ctx, tx, invoice, invItems); err != nil {
		return nil, fmt.Errorf("create invoice: %w", err)
	}
	if err := s.recalculateInvoiceTotals(ctx, tx, req.CompanyID, invoice.InvoiceID); err != nil {
		return nil, err
	}
	// Re‑fetch to get updated totals
	invoice, err = s.invoiceRepo.GetByID(ctx, tx, req.CompanyID, invoice.InvoiceID)
	if err != nil {
		return nil, err
	}
	return invoice, nil
}
