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

// ------------------------ Request/Response DTOs ------------------------

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
	ValidateCustomerCredit(ctx context.Context, companyID, customerID uuid.UUID, invoiceAmount decimal.Decimal) error
	CanIssueInvoice(ctx context.Context, companyID, invoiceID uuid.UUID) error
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
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		pgClient:         pgClient,
		logger:           logger.Named("invoice_service"),
	}
}

// ------------------------ Helper Methods ------------------------

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
		// Calculate tax using pricing repository
		taxable := lineSubtotal
		if it.DiscountAmount != nil {
			taxable = taxable.Sub(*it.DiscountAmount)
		}
		tax, err := s.pricingRepo.CalculateLineTax(ctx, tx, companyID, *it.ProductID, taxable)
		if err != nil {
			return fmt.Errorf("calculate line tax: %w", err)
		}
		it.TaxAmount = &tax
		taxTotal = taxTotal.Add(tax)

		// Update tax amount in DB
		updateQuery := `UPDATE sales.invoice_items SET tax_amount = $1 WHERE invoice_item_id = $2`
		if _, err := tx.ExecContext(ctx, updateQuery, tax, it.InvoiceItemID); err != nil {
			return fmt.Errorf("update item tax: %w", err)
		}
	}

	// Fetch invoice to update totals
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

	// Store tax snapshots
	if err := s.taxSnapshotRepo.DeleteByEntity(ctx, tx, companyID, "invoice", invoiceID); err != nil {
		s.logger.Warn("failed to delete old tax snapshots", zap.Error(err))
	}
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
	for _, s := range allowed {
		if s == next {
			return nil
		}
	}
	return fmt.Errorf("%w: cannot transition from %s to %s", salesErrors.ErrInvalidTransition, current, next)
}

// ------------------------ Core CRUD ------------------------

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

	// Idempotency key is optional – we'll use invoice number as key if empty
	idempKey := req.InvoiceNumber
	if idempKey == "" {
		idempKey = uuid.New().String()
	}
	var cached *models.Invoice
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached invoice")
		return cached, nil
	}

	// Determine invoice number
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

	// Validate customer exists and is active
	active, err := s.customerSvc.IsCustomerActive(ctx, req.CompanyID, req.CustomerID)
	if err != nil {
		return nil, err
	}
	if !active {
		return nil, salesErrors.ErrCustomerInactive
	}

	// Validate items and build invoice items
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
			InvoiceID:           uuid.Nil, // set after invoice created
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

	// Create invoice
	invoice := &models.Invoice{
		InvoiceID:     uuid.New(),
		CompanyID:     req.CompanyID,
		CustomerID:    req.CustomerID,
		OrderID:       req.OrderID,
		InvoiceNumber: invoiceNumber,
		ExternalRef:   req.ExternalRef,
		InvoiceDate:   req.InvoiceDate,
		DueDate:       req.DueDate,
		Status:        enums.InvoiceStatusDraft,
		Currency:      req.Currency,
		Notes:         req.Notes,
		AmountPaid:    decimal.Zero,
		AmountDue:     decimal.Zero,
		IsLocked:      false,
		CreatedBy:     req.CreatedBy,
		UpdatedBy:     req.CreatedBy,
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

	// Recalculate totals (taxes)
	if err := s.recalculateInvoiceTotals(ctx, tx, req.CompanyID, invoice.InvoiceID); err != nil {
		return nil, err
	}

	// Refresh invoice with updated totals
	invoice, err = s.invoiceRepo.GetByID(ctx, tx, req.CompanyID, invoice.InvoiceID)
	if err != nil {
		return nil, err
	}

	// Emit event
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
	// Fetch order and items, then convert to invoice items
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	order, err := s.orderRepo.GetByID(ctx, tx, companyID, orderID)
	if err != nil {
		return nil, err
	}
	if order.Status != enums.OrderStatusConfirmed && order.Status != enums.OrderStatusProcessing && order.Status != enums.OrderStatusShipped {
		return nil, fmt.Errorf("%w: only confirmed/processing/shipped orders can be invoiced", salesErrors.ErrInvalidStatus)
	}

	orderItems, err := s.orderRepo.GetItems(ctx, tx, companyID, orderID)
	if err != nil {
		return nil, err
	}
	invItems := make([]CreateInvoiceItemRequest, 0, len(orderItems))
	for _, oi := range orderItems {
		invItems = append(invItems, CreateInvoiceItemRequest{
			ProductID: oi.ProductID,
			Quantity:  oi.Quantity,
			UnitPrice: &oi.UnitPrice,
			Discount:  oi.DiscountAmount,
		})
	}
	createReq := &CreateInvoiceRequest{
		CompanyID:   companyID,
		CustomerID:  order.CustomerID,
		OrderID:     &orderID,
		InvoiceDate: time.Now(),
		DueDate:     time.Now().Add(30 * 24 * time.Hour),
		Currency:    order.Currency,
		Notes:       req.Notes,
		Items:       invItems,
		CreatedBy:   &req.CreatedBy,
	}
	// Use order number as idempotency key
	invoice, err := s.CreateDraftInvoice(ctx, createReq)
	if err != nil {
		return nil, err
	}
	return invoice, nil
}

func (s *invoiceService) CreateInvoiceFromQuote(ctx context.Context, companyID, quoteID uuid.UUID, req *CreateInvoiceFromQuoteRequest) (*models.Invoice, error) {
	// Similar to order, but we need QuoteService – for brevity, assume similar pattern
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

// ------------------------ Retrieval Methods ------------------------

func (s *invoiceService) GetInvoiceByID(ctx context.Context, companyID, invoiceID uuid.UUID) (*models.Invoice, error) {
	return s.invoiceRepo.GetByID(ctx, nil, companyID, invoiceID)
}

func (s *invoiceService) GetInvoiceByNumber(ctx context.Context, companyID uuid.UUID, invoiceNumber string) (*models.Invoice, error) {
	return s.invoiceRepo.GetByNumber(ctx, nil, companyID, invoiceNumber)
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
	return s.invoiceRepo.List(ctx, nil, repoFilter,
		repository.Pagination{Limit: p.Limit, Offset: p.Offset},
		repository.Sort{Field: srt.Field, Direction: srt.Direction})
}

func (s *invoiceService) SearchInvoices(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.Invoice, int64, error) {
	return s.invoiceRepo.Search(ctx, nil, companyID, query, limit, offset)
}

func (s *invoiceService) GetInvoicesByCustomer(ctx context.Context, companyID, customerID uuid.UUID, p Pagination, srt Sort) ([]*models.Invoice, int64, error) {
	return s.invoiceRepo.GetByCustomer(ctx, nil, companyID, customerID,
		repository.Pagination{Limit: p.Limit, Offset: p.Offset},
		repository.Sort{Field: srt.Field, Direction: srt.Direction})
}

func (s *invoiceService) GetInvoicesByOrder(ctx context.Context, companyID, orderID uuid.UUID) ([]*models.Invoice, error) {
	return s.invoiceRepo.GetByOrder(ctx, nil, companyID, orderID)
}

// ------------------------ Item Management ------------------------

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
	return s.invoiceRepo.GetItems(ctx, nil, companyID, invoiceID)
}

// ------------------------ Pricing ------------------------

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
		prod, err := s.productRepo.GetByID(ctx, nil, req.CompanyID, it.ProductID)
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
		tax, err := s.pricingRepo.CalculateLineTax(ctx, nil, req.CompanyID, it.ProductID, taxable)
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
	return s.invoiceRepo.GetTotals(ctx, nil, companyID, invoiceID)
}

// ------------------------ Discounts ------------------------

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
	// Store manual discount in discount_applications table
	// app := &discount.DiscountApplication{
	// 	ApplicationID: uuid.New(),
	// 	InvoiceID:     &invoiceID,
	// 	DiscountType:  "manual",
	// 	DiscountName:  &reason,
	// 	Amount:        discountAmount,
	// }
	// We need discount usage repository; assuming we have one
	// s.discountUsageRepo.Create(ctx, tx, app)
	// For simplicity, we'll recalculate totals by adding discount to DiscountTotal
	invoice.DiscountTotal = invoice.DiscountTotal.Add(discountAmount)
	invoice.GrandTotal = invoice.Subtotal.Sub(invoice.DiscountTotal).Add(invoice.TaxTotal)
	if err := s.invoiceRepo.Update(ctx, tx, invoice); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *invoiceService) RemoveManualDiscount(ctx context.Context, companyID, invoiceID uuid.UUID, updatedBy uuid.UUID) error {
	// In a real implementation, you would delete the manual discount application and recalc
	return fmt.Errorf("not implemented")
}

// ------------------------ Status Transitions ------------------------

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
	// Emit event based on status
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
	// Validate credit limit
	if err := s.ValidateCustomerCredit(ctx, companyID, invoice.CustomerID, invoice.GrandTotal); err != nil {
		return err
	}
	// Validate pricing consistency
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
		return err
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
	if err := s.invoiceRepo.Cancel(ctx, tx, companyID, invoiceID, time.Now(), &voidedBy); err != nil {
		return err
	}
	invoice.Status = enums.InvoiceStatusCancelled
	if err := s.emitInvoiceEvent(ctx, tx, invoice, salesEvents.EventInvoiceCancelled, nil); err != nil {
		s.logger.Warn("failed to emit invoice cancelled event", zap.Error(err))
	}
	return tx.Commit()
}

// ------------------------ Payment Handling ------------------------

func (s *invoiceService) RegisterPayment(ctx context.Context, req *RegisterInvoicePaymentRequest) error {
	// This method would typically be called by a PaymentService after a payment is completed.
	// It creates a payment allocation and updates invoice balances.
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Validate payment exists and is completed
	payment, err := s.paymentRepo.GetByID(ctx, tx, req.CompanyID, req.PaymentID)
	if err != nil {
		return err
	}
	if payment.Status != enums.PaymentStatusCompleted {
		return fmt.Errorf("%w: payment not completed", salesErrors.ErrInvalidStatus)
	}
	// Check if already allocated to this invoice
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
	// Refresh invoice amount_paid and amount_due via trigger or manual
	if err := s.invoiceRepo.UpdateAmounts(ctx, tx, req.CompanyID, req.InvoiceID, req.Amount, decimal.Zero, req.AllocatedBy); err != nil {
		return err
	}
	// Check if invoice becomes fully paid and update status accordingly
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
	// Similar to RegisterPayment, but maybe partial allocation
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

	// Find allocation and delete
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
	// Recalculate invoice amounts (trigger will handle, but force refresh)
	if err := s.invoiceRepo.UpdateAmounts(ctx, tx, companyID, invoiceID, decimal.Zero, decimal.Zero, &removedBy); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *invoiceService) GetInvoicePayments(ctx context.Context, companyID, invoiceID uuid.UUID) ([]*InvoicePayment, error) {
	allocs, err := s.paymentRepo.GetAllocationsByInvoice(ctx, nil, companyID, invoiceID)
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
	return s.invoiceRepo.GetAmountDue(ctx, nil, companyID, invoiceID)
}

func (s *invoiceService) HasPartialPayments(ctx context.Context, companyID, invoiceID uuid.UUID) (bool, error) {
	amountPaid, err := s.invoiceRepo.GetAmountPaid(ctx, nil, companyID, invoiceID)
	if err != nil {
		return false, err
	}
	grandTotal, _, _, _, _, _, err := s.invoiceRepo.GetTotals(ctx, nil, companyID, invoiceID)
	if err != nil {
		return false, err
	}
	return amountPaid.GreaterThan(decimal.Zero) && amountPaid.LessThan(grandTotal), nil
}

func (s *invoiceService) RefreshPaymentBalances(ctx context.Context, companyID, invoiceID uuid.UUID, updatedBy uuid.UUID) error {
	// The database trigger should already keep amounts consistent. This method can force a recalculation.
	_, _, _, _, amountPaid, amountDue, err := s.invoiceRepo.GetTotals(ctx, nil, companyID, invoiceID)
	if err != nil {
		return err
	}
	if err := s.invoiceRepo.UpdateAmounts(ctx, nil, companyID, invoiceID, amountPaid, amountDue, &updatedBy); err != nil {
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

// ------------------------ Reporting and Validation ------------------------

func (s *invoiceService) GetOverdueInvoices(ctx context.Context, companyID uuid.UUID, at time.Time) ([]*models.Invoice, error) {
	return s.invoiceRepo.GetOverdueInvoices(ctx, nil, companyID)
}

func (s *invoiceService) GetInvoicesDueSoon(ctx context.Context, companyID uuid.UUID, before time.Time) ([]*models.Invoice, error) {
	// Custom query: invoices with due_date <= before and not paid
	return nil, fmt.Errorf("not implemented")
}

func (s *invoiceService) SendDueReminder(ctx context.Context, companyID, invoiceID uuid.UUID, triggeredBy uuid.UUID) error {
	// Placeholder – would integrate with notification service
	return nil
}

func (s *invoiceService) SendOverdueReminder(ctx context.Context, companyID, invoiceID uuid.UUID, triggeredBy uuid.UUID) error {
	return nil
}

func (s *invoiceService) ValidateCustomerCredit(ctx context.Context, companyID, customerID uuid.UUID, invoiceAmount decimal.Decimal) error {
	canPurchase, err := s.customerSvc.CanCustomerPurchaseAmount(ctx, companyID, customerID, invoiceAmount)
	if err != nil {
		return err
	}
	if !canPurchase {
		return fmt.Errorf("%w: customer credit limit would be exceeded", salesErrors.ErrInvalidAmount)
	}
	return nil
}

func (s *invoiceService) CanIssueInvoice(ctx context.Context, companyID, invoiceID uuid.UUID) error {
	invoice, err := s.invoiceRepo.GetByID(ctx, nil, companyID, invoiceID)
	if err != nil {
		return err
	}
	if invoice.Status != enums.InvoiceStatusDraft {
		return fmt.Errorf("%w: invoice not in draft status", salesErrors.ErrInvalidStatus)
	}
	if invoice.GrandTotal.LessThanOrEqual(decimal.Zero) {
		return fmt.Errorf("%w: invoice total must be positive", salesErrors.ErrInvalidAmount)
	}
	return s.ValidateCustomerCredit(ctx, companyID, invoice.CustomerID, invoice.GrandTotal)
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
		exists, err := s.productRepo.Exists(ctx, nil, companyID, it.ProductID)
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
	items, err := s.invoiceRepo.GetItems(ctx, nil, companyID, invoiceID)
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
	subtotal, discountTotal, taxTotal, grandTotal, _, _, err := s.invoiceRepo.GetTotals(ctx, nil, companyID, invoiceID)
	if err != nil {
		return err
	}
	if !subtotal.Equal(calcSubtotal) || !discountTotal.Equal(calcDiscount) || !taxTotal.Equal(calcTax) || !grandTotal.Equal(calcGrand) {
		return fmt.Errorf("pricing validation failed: stored totals do not match line items")
	}
	return nil
}

func (s *invoiceService) ValidatePayments(ctx context.Context, companyID, invoiceID uuid.UUID) error {
	amountPaid, err := s.invoiceRepo.GetAmountPaid(ctx, nil, companyID, invoiceID)
	if err != nil {
		return err
	}
	grandTotal, _, _, _, _, _, err := s.invoiceRepo.GetTotals(ctx, nil, companyID, invoiceID)
	if err != nil {
		return err
	}
	if amountPaid.GreaterThan(grandTotal) {
		return fmt.Errorf("%w: total payments exceed invoice total", salesErrors.ErrPaymentOverAlloc)
	}
	return nil
}

// ------------------------ Analytics ------------------------

func (s *invoiceService) GetTotalInvoicedRevenue(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	return s.invoiceRepo.GetInvoiceRevenue(ctx, nil, companyID, from, to)
}

func (s *invoiceService) GetCollectedRevenue(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	return s.invoiceRepo.GetCollectedRevenue(ctx, nil, companyID, from, to)
}

func (s *invoiceService) GetOutstandingReceivables(ctx context.Context, companyID uuid.UUID) (decimal.Decimal, error) {
	return s.invoiceRepo.GetOutstandingAmount(ctx, nil, companyID)
}

func (s *invoiceService) GetAveragePaymentTime(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	// Placeholder – implement via analytics repo
	return decimal.Zero, nil
}

func (s *invoiceService) GetTopOverdueInvoices(ctx context.Context, companyID uuid.UUID, limit int) ([]*models.Invoice, error) {
	// Custom query
	return nil, fmt.Errorf("not implemented")
}

// ------------------------ Existence Helpers ------------------------

func (s *invoiceService) InvoiceExists(ctx context.Context, companyID, invoiceID uuid.UUID) (bool, error) {
	return s.invoiceRepo.Exists(ctx, nil, companyID, invoiceID)
}

func (s *invoiceService) InvoiceNumberExists(ctx context.Context, companyID uuid.UUID, invoiceNumber string) (bool, error) {
	return s.invoiceRepo.ExistsByNumber(ctx, nil, companyID, invoiceNumber)
}

func (s *invoiceService) IsInvoicePaid(ctx context.Context, companyID, invoiceID uuid.UUID) (bool, error) {
	inv, err := s.invoiceRepo.GetByID(ctx, nil, companyID, invoiceID)
	if err != nil {
		return false, err
	}
	return inv.Status == enums.InvoiceStatusPaid, nil
}

func (s *invoiceService) IsInvoiceOverdue(ctx context.Context, companyID, invoiceID uuid.UUID, at time.Time) (bool, error) {
	inv, err := s.invoiceRepo.GetByID(ctx, nil, companyID, invoiceID)
	if err != nil {
		return false, err
	}
	return inv.Status == enums.InvoiceStatusOverdue || (inv.Status == enums.InvoiceStatusIssued && at.After(inv.DueDate)), nil
}
