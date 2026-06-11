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

// CreditNoteService defines all credit note operations
type CreditNoteService interface {
	CreateDraftCreditNote(ctx context.Context, req *CreateCreditNoteRequest) (*models.CreditNote, error)
	CreateFromInvoice(ctx context.Context, companyID, invoiceID uuid.UUID, req *CreateCreditNoteFromInvoiceRequest) (*models.CreditNote, error)
	CreateFromReturn(ctx context.Context, companyID, returnID uuid.UUID, req *CreateCreditNoteFromReturnRequest) (*models.CreditNote, error)
	UpdateCreditNote(ctx context.Context, companyID, creditNoteID uuid.UUID, req *UpdateCreditNoteRequest) (*models.CreditNote, error)
	DeleteCreditNote(ctx context.Context, companyID, creditNoteID uuid.UUID, deletedBy uuid.UUID) error
	GetCreditNoteByID(ctx context.Context, companyID, creditNoteID uuid.UUID) (*models.CreditNote, error)
	GetCreditNoteByNumber(ctx context.Context, companyID uuid.UUID, creditNoteNumber string) (*models.CreditNote, error)
	ListCreditNotes(ctx context.Context, filter CreditNoteListFilter, p Pagination, s Sort) ([]*models.CreditNote, int64, error)
	SearchCreditNotes(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.CreditNote, int64, error)
	AddItems(ctx context.Context, companyID, creditNoteID uuid.UUID, items []*CreateCreditNoteItemRequest, updatedBy uuid.UUID) error
	ReplaceItems(ctx context.Context, companyID, creditNoteID uuid.UUID, items []*CreateCreditNoteItemRequest, updatedBy uuid.UUID) error
	RemoveItem(ctx context.Context, companyID, creditNoteID, creditNoteItemID uuid.UUID, updatedBy uuid.UUID) error
	GetCreditNoteItems(ctx context.Context, companyID, creditNoteID uuid.UUID) ([]*models.CreditNoteItem, error)
	CalculateTotals(ctx context.Context, companyID, creditNoteID uuid.UUID) error
	PreviewTotals(ctx context.Context, req *CreditNotePreviewRequest) (*CreditNotePreviewResult, error)
	GetCreditNoteTotals(ctx context.Context, companyID, creditNoteID uuid.UUID) (subtotal, taxTotal, totalAmount, remainingAmount decimal.Decimal, err error)
	UpdateStatus(ctx context.Context, companyID, creditNoteID uuid.UUID, status enums.CreditNoteStatus, updatedBy uuid.UUID) error
	IssueCreditNote(ctx context.Context, companyID, creditNoteID uuid.UUID, issuedBy uuid.UUID) error
	VoidCreditNote(ctx context.Context, companyID, creditNoteID uuid.UUID, reason string, voidedBy uuid.UUID) error
	MarkFullyApplied(ctx context.Context, companyID, creditNoteID uuid.UUID, updatedBy uuid.UUID) error
	ApplyToInvoice(ctx context.Context, companyID, creditNoteID, invoiceID uuid.UUID, amount decimal.Decimal, appliedBy uuid.UUID) error
	ApplyToInvoices(ctx context.Context, companyID, creditNoteID uuid.UUID, applications []*CreditNoteApplicationRequest, appliedBy uuid.UUID) error
	AutoApplyToOutstandingInvoices(ctx context.Context, companyID, creditNoteID uuid.UUID, appliedBy uuid.UUID) error
	RemoveApplication(ctx context.Context, companyID, creditNoteID, applicationID uuid.UUID, removedBy uuid.UUID) error
	GetApplications(ctx context.Context, companyID, creditNoteID uuid.UUID) ([]*models.CreditNoteApplication, error)
	GetRemainingBalance(ctx context.Context, companyID, creditNoteID uuid.UUID) (decimal.Decimal, error)
	IsFullyApplied(ctx context.Context, companyID, creditNoteID uuid.UUID) (bool, error)
	GetCustomerCreditBalance(ctx context.Context, companyID, customerID uuid.UUID) (decimal.Decimal, error)
	GetUnusedCreditNotes(ctx context.Context, companyID, customerID uuid.UUID) ([]*models.CreditNote, error)
	ConvertToRefund(ctx context.Context, companyID, creditNoteID uuid.UUID, req *ConvertCreditNoteToRefundRequest) (*models.PaymentRefund, error)
	ValidateCreditNote(ctx context.Context, creditNote *models.CreditNote, items []*models.CreditNoteItem) error
	ValidateApplication(ctx context.Context, companyID, creditNoteID, invoiceID uuid.UUID, amount decimal.Decimal) error
	ValidateStatusTransition(ctx context.Context, currentStatus, nextStatus enums.CreditNoteStatus) error
	GetTotalCreditIssued(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetTotalCreditApplied(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetOutstandingCredits(ctx context.Context, companyID uuid.UUID) (decimal.Decimal, error)
	CreditNoteExists(ctx context.Context, companyID, creditNoteID uuid.UUID) (bool, error)
	CreditNoteNumberExists(ctx context.Context, companyID uuid.UUID, creditNoteNumber string) (bool, error)
}

type creditNoteService struct {
	creditNoteRepo   repository.CreditNoteRepository
	appRepo          repository.CreditNoteApplicationRepository
	invoiceRepo      repository.InvoiceRepository
	invoiceService   InvoiceService
	paymentService   PaymentService
	returnRepo       repository.ReturnRepository
	orderRepo        repository.OrderRepository
	productRepo      repository.ProductRepository
	pgClient         *client.PostgresClient
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	logger           *zap.Logger
}

// NewCreditNoteService creates a new credit note service
func NewCreditNoteService(
	creditNoteRepo repository.CreditNoteRepository,
	appRepo repository.CreditNoteApplicationRepository,
	invoiceRepo repository.InvoiceRepository,
	invoiceService InvoiceService,
	paymentService PaymentService,
	returnRepo repository.ReturnRepository,
	orderRepo repository.OrderRepository,
	productRepo repository.ProductRepository,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) CreditNoteService {
	return &creditNoteService{
		creditNoteRepo:   creditNoteRepo,
		appRepo:          appRepo,
		invoiceRepo:      invoiceRepo,
		invoiceService:   invoiceService,
		paymentService:   paymentService,
		returnRepo:       returnRepo,
		orderRepo:        orderRepo,
		productRepo:      productRepo,
		pgClient:         pgClient,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		logger:           logger.Named("credit_note_service"),
	}
}

// getDBTX returns the appropriate DBTX (transaction or main DB)
func (s *creditNoteService) getDBTX(tx *sql.Tx) repository.DBTX {
	if tx != nil {
		return tx
	}
	return s.pgClient.DB
}

// fetchProductName retrieves product name (uses tx if provided)
func (s *creditNoteService) fetchProductName(ctx context.Context, tx *sql.Tx, productID uuid.UUID) string {
	if productID == uuid.Nil {
		return "Unknown Product"
	}
	var name string
	db := s.getDBTX(tx)
	query := `SELECT name FROM sales.products WHERE product_id = $1`
	err := db.QueryRowContext(ctx, query, productID).Scan(&name)
	if err != nil {
		s.logger.Warn("failed to fetch product name", zap.String("product_id", productID.String()), zap.Error(err))
		return "Product"
	}
	return name
}

// generateCreditNoteNumber generates a unique credit note number inside a transaction
func (s *creditNoteService) generateCreditNoteNumber(ctx context.Context, tx *sql.Tx, companyID uuid.UUID) (string, error) {
	prefix := fmt.Sprintf("CN-%s-", time.Now().Format("20060102"))
	var seq int
	query := `
		SELECT COALESCE(MAX(CAST(SUBSTRING(credit_note_number FROM '[0-9]+$') AS INTEGER)), 0) + 1
		FROM sales.credit_notes
		WHERE company_id = $1 AND credit_note_number LIKE $2
	`
	err := tx.QueryRowContext(ctx, query, companyID, prefix+"%").Scan(&seq)
	if err != nil && err != sql.ErrNoRows {
		return "", fmt.Errorf("generate credit note number: %w", err)
	}
	return fmt.Sprintf("%s%04d", prefix, seq), nil
}

// emitEvent sends a domain event
func (s *creditNoteService) emitEvent(ctx context.Context, tx *sql.Tx, eventType string, creditNote *models.CreditNote, extra map[string]interface{}) error {
	payload := map[string]interface{}{
		"credit_note_id":     creditNote.CreditNoteID.String(),
		"company_id":         creditNote.CompanyID.String(),
		"customer_id":        creditNote.CustomerID.String(),
		"credit_note_number": creditNote.CreditNoteNumber,
		"status":             string(creditNote.Status),
		"total_amount":       creditNote.TotalAmount.String(),
		"issue_date":         creditNote.IssueDate.Format(time.RFC3339),
	}
	if creditNote.InvoiceID != nil {
		payload["invoice_id"] = creditNote.InvoiceID.String()
	}
	if creditNote.ReturnID != nil {
		payload["return_id"] = creditNote.ReturnID.String()
	}
	for k, v := range extra {
		payload[k] = v
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "credit_note",
		AggregateID:   creditNote.CreditNoteID.String(),
		EventType:     eventType,
		Topic:         salesEvents.TopicSalesEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}

// audit logs an action
func (s *creditNoteService) audit(ctx context.Context, companyID uuid.UUID, action string, creditNoteID uuid.UUID, userID *uuid.UUID, changes map[string]interface{}) {
	if s.auditService == nil {
		return
	}
	_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", action, "credit_note",
		&creditNoteID, "user", userID, nil, nil, changes)
}

// ------------------- CreateDraftCreditNote (idempotent) -------------------
func (s *creditNoteService) CreateDraftCreditNote(ctx context.Context, req *CreateCreditNoteRequest) (*models.CreditNote, error) {
	logger := s.logger.With(zap.String("method", "CreateDraftCreditNote"))

	if req.CompanyID == uuid.Nil || req.CustomerID == uuid.Nil || len(req.Items) == 0 {
		return nil, fmt.Errorf("%w: company_id, customer_id and items required", salesErrors.ErrInvalidInput)
	}

	// Idempotency key from context
	idempKey, ok := ctx.Value("idempotency_key").(string)
	if !ok || idempKey == "" {
		return nil, fmt.Errorf("idempotency key missing in context")
	}

	// Check cache
	var cached models.CreditNote
	err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached)
	if err == nil && cached.CreditNoteID != uuid.Nil {
		logger.Info("idempotent – returning cached credit note", zap.String("id", cached.CreditNoteID.String()))
		cached.RemainingAmount = cached.TotalAmount.Add(cached.AmountApplied)
		return &cached, nil
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	number, err := s.generateCreditNoteNumber(ctx, tx, req.CompanyID)
	if err != nil {
		return nil, err
	}

	var creditItems []*models.CreditNoteItem
	var subtotal, taxTotal decimal.Decimal

	for _, it := range req.Items {
		if it.ProductID == uuid.Nil || it.Quantity.LessThanOrEqual(decimal.Zero) || it.UnitPrice.LessThanOrEqual(decimal.Zero) {
			return nil, fmt.Errorf("%w: invalid item", salesErrors.ErrInvalidInput)
		}
		lineAmount := it.UnitPrice.Mul(it.Quantity).Neg()
		taxAmt := decimal.Zero
		if it.TaxRate != nil {
			taxAmt = lineAmount.Mul(*it.TaxRate).Div(decimal.NewFromInt(100)).Round(2)
		}
		creditItem := &models.CreditNoteItem{
			CreditNoteItemID:    uuid.New(),
			InvoiceItemID:       it.InvoiceItemID,
			ProductID:           &it.ProductID,
			ProductNameSnapshot: s.fetchProductName(ctx, tx, it.ProductID),
			Quantity:            it.Quantity,
			UnitPrice:           it.UnitPrice,
			TaxRate:             it.TaxRate,
			TaxAmount:           taxAmt,
			LineAmount:          lineAmount.Add(taxAmt),
		}
		creditItems = append(creditItems, creditItem)
		subtotal = subtotal.Add(lineAmount)
		taxTotal = taxTotal.Add(taxAmt)
	}
	totalAmount := subtotal.Add(taxTotal)

	currency := "USD"
	if req.Currency != nil {
		currency = *req.Currency
	}

	creditNote := &models.CreditNote{
		CreditNoteID:     uuid.New(),
		CompanyID:        req.CompanyID,
		CustomerID:       req.CustomerID,
		CreditNoteNumber: number,
		IssueDate:        req.CreditNoteDate,
		Status:           enums.CreditNoteDraft,
		Currency:         currency,
		Subtotal:         subtotal,
		TaxTotal:         taxTotal,
		TotalAmount:      totalAmount,
		AmountApplied:    decimal.Zero,
		RemainingAmount:  totalAmount,
		Reason:           req.Reason,
		Notes:            req.Notes,
		CreatedBy:        req.CreatedBy,
	}

	if err := s.creditNoteRepo.Create(ctx, tx, creditNote, creditItems); err != nil {
		return nil, err
	}

	// Store idempotency
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, creditNote); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	s.audit(ctx, req.CompanyID, "create_credit_note", creditNote.CreditNoteID, req.CreatedBy, map[string]interface{}{
		"credit_note_number": creditNote.CreditNoteNumber,
		"total_amount":       creditNote.TotalAmount.String(),
	})

	return creditNote, nil
}

// ------------------- CreateFromInvoice (idempotent) -------------------
// ------------------- CreateFromInvoice (idempotent) -------------------
// ------------------- CreateFromInvoice (idempotent) -------------------
func (s *creditNoteService) CreateFromInvoice(ctx context.Context, companyID, invoiceID uuid.UUID, req *CreateCreditNoteFromInvoiceRequest) (*models.CreditNote, error) {
	logger := s.logger.With(zap.String("method", "CreateFromInvoice"))

	idempKey, ok := ctx.Value("idempotency_key").(string)
	if !ok || idempKey == "" {
		return nil, fmt.Errorf("idempotency key missing")
	}

	var cached models.CreditNote
	err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached)
	if err == nil && cached.CreditNoteID != uuid.Nil {
		logger.Info("idempotent – returning cached credit note")
		cached.RemainingAmount = cached.TotalAmount.Add(cached.AmountApplied)
		return &cached, nil
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	invoice, err := s.invoiceRepo.GetByID(ctx, tx, companyID, invoiceID)
	if err != nil {
		return nil, err
	}
	if invoice.Status != enums.InvoiceStatusIssued && invoice.Status != enums.InvoiceStatusOverdue {
		return nil, fmt.Errorf("%w: can only credit issued or overdue invoices", salesErrors.ErrInvalidStatus)
	}

	// ✅ FIX: If the invoice has no remaining amount due, reject immediately
	if invoice.AmountDue.LessThanOrEqual(decimal.Zero) {
		return nil, fmt.Errorf("%w: invoice fully paid – nothing to credit", salesErrors.ErrInvalidInput)
	}

	creditItems, subtotal, taxTotal, err := s.copyInvoiceItemsToCreditNoteItems(ctx, tx, companyID, invoiceID, req.Items)
	if err != nil {
		return nil, err
	}
	totalAmount := subtotal.Add(taxTotal) // negative

	// ✅ FIX: Ensure total credit does not exceed the invoice's amount due
	if totalAmount.Neg().GreaterThan(invoice.AmountDue) {
		return nil, fmt.Errorf("%w: total credit amount (%.2f) exceeds invoice amount due (%.2f)",
			salesErrors.ErrInvalidAmount, totalAmount.Neg().InexactFloat64(), invoice.AmountDue.InexactFloat64())
	}

	number, err := s.generateCreditNoteNumber(ctx, tx, companyID)
	if err != nil {
		return nil, err
	}

	creditNote := &models.CreditNote{
		CreditNoteID:     uuid.New(),
		CompanyID:        companyID,
		CustomerID:       invoice.CustomerID,
		CreditNoteNumber: number,
		InvoiceID:        &invoiceID,
		IssueDate:        time.Now(),
		Status:           enums.CreditNoteDraft,
		Currency:         invoice.Currency,
		Subtotal:         subtotal,
		TaxTotal:         taxTotal,
		TotalAmount:      totalAmount,
		AmountApplied:    decimal.Zero,
		RemainingAmount:  totalAmount,
		Reason:           req.Reason,
		Notes:            req.Notes,
	}

	if err := s.creditNoteRepo.Create(ctx, tx, creditNote, creditItems); err != nil {
		return nil, err
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, creditNote); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	return creditNote, nil
}

// Helper to copy invoice items to credit note items
func (s *creditNoteService) copyInvoiceItemsToCreditNoteItems(
	ctx context.Context,
	tx *sql.Tx,
	companyID, invoiceID uuid.UUID,
	selectedItemIDs []uuid.UUID,
) ([]*models.CreditNoteItem, decimal.Decimal, decimal.Decimal, error) {
	items, err := s.invoiceRepo.GetItems(ctx, tx, companyID, invoiceID)
	if err != nil {
		return nil, decimal.Zero, decimal.Zero, fmt.Errorf("get invoice items: %w", err)
	}

	var filtered []*models.InvoiceItem
	if len(selectedItemIDs) == 0 {
		filtered = items
	} else {
		selected := make(map[uuid.UUID]bool, len(selectedItemIDs))
		for _, id := range selectedItemIDs {
			selected[id] = true
		}
		for _, it := range items {
			if selected[it.InvoiceItemID] {
				filtered = append(filtered, it)
			}
		}
	}
	if len(filtered) == 0 {
		return nil, decimal.Zero, decimal.Zero, fmt.Errorf("no items selected for credit")
	}

	var creditItems []*models.CreditNoteItem
	var subtotal, taxTotal decimal.Decimal
	for _, it := range filtered {
		lineAmount := it.UnitPrice.Mul(it.Quantity).Neg()
		if it.DiscountAmount != nil {
			lineAmount = lineAmount.Sub(*it.DiscountAmount)
		}
		taxAmt := decimal.Zero
		if it.TaxAmount != nil {
			taxAmt = it.TaxAmount.Neg()
			taxTotal = taxTotal.Add(taxAmt)
			lineAmount = lineAmount.Add(taxAmt)
		}
		subtotal = subtotal.Add(lineAmount.Sub(taxAmt))

		creditItem := &models.CreditNoteItem{
			CreditNoteItemID:    uuid.New(),
			InvoiceItemID:       &it.InvoiceItemID,
			ProductID:           it.ProductID,
			ProductNameSnapshot: it.ProductNameSnapshot,
			Quantity:            it.Quantity,
			UnitPrice:           it.UnitPrice,
			TaxAmount:           taxAmt,
			LineAmount:          lineAmount,
		}
		creditItems = append(creditItems, creditItem)
	}
	return creditItems, subtotal, taxTotal, nil
}

// ------------------- CreateFromReturn (idempotent) -------------------
func (s *creditNoteService) CreateFromReturn(ctx context.Context, companyID, returnID uuid.UUID, req *CreateCreditNoteFromReturnRequest) (*models.CreditNote, error) {
	logger := s.logger.With(zap.String("method", "CreateFromReturn"))

	idempKey, ok := ctx.Value("idempotency_key").(string)
	if !ok || idempKey == "" {
		return nil, fmt.Errorf("idempotency key missing")
	}
	var cached models.CreditNote
	err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached)
	if err == nil && cached.CreditNoteID != uuid.Nil {
		logger.Info("idempotent – returning cached credit note")
		cached.RemainingAmount = cached.TotalAmount.Add(cached.AmountApplied)
		return &cached, nil
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	ret, err := s.returnRepo.GetByID(ctx, tx, companyID, returnID)
	if err != nil {
		return nil, err
	}
	if ret.Status != string(enums.ReturnStatusApproved) {
		return nil, fmt.Errorf("%w: return must be approved before generating credit note", salesErrors.ErrInvalidStatus)
	}
	existing, _ := s.creditNoteRepo.GetByReturn(ctx, tx, companyID, returnID)
	if existing != nil {
		return nil, fmt.Errorf("%w: credit note already exists for this return", salesErrors.ErrDuplicate)
	}

	order, err := s.orderRepo.GetByID(ctx, tx, companyID, ret.OrderID)
	if err != nil {
		return nil, fmt.Errorf("failed to get order for return: %w", err)
	}
	returnItems, err := s.returnRepo.GetItems(ctx, tx, companyID, returnID)
	if err != nil {
		return nil, err
	}
	if len(returnItems) == 0 {
		return nil, fmt.Errorf("%w: return has no items", salesErrors.ErrInvalidInput)
	}

	var creditItems []*models.CreditNoteItem
	var subtotal, taxTotal decimal.Decimal
	for _, it := range returnItems {
		lineAmount := it.RefundAmount.Neg()
		creditItem := &models.CreditNoteItem{
			CreditNoteItemID:    uuid.New(),
			ProductID:           &it.ProductID,
			ProductNameSnapshot: it.ProductNameSnapshot,
			Quantity:            it.Quantity,
			UnitPrice:           it.UnitPrice,
			TaxAmount:           decimal.Zero,
			LineAmount:          lineAmount,
		}
		creditItems = append(creditItems, creditItem)
		subtotal = subtotal.Add(lineAmount)
	}
	totalAmount := subtotal.Add(taxTotal)

	number, err := s.generateCreditNoteNumber(ctx, tx, companyID)
	if err != nil {
		return nil, err
	}

	creditNote := &models.CreditNote{
		CreditNoteID:     uuid.New(),
		CompanyID:        companyID,
		CustomerID:       order.CustomerID,
		CreditNoteNumber: number,
		ReturnID:         &returnID,
		IssueDate:        time.Now(),
		Status:           enums.CreditNoteDraft,
		Currency:         "USD",
		Subtotal:         subtotal,
		TaxTotal:         taxTotal,
		TotalAmount:      totalAmount,
		AmountApplied:    decimal.Zero,
		RemainingAmount:  totalAmount,
		Reason:           req.Reason,
		Notes:            req.Notes,
	}

	if err := s.creditNoteRepo.Create(ctx, tx, creditNote, creditItems); err != nil {
		return nil, err
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, creditNote); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return creditNote, nil
}

// ------------------- UpdateCreditNote (idempotent) -------------------
func (s *creditNoteService) UpdateCreditNote(ctx context.Context, companyID, creditNoteID uuid.UUID, req *UpdateCreditNoteRequest) (*models.CreditNote, error) {
	logger := s.logger.With(zap.String("method", "UpdateCreditNote"))
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = creditNoteID.String()
	}

	var cached models.CreditNote
	err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached)
	if err == nil && cached.CreditNoteID != uuid.Nil {
		logger.Info("idempotent – returning cached credit note")
		cached.RemainingAmount = cached.TotalAmount.Add(cached.AmountApplied)
		return &cached, nil
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	cn, err := s.creditNoteRepo.GetByIDForUpdate(ctx, tx, companyID, creditNoteID)
	if err != nil {
		return nil, err
	}
	if cn.Status != enums.CreditNoteDraft {
		// FIX: return conflict (invalid state transition) instead of generic invalid status
		return nil, fmt.Errorf("%w: only draft credit notes can be updated", salesErrors.ErrInvalidStateTransition)
	}
	if req.Reason != nil {
		cn.Reason = req.Reason
	}
	if req.Notes != nil {
		cn.Notes = req.Notes
	}
	if err := s.creditNoteRepo.Update(ctx, tx, cn); err != nil {
		return nil, err
	}
	cn.RemainingAmount = cn.TotalAmount.Add(cn.AmountApplied)

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, cn); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return cn, nil
}

// ------------------- DeleteCreditNote (idempotent) -------------------
func (s *creditNoteService) DeleteCreditNote(ctx context.Context, companyID, creditNoteID uuid.UUID, deletedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteCreditNote"))
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = creditNoteID.String()
	}

	var processed bool
	err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed)
	if err == nil && processed {
		logger.Info("idempotent – already deleted")
		return nil
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	cn, err := s.creditNoteRepo.GetByID(ctx, tx, companyID, creditNoteID)
	if err != nil {
		return err
	}
	if cn.Status != enums.CreditNoteDraft {
		return fmt.Errorf("%w: only draft credit notes can be deleted", salesErrors.ErrInvalidStatus)
	}
	if err := s.creditNoteRepo.Delete(ctx, tx, companyID, creditNoteID); err != nil {
		return err
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

// ------------------- Read methods (no transaction) -------------------
func (s *creditNoteService) GetCreditNoteByID(ctx context.Context, companyID, creditNoteID uuid.UUID) (*models.CreditNote, error) {
	db := s.pgClient.DB
	cn, err := s.creditNoteRepo.GetByID(ctx, db, companyID, creditNoteID)
	if err != nil {
		return nil, err
	}
	cn.RemainingAmount = cn.TotalAmount.Add(cn.AmountApplied)
	return cn, nil
}

func (s *creditNoteService) GetCreditNoteByNumber(ctx context.Context, companyID uuid.UUID, creditNoteNumber string) (*models.CreditNote, error) {
	db := s.pgClient.DB
	return s.creditNoteRepo.GetByNumber(ctx, db, companyID, creditNoteNumber)
}

func (s *creditNoteService) ListCreditNotes(ctx context.Context, filter CreditNoteListFilter, p Pagination, srt Sort) ([]*models.CreditNote, int64, error) {
	db := s.pgClient.DB
	repoFilter := repository.CreditNoteFilter{
		CompanyID:  filter.CompanyID,
		CustomerID: filter.CustomerID,
		Status:     filter.Status,
		FromDate:   filter.FromDate,
		ToDate:     filter.ToDate,
		InvoiceID:  filter.InvoiceID,
		ReturnID:   filter.ReturnID,
	}
	repoPagination := repository.Pagination{Limit: p.Limit, Offset: p.Offset}
	repoSort := repository.Sort{Field: srt.Field, Direction: srt.Direction}
	notes, total, err := s.creditNoteRepo.List(ctx, db, repoFilter, repoPagination, repoSort)
	if err != nil {
		return nil, 0, err
	}
	for _, n := range notes {
		n.RemainingAmount = n.TotalAmount.Add(n.AmountApplied)
	}
	return notes, total, nil
}

func (s *creditNoteService) SearchCreditNotes(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.CreditNote, int64, error) {
	db := s.pgClient.DB
	notes, total, err := s.creditNoteRepo.Search(ctx, db, companyID, query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	for _, n := range notes {
		n.RemainingAmount = n.TotalAmount.Add(n.AmountApplied)
	}
	return notes, total, nil
}

func (s *creditNoteService) GetCreditNoteItems(ctx context.Context, companyID, creditNoteID uuid.UUID) ([]*models.CreditNoteItem, error) {
	db := s.pgClient.DB
	return s.creditNoteRepo.GetItems(ctx, db, companyID, creditNoteID)
}

func (s *creditNoteService) GetCreditNoteTotals(ctx context.Context, companyID, creditNoteID uuid.UUID) (subtotal, taxTotal, totalAmount, remainingAmount decimal.Decimal, err error) {
	cn, err := s.GetCreditNoteByID(ctx, companyID, creditNoteID)
	if err != nil {
		return
	}
	subtotal = cn.Subtotal
	taxTotal = cn.TaxTotal
	totalAmount = cn.TotalAmount
	remainingAmount = cn.TotalAmount.Add(cn.AmountApplied)
	return
}

func (s *creditNoteService) GetRemainingBalance(ctx context.Context, companyID, creditNoteID uuid.UUID) (decimal.Decimal, error) {
	cn, err := s.GetCreditNoteByID(ctx, companyID, creditNoteID)
	if err != nil {
		return decimal.Zero, err
	}
	return cn.RemainingAmount, nil
}

func (s *creditNoteService) IsFullyApplied(ctx context.Context, companyID, creditNoteID uuid.UUID) (bool, error) {
	cn, err := s.GetCreditNoteByID(ctx, companyID, creditNoteID)
	if err != nil {
		return false, err
	}
	return cn.Status == enums.CreditNoteFullyUsed, nil
}

func (s *creditNoteService) GetCustomerCreditBalance(ctx context.Context, companyID, customerID uuid.UUID) (decimal.Decimal, error) {
	db := s.pgClient.DB
	var total decimal.Decimal
	query := `
		SELECT COALESCE(SUM(-total_amount - amount_applied), 0)
		FROM sales.credit_notes
		WHERE company_id = $1 AND customer_id = $2 AND status IN ('issued', 'partially_used')
	`
	err := db.QueryRowContext(ctx, query, companyID, customerID).Scan(&total)
	return total, err
}

func (s *creditNoteService) GetUnusedCreditNotes(ctx context.Context, companyID, customerID uuid.UUID) ([]*models.CreditNote, error) {
	return s.creditNoteRepo.GetUnusedByCustomer(ctx, s.pgClient.DB, companyID, customerID)
}

func (s *creditNoteService) CreditNoteExists(ctx context.Context, companyID, creditNoteID uuid.UUID) (bool, error) {
	db := s.pgClient.DB
	return s.creditNoteRepo.Exists(ctx, db, companyID, creditNoteID)
}

func (s *creditNoteService) CreditNoteNumberExists(ctx context.Context, companyID uuid.UUID, creditNoteNumber string) (bool, error) {
	db := s.pgClient.DB
	return s.creditNoteRepo.ExistsByNumber(ctx, db, companyID, creditNoteNumber)
}

// ------------------- Item management (idempotent) -------------------
func (s *creditNoteService) AddItems(ctx context.Context, companyID, creditNoteID uuid.UUID, items []*CreateCreditNoteItemRequest, updatedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "AddItems"))
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = creditNoteID.String() + "-add"
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – items already added")
		return nil
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	cn, err := s.creditNoteRepo.GetByIDForUpdate(ctx, tx, companyID, creditNoteID)
	if err != nil {
		return err
	}
	if cn.Status != enums.CreditNoteDraft {
		return fmt.Errorf("%w: only draft credit notes can be modified", salesErrors.ErrInvalidStatus)
	}
	var creditItems []*models.CreditNoteItem
	for _, it := range items {
		if it.ProductID == uuid.Nil || it.Quantity.LessThanOrEqual(decimal.Zero) || it.UnitPrice.LessThanOrEqual(decimal.Zero) {
			return fmt.Errorf("%w: invalid item", salesErrors.ErrInvalidInput)
		}
		lineAmount := it.UnitPrice.Mul(it.Quantity).Neg()
		taxAmt := decimal.Zero
		if it.TaxRate != nil {
			taxAmt = lineAmount.Mul(*it.TaxRate).Div(decimal.NewFromInt(100)).Round(2)
		}
		creditItem := &models.CreditNoteItem{
			CreditNoteItemID:    uuid.New(),
			InvoiceItemID:       it.InvoiceItemID,
			ProductID:           &it.ProductID,
			ProductNameSnapshot: s.fetchProductName(ctx, tx, it.ProductID),
			Quantity:            it.Quantity,
			UnitPrice:           it.UnitPrice,
			TaxRate:             it.TaxRate,
			TaxAmount:           taxAmt,
			LineAmount:          lineAmount.Add(taxAmt),
		}
		creditItems = append(creditItems, creditItem)
	}
	if err := s.creditNoteRepo.AddItems(ctx, tx, companyID, creditNoteID, creditItems); err != nil {
		return err
	}
	if err := s.creditNoteRepo.RecalculateTotals(ctx, tx, companyID, creditNoteID); err != nil {
		return err
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *creditNoteService) ReplaceItems(ctx context.Context, companyID, creditNoteID uuid.UUID, items []*CreateCreditNoteItemRequest, updatedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "ReplaceItems"))
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = creditNoteID.String() + "-replace"
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – items already replaced")
		return nil
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	cn, err := s.creditNoteRepo.GetByIDForUpdate(ctx, tx, companyID, creditNoteID)
	if err != nil {
		return err
	}
	if cn.Status != enums.CreditNoteDraft {
		return fmt.Errorf("%w: only draft credit notes can be modified", salesErrors.ErrInvalidStatus)
	}
	var creditItems []*models.CreditNoteItem
	for _, it := range items {
		if it.ProductID == uuid.Nil || it.Quantity.LessThanOrEqual(decimal.Zero) || it.UnitPrice.LessThanOrEqual(decimal.Zero) {
			return fmt.Errorf("%w: invalid item", salesErrors.ErrInvalidInput)
		}
		lineAmount := it.UnitPrice.Mul(it.Quantity).Neg()
		taxAmt := decimal.Zero
		if it.TaxRate != nil {
			taxAmt = lineAmount.Mul(*it.TaxRate).Div(decimal.NewFromInt(100)).Round(2)
		}
		creditItem := &models.CreditNoteItem{
			CreditNoteItemID:    uuid.New(),
			InvoiceItemID:       it.InvoiceItemID,
			ProductID:           &it.ProductID,
			ProductNameSnapshot: s.fetchProductName(ctx, tx, it.ProductID),
			Quantity:            it.Quantity,
			UnitPrice:           it.UnitPrice,
			TaxRate:             it.TaxRate,
			TaxAmount:           taxAmt,
			LineAmount:          lineAmount.Add(taxAmt),
		}
		creditItems = append(creditItems, creditItem)
	}
	if err := s.creditNoteRepo.ReplaceItems(ctx, tx, companyID, creditNoteID, creditItems); err != nil {
		return err
	}
	if err := s.creditNoteRepo.RecalculateTotals(ctx, tx, companyID, creditNoteID); err != nil {
		return err
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *creditNoteService) RemoveItem(ctx context.Context, companyID, creditNoteID, creditNoteItemID uuid.UUID, updatedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "RemoveItem"))
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = creditNoteID.String() + "-remove"
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – item already removed")
		return nil
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	cn, err := s.creditNoteRepo.GetByIDForUpdate(ctx, tx, companyID, creditNoteID)
	if err != nil {
		return err
	}
	if cn.Status != enums.CreditNoteDraft {
		return fmt.Errorf("%w: only draft credit notes can be modified", salesErrors.ErrInvalidStatus)
	}
	if err := s.creditNoteRepo.DeleteItem(ctx, tx, companyID, creditNoteID, creditNoteItemID); err != nil {
		return err
	}
	if err := s.creditNoteRepo.RecalculateTotals(ctx, tx, companyID, creditNoteID); err != nil {
		return err
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

// ------------------- Calculate & Preview -------------------
func (s *creditNoteService) CalculateTotals(ctx context.Context, companyID, creditNoteID uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.creditNoteRepo.RecalculateTotals(ctx, tx, companyID, creditNoteID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *creditNoteService) PreviewTotals(ctx context.Context, req *CreditNotePreviewRequest) (*CreditNotePreviewResult, error) {
	var subtotal, taxTotal decimal.Decimal
	for _, it := range req.Items {
		lineAmount := it.UnitPrice.Mul(it.Quantity).Neg()
		taxAmt := decimal.Zero
		if it.TaxRate != nil {
			taxAmt = lineAmount.Mul(*it.TaxRate).Div(decimal.NewFromInt(100)).Round(2)
		}
		subtotal = subtotal.Add(lineAmount)
		taxTotal = taxTotal.Add(taxAmt)
	}
	return &CreditNotePreviewResult{
		Subtotal:    subtotal,
		TaxTotal:    taxTotal,
		TotalAmount: subtotal.Add(taxTotal),
	}, nil
}

// ------------------- Status transitions (idempotent) -------------------
func (s *creditNoteService) UpdateStatus(ctx context.Context, companyID, creditNoteID uuid.UUID, status enums.CreditNoteStatus, updatedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "UpdateStatus"))
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = creditNoteID.String() + "-status"
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – status already updated")
		return nil
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.creditNoteRepo.UpdateStatus(ctx, tx, companyID, creditNoteID, status, &updatedBy); err != nil {
		return err
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *creditNoteService) IssueCreditNote(ctx context.Context, companyID, creditNoteID uuid.UUID, issuedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "IssueCreditNote"))
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = creditNoteID.String() + "-issue"
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – already issued")
		return nil
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	cn, err := s.creditNoteRepo.GetByIDForUpdate(ctx, tx, companyID, creditNoteID)
	if err != nil {
		return err
	}
	if cn.Status != enums.CreditNoteDraft {
		return fmt.Errorf("%w: only draft credit notes can be issued", salesErrors.ErrInvalidStatus)
	}
	now := time.Now()
	if err := s.creditNoteRepo.Issue(ctx, tx, companyID, creditNoteID, now, &issuedBy); err != nil {
		return err
	}
	if err := s.emitEvent(ctx, tx, "sales.credit_note.issued", cn, nil); err != nil {
		logger.Warn("failed to emit issued event", zap.Error(err))
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

// FIX: VoidCreditNote handles idempotency for already voided notes
func (s *creditNoteService) VoidCreditNote(ctx context.Context, companyID, creditNoteID uuid.UUID, reason string, voidedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "VoidCreditNote"))
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = creditNoteID.String() + "-void"
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – already voided")
		return nil
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	cn, err := s.creditNoteRepo.GetByIDForUpdate(ctx, tx, companyID, creditNoteID)
	if err != nil {
		return err
	}
	// Idempotent: if already voided, treat as success
	if cn.Status == enums.CreditNoteVoided {
		logger.Info("credit note already voided – idempotent")
		return nil
	}
	if cn.Status == enums.CreditNoteFullyUsed {
		return fmt.Errorf("%w: cannot void fully used credit note", salesErrors.ErrInvalidStatus)
	}
	now := time.Now()
	if err := s.creditNoteRepo.Void(ctx, tx, companyID, creditNoteID, reason, now, &voidedBy); err != nil {
		return err
	}
	if err := s.emitEvent(ctx, tx, "sales.credit_note.voided", cn, map[string]interface{}{"reason": reason}); err != nil {
		logger.Warn("failed to emit voided event", zap.Error(err))
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *creditNoteService) MarkFullyApplied(ctx context.Context, companyID, creditNoteID uuid.UUID, updatedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "MarkFullyApplied"))
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = creditNoteID.String() + "-fully-applied"
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – already marked fully applied")
		return nil
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	cn, err := s.creditNoteRepo.GetByIDForUpdate(ctx, tx, companyID, creditNoteID)
	if err != nil {
		return err
	}
	if cn.Status != enums.CreditNotePartiallyUsed && cn.Status != enums.CreditNoteIssued {
		return fmt.Errorf("%w: cannot mark fully applied from status %s", salesErrors.ErrInvalidStatus, cn.Status)
	}
	if err := s.creditNoteRepo.UpdateStatus(ctx, tx, companyID, creditNoteID, enums.CreditNoteFullyUsed, &updatedBy); err != nil {
		return err
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

// ------------------- Apply to invoices (idempotent) -------------------
func (s *creditNoteService) ApplyToInvoice(ctx context.Context, companyID, creditNoteID, invoiceID uuid.UUID, amount decimal.Decimal, appliedBy uuid.UUID) error {
	return s.ApplyToInvoices(ctx, companyID, creditNoteID, []*CreditNoteApplicationRequest{{InvoiceID: invoiceID, Amount: amount}}, appliedBy)
}

// FIX: Correct remaining balance calculation and logging
func (s *creditNoteService) ApplyToInvoices(ctx context.Context, companyID, creditNoteID uuid.UUID, applications []*CreditNoteApplicationRequest, appliedBy uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "ApplyToInvoices"),
		zap.String("credit_note_id", creditNoteID.String()),
		zap.String("company_id", companyID.String()),
	)

	if len(applications) == 0 {
		logger.Warn("no applications provided")
		return nil
	}

	idempKey, ok := ctx.Value("idempotency_key").(string)
	if !ok || idempKey == "" {
		idempKey = creditNoteID.String() + "-apply"
		logger.Warn("idempotency key not found in context, using fallback", zap.String("fallback_key", idempKey))
	}

	var processed bool
	err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed)
	if err == nil && processed {
		logger.Info("idempotent – applications already processed")
		return nil
	}
	logger.Info("no cached result, starting transaction")

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		logger.Error("failed to begin transaction", zap.Error(err))
		return err
	}
	defer tx.Rollback()

	// Lock credit note for update
	cn, err := s.creditNoteRepo.GetByIDForUpdate(ctx, tx, companyID, creditNoteID)
	if err != nil {
		logger.Error("failed to get credit note for update", zap.Error(err))
		return err
	}
	logger.Info("credit note retrieved",
		zap.String("status", string(cn.Status)),
		zap.String("total_amount", cn.TotalAmount.String()),
		zap.String("amount_applied", cn.AmountApplied.String()),
	)

	// FIX: RemainingAmount = TotalAmount + AmountApplied (negative)
	remaining := cn.TotalAmount.Add(cn.AmountApplied) // e.g., -550 + 100 = -450
	availableCredit := remaining.Neg()                // 450
	logger.Info("remaining balance", zap.String("remaining", remaining.String()))
	logger.Info("available credit", zap.String("available_credit", availableCredit.String()))

	totalApply := decimal.Zero
	for i, app := range applications {
		if app.Amount.LessThanOrEqual(decimal.Zero) {
			logger.Error("invalid amount in application", zap.Int("index", i), zap.String("amount", app.Amount.String()))
			return fmt.Errorf("%w: amount must be positive", salesErrors.ErrInvalidAmount)
		}
		totalApply = totalApply.Add(app.Amount)
	}
	logger.Info("total application amount", zap.String("total_apply", totalApply.String()))

	if totalApply.GreaterThan(availableCredit) {
		logger.Error("total application exceeds available credit",
			zap.String("total_apply", totalApply.String()),
			zap.String("available_credit", availableCredit.String()))
		return fmt.Errorf("%w: total application amount exceeds remaining balance", salesErrors.ErrInvalidAmount)
	}

	// Process each application
	for i, app := range applications {
		logger.Info("processing application",
			zap.Int("index", i),
			zap.String("invoice_id", app.InvoiceID.String()),
			zap.String("amount", app.Amount.String()),
		)
		if err := s.applyToInvoiceInternal(ctx, tx, companyID, creditNoteID, app.InvoiceID, app.Amount, appliedBy); err != nil {
			logger.Error("applyToInvoiceInternal failed", zap.Int("index", i), zap.Error(err))
			return err
		}
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		logger.Error("commit transaction failed", zap.Error(err))
		return err
	}
	logger.Info("successfully applied all applications")
	return nil
}

// FIX: AutoApply uses correct available credit calculation
func (s *creditNoteService) AutoApplyToOutstandingInvoices(ctx context.Context, companyID, creditNoteID uuid.UUID, appliedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "AutoApplyToOutstandingInvoices"))
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = creditNoteID.String() + "-auto-apply"
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – auto-apply already done")
		return nil
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	cn, err := s.creditNoteRepo.GetByIDForUpdate(ctx, tx, companyID, creditNoteID)
	if err != nil {
		return err
	}
	// FIX: available credit = -total_amount - amount_applied (positive)
	available := cn.TotalAmount.Neg().Sub(cn.AmountApplied)
	if available.LessThanOrEqual(decimal.Zero) {
		logger.Info("no available credit", zap.String("available", available.String()))
		return nil
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT invoice_id, amount_due
		FROM sales.invoices
		WHERE company_id = $1 AND customer_id = $2 AND status IN ('issued', 'overdue') AND amount_due > 0
		ORDER BY invoice_date ASC
	`, companyID, cn.CustomerID)
	if err != nil {
		return err
	}
	defer rows.Close()

	var apps []*CreditNoteApplicationRequest
	remainingAvailable := available
	for rows.Next() {
		var invID uuid.UUID
		var due decimal.Decimal
		if err := rows.Scan(&invID, &due); err != nil {
			return err
		}
		if remainingAvailable.IsZero() {
			break
		}
		applyAmount := due
		if applyAmount.GreaterThan(remainingAvailable) {
			applyAmount = remainingAvailable
		}
		apps = append(apps, &CreditNoteApplicationRequest{InvoiceID: invID, Amount: applyAmount})
		remainingAvailable = remainingAvailable.Sub(applyAmount)
	}
	for _, app := range apps {
		if err := s.applyToInvoiceInternal(ctx, tx, companyID, creditNoteID, app.InvoiceID, app.Amount, appliedBy); err != nil {
			return err
		}
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

// internal application logic (assumes tx and credit note already locked)
func (s *creditNoteService) applyToInvoiceInternal(ctx context.Context, tx *sql.Tx, companyID, creditNoteID, invoiceID uuid.UUID, amount decimal.Decimal, appliedBy uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "applyToInvoiceInternal"),
		zap.String("credit_note_id", creditNoteID.String()),
		zap.String("invoice_id", invoiceID.String()),
		zap.String("amount", amount.String()),
	)

	// Lock credit note again (already locked by caller, but safe to re-fetch)
	cn, err := s.creditNoteRepo.GetByIDForUpdate(ctx, tx, companyID, creditNoteID)
	if err != nil {
		logger.Error("failed to get credit note", zap.Error(err))
		return err
	}
	remaining := cn.TotalAmount.Add(cn.AmountApplied) // negative
	logger.Info("credit note state", zap.String("status", string(cn.Status)), zap.String("remaining", remaining.String()))

	if amount.GreaterThan(remaining.Neg()) {
		logger.Error("amount exceeds remaining balance", zap.String("amount", amount.String()), zap.String("remaining_abs", remaining.Neg().String()))
		return fmt.Errorf("%w: amount exceeds remaining balance", salesErrors.ErrInvalidAmount)
	}

	// Lock invoice for update
	invoice, err := s.invoiceRepo.GetByIDForUpdate(ctx, tx, companyID, invoiceID)
	if err != nil {
		logger.Error("failed to get invoice for update", zap.Error(err))
		return err
	}
	logger.Info("invoice state", zap.String("status", string(invoice.Status)), zap.String("amount_due", invoice.AmountDue.String()), zap.String("grand_total", invoice.GrandTotal.String()))

	// FIX: Clear error messages
	if invoice.Status != enums.InvoiceStatusIssued && invoice.Status != enums.InvoiceStatusOverdue {
		logger.Error("invoice not eligible", zap.String("status", string(invoice.Status)), zap.String("expected", "issued or overdue"))
		return fmt.Errorf("%w: invoice not eligible for credit application (status=%s)", salesErrors.ErrInvalidStatus, invoice.Status)
	}
	if invoice.AmountDue.LessThanOrEqual(decimal.Zero) {
		logger.Error("invoice fully paid", zap.String("amount_due", invoice.AmountDue.String()))
		return fmt.Errorf("%w: invoice fully paid – cannot apply credit", salesErrors.ErrInvalidAmount)
	}
	if amount.GreaterThan(invoice.AmountDue) {
		logger.Error("amount exceeds invoice amount due", zap.String("amount_due", invoice.AmountDue.String()))
		return fmt.Errorf("%w: amount exceeds invoice amount due", salesErrors.ErrInvalidAmount)
	}

	// Create application record
	app := &models.CreditNoteApplication{
		ApplicationID: uuid.New(),
		CreditNoteID:  creditNoteID,
		InvoiceID:     invoiceID,
		Amount:        amount,
		AppliedAt:     time.Now(),
		AppliedBy:     &appliedBy,
	}
	if err := s.appRepo.Create(ctx, tx, app); err != nil {
		logger.Error("failed to create application record", zap.Error(err))
		return err
	}

	// Update applied amount on credit note
	if err := s.creditNoteRepo.UpdateAppliedAmount(ctx, tx, companyID, creditNoteID, amount, &appliedBy); err != nil {
		logger.Error("failed to update applied amount on credit note", zap.Error(err))
		return err
	}

	// Update invoice amount_due
	newAmountDue := invoice.AmountDue.Sub(amount)
	if newAmountDue.LessThan(decimal.Zero) {
		newAmountDue = decimal.Zero
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE sales.invoices 
		SET amount_due = $3, updated_at = NOW(), updated_by = $4 
		WHERE invoice_id = $1 AND company_id = $2`,
		invoiceID, companyID, newAmountDue, uuid.NullUUID{UUID: appliedBy, Valid: true})
	if err != nil {
		logger.Error("failed to update invoice amount_due", zap.Error(err))
		return err
	}
	logger.Info("invoice amount_due updated", zap.String("new_amount_due", newAmountDue.String()))

	// Emit event
	if err := s.emitEvent(ctx, tx, "sales.credit_note.applied", cn, map[string]interface{}{
		"invoice_id": invoiceID.String(),
		"amount":     amount.String(),
	}); err != nil {
		logger.Warn("failed to emit applied event", zap.Error(err))
	}

	logger.Info("application successful")
	return nil
}

// ------------------- Application removal (idempotent) -------------------
func (s *creditNoteService) RemoveApplication(ctx context.Context, companyID, creditNoteID, applicationID uuid.UUID, removedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "RemoveApplication"))
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = creditNoteID.String() + "-remove-app"
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – application already removed")
		return nil
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	app, err := s.appRepo.GetByIDForUpdate(ctx, tx, applicationID)
	if err != nil {
		return err
	}
	if app.CreditNoteID != creditNoteID {
		return salesErrors.ErrPermissionDenied
	}
	cn, err := s.creditNoteRepo.GetByIDForUpdate(ctx, tx, companyID, creditNoteID)
	if err != nil {
		return err
	}
	if cn.Status == enums.CreditNoteFullyUsed || cn.Status == enums.CreditNoteVoided {
		return fmt.Errorf("%w: cannot remove application from %s credit note", salesErrors.ErrInvalidStatus, cn.Status)
	}
	invoice, err := s.invoiceRepo.GetByIDForUpdate(ctx, tx, companyID, app.InvoiceID)
	if err != nil {
		return err
	}
	newAmountDue := invoice.AmountDue.Add(app.Amount)
	if newAmountDue.GreaterThan(invoice.GrandTotal) {
		newAmountDue = invoice.GrandTotal
	}
	_, err = tx.ExecContext(ctx, `UPDATE sales.invoices SET amount_due = $3, updated_at = NOW(), updated_by = $4 WHERE invoice_id = $1 AND company_id = $2`,
		app.InvoiceID, companyID, newAmountDue, uuid.NullUUID{UUID: removedBy, Valid: true})
	if err != nil {
		return err
	}
	if err := s.appRepo.Delete(ctx, tx, applicationID); err != nil {
		return err
	}
	if err := s.creditNoteRepo.UpdateAppliedAmount(ctx, tx, companyID, creditNoteID, app.Amount.Neg(), &removedBy); err != nil {
		return err
	}
	if cn.Status == enums.CreditNoteFullyUsed {
		newStatus := enums.CreditNotePartiallyUsed
		newApplied := cn.AmountApplied.Sub(app.Amount)
		if newApplied.IsZero() {
			newStatus = enums.CreditNoteIssued
		}
		if err := s.creditNoteRepo.UpdateStatus(ctx, tx, companyID, creditNoteID, newStatus, &removedBy); err != nil {
			return err
		}
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *creditNoteService) GetApplications(ctx context.Context, companyID, creditNoteID uuid.UUID) ([]*models.CreditNoteApplication, error) {
	db := s.pgClient.DB
	return s.appRepo.GetByCreditNote(ctx, db, creditNoteID)
}

// ------------------- Convert to refund (idempotent) -------------------
// FIX: Convert remaining negative balance to positive refund amount
// ------------------- Convert to refund (idempotent) -------------------
func (s *creditNoteService) ConvertToRefund(ctx context.Context, companyID, creditNoteID uuid.UUID, req *ConvertCreditNoteToRefundRequest) (*models.PaymentRefund, error) {
	logger := s.logger.With(zap.String("method", "ConvertToRefund"))
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = creditNoteID.String() + "-convert"
	}
	var cached *models.PaymentRefund
	err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached)
	if err == nil && cached != nil {
		logger.Info("idempotent – returning cached refund")
		return cached, nil
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	cn, err := s.creditNoteRepo.GetByIDForUpdate(ctx, tx, companyID, creditNoteID)
	if err != nil {
		return nil, err
	}
	if cn.Status != enums.CreditNoteIssued && cn.Status != enums.CreditNotePartiallyUsed {
		return nil, fmt.Errorf("%w: only issued or partially used credit notes can be refunded", salesErrors.ErrInvalidStatus)
	}
	remaining := cn.TotalAmount.Add(cn.AmountApplied) // negative
	if remaining.IsZero() {
		return nil, fmt.Errorf("%w: no remaining balance to refund", salesErrors.ErrInvalidAmount)
	}
	if req.PaymentID == uuid.Nil {
		return nil, fmt.Errorf("%w: payment_id required for refund", salesErrors.ErrInvalidInput)
	}

	// ✅ Convert negative remaining balance to positive refund amount
	refundAmount := remaining.Neg()

	// ✅ Optional: Check that the payment has sufficient remaining amount before calling CreateRefund
	// (If your PaymentService already does this, you can skip)
	// But to give a clear error, we can pre-check.
	// Assuming PaymentService has a method GetPaymentByID.
	// For brevity, we rely on CreateRefund's internal validation.

	refundReq := &CreateRefundRequest{
		CompanyID:  companyID,
		PaymentID:  req.PaymentID,
		Amount:     refundAmount,
		Reason:     req.Reason,
		RefundedBy: uuid.Nil,
	}
	refund, err := s.paymentService.CreateRefund(ctx, refundReq)
	if err != nil {
		return nil, fmt.Errorf("create refund: %w", err)
	}

	// Mark credit note as fully applied (since we refund the entire remaining balance)
	if err := s.creditNoteRepo.UpdateAppliedAmount(ctx, tx, companyID, creditNoteID, refundAmount, nil); err != nil {
		return nil, err
	}
	if err := s.creditNoteRepo.UpdateStatus(ctx, tx, companyID, creditNoteID, enums.CreditNoteFullyUsed, nil); err != nil {
		return nil, err
	}
	if err := s.emitEvent(ctx, tx, "sales.credit_note.refunded", cn, map[string]interface{}{
		"refund_id": refund.RefundID.String(),
		"amount":    refundAmount.String(),
	}); err != nil {
		logger.Warn("failed to emit refunded event", zap.Error(err))
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, refund); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return refund, nil
}

// ------------------- Analytics & helpers -------------------
func (s *creditNoteService) GetTotalCreditIssued(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	db := s.pgClient.DB
	return s.creditNoteRepo.GetTotalCreditIssued(ctx, db, companyID, from, to)
}

func (s *creditNoteService) GetTotalCreditApplied(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	db := s.pgClient.DB
	return s.creditNoteRepo.GetTotalCreditApplied(ctx, db, companyID, from, to)
}

func (s *creditNoteService) GetOutstandingCredits(ctx context.Context, companyID uuid.UUID) (decimal.Decimal, error) {
	db := s.pgClient.DB
	return s.creditNoteRepo.GetOutstandingCredits(ctx, db, companyID)
}

// Validation methods (stubs – implement as needed)
func (s *creditNoteService) ValidateCreditNote(ctx context.Context, creditNote *models.CreditNote, items []*models.CreditNoteItem) error {
	return nil
}
func (s *creditNoteService) ValidateApplication(ctx context.Context, companyID, creditNoteID, invoiceID uuid.UUID, amount decimal.Decimal) error {
	return nil
}
func (s *creditNoteService) ValidateStatusTransition(ctx context.Context, currentStatus, nextStatus enums.CreditNoteStatus) error {
	return nil
}

// ---------------------------------------------------------------------
// Request/response types used by the service
// ---------------------------------------------------------------------

type CreateCreditNoteRequest struct {
	CompanyID      uuid.UUID
	CustomerID     uuid.UUID
	CreditNoteDate time.Time
	Currency       *string
	Items          []*CreateCreditNoteItemRequest
	Reason         *string
	Notes          *string
	CreatedBy      *uuid.UUID
}

type CreateCreditNoteFromInvoiceRequest struct {
	Items  []uuid.UUID
	Reason *string
	Notes  *string
}

type CreateCreditNoteFromReturnRequest struct {
	Reason *string
	Notes  *string
}

type UpdateCreditNoteRequest struct {
	Reason *string
	Notes  *string
}

type ConvertCreditNoteToRefundRequest struct {
	PaymentID uuid.UUID
	Reason    string
}
