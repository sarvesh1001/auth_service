// service/credit_note_service.go
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

// -------------------------------------------------------------------------
// Interface Definition
// -------------------------------------------------------------------------

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

// -------------------------------------------------------------------------
// Request/Response Types (should be placed in service/types.go)
// -------------------------------------------------------------------------

// -------------------------------------------------------------------------
// Service Implementation
// -------------------------------------------------------------------------

type creditNoteService struct {
	creditNoteRepo   repository.CreditNoteRepository
	appRepo          repository.CreditNoteApplicationRepository
	invoiceRepo      repository.InvoiceRepository
	invoiceService   InvoiceService
	paymentService   PaymentService
	returnRepo       repository.ReturnRepository
	orderRepo        repository.OrderRepository // needed for customer lookup
	productRepo      repository.ProductRepository
	pgClient         *client.PostgresClient
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	logger           *zap.Logger
}

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

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

func (s *creditNoteService) generateCreditNoteNumber(ctx context.Context, tx *sql.Tx, companyID uuid.UUID) (string, error) {
	var seq int
	prefix := fmt.Sprintf("CN-%s-", time.Now().Format("20060102"))
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

func (s *creditNoteService) fetchProductName(ctx context.Context, db repository.DBTX, productID uuid.UUID) string {
	if productID == uuid.Nil {
		return "Unknown Product"
	}
	var name string
	query := `SELECT name FROM sales.products WHERE product_id = $1`
	err := db.QueryRowContext(ctx, query, productID).Scan(&name)
	if err != nil {
		s.logger.Warn("failed to fetch product name", zap.String("product_id", productID.String()), zap.Error(err))
		return "Product"
	}
	return name
}

func (s *creditNoteService) audit(ctx context.Context, companyID uuid.UUID, action string, creditNoteID uuid.UUID, userID *uuid.UUID, changes map[string]interface{}) {
	if s.auditService == nil {
		return
	}
	_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", action, "credit_note",
		&creditNoteID, "user", userID, nil, nil, changes)
}

func nullUUID(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

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

// copyInvoiceItemsToCreditNoteItems builds credit note items from an invoice,
// optionally filtering by selected invoice item IDs.
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
		lineAmount := it.UnitPrice.Mul(it.Quantity)
		if it.DiscountAmount != nil {
			lineAmount = lineAmount.Sub(*it.DiscountAmount)
		}
		if it.TaxAmount != nil {
			taxTotal = taxTotal.Add(*it.TaxAmount)
			lineAmount = lineAmount.Add(*it.TaxAmount)
		}
		// Negate for credit
		lineAmount = lineAmount.Neg()
		taxAmt := decimal.Zero
		if it.TaxAmount != nil {
			taxAmt = it.TaxAmount.Neg()
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

// -------------------------------------------------------------------------
// Creation Methods
// -------------------------------------------------------------------------

func (s *creditNoteService) CreateDraftCreditNote(ctx context.Context, req *CreateCreditNoteRequest) (*models.CreditNote, error) {
	if req.CompanyID == uuid.Nil || req.CustomerID == uuid.Nil || len(req.Items) == 0 {
		return nil, fmt.Errorf("%w: company_id, customer_id and items required", salesErrors.ErrInvalidInput)
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
		Reason:           req.Reason,
		Notes:            req.Notes,
		CreatedBy:        req.CreatedBy,
	}

	if err := s.creditNoteRepo.Create(ctx, tx, creditNote, creditItems); err != nil {
		return nil, err
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

func (s *creditNoteService) CreateFromInvoice(ctx context.Context, companyID, invoiceID uuid.UUID, req *CreateCreditNoteFromInvoiceRequest) (*models.CreditNote, error) {
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

	creditItems, subtotal, taxTotal, err := s.copyInvoiceItemsToCreditNoteItems(ctx, tx, companyID, invoiceID, req.Items)
	if err != nil {
		return nil, err
	}
	totalAmount := subtotal.Add(taxTotal)
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
		Reason:           req.Reason,
		Notes:            req.Notes,
	}

	if err := s.creditNoteRepo.Create(ctx, tx, creditNote, creditItems); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	s.audit(ctx, companyID, "create_credit_note_from_invoice", creditNote.CreditNoteID, nil, map[string]interface{}{
		"invoice_id": invoiceID.String(),
	})
	return creditNote, nil
}

func (s *creditNoteService) CreateFromReturn(ctx context.Context, companyID, returnID uuid.UUID, req *CreateCreditNoteFromReturnRequest) (*models.CreditNote, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	ret, err := s.returnRepo.GetByID(ctx, tx, companyID, returnID)
	if err != nil {
		return nil, err
	}
	// Fix: Compare with string constant
	if ret.Status != string(enums.ReturnStatusApproved) {
		return nil, fmt.Errorf("%w: return must be approved before generating credit note", salesErrors.ErrInvalidStatus)
	}

	existing, _ := s.creditNoteRepo.GetByReturn(ctx, tx, companyID, returnID)
	if existing != nil {
		return nil, fmt.Errorf("%w: credit note already exists for this return", salesErrors.ErrDuplicate)
	}

	// Get order to fetch customer ID
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
		Reason:           req.Reason,
		Notes:            req.Notes,
	}
	if err := s.creditNoteRepo.Create(ctx, tx, creditNote, creditItems); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	s.audit(ctx, companyID, "create_credit_note_from_return", creditNote.CreditNoteID, nil, map[string]interface{}{
		"return_id": returnID.String(),
	})
	return creditNote, nil
}

// -------------------------------------------------------------------------
// Update & Delete
// -------------------------------------------------------------------------

func (s *creditNoteService) UpdateCreditNote(ctx context.Context, companyID, creditNoteID uuid.UUID, req *UpdateCreditNoteRequest) (*models.CreditNote, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	cn, err := s.creditNoteRepo.GetByIDForUpdate(ctx, tx, companyID, creditNoteID)
	if err != nil {
		return nil, err
	}
	if cn.Status != enums.CreditNoteDraft {
		return nil, fmt.Errorf("%w: only draft credit notes can be updated", salesErrors.ErrInvalidStatus)
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
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	return cn, nil
}

func (s *creditNoteService) DeleteCreditNote(ctx context.Context, companyID, creditNoteID uuid.UUID, deletedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
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
	return tx.Commit()
}

// -------------------------------------------------------------------------
// Getters
// -------------------------------------------------------------------------

func (s *creditNoteService) GetCreditNoteByID(ctx context.Context, companyID, creditNoteID uuid.UUID) (*models.CreditNote, error) {
	return s.creditNoteRepo.GetByID(ctx, nil, companyID, creditNoteID)
}

func (s *creditNoteService) GetCreditNoteByNumber(ctx context.Context, companyID uuid.UUID, creditNoteNumber string) (*models.CreditNote, error) {
	return s.creditNoteRepo.GetByNumber(ctx, nil, companyID, creditNoteNumber)
}

func (s *creditNoteService) ListCreditNotes(ctx context.Context, filter CreditNoteListFilter, p Pagination, srt Sort) ([]*models.CreditNote, int64, error) {
	repoFilter := repository.CreditNoteFilter{
		CompanyID:  filter.CompanyID,
		CustomerID: filter.CustomerID,
		Status:     filter.Status,
		FromDate:   filter.FromDate,
		ToDate:     filter.ToDate,
		InvoiceID:  filter.InvoiceID,
		ReturnID:   filter.ReturnID,
	}
	// Convert service Pagination/Sort to repository types
	repoPagination := repository.Pagination{Limit: p.Limit, Offset: p.Offset}
	repoSort := repository.Sort{Field: srt.Field, Direction: srt.Direction}
	return s.creditNoteRepo.List(ctx, nil, repoFilter, repoPagination, repoSort)
}

func (s *creditNoteService) SearchCreditNotes(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.CreditNote, int64, error) {
	return s.creditNoteRepo.Search(ctx, nil, companyID, query, limit, offset)
}

// -------------------------------------------------------------------------
// Items Management
// -------------------------------------------------------------------------

func (s *creditNoteService) AddItems(ctx context.Context, companyID, creditNoteID uuid.UUID, items []*CreateCreditNoteItemRequest, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
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
	return tx.Commit()
}

func (s *creditNoteService) ReplaceItems(ctx context.Context, companyID, creditNoteID uuid.UUID, items []*CreateCreditNoteItemRequest, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
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
	return tx.Commit()
}

func (s *creditNoteService) RemoveItem(ctx context.Context, companyID, creditNoteID, creditNoteItemID uuid.UUID, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
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
	return tx.Commit()
}

func (s *creditNoteService) GetCreditNoteItems(ctx context.Context, companyID, creditNoteID uuid.UUID) ([]*models.CreditNoteItem, error) {
	return s.creditNoteRepo.GetItems(ctx, nil, companyID, creditNoteID)
}

// -------------------------------------------------------------------------
// Calculations & Preview
// -------------------------------------------------------------------------

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

func (s *creditNoteService) GetCreditNoteTotals(ctx context.Context, companyID, creditNoteID uuid.UUID) (subtotal, taxTotal, totalAmount, remainingAmount decimal.Decimal, err error) {
	cn, err := s.creditNoteRepo.GetByID(ctx, nil, companyID, creditNoteID)
	if err != nil {
		return
	}
	return cn.Subtotal, cn.TaxTotal, cn.TotalAmount, cn.TotalAmount.Sub(cn.AmountApplied), nil
}

// -------------------------------------------------------------------------
// Status & Lifecycle
// -------------------------------------------------------------------------

func (s *creditNoteService) UpdateStatus(ctx context.Context, companyID, creditNoteID uuid.UUID, status enums.CreditNoteStatus, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.creditNoteRepo.UpdateStatus(ctx, tx, companyID, creditNoteID, status, &updatedBy); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *creditNoteService) IssueCreditNote(ctx context.Context, companyID, creditNoteID uuid.UUID, issuedBy uuid.UUID) error {
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
		s.logger.Warn("failed to emit credit_note.issued event", zap.Error(err))
	}
	s.audit(ctx, companyID, "issue_credit_note", creditNoteID, &issuedBy, nil)
	return tx.Commit()
}

func (s *creditNoteService) VoidCreditNote(ctx context.Context, companyID, creditNoteID uuid.UUID, reason string, voidedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	cn, err := s.creditNoteRepo.GetByIDForUpdate(ctx, tx, companyID, creditNoteID)
	if err != nil {
		return err
	}
	if cn.Status == enums.CreditNoteVoided || cn.Status == enums.CreditNoteFullyUsed {
		return fmt.Errorf("%w: cannot void credit note in status %s", salesErrors.ErrInvalidStatus, cn.Status)
	}
	now := time.Now()
	if err := s.creditNoteRepo.Void(ctx, tx, companyID, creditNoteID, reason, now, &voidedBy); err != nil {
		return err
	}
	if err := s.emitEvent(ctx, tx, "sales.credit_note.voided", cn, map[string]interface{}{"reason": reason}); err != nil {
		s.logger.Warn("failed to emit credit_note.voided event", zap.Error(err))
	}
	s.audit(ctx, companyID, "void_credit_note", creditNoteID, &voidedBy, map[string]interface{}{"reason": reason})
	return tx.Commit()
}

func (s *creditNoteService) MarkFullyApplied(ctx context.Context, companyID, creditNoteID uuid.UUID, updatedBy uuid.UUID) error {
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
	return tx.Commit()
}

// -------------------------------------------------------------------------
// Applications
// -------------------------------------------------------------------------

func (s *creditNoteService) ApplyToInvoice(ctx context.Context, companyID, creditNoteID, invoiceID uuid.UUID, amount decimal.Decimal, appliedBy uuid.UUID) error {
	if amount.LessThanOrEqual(decimal.Zero) {
		return fmt.Errorf("%w: amount must be positive", salesErrors.ErrInvalidInput)
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.applyToInvoiceInternal(ctx, tx, companyID, creditNoteID, invoiceID, amount, appliedBy); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *creditNoteService) ApplyToInvoices(ctx context.Context, companyID, creditNoteID uuid.UUID, applications []*CreditNoteApplicationRequest, appliedBy uuid.UUID) error {
	if len(applications) == 0 {
		return nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, app := range applications {
		if err := s.applyToInvoiceInternal(ctx, tx, companyID, creditNoteID, app.InvoiceID, app.Amount, appliedBy); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *creditNoteService) AutoApplyToOutstandingInvoices(ctx context.Context, companyID, creditNoteID uuid.UUID, appliedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	cn, err := s.creditNoteRepo.GetByIDForUpdate(ctx, tx, companyID, creditNoteID)
	if err != nil {
		return err
	}
	remaining := cn.TotalAmount.Sub(cn.AmountApplied)
	if remaining.LessThanOrEqual(decimal.Zero) {
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
	for rows.Next() {
		var invID uuid.UUID
		var due decimal.Decimal
		if err := rows.Scan(&invID, &due); err != nil {
			return err
		}
		if remaining.IsZero() {
			break
		}
		applyAmount := due
		if applyAmount.GreaterThan(remaining) {
			applyAmount = remaining
		}
		apps = append(apps, &CreditNoteApplicationRequest{InvoiceID: invID, Amount: applyAmount})
		remaining = remaining.Sub(applyAmount)
	}
	for _, app := range apps {
		if err := s.applyToInvoiceInternal(ctx, tx, companyID, creditNoteID, app.InvoiceID, app.Amount, appliedBy); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *creditNoteService) RemoveApplication(ctx context.Context, companyID, creditNoteID, applicationID uuid.UUID, removedBy uuid.UUID) error {
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

	// Update invoice: add back the amount due
	invoice, err := s.invoiceRepo.GetByIDForUpdate(ctx, tx, companyID, app.InvoiceID)
	if err != nil {
		return err
	}
	newAmountDue := invoice.AmountDue.Add(app.Amount)
	if newAmountDue.GreaterThan(invoice.GrandTotal) {
		newAmountDue = invoice.GrandTotal
	}
	_, err = tx.ExecContext(ctx, `UPDATE sales.invoices SET amount_due = $3, updated_at = NOW(), updated_by = $4 WHERE invoice_id = $1 AND company_id = $2`,
		app.InvoiceID, companyID, newAmountDue, nullUUID(&removedBy))
	if err != nil {
		return err
	}
	if err := s.appRepo.Delete(ctx, tx, applicationID); err != nil {
		return err
	}
	// Decrease applied amount on credit note
	if err := s.creditNoteRepo.UpdateAppliedAmount(ctx, tx, companyID, creditNoteID, app.Amount.Neg(), &removedBy); err != nil {
		return err
	}
	// Adjust status if needed
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
	return tx.Commit()
}

func (s *creditNoteService) GetApplications(ctx context.Context, companyID, creditNoteID uuid.UUID) ([]*models.CreditNoteApplication, error) {
	return s.appRepo.GetByCreditNote(ctx, nil, creditNoteID)
}

func (s *creditNoteService) GetRemainingBalance(ctx context.Context, companyID, creditNoteID uuid.UUID) (decimal.Decimal, error) {
	cn, err := s.creditNoteRepo.GetByID(ctx, nil, companyID, creditNoteID)
	if err != nil {
		return decimal.Zero, err
	}
	return cn.TotalAmount.Sub(cn.AmountApplied), nil
}

func (s *creditNoteService) IsFullyApplied(ctx context.Context, companyID, creditNoteID uuid.UUID) (bool, error) {
	cn, err := s.creditNoteRepo.GetByID(ctx, nil, companyID, creditNoteID)
	if err != nil {
		return false, err
	}
	return cn.Status == enums.CreditNoteFullyUsed, nil
}

func (s *creditNoteService) GetCustomerCreditBalance(ctx context.Context, companyID, customerID uuid.UUID) (decimal.Decimal, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return decimal.Zero, err
	}
	defer tx.Rollback()
	var total decimal.Decimal
	query := `
		SELECT COALESCE(SUM(total_amount - amount_applied), 0)
		FROM sales.credit_notes
		WHERE company_id = $1 AND customer_id = $2 AND status IN ('issued', 'partially_used')
	`
	err = tx.QueryRowContext(ctx, query, companyID, customerID).Scan(&total)
	return total, err
}

func (s *creditNoteService) GetUnusedCreditNotes(ctx context.Context, companyID, customerID uuid.UUID) ([]*models.CreditNote, error) {
	return s.creditNoteRepo.GetUnusedByCustomer(ctx, nil, companyID, customerID)
}

// -------------------------------------------------------------------------
// Convert to Refund
// -------------------------------------------------------------------------

func (s *creditNoteService) ConvertToRefund(ctx context.Context, companyID, creditNoteID uuid.UUID, req *ConvertCreditNoteToRefundRequest) (*models.PaymentRefund, error) {
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
	remaining := cn.TotalAmount.Sub(cn.AmountApplied)
	if remaining.IsZero() {
		return nil, fmt.Errorf("%w: no remaining balance to refund", salesErrors.ErrInvalidAmount)
	}
	if req.PaymentID == uuid.Nil {
		return nil, fmt.Errorf("%w: payment_id required for refund", salesErrors.ErrInvalidInput)
	}
	refundReq := &CreateRefundRequest{
		CompanyID:  companyID,
		PaymentID:  req.PaymentID,
		Amount:     remaining,
		Reason:     req.Reason,
		RefundedBy: uuid.Nil, // would be passed if needed
	}
	refund, err := s.paymentService.CreateRefund(ctx, refundReq)
	if err != nil {
		return nil, fmt.Errorf("create refund: %w", err)
	}
	if err := s.creditNoteRepo.UpdateAppliedAmount(ctx, tx, companyID, creditNoteID, remaining, nil); err != nil {
		return nil, err
	}
	if err := s.creditNoteRepo.UpdateStatus(ctx, tx, companyID, creditNoteID, enums.CreditNoteFullyUsed, nil); err != nil {
		return nil, err
	}
	if err := s.emitEvent(ctx, tx, "sales.credit_note.refunded", cn, map[string]interface{}{
		"refund_id": refund.RefundID.String(),
		"amount":    remaining.String(),
	}); err != nil {
		s.logger.Warn("failed to emit credit_note.refunded event", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return refund, nil
}

// -------------------------------------------------------------------------
// Validations
// -------------------------------------------------------------------------

func (s *creditNoteService) ValidateCreditNote(ctx context.Context, creditNote *models.CreditNote, items []*models.CreditNoteItem) error {
	if creditNote.CreditNoteNumber == "" {
		return fmt.Errorf("%w: credit note number required", salesErrors.ErrInvalidInput)
	}
	if creditNote.TotalAmount.GreaterThan(decimal.Zero) {
		return fmt.Errorf("%w: credit note total must be negative or zero", salesErrors.ErrInvalidInput)
	}
	// additional validations: check items, etc.
	return nil
}

func (s *creditNoteService) ValidateApplication(ctx context.Context, companyID, creditNoteID, invoiceID uuid.UUID, amount decimal.Decimal) error {
	if amount.LessThanOrEqual(decimal.Zero) {
		return fmt.Errorf("%w: amount must be positive", salesErrors.ErrInvalidInput)
	}
	return nil
}

func (s *creditNoteService) ValidateStatusTransition(ctx context.Context, currentStatus, nextStatus enums.CreditNoteStatus) error {
	switch currentStatus {
	case enums.CreditNoteDraft:
		if nextStatus != enums.CreditNoteIssued && nextStatus != enums.CreditNoteVoided {
			return fmt.Errorf("%w: invalid transition from draft", salesErrors.ErrInvalidTransition)
		}
	case enums.CreditNoteIssued:
		if nextStatus != enums.CreditNotePartiallyUsed && nextStatus != enums.CreditNoteFullyUsed && nextStatus != enums.CreditNoteVoided {
			return fmt.Errorf("%w: invalid transition from issued", salesErrors.ErrInvalidTransition)
		}
	case enums.CreditNotePartiallyUsed:
		if nextStatus != enums.CreditNoteFullyUsed && nextStatus != enums.CreditNoteVoided {
			return fmt.Errorf("%w: invalid transition from partially_used", salesErrors.ErrInvalidTransition)
		}
	default:
		return fmt.Errorf("%w: transition not allowed from %s", salesErrors.ErrInvalidTransition, currentStatus)
	}
	return nil
}

// -------------------------------------------------------------------------
// Analytics / Aggregates
// -------------------------------------------------------------------------

func (s *creditNoteService) GetTotalCreditIssued(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	return s.creditNoteRepo.GetTotalCreditIssued(ctx, nil, companyID, from, to)
}

func (s *creditNoteService) GetTotalCreditApplied(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	return s.creditNoteRepo.GetTotalCreditApplied(ctx, nil, companyID, from, to)
}

func (s *creditNoteService) GetOutstandingCredits(ctx context.Context, companyID uuid.UUID) (decimal.Decimal, error) {
	return s.creditNoteRepo.GetOutstandingCredits(ctx, nil, companyID)
}

func (s *creditNoteService) CreditNoteExists(ctx context.Context, companyID, creditNoteID uuid.UUID) (bool, error) {
	return s.creditNoteRepo.Exists(ctx, nil, companyID, creditNoteID)
}

func (s *creditNoteService) CreditNoteNumberExists(ctx context.Context, companyID uuid.UUID, creditNoteNumber string) (bool, error) {
	return s.creditNoteRepo.ExistsByNumber(ctx, nil, companyID, creditNoteNumber)
}

// -------------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------------

func (s *creditNoteService) applyToInvoiceInternal(ctx context.Context, tx *sql.Tx, companyID, creditNoteID, invoiceID uuid.UUID, amount decimal.Decimal, appliedBy uuid.UUID) error {
	cn, err := s.creditNoteRepo.GetByIDForUpdate(ctx, tx, companyID, creditNoteID)
	if err != nil {
		return err
	}
	remaining := cn.TotalAmount.Sub(cn.AmountApplied)
	if amount.GreaterThan(remaining) {
		return fmt.Errorf("%w: amount exceeds remaining balance", salesErrors.ErrInvalidAmount)
	}
	invoice, err := s.invoiceRepo.GetByIDForUpdate(ctx, tx, companyID, invoiceID)
	if err != nil {
		return err
	}
	if invoice.Status != enums.InvoiceStatusIssued && invoice.Status != enums.InvoiceStatusOverdue {
		return fmt.Errorf("%w: invoice not eligible for credit application", salesErrors.ErrInvalidStatus)
	}
	app := &models.CreditNoteApplication{
		ApplicationID: uuid.New(),
		CreditNoteID:  creditNoteID,
		InvoiceID:     invoiceID,
		Amount:        amount,
		AppliedAt:     time.Now(),
		AppliedBy:     &appliedBy,
	}
	if err := s.appRepo.Create(ctx, tx, app); err != nil {
		return err
	}
	if err := s.creditNoteRepo.UpdateAppliedAmount(ctx, tx, companyID, creditNoteID, amount, &appliedBy); err != nil {
		return err
	}
	newAmountDue := invoice.AmountDue.Sub(amount)
	if newAmountDue.LessThan(decimal.Zero) {
		newAmountDue = decimal.Zero
	}
	_, err = tx.ExecContext(ctx, `UPDATE sales.invoices SET amount_due = $3, updated_at = NOW(), updated_by = $4 WHERE invoice_id = $1 AND company_id = $2`,
		invoiceID, companyID, newAmountDue, nullUUID(&appliedBy))
	if err != nil {
		return err
	}
	if err := s.emitEvent(ctx, tx, "sales.credit_note.applied", cn, map[string]interface{}{
		"invoice_id": invoiceID.String(),
		"amount":     amount.String(),
	}); err != nil {
		s.logger.Warn("failed to emit credit_note.applied event", zap.Error(err))
	}
	return nil
}
