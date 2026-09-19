// internal/service/invoice.go
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	apperrors "auth-service/internal/errors"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/models"
	"auth-service/internal/repository/postgres"
)

// InvoiceConfig holds configuration for invoice generation.
type InvoiceConfig struct {
	DueDays       int     // days after invoice date when due
	TaxRate       float64 // default tax rate (percentage)
	DiscountRate  float64 // default discount rate (percentage)
	InvoicePrefix string  // prefix for invoice numbers, e.g. "INV-"
}

// DefaultInvoiceConfig returns sensible defaults.
func DefaultInvoiceConfig() InvoiceConfig {
	return InvoiceConfig{
		DueDays:       7,
		TaxRate:       0,
		DiscountRate:  0,
		InvoicePrefix: "INV-",
	}
}

// SubscriptionInvoiceService handles subscription invoice operations.
type SubscriptionInvoiceService struct {
	invoiceRepo      postgres.SubscriptionInvoiceRepository
	itemRepo         postgres.SubscriptionInvoiceItemRepository
	companyRepo      postgres.CompanyRepository
	auditService     *audit.AuditService
	idempotencyStore idempotency.Store
	cfg              InvoiceConfig
}

// NewSubscriptionInvoiceService creates a new instance.
func NewSubscriptionInvoiceService(
	invoiceRepo postgres.SubscriptionInvoiceRepository,
	itemRepo postgres.SubscriptionInvoiceItemRepository,
	companyRepo postgres.CompanyRepository,
	auditService *audit.AuditService,
	idempotencyStore idempotency.Store,
	cfg *InvoiceConfig,
) *SubscriptionInvoiceService {
	if cfg == nil {
		defaultCfg := DefaultInvoiceConfig()
		cfg = &defaultCfg
	}
	return &SubscriptionInvoiceService{
		invoiceRepo:      invoiceRepo,
		itemRepo:         itemRepo,
		companyRepo:      companyRepo,
		auditService:     auditService,
		idempotencyStore: idempotencyStore,
		cfg:              *cfg,
	}
}

// ---------- Helper: Generate Invoice Number ----------

// generateInvoiceNumber creates a unique invoice number.
// Format: PREFIX + YYYYMMDD + '-' + 4-digit sequence (or random)
func (s *SubscriptionInvoiceService) generateInvoiceNumber(ctx context.Context, companyID uuid.UUID) (string, error) {
	// For production, you may want a sequence counter per company.
	// Here we use timestamp + random for simplicity.
	now := time.Now().UTC()
	datePart := now.Format("20060102")
	// Use a random suffix to avoid collisions.
	suffix := uuid.New().String()[:8] // 8 chars
	return fmt.Sprintf("%s%s-%s", s.cfg.InvoicePrefix, datePart, suffix), nil
}

// ---------- Create Invoice (with items) ----------

// CreateInvoice creates a new invoice with its line items.
// It validates the invoice, generates a number, and inserts all records in a transaction.
func (s *SubscriptionInvoiceService) CreateInvoice(
	ctx context.Context,
	invoice *models.SubscriptionInvoice,
	items []*models.SubscriptionInvoiceItem,
) (*models.SubscriptionInvoice, error) {
	// Validate invoice
	if err := s.validateInvoice(invoice); err != nil {
		return nil, err
	}

	// Generate invoice number if not provided
	if invoice.InvoiceNumber == "" {
		num, err := s.generateInvoiceNumber(ctx, invoice.CompanyID)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to generate invoice number: %v", apperrors.ErrInternal, err)
		}
		invoice.InvoiceNumber = num
	}

	// Set timestamps
	now := time.Now().UTC()
	if invoice.InvoiceDate.IsZero() {
		invoice.InvoiceDate = now
	}
	if invoice.DueDate.IsZero() {
		invoice.DueDate = now.AddDate(0, 0, s.cfg.DueDays)
	}
	invoice.CreatedAt = now
	invoice.UpdatedAt = now
	if invoice.Status == "" {
		invoice.Status = models.InvoiceStatusDraft
	}
	if invoice.Currency == "" {
		invoice.Currency = "USD"
	}

	// Compute totals from items if not explicitly set
	if invoice.GrandTotal == 0 && len(items) > 0 {
		var subtotal, taxTotal, discountTotal float64
		for _, item := range items {
			// Ensure item totals are calculated
			if item.TotalPrice == 0 {
				item.TotalPrice = item.Quantity * item.UnitPrice
			}
			subtotal += item.TotalPrice
			taxTotal += item.TaxAmount
			// discountTotal may be zero
		}
		invoice.Subtotal = subtotal
		invoice.TaxTotal = taxTotal
		invoice.DiscountTotal = discountTotal
		invoice.GrandTotal = subtotal + taxTotal - discountTotal
	}

	// Check for duplicate invoice number (unique constraint)
	existing, _ := s.invoiceRepo.GetByNumber(ctx, invoice.InvoiceNumber)
	if existing != nil {
		// Try regenerating once
		newNum, err := s.generateInvoiceNumber(ctx, invoice.CompanyID)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to generate unique invoice number", apperrors.ErrInternal)
		}
		invoice.InvoiceNumber = newNum
	}

	// Insert invoice
	if err := s.invoiceRepo.Create(ctx, invoice); err != nil {
		if err == apperrors.ErrDuplicate {
			return nil, fmt.Errorf("%w: invoice number '%s' already exists", apperrors.ErrDuplicate, invoice.InvoiceNumber)
		}
		return nil, fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}

	// Insert items
	if len(items) > 0 {
		for _, item := range items {
			item.ItemID = uuid.New()
			item.InvoiceID = invoice.InvoiceID
			item.CreatedAt = now
			if item.TotalPrice == 0 {
				item.TotalPrice = item.Quantity * item.UnitPrice
			}
		}
		if err := s.itemRepo.CreateMany(ctx, items); err != nil {
			// Attempt to delete the invoice (or just log error)
			_ = s.invoiceRepo.SoftDelete(ctx, invoice.InvoiceID)
			return nil, fmt.Errorf("%w: failed to create invoice items: %v", apperrors.ErrInternal, err)
		}
	}

	// Audit
	if s.auditService != nil {
		ip, _ := ctx.Value("ip_address").(string)
		_ = s.auditService.LogAction(ctx, nil, nil, "invoice", "create", "invoice",
			&invoice.InvoiceID, "system", nil, nil, nil, map[string]interface{}{
				"company_id":     invoice.CompanyID,
				"invoice_number": invoice.InvoiceNumber,
				"grand_total":    invoice.GrandTotal,
				"ip_address":     ip,
			})
	}
	return invoice, nil
}

// ---------- Read Methods ----------

// GetInvoiceByID retrieves an invoice by ID.
func (s *SubscriptionInvoiceService) GetInvoiceByID(ctx context.Context, invoiceID uuid.UUID) (*models.SubscriptionInvoice, error) {
	if invoiceID == uuid.Nil {
		return nil, fmt.Errorf("%w: invoice_id is required", apperrors.ErrInvalidInput)
	}
	invoice, err := s.invoiceRepo.GetByID(ctx, invoiceID)
	if err != nil {
		if err == apperrors.ErrNotFound {
			return nil, fmt.Errorf("%w: invoice with id %s not found", apperrors.ErrNotFound, invoiceID)
		}
		return nil, fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}
	return invoice, nil
}

// GetInvoiceByNumber retrieves an invoice by its number.
func (s *SubscriptionInvoiceService) GetInvoiceByNumber(ctx context.Context, invoiceNumber string) (*models.SubscriptionInvoice, error) {
	if invoiceNumber == "" {
		return nil, fmt.Errorf("%w: invoice_number is required", apperrors.ErrInvalidInput)
	}
	invoice, err := s.invoiceRepo.GetByNumber(ctx, invoiceNumber)
	if err != nil {
		if err == apperrors.ErrNotFound {
			return nil, fmt.Errorf("%w: invoice number '%s' not found", apperrors.ErrNotFound, invoiceNumber)
		}
		return nil, fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}
	return invoice, nil
}

// ListInvoicesForCompany returns invoices with pagination.
func (s *SubscriptionInvoiceService) ListInvoicesForCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.SubscriptionInvoice, int, error) {
	if companyID == uuid.Nil {
		return nil, 0, fmt.Errorf("%w: company_id is required", apperrors.ErrInvalidInput)
	}
	// pagination limits
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	return s.invoiceRepo.ListByCompany(ctx, companyID, limit, offset)
}

// GetInvoiceItems returns all items for an invoice.
func (s *SubscriptionInvoiceService) GetInvoiceItems(ctx context.Context, invoiceID uuid.UUID) ([]*models.SubscriptionInvoiceItem, error) {
	if invoiceID == uuid.Nil {
		return nil, fmt.Errorf("%w: invoice_id is required", apperrors.ErrInvalidInput)
	}
	// Check if invoice exists first
	_, err := s.invoiceRepo.GetByID(ctx, invoiceID)
	if err != nil {
		return nil, err
	}
	return s.itemRepo.GetByInvoice(ctx, invoiceID)
}

// ---------- Update Methods ----------

// UpdateInvoice updates the invoice header and optionally items.
// If items are provided, they replace the existing ones.
func (s *SubscriptionInvoiceService) UpdateInvoice(
	ctx context.Context,
	invoiceID uuid.UUID,
	updates *models.SubscriptionInvoice,
	items []*models.SubscriptionInvoiceItem,
) (*models.SubscriptionInvoice, error) {
	if invoiceID == uuid.Nil {
		return nil, fmt.Errorf("%w: invoice_id is required", apperrors.ErrInvalidInput)
	}

	existing, err := s.invoiceRepo.GetByID(ctx, invoiceID)
	if err != nil {
		return nil, err
	}

	// Cannot modify a paid or cancelled invoice
	if existing.Status == models.InvoiceStatusPaid {
		return nil, fmt.Errorf("%w: cannot update a paid invoice", apperrors.ErrInvalidState)
	}
	if existing.Status == models.InvoiceStatusCancelled {
		return nil, fmt.Errorf("%w: cannot update a cancelled invoice", apperrors.ErrInvalidState)
	}

	before, _ := json.Marshal(existing)

	// Apply updates
	if updates.InvoiceNumber != "" && updates.InvoiceNumber != existing.InvoiceNumber {
		// Check uniqueness
		other, _ := s.invoiceRepo.GetByNumber(ctx, updates.InvoiceNumber)
		if other != nil && other.InvoiceID != invoiceID {
			return nil, fmt.Errorf("%w: invoice number '%s' already in use", apperrors.ErrDuplicate, updates.InvoiceNumber)
		}
		existing.InvoiceNumber = updates.InvoiceNumber
	}
	if !updates.InvoiceDate.IsZero() {
		existing.InvoiceDate = updates.InvoiceDate
	}
	if !updates.DueDate.IsZero() {
		existing.DueDate = updates.DueDate
	}
	if updates.Currency != "" {
		existing.Currency = updates.Currency
	}
	if updates.Subtotal > 0 {
		existing.Subtotal = updates.Subtotal
	}
	if updates.TaxTotal > 0 {
		existing.TaxTotal = updates.TaxTotal
	}
	if updates.DiscountTotal > 0 {
		existing.DiscountTotal = updates.DiscountTotal
	}
	if updates.GrandTotal > 0 {
		existing.GrandTotal = updates.GrandTotal
	}
	if updates.Status != "" {
		existing.Status = updates.Status
	}
	if updates.Notes != nil {
		existing.Notes = updates.Notes
	}
	existing.UpdatedAt = time.Now().UTC()

	// Update in DB
	if err := s.invoiceRepo.Update(ctx, existing); err != nil {
		return nil, fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}

	// If items are provided, replace them
	if items != nil {
		// Delete old items
		_ = s.itemRepo.DeleteByInvoice(ctx, invoiceID)
		// Insert new items
		now := time.Now().UTC()
		for _, item := range items {
			item.ItemID = uuid.New()
			item.InvoiceID = invoiceID
			item.CreatedAt = now
			if item.TotalPrice == 0 {
				item.TotalPrice = item.Quantity * item.UnitPrice
			}
		}
		if err := s.itemRepo.CreateMany(ctx, items); err != nil {
			// Rollback? We'll log and return error
			return nil, fmt.Errorf("%w: failed to update items: %v", apperrors.ErrInternal, err)
		}
	}

	after, _ := json.Marshal(existing)
	if s.auditService != nil {
		ip, _ := ctx.Value("ip_address").(string)
		_ = s.auditService.LogAction(ctx, nil, nil, "invoice", "update", "invoice",
			&invoiceID, "system", nil, before, after, map[string]interface{}{
				"ip_address": ip,
			})
	}
	return existing, nil
}

// ---------- Status Transitions ----------

// UpdateInvoiceStatus changes the invoice status.
func (s *SubscriptionInvoiceService) UpdateInvoiceStatus(ctx context.Context, invoiceID uuid.UUID, status string) error {
	if invoiceID == uuid.Nil {
		return fmt.Errorf("%w: invoice_id is required", apperrors.ErrInvalidInput)
	}
	validStatuses := map[string]bool{
		models.InvoiceStatusDraft:     true,
		models.InvoiceStatusIssued:    true,
		models.InvoiceStatusPaid:      true,
		models.InvoiceStatusOverdue:   true,
		models.InvoiceStatusCancelled: true,
	}
	if !validStatuses[status] {
		return fmt.Errorf("%w: invalid status '%s'", apperrors.ErrInvalidInput, status)
	}
	return s.invoiceRepo.UpdateStatus(ctx, invoiceID, status)
}

// MarkAsIssued sets status to issued.
func (s *SubscriptionInvoiceService) MarkAsIssued(ctx context.Context, invoiceID uuid.UUID) error {
	if invoiceID == uuid.Nil {
		return fmt.Errorf("%w: invoice_id is required", apperrors.ErrInvalidInput)
	}
	// Optionally check current status to prevent invalid transitions
	inv, err := s.invoiceRepo.GetByID(ctx, invoiceID)
	if err != nil {
		return err
	}
	if inv.Status == models.InvoiceStatusPaid || inv.Status == models.InvoiceStatusCancelled {
		return fmt.Errorf("%w: cannot issue a paid or cancelled invoice", apperrors.ErrInvalidState)
	}
	return s.invoiceRepo.MarkAsIssued(ctx, invoiceID)
}

// MarkAsPaid sets status to paid.
func (s *SubscriptionInvoiceService) MarkAsPaid(ctx context.Context, invoiceID uuid.UUID) error {
	if invoiceID == uuid.Nil {
		return fmt.Errorf("%w: invoice_id is required", apperrors.ErrInvalidInput)
	}
	inv, err := s.invoiceRepo.GetByID(ctx, invoiceID)
	if err != nil {
		return err
	}
	if inv.Status == models.InvoiceStatusCancelled {
		return fmt.Errorf("%w: cannot mark a cancelled invoice as paid", apperrors.ErrInvalidState)
	}
	return s.invoiceRepo.MarkAsPaid(ctx, invoiceID)
}

// MarkAsOverdue sets status to overdue.
func (s *SubscriptionInvoiceService) MarkAsOverdue(ctx context.Context, invoiceID uuid.UUID) error {
	if invoiceID == uuid.Nil {
		return fmt.Errorf("%w: invoice_id is required", apperrors.ErrInvalidInput)
	}
	inv, err := s.invoiceRepo.GetByID(ctx, invoiceID)
	if err != nil {
		return err
	}
	if inv.Status == models.InvoiceStatusPaid || inv.Status == models.InvoiceStatusCancelled {
		return fmt.Errorf("%w: cannot mark paid/cancelled invoice as overdue", apperrors.ErrInvalidState)
	}
	return s.invoiceRepo.MarkAsOverdue(ctx, invoiceID)
}

// CancelInvoice sets status to cancelled.
func (s *SubscriptionInvoiceService) CancelInvoice(ctx context.Context, invoiceID uuid.UUID) error {
	if invoiceID == uuid.Nil {
		return fmt.Errorf("%w: invoice_id is required", apperrors.ErrInvalidInput)
	}
	inv, err := s.invoiceRepo.GetByID(ctx, invoiceID)
	if err != nil {
		return err
	}
	if inv.Status == models.InvoiceStatusPaid {
		return fmt.Errorf("%w: cannot cancel a paid invoice", apperrors.ErrInvalidState)
	}
	return s.invoiceRepo.Cancel(ctx, invoiceID)
}

// ---------- Soft Delete ----------

// SoftDeleteInvoice marks an invoice as deleted.
func (s *SubscriptionInvoiceService) SoftDeleteInvoice(ctx context.Context, invoiceID uuid.UUID) error {
	if invoiceID == uuid.Nil {
		return fmt.Errorf("%w: invoice_id is required", apperrors.ErrInvalidInput)
	}
	// Ensure not paid
	inv, err := s.invoiceRepo.GetByID(ctx, invoiceID)
	if err != nil {
		return err
	}
	if inv.Status == models.InvoiceStatusPaid {
		return fmt.Errorf("%w: cannot delete a paid invoice", apperrors.ErrInvalidState)
	}
	return s.invoiceRepo.SoftDelete(ctx, invoiceID)
}

// ---------- Generate Invoice from Payment ----------

// GenerateInvoiceFromPayment creates an invoice for a successful payment.
// It uses the plan details to create a description, and sets the amount from the payment.
// The invoice is created in "issued" state.
func (s *SubscriptionInvoiceService) GenerateInvoiceFromPayment(
	ctx context.Context,
	payment *models.CompanyPayment,
	plan *models.SubscriptionPlan,
) (*models.SubscriptionInvoice, error) {
	if payment == nil {
		return nil, fmt.Errorf("%w: payment is required", apperrors.ErrInvalidInput)
	}
	if plan == nil {
		return nil, fmt.Errorf("%w: plan is required", apperrors.ErrInvalidInput)
	}
	// Ensure payment is successful
	if payment.Status != models.PaymentStatusSuccess {
		return nil, fmt.Errorf("%w: cannot generate invoice for non-successful payment", apperrors.ErrInvalidState)
	}

	// Create invoice
	now := time.Now().UTC()
	invoice := &models.SubscriptionInvoice{
		InvoiceID:   uuid.New(),
		CompanyID:   payment.CompanyID,
		InvoiceDate: now,
		DueDate:     now.AddDate(0, 0, s.cfg.DueDays),
		Currency:    payment.Currency,
		Status:      models.InvoiceStatusIssued,
		IssuedAt:    &now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	// Generate number
	num, err := s.generateInvoiceNumber(ctx, payment.CompanyID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}
	invoice.InvoiceNumber = num

	// Compute totals (no tax/discount for simplicity)
	subtotal := payment.Amount
	taxTotal := 0.0
	discountTotal := 0.0
	grandTotal := subtotal

	invoice.Subtotal = subtotal
	invoice.TaxTotal = taxTotal
	invoice.DiscountTotal = discountTotal
	invoice.GrandTotal = grandTotal

	// Create one line item
	item := &models.SubscriptionInvoiceItem{
		ItemID:      uuid.New(),
		InvoiceID:   invoice.InvoiceID,
		Description: fmt.Sprintf("%s (%d days) subscription", plan.PlanName, plan.DurationDays),
		Quantity:    1,
		UnitPrice:   payment.Amount,
		TotalPrice:  payment.Amount,
		TaxRate:     s.cfg.TaxRate,
		TaxAmount:   0,
		CreatedAt:   now,
	}

	// Insert invoice and item
	if err := s.invoiceRepo.Create(ctx, invoice); err != nil {
		return nil, fmt.Errorf("%w: failed to create invoice: %v", apperrors.ErrInternal, err)
	}
	if err := s.itemRepo.Create(ctx, item); err != nil {
		// Rollback invoice
		_ = s.invoiceRepo.SoftDelete(ctx, invoice.InvoiceID)
		return nil, fmt.Errorf("%w: failed to create invoice item: %v", apperrors.ErrInternal, err)
	}

	// Audit
	if s.auditService != nil {
		ip, _ := ctx.Value("ip_address").(string)
		_ = s.auditService.LogAction(ctx, nil, nil, "invoice", "generate_from_payment", "invoice",
			&invoice.InvoiceID, "system", nil, nil, nil, map[string]interface{}{
				"payment_id":     payment.PaymentID,
				"plan_code":      plan.PlanCode,
				"amount":         payment.Amount,
				"invoice_number": invoice.InvoiceNumber,
				"ip_address":     ip,
			})
	}
	return invoice, nil
}

// ---------- Validation ----------

func (s *SubscriptionInvoiceService) validateInvoice(inv *models.SubscriptionInvoice) error {
	if inv.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id is required", apperrors.ErrInvalidInput)
	}
	if inv.Currency == "" {
		inv.Currency = "USD"
	}
	if len(inv.Currency) != 3 {
		return fmt.Errorf("%w: currency must be 3-letter ISO code", apperrors.ErrInvalidInput)
	}
	if inv.GrandTotal < 0 {
		return fmt.Errorf("%w: grand_total cannot be negative", apperrors.ErrInvalidInput)
	}
	if inv.Subtotal < 0 {
		return fmt.Errorf("%w: subtotal cannot be negative", apperrors.ErrInvalidInput)
	}
	if inv.TaxTotal < 0 {
		return fmt.Errorf("%w: tax_total cannot be negative", apperrors.ErrInvalidInput)
	}
	if inv.DiscountTotal < 0 {
		return fmt.Errorf("%w: discount_total cannot be negative", apperrors.ErrInvalidInput)
	}
	// If invoice number is provided, check length
	if inv.InvoiceNumber != "" && len(inv.InvoiceNumber) > 50 {
		return fmt.Errorf("%w: invoice_number exceeds 50 characters", apperrors.ErrInvalidInput)
	}
	return nil
}
