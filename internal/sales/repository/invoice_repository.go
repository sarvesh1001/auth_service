// package repository
// filename: invoice_repository.go

package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	salesErrors "auth-service/internal/sales/errors"
	"auth-service/internal/sales/models"
	"auth-service/internal/sales/models/enums"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"
)

// -------------------------------------------------------------------------
// Interfaces and Types
// -------------------------------------------------------------------------

type InvoiceRepository interface {
	// INVOICE CRUD
	Create(ctx context.Context, db DBTX, invoice *models.Invoice, items []*models.InvoiceItem) error
	GetByID(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) (*models.Invoice, error)
	GetByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, invoiceNumber string) (*models.Invoice, error)
	Update(ctx context.Context, db DBTX, invoice *models.Invoice) error
	Delete(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) error
	UpdateItemTaxAmount(ctx context.Context, tx DBTX, invoiceItemID uuid.UUID, taxAmount decimal.Decimal) error

	// INVOICE ITEMS
	AddItems(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID, items []*models.InvoiceItem) error
	ReplaceItems(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID, items []*models.InvoiceItem) error
	DeleteItem(ctx context.Context, db DBTX, companyID, invoiceID, invoiceItemID uuid.UUID) error
	GetItems(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) ([]*models.InvoiceItem, error)
	GetItemByID(ctx context.Context, db DBTX, companyID, invoiceID, invoiceItemID uuid.UUID) (*models.InvoiceItem, error)
	ExistsItem(ctx context.Context, db DBTX, companyID, invoiceID, invoiceItemID uuid.UUID) (bool, error)

	// TOTALS / FINANCIALS
	RecalculateTotals(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) error
	GetTotals(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) (subtotal, discountTotal, taxTotal, grandTotal, amountPaid, amountDue decimal.Decimal, err error)
	UpdateAmounts(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID, amountPaid, amountDue decimal.Decimal, updatedBy *uuid.UUID) error

	// STATUS / LIFECYCLE
	UpdateStatus(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID, status enums.InvoiceStatus, updatedBy *uuid.UUID) error
	Issue(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID, issuedAt time.Time, updatedBy *uuid.UUID) error
	MarkPaid(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID, paidAt time.Time, updatedBy *uuid.UUID) error
	MarkOverdue(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID, updatedBy *uuid.UUID) error
	Cancel(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID, cancelledAt time.Time, updatedBy *uuid.UUID) error
	MarkCredited(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID, updatedBy *uuid.UUID) error
	SetLockStatus(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID, isLocked bool, updatedBy *uuid.UUID) error

	// EXISTENCE / VALIDATION
	Exists(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) (bool, error)
	ExistsByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, invoiceNumber string) (bool, error)
	ExistsByExternalRef(ctx context.Context, db DBTX, companyID uuid.UUID, externalRef string) (bool, error)
	IsLocked(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) (bool, error)
	HasPayments(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) (bool, error)
	HasCompletedPayments(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) (bool, error)
	HasReturns(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) (bool, error)

	// PAYMENT / ALLOCATION QUERIES
	GetAmountPaid(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) (decimal.Decimal, error)
	GetAmountDue(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) (decimal.Decimal, error)
	GetOutstandingInvoices(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Invoice, error)
	GetOverdueInvoices(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Invoice, error)

	// QUERYING / LISTING
	List(ctx context.Context, db DBTX, filter InvoiceFilter, p Pagination, s Sort) ([]*models.Invoice, int64, error)
	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.Invoice, int64, error)
	GetByCustomer(ctx context.Context, db DBTX, companyID, customerID uuid.UUID, p Pagination, s Sort) ([]*models.Invoice, int64, error)
	GetByOrder(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) ([]*models.Invoice, error)
	GetInvoicesReadyForCollection(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Invoice, error)

	// ANALYTICS / REPORTING
	GetInvoiceRevenue(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetCollectedRevenue(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetOutstandingAmount(ctx context.Context, db DBTX, companyID uuid.UUID) (decimal.Decimal, error)
	GetAverageInvoiceValue(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetTopInvoicesByValue(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.Invoice, error)
	UpdateTaxTotal(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID, taxTotal decimal.Decimal, updatedBy *uuid.UUID) error

	// CONCURRENCY / LOCKING
	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) (*models.Invoice, error)
	GetItemByIDForUpdate(ctx context.Context, db DBTX, companyID, invoiceID, invoiceItemID uuid.UUID) (*models.InvoiceItem, error)
}

// InvoiceFilter now includes SalesRepID
type InvoiceFilter struct {
	CompanyID uuid.UUID

	CustomerID *uuid.UUID
	OrderID    *uuid.UUID
	SalesRepID *uuid.UUID

	InvoiceIDs []uuid.UUID

	Statuses []enums.InvoiceStatus

	InvoiceNumber *string
	ExternalRef   *string

	Currency *string

	IsLocked *bool

	MinSubtotal *decimal.Decimal
	MaxSubtotal *decimal.Decimal

	MinGrandTotal *decimal.Decimal
	MaxGrandTotal *decimal.Decimal

	MinAmountPaid *decimal.Decimal
	MaxAmountPaid *decimal.Decimal

	MinAmountDue *decimal.Decimal
	MaxAmountDue *decimal.Decimal

	InvoiceDateFrom *time.Time
	InvoiceDateTo   *time.Time

	DueDateFrom *time.Time
	DueDateTo   *time.Time

	IssuedFrom *time.Time
	IssuedTo   *time.Time

	PaidFrom *time.Time
	PaidTo   *time.Time

	CreatedFrom *time.Time
	CreatedTo   *time.Time

	UpdatedFrom *time.Time
	UpdatedTo   *time.Time
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type invoiceRepository struct {
	logger *zap.Logger
}

func NewInvoiceRepository(logger *zap.Logger) InvoiceRepository {
	return &invoiceRepository{
		logger: logger.Named("sales_invoice_repo"),
	}
}

// Helper functions
func (r *invoiceRepository) nullUUIDParam(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func (r *invoiceRepository) nullIntParam(i *int) interface{} {
	if i == nil {
		return nil
	}
	return *i
}

func (r *invoiceRepository) nullDecimalParam(d *decimal.Decimal) interface{} {
	if d == nil {
		return nil
	}
	return d.String()
}

func (r *invoiceRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
	if s.Field == "" {
		return "", nil
	}
	if !allowed[s.Field] {
		return "", fmt.Errorf("invalid sort field: %s", s.Field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "ASC"
	}
	return fmt.Sprintf("ORDER BY %s %s", s.Field, dir), nil
}

func (r *invoiceRepository) validatePagination(p Pagination) (int, int) {
	limit := p.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := p.Offset
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// buildInvoiceFilter now includes SalesRepID
func (r *invoiceRepository) buildInvoiceFilter(filter InvoiceFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.CustomerID != nil {
		conds = append(conds, fmt.Sprintf("customer_id = $%d", idx))
		args = append(args, *filter.CustomerID)
		idx++
	}
	if filter.OrderID != nil {
		conds = append(conds, fmt.Sprintf("order_id = $%d", idx))
		args = append(args, *filter.OrderID)
		idx++
	}
	if filter.SalesRepID != nil {
		conds = append(conds, fmt.Sprintf("sales_rep_id = $%d", idx))
		args = append(args, *filter.SalesRepID)
		idx++
	}
	if len(filter.InvoiceIDs) > 0 {
		placeholders := make([]string, len(filter.InvoiceIDs))
		for i, id := range filter.InvoiceIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("invoice_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if len(filter.Statuses) > 0 {
		placeholders := make([]string, len(filter.Statuses))
		for i, st := range filter.Statuses {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, string(st))
			idx++
		}
		conds = append(conds, fmt.Sprintf("status IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.InvoiceNumber != nil {
		conds = append(conds, fmt.Sprintf("invoice_number = $%d", idx))
		args = append(args, *filter.InvoiceNumber)
		idx++
	}
	if filter.ExternalRef != nil {
		conds = append(conds, fmt.Sprintf("external_ref = $%d", idx))
		args = append(args, *filter.ExternalRef)
		idx++
	}
	if filter.Currency != nil {
		conds = append(conds, fmt.Sprintf("currency = $%d", idx))
		args = append(args, *filter.Currency)
		idx++
	}
	if filter.IsLocked != nil {
		conds = append(conds, fmt.Sprintf("is_locked = $%d", idx))
		args = append(args, *filter.IsLocked)
		idx++
	}
	if filter.MinSubtotal != nil {
		conds = append(conds, fmt.Sprintf("subtotal >= $%d", idx))
		args = append(args, *filter.MinSubtotal)
		idx++
	}
	if filter.MaxSubtotal != nil {
		conds = append(conds, fmt.Sprintf("subtotal <= $%d", idx))
		args = append(args, *filter.MaxSubtotal)
		idx++
	}
	if filter.MinGrandTotal != nil {
		conds = append(conds, fmt.Sprintf("grand_total >= $%d", idx))
		args = append(args, *filter.MinGrandTotal)
		idx++
	}
	if filter.MaxGrandTotal != nil {
		conds = append(conds, fmt.Sprintf("grand_total <= $%d", idx))
		args = append(args, *filter.MaxGrandTotal)
		idx++
	}
	if filter.MinAmountPaid != nil {
		conds = append(conds, fmt.Sprintf("amount_paid >= $%d", idx))
		args = append(args, *filter.MinAmountPaid)
		idx++
	}
	if filter.MaxAmountPaid != nil {
		conds = append(conds, fmt.Sprintf("amount_paid <= $%d", idx))
		args = append(args, *filter.MaxAmountPaid)
		idx++
	}
	if filter.MinAmountDue != nil {
		conds = append(conds, fmt.Sprintf("amount_due >= $%d", idx))
		args = append(args, *filter.MinAmountDue)
		idx++
	}
	if filter.MaxAmountDue != nil {
		conds = append(conds, fmt.Sprintf("amount_due <= $%d", idx))
		args = append(args, *filter.MaxAmountDue)
		idx++
	}
	if filter.InvoiceDateFrom != nil {
		conds = append(conds, fmt.Sprintf("invoice_date >= $%d", idx))
		args = append(args, *filter.InvoiceDateFrom)
		idx++
	}
	if filter.InvoiceDateTo != nil {
		conds = append(conds, fmt.Sprintf("invoice_date <= $%d", idx))
		args = append(args, *filter.InvoiceDateTo)
		idx++
	}
	if filter.DueDateFrom != nil {
		conds = append(conds, fmt.Sprintf("due_date >= $%d", idx))
		args = append(args, *filter.DueDateFrom)
		idx++
	}
	if filter.DueDateTo != nil {
		conds = append(conds, fmt.Sprintf("due_date <= $%d", idx))
		args = append(args, *filter.DueDateTo)
		idx++
	}
	if filter.IssuedFrom != nil {
		conds = append(conds, fmt.Sprintf("issued_at >= $%d", idx))
		args = append(args, *filter.IssuedFrom)
		idx++
	}
	if filter.IssuedTo != nil {
		conds = append(conds, fmt.Sprintf("issued_at <= $%d", idx))
		args = append(args, *filter.IssuedTo)
		idx++
	}
	if filter.PaidFrom != nil {
		conds = append(conds, fmt.Sprintf("paid_at >= $%d", idx))
		args = append(args, *filter.PaidFrom)
		idx++
	}
	if filter.PaidTo != nil {
		conds = append(conds, fmt.Sprintf("paid_at <= $%d", idx))
		args = append(args, *filter.PaidTo)
		idx++
	}
	if filter.CreatedFrom != nil {
		conds = append(conds, fmt.Sprintf("created_at >= $%d", idx))
		args = append(args, *filter.CreatedFrom)
		idx++
	}
	if filter.CreatedTo != nil {
		conds = append(conds, fmt.Sprintf("created_at <= $%d", idx))
		args = append(args, *filter.CreatedTo)
		idx++
	}
	if filter.UpdatedFrom != nil {
		conds = append(conds, fmt.Sprintf("updated_at >= $%d", idx))
		args = append(args, *filter.UpdatedFrom)
		idx++
	}
	if filter.UpdatedTo != nil {
		conds = append(conds, fmt.Sprintf("updated_at <= $%d", idx))
		args = append(args, *filter.UpdatedTo)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

func (r *invoiceRepository) scanInvoice(s scanner) (*models.Invoice, error) {
	var inv models.Invoice
	var orderID, createdBy, updatedBy uuid.NullUUID
	var exchangeRate sql.NullString
	var notes, externalRef sql.NullString
	var issuedAt, paidAt, cancelledAt sql.NullTime
	var salesRepID uuid.NullUUID
	var paymentTermName sql.NullString
	var paymentDueDays sql.NullInt32
	var earlyDiscountPercent sql.NullString
	var earlyDiscountDays sql.NullInt32

	err := s.Scan(
		&inv.InvoiceID,
		&inv.CompanyID,
		&orderID,
		&inv.CustomerID,
		&inv.InvoiceNumber,
		&externalRef,
		&inv.InvoiceDate,
		&inv.DueDate,
		&inv.Status,
		&inv.Currency,
		&exchangeRate,
		&inv.Subtotal,
		&inv.DiscountTotal,
		&inv.TaxTotal,
		&inv.GrandTotal,
		&inv.AmountPaid,
		&inv.AmountDue,
		&notes,
		&inv.IsLocked,
		&issuedAt,
		&paidAt,
		&cancelledAt,
		&inv.CreatedAt,
		&inv.UpdatedAt,
		&createdBy,
		&updatedBy,
		&salesRepID,
		&paymentTermName,
		&paymentDueDays,
		&earlyDiscountPercent,
		&earlyDiscountDays,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, salesErrors.ErrNotFound
		}
		return nil, fmt.Errorf("scan invoice: %w", err)
	}

	if orderID.Valid {
		inv.OrderID = &orderID.UUID
	}
	if externalRef.Valid {
		inv.ExternalRef = &externalRef.String
	}
	if exchangeRate.Valid {
		val, err := decimal.NewFromString(exchangeRate.String)
		if err == nil {
			inv.ExchangeRate = &val
		}
	}
	if notes.Valid {
		inv.Notes = &notes.String
	}
	if issuedAt.Valid {
		inv.IssuedAt = &issuedAt.Time
	}
	if paidAt.Valid {
		inv.PaidAt = &paidAt.Time
	}
	if cancelledAt.Valid {
		inv.CancelledAt = &cancelledAt.Time
	}
	if createdBy.Valid {
		inv.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		inv.UpdatedBy = &updatedBy.UUID
	}
	if salesRepID.Valid {
		inv.SalesRepID = &salesRepID.UUID
	}
	if paymentTermName.Valid {
		inv.PaymentTermName = &paymentTermName.String
	}
	if paymentDueDays.Valid {
		val := int(paymentDueDays.Int32)
		inv.PaymentDueDays = &val
	}
	if earlyDiscountPercent.Valid {
		val, err := decimal.NewFromString(earlyDiscountPercent.String)
		if err == nil {
			inv.EarlyDiscountPercent = &val
		}
	}
	if earlyDiscountDays.Valid {
		val := int(earlyDiscountDays.Int32)
		inv.EarlyDiscountDays = &val
	}
	return &inv, nil
}

// scanInvoiceItem now includes order_item_id and tax_rate.
// total_price is a generated column and not selected – we compute it in Go.
func (r *invoiceRepository) scanInvoiceItem(s scanner) (*models.InvoiceItem, error) {
	var item models.InvoiceItem
	var productID, orderItemID uuid.NullUUID
	var discountAmount, taxAmount, taxRate sql.NullString
	var metadata models.JSONB

	err := s.Scan(
		&item.InvoiceItemID,
		&item.InvoiceID,
		&orderItemID,
		&productID,
		&item.ProductNameSnapshot,
		&item.Quantity,
		&item.UnitPrice,
		&discountAmount,
		&taxRate, // NEW: tax_rate column
		&taxAmount,
		&metadata,
		&item.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, salesErrors.ErrNotFound
		}
		return nil, fmt.Errorf("scan invoice item: %w", err)
	}

	if orderItemID.Valid {
		item.OrderItemID = &orderItemID.UUID
	}
	if productID.Valid {
		item.ProductID = &productID.UUID
	}
	disc := decimal.Zero
	if discountAmount.Valid {
		val, err := decimal.NewFromString(discountAmount.String)
		if err == nil {
			disc = val
			item.DiscountAmount = &val
		}
	}
	if taxRate.Valid {
		val, err := decimal.NewFromString(taxRate.String)
		if err == nil {
			item.TaxRate = &val
		}
	}
	tax := decimal.Zero
	if taxAmount.Valid {
		val, err := decimal.NewFromString(taxAmount.String)
		if err == nil {
			tax = val
			item.TaxAmount = &val
		}
	}
	// Compute total_price = (unit_price * quantity) - discount + tax
	lineSubtotal := item.UnitPrice.Mul(item.Quantity)
	item.TotalPrice = lineSubtotal.Sub(disc).Add(tax)

	item.Metadata = metadata
	return &item, nil
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

// Create inserts a new invoice and its items.
// grand_total and total_price are generated columns – they are not inserted.
func (r *invoiceRepository) Create(ctx context.Context, db DBTX, invoice *models.Invoice, items []*models.InvoiceItem) error {
	query := `
		INSERT INTO sales.invoices (
			invoice_id, company_id, order_id, customer_id, invoice_number, external_ref,
			invoice_date, due_date, status, currency, exchange_rate,
			subtotal, discount_total, tax_total,
			amount_paid, amount_due, notes, is_locked,
			issued_at, paid_at, cancelled_at,
			created_at, updated_at, created_by, updated_by,
			sales_rep_id, payment_term_name, payment_due_days, early_discount_percent, early_discount_days
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
			$12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22,
			$23, $24, $25, $26, $27, $28, $29, $30
		)
		RETURNING created_at, updated_at
	`

	var exchangeRate interface{}
	if invoice.ExchangeRate != nil {
		exchangeRate = invoice.ExchangeRate.String()
	} else {
		exchangeRate = nil
	}

	now := time.Now()

	err := db.QueryRowContext(ctx, query,
		invoice.InvoiceID,
		invoice.CompanyID,
		r.nullUUIDParam(invoice.OrderID),
		invoice.CustomerID,
		invoice.InvoiceNumber,
		invoice.ExternalRef,
		invoice.InvoiceDate,
		invoice.DueDate,
		invoice.Status,
		invoice.Currency,
		exchangeRate,
		invoice.Subtotal,
		invoice.DiscountTotal,
		invoice.TaxTotal,
		invoice.AmountPaid,
		invoice.AmountDue,
		invoice.Notes,
		invoice.IsLocked,
		invoice.IssuedAt,
		invoice.PaidAt,
		invoice.CancelledAt,
		now,
		now,
		r.nullUUIDParam(invoice.CreatedBy),
		r.nullUUIDParam(invoice.UpdatedBy),
		r.nullUUIDParam(invoice.SalesRepID),
		invoice.PaymentTermName,
		r.nullIntParam(invoice.PaymentDueDays),
		r.nullDecimalParam(invoice.EarlyDiscountPercent),
		r.nullIntParam(invoice.EarlyDiscountDays),
	).Scan(&invoice.CreatedAt, &invoice.UpdatedAt)

	if err != nil {
		r.logger.Error("failed to create invoice", zap.Error(err))
		return fmt.Errorf("create invoice: %w", err)
	}

	if len(items) > 0 {
		if err := r.AddItems(ctx, db, invoice.CompanyID, invoice.InvoiceID, items); err != nil {
			return fmt.Errorf("add invoice items: %w", err)
		}
	}
	return nil
}

func (r *invoiceRepository) GetByID(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) (*models.Invoice, error) {
	query := `
		SELECT 
			invoice_id, company_id, order_id, customer_id, invoice_number, external_ref,
			invoice_date, due_date, status, currency, exchange_rate,
			subtotal, discount_total, tax_total, grand_total,
			amount_paid, amount_due, notes, is_locked,
			issued_at, paid_at, cancelled_at,
			created_at, updated_at, created_by, updated_by,
			sales_rep_id, payment_term_name, payment_due_days, early_discount_percent, early_discount_days
		FROM sales.invoices
		WHERE company_id = $1 AND invoice_id = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, invoiceID)
	return r.scanInvoice(row)
}

func (r *invoiceRepository) GetByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, invoiceNumber string) (*models.Invoice, error) {
	query := `
		SELECT 
			invoice_id, company_id, order_id, customer_id, invoice_number, external_ref,
			invoice_date, due_date, status, currency, exchange_rate,
			subtotal, discount_total, tax_total, grand_total,
			amount_paid, amount_due, notes, is_locked,
			issued_at, paid_at, cancelled_at,
			created_at, updated_at, created_by, updated_by,
			sales_rep_id, payment_term_name, payment_due_days, early_discount_percent, early_discount_days
		FROM sales.invoices
		WHERE company_id = $1 AND invoice_number = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, invoiceNumber)
	return r.scanInvoice(row)
}

func (r *invoiceRepository) Update(ctx context.Context, db DBTX, invoice *models.Invoice) error {
	query := `
		UPDATE sales.invoices SET
			order_id = $3,
			customer_id = $4,
			invoice_number = $5,
			external_ref = $6,
			invoice_date = $7,
			due_date = $8,
			status = $9,
			currency = $10,
			exchange_rate = $11,
			subtotal = $12,
			discount_total = $13,
			tax_total = $14,
			amount_paid = $15,
			amount_due = $16,
			notes = $17,
			is_locked = $18,
			issued_at = $19,
			paid_at = $20,
			cancelled_at = $21,
			updated_at = NOW(),
			updated_by = $22,
			sales_rep_id = $23,
			payment_term_name = $24,
			payment_due_days = $25,
			early_discount_percent = $26,
			early_discount_days = $27
		WHERE invoice_id = $1 AND company_id = $2
		RETURNING updated_at
	`
	var exchangeRate interface{}
	if invoice.ExchangeRate != nil {
		exchangeRate = invoice.ExchangeRate.String()
	} else {
		exchangeRate = nil
	}
	err := db.QueryRowContext(ctx, query,
		invoice.InvoiceID,
		invoice.CompanyID,
		r.nullUUIDParam(invoice.OrderID),
		invoice.CustomerID,
		invoice.InvoiceNumber,
		invoice.ExternalRef,
		invoice.InvoiceDate,
		invoice.DueDate,
		invoice.Status,
		invoice.Currency,
		exchangeRate,
		invoice.Subtotal,
		invoice.DiscountTotal,
		invoice.TaxTotal,
		invoice.AmountPaid,
		invoice.AmountDue,
		invoice.Notes,
		invoice.IsLocked,
		invoice.IssuedAt,
		invoice.PaidAt,
		invoice.CancelledAt,
		r.nullUUIDParam(invoice.UpdatedBy),
		r.nullUUIDParam(invoice.SalesRepID),
		invoice.PaymentTermName,
		r.nullIntParam(invoice.PaymentDueDays),
		r.nullDecimalParam(invoice.EarlyDiscountPercent),
		r.nullIntParam(invoice.EarlyDiscountDays),
	).Scan(&invoice.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return salesErrors.ErrNotFound
		}
		return fmt.Errorf("update invoice: %w", err)
	}
	return nil
}

func (r *invoiceRepository) Delete(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) error {
	query := `DELETE FROM sales.invoices WHERE company_id = $1 AND invoice_id = $2`
	result, err := db.ExecContext(ctx, query, companyID, invoiceID)
	if err != nil {
		return fmt.Errorf("delete invoice: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

// -------------------------------------------------------------------------
// Invoice Items
// -------------------------------------------------------------------------

// AddItems inserts one or more invoice items. Supports tax_rate.
func (r *invoiceRepository) AddItems(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID, items []*models.InvoiceItem) error {
	if len(items) == 0 {
		return nil
	}
	// total_price is a generated column – do NOT insert it
	valueStrings := make([]string, 0, len(items))
	// Now there are 12 placeholders (added tax_rate)
	args := make([]interface{}, 0, len(items)*12)
	idx := 1
	for _, item := range items {
		valueStrings = append(valueStrings, fmt.Sprintf(
			"($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, NOW())",
			idx, idx+1, idx+2, idx+3, idx+4, idx+5, idx+6, idx+7, idx+8, idx+9, idx+10))
		args = append(args,
			item.InvoiceItemID,
			invoiceID,
			r.nullUUIDParam(item.OrderItemID),
			r.nullUUIDParam(item.ProductID),
			item.ProductNameSnapshot,
			item.Quantity,
			item.UnitPrice,
			item.DiscountAmount,
			item.TaxRate, // new field
			item.TaxAmount,
			item.Metadata,
		)
		idx += 11 // because we added tax_rate (10th? Actually count: 11 fields)
	}
	query := fmt.Sprintf(`
		INSERT INTO sales.invoice_items (
			invoice_item_id, invoice_id, order_item_id, product_id, product_name_snapshot,
			quantity, unit_price, discount_amount, tax_rate, tax_amount, metadata, created_at
		) VALUES %s
	`, strings.Join(valueStrings, ","))
	_, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("add invoice items: %w", err)
	}
	return nil
}

func (r *invoiceRepository) ReplaceItems(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID, items []*models.InvoiceItem) error {
	if err := r.deleteItemsByInvoice(ctx, db, invoiceID); err != nil {
		return err
	}
	return r.AddItems(ctx, db, companyID, invoiceID, items)
}

func (r *invoiceRepository) deleteItemsByInvoice(ctx context.Context, db DBTX, invoiceID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM sales.invoice_items WHERE invoice_id = $1`, invoiceID)
	if err != nil {
		return fmt.Errorf("delete invoice items: %w", err)
	}
	return nil
}

func (r *invoiceRepository) DeleteItem(ctx context.Context, db DBTX, companyID, invoiceID, invoiceItemID uuid.UUID) error {
	query := `
		DELETE FROM sales.invoice_items
		USING sales.invoices
		WHERE invoice_items.invoice_item_id = $1
		AND invoice_items.invoice_id = $2
		AND invoices.invoice_id = $2
		AND invoices.company_id = $3
	`
	result, err := db.ExecContext(ctx, query, invoiceItemID, invoiceID, companyID)
	if err != nil {
		return fmt.Errorf("delete invoice item: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

func (r *invoiceRepository) GetItems(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) ([]*models.InvoiceItem, error) {
	query := `
		SELECT 
			ii.invoice_item_id, ii.invoice_id, ii.order_item_id, ii.product_id, ii.product_name_snapshot,
			ii.quantity, ii.unit_price, ii.discount_amount, ii.tax_rate, ii.tax_amount,
			ii.metadata, ii.created_at
		FROM sales.invoice_items ii
		JOIN sales.invoices i ON ii.invoice_id = i.invoice_id
		WHERE i.company_id = $1 AND ii.invoice_id = $2
		ORDER BY ii.created_at
	`
	rows, err := db.QueryContext(ctx, query, companyID, invoiceID)
	if err != nil {
		return nil, fmt.Errorf("get invoice items: %w", err)
	}
	defer rows.Close()
	var result []*models.InvoiceItem
	for rows.Next() {
		item, err := r.scanInvoiceItem(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (r *invoiceRepository) GetItemByID(ctx context.Context, db DBTX, companyID, invoiceID, invoiceItemID uuid.UUID) (*models.InvoiceItem, error) {
	query := `
		SELECT 
			ii.invoice_item_id, ii.invoice_id, ii.order_item_id, ii.product_id, ii.product_name_snapshot,
			ii.quantity, ii.unit_price, ii.discount_amount, ii.tax_rate, ii.tax_amount,
			ii.metadata, ii.created_at
		FROM sales.invoice_items ii
		JOIN sales.invoices i ON ii.invoice_id = i.invoice_id
		WHERE i.company_id = $1 AND ii.invoice_id = $2 AND ii.invoice_item_id = $3
	`
	row := db.QueryRowContext(ctx, query, companyID, invoiceID, invoiceItemID)
	return r.scanInvoiceItem(row)
}

func (r *invoiceRepository) ExistsItem(ctx context.Context, db DBTX, companyID, invoiceID, invoiceItemID uuid.UUID) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(
			SELECT 1 FROM sales.invoice_items ii
			JOIN sales.invoices i ON ii.invoice_id = i.invoice_id
			WHERE i.company_id = $1 AND ii.invoice_id = $2 AND ii.invoice_item_id = $3
		)
	`
	err := db.QueryRowContext(ctx, query, companyID, invoiceID, invoiceItemID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists item: %w", err)
	}
	return exists, nil
}

// -------------------------------------------------------------------------
// Totals & Financials
// -------------------------------------------------------------------------

func (r *invoiceRepository) RecalculateTotals(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) error {
	query := `
		UPDATE sales.invoices
		SET 
			subtotal = COALESCE((SELECT SUM(total_price) FROM sales.invoice_items WHERE invoice_id = $2), 0),
			discount_total = COALESCE((SELECT SUM(discount_amount) FROM sales.invoice_items WHERE invoice_id = $2), 0),
			tax_total = COALESCE((SELECT SUM(tax_amount) FROM sales.invoice_items WHERE invoice_id = $2), 0),
			updated_at = NOW()
		WHERE company_id = $1 AND invoice_id = $2
	`
	_, err := db.ExecContext(ctx, query, companyID, invoiceID)
	if err != nil {
		return fmt.Errorf("recalculate totals: %w", err)
	}
	return nil
}

func (r *invoiceRepository) GetTotals(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) (
	subtotal, discountTotal, taxTotal, grandTotal, amountPaid, amountDue decimal.Decimal, err error) {
	query := `
		SELECT subtotal, discount_total, tax_total, grand_total, amount_paid, amount_due
		FROM sales.invoices
		WHERE company_id = $1 AND invoice_id = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, invoiceID)
	err = row.Scan(&subtotal, &discountTotal, &taxTotal, &grandTotal, &amountPaid, &amountDue)
	if err != nil {
		if err == sql.ErrNoRows {
			err = salesErrors.ErrNotFound
		}
		return
	}
	return
}

func (r *invoiceRepository) UpdateAmounts(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID,
	amountPaid, amountDue decimal.Decimal, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.invoices
		SET amount_paid = $3, amount_due = $4, updated_at = NOW(), updated_by = $5
		WHERE company_id = $1 AND invoice_id = $2
	`
	_, err := db.ExecContext(ctx, query, companyID, invoiceID, amountPaid, amountDue, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("update amounts: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Status / Lifecycle
// -------------------------------------------------------------------------

func (r *invoiceRepository) UpdateStatus(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID, status enums.InvoiceStatus, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.invoices
		SET status = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND invoice_id = $2
	`
	_, err := db.ExecContext(ctx, query, companyID, invoiceID, status, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("update status: %w", err)
	}
	return nil
}

func (r *invoiceRepository) Issue(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID, issuedAt time.Time, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.invoices
		SET status = 'issued', issued_at = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND invoice_id = $2 AND status = 'draft'
	`
	_, err := db.ExecContext(ctx, query, companyID, invoiceID, issuedAt, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("issue invoice: %w", err)
	}
	return nil
}

func (r *invoiceRepository) MarkPaid(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID, paidAt time.Time, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.invoices
		SET status = 'paid', amount_paid = grand_total, amount_due = 0, paid_at = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND invoice_id = $2 AND status NOT IN ('paid', 'cancelled')
	`
	_, err := db.ExecContext(ctx, query, companyID, invoiceID, paidAt, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("mark paid: %w", err)
	}
	return nil
}

func (r *invoiceRepository) MarkOverdue(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.invoices
		SET status = 'overdue', updated_at = NOW(), updated_by = $3
		WHERE company_id = $1 AND invoice_id = $2 AND status = 'issued' AND due_date < NOW()
	`
	_, err := db.ExecContext(ctx, query, companyID, invoiceID, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("mark overdue: %w", err)
	}
	return nil
}

func (r *invoiceRepository) Cancel(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID, cancelledAt time.Time, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.invoices
		SET status = 'cancelled', cancelled_at = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND invoice_id = $2 AND status NOT IN ('paid', 'cancelled')
	`
	_, err := db.ExecContext(ctx, query, companyID, invoiceID, cancelledAt, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("cancel invoice: %w", err)
	}
	return nil
}

func (r *invoiceRepository) MarkCredited(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.invoices
		SET status = 'credited', updated_at = NOW(), updated_by = $3
		WHERE company_id = $1 AND invoice_id = $2 AND status = 'issued'
	`
	_, err := db.ExecContext(ctx, query, companyID, invoiceID, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("mark credited: %w", err)
	}
	return nil
}

func (r *invoiceRepository) SetLockStatus(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID, isLocked bool, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.invoices
		SET is_locked = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND invoice_id = $2
	`
	_, err := db.ExecContext(ctx, query, companyID, invoiceID, isLocked, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("set lock status: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Existence / Validation
// -------------------------------------------------------------------------

func (r *invoiceRepository) Exists(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.invoices WHERE company_id = $1 AND invoice_id = $2)`
	err := db.QueryRowContext(ctx, query, companyID, invoiceID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists: %w", err)
	}
	return exists, nil
}

func (r *invoiceRepository) ExistsByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, invoiceNumber string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.invoices WHERE company_id = $1 AND invoice_number = $2)`
	err := db.QueryRowContext(ctx, query, companyID, invoiceNumber).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists by number: %w", err)
	}
	return exists, nil
}

func (r *invoiceRepository) ExistsByExternalRef(ctx context.Context, db DBTX, companyID uuid.UUID, externalRef string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.invoices WHERE company_id = $1 AND external_ref = $2 AND external_ref IS NOT NULL)`
	err := db.QueryRowContext(ctx, query, companyID, externalRef).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists by external ref: %w", err)
	}
	return exists, nil
}

func (r *invoiceRepository) IsLocked(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) (bool, error) {
	var locked bool
	query := `SELECT is_locked FROM sales.invoices WHERE company_id = $1 AND invoice_id = $2`
	err := db.QueryRowContext(ctx, query, companyID, invoiceID).Scan(&locked)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, salesErrors.ErrNotFound
		}
		return false, fmt.Errorf("is locked: %w", err)
	}
	return locked, nil
}

func (r *invoiceRepository) HasPayments(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.payment_allocations WHERE invoice_id = $1)`
	err := db.QueryRowContext(ctx, query, invoiceID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("has payments: %w", err)
	}
	return exists, nil
}

func (r *invoiceRepository) HasCompletedPayments(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(
			SELECT 1 FROM sales.payment_allocations pa
			JOIN sales.payments p ON pa.payment_id = p.payment_id
			WHERE pa.invoice_id = $1 AND p.status = 'completed'
		)
	`
	err := db.QueryRowContext(ctx, query, invoiceID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("has completed payments: %w", err)
	}
	return exists, nil
}

func (r *invoiceRepository) HasReturns(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.returns WHERE invoice_id = $1 AND status != 'rejected')`
	err := db.QueryRowContext(ctx, query, invoiceID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("has returns: %w", err)
	}
	return exists, nil
}

// -------------------------------------------------------------------------
// Payment / Allocation Queries
// -------------------------------------------------------------------------

func (r *invoiceRepository) GetAmountPaid(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) (decimal.Decimal, error) {
	var amountPaid decimal.Decimal
	query := `SELECT COALESCE(amount_paid, 0) FROM sales.invoices WHERE company_id = $1 AND invoice_id = $2`
	err := db.QueryRowContext(ctx, query, companyID, invoiceID).Scan(&amountPaid)
	if err != nil {
		if err == sql.ErrNoRows {
			return decimal.Zero, salesErrors.ErrNotFound
		}
		return decimal.Zero, fmt.Errorf("get amount paid: %w", err)
	}
	return amountPaid, nil
}

func (r *invoiceRepository) GetAmountDue(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) (decimal.Decimal, error) {
	var amountDue decimal.Decimal
	query := `SELECT COALESCE(amount_due, 0) FROM sales.invoices WHERE company_id = $1 AND invoice_id = $2`
	err := db.QueryRowContext(ctx, query, companyID, invoiceID).Scan(&amountDue)
	if err != nil {
		if err == sql.ErrNoRows {
			return decimal.Zero, salesErrors.ErrNotFound
		}
		return decimal.Zero, fmt.Errorf("get amount due: %w", err)
	}
	return amountDue, nil
}

func (r *invoiceRepository) GetOutstandingInvoices(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Invoice, error) {
	filter := InvoiceFilter{
		CompanyID: companyID,
		Statuses:  []enums.InvoiceStatus{enums.InvoiceStatusIssued, enums.InvoiceStatusOverdue},
	}
	inv, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "due_date", Direction: "ASC"})
	return inv, err
}

func (r *invoiceRepository) GetOverdueInvoices(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Invoice, error) {
	filter := InvoiceFilter{
		CompanyID: companyID,
		Statuses:  []enums.InvoiceStatus{enums.InvoiceStatusIssued},
		DueDateTo: timePtr(time.Now()),
	}
	inv, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "due_date", Direction: "ASC"})
	return inv, err
}

func timePtr(t time.Time) *time.Time {
	return &t
}

// -------------------------------------------------------------------------
// Querying / Listing
// -------------------------------------------------------------------------

func (r *invoiceRepository) List(ctx context.Context, db DBTX, filter InvoiceFilter, p Pagination, s Sort) ([]*models.Invoice, int64, error) {
	where, args := r.buildInvoiceFilter(filter)
	if where == "" {
		return nil, 0, fmt.Errorf("list requires at least company_id filter")
	}
	allowedSort := map[string]bool{
		"invoice_number": true,
		"invoice_date":   true,
		"due_date":       true,
		"status":         true,
		"grand_total":    true,
		"amount_due":     true,
		"created_at":     true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY invoice_date DESC"
	}
	limit, offset := r.validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sales.invoices %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count invoices: %w", err)
	}
	if total == 0 {
		return []*models.Invoice{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT 
			invoice_id, company_id, order_id, customer_id, invoice_number, external_ref,
			invoice_date, due_date, status, currency, exchange_rate,
			subtotal, discount_total, tax_total, grand_total,
			amount_paid, amount_due, notes, is_locked,
			issued_at, paid_at, cancelled_at,
			created_at, updated_at, created_by, updated_by,
			sales_rep_id, payment_term_name, payment_due_days, early_discount_percent, early_discount_days
		FROM sales.invoices
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list invoices: %w", err)
	}
	defer rows.Close()
	var result []*models.Invoice
	for rows.Next() {
		inv, err := r.scanInvoice(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, inv)
	}
	return result, total, rows.Err()
}

func (r *invoiceRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, queryStr string, limit, offset int) ([]*models.Invoice, int64, error) {
	searchPattern := "%" + queryStr + "%"
	baseArgs := []interface{}{companyID, searchPattern, searchPattern}
	countQuery := `
		SELECT COUNT(*)
		FROM sales.invoices
		WHERE company_id = $1
		AND (invoice_number ILIKE $2 OR external_ref ILIKE $3)
	`
	var total int64
	err := db.QueryRowContext(ctx, countQuery, baseArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search count: %w", err)
	}
	if total == 0 {
		return []*models.Invoice{}, 0, nil
	}

	dataQuery := `
		SELECT 
			invoice_id, company_id, order_id, customer_id, invoice_number, external_ref,
			invoice_date, due_date, status, currency, exchange_rate,
			subtotal, discount_total, tax_total, grand_total,
			amount_paid, amount_due, notes, is_locked,
			issued_at, paid_at, cancelled_at,
			created_at, updated_at, created_by, updated_by,
			sales_rep_id, payment_term_name, payment_due_days, early_discount_percent, early_discount_days
		FROM sales.invoices
		WHERE company_id = $1
		AND (invoice_number ILIKE $2 OR external_ref ILIKE $3)
		ORDER BY invoice_date DESC
		LIMIT $4 OFFSET $5
	`
	args := append(baseArgs, limit, offset)
	rows, err := db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search data: %w", err)
	}
	defer rows.Close()
	var result []*models.Invoice
	for rows.Next() {
		inv, err := r.scanInvoice(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, inv)
	}
	return result, total, rows.Err()
}

func (r *invoiceRepository) GetByCustomer(ctx context.Context, db DBTX, companyID, customerID uuid.UUID, p Pagination, s Sort) ([]*models.Invoice, int64, error) {
	filter := InvoiceFilter{
		CompanyID:  companyID,
		CustomerID: &customerID,
	}
	return r.List(ctx, db, filter, p, s)
}

func (r *invoiceRepository) GetByOrder(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) ([]*models.Invoice, error) {
	filter := InvoiceFilter{
		CompanyID: companyID,
		OrderID:   &orderID,
	}
	inv, _, err := r.List(ctx, db, filter, Pagination{Limit: 100}, Sort{Field: "invoice_date", Direction: "DESC"})
	return inv, err
}

func (r *invoiceRepository) GetInvoicesReadyForCollection(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Invoice, error) {
	filter := InvoiceFilter{
		CompanyID: companyID,
		Statuses:  []enums.InvoiceStatus{enums.InvoiceStatusIssued, enums.InvoiceStatusOverdue},
	}
	inv, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "due_date", Direction: "ASC"})
	return inv, err
}

// -------------------------------------------------------------------------
// Analytics / Reporting
// -------------------------------------------------------------------------

func (r *invoiceRepository) GetInvoiceRevenue(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	var conds []string
	var args []interface{}
	idx := 1
	conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
	args = append(args, companyID)
	idx++
	conds = append(conds, "status != 'cancelled'")
	if from != nil {
		conds = append(conds, fmt.Sprintf("invoice_date >= $%d", idx))
		args = append(args, *from)
		idx++
	}
	if to != nil {
		conds = append(conds, fmt.Sprintf("invoice_date <= $%d", idx))
		args = append(args, *to)
		idx++
	}
	where := strings.Join(conds, " AND ")
	query := fmt.Sprintf("SELECT COALESCE(SUM(grand_total), 0) FROM sales.invoices WHERE %s", where)
	var revenue decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&revenue)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get invoice revenue: %w", err)
	}
	return revenue, nil
}

func (r *invoiceRepository) GetCollectedRevenue(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	var conds []string
	var args []interface{}
	idx := 1
	conds = append(conds, "i.company_id = $1")
	args = append(args, companyID)
	idx++
	conds = append(conds, "p.status = 'completed'")
	if from != nil {
		conds = append(conds, fmt.Sprintf("p.completed_at >= $%d", idx))
		args = append(args, *from)
		idx++
	}
	if to != nil {
		conds = append(conds, fmt.Sprintf("p.completed_at <= $%d", idx))
		args = append(args, *to)
		idx++
	}
	where := strings.Join(conds, " AND ")
	query := fmt.Sprintf(`
		SELECT COALESCE(SUM(pa.amount), 0)
		FROM sales.payment_allocations pa
		JOIN sales.payments p ON pa.payment_id = p.payment_id
		JOIN sales.invoices i ON pa.invoice_id = i.invoice_id
		WHERE %s
	`, where)
	var revenue decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&revenue)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get collected revenue: %w", err)
	}
	return revenue, nil
}

func (r *invoiceRepository) GetOutstandingAmount(ctx context.Context, db DBTX, companyID uuid.UUID) (decimal.Decimal, error) {
	query := `
		SELECT COALESCE(SUM(amount_due), 0)
		FROM sales.invoices
		WHERE company_id = $1 AND status NOT IN ('paid', 'cancelled')
	`
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, companyID).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get outstanding amount: %w", err)
	}
	return total, nil
}

func (r *invoiceRepository) GetAverageInvoiceValue(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	var conds []string
	var args []interface{}
	idx := 1
	conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
	args = append(args, companyID)
	idx++
	conds = append(conds, "status != 'cancelled'")
	if from != nil {
		conds = append(conds, fmt.Sprintf("invoice_date >= $%d", idx))
		args = append(args, *from)
		idx++
	}
	if to != nil {
		conds = append(conds, fmt.Sprintf("invoice_date <= $%d", idx))
		args = append(args, *to)
		idx++
	}
	where := strings.Join(conds, " AND ")
	query := fmt.Sprintf(`
		SELECT COALESCE(AVG(grand_total), 0)
		FROM sales.invoices
		WHERE %s
	`, where)
	var avg decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&avg)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get average invoice value: %w", err)
	}
	return avg, nil
}

func (r *invoiceRepository) GetTopInvoicesByValue(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.Invoice, error) {
	var conds []string
	var args []interface{}
	idx := 1
	conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
	args = append(args, companyID)
	idx++
	conds = append(conds, "status != 'cancelled'")
	if from != nil {
		conds = append(conds, fmt.Sprintf("invoice_date >= $%d", idx))
		args = append(args, *from)
		idx++
	}
	if to != nil {
		conds = append(conds, fmt.Sprintf("invoice_date <= $%d", idx))
		args = append(args, *to)
		idx++
	}
	where := strings.Join(conds, " AND ")
	query := fmt.Sprintf(`
		SELECT 
			invoice_id, company_id, order_id, customer_id, invoice_number, external_ref,
			invoice_date, due_date, status, currency, exchange_rate,
			subtotal, discount_total, tax_total, grand_total,
			amount_paid, amount_due, notes, is_locked,
			issued_at, paid_at, cancelled_at,
			created_at, updated_at, created_by, updated_by,
			sales_rep_id, payment_term_name, payment_due_days, early_discount_percent, early_discount_days
		FROM sales.invoices
		WHERE %s
		ORDER BY grand_total DESC
		LIMIT $%d
	`, where, idx)
	args = append(args, limit)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get top invoices: %w", err)
	}
	defer rows.Close()
	var result []*models.Invoice
	for rows.Next() {
		inv, err := r.scanInvoice(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, inv)
	}
	return result, rows.Err()
}

// -------------------------------------------------------------------------
// Concurrency / Locking
// -------------------------------------------------------------------------

func (r *invoiceRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) (*models.Invoice, error) {
	query := `
		SELECT 
			invoice_id, company_id, order_id, customer_id, invoice_number, external_ref,
			invoice_date, due_date, status, currency, exchange_rate,
			subtotal, discount_total, tax_total, grand_total,
			amount_paid, amount_due, notes, is_locked,
			issued_at, paid_at, cancelled_at,
			created_at, updated_at, created_by, updated_by,
			sales_rep_id, payment_term_name, payment_due_days, early_discount_percent, early_discount_days
		FROM sales.invoices
		WHERE company_id = $1 AND invoice_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, companyID, invoiceID)
	return r.scanInvoice(row)
}

func (r *invoiceRepository) GetItemByIDForUpdate(ctx context.Context, db DBTX, companyID, invoiceID, invoiceItemID uuid.UUID) (*models.InvoiceItem, error) {
	query := `
		SELECT 
			ii.invoice_item_id, ii.invoice_id, ii.order_item_id, ii.product_id, ii.product_name_snapshot,
			ii.quantity, ii.unit_price, ii.discount_amount, ii.tax_rate, ii.tax_amount,
			ii.metadata, ii.created_at
		FROM sales.invoice_items ii
		JOIN sales.invoices i ON ii.invoice_id = i.invoice_id
		WHERE i.company_id = $1 AND ii.invoice_id = $2 AND ii.invoice_item_id = $3
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, companyID, invoiceID, invoiceItemID)
	return r.scanInvoiceItem(row)
}
func (r *invoiceRepository) UpdateTaxTotal(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID, taxTotal decimal.Decimal, updatedBy *uuid.UUID) error {
	query := `
        UPDATE sales.invoices
        SET tax_total = $1, updated_at = NOW(), updated_by = $2
        WHERE company_id = $3 AND invoice_id = $4
    `
	result, err := db.ExecContext(ctx, query, taxTotal, r.nullUUIDParam(updatedBy), companyID, invoiceID)
	if err != nil {
		return fmt.Errorf("update invoice tax total: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}
func (r *invoiceRepository) UpdateItemTaxAmount(ctx context.Context, tx DBTX, invoiceItemID uuid.UUID, taxAmount decimal.Decimal) error {
	query := `UPDATE sales.invoice_items SET tax_amount = $1 WHERE invoice_item_id = $2`
	res, err := tx.ExecContext(ctx, query, taxAmount, invoiceItemID)
	if err != nil {
		return fmt.Errorf("update invoice item tax amount: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}
