package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	salesErrors "auth-service/internal/sales/errors"
	"auth-service/internal/sales/models"
	"auth-service/internal/sales/models/enums"
)

type QuoteRepository interface {
	Create(ctx context.Context, db DBTX, quote *models.Quote, items []*models.QuoteItem) error
	GetByID(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID) (*models.Quote, error)
	GetByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, quoteNumber string, revision int) (*models.Quote, error)
	Update(ctx context.Context, db DBTX, quote *models.Quote) error
	Delete(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID) error

	AddItems(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID, items []*models.QuoteItem) error
	ReplaceItems(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID, items []*models.QuoteItem) error
	DeleteItem(ctx context.Context, db DBTX, companyID, quoteID, quoteItemID uuid.UUID) error
	GetItems(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID) ([]*models.QuoteItem, error)
	GetItemByID(ctx context.Context, db DBTX, companyID, quoteID, quoteItemID uuid.UUID) (*models.QuoteItem, error)

	RecalculateTotals(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID) error
	GetTotals(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID) (subtotal, discountTotal, taxTotal, grandTotal decimal.Decimal, err error)

	UpdateStatus(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID, status enums.QuoteStatus, updatedBy *uuid.UUID) error
	MarkSent(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID, updatedBy *uuid.UUID) error
	Accept(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID, updatedBy *uuid.UUID) error
	Reject(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID, updatedBy *uuid.UUID) error
	Expire(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID, updatedBy *uuid.UUID) error

	ConvertToOrder(ctx context.Context, db DBTX, companyID, quoteID, orderID uuid.UUID, updatedBy *uuid.UUID) error
	IsConverted(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID) (bool, error)

	Exists(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID) (bool, error)
	ExistsByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, quoteNumber string, revision int) (bool, error)
	IsExpired(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID, at time.Time) (bool, error)

	List(ctx context.Context, db DBTX, filter QuoteFilter, p Pagination, s Sort) ([]*models.Quote, int64, error)
	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.Quote, int64, error)
	GetByCustomer(ctx context.Context, db DBTX, companyID, customerID uuid.UUID, p Pagination, s Sort) ([]*models.Quote, int64, error)
	GetExpiringQuotes(ctx context.Context, db DBTX, companyID uuid.UUID, before time.Time) ([]*models.Quote, error)

	GetQuoteConversionRate(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetTotalQuotedRevenue(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)

	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID) (*models.Quote, error)
}

type QuoteFilter struct {
	CompanyID        uuid.UUID
	CustomerID       *uuid.UUID
	SalesRepID       *uuid.UUID
	QuoteIDs         []uuid.UUID
	Statuses         []enums.QuoteStatus
	QuoteNumber      *string
	Currency         *string
	ConvertedOrderID *uuid.UUID
	MinGrandTotal    *decimal.Decimal
	MaxGrandTotal    *decimal.Decimal
	QuoteDateFrom    *time.Time
	QuoteDateTo      *time.Time
	ExpiryDateFrom   *time.Time
	ExpiryDateTo     *time.Time
	CreatedFrom      *time.Time
	CreatedTo        *time.Time
	UpdatedFrom      *time.Time
	UpdatedTo        *time.Time
}

type quoteRepository struct {
	logger *zap.Logger
}

func NewQuoteRepository(logger *zap.Logger) QuoteRepository {
	return &quoteRepository{
		logger: logger.Named("sales_quote_repo"),
	}
}

func (r *quoteRepository) nullUUIDParam(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func (r *quoteRepository) nullStringParam(s *string) interface{} {
	if s == nil {
		return nil
	}
	return *s
}

func (r *quoteRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *quoteRepository) validatePagination(p Pagination) (int, int) {
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

func (r *quoteRepository) buildQuoteFilter(filter QuoteFilter) (string, []interface{}) {
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
	if filter.SalesRepID != nil {
		conds = append(conds, fmt.Sprintf("sales_rep_id = $%d", idx))
		args = append(args, *filter.SalesRepID)
		idx++
	}
	if len(filter.QuoteIDs) > 0 {
		placeholders := make([]string, len(filter.QuoteIDs))
		for i, id := range filter.QuoteIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("quote_id IN (%s)", strings.Join(placeholders, ",")))
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
	if filter.QuoteNumber != nil {
		conds = append(conds, fmt.Sprintf("quote_number = $%d", idx))
		args = append(args, *filter.QuoteNumber)
		idx++
	}
	if filter.Currency != nil {
		conds = append(conds, fmt.Sprintf("currency = $%d", idx))
		args = append(args, *filter.Currency)
		idx++
	}
	if filter.ConvertedOrderID != nil {
		conds = append(conds, fmt.Sprintf("converted_order_id = $%d", idx))
		args = append(args, *filter.ConvertedOrderID)
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
	if filter.QuoteDateFrom != nil {
		conds = append(conds, fmt.Sprintf("quote_date >= $%d", idx))
		args = append(args, *filter.QuoteDateFrom)
		idx++
	}
	if filter.QuoteDateTo != nil {
		conds = append(conds, fmt.Sprintf("quote_date <= $%d", idx))
		args = append(args, *filter.QuoteDateTo)
		idx++
	}
	if filter.ExpiryDateFrom != nil {
		conds = append(conds, fmt.Sprintf("expiry_date >= $%d", idx))
		args = append(args, *filter.ExpiryDateFrom)
		idx++
	}
	if filter.ExpiryDateTo != nil {
		conds = append(conds, fmt.Sprintf("expiry_date <= $%d", idx))
		args = append(args, *filter.ExpiryDateTo)
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

// scanQuote scans a row into a Quote model
func (r *quoteRepository) scanQuote(s scanner) (*models.Quote, error) {
	var q models.Quote
	var expiryDate sql.NullTime
	var notes sql.NullString
	var convertedOrderID, salesRepID, createdBy, updatedBy uuid.NullUUID
	var currency, statusStr string

	err := s.Scan(
		&q.QuoteID,
		&q.CompanyID,
		&q.CustomerID,
		&q.QuoteNumber,
		&q.Revision,
		&q.QuoteDate,
		&expiryDate,
		&statusStr,
		&currency,
		&q.Subtotal,
		&q.DiscountTotal,
		&q.TaxTotal,
		&q.GrandTotal,
		&notes,
		&convertedOrderID,
		&salesRepID,
		&q.CreatedAt,
		&q.UpdatedAt,
		&createdBy,
		&updatedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, salesErrors.ErrNotFound
		}
		return nil, fmt.Errorf("scan quote: %w", err)
	}

	if expiryDate.Valid {
		q.ExpiryDate = &expiryDate.Time
	}
	if notes.Valid {
		q.Notes = &notes.String
	}
	if convertedOrderID.Valid {
		q.ConvertedOrderID = &convertedOrderID.UUID
	}
	if salesRepID.Valid {
		q.SalesRepID = &salesRepID.UUID
	}
	if createdBy.Valid {
		q.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		q.UpdatedBy = &updatedBy.UUID
	}
	q.Status = enums.QuoteStatus(statusStr)
	q.Currency = currency
	return &q, nil
}

func (r *quoteRepository) scanQuoteItem(s scanner) (*models.QuoteItem, error) {
	var i models.QuoteItem
	var productID uuid.UUID
	var discountAmount, taxAmount sql.NullString
	var metadata models.JSONB

	err := s.Scan(
		&i.QuoteItemID,
		&i.QuoteID,
		&productID,
		&i.ProductNameSnapshot,
		&i.Quantity,
		&i.UnitPrice,
		&discountAmount,
		&taxAmount,
		&i.TotalPrice,
		&metadata,
		&i.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, salesErrors.ErrNotFound
		}
		return nil, fmt.Errorf("scan quote item: %w", err)
	}
	i.ProductID = productID
	if discountAmount.Valid {
		val, err := decimal.NewFromString(discountAmount.String)
		if err == nil {
			i.DiscountAmount = val
		}
	}
	if taxAmount.Valid {
		val, err := decimal.NewFromString(taxAmount.String)
		if err == nil {
			i.TaxAmount = val
		}
	}
	i.Metadata = metadata
	return &i, nil
}

// ---------- CRUD ----------
func (r *quoteRepository) Create(ctx context.Context, db DBTX, quote *models.Quote, items []*models.QuoteItem) error {
	query := `
		INSERT INTO sales.quotes (
			quote_id, company_id, customer_id, quote_number, revision,
			quote_date, expiry_date, status, currency,
			subtotal, discount_total, tax_total,
			notes, converted_order_id, sales_rep_id,
			created_at, updated_at, created_by, updated_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9,
			$10, $11, $12, $13, $14, $15,
			NOW(), NOW(), $16, $17
		)
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		quote.QuoteID,
		quote.CompanyID,
		quote.CustomerID,
		quote.QuoteNumber,
		quote.Revision,
		quote.QuoteDate,
		quote.ExpiryDate,
		quote.Status,
		quote.Currency,
		quote.Subtotal,
		quote.DiscountTotal,
		quote.TaxTotal,
		r.nullStringParam(quote.Notes),
		r.nullUUIDParam(quote.ConvertedOrderID),
		r.nullUUIDParam(quote.SalesRepID),
		r.nullUUIDParam(quote.CreatedBy),
		r.nullUUIDParam(quote.UpdatedBy),
	).Scan(&quote.CreatedAt, &quote.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create quote", zap.Error(err))
		return fmt.Errorf("create quote: %w", err)
	}
	if len(items) > 0 {
		if err := r.AddItems(ctx, db, quote.CompanyID, quote.QuoteID, items); err != nil {
			return err
		}
	}
	return nil
}

func (r *quoteRepository) GetByID(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID) (*models.Quote, error) {
	query := `
		SELECT quote_id, company_id, customer_id, quote_number, revision,
		       quote_date, expiry_date, status, currency,
		       subtotal, discount_total, tax_total, grand_total,
		       notes, converted_order_id, sales_rep_id,
		       created_at, updated_at, created_by, updated_by
		FROM sales.quotes
		WHERE company_id = $1 AND quote_id = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, quoteID)
	return r.scanQuote(row)
}

func (r *quoteRepository) GetByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, quoteNumber string, revision int) (*models.Quote, error) {
	query := `
		SELECT quote_id, company_id, customer_id, quote_number, revision,
		       quote_date, expiry_date, status, currency,
		       subtotal, discount_total, tax_total, grand_total,
		       notes, converted_order_id, sales_rep_id,
		       created_at, updated_at, created_by, updated_by
		FROM sales.quotes
		WHERE company_id = $1 AND quote_number = $2 AND revision = $3
	`
	row := db.QueryRowContext(ctx, query, companyID, quoteNumber, revision)
	return r.scanQuote(row)
}

func (r *quoteRepository) Update(ctx context.Context, db DBTX, quote *models.Quote) error {
	query := `
		UPDATE sales.quotes SET
			customer_id = $3,
			quote_number = $4,
			revision = $5,
			quote_date = $6,
			expiry_date = $7,
			status = $8,
			currency = $9,
			subtotal = $10,
			discount_total = $11,
			tax_total = $12,
			notes = $13,
			converted_order_id = $14,
			sales_rep_id = $15,
			updated_at = NOW(),
			updated_by = $16
		WHERE quote_id = $1 AND company_id = $2
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		quote.QuoteID,
		quote.CompanyID,
		quote.CustomerID,
		quote.QuoteNumber,
		quote.Revision,
		quote.QuoteDate,
		quote.ExpiryDate,
		quote.Status,
		quote.Currency,
		quote.Subtotal,
		quote.DiscountTotal,
		quote.TaxTotal,
		r.nullStringParam(quote.Notes),
		r.nullUUIDParam(quote.ConvertedOrderID),
		r.nullUUIDParam(quote.SalesRepID),
		r.nullUUIDParam(quote.UpdatedBy),
	).Scan(&quote.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return salesErrors.ErrNotFound
		}
		return fmt.Errorf("update quote: %w", err)
	}
	return nil
}

func (r *quoteRepository) Delete(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID) error {
	query := `DELETE FROM sales.quotes WHERE company_id = $1 AND quote_id = $2`
	result, err := db.ExecContext(ctx, query, companyID, quoteID)
	if err != nil {
		return fmt.Errorf("delete quote: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

// ---------- Quote Items ----------
func (r *quoteRepository) AddItems(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID, items []*models.QuoteItem) error {
	if len(items) == 0 {
		return nil
	}
	query := `
		INSERT INTO sales.quote_items (
			quote_item_id, quote_id, product_id, product_name_snapshot,
			quantity, unit_price, discount_amount, tax_amount, metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
	`
	for _, it := range items {
		_, err := db.ExecContext(ctx, query,
			it.QuoteItemID,
			quoteID,
			it.ProductID,
			it.ProductNameSnapshot,
			it.Quantity,
			it.UnitPrice,
			it.DiscountAmount,
			it.TaxAmount,
			it.Metadata,
		)
		if err != nil {
			return fmt.Errorf("add quote item: %w", err)
		}
	}
	return nil
}

func (r *quoteRepository) ReplaceItems(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID, items []*models.QuoteItem) error {
	_, err := db.ExecContext(ctx, `DELETE FROM sales.quote_items WHERE quote_id = $1`, quoteID)
	if err != nil {
		return fmt.Errorf("delete old quote items: %w", err)
	}
	return r.AddItems(ctx, db, companyID, quoteID, items)
}

func (r *quoteRepository) DeleteItem(ctx context.Context, db DBTX, companyID, quoteID, quoteItemID uuid.UUID) error {
	query := `DELETE FROM sales.quote_items WHERE quote_item_id = $1 AND quote_id = $2`
	result, err := db.ExecContext(ctx, query, quoteItemID, quoteID)
	if err != nil {
		return fmt.Errorf("delete quote item: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

func (r *quoteRepository) GetItems(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID) ([]*models.QuoteItem, error) {
	query := `
		SELECT quote_item_id, quote_id, product_id, product_name_snapshot,
		       quantity, unit_price, discount_amount, tax_amount, total_price, metadata, created_at
		FROM sales.quote_items
		WHERE quote_id = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, quoteID)
	if err != nil {
		return nil, fmt.Errorf("get quote items: %w", err)
	}
	defer rows.Close()
	var result []*models.QuoteItem
	for rows.Next() {
		it, err := r.scanQuoteItem(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, it)
	}
	return result, rows.Err()
}

func (r *quoteRepository) GetItemByID(ctx context.Context, db DBTX, companyID, quoteID, quoteItemID uuid.UUID) (*models.QuoteItem, error) {
	query := `
		SELECT quote_item_id, quote_id, product_id, product_name_snapshot,
		       quantity, unit_price, discount_amount, tax_amount, total_price, metadata, created_at
		FROM sales.quote_items
		WHERE quote_item_id = $1 AND quote_id = $2
	`
	row := db.QueryRowContext(ctx, query, quoteItemID, quoteID)
	return r.scanQuoteItem(row)
}

// ---------- Totals ----------
func (r *quoteRepository) RecalculateTotals(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID) error {
	query := `
		UPDATE sales.quotes
		SET
			subtotal = COALESCE((SELECT SUM(total_price) FROM sales.quote_items WHERE quote_id = $2), 0),
			discount_total = COALESCE((SELECT SUM(discount_amount) FROM sales.quote_items WHERE quote_id = $2), 0),
			tax_total = COALESCE((SELECT SUM(tax_amount) FROM sales.quote_items WHERE quote_id = $2), 0),
			updated_at = NOW()
		WHERE company_id = $1 AND quote_id = $2
	`
	_, err := db.ExecContext(ctx, query, companyID, quoteID)
	if err != nil {
		return fmt.Errorf("recalculate quote totals: %w", err)
	}
	return nil
}

func (r *quoteRepository) GetTotals(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID) (
	subtotal, discountTotal, taxTotal, grandTotal decimal.Decimal, err error) {
	query := `
		SELECT subtotal, discount_total, tax_total, grand_total
		FROM sales.quotes
		WHERE company_id = $1 AND quote_id = $2
	`
	err = db.QueryRowContext(ctx, query, companyID, quoteID).Scan(&subtotal, &discountTotal, &taxTotal, &grandTotal)
	if err != nil {
		if err == sql.ErrNoRows {
			err = salesErrors.ErrNotFound
		}
	}
	return
}

// ---------- Status / Lifecycle ----------
func (r *quoteRepository) UpdateStatus(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID, status enums.QuoteStatus, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.quotes
		SET status = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND quote_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, quoteID, status, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("update quote status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

func (r *quoteRepository) MarkSent(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID, updatedBy *uuid.UUID) error {
	return r.UpdateStatus(ctx, db, companyID, quoteID, enums.QuoteStatusSent, updatedBy)
}

func (r *quoteRepository) Accept(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID, updatedBy *uuid.UUID) error {
	return r.UpdateStatus(ctx, db, companyID, quoteID, enums.QuoteStatusAccepted, updatedBy)
}

func (r *quoteRepository) Reject(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID, updatedBy *uuid.UUID) error {
	return r.UpdateStatus(ctx, db, companyID, quoteID, enums.QuoteStatusRejected, updatedBy)
}

func (r *quoteRepository) Expire(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID, updatedBy *uuid.UUID) error {
	return r.UpdateStatus(ctx, db, companyID, quoteID, enums.QuoteStatusExpired, updatedBy)
}

// ---------- Conversion ----------
func (r *quoteRepository) ConvertToOrder(ctx context.Context, db DBTX, companyID, quoteID, orderID uuid.UUID, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.quotes
		SET status = 'converted', converted_order_id = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND quote_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, quoteID, orderID, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("convert quote to order: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

func (r *quoteRepository) IsConverted(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID) (bool, error) {
	var converted bool
	query := `SELECT converted_order_id IS NOT NULL FROM sales.quotes WHERE company_id = $1 AND quote_id = $2`
	err := db.QueryRowContext(ctx, query, companyID, quoteID).Scan(&converted)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, salesErrors.ErrNotFound
		}
		return false, fmt.Errorf("is converted: %w", err)
	}
	return converted, nil
}

// ---------- Existence / Validation ----------
func (r *quoteRepository) Exists(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.quotes WHERE company_id = $1 AND quote_id = $2)`
	err := db.QueryRowContext(ctx, query, companyID, quoteID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists quote: %w", err)
	}
	return exists, nil
}

func (r *quoteRepository) ExistsByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, quoteNumber string, revision int) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.quotes WHERE company_id = $1 AND quote_number = $2 AND revision = $3)`
	err := db.QueryRowContext(ctx, query, companyID, quoteNumber, revision).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists by number: %w", err)
	}
	return exists, nil
}

func (r *quoteRepository) IsExpired(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID, at time.Time) (bool, error) {
	var expired bool
	query := `SELECT expiry_date < $3 FROM sales.quotes WHERE company_id = $1 AND quote_id = $2`
	err := db.QueryRowContext(ctx, query, companyID, quoteID, at).Scan(&expired)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, salesErrors.ErrNotFound
		}
		return false, fmt.Errorf("is expired: %w", err)
	}
	return expired, nil
}

// ---------- Querying / Listing ----------
func (r *quoteRepository) List(ctx context.Context, db DBTX, filter QuoteFilter, p Pagination, s Sort) ([]*models.Quote, int64, error) {
	where, args := r.buildQuoteFilter(filter)
	if where == "" {
		return nil, 0, fmt.Errorf("list requires at least company_id filter")
	}
	allowedSort := map[string]bool{
		"quote_number": true,
		"quote_date":   true,
		"expiry_date":  true,
		"status":       true,
		"grand_total":  true,
		"created_at":   true,
		"revision":     true, // <-- ADD THIS LINE

	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY quote_date DESC"
	}
	limit, offset := r.validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sales.quotes %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count quotes: %w", err)
	}
	if total == 0 {
		return []*models.Quote{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT quote_id, company_id, customer_id, quote_number, revision,
		       quote_date, expiry_date, status, currency,
		       subtotal, discount_total, tax_total, grand_total,
		       notes, converted_order_id, sales_rep_id,
		       created_at, updated_at, created_by, updated_by
		FROM sales.quotes
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list quotes: %w", err)
	}
	defer rows.Close()

	var result []*models.Quote
	for rows.Next() {
		q, err := r.scanQuote(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, q)
	}
	return result, total, rows.Err()
}

func (r *quoteRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, queryStr string, limit, offset int) ([]*models.Quote, int64, error) {
	searchPattern := "%" + queryStr + "%"
	baseArgs := []interface{}{companyID, searchPattern}
	countQuery := `
		SELECT COUNT(*)
		FROM sales.quotes
		WHERE company_id = $1
		AND (quote_number ILIKE $2)
	`
	var total int64
	err := db.QueryRowContext(ctx, countQuery, baseArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search count: %w", err)
	}
	if total == 0 {
		return []*models.Quote{}, 0, nil
	}

	dataQuery := `
		SELECT quote_id, company_id, customer_id, quote_number, revision,
		       quote_date, expiry_date, status, currency,
		       subtotal, discount_total, tax_total, grand_total,
		       notes, converted_order_id, sales_rep_id,
		       created_at, updated_at, created_by, updated_by
		FROM sales.quotes
		WHERE company_id = $1
		AND (quote_number ILIKE $2)
		ORDER BY quote_date DESC
		LIMIT $3 OFFSET $4
	`
	args := append(baseArgs, limit, offset)
	rows, err := db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search data: %w", err)
	}
	defer rows.Close()

	var result []*models.Quote
	for rows.Next() {
		q, err := r.scanQuote(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, q)
	}
	return result, total, rows.Err()
}

func (r *quoteRepository) GetByCustomer(ctx context.Context, db DBTX, companyID, customerID uuid.UUID, p Pagination, s Sort) ([]*models.Quote, int64, error) {
	filter := QuoteFilter{
		CompanyID:  companyID,
		CustomerID: &customerID,
	}
	return r.List(ctx, db, filter, p, s)
}

func (r *quoteRepository) GetExpiringQuotes(ctx context.Context, db DBTX, companyID uuid.UUID, before time.Time) ([]*models.Quote, error) {
	filter := QuoteFilter{
		CompanyID:      companyID,
		ExpiryDateFrom: nil,
		ExpiryDateTo:   &before,
	}
	quotes, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "expiry_date", Direction: "ASC"})
	return quotes, err
}

// ---------- Analytics ----------
func (r *quoteRepository) GetQuoteConversionRate(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	var totalQuotes int64
	var convertedQuotes int64

	where := "company_id = $1"
	args := []interface{}{companyID}
	idx := 2
	if from != nil {
		where += fmt.Sprintf(" AND quote_date >= $%d", idx)
		args = append(args, *from)
		idx++
	}
	if to != nil {
		where += fmt.Sprintf(" AND quote_date <= $%d", idx)
		args = append(args, *to)
		idx++
	}

	// total quotes (excluding draft? usually count all that were sent)
	queryTotal := fmt.Sprintf("SELECT COUNT(*) FROM sales.quotes WHERE %s AND status != 'draft'", where)
	err := db.QueryRowContext(ctx, queryTotal, args...).Scan(&totalQuotes)
	if err != nil {
		return decimal.Zero, fmt.Errorf("total quotes count: %w", err)
	}
	if totalQuotes == 0 {
		return decimal.Zero, nil
	}

	queryConverted := fmt.Sprintf("SELECT COUNT(*) FROM sales.quotes WHERE %s AND status = 'converted'", where)
	err = db.QueryRowContext(ctx, queryConverted, args...).Scan(&convertedQuotes)
	if err != nil {
		return decimal.Zero, fmt.Errorf("converted quotes count: %w", err)
	}
	rate := decimal.NewFromInt(convertedQuotes).Div(decimal.NewFromInt(totalQuotes))
	return rate, nil
}

func (r *quoteRepository) GetTotalQuotedRevenue(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	var where string
	args := []interface{}{companyID}
	idx := 2
	if from != nil {
		where += fmt.Sprintf(" AND quote_date >= $%d", idx)
		args = append(args, *from)
		idx++
	}
	if to != nil {
		where += fmt.Sprintf(" AND quote_date <= $%d", idx)
		args = append(args, *to)
		idx++
	}
	query := fmt.Sprintf("SELECT COALESCE(SUM(grand_total), 0) FROM sales.quotes WHERE company_id = $1%s", where)
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get total quoted revenue: %w", err)
	}
	return total, nil
}

// ---------- Concurrency / Locking ----------
func (r *quoteRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, quoteID uuid.UUID) (*models.Quote, error) {
	query := `
		SELECT quote_id, company_id, customer_id, quote_number, revision,
		       quote_date, expiry_date, status, currency,
		       subtotal, discount_total, tax_total, grand_total,
		       notes, converted_order_id, sales_rep_id,
		       created_at, updated_at, created_by, updated_by
		FROM sales.quotes
		WHERE company_id = $1 AND quote_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, companyID, quoteID)
	return r.scanQuote(row)
}
