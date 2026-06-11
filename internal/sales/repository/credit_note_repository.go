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

	"auth-service/internal/sales/errors"
	"auth-service/internal/sales/models"
	"auth-service/internal/sales/models/enums"
)

// -------------------------------------------------------------------------
// Types & Interface
// -------------------------------------------------------------------------

type CreditNoteRepository interface {
	Create(ctx context.Context, db DBTX, cn *models.CreditNote, items []*models.CreditNoteItem) error
	GetByID(ctx context.Context, db DBTX, companyID, creditNoteID uuid.UUID) (*models.CreditNote, error)
	GetByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, number string) (*models.CreditNote, error)
	Update(ctx context.Context, db DBTX, cn *models.CreditNote) error
	Delete(ctx context.Context, db DBTX, companyID, creditNoteID uuid.UUID) error

	AddItems(ctx context.Context, db DBTX, companyID, creditNoteID uuid.UUID, items []*models.CreditNoteItem) error
	ReplaceItems(ctx context.Context, db DBTX, companyID, creditNoteID uuid.UUID, items []*models.CreditNoteItem) error
	DeleteItem(ctx context.Context, db DBTX, companyID, creditNoteID, itemID uuid.UUID) error
	GetItems(ctx context.Context, db DBTX, companyID, creditNoteID uuid.UUID) ([]*models.CreditNoteItem, error)
	RecalculateTotals(ctx context.Context, db DBTX, companyID, creditNoteID uuid.UUID) error

	UpdateStatus(ctx context.Context, db DBTX, companyID, creditNoteID uuid.UUID, status enums.CreditNoteStatus, updatedBy *uuid.UUID) error
	Issue(ctx context.Context, db DBTX, companyID, creditNoteID uuid.UUID, issuedAt time.Time, updatedBy *uuid.UUID) error
	Void(ctx context.Context, db DBTX, companyID, creditNoteID uuid.UUID, reason string, voidedAt time.Time, updatedBy *uuid.UUID) error
	UpdateAppliedAmount(ctx context.Context, db DBTX, companyID, creditNoteID uuid.UUID, appliedAmount decimal.Decimal, updatedBy *uuid.UUID) error

	Exists(ctx context.Context, db DBTX, companyID, creditNoteID uuid.UUID) (bool, error)
	ExistsByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, number string) (bool, error)

	List(ctx context.Context, db DBTX, filter CreditNoteFilter, p Pagination, s Sort) ([]*models.CreditNote, int64, error)
	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.CreditNote, int64, error)
	GetByCustomer(ctx context.Context, db DBTX, companyID, customerID uuid.UUID, p Pagination, s Sort) ([]*models.CreditNote, int64, error)
	GetByInvoice(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) ([]*models.CreditNote, error)
	GetByReturn(ctx context.Context, db DBTX, companyID, returnID uuid.UUID) (*models.CreditNote, error)
	GetUnusedByCustomer(ctx context.Context, db DBTX, companyID, customerID uuid.UUID) ([]*models.CreditNote, error)

	GetTotalCreditIssued(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetTotalCreditApplied(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetOutstandingCredits(ctx context.Context, db DBTX, companyID uuid.UUID) (decimal.Decimal, error)

	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, creditNoteID uuid.UUID) (*models.CreditNote, error)
}

type CreditNoteFilter struct {
	CompanyID     uuid.UUID
	CustomerID    *uuid.UUID
	Status        *enums.CreditNoteStatus
	FromDate      *time.Time
	ToDate        *time.Time
	InvoiceID     *uuid.UUID
	ReturnID      *uuid.UUID
	CreditNoteIDs []uuid.UUID
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type creditNoteRepository struct {
	logger *zap.Logger
}

func NewCreditNoteRepository(logger *zap.Logger) CreditNoteRepository {
	return &creditNoteRepository{
		logger: logger.Named("sales_credit_note_repo"),
	}
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

func (r *creditNoteRepository) nullUUIDParam(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func (r *creditNoteRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *creditNoteRepository) validatePagination(p Pagination) (int, int) {
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

func (r *creditNoteRepository) buildFilter(filter CreditNoteFilter) (string, []interface{}) {
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
	if filter.Status != nil {
		conds = append(conds, fmt.Sprintf("status = $%d", idx))
		args = append(args, *filter.Status)
		idx++
	}
	if filter.FromDate != nil {
		conds = append(conds, fmt.Sprintf("issue_date >= $%d", idx))
		args = append(args, *filter.FromDate)
		idx++
	}
	if filter.ToDate != nil {
		conds = append(conds, fmt.Sprintf("issue_date <= $%d", idx))
		args = append(args, *filter.ToDate)
		idx++
	}
	if filter.InvoiceID != nil {
		conds = append(conds, fmt.Sprintf("invoice_id = $%d", idx))
		args = append(args, *filter.InvoiceID)
		idx++
	}
	if filter.ReturnID != nil {
		conds = append(conds, fmt.Sprintf("return_id = $%d", idx))
		args = append(args, *filter.ReturnID)
		idx++
	}
	if len(filter.CreditNoteIDs) > 0 {
		placeholders := make([]string, len(filter.CreditNoteIDs))
		for i, id := range filter.CreditNoteIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("credit_note_id IN (%s)", strings.Join(placeholders, ",")))
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// scanCreditNote maps a database row to models.CreditNote
// scanCreditNote maps a database row to models.CreditNote
func (r *creditNoteRepository) scanCreditNote(s scanner) (*models.CreditNote, error) {
	var cn models.CreditNote
	var createdBy, updatedBy uuid.NullUUID
	var invoiceID, returnID uuid.NullUUID
	var issuedAt, voidedAt sql.NullTime

	err := s.Scan(
		&cn.CreditNoteID,
		&cn.CompanyID,
		&cn.CustomerID,
		&cn.CreditNoteNumber,
		&invoiceID,
		&returnID,
		&cn.IssueDate,
		&cn.Status,
		&cn.Currency,
		&cn.Subtotal,
		&cn.TaxTotal,
		&cn.TotalAmount,
		&cn.AmountApplied,
		&cn.Reason,
		&cn.Notes,
		&issuedAt,
		&voidedAt,
		&cn.VoidReason,
		&cn.CreatedAt,
		&cn.UpdatedAt,
		&createdBy,
		&updatedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan credit note: %w", err)
	}

	if invoiceID.Valid {
		cn.InvoiceID = &invoiceID.UUID
	}
	if returnID.Valid {
		cn.ReturnID = &returnID.UUID
	}
	if issuedAt.Valid {
		cn.IssuedAt = &issuedAt.Time
	}
	if voidedAt.Valid {
		cn.VoidedAt = &voidedAt.Time
	}
	if createdBy.Valid {
		cn.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		cn.UpdatedBy = &updatedBy.UUID
	}

	// ✅ FIX: RemainingAmount = TotalAmount + AmountApplied (both negative? TotalAmount negative, AmountApplied positive)
	// e.g., -550 + 100 = -450 (still negative, represents remaining credit)
	cn.RemainingAmount = cn.TotalAmount.Add(cn.AmountApplied)
	return &cn, nil
}

// scanCreditNoteItem maps a row to models.CreditNoteItem
func (r *creditNoteRepository) scanCreditNoteItem(s scanner) (*models.CreditNoteItem, error) {
	var item models.CreditNoteItem
	var invoiceItemID, productID uuid.NullUUID
	var taxRate sql.NullString
	var createdBy uuid.NullUUID

	err := s.Scan(
		&item.CreditNoteItemID,
		&item.CreditNoteID,
		&invoiceItemID,
		&productID,
		&item.ProductNameSnapshot,
		&item.Quantity,
		&item.UnitPrice,
		&taxRate,
		&item.TaxAmount,
		&item.LineAmount,
		&item.CreatedAt,
		&createdBy,
	)
	if err != nil {
		return nil, fmt.Errorf("scan credit note item: %w", err)
	}
	if invoiceItemID.Valid {
		item.InvoiceItemID = &invoiceItemID.UUID
	}
	if productID.Valid {
		item.ProductID = &productID.UUID
	}
	if taxRate.Valid {
		rate, err := decimal.NewFromString(taxRate.String)
		if err == nil {
			item.TaxRate = &rate
		}
	}
	if createdBy.Valid {
		item.CreatedBy = &createdBy.UUID
	}
	return &item, nil
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (r *creditNoteRepository) Create(ctx context.Context, db DBTX, cn *models.CreditNote, items []*models.CreditNoteItem) error {
	tx, ok := db.(*sql.Tx)
	if !ok {
		// if not a transaction, wrap in a transaction? We assume caller passes a transaction.
		return fmt.Errorf("Create requires a *sql.Tx")
	}

	// Insert credit note
	query := `
		INSERT INTO sales.credit_notes (
			credit_note_id, company_id, customer_id, credit_note_number,
			invoice_id, return_id, issue_date, status, currency,
			subtotal, tax_total, total_amount, amount_applied,
			reason, notes, issued_at, voided_at, void_reason,
			created_at, updated_at, created_by, updated_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9,
			$10, $11, $12, $13, $14, $15, $16, $17, $18,
			NOW(), NOW(), $19, $20
		)
		RETURNING created_at, updated_at
	`

	err := tx.QueryRowContext(ctx, query,
		cn.CreditNoteID,
		cn.CompanyID,
		cn.CustomerID,
		cn.CreditNoteNumber,
		r.nullUUIDParam(cn.InvoiceID),
		r.nullUUIDParam(cn.ReturnID),
		cn.IssueDate,
		cn.Status,
		cn.Currency,
		cn.Subtotal,
		cn.TaxTotal,
		cn.TotalAmount,
		cn.AmountApplied,
		cn.Reason,
		cn.Notes,
		cn.IssuedAt,
		cn.VoidedAt,
		cn.VoidReason,
		r.nullUUIDParam(cn.CreatedBy),
		r.nullUUIDParam(cn.UpdatedBy),
	).Scan(&cn.CreatedAt, &cn.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create credit note", zap.Error(err))
		return fmt.Errorf("create credit note: %w", err)
	}

	// Insert items
	if len(items) > 0 {
		if err := r.AddItems(ctx, tx, cn.CompanyID, cn.CreditNoteID, items); err != nil {
			return err
		}
	}
	return nil
}

func (r *creditNoteRepository) GetByID(ctx context.Context, db DBTX, companyID, creditNoteID uuid.UUID) (*models.CreditNote, error) {
	query := `
		SELECT 
			credit_note_id, company_id, customer_id, credit_note_number,
			invoice_id, return_id, issue_date, status, currency,
			subtotal, tax_total, total_amount, amount_applied,
			reason, notes, issued_at, voided_at, void_reason,
			created_at, updated_at, created_by, updated_by
		FROM sales.credit_notes
		WHERE company_id = $1 AND credit_note_id = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, creditNoteID)
	return r.scanCreditNote(row)
}

func (r *creditNoteRepository) GetByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, number string) (*models.CreditNote, error) {
	query := `
		SELECT 
			credit_note_id, company_id, customer_id, credit_note_number,
			invoice_id, return_id, issue_date, status, currency,
			subtotal, tax_total, total_amount, amount_applied,
			reason, notes, issued_at, voided_at, void_reason,
			created_at, updated_at, created_by, updated_by
		FROM sales.credit_notes
		WHERE company_id = $1 AND credit_note_number = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, number)
	return r.scanCreditNote(row)
}

func (r *creditNoteRepository) Update(ctx context.Context, db DBTX, cn *models.CreditNote) error {
	query := `
		UPDATE sales.credit_notes SET
			customer_id = $3,
			credit_note_number = $4,
			invoice_id = $5,
			return_id = $6,
			issue_date = $7,
			status = $8,
			currency = $9,
			subtotal = $10,
			tax_total = $11,
			total_amount = $12,
			amount_applied = $13,
			reason = $14,
			notes = $15,
			issued_at = $16,
			voided_at = $17,
			void_reason = $18,
			updated_at = NOW(),
			updated_by = $19
		WHERE credit_note_id = $1 AND company_id = $2
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		cn.CreditNoteID,
		cn.CompanyID,
		cn.CustomerID,
		cn.CreditNoteNumber,
		r.nullUUIDParam(cn.InvoiceID),
		r.nullUUIDParam(cn.ReturnID),
		cn.IssueDate,
		cn.Status,
		cn.Currency,
		cn.Subtotal,
		cn.TaxTotal,
		cn.TotalAmount,
		cn.AmountApplied,
		cn.Reason,
		cn.Notes,
		cn.IssuedAt,
		cn.VoidedAt,
		cn.VoidReason,
		r.nullUUIDParam(cn.UpdatedBy),
	).Scan(&cn.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return fmt.Errorf("update credit note: %w", err)
	}
	return nil
}

func (r *creditNoteRepository) Delete(ctx context.Context, db DBTX, companyID, creditNoteID uuid.UUID) error {
	query := `DELETE FROM sales.credit_notes WHERE company_id = $1 AND credit_note_id = $2`
	result, err := db.ExecContext(ctx, query, companyID, creditNoteID)
	if err != nil {
		return fmt.Errorf("delete credit note: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// -------------------------------------------------------------------------
// Items
// -------------------------------------------------------------------------

func (r *creditNoteRepository) AddItems(ctx context.Context, db DBTX, companyID, creditNoteID uuid.UUID, items []*models.CreditNoteItem) error {
	if len(items) == 0 {
		return nil
	}
	query := `
		INSERT INTO sales.credit_note_items (
			credit_note_item_id, credit_note_id, invoice_item_id, product_id,
			product_name_snapshot, quantity, unit_price, tax_rate, tax_amount, line_amount,
			created_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), $11)
	`
	for _, item := range items {
		_, err := db.ExecContext(ctx, query,
			item.CreditNoteItemID,
			creditNoteID,
			r.nullUUIDParam(item.InvoiceItemID),
			r.nullUUIDParam(item.ProductID),
			item.ProductNameSnapshot,
			item.Quantity,
			item.UnitPrice,
			item.TaxRate,
			item.TaxAmount,
			item.LineAmount,
			r.nullUUIDParam(item.CreatedBy),
		)
		if err != nil {
			return fmt.Errorf("insert credit note item: %w", err)
		}
	}
	return nil
}

func (r *creditNoteRepository) ReplaceItems(ctx context.Context, db DBTX, companyID, creditNoteID uuid.UUID, items []*models.CreditNoteItem) error {
	// Delete existing items
	delQuery := `DELETE FROM sales.credit_note_items WHERE credit_note_id = $1`
	if _, err := db.ExecContext(ctx, delQuery, creditNoteID); err != nil {
		return fmt.Errorf("delete existing items: %w", err)
	}
	// Add new items
	return r.AddItems(ctx, db, companyID, creditNoteID, items)
}

func (r *creditNoteRepository) DeleteItem(ctx context.Context, db DBTX, companyID, creditNoteID, itemID uuid.UUID) error {
	query := `DELETE FROM sales.credit_note_items WHERE credit_note_item_id = $1 AND credit_note_id = $2`
	result, err := db.ExecContext(ctx, query, itemID, creditNoteID)
	if err != nil {
		return fmt.Errorf("delete credit note item: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *creditNoteRepository) GetItems(ctx context.Context, db DBTX, companyID, creditNoteID uuid.UUID) ([]*models.CreditNoteItem, error) {
	query := `
		SELECT 
			credit_note_item_id, credit_note_id, invoice_item_id, product_id,
			product_name_snapshot, quantity, unit_price, tax_rate, tax_amount, line_amount,
			created_at, created_by
		FROM sales.credit_note_items
		WHERE credit_note_id = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, creditNoteID)
	if err != nil {
		return nil, fmt.Errorf("get credit note items: %w", err)
	}
	defer rows.Close()
	var result []*models.CreditNoteItem
	for rows.Next() {
		item, err := r.scanCreditNoteItem(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (r *creditNoteRepository) RecalculateTotals(ctx context.Context, db DBTX, companyID, creditNoteID uuid.UUID) error {
	// Compute subtotal, tax_total, total_amount from items
	query := `
		UPDATE sales.credit_notes
		SET 
			subtotal = COALESCE((SELECT SUM(line_amount - tax_amount) FROM sales.credit_note_items WHERE credit_note_id = $1), 0),
			tax_total = COALESCE((SELECT SUM(tax_amount) FROM sales.credit_note_items WHERE credit_note_id = $1), 0),
			total_amount = COALESCE((SELECT SUM(line_amount) FROM sales.credit_note_items WHERE credit_note_id = $1), 0),
			updated_at = NOW()
		WHERE credit_note_id = $1 AND company_id = $2
	`
	_, err := db.ExecContext(ctx, query, creditNoteID, companyID)
	if err != nil {
		return fmt.Errorf("recalculate totals: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Status & lifecycle
// -------------------------------------------------------------------------

func (r *creditNoteRepository) UpdateStatus(ctx context.Context, db DBTX, companyID, creditNoteID uuid.UUID, status enums.CreditNoteStatus, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.credit_notes
		SET status = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND credit_note_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, creditNoteID, status, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("update status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *creditNoteRepository) Issue(ctx context.Context, db DBTX, companyID, creditNoteID uuid.UUID, issuedAt time.Time, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.credit_notes
		SET status = 'issued', issued_at = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND credit_note_id = $2
		AND status IN ('draft')
	`
	result, err := db.ExecContext(ctx, query, companyID, creditNoteID, issuedAt, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("issue credit note: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrInvalidStatus
	}
	return nil
}

func (r *creditNoteRepository) Void(ctx context.Context, db DBTX, companyID, creditNoteID uuid.UUID, reason string, voidedAt time.Time, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.credit_notes
		SET status = 'voided', voided_at = $3, void_reason = $4, updated_at = NOW(), updated_by = $5
		WHERE company_id = $1 AND credit_note_id = $2
		AND status NOT IN ('voided', 'fully_used')
	`
	result, err := db.ExecContext(ctx, query, companyID, creditNoteID, voidedAt, reason, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("void credit note: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrInvalidStatus
	}
	return nil
}

func (r *creditNoteRepository) UpdateAppliedAmount(ctx context.Context, db DBTX, companyID, creditNoteID uuid.UUID, appliedAmount decimal.Decimal, updatedBy *uuid.UUID) error {
	logger := r.logger.With(
		zap.String("method", "UpdateAppliedAmount"),
		zap.String("credit_note_id", creditNoteID.String()),
		zap.String("applied_amount", appliedAmount.String()),
	)

	// First get current credit note to log state
	var currentTotal, currentApplied decimal.Decimal
	var currentStatus string
	checkQuery := `SELECT total_amount, amount_applied, status FROM sales.credit_notes WHERE credit_note_id = $1`
	err := db.QueryRowContext(ctx, checkQuery, creditNoteID).Scan(&currentTotal, &currentApplied, &currentStatus)
	if err != nil {
		logger.Error("failed to fetch current credit note state", zap.Error(err))
		return fmt.Errorf("fetch current state: %w", err)
	}
	logger.Info("current credit note state",
		zap.String("total_amount", currentTotal.String()),
		zap.String("amount_applied", currentApplied.String()),
		zap.String("status", currentStatus),
	)

	// Correct condition: appliedAmount + currentApplied must not exceed the absolute value of total_amount
	absTotal := currentTotal.Abs()
	if appliedAmount.Add(currentApplied).GreaterThan(absTotal) {
		logger.Error("applied amount would exceed remaining balance",
			zap.String("abs_total", absTotal.String()),
			zap.String("new_total_applied", appliedAmount.Add(currentApplied).String()),
		)
		return errors.ErrInvalidStatus
	}

	query := `
		UPDATE sales.credit_notes
		SET amount_applied = amount_applied + $3,
			status = CASE 
				WHEN amount_applied + $3 >= -total_amount THEN 'fully_used'
				WHEN amount_applied + $3 > 0 THEN 'partially_used'
				ELSE status
			END,
			updated_at = NOW(),
			updated_by = $4
		WHERE company_id = $1 AND credit_note_id = $2
		AND status IN ('issued', 'partially_used')
		AND amount_applied + $3 <= -total_amount
	`
	result, err := db.ExecContext(ctx, query, companyID, creditNoteID, appliedAmount, r.nullUUIDParam(updatedBy))
	if err != nil {
		logger.Error("update applied amount query failed", zap.Error(err))
		return fmt.Errorf("update applied amount: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		logger.Error("no rows updated – condition failed",
			zap.String("total_amount", currentTotal.String()),
			zap.String("amount_applied", currentApplied.String()),
			zap.String("appliedAmount", appliedAmount.String()),
		)
		return errors.ErrInvalidStatus
	}
	logger.Info("successfully updated applied amount", zap.Int64("rows_affected", rows))
	return nil
}

// -------------------------------------------------------------------------
// Existence
// -------------------------------------------------------------------------

func (r *creditNoteRepository) Exists(ctx context.Context, db DBTX, companyID, creditNoteID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.credit_notes WHERE company_id = $1 AND credit_note_id = $2)`
	err := db.QueryRowContext(ctx, query, companyID, creditNoteID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists: %w", err)
	}
	return exists, nil
}

func (r *creditNoteRepository) ExistsByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, number string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.credit_notes WHERE company_id = $1 AND credit_note_number = $2)`
	err := db.QueryRowContext(ctx, query, companyID, number).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists by number: %w", err)
	}
	return exists, nil
}

// -------------------------------------------------------------------------
// Listing & Search
// -------------------------------------------------------------------------

func (r *creditNoteRepository) List(ctx context.Context, db DBTX, filter CreditNoteFilter, p Pagination, s Sort) ([]*models.CreditNote, int64, error) {
	where, args := r.buildFilter(filter)
	if where == "" {
		// company_id must be present; if not, error
		if filter.CompanyID == uuid.Nil {
			return nil, 0, fmt.Errorf("list requires company_id filter")
		}
		where = "WHERE company_id = $1"
		args = []interface{}{filter.CompanyID}
	}

	allowedSort := map[string]bool{
		"credit_note_number": true,
		"issue_date":         true,
		"status":             true,
		"total_amount":       true,
		"created_at":         true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY issue_date DESC"
	}
	limit, offset := r.validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sales.credit_notes %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count credit notes: %w", err)
	}
	if total == 0 {
		return []*models.CreditNote{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT 
			credit_note_id, company_id, customer_id, credit_note_number,
			invoice_id, return_id, issue_date, status, currency,
			subtotal, tax_total, total_amount, amount_applied,
			reason, notes, issued_at, voided_at, void_reason,
			created_at, updated_at, created_by, updated_by
		FROM sales.credit_notes
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list credit notes: %w", err)
	}
	defer rows.Close()

	var result []*models.CreditNote
	for rows.Next() {
		cn, err := r.scanCreditNote(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, cn)
	}
	return result, total, rows.Err()
}

func (r *creditNoteRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, queryStr string, limit, offset int) ([]*models.CreditNote, int64, error) {
	searchPattern := "%" + queryStr + "%"
	baseArgs := []interface{}{companyID, searchPattern, searchPattern, searchPattern}
	countQuery := `
		SELECT COUNT(*)
		FROM sales.credit_notes
		WHERE company_id = $1
		AND (credit_note_number ILIKE $2 OR reason ILIKE $3 OR notes ILIKE $4)
	`
	var total int64
	err := db.QueryRowContext(ctx, countQuery, baseArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search count: %w", err)
	}
	if total == 0 {
		return []*models.CreditNote{}, 0, nil
	}

	dataQuery := `
		SELECT 
			credit_note_id, company_id, customer_id, credit_note_number,
			invoice_id, return_id, issue_date, status, currency,
			subtotal, tax_total, total_amount, amount_applied,
			reason, notes, issued_at, voided_at, void_reason,
			created_at, updated_at, created_by, updated_by
		FROM sales.credit_notes
		WHERE company_id = $1
		AND (credit_note_number ILIKE $2 OR reason ILIKE $3 OR notes ILIKE $4)
		ORDER BY issue_date DESC
		LIMIT $5 OFFSET $6
	`
	args := append(baseArgs, limit, offset)
	rows, err := db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search data: %w", err)
	}
	defer rows.Close()

	var result []*models.CreditNote
	for rows.Next() {
		cn, err := r.scanCreditNote(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, cn)
	}
	return result, total, rows.Err()
}

func (r *creditNoteRepository) GetByCustomer(ctx context.Context, db DBTX, companyID, customerID uuid.UUID, p Pagination, s Sort) ([]*models.CreditNote, int64, error) {
	filter := CreditNoteFilter{
		CompanyID:  companyID,
		CustomerID: &customerID,
	}
	return r.List(ctx, db, filter, p, s)
}

func (r *creditNoteRepository) GetByInvoice(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) ([]*models.CreditNote, error) {
	filter := CreditNoteFilter{
		CompanyID: companyID,
		InvoiceID: &invoiceID,
	}
	// Use list with default pagination large enough
	result, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{})
	return result, err
}

func (r *creditNoteRepository) GetByReturn(ctx context.Context, db DBTX, companyID, returnID uuid.UUID) (*models.CreditNote, error) {
	query := `
		SELECT 
			credit_note_id, company_id, customer_id, credit_note_number,
			invoice_id, return_id, issue_date, status, currency,
			subtotal, tax_total, total_amount, amount_applied,
			reason, notes, issued_at, voided_at, void_reason,
			created_at, updated_at, created_by, updated_by
		FROM sales.credit_notes
		WHERE company_id = $1 AND return_id = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, returnID)
	return r.scanCreditNote(row)
}

func (r *creditNoteRepository) GetUnusedByCustomer(ctx context.Context, db DBTX, companyID, customerID uuid.UUID) ([]*models.CreditNote, error) {
	filter := CreditNoteFilter{
		CompanyID:  companyID,
		CustomerID: &customerID,
		Status:     ptr(enums.CreditNoteIssued),
	}
	// also partially_used are still usable
	result, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{})
	if err != nil {
		return nil, err
	}
	// Also include partially_used
	filter2 := CreditNoteFilter{
		CompanyID:  companyID,
		CustomerID: &customerID,
		Status:     ptr(enums.CreditNotePartiallyUsed),
	}
	result2, _, err := r.List(ctx, db, filter2, Pagination{Limit: 1000}, Sort{})
	if err != nil {
		return nil, err
	}
	return append(result, result2...), nil
}

// -------------------------------------------------------------------------
// Aggregates
// -------------------------------------------------------------------------

// GetTotalCreditIssued returns the total credit amount issued in the given date range.
// Since total_amount is stored as negative, we return the absolute value (SUM(-total_amount)).
func (r *creditNoteRepository) GetTotalCreditIssued(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	var conds []string
	var args []interface{}
	idx := 1

	conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
	args = append(args, companyID)
	idx++

	if from != nil {
		conds = append(conds, fmt.Sprintf("issue_date >= $%d", idx))
		args = append(args, *from)
		idx++
	}
	if to != nil {
		conds = append(conds, fmt.Sprintf("issue_date <= $%d", idx))
		args = append(args, *to)
		idx++
	}
	// Only include credit notes that have been issued (draft notes are not yet issued)
	conds = append(conds, "status IN ('issued', 'partially_used', 'fully_used')")

	where := "WHERE " + strings.Join(conds, " AND ")
	// FIX: Use SUM(-total_amount) to get positive total issued amount
	query := fmt.Sprintf("SELECT COALESCE(SUM(-total_amount), 0) FROM sales.credit_notes %s", where)

	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get total credit issued: %w", err)
	}
	return total, nil
}
func (r *creditNoteRepository) GetTotalCreditApplied(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	var conds []string
	var args []interface{}
	idx := 1
	conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
	args = append(args, companyID)
	idx++
	if from != nil {
		conds = append(conds, fmt.Sprintf("updated_at >= $%d", idx))
		args = append(args, *from)
		idx++
	}
	if to != nil {
		conds = append(conds, fmt.Sprintf("updated_at <= $%d", idx))
		args = append(args, *to)
		idx++
	}
	conds = append(conds, "amount_applied > 0")
	where := "WHERE " + strings.Join(conds, " AND ")
	query := fmt.Sprintf("SELECT COALESCE(SUM(amount_applied), 0) FROM sales.credit_notes %s", where)
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get total credit applied: %w", err)
	}
	return total, nil
}

func (r *creditNoteRepository) GetOutstandingCredits(ctx context.Context, db DBTX, companyID uuid.UUID) (decimal.Decimal, error) {
	// ✅ FIX: SUM(-total_amount - amount_applied) gives positive outstanding credit
	query := `
		SELECT COALESCE(SUM(-total_amount - amount_applied), 0)
		FROM sales.credit_notes
		WHERE company_id = $1 AND status IN ('issued', 'partially_used')
	`
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, companyID).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get outstanding credits: %w", err)
	}
	return total, nil
}

// -------------------------------------------------------------------------
// Locking
// -------------------------------------------------------------------------

func (r *creditNoteRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, creditNoteID uuid.UUID) (*models.CreditNote, error) {
	query := `
		SELECT 
			credit_note_id, company_id, customer_id, credit_note_number,
			invoice_id, return_id, issue_date, status, currency,
			subtotal, tax_total, total_amount, amount_applied,
			reason, notes, issued_at, voided_at, void_reason,
			created_at, updated_at, created_by, updated_by
		FROM sales.credit_notes
		WHERE company_id = $1 AND credit_note_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, companyID, creditNoteID)
	return r.scanCreditNote(row)
}

// -------------------------------------------------------------------------
// Helper
// -------------------------------------------------------------------------

func ptr[T any](v T) *T {
	return &v
}
