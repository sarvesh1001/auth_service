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

// -------------------------------------------------------------------------
// Interface (already defined – for clarity)
// -------------------------------------------------------------------------

type ReturnRepository interface {
	// CRUD for Return
	Create(ctx context.Context, db DBTX, ret *models.Return, items []*models.ReturnItem) error
	GetByID(ctx context.Context, db DBTX, companyID, returnID uuid.UUID) (*models.Return, error)
	GetByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, returnNumber string) (*models.Return, error)
	Update(ctx context.Context, db DBTX, ret *models.Return) error
	Delete(ctx context.Context, db DBTX, companyID, returnID uuid.UUID) error

	// Return Items
	AddItems(ctx context.Context, db DBTX, companyID, returnID uuid.UUID, items []*models.ReturnItem) error
	ReplaceItems(ctx context.Context, db DBTX, companyID, returnID uuid.UUID, items []*models.ReturnItem) error
	DeleteItem(ctx context.Context, db DBTX, companyID, returnID, returnItemID uuid.UUID) error
	GetItems(ctx context.Context, db DBTX, companyID, returnID uuid.UUID) ([]*models.ReturnItem, error)
	GetItemByID(ctx context.Context, db DBTX, companyID, returnID, returnItemID uuid.UUID) (*models.ReturnItem, error)
	ExistsItem(ctx context.Context, db DBTX, companyID, returnID, returnItemID uuid.UUID) (bool, error)

	// Totals / Refunds
	RecalculateRefundTotal(ctx context.Context, db DBTX, companyID, returnID uuid.UUID) error
	GetRefundTotal(ctx context.Context, db DBTX, companyID, returnID uuid.UUID) (decimal.Decimal, error)
	UpdateRefundTotal(ctx context.Context, db DBTX, companyID, returnID uuid.UUID, totalRefund decimal.Decimal, updatedBy *uuid.UUID) error

	// Status / Lifecycle
	UpdateStatus(ctx context.Context, db DBTX, companyID, returnID uuid.UUID, status enums.ReturnStatus, updatedBy *uuid.UUID) error
	Approve(ctx context.Context, db DBTX, companyID, returnID uuid.UUID, approvedAt time.Time, updatedBy *uuid.UUID) error
	Complete(ctx context.Context, db DBTX, companyID, returnID uuid.UUID, completedAt time.Time, updatedBy *uuid.UUID) error
	Reject(ctx context.Context, db DBTX, companyID, returnID uuid.UUID, updatedBy *uuid.UUID) error

	// Credit Note / Invoice Linking
	SetCreditNote(ctx context.Context, db DBTX, companyID, returnID uuid.UUID, creditNoteID *uuid.UUID, updatedBy *uuid.UUID) error
	GetCreditNote(ctx context.Context, db DBTX, companyID, returnID uuid.UUID) (*models.Invoice, error)

	// Existence / Validation
	Exists(ctx context.Context, db DBTX, companyID, returnID uuid.UUID) (bool, error)
	ExistsByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, returnNumber string) (bool, error)
	ExistsByOrder(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) (bool, error)
	HasCreditNote(ctx context.Context, db DBTX, companyID, returnID uuid.UUID) (bool, error)

	// Order / Invoice Relations
	GetByOrder(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) ([]*models.Return, error)
	GetByInvoice(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) ([]*models.Return, error)
	GetPendingReturns(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Return, error)
	GetApprovedReturns(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Return, error)
	GetCompletedReturns(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Return, error)

	// Querying / Listing
	List(ctx context.Context, db DBTX, filter ReturnFilter, p Pagination, s Sort) ([]*models.Return, int64, error)
	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.Return, int64, error)

	// Analytics / Reporting
	GetTotalRefundedAmount(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetReturnRate(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetTopReturnedProducts(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.Product, error)
	GetReturnsWithoutCreditNotes(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Return, error)

	// Concurrency / Locking
	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, returnID uuid.UUID) (*models.Return, error)
	GetItemByIDForUpdate(ctx context.Context, db DBTX, companyID, returnID, returnItemID uuid.UUID) (*models.ReturnItem, error)
}

// -------------------------------------------------------------------------
// Filter type (already defined)
// -------------------------------------------------------------------------

type ReturnFilter struct {
	CompanyID      uuid.UUID
	OrderID        *uuid.UUID
	InvoiceID      *uuid.UUID
	ReturnIDs      []uuid.UUID
	Statuses       []enums.ReturnStatus
	ReturnNumber   *string
	MinRefundTotal *decimal.Decimal
	MaxRefundTotal *decimal.Decimal
	ReturnDateFrom *time.Time
	ReturnDateTo   *time.Time
	ApprovedFrom   *time.Time
	ApprovedTo     *time.Time
	CompletedFrom  *time.Time
	CompletedTo    *time.Time
	CreatedFrom    *time.Time
	CreatedTo      *time.Time
	UpdatedFrom    *time.Time
	UpdatedTo      *time.Time
}

// -------------------------------------------------------------------------
// Repository implementation
// -------------------------------------------------------------------------

type returnRepository struct {
	logger *zap.Logger
}

func NewReturnRepository(logger *zap.Logger) ReturnRepository {
	return &returnRepository{
		logger: logger.Named("sales_return_repo"),
	}
}

// -------------------------------------------------------------------------
// Helper functions (shared with other repos)
// -------------------------------------------------------------------------

func (r *returnRepository) nullUUIDParam(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func (r *returnRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *returnRepository) validatePagination(p Pagination) (int, int) {
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

func (r *returnRepository) buildReturnFilter(filter ReturnFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.OrderID != nil {
		conds = append(conds, fmt.Sprintf("order_id = $%d", idx))
		args = append(args, *filter.OrderID)
		idx++
	}
	if filter.InvoiceID != nil {
		conds = append(conds, fmt.Sprintf("invoice_id = $%d", idx))
		args = append(args, *filter.InvoiceID)
		idx++
	}
	if len(filter.ReturnIDs) > 0 {
		placeholders := make([]string, len(filter.ReturnIDs))
		for i, id := range filter.ReturnIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("return_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if len(filter.Statuses) > 0 {
		placeholders := make([]string, len(filter.Statuses))
		for i, st := range filter.Statuses {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, st.String())
			idx++
		}
		conds = append(conds, fmt.Sprintf("status IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.ReturnNumber != nil {
		conds = append(conds, fmt.Sprintf("return_number = $%d", idx))
		args = append(args, *filter.ReturnNumber)
		idx++
	}
	if filter.MinRefundTotal != nil {
		conds = append(conds, fmt.Sprintf("total_refund >= $%d", idx))
		args = append(args, *filter.MinRefundTotal)
		idx++
	}
	if filter.MaxRefundTotal != nil {
		conds = append(conds, fmt.Sprintf("total_refund <= $%d", idx))
		args = append(args, *filter.MaxRefundTotal)
		idx++
	}
	if filter.ReturnDateFrom != nil {
		conds = append(conds, fmt.Sprintf("return_date >= $%d", idx))
		args = append(args, *filter.ReturnDateFrom)
		idx++
	}
	if filter.ReturnDateTo != nil {
		conds = append(conds, fmt.Sprintf("return_date <= $%d", idx))
		args = append(args, *filter.ReturnDateTo)
		idx++
	}
	if filter.ApprovedFrom != nil {
		conds = append(conds, fmt.Sprintf("approved_at >= $%d", idx))
		args = append(args, *filter.ApprovedFrom)
		idx++
	}
	if filter.ApprovedTo != nil {
		conds = append(conds, fmt.Sprintf("approved_at <= $%d", idx))
		args = append(args, *filter.ApprovedTo)
		idx++
	}
	if filter.CompletedFrom != nil {
		conds = append(conds, fmt.Sprintf("completed_at >= $%d", idx))
		args = append(args, *filter.CompletedFrom)
		idx++
	}
	if filter.CompletedTo != nil {
		conds = append(conds, fmt.Sprintf("completed_at <= $%d", idx))
		args = append(args, *filter.CompletedTo)
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

// -------------------------------------------------------------------------
// Scanner functions
// -------------------------------------------------------------------------

func (r *returnRepository) scanReturn(s scanner) (*models.Return, error) {
	var ret models.Return
	var invoiceID, creditNoteID, createdBy, updatedBy uuid.NullUUID
	var reason sql.NullString
	var approvedAt, completedAt sql.NullTime

	err := s.Scan(
		&ret.ReturnID,
		&ret.CompanyID,
		&ret.OrderID,
		&invoiceID,
		&creditNoteID,
		&ret.ReturnNumber,
		&ret.ReturnDate,
		&reason,
		&ret.Status,
		&ret.TotalRefund,
		&approvedAt,
		&completedAt,
		&ret.CreatedAt,
		&ret.UpdatedAt,
		&createdBy,
		&updatedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, salesErrors.ErrNotFound
		}
		return nil, fmt.Errorf("scan return: %w", err)
	}

	if invoiceID.Valid {
		ret.InvoiceID = &invoiceID.UUID
	}
	if creditNoteID.Valid {
		ret.CreditNoteID = &creditNoteID.UUID
	}
	if reason.Valid {
		ret.Reason = &reason.String
	}
	if approvedAt.Valid {
		ret.ApprovedAt = &approvedAt.Time
	}
	if completedAt.Valid {
		ret.CompletedAt = &completedAt.Time
	}
	if createdBy.Valid {
		ret.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		ret.UpdatedBy = &updatedBy.UUID
	}
	return &ret, nil
}

func (r *returnRepository) scanReturnItem(s scanner) (*models.ReturnItem, error) {
	var item models.ReturnItem
	var orderItemID, createdBy uuid.NullUUID
	var reason sql.NullString

	err := s.Scan(
		&item.ReturnItemID,
		&item.ReturnID,
		&orderItemID,
		&item.ProductID,
		&item.ProductNameSnapshot,
		&item.Quantity,
		&item.UnitPrice,
		&item.RefundAmount,
		&reason,
		&item.CreatedAt,
		&createdBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, salesErrors.ErrNotFound
		}
		return nil, fmt.Errorf("scan return item: %w", err)
	}

	if orderItemID.Valid {
		item.OrderItemID = &orderItemID.UUID
	}
	if reason.Valid {
		item.Reason = &reason.String
	}
	return &item, nil
}

// -------------------------------------------------------------------------
// CRUD: Return
// -------------------------------------------------------------------------

func (r *returnRepository) Create(ctx context.Context, db DBTX, ret *models.Return, items []*models.ReturnItem) error {
	// Start transaction manually? No, we assume the caller already started a transaction.
	// Insert return
	query := `
		INSERT INTO sales.returns (
			return_id, company_id, order_id, invoice_id, credit_note_id,
			return_number, return_date, reason, status, total_refund,
			approved_at, completed_at, created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), NOW(), $13, $14)
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		ret.ReturnID, ret.CompanyID, ret.OrderID,
		r.nullUUIDParam(ret.InvoiceID), r.nullUUIDParam(ret.CreditNoteID),
		ret.ReturnNumber, ret.ReturnDate, ret.Reason, ret.Status, ret.TotalRefund,
		ret.ApprovedAt, ret.CompletedAt,
		r.nullUUIDParam(ret.CreatedBy), r.nullUUIDParam(ret.UpdatedBy),
	).Scan(&ret.CreatedAt, &ret.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create return", zap.Error(err))
		return fmt.Errorf("create return: %w", err)
	}

	// Insert items
	if len(items) > 0 {
		if err := r.AddItems(ctx, db, ret.CompanyID, ret.ReturnID, items); err != nil {
			return err
		}
	}
	return nil
}

func (r *returnRepository) GetByID(ctx context.Context, db DBTX, companyID, returnID uuid.UUID) (*models.Return, error) {
	query := `
		SELECT 
			return_id, company_id, order_id, invoice_id, credit_note_id,
			return_number, return_date, reason, status, total_refund,
			approved_at, completed_at, created_at, updated_at, created_by, updated_by
		FROM sales.returns
		WHERE company_id = $1 AND return_id = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, returnID)
	return r.scanReturn(row)
}

func (r *returnRepository) GetByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, returnNumber string) (*models.Return, error) {
	query := `
		SELECT 
			return_id, company_id, order_id, invoice_id, credit_note_id,
			return_number, return_date, reason, status, total_refund,
			approved_at, completed_at, created_at, updated_at, created_by, updated_by
		FROM sales.returns
		WHERE company_id = $1 AND return_number = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, returnNumber)
	return r.scanReturn(row)
}

func (r *returnRepository) Update(ctx context.Context, db DBTX, ret *models.Return) error {
	query := `
		UPDATE sales.returns SET
			order_id = $3,
			invoice_id = $4,
			credit_note_id = $5,
			return_number = $6,
			return_date = $7,
			reason = $8,
			status = $9,
			total_refund = $10,
			approved_at = $11,
			completed_at = $12,
			updated_at = NOW(),
			updated_by = $13
		WHERE return_id = $1 AND company_id = $2
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		ret.ReturnID, ret.CompanyID,
		ret.OrderID,
		r.nullUUIDParam(ret.InvoiceID),
		r.nullUUIDParam(ret.CreditNoteID),
		ret.ReturnNumber,
		ret.ReturnDate,
		ret.Reason,
		ret.Status,
		ret.TotalRefund,
		ret.ApprovedAt,
		ret.CompletedAt,
		r.nullUUIDParam(ret.UpdatedBy),
	).Scan(&ret.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return salesErrors.ErrNotFound
		}
		return fmt.Errorf("update return: %w", err)
	}
	return nil
}

func (r *returnRepository) Delete(ctx context.Context, db DBTX, companyID, returnID uuid.UUID) error {
	query := `DELETE FROM sales.returns WHERE company_id = $1 AND return_id = $2`
	result, err := db.ExecContext(ctx, query, companyID, returnID)
	if err != nil {
		return fmt.Errorf("delete return: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

// -------------------------------------------------------------------------
// Return Items
// -------------------------------------------------------------------------

func (r *returnRepository) AddItems(ctx context.Context, db DBTX, companyID, returnID uuid.UUID, items []*models.ReturnItem) error {
	if len(items) == 0 {
		return nil
	}
	// Note: company_id is not stored in return_items table, but we can verify ownership via return.
	// We'll rely on the caller to ensure the return belongs to the company.
	query := `
		INSERT INTO sales.return_items (
			return_item_id, return_id, order_item_id, product_id,
			product_name_snapshot, quantity, unit_price, refund_amount, reason, created_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), $10)
	`
	for _, it := range items {
		_, err := db.ExecContext(ctx, query,
			it.ReturnItemID, returnID,
			r.nullUUIDParam(it.OrderItemID),
			it.ProductID,
			it.ProductNameSnapshot,
			it.Quantity, it.UnitPrice, it.RefundAmount,
			it.Reason,
			r.nullUUIDParam(it.CreatedBy),
		)
		if err != nil {
			return fmt.Errorf("add return item: %w", err)
		}
	}
	return nil
}

func (r *returnRepository) ReplaceItems(ctx context.Context, db DBTX, companyID, returnID uuid.UUID, items []*models.ReturnItem) error {
	// Delete all existing items
	if err := r.DeleteItem(ctx, db, companyID, returnID, uuid.Nil); err != nil && err != salesErrors.ErrNotFound {
		return err
	}
	// Add new items
	if len(items) > 0 {
		return r.AddItems(ctx, db, companyID, returnID, items)
	}
	return nil
}

func (r *returnRepository) DeleteItem(ctx context.Context, db DBTX, companyID, returnID, returnItemID uuid.UUID) error {
	var query string
	var args []interface{}
	if returnItemID != uuid.Nil {
		query = `DELETE FROM sales.return_items WHERE return_item_id = $1 AND return_id = $2`
		args = []interface{}{returnItemID, returnID}
	} else {
		// Delete all items for the return
		query = `DELETE FROM sales.return_items WHERE return_id = $1`
		args = []interface{}{returnID}
	}
	result, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("delete return item(s): %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 && returnItemID != uuid.Nil {
		return salesErrors.ErrNotFound
	}
	return nil
}

func (r *returnRepository) GetItems(ctx context.Context, db DBTX, companyID, returnID uuid.UUID) ([]*models.ReturnItem, error) {
	// Join with returns to ensure company_id matches (for multi-tenant)
	query := `
		SELECT 
			ri.return_item_id, ri.return_id, ri.order_item_id, ri.product_id,
			ri.product_name_snapshot, ri.quantity, ri.unit_price, ri.refund_amount,
			ri.reason, ri.created_at, ri.created_by
		FROM sales.return_items ri
		JOIN sales.returns r ON ri.return_id = r.return_id
		WHERE r.company_id = $1 AND ri.return_id = $2
		ORDER BY ri.created_at
	`
	rows, err := db.QueryContext(ctx, query, companyID, returnID)
	if err != nil {
		return nil, fmt.Errorf("get return items: %w", err)
	}
	defer rows.Close()
	var result []*models.ReturnItem
	for rows.Next() {
		it, err := r.scanReturnItem(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, it)
	}
	return result, rows.Err()
}

func (r *returnRepository) GetItemByID(ctx context.Context, db DBTX, companyID, returnID, returnItemID uuid.UUID) (*models.ReturnItem, error) {
	query := `
		SELECT 
			ri.return_item_id, ri.return_id, ri.order_item_id, ri.product_id,
			ri.product_name_snapshot, ri.quantity, ri.unit_price, ri.refund_amount,
			ri.reason, ri.created_at, ri.created_by
		FROM sales.return_items ri
		JOIN sales.returns r ON ri.return_id = r.return_id
		WHERE r.company_id = $1 AND ri.return_item_id = $2 AND ri.return_id = $3
	`
	row := db.QueryRowContext(ctx, query, companyID, returnItemID, returnID)
	return r.scanReturnItem(row)
}

func (r *returnRepository) ExistsItem(ctx context.Context, db DBTX, companyID, returnID, returnItemID uuid.UUID) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(
			SELECT 1 FROM sales.return_items ri
			JOIN sales.returns r ON ri.return_id = r.return_id
			WHERE r.company_id = $1 AND ri.return_item_id = $2 AND ri.return_id = $3
		)
	`
	err := db.QueryRowContext(ctx, query, companyID, returnItemID, returnID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists item: %w", err)
	}
	return exists, nil
}

// -------------------------------------------------------------------------
// Totals / Refunds
// -------------------------------------------------------------------------

func (r *returnRepository) RecalculateRefundTotal(ctx context.Context, db DBTX, companyID, returnID uuid.UUID) error {
	query := `
		UPDATE sales.returns
		SET total_refund = COALESCE(
			(SELECT SUM(refund_amount) FROM sales.return_items WHERE return_id = $2),
			0
		),
		updated_at = NOW()
		WHERE company_id = $1 AND return_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, returnID)
	if err != nil {
		return fmt.Errorf("recalculate refund total: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

func (r *returnRepository) GetRefundTotal(ctx context.Context, db DBTX, companyID, returnID uuid.UUID) (decimal.Decimal, error) {
	var total decimal.Decimal
	query := `SELECT total_refund FROM sales.returns WHERE company_id = $1 AND return_id = $2`
	err := db.QueryRowContext(ctx, query, companyID, returnID).Scan(&total)
	if err != nil {
		if err == sql.ErrNoRows {
			return decimal.Zero, salesErrors.ErrNotFound
		}
		return decimal.Zero, fmt.Errorf("get refund total: %w", err)
	}
	return total, nil
}

func (r *returnRepository) UpdateRefundTotal(ctx context.Context, db DBTX, companyID, returnID uuid.UUID, totalRefund decimal.Decimal, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.returns
		SET total_refund = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND return_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, returnID, totalRefund, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("update refund total: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

// -------------------------------------------------------------------------
// Status / Lifecycle
// -------------------------------------------------------------------------

func (r *returnRepository) UpdateStatus(ctx context.Context, db DBTX, companyID, returnID uuid.UUID, status enums.ReturnStatus, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.returns
		SET status = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND return_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, returnID, status.String(), r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("update status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

func (r *returnRepository) Approve(ctx context.Context, db DBTX, companyID, returnID uuid.UUID, approvedAt time.Time, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.returns
		SET status = 'approved', approved_at = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND return_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, returnID, approvedAt, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("approve return: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

func (r *returnRepository) Complete(ctx context.Context, db DBTX, companyID, returnID uuid.UUID, completedAt time.Time, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.returns
		SET status = 'completed', completed_at = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND return_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, returnID, completedAt, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("complete return: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

func (r *returnRepository) Reject(ctx context.Context, db DBTX, companyID, returnID uuid.UUID, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.returns
		SET status = 'rejected', updated_at = NOW(), updated_by = $3
		WHERE company_id = $1 AND return_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, returnID, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("reject return: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

// -------------------------------------------------------------------------
// Credit Note / Invoice Linking
// -------------------------------------------------------------------------

func (r *returnRepository) SetCreditNote(ctx context.Context, db DBTX, companyID, returnID uuid.UUID, creditNoteID *uuid.UUID, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.returns
		SET credit_note_id = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND return_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, returnID, r.nullUUIDParam(creditNoteID), r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("set credit note: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

func (r *returnRepository) GetCreditNote(ctx context.Context, db DBTX, companyID, returnID uuid.UUID) (*models.Invoice, error) {
	// This requires joining with sales.invoices
	query := `
		SELECT 
			i.invoice_id, i.company_id, i.order_id, i.customer_id,
			i.invoice_number, i.external_ref, i.invoice_date, i.due_date,
			i.status, i.currency, i.exchange_rate, i.subtotal,
			i.discount_total, i.tax_total, i.amount_paid, i.amount_due,
			i.notes, i.is_locked, i.issued_at, i.paid_at, i.cancelled_at,
			i.created_at, i.updated_at, i.created_by, i.updated_by
		FROM sales.returns r
		JOIN sales.invoices i ON r.credit_note_id = i.invoice_id
		WHERE r.company_id = $1 AND r.return_id = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, returnID)
	// We need an invoice scanner; reuse from invoice repository's scanInvoice (if available) or implement inline.
	// For simplicity, we'll implement a direct scan here.
	var inv models.Invoice
	var exchangeRate sql.NullString
	var orderID, createdBy, updatedBy uuid.NullUUID
	var externalRef, notes sql.NullString
	var issuedAt, paidAt, cancelledAt sql.NullTime
	err := row.Scan(
		&inv.InvoiceID, &inv.CompanyID, &orderID, &inv.CustomerID,
		&inv.InvoiceNumber, &externalRef, &inv.InvoiceDate, &inv.DueDate,
		&inv.Status, &inv.Currency, &exchangeRate, &inv.Subtotal,
		&inv.DiscountTotal, &inv.TaxTotal, &inv.AmountPaid, &inv.AmountDue,
		&notes, &inv.IsLocked, &issuedAt, &paidAt, &cancelledAt,
		&inv.CreatedAt, &inv.UpdatedAt, &createdBy, &updatedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, salesErrors.ErrNotFound
		}
		return nil, fmt.Errorf("get credit note: %w", err)
	}
	if orderID.Valid {
		inv.OrderID = &orderID.UUID
	}
	if externalRef.Valid {
		inv.ExternalRef = &externalRef.String
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
	if exchangeRate.Valid {
		rate, err := decimal.NewFromString(exchangeRate.String)
		if err == nil {
			inv.ExchangeRate = &rate
		}
	}
	return &inv, nil
}

// -------------------------------------------------------------------------
// Existence / Validation
// -------------------------------------------------------------------------

func (r *returnRepository) Exists(ctx context.Context, db DBTX, companyID, returnID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.returns WHERE company_id = $1 AND return_id = $2)`
	err := db.QueryRowContext(ctx, query, companyID, returnID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists return: %w", err)
	}
	return exists, nil
}

func (r *returnRepository) ExistsByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, returnNumber string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.returns WHERE company_id = $1 AND return_number = $2)`
	err := db.QueryRowContext(ctx, query, companyID, returnNumber).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists by number: %w", err)
	}
	return exists, nil
}

func (r *returnRepository) ExistsByOrder(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.returns WHERE company_id = $1 AND order_id = $2)`
	err := db.QueryRowContext(ctx, query, companyID, orderID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists by order: %w", err)
	}
	return exists, nil
}

func (r *returnRepository) HasCreditNote(ctx context.Context, db DBTX, companyID, returnID uuid.UUID) (bool, error) {
	var has bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.returns WHERE company_id = $1 AND return_id = $2 AND credit_note_id IS NOT NULL)`
	err := db.QueryRowContext(ctx, query, companyID, returnID).Scan(&has)
	if err != nil {
		return false, fmt.Errorf("has credit note: %w", err)
	}
	return has, nil
}

// -------------------------------------------------------------------------
// Order / Invoice Relations
// -------------------------------------------------------------------------

func (r *returnRepository) GetByOrder(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) ([]*models.Return, error) {
	query := `
		SELECT 
			return_id, company_id, order_id, invoice_id, credit_note_id,
			return_number, return_date, reason, status, total_refund,
			approved_at, completed_at, created_at, updated_at, created_by, updated_by
		FROM sales.returns
		WHERE company_id = $1 AND order_id = $2
		ORDER BY return_date DESC
	`
	rows, err := db.QueryContext(ctx, query, companyID, orderID)
	if err != nil {
		return nil, fmt.Errorf("get returns by order: %w", err)
	}
	defer rows.Close()
	var result []*models.Return
	for rows.Next() {
		ret, err := r.scanReturn(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, ret)
	}
	return result, rows.Err()
}

func (r *returnRepository) GetByInvoice(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) ([]*models.Return, error) {
	query := `
		SELECT 
			return_id, company_id, order_id, invoice_id, credit_note_id,
			return_number, return_date, reason, status, total_refund,
			approved_at, completed_at, created_at, updated_at, created_by, updated_by
		FROM sales.returns
		WHERE company_id = $1 AND invoice_id = $2
		ORDER BY return_date DESC
	`
	rows, err := db.QueryContext(ctx, query, companyID, invoiceID)
	if err != nil {
		return nil, fmt.Errorf("get returns by invoice: %w", err)
	}
	defer rows.Close()
	var result []*models.Return
	for rows.Next() {
		ret, err := r.scanReturn(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, ret)
	}
	return result, rows.Err()
}

func (r *returnRepository) GetPendingReturns(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Return, error) {
	query := `
		SELECT 
			return_id, company_id, order_id, invoice_id, credit_note_id,
			return_number, return_date, reason, status, total_refund,
			approved_at, completed_at, created_at, updated_at, created_by, updated_by
		FROM sales.returns
		WHERE company_id = $1 AND status = 'pending'
		ORDER BY return_date ASC
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("get pending returns: %w", err)
	}
	defer rows.Close()
	var result []*models.Return
	for rows.Next() {
		ret, err := r.scanReturn(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, ret)
	}
	return result, rows.Err()
}

func (r *returnRepository) GetApprovedReturns(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Return, error) {
	query := `
		SELECT 
			return_id, company_id, order_id, invoice_id, credit_note_id,
			return_number, return_date, reason, status, total_refund,
			approved_at, completed_at, created_at, updated_at, created_by, updated_by
		FROM sales.returns
		WHERE company_id = $1 AND status = 'approved'
		ORDER BY approved_at ASC
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("get approved returns: %w", err)
	}
	defer rows.Close()
	var result []*models.Return
	for rows.Next() {
		ret, err := r.scanReturn(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, ret)
	}
	return result, rows.Err()
}

func (r *returnRepository) GetCompletedReturns(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Return, error) {
	query := `
		SELECT 
			return_id, company_id, order_id, invoice_id, credit_note_id,
			return_number, return_date, reason, status, total_refund,
			approved_at, completed_at, created_at, updated_at, created_by, updated_by
		FROM sales.returns
		WHERE company_id = $1 AND status = 'completed'
		ORDER BY completed_at DESC
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("get completed returns: %w", err)
	}
	defer rows.Close()
	var result []*models.Return
	for rows.Next() {
		ret, err := r.scanReturn(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, ret)
	}
	return result, rows.Err()
}

// -------------------------------------------------------------------------
// Listing & Searching
// -------------------------------------------------------------------------

func (r *returnRepository) List(ctx context.Context, db DBTX, filter ReturnFilter, p Pagination, s Sort) ([]*models.Return, int64, error) {
	where, args := r.buildReturnFilter(filter)
	if where == "" {
		return nil, 0, fmt.Errorf("list requires at least company_id filter")
	}
	allowedSort := map[string]bool{
		"return_number": true,
		"return_date":   true,
		"status":        true,
		"total_refund":  true,
		"created_at":    true,
		"updated_at":    true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY return_date DESC"
	}
	limit, offset := r.validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sales.returns %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count returns: %w", err)
	}
	if total == 0 {
		return []*models.Return{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT 
			return_id, company_id, order_id, invoice_id, credit_note_id,
			return_number, return_date, reason, status, total_refund,
			approved_at, completed_at, created_at, updated_at, created_by, updated_by
		FROM sales.returns
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list returns: %w", err)
	}
	defer rows.Close()
	var result []*models.Return
	for rows.Next() {
		ret, err := r.scanReturn(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, ret)
	}
	return result, total, rows.Err()
}

func (r *returnRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, queryStr string, limit, offset int) ([]*models.Return, int64, error) {
	searchPattern := "%" + queryStr + "%"
	baseArgs := []interface{}{companyID, searchPattern, searchPattern}
	countQuery := `
		SELECT COUNT(*)
		FROM sales.returns
		WHERE company_id = $1
		AND (return_number ILIKE $2 OR reason ILIKE $3)
	`
	var total int64
	err := db.QueryRowContext(ctx, countQuery, baseArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search returns count: %w", err)
	}
	if total == 0 {
		return []*models.Return{}, 0, nil
	}

	dataQuery := `
		SELECT 
			return_id, company_id, order_id, invoice_id, credit_note_id,
			return_number, return_date, reason, status, total_refund,
			approved_at, completed_at, created_at, updated_at, created_by, updated_by
		FROM sales.returns
		WHERE company_id = $1
		AND (return_number ILIKE $2 OR reason ILIKE $3)
		ORDER BY return_date DESC
		LIMIT $4 OFFSET $5
	`
	args := append(baseArgs, limit, offset)
	rows, err := db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search returns data: %w", err)
	}
	defer rows.Close()
	var result []*models.Return
	for rows.Next() {
		ret, err := r.scanReturn(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, ret)
	}
	return result, total, rows.Err()
}

// -------------------------------------------------------------------------
// Analytics / Reporting
// -------------------------------------------------------------------------

func (r *returnRepository) GetTotalRefundedAmount(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	var conds []string
	var args []interface{}
	idx := 1
	conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
	args = append(args, companyID)
	idx++
	conds = append(conds, "status IN ('approved','completed')")
	if from != nil {
		conds = append(conds, fmt.Sprintf("return_date >= $%d", idx))
		args = append(args, *from)
		idx++
	}
	if to != nil {
		conds = append(conds, fmt.Sprintf("return_date <= $%d", idx))
		args = append(args, *to)
		idx++
	}
	where := strings.Join(conds, " AND ")
	query := fmt.Sprintf("SELECT COALESCE(SUM(total_refund), 0) FROM sales.returns WHERE %s", where)
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get total refunded amount: %w", err)
	}
	return total, nil
}

func (r *returnRepository) GetReturnRate(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	// Return rate = total refunded value / total invoiced value (in the same period)
	// We need to sum invoice grand_total for the period (excluding cancelled invoices)
	var invoicedTotal decimal.Decimal
	invConds := []string{"company_id = $1", "status != 'cancelled'"}
	invArgs := []interface{}{companyID}
	idx := 2
	if from != nil {
		invConds = append(invConds, fmt.Sprintf("invoice_date >= $%d", idx))
		invArgs = append(invArgs, *from)
		idx++
	}
	if to != nil {
		invConds = append(invConds, fmt.Sprintf("invoice_date <= $%d", idx))
		invArgs = append(invArgs, *to)
		idx++
	}
	invQuery := fmt.Sprintf("SELECT COALESCE(SUM(grand_total), 0) FROM sales.invoices WHERE %s", strings.Join(invConds, " AND "))
	err := db.QueryRowContext(ctx, invQuery, invArgs...).Scan(&invoicedTotal)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get invoiced total for return rate: %w", err)
	}
	if invoicedTotal.IsZero() {
		return decimal.Zero, nil
	}
	refundTotal, err := r.GetTotalRefundedAmount(ctx, db, companyID, from, to)
	if err != nil {
		return decimal.Zero, err
	}
	rate := refundTotal.Div(invoicedTotal)
	return rate, nil
}

func (r *returnRepository) GetTopReturnedProducts(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.Product, error) {
	// Build conditions for return_items joined with returns
	var conds []string
	var args []interface{}
	idx := 1
	conds = append(conds, fmt.Sprintf("r.company_id = $%d", idx))
	args = append(args, companyID)
	idx++
	conds = append(conds, "r.status IN ('approved','completed')")
	if from != nil {
		conds = append(conds, fmt.Sprintf("r.return_date >= $%d", idx))
		args = append(args, *from)
		idx++
	}
	if to != nil {
		conds = append(conds, fmt.Sprintf("r.return_date <= $%d", idx))
		args = append(args, *to)
		idx++
	}
	where := strings.Join(conds, " AND ")

	query := fmt.Sprintf(`
		SELECT 
			p.product_id, p.company_id, p.sku, p.name, p.description,
			p.unit_price, p.is_active, p.inventory_item_id,
			p.created_at, p.updated_at, p.created_by, p.updated_by,
			SUM(ri.quantity) as total_returned_qty
		FROM sales.return_items ri
		JOIN sales.returns r ON ri.return_id = r.return_id
		JOIN sales.products p ON ri.product_id = p.product_id
		WHERE %s
		GROUP BY p.product_id
		ORDER BY total_returned_qty DESC
		LIMIT $%d
	`, where, idx)
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get top returned products: %w", err)
	}
	defer rows.Close()
	var result []*models.Product
	for rows.Next() {
		var prod models.Product
		var totalReturnedQty decimal.Decimal
		err := rows.Scan(
			&prod.ProductID, &prod.CompanyID, &prod.SKU, &prod.Name,
			&prod.Description, &prod.UnitPrice, &prod.IsActive, &prod.InventoryItemID,
			&prod.CreatedAt, &prod.UpdatedAt, &prod.CreatedBy, &prod.UpdatedBy,
			&totalReturnedQty,
		)
		if err != nil {
			return nil, fmt.Errorf("scan top returned product: %w", err)
		}
		// The total quantity is not part of Product model, but we ignore it for now.
		result = append(result, &prod)
	}
	return result, rows.Err()
}

func (r *returnRepository) GetReturnsWithoutCreditNotes(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Return, error) {
	query := `
		SELECT 
			return_id, company_id, order_id, invoice_id, credit_note_id,
			return_number, return_date, reason, status, total_refund,
			approved_at, completed_at, created_at, updated_at, created_by, updated_by
		FROM sales.returns
		WHERE company_id = $1 AND status = 'approved' AND credit_note_id IS NULL
		ORDER BY return_date ASC
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("get returns without credit notes: %w", err)
	}
	defer rows.Close()
	var result []*models.Return
	for rows.Next() {
		ret, err := r.scanReturn(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, ret)
	}
	return result, rows.Err()
}

// -------------------------------------------------------------------------
// Concurrency / Locking
// -------------------------------------------------------------------------

func (r *returnRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, returnID uuid.UUID) (*models.Return, error) {
	query := `
		SELECT 
			return_id, company_id, order_id, invoice_id, credit_note_id,
			return_number, return_date, reason, status, total_refund,
			approved_at, completed_at, created_at, updated_at, created_by, updated_by
		FROM sales.returns
		WHERE company_id = $1 AND return_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, companyID, returnID)
	return r.scanReturn(row)
}

func (r *returnRepository) GetItemByIDForUpdate(ctx context.Context, db DBTX, companyID, returnID, returnItemID uuid.UUID) (*models.ReturnItem, error) {
	query := `
		SELECT 
			ri.return_item_id, ri.return_id, ri.order_item_id, ri.product_id,
			ri.product_name_snapshot, ri.quantity, ri.unit_price, ri.refund_amount,
			ri.reason, ri.created_at, ri.created_by
		FROM sales.return_items ri
		JOIN sales.returns r ON ri.return_id = r.return_id
		WHERE r.company_id = $1 AND ri.return_item_id = $2 AND ri.return_id = $3
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, companyID, returnItemID, returnID)
	return r.scanReturnItem(row)
}
