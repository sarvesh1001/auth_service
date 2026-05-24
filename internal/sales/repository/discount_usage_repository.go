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
	"auth-service/internal/sales/models/discount"
)

// -------------------------------------------------------------------------
// Interface (unchanged – but all methods now expect/use company_id)
// -------------------------------------------------------------------------

type DiscountUsageRepository interface {
	Create(ctx context.Context, db DBTX, application *discount.DiscountApplication) error
	BulkCreate(ctx context.Context, db DBTX, applications []*discount.DiscountApplication) error
	GetByID(ctx context.Context, db DBTX, applicationID uuid.UUID) (*discount.DiscountApplication, error)
	Delete(ctx context.Context, db DBTX, applicationID uuid.UUID) error
	DeleteByOrder(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) error
	DeleteByInvoice(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) error

	Exists(ctx context.Context, db DBTX, applicationID uuid.UUID) (bool, error)
	ExistsForOrder(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) (bool, error)
	ExistsForInvoice(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) (bool, error)

	GetByOrder(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) ([]*discount.DiscountApplication, error)
	GetByInvoice(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) ([]*discount.DiscountApplication, error)

	GetByDiscountID(ctx context.Context, db DBTX, discountID uuid.UUID) ([]*discount.DiscountApplication, error)
	GetByAutoDiscountID(ctx context.Context, db DBTX, autoDiscountID uuid.UUID) ([]*discount.DiscountApplication, error)
	GetByDiscountName(ctx context.Context, db DBTX, companyID uuid.UUID, discountName string) ([]*discount.DiscountApplication, error)

	GetTotalDiscountForOrder(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) (decimal.Decimal, error)
	GetTotalDiscountForInvoice(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) (decimal.Decimal, error)
	GetTotalDiscountByDiscountID(ctx context.Context, db DBTX, discountID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetTotalDiscountByAutoDiscountID(ctx context.Context, db DBTX, autoDiscountID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetTotalDiscountAmount(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)

	GetTopDiscountsByUsage(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*DiscountUsageAggregate, error)
	GetTopDiscountsByAmount(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*DiscountAmountAggregate, error)
	GetAverageDiscountAmount(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)

	List(ctx context.Context, db DBTX, filter DiscountUsageFilter, p Pagination, s Sort) ([]*discount.DiscountApplication, int64, error)

	GetByIDForUpdate(ctx context.Context, db DBTX, applicationID uuid.UUID) (*discount.DiscountApplication, error)
}

// -------------------------------------------------------------------------
// Filters & Aggregates (unchanged)
// -------------------------------------------------------------------------

type DiscountUsageFilter struct {
	CompanyID uuid.UUID

	OrderID   *uuid.UUID
	InvoiceID *uuid.UUID

	ApplicationIDs []uuid.UUID

	DiscountID     *uuid.UUID
	AutoDiscountID *uuid.UUID
	DiscountType   *string
	DiscountName   *string

	MinAmount *decimal.Decimal
	MaxAmount *decimal.Decimal

	CreatedFrom *time.Time
	CreatedTo   *time.Time
}

type DiscountUsageAggregate struct {
	DiscountID     *uuid.UUID
	AutoDiscountID *uuid.UUID
	DiscountName   *string
	UsageCount     int64
	TotalAmount    decimal.Decimal
}

type DiscountAmountAggregate struct {
	DiscountID     *uuid.UUID
	AutoDiscountID *uuid.UUID
	DiscountName   *string
	TotalAmount    decimal.Decimal
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type discountUsageRepository struct {
	logger *zap.Logger
}

func NewDiscountUsageRepository(logger *zap.Logger) DiscountUsageRepository {
	return &discountUsageRepository{
		logger: logger.Named("sales_discount_usage_repo"),
	}
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

func (r *discountUsageRepository) nullUUIDParam(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func (r *discountUsageRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *discountUsageRepository) validatePagination(p Pagination) (int, int) {
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

func (r *discountUsageRepository) buildFilter(filter DiscountUsageFilter) (string, []interface{}) {
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
	if len(filter.ApplicationIDs) > 0 {
		placeholders := make([]string, len(filter.ApplicationIDs))
		for i, id := range filter.ApplicationIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("application_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.DiscountID != nil {
		conds = append(conds, fmt.Sprintf("discount_id = $%d", idx))
		args = append(args, *filter.DiscountID)
		idx++
	}
	if filter.AutoDiscountID != nil {
		conds = append(conds, fmt.Sprintf("auto_discount_id = $%d", idx))
		args = append(args, *filter.AutoDiscountID)
		idx++
	}
	if filter.DiscountType != nil {
		conds = append(conds, fmt.Sprintf("discount_type = $%d", idx))
		args = append(args, *filter.DiscountType)
		idx++
	}
	if filter.DiscountName != nil {
		conds = append(conds, fmt.Sprintf("discount_name ILIKE $%d", idx))
		args = append(args, "%"+*filter.DiscountName+"%")
		idx++
	}
	if filter.MinAmount != nil {
		conds = append(conds, fmt.Sprintf("amount >= $%d", idx))
		args = append(args, *filter.MinAmount)
		idx++
	}
	if filter.MaxAmount != nil {
		conds = append(conds, fmt.Sprintf("amount <= $%d", idx))
		args = append(args, *filter.MaxAmount)
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

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// scanDiscountApplication now includes company_id
func (r *discountUsageRepository) scanDiscountApplication(s scanner) (*discount.DiscountApplication, error) {
	var d discount.DiscountApplication
	var orderID, invoiceID, discountID, autoDiscountID uuid.NullUUID

	err := s.Scan(
		&d.ApplicationID,
		&d.CompanyID,
		&orderID,
		&invoiceID,
		&d.DiscountType,
		&discountID,
		&autoDiscountID,
		&d.DiscountName,
		&d.Amount,
		&d.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, salesErrors.ErrNotFound
		}
		return nil, fmt.Errorf("scan discount application: %w", err)
	}

	if orderID.Valid {
		d.OrderID = &orderID.UUID
	}
	if invoiceID.Valid {
		d.InvoiceID = &invoiceID.UUID
	}
	if discountID.Valid {
		d.DiscountID = &discountID.UUID
	}
	if autoDiscountID.Valid {
		d.AutoDiscountID = &autoDiscountID.UUID
	}
	return &d, nil
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (r *discountUsageRepository) Create(ctx context.Context, db DBTX, application *discount.DiscountApplication) error {
	query := `
		INSERT INTO sales.discount_applications (
			application_id, company_id, order_id, invoice_id, discount_type,
			discount_id, auto_discount_id, discount_name, amount, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
		RETURNING created_at
	`
	err := db.QueryRowContext(ctx, query,
		application.ApplicationID,
		application.CompanyID,
		r.nullUUIDParam(application.OrderID),
		r.nullUUIDParam(application.InvoiceID),
		application.DiscountType,
		r.nullUUIDParam(application.DiscountID),
		r.nullUUIDParam(application.AutoDiscountID),
		application.DiscountName,
		application.Amount,
	).Scan(&application.CreatedAt)
	if err != nil {
		r.logger.Error("failed to create discount application", zap.Error(err))
		return fmt.Errorf("create discount application: %w", err)
	}
	return nil
}

func (r *discountUsageRepository) BulkCreate(ctx context.Context, db DBTX, applications []*discount.DiscountApplication) error {
	if len(applications) == 0 {
		return nil
	}
	valueStrings := make([]string, 0, len(applications))
	args := make([]interface{}, 0, len(applications)*9)
	idx := 1
	for _, app := range applications {
		valueStrings = append(valueStrings, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, NOW())",
			idx, idx+1, idx+2, idx+3, idx+4, idx+5, idx+6, idx+7, idx+8))
		args = append(args,
			app.ApplicationID,
			app.CompanyID,
			r.nullUUIDParam(app.OrderID),
			r.nullUUIDParam(app.InvoiceID),
			app.DiscountType,
			r.nullUUIDParam(app.DiscountID),
			r.nullUUIDParam(app.AutoDiscountID),
			app.DiscountName,
			app.Amount,
		)
		idx += 9
	}
	query := fmt.Sprintf(`
		INSERT INTO sales.discount_applications (
			application_id, company_id, order_id, invoice_id, discount_type,
			discount_id, auto_discount_id, discount_name, amount, created_at
		) VALUES %s
	`, strings.Join(valueStrings, ","))
	_, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to bulk create discount applications", zap.Error(err))
		return fmt.Errorf("bulk create discount applications: %w", err)
	}
	return nil
}

func (r *discountUsageRepository) GetByID(ctx context.Context, db DBTX, applicationID uuid.UUID) (*discount.DiscountApplication, error) {
	query := `
		SELECT application_id, company_id, order_id, invoice_id, discount_type,
			discount_id, auto_discount_id, discount_name, amount, created_at
		FROM sales.discount_applications
		WHERE application_id = $1
	`
	row := db.QueryRowContext(ctx, query, applicationID)
	return r.scanDiscountApplication(row)
}

func (r *discountUsageRepository) Delete(ctx context.Context, db DBTX, applicationID uuid.UUID) error {
	query := `DELETE FROM sales.discount_applications WHERE application_id = $1`
	result, err := db.ExecContext(ctx, query, applicationID)
	if err != nil {
		return fmt.Errorf("delete discount application: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

func (r *discountUsageRepository) DeleteByOrder(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) error {
	query := `DELETE FROM sales.discount_applications WHERE order_id = $1 AND company_id = $2`
	_, err := db.ExecContext(ctx, query, orderID, companyID)
	if err != nil {
		return fmt.Errorf("delete by order: %w", err)
	}
	return nil
}

func (r *discountUsageRepository) DeleteByInvoice(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) error {
	query := `DELETE FROM sales.discount_applications WHERE invoice_id = $1 AND company_id = $2`
	_, err := db.ExecContext(ctx, query, invoiceID, companyID)
	if err != nil {
		return fmt.Errorf("delete by invoice: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Existence / Validation
// -------------------------------------------------------------------------

func (r *discountUsageRepository) Exists(ctx context.Context, db DBTX, applicationID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.discount_applications WHERE application_id = $1)`
	err := db.QueryRowContext(ctx, query, applicationID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists: %w", err)
	}
	return exists, nil
}

func (r *discountUsageRepository) ExistsForOrder(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.discount_applications WHERE order_id = $1 AND company_id = $2)`
	err := db.QueryRowContext(ctx, query, orderID, companyID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists for order: %w", err)
	}
	return exists, nil
}

func (r *discountUsageRepository) ExistsForInvoice(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.discount_applications WHERE invoice_id = $1 AND company_id = $2)`
	err := db.QueryRowContext(ctx, query, invoiceID, companyID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists for invoice: %w", err)
	}
	return exists, nil
}

// -------------------------------------------------------------------------
// Lookups by Order / Invoice
// -------------------------------------------------------------------------

func (r *discountUsageRepository) GetByOrder(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) ([]*discount.DiscountApplication, error) {
	query := `
		SELECT application_id, company_id, order_id, invoice_id, discount_type,
			discount_id, auto_discount_id, discount_name, amount, created_at
		FROM sales.discount_applications
		WHERE company_id = $1 AND order_id = $2
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, companyID, orderID)
	if err != nil {
		return nil, fmt.Errorf("get by order: %w", err)
	}
	defer rows.Close()
	var result []*discount.DiscountApplication
	for rows.Next() {
		d, err := r.scanDiscountApplication(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, d)
	}
	return result, rows.Err()
}

func (r *discountUsageRepository) GetByInvoice(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) ([]*discount.DiscountApplication, error) {
	query := `
		SELECT application_id, company_id, order_id, invoice_id, discount_type,
			discount_id, auto_discount_id, discount_name, amount, created_at
		FROM sales.discount_applications
		WHERE company_id = $1 AND invoice_id = $2
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, companyID, invoiceID)
	if err != nil {
		return nil, fmt.Errorf("get by invoice: %w", err)
	}
	defer rows.Close()
	var result []*discount.DiscountApplication
	for rows.Next() {
		d, err := r.scanDiscountApplication(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, d)
	}
	return result, rows.Err()
}

// -------------------------------------------------------------------------
// Lookups by Discount ID / Name
// -------------------------------------------------------------------------

func (r *discountUsageRepository) GetByDiscountID(ctx context.Context, db DBTX, discountID uuid.UUID) ([]*discount.DiscountApplication, error) {
	query := `
		SELECT application_id, company_id, order_id, invoice_id, discount_type,
			discount_id, auto_discount_id, discount_name, amount, created_at
		FROM sales.discount_applications
		WHERE discount_id = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, discountID)
	if err != nil {
		return nil, fmt.Errorf("get by discount id: %w", err)
	}
	defer rows.Close()
	var result []*discount.DiscountApplication
	for rows.Next() {
		d, err := r.scanDiscountApplication(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, d)
	}
	return result, rows.Err()
}

func (r *discountUsageRepository) GetByAutoDiscountID(ctx context.Context, db DBTX, autoDiscountID uuid.UUID) ([]*discount.DiscountApplication, error) {
	query := `
		SELECT application_id, company_id, order_id, invoice_id, discount_type,
			discount_id, auto_discount_id, discount_name, amount, created_at
		FROM sales.discount_applications
		WHERE auto_discount_id = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, autoDiscountID)
	if err != nil {
		return nil, fmt.Errorf("get by auto discount id: %w", err)
	}
	defer rows.Close()
	var result []*discount.DiscountApplication
	for rows.Next() {
		d, err := r.scanDiscountApplication(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, d)
	}
	return result, rows.Err()
}

func (r *discountUsageRepository) GetByDiscountName(ctx context.Context, db DBTX, companyID uuid.UUID, discountName string) ([]*discount.DiscountApplication, error) {
	query := `
		SELECT application_id, company_id, order_id, invoice_id, discount_type,
			discount_id, auto_discount_id, discount_name, amount, created_at
		FROM sales.discount_applications
		WHERE company_id = $1 AND discount_name ILIKE $2
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, companyID, "%"+discountName+"%")
	if err != nil {
		return nil, fmt.Errorf("get by discount name: %w", err)
	}
	defer rows.Close()
	var result []*discount.DiscountApplication
	for rows.Next() {
		d, err := r.scanDiscountApplication(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, d)
	}
	return result, rows.Err()
}

// -------------------------------------------------------------------------
// Financial / Totals
// -------------------------------------------------------------------------

func (r *discountUsageRepository) GetTotalDiscountForOrder(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) (decimal.Decimal, error) {
	query := `
		SELECT COALESCE(SUM(amount), 0)
		FROM sales.discount_applications
		WHERE company_id = $1 AND order_id = $2
	`
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, companyID, orderID).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("total discount for order: %w", err)
	}
	return total, nil
}

func (r *discountUsageRepository) GetTotalDiscountForInvoice(ctx context.Context, db DBTX, companyID, invoiceID uuid.UUID) (decimal.Decimal, error) {
	query := `
		SELECT COALESCE(SUM(amount), 0)
		FROM sales.discount_applications
		WHERE company_id = $1 AND invoice_id = $2
	`
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, companyID, invoiceID).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("total discount for invoice: %w", err)
	}
	return total, nil
}

func (r *discountUsageRepository) GetTotalDiscountByDiscountID(ctx context.Context, db DBTX, discountID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	query := `
		SELECT COALESCE(SUM(amount), 0)
		FROM sales.discount_applications
		WHERE discount_id = $1
	`
	args := []interface{}{discountID}
	idx := 2
	if from != nil {
		query += fmt.Sprintf(" AND created_at >= $%d", idx)
		args = append(args, *from)
		idx++
	}
	if to != nil {
		query += fmt.Sprintf(" AND created_at <= $%d", idx)
		args = append(args, *to)
	}
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("total discount by discount id: %w", err)
	}
	return total, nil
}

func (r *discountUsageRepository) GetTotalDiscountByAutoDiscountID(ctx context.Context, db DBTX, autoDiscountID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	query := `
		SELECT COALESCE(SUM(amount), 0)
		FROM sales.discount_applications
		WHERE auto_discount_id = $1
	`
	args := []interface{}{autoDiscountID}
	idx := 2
	if from != nil {
		query += fmt.Sprintf(" AND created_at >= $%d", idx)
		args = append(args, *from)
		idx++
	}
	if to != nil {
		query += fmt.Sprintf(" AND created_at <= $%d", idx)
		args = append(args, *to)
	}
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("total discount by auto discount id: %w", err)
	}
	return total, nil
}

func (r *discountUsageRepository) GetTotalDiscountAmount(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	query := `
		SELECT COALESCE(SUM(amount), 0)
		FROM sales.discount_applications
		WHERE company_id = $1
	`
	args := []interface{}{companyID}
	idx := 2
	if from != nil {
		query += fmt.Sprintf(" AND created_at >= $%d", idx)
		args = append(args, *from)
		idx++
	}
	if to != nil {
		query += fmt.Sprintf(" AND created_at <= $%d", idx)
		args = append(args, *to)
	}
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("total discount amount: %w", err)
	}
	return total, nil
}

// -------------------------------------------------------------------------
// Analytics / Reporting
// -------------------------------------------------------------------------

func (r *discountUsageRepository) GetTopDiscountsByUsage(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*DiscountUsageAggregate, error) {
	query := `
		SELECT 
			discount_id,
			auto_discount_id,
			discount_name,
			COUNT(*) as usage_count,
			COALESCE(SUM(amount), 0) as total_amount
		FROM sales.discount_applications
		WHERE company_id = $1
	`
	args := []interface{}{companyID}
	idx := 2
	if from != nil {
		query += fmt.Sprintf(" AND created_at >= $%d", idx)
		args = append(args, *from)
		idx++
	}
	if to != nil {
		query += fmt.Sprintf(" AND created_at <= $%d", idx)
		args = append(args, *to)
	}
	query += `
		GROUP BY discount_id, auto_discount_id, discount_name
		ORDER BY usage_count DESC
		LIMIT $` + fmt.Sprintf("%d", idx)
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get top discounts by usage: %w", err)
	}
	defer rows.Close()
	var result []*DiscountUsageAggregate
	for rows.Next() {
		var agg DiscountUsageAggregate
		var discountID, autoDiscountID uuid.NullUUID
		var discountName sql.NullString
		err := rows.Scan(&discountID, &autoDiscountID, &discountName, &agg.UsageCount, &agg.TotalAmount)
		if err != nil {
			return nil, err
		}
		if discountID.Valid {
			agg.DiscountID = &discountID.UUID
		}
		if autoDiscountID.Valid {
			agg.AutoDiscountID = &autoDiscountID.UUID
		}
		if discountName.Valid {
			agg.DiscountName = &discountName.String
		}
		result = append(result, &agg)
	}
	return result, rows.Err()
}

func (r *discountUsageRepository) GetTopDiscountsByAmount(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*DiscountAmountAggregate, error) {
	query := `
		SELECT 
			discount_id,
			auto_discount_id,
			discount_name,
			COALESCE(SUM(amount), 0) as total_amount
		FROM sales.discount_applications
		WHERE company_id = $1
	`
	args := []interface{}{companyID}
	idx := 2
	if from != nil {
		query += fmt.Sprintf(" AND created_at >= $%d", idx)
		args = append(args, *from)
		idx++
	}
	if to != nil {
		query += fmt.Sprintf(" AND created_at <= $%d", idx)
		args = append(args, *to)
	}
	query += `
		GROUP BY discount_id, auto_discount_id, discount_name
		ORDER BY total_amount DESC
		LIMIT $` + fmt.Sprintf("%d", idx)
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get top discounts by amount: %w", err)
	}
	defer rows.Close()
	var result []*DiscountAmountAggregate
	for rows.Next() {
		var agg DiscountAmountAggregate
		var discountID, autoDiscountID uuid.NullUUID
		var discountName sql.NullString
		err := rows.Scan(&discountID, &autoDiscountID, &discountName, &agg.TotalAmount)
		if err != nil {
			return nil, err
		}
		if discountID.Valid {
			agg.DiscountID = &discountID.UUID
		}
		if autoDiscountID.Valid {
			agg.AutoDiscountID = &autoDiscountID.UUID
		}
		if discountName.Valid {
			agg.DiscountName = &discountName.String
		}
		result = append(result, &agg)
	}
	return result, rows.Err()
}

func (r *discountUsageRepository) GetAverageDiscountAmount(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	query := `
		SELECT COALESCE(AVG(amount), 0)
		FROM sales.discount_applications
		WHERE company_id = $1
	`
	args := []interface{}{companyID}
	idx := 2
	if from != nil {
		query += fmt.Sprintf(" AND created_at >= $%d", idx)
		args = append(args, *from)
		idx++
	}
	if to != nil {
		query += fmt.Sprintf(" AND created_at <= $%d", idx)
		args = append(args, *to)
	}
	var avg decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&avg)
	if err != nil {
		return decimal.Zero, fmt.Errorf("average discount amount: %w", err)
	}
	return avg, nil
}

// -------------------------------------------------------------------------
// Listing / Filtering
// -------------------------------------------------------------------------

func (r *discountUsageRepository) List(ctx context.Context, db DBTX, filter DiscountUsageFilter, p Pagination, s Sort) ([]*discount.DiscountApplication, int64, error) {
	where, args := r.buildFilter(filter)
	if where == "" {
		return nil, 0, fmt.Errorf("list requires at least company_id filter")
	}
	allowedSort := map[string]bool{
		"amount":     true,
		"created_at": true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY created_at DESC"
	}
	limit, offset := r.validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sales.discount_applications %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count discount applications: %w", err)
	}
	if total == 0 {
		return []*discount.DiscountApplication{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT application_id, company_id, order_id, invoice_id, discount_type,
			discount_id, auto_discount_id, discount_name, amount, created_at
		FROM sales.discount_applications
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list discount applications: %w", err)
	}
	defer rows.Close()

	var result []*discount.DiscountApplication
	for rows.Next() {
		d, err := r.scanDiscountApplication(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, d)
	}
	return result, total, rows.Err()
}

// -------------------------------------------------------------------------
// Concurrency / Locking
// -------------------------------------------------------------------------

func (r *discountUsageRepository) GetByIDForUpdate(ctx context.Context, db DBTX, applicationID uuid.UUID) (*discount.DiscountApplication, error) {
	query := `
		SELECT application_id, company_id, order_id, invoice_id, discount_type,
			discount_id, auto_discount_id, discount_name, amount, created_at
		FROM sales.discount_applications
		WHERE application_id = $1
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, applicationID)
	return r.scanDiscountApplication(row)
}
