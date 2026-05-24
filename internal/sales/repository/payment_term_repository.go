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
)

type PaymentTermRepository interface {
	Create(ctx context.Context, db DBTX, term *models.PaymentTerm) error
	GetByID(ctx context.Context, db DBTX, companyID, termID uuid.UUID) (*models.PaymentTerm, error)
	GetByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (*models.PaymentTerm, error)
	GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, termName string) (*models.PaymentTerm, error)
	Update(ctx context.Context, db DBTX, term *models.PaymentTerm) error
	Delete(ctx context.Context, db DBTX, companyID, termID uuid.UUID) error
	SetActiveStatus(ctx context.Context, db DBTX, companyID, termID uuid.UUID, isActive bool, updatedBy *uuid.UUID) error
	Exists(ctx context.Context, db DBTX, companyID, termID uuid.UUID) (bool, error)
	ExistsByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (bool, error)
	IsActive(ctx context.Context, db DBTX, companyID, termID uuid.UUID) (bool, error)
	CalculateDueDate(ctx context.Context, db DBTX, companyID, termID uuid.UUID, invoiceDate time.Time) (time.Time, error)
	CalculateEarlyPaymentDiscount(ctx context.Context, db DBTX, companyID, termID uuid.UUID, invoiceAmount decimal.Decimal, paymentDate, invoiceDate time.Time) (decimal.Decimal, error)
	ApplyToCustomer(ctx context.Context, db DBTX, companyID, customerID, termID uuid.UUID, updatedBy *uuid.UUID) error
	List(ctx context.Context, db DBTX, filter PaymentTermFilter, p Pagination, s Sort) ([]*models.PaymentTerm, int64, error)
	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.PaymentTerm, int64, error)
	GetActiveTerms(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.PaymentTerm, error)
	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, termID uuid.UUID) (*models.PaymentTerm, error)
}

type PaymentTermFilter struct {
	CompanyID   uuid.UUID
	TermIDs     []uuid.UUID
	IsActive    *bool
	Code        *string
	TermName    *string
	DueDaysMin  *int
	DueDaysMax  *int
	CreatedFrom *time.Time
	CreatedTo   *time.Time
	UpdatedFrom *time.Time
	UpdatedTo   *time.Time
}

type paymentTermRepository struct {
	logger *zap.Logger
}

func NewPaymentTermRepository(logger *zap.Logger) PaymentTermRepository {
	return &paymentTermRepository{
		logger: logger.Named("sales_payment_term_repo"),
	}
}

func (r *paymentTermRepository) nullUUIDParam(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func (r *paymentTermRepository) nullStringParam(s *string) interface{} {
	if s == nil {
		return nil
	}
	return *s
}

func (r *paymentTermRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *paymentTermRepository) validatePagination(p Pagination) (int, int) {
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

func (r *paymentTermRepository) buildPaymentTermFilter(filter PaymentTermFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if len(filter.TermIDs) > 0 {
		placeholders := make([]string, len(filter.TermIDs))
		for i, id := range filter.TermIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("term_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.IsActive != nil {
		conds = append(conds, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}
	if filter.Code != nil {
		conds = append(conds, fmt.Sprintf("code = $%d", idx))
		args = append(args, *filter.Code)
		idx++
	}
	if filter.TermName != nil {
		conds = append(conds, fmt.Sprintf("term_name = $%d", idx))
		args = append(args, *filter.TermName)
		idx++
	}
	if filter.DueDaysMin != nil {
		conds = append(conds, fmt.Sprintf("due_days >= $%d", idx))
		args = append(args, *filter.DueDaysMin)
		idx++
	}
	if filter.DueDaysMax != nil {
		conds = append(conds, fmt.Sprintf("due_days <= $%d", idx))
		args = append(args, *filter.DueDaysMax)
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

func (r *paymentTermRepository) scanPaymentTerm(s scanner) (*models.PaymentTerm, error) {
	var t models.PaymentTerm
	var description sql.NullString
	var discountPercent sql.NullString
	var createdBy, updatedBy uuid.NullUUID

	err := s.Scan(
		&t.TermID,
		&t.CompanyID,
		&t.Code,
		&t.TermName,
		&description,
		&t.DueDays,
		&discountPercent,
		&t.DiscountDays,
		&t.IsActive,
		&t.CreatedAt,
		&t.UpdatedAt,
		&createdBy,
		&updatedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, salesErrors.ErrNotFound
		}
		return nil, fmt.Errorf("scan payment term: %w", err)
	}

	if description.Valid {
		t.Description = &description.String
	}
	if discountPercent.Valid {
		val, err := decimal.NewFromString(discountPercent.String)
		if err == nil {
			t.DiscountPercent = val
		}
	}
	if createdBy.Valid {
		t.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		t.UpdatedBy = &updatedBy.UUID
	}
	return &t, nil
}

// ---------- CRUD ----------
func (r *paymentTermRepository) Create(ctx context.Context, db DBTX, term *models.PaymentTerm) error {
	query := `
		INSERT INTO sales.payment_terms (
			term_id, company_id, code, term_name, description,
			due_days, discount_percent, discount_days, is_active,
			created_at, updated_at, created_by, updated_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW(), $10, $11
		)
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		term.TermID,
		term.CompanyID,
		term.Code,
		term.TermName,
		term.Description,
		term.DueDays,
		term.DiscountPercent,
		term.DiscountDays,
		term.IsActive,
		r.nullUUIDParam(term.CreatedBy),
		r.nullUUIDParam(term.UpdatedBy),
	).Scan(&term.CreatedAt, &term.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create payment term", zap.Error(err))
		return fmt.Errorf("create payment term: %w", err)
	}
	return nil
}

func (r *paymentTermRepository) GetByID(ctx context.Context, db DBTX, companyID, termID uuid.UUID) (*models.PaymentTerm, error) {
	query := `
		SELECT term_id, company_id, code, term_name, description,
		       due_days, discount_percent, discount_days, is_active,
		       created_at, updated_at, created_by, updated_by
		FROM sales.payment_terms
		WHERE company_id = $1 AND term_id = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, termID)
	return r.scanPaymentTerm(row)
}

func (r *paymentTermRepository) GetByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (*models.PaymentTerm, error) {
	query := `
		SELECT term_id, company_id, code, term_name, description,
		       due_days, discount_percent, discount_days, is_active,
		       created_at, updated_at, created_by, updated_by
		FROM sales.payment_terms
		WHERE company_id = $1 AND code = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, code)
	return r.scanPaymentTerm(row)
}

func (r *paymentTermRepository) GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, termName string) (*models.PaymentTerm, error) {
	query := `
		SELECT term_id, company_id, code, term_name, description,
		       due_days, discount_percent, discount_days, is_active,
		       created_at, updated_at, created_by, updated_by
		FROM sales.payment_terms
		WHERE company_id = $1 AND term_name = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, termName)
	return r.scanPaymentTerm(row)
}

func (r *paymentTermRepository) Update(ctx context.Context, db DBTX, term *models.PaymentTerm) error {
	query := `
		UPDATE sales.payment_terms SET
			code = $3,
			term_name = $4,
			description = $5,
			due_days = $6,
			discount_percent = $7,
			discount_days = $8,
			is_active = $9,
			updated_at = NOW(),
			updated_by = $10
		WHERE term_id = $1 AND company_id = $2
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		term.TermID,
		term.CompanyID,
		term.Code,
		term.TermName,
		term.Description,
		term.DueDays,
		term.DiscountPercent,
		term.DiscountDays,
		term.IsActive,
		r.nullUUIDParam(term.UpdatedBy),
	).Scan(&term.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return salesErrors.ErrNotFound
		}
		return fmt.Errorf("update payment term: %w", err)
	}
	return nil
}

func (r *paymentTermRepository) Delete(ctx context.Context, db DBTX, companyID, termID uuid.UUID) error {
	query := `DELETE FROM sales.payment_terms WHERE company_id = $1 AND term_id = $2`
	result, err := db.ExecContext(ctx, query, companyID, termID)
	if err != nil {
		return fmt.Errorf("delete payment term: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

// ---------- Status / Validation ----------
func (r *paymentTermRepository) SetActiveStatus(ctx context.Context, db DBTX, companyID, termID uuid.UUID, isActive bool, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.payment_terms
		SET is_active = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND term_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, termID, isActive, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("set active status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

func (r *paymentTermRepository) Exists(ctx context.Context, db DBTX, companyID, termID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.payment_terms WHERE company_id = $1 AND term_id = $2)`
	err := db.QueryRowContext(ctx, query, companyID, termID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists: %w", err)
	}
	return exists, nil
}

func (r *paymentTermRepository) ExistsByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.payment_terms WHERE company_id = $1 AND code = $2)`
	err := db.QueryRowContext(ctx, query, companyID, code).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists by code: %w", err)
	}
	return exists, nil
}

func (r *paymentTermRepository) IsActive(ctx context.Context, db DBTX, companyID, termID uuid.UUID) (bool, error) {
	var active bool
	query := `SELECT is_active FROM sales.payment_terms WHERE company_id = $1 AND term_id = $2`
	err := db.QueryRowContext(ctx, query, companyID, termID).Scan(&active)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, salesErrors.ErrNotFound
		}
		return false, fmt.Errorf("is active: %w", err)
	}
	return active, nil
}

// ---------- Business Logic ----------
func (r *paymentTermRepository) CalculateDueDate(ctx context.Context, db DBTX, companyID, termID uuid.UUID, invoiceDate time.Time) (time.Time, error) {
	term, err := r.GetByID(ctx, db, companyID, termID)
	if err != nil {
		return time.Time{}, err
	}
	return invoiceDate.AddDate(0, 0, term.DueDays), nil
}

func (r *paymentTermRepository) CalculateEarlyPaymentDiscount(ctx context.Context, db DBTX, companyID, termID uuid.UUID, invoiceAmount decimal.Decimal, paymentDate, invoiceDate time.Time) (decimal.Decimal, error) {
	term, err := r.GetByID(ctx, db, companyID, termID)
	if err != nil {
		return decimal.Zero, err
	}
	if term.DiscountPercent.IsZero() || term.DiscountDays == 0 {
		return decimal.Zero, nil
	}
	daysDiff := int(paymentDate.Sub(invoiceDate).Hours() / 24)
	if daysDiff <= term.DiscountDays {
		discount := invoiceAmount.Mul(term.DiscountPercent).Div(decimal.NewFromInt(100))
		return discount, nil
	}
	return decimal.Zero, nil
}

func (r *paymentTermRepository) ApplyToCustomer(ctx context.Context, db DBTX, companyID, customerID, termID uuid.UUID, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.customers
		SET payment_term_id = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND customer_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, customerID, r.nullUUIDParam(&termID), r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("apply payment term to customer: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

// ---------- Querying / Listing ----------
func (r *paymentTermRepository) List(ctx context.Context, db DBTX, filter PaymentTermFilter, p Pagination, s Sort) ([]*models.PaymentTerm, int64, error) {
	where, args := r.buildPaymentTermFilter(filter)
	if where == "" {
		return nil, 0, fmt.Errorf("list requires at least company_id filter")
	}
	allowedSort := map[string]bool{
		"code":       true,
		"term_name":  true,
		"due_days":   true,
		"is_active":  true,
		"created_at": true,
		"updated_at": true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY term_name ASC"
	}
	limit, offset := r.validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sales.payment_terms %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count payment terms: %w", err)
	}
	if total == 0 {
		return []*models.PaymentTerm{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT term_id, company_id, code, term_name, description,
		       due_days, discount_percent, discount_days, is_active,
		       created_at, updated_at, created_by, updated_by
		FROM sales.payment_terms
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list payment terms: %w", err)
	}
	defer rows.Close()

	var result []*models.PaymentTerm
	for rows.Next() {
		t, err := r.scanPaymentTerm(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, t)
	}
	return result, total, rows.Err()
}

func (r *paymentTermRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, queryStr string, limit, offset int) ([]*models.PaymentTerm, int64, error) {
	searchPattern := "%" + queryStr + "%"
	baseArgs := []interface{}{companyID, searchPattern, searchPattern}
	countQuery := `
		SELECT COUNT(*)
		FROM sales.payment_terms
		WHERE company_id = $1
		AND (code ILIKE $2 OR term_name ILIKE $3)
	`
	var total int64
	err := db.QueryRowContext(ctx, countQuery, baseArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search count: %w", err)
	}
	if total == 0 {
		return []*models.PaymentTerm{}, 0, nil
	}

	dataQuery := `
		SELECT term_id, company_id, code, term_name, description,
		       due_days, discount_percent, discount_days, is_active,
		       created_at, updated_at, created_by, updated_by
		FROM sales.payment_terms
		WHERE company_id = $1
		AND (code ILIKE $2 OR term_name ILIKE $3)
		ORDER BY term_name ASC
		LIMIT $4 OFFSET $5
	`
	args := append(baseArgs, limit, offset)
	rows, err := db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search data: %w", err)
	}
	defer rows.Close()

	var result []*models.PaymentTerm
	for rows.Next() {
		t, err := r.scanPaymentTerm(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, t)
	}
	return result, total, rows.Err()
}

func (r *paymentTermRepository) GetActiveTerms(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.PaymentTerm, error) {
	filter := PaymentTermFilter{
		CompanyID: companyID,
		IsActive:  boolPtr(true),
	}
	terms, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "term_name", Direction: "ASC"})
	return terms, err
}

// ---------- Concurrency / Locking ----------
func (r *paymentTermRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, termID uuid.UUID) (*models.PaymentTerm, error) {
	query := `
		SELECT term_id, company_id, code, term_name, description,
		       due_days, discount_percent, discount_days, is_active,
		       created_at, updated_at, created_by, updated_by
		FROM sales.payment_terms
		WHERE company_id = $1 AND term_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, companyID, termID)
	return r.scanPaymentTerm(row)
}

func boolPtr(b bool) *bool {
	return &b
}
