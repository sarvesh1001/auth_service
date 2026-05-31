// internal/sales/repository/sales_rep_repository.go

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

// -------------------------------------------------------------------------
// Types & Interface
// -------------------------------------------------------------------------

type SalesRepRepository interface {
	Create(ctx context.Context, db DBTX, rep *models.SalesRep) error
	GetByID(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID) (*models.SalesRep, error)
	GetByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (*models.SalesRep, error)
	GetByUserID(ctx context.Context, db DBTX, companyID, userID uuid.UUID) (*models.SalesRep, error)
	Update(ctx context.Context, db DBTX, rep *models.SalesRep) error
	Delete(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID) error
	SetActiveStatus(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID, isActive bool, updatedBy *uuid.UUID) error
	Exists(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID) (bool, error)
	ExistsByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (bool, error)
	ExistsByEmailHash(ctx context.Context, db DBTX, companyID uuid.UUID, emailHash string) (bool, error)
	ExistsByEmailHashExcluding(ctx context.Context, db DBTX, companyID uuid.UUID, emailHash string, excludeRepID uuid.UUID) (bool, error)
	ExistsByUserID(ctx context.Context, db DBTX, companyID, userID uuid.UUID) (bool, error)
	IsActive(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID) (bool, error)
	List(ctx context.Context, db DBTX, filter SalesRepFilter, p Pagination, s Sort) ([]*models.SalesRep, int64, error)
	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.SalesRep, int64, error)
	GetActiveSalesReps(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.SalesRep, error)
	GetTopSalesRepsByRevenue(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.SalesRep, error)
	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID) (*models.SalesRep, error)
	UserExists(ctx context.Context, db DBTX, userID uuid.UUID) (bool, error)
}

// SalesRepFilter excludes Email/Phone because they are encrypted and not searchable via ILIKE.
type SalesRepFilter struct {
	CompanyID   uuid.UUID
	SalesRepIDs []uuid.UUID
	UserID      *uuid.UUID
	IsActive    *bool
	Code        *string
	Name        *string
	CreatedFrom *time.Time
	CreatedTo   *time.Time
	UpdatedFrom *time.Time
	UpdatedTo   *time.Time
}

type salesRepRepository struct {
	logger *zap.Logger
}

func NewSalesRepRepository(logger *zap.Logger) SalesRepRepository {
	return &salesRepRepository{
		logger: logger.Named("sales_sales_rep_repo"),
	}
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

func (r *salesRepRepository) nullUUIDParam(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func (r *salesRepRepository) nullStringParam(s *string) interface{} {
	if s == nil {
		return nil
	}
	return *s
}

func (r *salesRepRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *salesRepRepository) validatePagination(p Pagination) (int, int) {
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

func (r *salesRepRepository) buildSalesRepFilter(filter SalesRepFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if len(filter.SalesRepIDs) > 0 {
		placeholders := make([]string, len(filter.SalesRepIDs))
		for i, id := range filter.SalesRepIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("sales_rep_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.UserID != nil {
		conds = append(conds, fmt.Sprintf("user_id = $%d", idx))
		args = append(args, *filter.UserID)
		idx++
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
	if filter.Name != nil {
		conds = append(conds, fmt.Sprintf("name ILIKE $%d", idx))
		args = append(args, "%"+*filter.Name+"%")
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

// scanSalesRep reads all encrypted columns and the hash.
func (r *salesRepRepository) scanSalesRep(s scanner) (*models.SalesRep, error) {
	var rep models.SalesRep
	var createdBy, updatedBy uuid.NullUUID
	var emailHash sql.NullString

	err := s.Scan(
		&rep.SalesRepID,
		&rep.CompanyID,
		&rep.UserID,
		&rep.Code,
		&rep.Name,
		&rep.EmailEncrypted,
		&rep.EmailDEK,
		&rep.EmailKeyID,
		&rep.PhoneEncrypted,
		&rep.PhoneDEK,
		&rep.PhoneKeyID,
		&rep.IsActive,
		&rep.CreatedAt,
		&rep.UpdatedAt,
		&createdBy,
		&updatedBy,
		&emailHash,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, salesErrors.ErrNotFound
		}
		return nil, fmt.Errorf("scan sales rep: %w", err)
	}

	if createdBy.Valid {
		rep.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		rep.UpdatedBy = &updatedBy.UUID
	}
	if emailHash.Valid {
		rep.EmailHash = &emailHash.String
	}
	return &rep, nil
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (r *salesRepRepository) Create(ctx context.Context, db DBTX, rep *models.SalesRep) error {
	query := `
		INSERT INTO sales.sales_reps (
			sales_rep_id, company_id, user_id, code, name,
			email, email_dek, email_key_id, email_hash,
			phone, phone_dek, phone_key_id,
			is_active, created_at, updated_at, created_by, updated_by
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12,
			$13, NOW(), NOW(), $14, $15
		)
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		rep.SalesRepID,
		rep.CompanyID,
		rep.UserID,
		rep.Code,
		rep.Name,
		r.nullStringParam(rep.EmailEncrypted),
		r.nullStringParam(rep.EmailDEK),
		r.nullStringParam(rep.EmailKeyID),
		r.nullStringParam(rep.EmailHash),
		r.nullStringParam(rep.PhoneEncrypted),
		r.nullStringParam(rep.PhoneDEK),
		r.nullStringParam(rep.PhoneKeyID),
		rep.IsActive,
		r.nullUUIDParam(rep.CreatedBy),
		r.nullUUIDParam(rep.UpdatedBy),
	).Scan(&rep.CreatedAt, &rep.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create sales rep", zap.Error(err))
		return fmt.Errorf("create sales rep: %w", err)
	}
	return nil
}

func (r *salesRepRepository) GetByID(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID) (*models.SalesRep, error) {
	query := `
		SELECT 
			sales_rep_id, company_id, user_id, code, name,
			email, email_dek, email_key_id,
			phone, phone_dek, phone_key_id,
			is_active, created_at, updated_at, created_by, updated_by,
			email_hash
		FROM sales.sales_reps
		WHERE company_id = $1 AND sales_rep_id = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, salesRepID)
	return r.scanSalesRep(row)
}

func (r *salesRepRepository) GetByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (*models.SalesRep, error) {
	query := `
		SELECT 
			sales_rep_id, company_id, user_id, code, name,
			email, email_dek, email_key_id,
			phone, phone_dek, phone_key_id,
			is_active, created_at, updated_at, created_by, updated_by,
			email_hash
		FROM sales.sales_reps
		WHERE company_id = $1 AND code = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, code)
	return r.scanSalesRep(row)
}

func (r *salesRepRepository) GetByUserID(ctx context.Context, db DBTX, companyID, userID uuid.UUID) (*models.SalesRep, error) {
	query := `
		SELECT 
			sales_rep_id, company_id, user_id, code, name,
			email, email_dek, email_key_id,
			phone, phone_dek, phone_key_id,
			is_active, created_at, updated_at, created_by, updated_by,
			email_hash
		FROM sales.sales_reps
		WHERE company_id = $1 AND user_id = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, userID)
	return r.scanSalesRep(row)
}

func (r *salesRepRepository) Update(ctx context.Context, db DBTX, rep *models.SalesRep) error {
	query := `
		UPDATE sales.sales_reps SET
			code = $3,
			name = $4,
			email = $5,
			email_dek = $6,
			email_key_id = $7,
			email_hash = $8,
			phone = $9,
			phone_dek = $10,
			phone_key_id = $11,
			is_active = $12,
			updated_at = NOW(),
			updated_by = $13
		WHERE sales_rep_id = $1 AND company_id = $2
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		rep.SalesRepID,
		rep.CompanyID,
		rep.Code,
		rep.Name,
		r.nullStringParam(rep.EmailEncrypted),
		r.nullStringParam(rep.EmailDEK),
		r.nullStringParam(rep.EmailKeyID),
		r.nullStringParam(rep.EmailHash),
		r.nullStringParam(rep.PhoneEncrypted),
		r.nullStringParam(rep.PhoneDEK),
		r.nullStringParam(rep.PhoneKeyID),
		rep.IsActive,
		r.nullUUIDParam(rep.UpdatedBy),
	).Scan(&rep.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return salesErrors.ErrNotFound
		}
		return fmt.Errorf("update sales rep: %w", err)
	}
	return nil
}

func (r *salesRepRepository) Delete(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID) error {
	query := `DELETE FROM sales.sales_reps WHERE company_id = $1 AND sales_rep_id = $2`
	result, err := db.ExecContext(ctx, query, companyID, salesRepID)
	if err != nil {
		return fmt.Errorf("delete sales rep: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

// -------------------------------------------------------------------------
// Status & Uniqueness Checks
// -------------------------------------------------------------------------

func (r *salesRepRepository) SetActiveStatus(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID, isActive bool, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.sales_reps
		SET is_active = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND sales_rep_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, salesRepID, isActive, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("set active status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

func (r *salesRepRepository) Exists(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.sales_reps WHERE company_id = $1 AND sales_rep_id = $2)`
	err := db.QueryRowContext(ctx, query, companyID, salesRepID).Scan(&exists)
	return exists, err
}

func (r *salesRepRepository) ExistsByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.sales_reps WHERE company_id = $1 AND code = $2)`
	err := db.QueryRowContext(ctx, query, companyID, code).Scan(&exists)
	return exists, err
}

func (r *salesRepRepository) ExistsByEmailHash(ctx context.Context, db DBTX, companyID uuid.UUID, emailHash string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.sales_reps WHERE company_id = $1 AND email_hash = $2)`
	err := db.QueryRowContext(ctx, query, companyID, emailHash).Scan(&exists)
	return exists, err
}

func (r *salesRepRepository) ExistsByEmailHashExcluding(ctx context.Context, db DBTX, companyID uuid.UUID, emailHash string, excludeRepID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.sales_reps WHERE company_id = $1 AND email_hash = $2 AND sales_rep_id != $3)`
	err := db.QueryRowContext(ctx, query, companyID, emailHash, excludeRepID).Scan(&exists)
	return exists, err
}

func (r *salesRepRepository) ExistsByUserID(ctx context.Context, db DBTX, companyID, userID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.sales_reps WHERE company_id = $1 AND user_id = $2)`
	err := db.QueryRowContext(ctx, query, companyID, userID).Scan(&exists)
	return exists, err
}

func (r *salesRepRepository) IsActive(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID) (bool, error) {
	var active bool
	query := `SELECT is_active FROM sales.sales_reps WHERE company_id = $1 AND sales_rep_id = $2`
	err := db.QueryRowContext(ctx, query, companyID, salesRepID).Scan(&active)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, salesErrors.ErrNotFound
		}
		return false, fmt.Errorf("is active: %w", err)
	}
	return active, nil
}

// -------------------------------------------------------------------------
// Listing & Search
// -------------------------------------------------------------------------

func (r *salesRepRepository) List(ctx context.Context, db DBTX, filter SalesRepFilter, p Pagination, s Sort) ([]*models.SalesRep, int64, error) {
	where, args := r.buildSalesRepFilter(filter)
	if where == "" {
		return nil, 0, fmt.Errorf("list requires at least company_id filter")
	}
	allowedSort := map[string]bool{
		"code":       true,
		"name":       true,
		"is_active":  true,
		"created_at": true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY name ASC"
	}
	limit, offset := r.validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sales.sales_reps %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count sales reps: %w", err)
	}
	if total == 0 {
		return []*models.SalesRep{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT 
			sales_rep_id, company_id, user_id, code, name,
			email, email_dek, email_key_id,
			phone, phone_dek, phone_key_id,
			is_active, created_at, updated_at, created_by, updated_by,
			email_hash
		FROM sales.sales_reps
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list sales reps: %w", err)
	}
	defer rows.Close()

	var result []*models.SalesRep
	for rows.Next() {
		rep, err := r.scanSalesRep(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, rep)
	}
	return result, total, rows.Err()
}

func (r *salesRepRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, queryStr string, limit, offset int) ([]*models.SalesRep, int64, error) {
	searchPattern := "%" + queryStr + "%"
	baseArgs := []interface{}{companyID, searchPattern, searchPattern}
	countQuery := `
		SELECT COUNT(*)
		FROM sales.sales_reps
		WHERE company_id = $1
		AND (code ILIKE $2 OR name ILIKE $3)
	`
	var total int64
	err := db.QueryRowContext(ctx, countQuery, baseArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search count: %w", err)
	}
	if total == 0 {
		return []*models.SalesRep{}, 0, nil
	}

	dataQuery := `
		SELECT 
			sales_rep_id, company_id, user_id, code, name,
			email, email_dek, email_key_id,
			phone, phone_dek, phone_key_id,
			is_active, created_at, updated_at, created_by, updated_by,
			email_hash
		FROM sales.sales_reps
		WHERE company_id = $1
		AND (code ILIKE $2 OR name ILIKE $3)
		ORDER BY name ASC
		LIMIT $4 OFFSET $5
	`
	args := append(baseArgs, limit, offset)
	rows, err := db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search data: %w", err)
	}
	defer rows.Close()

	var result []*models.SalesRep
	for rows.Next() {
		rep, err := r.scanSalesRep(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, rep)
	}
	return result, total, rows.Err()
}

func (r *salesRepRepository) GetActiveSalesReps(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.SalesRep, error) {
	filter := SalesRepFilter{
		CompanyID: companyID,
		IsActive:  boolPtr(true),
	}
	reps, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "name", Direction: "ASC"})
	return reps, err
}

// -------------------------------------------------------------------------
// Analytics & Locking
// -------------------------------------------------------------------------

func (r *salesRepRepository) GetTopSalesRepsByRevenue(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.SalesRep, error) {
	where := "i.company_id = $1 AND i.status NOT IN ('cancelled', 'draft')"
	args := []interface{}{companyID}
	idx := 2
	if from != nil {
		where += fmt.Sprintf(" AND i.invoice_date >= $%d", idx)
		args = append(args, *from)
		idx++
	}
	if to != nil {
		where += fmt.Sprintf(" AND i.invoice_date <= $%d", idx)
		args = append(args, *to)
		idx++
	}
	query := fmt.Sprintf(`
		SELECT 
			sr.sales_rep_id, sr.company_id, sr.user_id, sr.code, sr.name,
			sr.email, sr.email_dek, sr.email_key_id,
			sr.phone, sr.phone_dek, sr.phone_key_id,
			sr.is_active, sr.created_at, sr.updated_at, sr.created_by, sr.updated_by,
			sr.email_hash,
			COALESCE(SUM(i.grand_total), 0) as total_revenue
		FROM sales.sales_reps sr
		LEFT JOIN sales.invoices i ON sr.sales_rep_id = i.sales_rep_id
		WHERE %s
		GROUP BY sr.sales_rep_id
		ORDER BY total_revenue DESC
		LIMIT $%d
	`, where, idx)
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get top sales reps by revenue: %w", err)
	}
	defer rows.Close()

	var result []*models.SalesRep
	for rows.Next() {
		var rep models.SalesRep
		var totalRevenue decimal.Decimal
		err := rows.Scan(
			&rep.SalesRepID, &rep.CompanyID, &rep.UserID, &rep.Code, &rep.Name,
			&rep.EmailEncrypted, &rep.EmailDEK, &rep.EmailKeyID,
			&rep.PhoneEncrypted, &rep.PhoneDEK, &rep.PhoneKeyID,
			&rep.IsActive, &rep.CreatedAt, &rep.UpdatedAt, &rep.CreatedBy, &rep.UpdatedBy,
			&rep.EmailHash,
			&totalRevenue,
		)
		if err != nil {
			return nil, fmt.Errorf("scan top sales rep: %w", err)
		}
		result = append(result, &rep)
	}
	return result, rows.Err()
}

func (r *salesRepRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID) (*models.SalesRep, error) {
	query := `
		SELECT 
			sales_rep_id, company_id, user_id, code, name,
			email, email_dek, email_key_id,
			phone, phone_dek, phone_key_id,
			is_active, created_at, updated_at, created_by, updated_by,
			email_hash
		FROM sales.sales_reps
		WHERE company_id = $1 AND sales_rep_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, companyID, salesRepID)
	return r.scanSalesRep(row)
}

// UserExists checks if a user exists in the users table (partitioned by user_id)
func (r *salesRepRepository) UserExists(ctx context.Context, db DBTX, userID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE user_id = $1)`
	err := db.QueryRowContext(ctx, query, userID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check user existence: %w", err)
	}
	return exists, nil
}
