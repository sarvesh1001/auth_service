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

// SalesTargetRepository defines the interface for sales target persistence.
type SalesTargetRepository interface {
	Create(ctx context.Context, db DBTX, target *models.SalesTarget) error
	GetByID(ctx context.Context, db DBTX, companyID, targetID uuid.UUID) (*models.SalesTarget, error)
	GetByPeriod(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID, periodStart, periodEnd time.Time) (*models.SalesTarget, error)
	Update(ctx context.Context, db DBTX, target *models.SalesTarget) error
	Delete(ctx context.Context, db DBTX, companyID, targetID uuid.UUID) error
	List(ctx context.Context, db DBTX, filter SalesTargetFilter, p Pagination, s Sort) ([]*models.SalesTarget, int64, error)
	Exists(ctx context.Context, db DBTX, companyID, targetID uuid.UUID) (bool, error)
	ExistsForPeriod(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID, periodStart, periodEnd time.Time) (bool, error)
}

// SalesTargetFilter defines filter options for listing sales targets.
type SalesTargetFilter struct {
	CompanyID   uuid.UUID
	SalesRepID  *uuid.UUID
	PeriodStart *time.Time
	PeriodEnd   *time.Time
	TargetMin   *decimal.Decimal
	TargetMax   *decimal.Decimal
	CreatedFrom *time.Time
	CreatedTo   *time.Time
}

type salesTargetRepository struct {
	logger *zap.Logger
}

// NewSalesTargetRepository creates a new SalesTargetRepository instance.
func NewSalesTargetRepository(logger *zap.Logger) SalesTargetRepository {
	return &salesTargetRepository{
		logger: logger.Named("sales_target_repo"),
	}
}

// ---------- Helper methods ----------

func (r *salesTargetRepository) nullUUIDParam(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func (r *salesTargetRepository) nullDecimalParam(d *decimal.Decimal) interface{} {
	if d == nil {
		return nil
	}
	return *d
}

func (r *salesTargetRepository) nullTimeParam(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return *t
}

func (r *salesTargetRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *salesTargetRepository) validatePagination(p Pagination) (int, int) {
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

func (r *salesTargetRepository) buildFilter(filter SalesTargetFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.SalesRepID != nil {
		conds = append(conds, fmt.Sprintf("sales_rep_id = $%d", idx))
		args = append(args, *filter.SalesRepID)
		idx++
	}
	if filter.PeriodStart != nil {
		conds = append(conds, fmt.Sprintf("period_start >= $%d", idx))
		args = append(args, *filter.PeriodStart)
		idx++
	}
	if filter.PeriodEnd != nil {
		conds = append(conds, fmt.Sprintf("period_end <= $%d", idx))
		args = append(args, *filter.PeriodEnd)
		idx++
	}
	if filter.TargetMin != nil {
		conds = append(conds, fmt.Sprintf("target_amount >= $%d", idx))
		args = append(args, *filter.TargetMin)
		idx++
	}
	if filter.TargetMax != nil {
		conds = append(conds, fmt.Sprintf("target_amount <= $%d", idx))
		args = append(args, *filter.TargetMax)
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

func (r *salesTargetRepository) scanTarget(s scanner) (*models.SalesTarget, error) {
	var target models.SalesTarget
	var createdBy, updatedBy uuid.NullUUID

	err := s.Scan(
		&target.TargetID,
		&target.CompanyID,
		&target.SalesRepID,
		&target.PeriodStart,
		&target.PeriodEnd,
		&target.TargetAmount,
		&target.Currency,
		&target.CreatedAt,
		&target.UpdatedAt,
		&createdBy,
		&updatedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, salesErrors.ErrNotFound
		}
		return nil, fmt.Errorf("scan sales target: %w", err)
	}
	if createdBy.Valid {
		target.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		target.UpdatedBy = &updatedBy.UUID
	}
	return &target, nil
}

// ---------- CRUD operations ----------

// Create inserts a new sales target.
func (r *salesTargetRepository) Create(ctx context.Context, db DBTX, target *models.SalesTarget) error {
	query := `
		INSERT INTO sales.sales_targets (
			target_id, company_id, sales_rep_id, period_start, period_end,
			target_amount, currency, created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW(), $8, $9)
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		target.TargetID,
		target.CompanyID,
		target.SalesRepID,
		target.PeriodStart,
		target.PeriodEnd,
		target.TargetAmount,
		target.Currency,
		r.nullUUIDParam(target.CreatedBy),
		r.nullUUIDParam(target.UpdatedBy),
	).Scan(&target.CreatedAt, &target.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create sales target", zap.Error(err))
		return fmt.Errorf("create sales target: %w", err)
	}
	return nil
}

// GetByID retrieves a sales target by ID.
func (r *salesTargetRepository) GetByID(ctx context.Context, db DBTX, companyID, targetID uuid.UUID) (*models.SalesTarget, error) {
	query := `
		SELECT target_id, company_id, sales_rep_id, period_start, period_end,
		       target_amount, currency, created_at, updated_at, created_by, updated_by
		FROM sales.sales_targets
		WHERE company_id = $1 AND target_id = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, targetID)
	return r.scanTarget(row)
}

// GetByPeriod retrieves a sales target for a specific sales rep and period.
func (r *salesTargetRepository) GetByPeriod(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID, periodStart, periodEnd time.Time) (*models.SalesTarget, error) {
	query := `
		SELECT target_id, company_id, sales_rep_id, period_start, period_end,
		       target_amount, currency, created_at, updated_at, created_by, updated_by
		FROM sales.sales_targets
		WHERE company_id = $1 AND sales_rep_id = $2 AND period_start = $3 AND period_end = $4
	`
	row := db.QueryRowContext(ctx, query, companyID, salesRepID, periodStart, periodEnd)
	return r.scanTarget(row)
}

// Update modifies an existing sales target.
func (r *salesTargetRepository) Update(ctx context.Context, db DBTX, target *models.SalesTarget) error {
	query := `
		UPDATE sales.sales_targets SET
			sales_rep_id = $3,
			period_start = $4,
			period_end = $5,
			target_amount = $6,
			currency = $7,
			updated_at = NOW(),
			updated_by = $8
		WHERE target_id = $1 AND company_id = $2
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		target.TargetID,
		target.CompanyID,
		target.SalesRepID,
		target.PeriodStart,
		target.PeriodEnd,
		target.TargetAmount,
		target.Currency,
		r.nullUUIDParam(target.UpdatedBy),
	).Scan(&target.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return salesErrors.ErrNotFound
		}
		return fmt.Errorf("update sales target: %w", err)
	}
	return nil
}

// Delete removes a sales target by ID.
func (r *salesTargetRepository) Delete(ctx context.Context, db DBTX, companyID, targetID uuid.UUID) error {
	query := `DELETE FROM sales.sales_targets WHERE company_id = $1 AND target_id = $2`
	result, err := db.ExecContext(ctx, query, companyID, targetID)
	if err != nil {
		return fmt.Errorf("delete sales target: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

// List returns paginated sales targets matching the filter.
func (r *salesTargetRepository) List(ctx context.Context, db DBTX, filter SalesTargetFilter, p Pagination, s Sort) ([]*models.SalesTarget, int64, error) {
	where, args := r.buildFilter(filter)
	if where == "" {
		return nil, 0, fmt.Errorf("list requires at least company_id filter")
	}

	allowedSort := map[string]bool{
		"period_start":  true,
		"period_end":    true,
		"target_amount": true,
		"created_at":    true,
		"updated_at":    true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY period_start DESC"
	}
	limit, offset := r.validatePagination(p)

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sales.sales_targets %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count sales targets: %w", err)
	}
	if total == 0 {
		return []*models.SalesTarget{}, 0, nil
	}

	// Data query
	query := fmt.Sprintf(`
		SELECT target_id, company_id, sales_rep_id, period_start, period_end,
		       target_amount, currency, created_at, updated_at, created_by, updated_by
		FROM sales.sales_targets
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list sales targets: %w", err)
	}
	defer rows.Close()

	var result []*models.SalesTarget
	for rows.Next() {
		target, err := r.scanTarget(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, target)
	}
	return result, total, rows.Err()
}

// Exists checks if a sales target exists by ID.
func (r *salesTargetRepository) Exists(ctx context.Context, db DBTX, companyID, targetID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.sales_targets WHERE company_id = $1 AND target_id = $2)`
	err := db.QueryRowContext(ctx, query, companyID, targetID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists: %w", err)
	}
	return exists, nil
}

// ExistsForPeriod checks if a target already exists for the given sales rep and period.
func (r *salesTargetRepository) ExistsForPeriod(ctx context.Context, db DBTX, companyID, salesRepID uuid.UUID, periodStart, periodEnd time.Time) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(
			SELECT 1 FROM sales.sales_targets
			WHERE company_id = $1 AND sales_rep_id = $2
			AND period_start = $3 AND period_end = $4
		)
	`
	err := db.QueryRowContext(ctx, query, companyID, salesRepID, periodStart, periodEnd).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists for period: %w", err)
	}
	return exists, nil
}
