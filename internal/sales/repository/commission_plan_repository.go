package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	salesErrors "auth-service/internal/sales/errors"
	"auth-service/internal/sales/models"
)

// -------------------------------------------------------------------------
// Interface
// -------------------------------------------------------------------------

type CommissionPlanRepository interface {
	Create(ctx context.Context, db DBTX, plan *models.CommissionPlan) error
	GetByID(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (*models.CommissionPlan, error)
	GetByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (*models.CommissionPlan, error)
	Update(ctx context.Context, db DBTX, plan *models.CommissionPlan) error
	Delete(ctx context.Context, db DBTX, companyID, planID uuid.UUID) error
	Exists(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (bool, error)
	List(ctx context.Context, db DBTX, filter CommissionPlanFilter, p Pagination, s Sort) ([]*models.CommissionPlan, int64, error)
	GetActivePlans(ctx context.Context, db DBTX, companyID uuid.UUID, at time.Time) ([]*models.CommissionPlan, error)
	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (*models.CommissionPlan, error)
}

type CommissionPlanFilter struct {
	CompanyID uuid.UUID
	IsActive  *bool
	Code      *string
	Name      *string
	Effective *time.Time // return plans that are effective at this time (effective_from <= effective <= effective_to)
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type commissionPlanRepository struct {
	logger *zap.Logger
}

func NewCommissionPlanRepository(logger *zap.Logger) CommissionPlanRepository {
	return &commissionPlanRepository{
		logger: logger.Named("sales_commission_plan_repo"),
	}
}

// Helpers

func (r *commissionPlanRepository) nullUUIDParam(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func (r *commissionPlanRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *commissionPlanRepository) validatePagination(p Pagination) (int, int) {
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

func (r *commissionPlanRepository) buildFilter(filter CommissionPlanFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
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
		conds = append(conds, fmt.Sprintf("name = $%d", idx))
		args = append(args, *filter.Name)
		idx++
	}
	if filter.Effective != nil {
		conds = append(conds, fmt.Sprintf("effective_from <= $%d AND (effective_to IS NULL OR effective_to >= $%d)", idx, idx))
		args = append(args, *filter.Effective)
		idx++
		// Note: we reuse the same argument index for both sides because the value is the same.
		// The SQL will look like: effective_from <= $1 AND (effective_to IS NULL OR effective_to >= $1)
		// This is correct, but we must ensure idx is incremented only once.
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

func (r *commissionPlanRepository) scanCommissionPlan(s scanner) (*models.CommissionPlan, error) {
	var plan models.CommissionPlan
	var description sql.NullString
	var effectiveTo sql.NullTime
	var createdBy, updatedBy uuid.NullUUID

	err := s.Scan(
		&plan.PlanID,
		&plan.CompanyID,
		&plan.Code,
		&plan.Name,
		&description,
		&plan.EffectiveFrom,
		&effectiveTo,
		&plan.IsActive,
		&plan.CreatedAt,
		&plan.UpdatedAt,
		&createdBy,
		&updatedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, salesErrors.ErrNotFound
		}
		return nil, fmt.Errorf("scan commission plan: %w", err)
	}
	if description.Valid {
		plan.Description = &description.String
	}
	if effectiveTo.Valid {
		plan.EffectiveTo = &effectiveTo.Time
	}
	if createdBy.Valid {
		plan.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		plan.UpdatedBy = &updatedBy.UUID
	}
	return &plan, nil
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (r *commissionPlanRepository) Create(ctx context.Context, db DBTX, plan *models.CommissionPlan) error {
	query := `
		INSERT INTO sales.commission_plans (
			plan_id, company_id, code, name, description,
			effective_from, effective_to, is_active,
			created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW(), $9, $10)
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		plan.PlanID,
		plan.CompanyID,
		plan.Code,
		plan.Name,
		plan.Description,
		plan.EffectiveFrom,
		plan.EffectiveTo,
		plan.IsActive,
		r.nullUUIDParam(plan.CreatedBy),
		r.nullUUIDParam(plan.UpdatedBy),
	).Scan(&plan.CreatedAt, &plan.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create commission plan", zap.Error(err))
		return fmt.Errorf("create commission plan: %w", err)
	}
	return nil
}

func (r *commissionPlanRepository) GetByID(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (*models.CommissionPlan, error) {
	query := `
		SELECT plan_id, company_id, code, name, description,
			effective_from, effective_to, is_active,
			created_at, updated_at, created_by, updated_by
		FROM sales.commission_plans
		WHERE plan_id = $1 AND company_id = $2
	`
	row := db.QueryRowContext(ctx, query, planID, companyID)
	return r.scanCommissionPlan(row)
}

func (r *commissionPlanRepository) GetByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (*models.CommissionPlan, error) {
	query := `
		SELECT plan_id, company_id, code, name, description,
			effective_from, effective_to, is_active,
			created_at, updated_at, created_by, updated_by
		FROM sales.commission_plans
		WHERE company_id = $1 AND code = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, code)
	return r.scanCommissionPlan(row)
}

func (r *commissionPlanRepository) Update(ctx context.Context, db DBTX, plan *models.CommissionPlan) error {
	query := `
		UPDATE sales.commission_plans
		SET code = $3,
			name = $4,
			description = $5,
			effective_from = $6,
			effective_to = $7,
			is_active = $8,
			updated_at = NOW(),
			updated_by = $9
		WHERE plan_id = $1 AND company_id = $2
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		plan.PlanID,
		plan.CompanyID,
		plan.Code,
		plan.Name,
		plan.Description,
		plan.EffectiveFrom,
		plan.EffectiveTo,
		plan.IsActive,
		r.nullUUIDParam(plan.UpdatedBy),
	).Scan(&plan.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to update commission plan", zap.Error(err))
		return fmt.Errorf("update commission plan: %w", err)
	}
	return nil
}

func (r *commissionPlanRepository) Delete(ctx context.Context, db DBTX, companyID, planID uuid.UUID) error {
	query := `DELETE FROM sales.commission_plans WHERE plan_id = $1 AND company_id = $2`
	result, err := db.ExecContext(ctx, query, planID, companyID)
	if err != nil {
		return fmt.Errorf("delete commission plan: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

func (r *commissionPlanRepository) Exists(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.commission_plans WHERE plan_id = $1 AND company_id = $2)`
	err := db.QueryRowContext(ctx, query, planID, companyID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists commission plan: %w", err)
	}
	return exists, nil
}

func (r *commissionPlanRepository) List(ctx context.Context, db DBTX, filter CommissionPlanFilter, p Pagination, s Sort) ([]*models.CommissionPlan, int64, error) {
	where, args := r.buildFilter(filter)
	if where == "" && filter.CompanyID == uuid.Nil {
		return nil, 0, fmt.Errorf("list requires company_id filter")
	}
	// Ensure company_id is always present if no filter
	if filter.CompanyID != uuid.Nil && where == "" {
		where = "WHERE company_id = $1"
		args = []interface{}{filter.CompanyID}
	}

	allowedSort := map[string]bool{
		"code":           true,
		"name":           true,
		"effective_from": true,
		"effective_to":   true,
		"is_active":      true,
		"created_at":     true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY created_at DESC"
	}
	limit, offset := r.validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sales.commission_plans %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count commission plans: %w", err)
	}
	if total == 0 {
		return []*models.CommissionPlan{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT plan_id, company_id, code, name, description,
			effective_from, effective_to, is_active,
			created_at, updated_at, created_by, updated_by
		FROM sales.commission_plans
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list commission plans: %w", err)
	}
	defer rows.Close()

	var result []*models.CommissionPlan
	for rows.Next() {
		plan, err := r.scanCommissionPlan(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, plan)
	}
	return result, total, rows.Err()
}

func (r *commissionPlanRepository) GetActivePlans(ctx context.Context, db DBTX, companyID uuid.UUID, at time.Time) ([]*models.CommissionPlan, error) {
	query := `
		SELECT plan_id, company_id, code, name, description,
			effective_from, effective_to, is_active,
			created_at, updated_at, created_by, updated_by
		FROM sales.commission_plans
		WHERE company_id = $1
			AND is_active = true
			AND effective_from <= $2
			AND (effective_to IS NULL OR effective_to >= $2)
		ORDER BY effective_from DESC
	`
	rows, err := db.QueryContext(ctx, query, companyID, at)
	if err != nil {
		return nil, fmt.Errorf("get active plans: %w", err)
	}
	defer rows.Close()

	var result []*models.CommissionPlan
	for rows.Next() {
		plan, err := r.scanCommissionPlan(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, plan)
	}
	return result, rows.Err()
}

func (r *commissionPlanRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (*models.CommissionPlan, error) {
	query := `
		SELECT plan_id, company_id, code, name, description,
			effective_from, effective_to, is_active,
			created_at, updated_at, created_by, updated_by
		FROM sales.commission_plans
		WHERE plan_id = $1 AND company_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, planID, companyID)
	return r.scanCommissionPlan(row)
}
