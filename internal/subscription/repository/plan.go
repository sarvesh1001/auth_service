// repository/plan.go
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/datatypes"

	"auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/models"
)

// ---------------------------------------------------------------------
// PlanRepository Interface
// ---------------------------------------------------------------------

type PlanRepository interface {
	Create(ctx context.Context, db DBTX, plan *models.Plan) error
	Update(ctx context.Context, db DBTX, plan *models.Plan) error
	Delete(ctx context.Context, db DBTX, companyID, planID uuid.UUID) error

	GetByID(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (*models.Plan, error)
	GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.Plan, error)
	GetWithItems(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (*models.Plan, error)
	GetWithCatalog(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (*models.Plan, error)

	List(ctx context.Context, db DBTX, filter PlanFilter, p Pagination, s Sort) ([]*models.Plan, int64, error)
	ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Plan, error)

	Exists(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (bool, error)
	ExistsByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error)

	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.Plan, int64, error)

	SetActive(ctx context.Context, db DBTX, companyID, planID uuid.UUID) error
	SetInactive(ctx context.Context, db DBTX, companyID, planID uuid.UUID) error

	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (*models.Plan, error)
}

// ---------------------------------------------------------------------
// Filter
// ---------------------------------------------------------------------

type PlanFilter struct {
	CompanyID uuid.UUID

	PlanIDs []uuid.UUID

	Name *string

	BusinessModelID *int16

	BillingPolicyID *uuid.UUID

	RenewalPolicyID *uuid.UUID

	PausePolicyID *uuid.UUID

	ProrationPolicyID *uuid.UUID

	IsActive *bool
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------

type planRepository struct {
	logger *zap.Logger
}

func NewPlanRepository(logger *zap.Logger) PlanRepository {
	return &planRepository{
		logger: logger.Named("subscription_plan_repo"),
	}
}

const planTable = "subscription.plans"

func (r *planRepository) scanPlan(s scanner) (*models.Plan, error) {
	var p models.Plan
	var desc, cancelPolicy, metadata sql.NullString
	var deletedAt sql.NullTime
	err := s.Scan(
		&p.PlanID,
		&p.CompanyID,
		&p.Name,
		&p.BusinessModelID,
		&desc,
		&p.BillingPolicyID,
		&p.RenewalPolicyID,
		&p.PausePolicyID,
		&p.ProrationPolicyID,
		&p.DurationDays,
		&cancelPolicy,
		&metadata,
		&p.IsActive,
		&p.CreatedAt,
		&p.UpdatedAt,
		&deletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan plan: %w", err)
	}
	if desc.Valid {
		p.Description = &desc.String
	}
	if cancelPolicy.Valid {
		p.CancellationPolicy = &cancelPolicy.String
	}
	if metadata.Valid {
		p.Metadata = datatypes.JSON(metadata.String) // ✅ fixed
	}
	if deletedAt.Valid {
		p.DeletedAt.Time = deletedAt.Time
		p.DeletedAt.Valid = true
	}
	return &p, nil
}

func (r *planRepository) buildPlanFilter(filter PlanFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	// CompanyID is required – we always include it to ensure multi‑tenancy
	conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
	args = append(args, filter.CompanyID)
	idx++

	if len(filter.PlanIDs) > 0 {
		placeholders := make([]string, len(filter.PlanIDs))
		for i, id := range filter.PlanIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("plan_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.Name != nil {
		conds = append(conds, fmt.Sprintf("name = $%d", idx))
		args = append(args, *filter.Name)
		idx++
	}
	if filter.BusinessModelID != nil {
		conds = append(conds, fmt.Sprintf("business_model_id = $%d", idx))
		args = append(args, *filter.BusinessModelID)
		idx++
	}
	if filter.BillingPolicyID != nil {
		conds = append(conds, fmt.Sprintf("billing_policy_id = $%d", idx))
		args = append(args, *filter.BillingPolicyID)
		idx++
	}
	if filter.RenewalPolicyID != nil {
		conds = append(conds, fmt.Sprintf("renewal_policy_id = $%d", idx))
		args = append(args, *filter.RenewalPolicyID)
		idx++
	}
	if filter.PausePolicyID != nil {
		conds = append(conds, fmt.Sprintf("pause_policy_id = $%d", idx))
		args = append(args, *filter.PausePolicyID)
		idx++
	}
	if filter.ProrationPolicyID != nil {
		conds = append(conds, fmt.Sprintf("proration_policy_id = $%d", idx))
		args = append(args, *filter.ProrationPolicyID)
		idx++
	}
	if filter.IsActive != nil {
		conds = append(conds, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}

	// ignore soft‑deleted records
	conds = append(conds, "deleted_at IS NULL")

	return "WHERE " + strings.Join(conds, " AND "), args
}

var planAllowedSort = map[string]bool{
	"plan_id":           true,
	"name":              true,
	"business_model_id": true,
	"duration_days":     true,
	"is_active":         true,
	"created_at":        true,
	"updated_at":        true,
}

// ---------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------

func (r *planRepository) Create(ctx context.Context, db DBTX, plan *models.Plan) error {
	query := `
		INSERT INTO subscription.plans (
			plan_id, company_id, name, business_model_id, description,
			billing_policy_id, renewal_policy_id, pause_policy_id, proration_policy_id,
			duration_days, cancellation_policy, metadata, is_active,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), NOW())
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		plan.PlanID,
		plan.CompanyID,
		plan.Name,
		plan.BusinessModelID,
		plan.Description,
		plan.BillingPolicyID,
		plan.RenewalPolicyID,
		plan.PausePolicyID,
		plan.ProrationPolicyID,
		plan.DurationDays,
		plan.CancellationPolicy,
		plan.Metadata,
		plan.IsActive,
	).Scan(&plan.CreatedAt, &plan.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create plan: %w", err)
	}
	return nil
}

func (r *planRepository) Update(ctx context.Context, db DBTX, plan *models.Plan) error {
	query := `
		UPDATE subscription.plans SET
			name = $3,
			business_model_id = $4,
			description = $5,
			billing_policy_id = $6,
			renewal_policy_id = $7,
			pause_policy_id = $8,
			proration_policy_id = $9,
			duration_days = $10,
			cancellation_policy = $11,
			metadata = $12,
			is_active = $13,
			updated_at = NOW()
		WHERE plan_id = $1 AND company_id = $2 AND deleted_at IS NULL
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		plan.PlanID,
		plan.CompanyID,
		plan.Name,
		plan.BusinessModelID,
		plan.Description,
		plan.BillingPolicyID,
		plan.RenewalPolicyID,
		plan.PausePolicyID,
		plan.ProrationPolicyID,
		plan.DurationDays,
		plan.CancellationPolicy,
		plan.Metadata,
		plan.IsActive,
	).Scan(&plan.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return fmt.Errorf("update plan: %w", err)
	}
	return nil
}

func (r *planRepository) Delete(ctx context.Context, db DBTX, companyID, planID uuid.UUID) error {
	// Soft delete
	query := `UPDATE subscription.plans SET deleted_at = NOW() WHERE plan_id = $1 AND company_id = $2 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, planID, companyID)
	if err != nil {
		return fmt.Errorf("soft delete plan: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------
// Single Fetch
// ---------------------------------------------------------------------

func (r *planRepository) GetByID(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (*models.Plan, error) {
	query := `
		SELECT plan_id, company_id, name, business_model_id, description,
			billing_policy_id, renewal_policy_id, pause_policy_id, proration_policy_id,
			duration_days, cancellation_policy, metadata, is_active,
			created_at, updated_at, deleted_at
		FROM subscription.plans
		WHERE plan_id = $1 AND company_id = $2 AND deleted_at IS NULL
	`
	row := db.QueryRowContext(ctx, query, planID, companyID)
	return r.scanPlan(row)
}

func (r *planRepository) GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.Plan, error) {
	query := `
		SELECT plan_id, company_id, name, business_model_id, description,
			billing_policy_id, renewal_policy_id, pause_policy_id, proration_policy_id,
			duration_days, cancellation_policy, metadata, is_active,
			created_at, updated_at, deleted_at
		FROM subscription.plans
		WHERE company_id = $1 AND name = $2 AND deleted_at IS NULL
	`
	row := db.QueryRowContext(ctx, query, companyID, name)
	return r.scanPlan(row)
}

// ---------------------------------------------------------------------
// Loading with Associations
// ---------------------------------------------------------------------

func (r *planRepository) GetWithItems(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (*models.Plan, error) {
	plan, err := r.GetByID(ctx, db, companyID, planID)
	if err != nil {
		return nil, err
	}

	// Load PlanItems
	itemRepo := NewPlanItemRepository(r.logger)
	items, _, err := itemRepo.List(ctx, db, PlanItemFilter{
		PlanID:   planID,
		IsActive: ptrBool(true), // load active items by default
	}, Pagination{Limit: 1000}, Sort{})
	if err != nil {
		return nil, fmt.Errorf("load plan items: %w", err)
	}
	// Convert []*models.PlanItem to []models.PlanItem
	planItems := make([]models.PlanItem, len(items))
	for i, item := range items {
		if item != nil {
			planItems[i] = *item
		}
	}
	plan.PlanItems = planItems
	return plan, nil
}

func (r *planRepository) GetWithCatalog(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (*models.Plan, error) {
	// Load plan with items, and for each item load entitlements and benefits
	plan, err := r.GetWithItems(ctx, db, companyID, planID)
	if err != nil {
		return nil, err
	}

	// Load entitlements and benefits for each item
	entRepo := NewEntitlementRepository(r.logger)
	benRepo := NewBenefitRepository(r.logger)

	for i := range plan.PlanItems {
		item := &plan.PlanItems[i] // use pointer to modify

		// Entitlements
		ents, _, err := entRepo.List(ctx, db, EntitlementFilter{
			PlanItemID: &item.PlanItemID,
			IsEnabled:  ptrBool(true),
		}, Pagination{Limit: 1000}, Sort{})
		if err != nil {
			return nil, fmt.Errorf("load entitlements for item %s: %w", item.PlanItemID, err)
		}
		// Convert []*models.Entitlement to []models.Entitlement
		entitlements := make([]models.Entitlement, len(ents))
		for j, e := range ents {
			if e != nil {
				entitlements[j] = *e
			}
		}
		item.Entitlements = entitlements

		// Benefits
		bens, _, err := benRepo.List(ctx, db, BenefitFilter{
			PlanItemID: &item.PlanItemID,
		}, Pagination{Limit: 1000}, Sort{})
		if err != nil {
			return nil, fmt.Errorf("load benefits for item %s: %w", item.PlanItemID, err)
		}
		// Convert []*models.Benefit to []models.Benefit
		benefits := make([]models.Benefit, len(bens))
		for j, b := range bens {
			if b != nil {
				benefits[j] = *b
			}
		}
		item.Benefits = benefits
	}
	return plan, nil
}

// ---------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------

func (r *planRepository) List(ctx context.Context, db DBTX, filter PlanFilter, p Pagination, s Sort) ([]*models.Plan, int64, error) {
	where, args := r.buildPlanFilter(filter)
	orderBy, err := validateSort(s, planAllowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY name"
	}
	limit, offset := validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", planTable, where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count plans: %w", err)
	}
	if total == 0 {
		return []*models.Plan{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT plan_id, company_id, name, business_model_id, description,
			billing_policy_id, renewal_policy_id, pause_policy_id, proration_policy_id,
			duration_days, cancellation_policy, metadata, is_active,
			created_at, updated_at, deleted_at
		FROM %s
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, planTable, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list plans: %w", err)
	}
	defer rows.Close()

	var result []*models.Plan
	for rows.Next() {
		plan, err := r.scanPlan(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, plan)
	}
	return result, total, rows.Err()
}

func (r *planRepository) ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Plan, error) {
	filter := PlanFilter{
		CompanyID: companyID,
		IsActive:  ptrBool(true),
	}
	plans, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{})
	return plans, err
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

func (r *planRepository) Exists(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.plans WHERE plan_id = $1 AND company_id = $2 AND deleted_at IS NULL)`
	err := db.QueryRowContext(ctx, query, planID, companyID).Scan(&exists)
	return exists, err
}

func (r *planRepository) ExistsByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.plans WHERE company_id = $1 AND name = $2 AND deleted_at IS NULL)`
	err := db.QueryRowContext(ctx, query, companyID, name).Scan(&exists)
	return exists, err
}

// ---------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------

func (r *planRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.Plan, int64, error) {
	pattern := "%" + query + "%"
	where := "WHERE company_id = $1 AND deleted_at IS NULL AND (name ILIKE $2 OR description ILIKE $2)"
	args := []interface{}{companyID, pattern}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", planTable, where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search plans count: %w", err)
	}
	if total == 0 {
		return []*models.Plan{}, 0, nil
	}

	baseQuery := `
		SELECT plan_id, company_id, name, business_model_id, description,
			billing_policy_id, renewal_policy_id, pause_policy_id, proration_policy_id,
			duration_days, cancellation_policy, metadata, is_active,
			created_at, updated_at, deleted_at
		FROM subscription.plans
	`
	querySQL := fmt.Sprintf(`%s %s ORDER BY name LIMIT $%d OFFSET $%d`, baseQuery, where, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search plans: %w", err)
	}
	defer rows.Close()

	var result []*models.Plan
	for rows.Next() {
		plan, err := r.scanPlan(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, plan)
	}
	return result, total, rows.Err()
}

// ---------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------

func (r *planRepository) SetActive(ctx context.Context, db DBTX, companyID, planID uuid.UUID) error {
	query := `UPDATE subscription.plans SET is_active = true, updated_at = NOW() WHERE plan_id = $1 AND company_id = $2 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, planID, companyID)
	if err != nil {
		return fmt.Errorf("set active: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *planRepository) SetInactive(ctx context.Context, db DBTX, companyID, planID uuid.UUID) error {
	query := `UPDATE subscription.plans SET is_active = false, updated_at = NOW() WHERE plan_id = $1 AND company_id = $2 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, planID, companyID)
	if err != nil {
		return fmt.Errorf("set inactive: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------

func (r *planRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (*models.Plan, error) {
	query := `
		SELECT plan_id, company_id, name, business_model_id, description,
			billing_policy_id, renewal_policy_id, pause_policy_id, proration_policy_id,
			duration_days, cancellation_policy, metadata, is_active,
			created_at, updated_at, deleted_at
		FROM subscription.plans
		WHERE plan_id = $1 AND company_id = $2 AND deleted_at IS NULL
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, planID, companyID)
	return r.scanPlan(row)
}
