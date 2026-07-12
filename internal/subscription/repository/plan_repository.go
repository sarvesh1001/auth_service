// FILE: repository/plan_repository.go

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

	"auth-service/internal/subscription/models"
	"auth-service/internal/subscription/models/enums"
)

// -------------------------------------------------------------------------
// PlanRepository Interface (unchanged)
// -------------------------------------------------------------------------

type PlanRepository interface {
	Create(ctx context.Context, db DBTX, plan *models.Plan) error
	GetByID(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (*models.Plan, error)
	GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.Plan, error)
	Update(ctx context.Context, db DBTX, plan *models.Plan) error
	Delete(ctx context.Context, db DBTX, companyID, planID uuid.UUID) error

	Publish(ctx context.Context, db DBTX, companyID, planID uuid.UUID, publishedBy uuid.UUID) error
	Unpublish(ctx context.Context, db DBTX, companyID, planID uuid.UUID) error
	IncrementVersion(ctx context.Context, db DBTX, companyID, planID uuid.UUID) error

	Activate(ctx context.Context, db DBTX, companyID, planID uuid.UUID) error
	Deactivate(ctx context.Context, db DBTX, companyID, planID uuid.UUID) error
	SoftDelete(ctx context.Context, db DBTX, companyID, planID uuid.UUID) error
	Restore(ctx context.Context, db DBTX, companyID, planID uuid.UUID) error

	Exists(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (bool, error)
	ExistsByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error)
	IsActive(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (bool, error)
	IsPublished(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (bool, error)

	List(ctx context.Context, db DBTX, filter PlanFilter, p Pagination, s Sort) ([]*models.Plan, int64, error)
	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.Plan, int64, error)
	GetActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Plan, error)
	GetPublished(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Plan, error)
	GetByPlanType(ctx context.Context, db DBTX, companyID uuid.UUID, planType enums.PlanType) ([]*models.Plan, error)
	GetByBillingPolicy(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) ([]*models.Plan, error)
	GetByRenewalPolicy(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) ([]*models.Plan, error)
	GetByPausePolicy(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) ([]*models.Plan, error)
	GetByProrationPolicy(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) ([]*models.Plan, error)

	GetPlanTotalPrice(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (decimal.Decimal, error)

	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (*models.Plan, error)
}

// -------------------------------------------------------------------------
// Filter, Pagination, Sort (unchanged)
// -------------------------------------------------------------------------

type PlanFilter struct {
	CompanyID         uuid.UUID
	PlanIDs           []uuid.UUID
	Name              *string
	PlanType          *enums.PlanType
	BillingPolicyID   *uuid.UUID
	RenewalPolicyID   *uuid.UUID
	PausePolicyID     *uuid.UUID
	ProrationPolicyID *uuid.UUID
	DurationDaysMin   *int
	DurationDaysMax   *int
	VersionMin        *int
	VersionMax        *int
	IsActive          *bool
	IsPublished       *bool
	PublishedFrom     *time.Time
	PublishedTo       *time.Time
	CreatedFrom       *time.Time
	CreatedTo         *time.Time
	UpdatedFrom       *time.Time
	UpdatedTo         *time.Time
	Deleted           bool // if true, include soft-deleted records
}

// -------------------------------------------------------------------------
// Mapping helpers (unchanged)
// -------------------------------------------------------------------------

var planTypeToID = map[enums.PlanType]int{
	enums.PlanTypeRecurring:  1,
	enums.PlanTypeOneTime:    2,
	enums.PlanTypeUsageBased: 3,
	enums.PlanTypeContract:   4,
}

var idToPlanType = map[int]enums.PlanType{
	1: enums.PlanTypeRecurring,
	2: enums.PlanTypeOneTime,
	3: enums.PlanTypeUsageBased,
	4: enums.PlanTypeContract,
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type planRepository struct {
	logger *zap.Logger
}

func NewPlanRepository(logger *zap.Logger) PlanRepository {
	return &planRepository{
		logger: logger.Named("subscription_plan_repo"),
	}
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (r *planRepository) Create(ctx context.Context, db DBTX, plan *models.Plan) error {
	planTypeID, ok := planTypeToID[plan.PlanType]
	if !ok {
		return fmt.Errorf("invalid plan type: %s", plan.PlanType)
	}
	query := `
		INSERT INTO subscription.plans (
			plan_id, company_id, name, plan_type_id, description,
			billing_policy_id, renewal_policy_id, pause_policy_id, proration_policy_id,
			duration_days, cancellation_policy, metadata,
			is_active, version, published_at, published_by,
			created_at, updated_at, deleted_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
	`
	r.logger.Info("creating plan",
		zap.String("plan_id", plan.PlanID.String()),
		zap.String("company_id", plan.CompanyID.String()),
		zap.String("name", plan.Name))
	_, err := db.ExecContext(ctx, query,
		plan.PlanID,
		plan.CompanyID,
		plan.Name,
		planTypeID,
		plan.Description,
		plan.BillingPolicyID,
		plan.RenewalPolicyID,
		plan.PausePolicyID,
		plan.ProrationPolicyID,
		plan.DurationDays,
		plan.CancellationPolicy,
		plan.Metadata,
		plan.IsActive,
		plan.Version,
		plan.PublishedAt,
		plan.PublishedBy,
		plan.CreatedAt,
		plan.UpdatedAt,
		plan.DeletedAt,
	)
	if err != nil {
		r.logger.Error("failed to create plan", zap.Error(err))
		return fmt.Errorf("create plan: %w", err)
	}
	return nil
}

func (r *planRepository) GetByID(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (*models.Plan, error) {
	query := `
		SELECT plan_id, company_id, name, plan_type_id, description,
		       billing_policy_id, renewal_policy_id, pause_policy_id, proration_policy_id,
		       duration_days, cancellation_policy, metadata,
		       is_active, version, published_at, published_by,
		       created_at, updated_at, deleted_at
		FROM subscription.plans
		WHERE company_id = $1 AND plan_id = $2
	`
	var plan models.Plan
	var planTypeID int
	err := db.QueryRowContext(ctx, query, companyID, planID).Scan(
		&plan.PlanID,
		&plan.CompanyID,
		&plan.Name,
		&planTypeID,
		&plan.Description,
		&plan.BillingPolicyID,
		&plan.RenewalPolicyID,
		&plan.PausePolicyID,
		&plan.ProrationPolicyID,
		&plan.DurationDays,
		&plan.CancellationPolicy,
		&plan.Metadata,
		&plan.IsActive,
		&plan.Version,
		&plan.PublishedAt,
		&plan.PublishedBy,
		&plan.CreatedAt,
		&plan.UpdatedAt,
		&plan.DeletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get plan by ID", zap.Error(err))
		return nil, fmt.Errorf("get plan by ID: %w", err)
	}
	planType, ok := idToPlanType[planTypeID]
	if !ok {
		return nil, fmt.Errorf("unknown plan_type_id: %d", planTypeID)
	}
	plan.PlanType = planType
	return &plan, nil
}

func (r *planRepository) GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.Plan, error) {
	query := `
		SELECT plan_id, company_id, name, plan_type_id, description,
		       billing_policy_id, renewal_policy_id, pause_policy_id, proration_policy_id,
		       duration_days, cancellation_policy, metadata,
		       is_active, version, published_at, published_by,
		       created_at, updated_at, deleted_at
		FROM subscription.plans
		WHERE company_id = $1 AND name = $2
	`
	var plan models.Plan
	var planTypeID int
	err := db.QueryRowContext(ctx, query, companyID, name).Scan(
		&plan.PlanID,
		&plan.CompanyID,
		&plan.Name,
		&planTypeID,
		&plan.Description,
		&plan.BillingPolicyID,
		&plan.RenewalPolicyID,
		&plan.PausePolicyID,
		&plan.ProrationPolicyID,
		&plan.DurationDays,
		&plan.CancellationPolicy,
		&plan.Metadata,
		&plan.IsActive,
		&plan.Version,
		&plan.PublishedAt,
		&plan.PublishedBy,
		&plan.CreatedAt,
		&plan.UpdatedAt,
		&plan.DeletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get plan by name", zap.String("name", name), zap.Error(err))
		return nil, fmt.Errorf("get plan by name: %w", err)
	}
	planType, ok := idToPlanType[planTypeID]
	if !ok {
		return nil, fmt.Errorf("unknown plan_type_id: %d", planTypeID)
	}
	plan.PlanType = planType
	return &plan, nil
}

func (r *planRepository) Update(ctx context.Context, db DBTX, plan *models.Plan) error {
	planTypeID, ok := planTypeToID[plan.PlanType]
	if !ok {
		return fmt.Errorf("invalid plan type: %s", plan.PlanType)
	}
	query := `
		UPDATE subscription.plans
		SET name = $1,
		    plan_type_id = $2,
		    description = $3,
		    billing_policy_id = $4,
		    renewal_policy_id = $5,
		    pause_policy_id = $6,
		    proration_policy_id = $7,
		    duration_days = $8,
		    cancellation_policy = $9,
		    metadata = $10,
		    is_active = $11,
		    version = $12,
		    published_at = $13,
		    published_by = $14,
		    updated_at = $15,
		    deleted_at = $16
		WHERE company_id = $17 AND plan_id = $18
	`
	r.logger.Info("updating plan",
		zap.String("plan_id", plan.PlanID.String()),
		zap.String("company_id", plan.CompanyID.String()),
		zap.Bool("is_active", plan.IsActive),
		zap.Int("version", plan.Version))

	result, err := db.ExecContext(ctx, query,
		plan.Name,
		planTypeID,
		plan.Description,
		plan.BillingPolicyID,
		plan.RenewalPolicyID,
		plan.PausePolicyID,
		plan.ProrationPolicyID,
		plan.DurationDays,
		plan.CancellationPolicy,
		plan.Metadata,
		plan.IsActive,
		plan.Version,
		plan.PublishedAt,
		plan.PublishedBy,
		plan.UpdatedAt,
		plan.DeletedAt,
		plan.CompanyID,
		plan.PlanID,
	)
	if err != nil {
		r.logger.Error("failed to update plan", zap.Error(err))
		return fmt.Errorf("update plan: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		errMsg := fmt.Sprintf("no plan found with company_id %s and plan_id %s", plan.CompanyID.String(), plan.PlanID.String())
		r.logger.Warn("update affected 0 rows", zap.String("error", errMsg))
		return fmt.Errorf("%s", errMsg)
	}
	return nil
}

func (r *planRepository) Delete(ctx context.Context, db DBTX, companyID, planID uuid.UUID) error {
	query := `DELETE FROM subscription.plans WHERE company_id = $1 AND plan_id = $2`
	r.logger.Info("deleting plan",
		zap.String("plan_id", planID.String()),
		zap.String("company_id", companyID.String()))
	result, err := db.ExecContext(ctx, query, companyID, planID)
	if err != nil {
		r.logger.Error("failed to delete plan", zap.Error(err))
		return fmt.Errorf("delete plan: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		errMsg := fmt.Sprintf("no plan found with company_id %s and plan_id %s", companyID.String(), planID.String())
		r.logger.Warn("delete affected 0 rows", zap.String("error", errMsg))
		return fmt.Errorf("%s", errMsg)
	}
	return nil
}

// -------------------------------------------------------------------------
// Publishing / Versioning
// -------------------------------------------------------------------------

func (r *planRepository) Publish(ctx context.Context, db DBTX, companyID, planID uuid.UUID, publishedBy uuid.UUID) error {
	query := `
		UPDATE subscription.plans
		SET published_at = NOW(), published_by = $1, updated_at = NOW()
		WHERE company_id = $2 AND plan_id = $3 AND is_active = true
	`
	r.logger.Info("publishing plan",
		zap.String("plan_id", planID.String()),
		zap.String("company_id", companyID.String()),
		zap.String("published_by", publishedBy.String()))
	result, err := db.ExecContext(ctx, query, publishedBy, companyID, planID)
	if err != nil {
		r.logger.Error("failed to publish plan", zap.Error(err))
		return fmt.Errorf("publish plan: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		errMsg := fmt.Sprintf("no active plan found with company_id %s and plan_id %s", companyID.String(), planID.String())
		r.logger.Warn("publish affected 0 rows", zap.String("error", errMsg))
		return fmt.Errorf("%s", errMsg)
	}
	return nil
}

func (r *planRepository) Unpublish(ctx context.Context, db DBTX, companyID, planID uuid.UUID) error {
	query := `
		UPDATE subscription.plans
		SET published_at = NULL, published_by = NULL, updated_at = NOW()
		WHERE company_id = $1 AND plan_id = $2
	`
	r.logger.Info("unpublishing plan",
		zap.String("plan_id", planID.String()),
		zap.String("company_id", companyID.String()))
	result, err := db.ExecContext(ctx, query, companyID, planID)
	if err != nil {
		r.logger.Error("failed to unpublish plan", zap.Error(err))
		return fmt.Errorf("unpublish plan: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		errMsg := fmt.Sprintf("no plan found with company_id %s and plan_id %s", companyID.String(), planID.String())
		r.logger.Warn("unpublish affected 0 rows", zap.String("error", errMsg))
		return fmt.Errorf("%s", errMsg)
	}
	return nil
}

func (r *planRepository) IncrementVersion(ctx context.Context, db DBTX, companyID, planID uuid.UUID) error {
	query := `
		UPDATE subscription.plans
		SET version = version + 1, updated_at = NOW()
		WHERE company_id = $1 AND plan_id = $2
	`
	r.logger.Info("incrementing plan version",
		zap.String("plan_id", planID.String()),
		zap.String("company_id", companyID.String()))
	result, err := db.ExecContext(ctx, query, companyID, planID)
	if err != nil {
		r.logger.Error("failed to increment version", zap.Error(err))
		return fmt.Errorf("increment version: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		errMsg := fmt.Sprintf("no plan found with company_id %s and plan_id %s", companyID.String(), planID.String())
		r.logger.Warn("increment version affected 0 rows", zap.String("error", errMsg))
		return fmt.Errorf("%s", errMsg)
	}
	return nil
}

// -------------------------------------------------------------------------
// Status / Lifecycle
// -------------------------------------------------------------------------

func (r *planRepository) Activate(ctx context.Context, db DBTX, companyID, planID uuid.UUID) error {
	query := `UPDATE subscription.plans SET is_active = true, updated_at = NOW() WHERE company_id = $1 AND plan_id = $2`
	r.logger.Info("activating plan",
		zap.String("plan_id", planID.String()),
		zap.String("company_id", companyID.String()))
	result, err := db.ExecContext(ctx, query, companyID, planID)
	if err != nil {
		r.logger.Error("failed to activate plan", zap.Error(err))
		return fmt.Errorf("activate plan: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		errMsg := fmt.Sprintf("no plan found with company_id %s and plan_id %s", companyID.String(), planID.String())
		r.logger.Warn("activate affected 0 rows", zap.String("error", errMsg))
		return fmt.Errorf("%s", errMsg)
	}
	return nil
}

func (r *planRepository) Deactivate(ctx context.Context, db DBTX, companyID, planID uuid.UUID) error {
	query := `UPDATE subscription.plans SET is_active = false, updated_at = NOW() WHERE company_id = $1 AND plan_id = $2`
	r.logger.Info("deactivating plan",
		zap.String("plan_id", planID.String()),
		zap.String("company_id", companyID.String()))
	result, err := db.ExecContext(ctx, query, companyID, planID)
	if err != nil {
		r.logger.Error("failed to deactivate plan", zap.Error(err))
		return fmt.Errorf("deactivate plan: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		errMsg := fmt.Sprintf("no plan found with company_id %s and plan_id %s", companyID.String(), planID.String())
		r.logger.Warn("deactivate affected 0 rows", zap.String("error", errMsg))
		return fmt.Errorf("%s", errMsg)
	}
	return nil
}

func (r *planRepository) SoftDelete(ctx context.Context, db DBTX, companyID, planID uuid.UUID) error {
	query := `UPDATE subscription.plans SET deleted_at = NOW() WHERE company_id = $1 AND plan_id = $2`
	r.logger.Info("soft deleting plan",
		zap.String("plan_id", planID.String()),
		zap.String("company_id", companyID.String()))
	result, err := db.ExecContext(ctx, query, companyID, planID)
	if err != nil {
		r.logger.Error("failed to soft delete plan", zap.Error(err))
		return fmt.Errorf("soft delete plan: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		errMsg := fmt.Sprintf("no plan found with company_id %s and plan_id %s", companyID.String(), planID.String())
		r.logger.Warn("soft delete affected 0 rows", zap.String("error", errMsg))
		return fmt.Errorf("%s", errMsg)
	}
	return nil
}

func (r *planRepository) Restore(ctx context.Context, db DBTX, companyID, planID uuid.UUID) error {
	query := `UPDATE subscription.plans SET deleted_at = NULL WHERE company_id = $1 AND plan_id = $2`
	r.logger.Info("restoring plan",
		zap.String("plan_id", planID.String()),
		zap.String("company_id", companyID.String()))
	result, err := db.ExecContext(ctx, query, companyID, planID)
	if err != nil {
		r.logger.Error("failed to restore plan", zap.Error(err))
		return fmt.Errorf("restore plan: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		errMsg := fmt.Sprintf("no plan found with company_id %s and plan_id %s", companyID.String(), planID.String())
		r.logger.Warn("restore affected 0 rows", zap.String("error", errMsg))
		return fmt.Errorf("%s", errMsg)
	}
	return nil
}

// -------------------------------------------------------------------------
// Validation (unchanged, but with minimal logging)
// -------------------------------------------------------------------------

func (r *planRepository) Exists(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.plans WHERE company_id = $1 AND plan_id = $2 AND deleted_at IS NULL)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, planID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check exist: %w", err)
	}
	return exists, nil
}

func (r *planRepository) ExistsByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.plans WHERE company_id = $1 AND name = $2 AND deleted_at IS NULL)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, name).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check exist by name: %w", err)
	}
	return exists, nil
}

func (r *planRepository) IsActive(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (bool, error) {
	query := `SELECT is_active FROM subscription.plans WHERE company_id = $1 AND plan_id = $2 AND deleted_at IS NULL`
	var active bool
	err := db.QueryRowContext(ctx, query, companyID, planID).Scan(&active)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("check is active: %w", err)
	}
	return active, nil
}

func (r *planRepository) IsPublished(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (bool, error) {
	query := `SELECT published_at IS NOT NULL FROM subscription.plans WHERE company_id = $1 AND plan_id = $2 AND deleted_at IS NULL`
	var published bool
	err := db.QueryRowContext(ctx, query, companyID, planID).Scan(&published)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("check is published: %w", err)
	}
	return published, nil
}

// -------------------------------------------------------------------------
// Querying (unchanged)
// -------------------------------------------------------------------------

func (r *planRepository) List(ctx context.Context, db DBTX, filter PlanFilter, p Pagination, s Sort) ([]*models.Plan, int64, error) {
	where, args := r.buildFilterConditions(filter)
	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.plans %s`, whereClause)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count plans: %w", err)
	}
	if total == 0 {
		return []*models.Plan{}, 0, nil
	}

	sortClause := ""
	if s.Field != "" {
		direction := "ASC"
		if strings.ToUpper(s.Direction) == "DESC" {
			direction = "DESC"
		}
		sortClause = fmt.Sprintf("ORDER BY %s %s", s.Field, direction)
	} else {
		sortClause = "ORDER BY created_at DESC"
	}

	query := fmt.Sprintf(`
		SELECT plan_id, company_id, name, plan_type_id, description,
		       billing_policy_id, renewal_policy_id, pause_policy_id, proration_policy_id,
		       duration_days, cancellation_policy, metadata,
		       is_active, version, published_at, published_by,
		       created_at, updated_at, deleted_at
		FROM subscription.plans
		%s %s
		LIMIT $%d OFFSET $%d
	`, whereClause, sortClause, len(args)+1, len(args)+2)

	limitArgs := append(args, p.Limit, p.Offset)
	rows, err := db.QueryContext(ctx, query, limitArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list plans: %w", err)
	}
	defer rows.Close()

	var plans []*models.Plan
	for rows.Next() {
		var plan models.Plan
		var planTypeID int
		err := rows.Scan(
			&plan.PlanID,
			&plan.CompanyID,
			&plan.Name,
			&planTypeID,
			&plan.Description,
			&plan.BillingPolicyID,
			&plan.RenewalPolicyID,
			&plan.PausePolicyID,
			&plan.ProrationPolicyID,
			&plan.DurationDays,
			&plan.CancellationPolicy,
			&plan.Metadata,
			&plan.IsActive,
			&plan.Version,
			&plan.PublishedAt,
			&plan.PublishedBy,
			&plan.CreatedAt,
			&plan.UpdatedAt,
			&plan.DeletedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan plan: %w", err)
		}
		planType, ok := idToPlanType[planTypeID]
		if !ok {
			return nil, 0, fmt.Errorf("unknown plan_type_id: %d", planTypeID)
		}
		plan.PlanType = planType
		plans = append(plans, &plan)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", err)
	}
	return plans, total, nil
}

func (r *planRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.Plan, int64, error) {
	searchPattern := "%" + query + "%"
	where := "company_id = $1 AND deleted_at IS NULL AND (name ILIKE $2 OR description ILIKE $2)"
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.plans WHERE %s`, where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, companyID, searchPattern).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count search plans: %w", err)
	}
	if total == 0 {
		return []*models.Plan{}, 0, nil
	}

	dataQuery := fmt.Sprintf(`
		SELECT plan_id, company_id, name, plan_type_id, description,
		       billing_policy_id, renewal_policy_id, pause_policy_id, proration_policy_id,
		       duration_days, cancellation_policy, metadata,
		       is_active, version, published_at, published_by,
		       created_at, updated_at, deleted_at
		FROM subscription.plans
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, 3, 4)

	rows, err := db.QueryContext(ctx, dataQuery, companyID, searchPattern, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("search plans: %w", err)
	}
	defer rows.Close()

	var plans []*models.Plan
	for rows.Next() {
		var plan models.Plan
		var planTypeID int
		err := rows.Scan(
			&plan.PlanID,
			&plan.CompanyID,
			&plan.Name,
			&planTypeID,
			&plan.Description,
			&plan.BillingPolicyID,
			&plan.RenewalPolicyID,
			&plan.PausePolicyID,
			&plan.ProrationPolicyID,
			&plan.DurationDays,
			&plan.CancellationPolicy,
			&plan.Metadata,
			&plan.IsActive,
			&plan.Version,
			&plan.PublishedAt,
			&plan.PublishedBy,
			&plan.CreatedAt,
			&plan.UpdatedAt,
			&plan.DeletedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan plan: %w", err)
		}
		planType, ok := idToPlanType[planTypeID]
		if !ok {
			return nil, 0, fmt.Errorf("unknown plan_type_id: %d", planTypeID)
		}
		plan.PlanType = planType
		plans = append(plans, &plan)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", err)
	}
	return plans, total, nil
}

// -------------------------------------------------------------------------
// Convenience Query Methods (unchanged)
// -------------------------------------------------------------------------

func (r *planRepository) GetActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Plan, error) {
	query := `
		SELECT plan_id, company_id, name, plan_type_id, description,
		       billing_policy_id, renewal_policy_id, pause_policy_id, proration_policy_id,
		       duration_days, cancellation_policy, metadata,
		       is_active, version, published_at, published_by,
		       created_at, updated_at, deleted_at
		FROM subscription.plans
		WHERE company_id = $1 AND is_active = true AND deleted_at IS NULL
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("get active plans: %w", err)
	}
	defer rows.Close()
	return r.scanPlans(rows)
}

func (r *planRepository) GetPublished(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Plan, error) {
	query := `
		SELECT plan_id, company_id, name, plan_type_id, description,
		       billing_policy_id, renewal_policy_id, pause_policy_id, proration_policy_id,
		       duration_days, cancellation_policy, metadata,
		       is_active, version, published_at, published_by,
		       created_at, updated_at, deleted_at
		FROM subscription.plans
		WHERE company_id = $1 AND published_at IS NOT NULL AND deleted_at IS NULL
		ORDER BY published_at DESC
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("get published plans: %w", err)
	}
	defer rows.Close()
	return r.scanPlans(rows)
}

func (r *planRepository) GetByPlanType(ctx context.Context, db DBTX, companyID uuid.UUID, planType enums.PlanType) ([]*models.Plan, error) {
	planTypeID, ok := planTypeToID[planType]
	if !ok {
		return nil, fmt.Errorf("invalid plan type: %s", planType)
	}
	query := `
		SELECT plan_id, company_id, name, plan_type_id, description,
		       billing_policy_id, renewal_policy_id, pause_policy_id, proration_policy_id,
		       duration_days, cancellation_policy, metadata,
		       is_active, version, published_at, published_by,
		       created_at, updated_at, deleted_at
		FROM subscription.plans
		WHERE company_id = $1 AND plan_type_id = $2 AND deleted_at IS NULL
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, companyID, planTypeID)
	if err != nil {
		return nil, fmt.Errorf("get by plan type: %w", err)
	}
	defer rows.Close()
	return r.scanPlans(rows)
}

func (r *planRepository) GetByBillingPolicy(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) ([]*models.Plan, error) {
	query := `
		SELECT plan_id, company_id, name, plan_type_id, description,
		       billing_policy_id, renewal_policy_id, pause_policy_id, proration_policy_id,
		       duration_days, cancellation_policy, metadata,
		       is_active, version, published_at, published_by,
		       created_at, updated_at, deleted_at
		FROM subscription.plans
		WHERE company_id = $1 AND billing_policy_id = $2 AND deleted_at IS NULL
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, companyID, billingPolicyID)
	if err != nil {
		return nil, fmt.Errorf("get by billing policy: %w", err)
	}
	defer rows.Close()
	return r.scanPlans(rows)
}

func (r *planRepository) GetByRenewalPolicy(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) ([]*models.Plan, error) {
	query := `
		SELECT plan_id, company_id, name, plan_type_id, description,
		       billing_policy_id, renewal_policy_id, pause_policy_id, proration_policy_id,
		       duration_days, cancellation_policy, metadata,
		       is_active, version, published_at, published_by,
		       created_at, updated_at, deleted_at
		FROM subscription.plans
		WHERE company_id = $1 AND renewal_policy_id = $2 AND deleted_at IS NULL
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, companyID, renewalPolicyID)
	if err != nil {
		return nil, fmt.Errorf("get by renewal policy: %w", err)
	}
	defer rows.Close()
	return r.scanPlans(rows)
}

func (r *planRepository) GetByPausePolicy(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) ([]*models.Plan, error) {
	query := `
		SELECT plan_id, company_id, name, plan_type_id, description,
		       billing_policy_id, renewal_policy_id, pause_policy_id, proration_policy_id,
		       duration_days, cancellation_policy, metadata,
		       is_active, version, published_at, published_by,
		       created_at, updated_at, deleted_at
		FROM subscription.plans
		WHERE company_id = $1 AND pause_policy_id = $2 AND deleted_at IS NULL
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, companyID, pausePolicyID)
	if err != nil {
		return nil, fmt.Errorf("get by pause policy: %w", err)
	}
	defer rows.Close()
	return r.scanPlans(rows)
}

func (r *planRepository) GetByProrationPolicy(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) ([]*models.Plan, error) {
	query := `
		SELECT plan_id, company_id, name, plan_type_id, description,
		       billing_policy_id, renewal_policy_id, pause_policy_id, proration_policy_id,
		       duration_days, cancellation_policy, metadata,
		       is_active, version, published_at, published_by,
		       created_at, updated_at, deleted_at
		FROM subscription.plans
		WHERE company_id = $1 AND proration_policy_id = $2 AND deleted_at IS NULL
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, companyID, prorationPolicyID)
	if err != nil {
		return nil, fmt.Errorf("get by proration policy: %w", err)
	}
	defer rows.Close()
	return r.scanPlans(rows)
}

// -------------------------------------------------------------------------
// GetPlanTotalPrice (unchanged)
// -------------------------------------------------------------------------

func (r *planRepository) GetPlanTotalPrice(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (decimal.Decimal, error) {
	query := `
		SELECT COALESCE(SUM(price), 0)
		FROM subscription.plan_items
		WHERE plan_id = $1 AND deleted_at IS NULL
	`
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, planID).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get plan total price: %w", err)
	}
	return total, nil
}

// -------------------------------------------------------------------------
// Locking (unchanged)
// -------------------------------------------------------------------------

func (r *planRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (*models.Plan, error) {
	query := `
		SELECT plan_id, company_id, name, plan_type_id, description,
		       billing_policy_id, renewal_policy_id, pause_policy_id, proration_policy_id,
		       duration_days, cancellation_policy, metadata,
		       is_active, version, published_at, published_by,
		       created_at, updated_at, deleted_at
		FROM subscription.plans
		WHERE company_id = $1 AND plan_id = $2
		FOR UPDATE
	`
	var plan models.Plan
	var planTypeID int
	err := db.QueryRowContext(ctx, query, companyID, planID).Scan(
		&plan.PlanID,
		&plan.CompanyID,
		&plan.Name,
		&planTypeID,
		&plan.Description,
		&plan.BillingPolicyID,
		&plan.RenewalPolicyID,
		&plan.PausePolicyID,
		&plan.ProrationPolicyID,
		&plan.DurationDays,
		&plan.CancellationPolicy,
		&plan.Metadata,
		&plan.IsActive,
		&plan.Version,
		&plan.PublishedAt,
		&plan.PublishedBy,
		&plan.CreatedAt,
		&plan.UpdatedAt,
		&plan.DeletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get plan for update", zap.Error(err))
		return nil, fmt.Errorf("get plan for update: %w", err)
	}
	planType, ok := idToPlanType[planTypeID]
	if !ok {
		return nil, fmt.Errorf("unknown plan_type_id: %d", planTypeID)
	}
	plan.PlanType = planType
	return &plan, nil
}

// -------------------------------------------------------------------------
// Helper: scanPlans (unchanged)
// -------------------------------------------------------------------------

func (r *planRepository) scanPlans(rows *sql.Rows) ([]*models.Plan, error) {
	var plans []*models.Plan
	for rows.Next() {
		var plan models.Plan
		var planTypeID int
		err := rows.Scan(
			&plan.PlanID,
			&plan.CompanyID,
			&plan.Name,
			&planTypeID,
			&plan.Description,
			&plan.BillingPolicyID,
			&plan.RenewalPolicyID,
			&plan.PausePolicyID,
			&plan.ProrationPolicyID,
			&plan.DurationDays,
			&plan.CancellationPolicy,
			&plan.Metadata,
			&plan.IsActive,
			&plan.Version,
			&plan.PublishedAt,
			&plan.PublishedBy,
			&plan.CreatedAt,
			&plan.UpdatedAt,
			&plan.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan plan: %w", err)
		}
		planType, ok := idToPlanType[planTypeID]
		if !ok {
			return nil, fmt.Errorf("unknown plan_type_id: %d", planTypeID)
		}
		plan.PlanType = planType
		plans = append(plans, &plan)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return plans, nil
}

// -------------------------------------------------------------------------
// Helper: buildFilterConditions (unchanged)
// -------------------------------------------------------------------------

func (r *planRepository) buildFilterConditions(filter PlanFilter) ([]string, []interface{}) {
	var conditions []string
	var args []interface{}
	argPos := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", argPos))
		args = append(args, filter.CompanyID)
		argPos++
	}

	if len(filter.PlanIDs) > 0 {
		placeholders := make([]string, len(filter.PlanIDs))
		for i, id := range filter.PlanIDs {
			placeholders[i] = fmt.Sprintf("$%d", argPos+i)
			args = append(args, id)
		}
		conditions = append(conditions, fmt.Sprintf("plan_id IN (%s)", strings.Join(placeholders, ",")))
		argPos += len(filter.PlanIDs)
	}

	if filter.Name != nil {
		conditions = append(conditions, fmt.Sprintf("name ILIKE $%d", argPos))
		args = append(args, "%"+*filter.Name+"%")
		argPos++
	}

	if filter.PlanType != nil {
		planTypeID, ok := planTypeToID[*filter.PlanType]
		if !ok {
			// Invalid plan type – add a condition that never matches
			conditions = append(conditions, "1 = 0")
		} else {
			conditions = append(conditions, fmt.Sprintf("plan_type_id = $%d", argPos))
			args = append(args, planTypeID)
			argPos++
		}
	}

	if filter.BillingPolicyID != nil {
		conditions = append(conditions, fmt.Sprintf("billing_policy_id = $%d", argPos))
		args = append(args, *filter.BillingPolicyID)
		argPos++
	}
	if filter.RenewalPolicyID != nil {
		conditions = append(conditions, fmt.Sprintf("renewal_policy_id = $%d", argPos))
		args = append(args, *filter.RenewalPolicyID)
		argPos++
	}
	if filter.PausePolicyID != nil {
		conditions = append(conditions, fmt.Sprintf("pause_policy_id = $%d", argPos))
		args = append(args, *filter.PausePolicyID)
		argPos++
	}
	if filter.ProrationPolicyID != nil {
		conditions = append(conditions, fmt.Sprintf("proration_policy_id = $%d", argPos))
		args = append(args, *filter.ProrationPolicyID)
		argPos++
	}

	if filter.DurationDaysMin != nil {
		conditions = append(conditions, fmt.Sprintf("duration_days >= $%d", argPos))
		args = append(args, *filter.DurationDaysMin)
		argPos++
	}
	if filter.DurationDaysMax != nil {
		conditions = append(conditions, fmt.Sprintf("duration_days <= $%d", argPos))
		args = append(args, *filter.DurationDaysMax)
		argPos++
	}

	if filter.VersionMin != nil {
		conditions = append(conditions, fmt.Sprintf("version >= $%d", argPos))
		args = append(args, *filter.VersionMin)
		argPos++
	}
	if filter.VersionMax != nil {
		conditions = append(conditions, fmt.Sprintf("version <= $%d", argPos))
		args = append(args, *filter.VersionMax)
		argPos++
	}

	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argPos))
		args = append(args, *filter.IsActive)
		argPos++
	}

	if filter.IsPublished != nil {
		if *filter.IsPublished {
			conditions = append(conditions, "published_at IS NOT NULL")
		} else {
			conditions = append(conditions, "published_at IS NULL")
		}
	}

	if filter.PublishedFrom != nil {
		conditions = append(conditions, fmt.Sprintf("published_at >= $%d", argPos))
		args = append(args, *filter.PublishedFrom)
		argPos++
	}
	if filter.PublishedTo != nil {
		conditions = append(conditions, fmt.Sprintf("published_at <= $%d", argPos))
		args = append(args, *filter.PublishedTo)
		argPos++
	}

	if filter.CreatedFrom != nil {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", argPos))
		args = append(args, *filter.CreatedFrom)
		argPos++
	}
	if filter.CreatedTo != nil {
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", argPos))
		args = append(args, *filter.CreatedTo)
		argPos++
	}

	if filter.UpdatedFrom != nil {
		conditions = append(conditions, fmt.Sprintf("updated_at >= $%d", argPos))
		args = append(args, *filter.UpdatedFrom)
		argPos++
	}
	if filter.UpdatedTo != nil {
		conditions = append(conditions, fmt.Sprintf("updated_at <= $%d", argPos))
		args = append(args, *filter.UpdatedTo)
		argPos++
	}

	// Soft-delete handling
	if !filter.Deleted {
		conditions = append(conditions, "deleted_at IS NULL")
	} else {
		conditions = append(conditions, "deleted_at IS NOT NULL")
	}

	return conditions, args
}
