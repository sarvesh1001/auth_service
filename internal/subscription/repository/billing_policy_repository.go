// FILE: repository/billing_policy_repository.go

package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"auth-service/internal/subscription/models"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// -------------------------------------------------------------------------
// Filter, Pagination, Sort
// -------------------------------------------------------------------------

// Pagination defines page limits and offset.

// BillingPolicyFilter filters billing policies.
type BillingPolicyFilter struct {
	CompanyID          uuid.UUID
	PolicyIDs          []uuid.UUID
	Name               *string
	FrequencyID        *int16
	ModelID            *int16
	BillingIntervalMin *int
	BillingIntervalMax *int
	AdvanceDaysMin     *int
	AdvanceDaysMax     *int
	IsActive           *bool
	CreatedFrom        *time.Time
	CreatedTo          *time.Time
	UpdatedFrom        *time.Time
	UpdatedTo          *time.Time
}

// -------------------------------------------------------------------------
// BillingPolicyRepository Interface
// -------------------------------------------------------------------------

type BillingPolicyRepository interface {
	// -------------------------------------------------------------------------
	// CRUD
	// -------------------------------------------------------------------------

	Create(ctx context.Context, db DBTX, policy *models.BillingPolicy) error
	GetByID(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) (*models.BillingPolicy, error)
	GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.BillingPolicy, error)
	Update(ctx context.Context, db DBTX, policy *models.BillingPolicy) error
	Delete(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) error

	// -------------------------------------------------------------------------
	// Status / Lifecycle
	// -------------------------------------------------------------------------

	Activate(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) error
	Deactivate(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) error
	SoftDelete(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) error
	Restore(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) error

	// -------------------------------------------------------------------------
	// Validation
	// -------------------------------------------------------------------------

	Exists(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) (bool, error)
	ExistsByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error)
	IsActive(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) (bool, error)

	// -------------------------------------------------------------------------
	// Querying
	// -------------------------------------------------------------------------

	List(ctx context.Context, db DBTX, filter BillingPolicyFilter, pagination Pagination, sort Sort) ([]*models.BillingPolicy, int64, error)
	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.BillingPolicy, int64, error)
	GetActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.BillingPolicy, error)

	// -------------------------------------------------------------------------
	// Locking
	// -------------------------------------------------------------------------

	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) (*models.BillingPolicy, error)
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type billingPolicyRepository struct {
	logger *zap.Logger
}

func NewBillingPolicyRepository(logger *zap.Logger) BillingPolicyRepository {
	return &billingPolicyRepository{
		logger: logger.Named("subscription_billing_policy_repo"),
	}
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (r *billingPolicyRepository) Create(ctx context.Context, db DBTX, policy *models.BillingPolicy) error {
	query := `
		INSERT INTO subscription.billing_policies (
			billing_policy_id, company_id, name, frequency_id, billing_interval,
			model_id, advance_days, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	now := time.Now()
	policy.CreatedAt = now
	policy.UpdatedAt = now
	_, err := db.ExecContext(ctx, query,
		policy.BillingPolicyID,
		policy.CompanyID,
		policy.Name,
		policy.FrequencyID,
		policy.BillingInterval,
		policy.ModelID,
		policy.AdvanceDays,
		policy.IsActive,
		policy.CreatedAt,
		policy.UpdatedAt,
	)
	if err != nil {
		r.logger.Error("failed to create billing policy", zap.Error(err))
		return fmt.Errorf("create billing policy: %w", err)
	}
	return nil
}

func (r *billingPolicyRepository) GetByID(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) (*models.BillingPolicy, error) {
	query := `
		SELECT billing_policy_id, company_id, name, frequency_id, billing_interval,
		       model_id, advance_days, is_active, created_at, updated_at, deleted_at
		FROM subscription.billing_policies
		WHERE company_id = $1 AND billing_policy_id = $2 AND deleted_at IS NULL
	`
	var policy models.BillingPolicy
	err := db.QueryRowContext(ctx, query, companyID, billingPolicyID).Scan(
		&policy.BillingPolicyID,
		&policy.CompanyID,
		&policy.Name,
		&policy.FrequencyID,
		&policy.BillingInterval,
		&policy.ModelID,
		&policy.AdvanceDays,
		&policy.IsActive,
		&policy.CreatedAt,
		&policy.UpdatedAt,
		&policy.DeletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get billing policy by ID", zap.Error(err))
		return nil, fmt.Errorf("get billing policy by ID: %w", err)
	}
	return &policy, nil
}

func (r *billingPolicyRepository) GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.BillingPolicy, error) {
	query := `
		SELECT billing_policy_id, company_id, name, frequency_id, billing_interval,
		       model_id, advance_days, is_active, created_at, updated_at, deleted_at
		FROM subscription.billing_policies
		WHERE company_id = $1 AND name = $2 AND deleted_at IS NULL
	`
	var policy models.BillingPolicy
	err := db.QueryRowContext(ctx, query, companyID, name).Scan(
		&policy.BillingPolicyID,
		&policy.CompanyID,
		&policy.Name,
		&policy.FrequencyID,
		&policy.BillingInterval,
		&policy.ModelID,
		&policy.AdvanceDays,
		&policy.IsActive,
		&policy.CreatedAt,
		&policy.UpdatedAt,
		&policy.DeletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get billing policy by name", zap.String("name", name), zap.Error(err))
		return nil, fmt.Errorf("get billing policy by name: %w", err)
	}
	return &policy, nil
}

func (r *billingPolicyRepository) Update(ctx context.Context, db DBTX, policy *models.BillingPolicy) error {
	query := `
		UPDATE subscription.billing_policies
		SET name = $1, frequency_id = $2, billing_interval = $3,
		    model_id = $4, advance_days = $5, is_active = $6, updated_at = $7
		WHERE company_id = $8 AND billing_policy_id = $9 AND deleted_at IS NULL
	`
	policy.UpdatedAt = time.Now()
	result, err := db.ExecContext(ctx, query,
		policy.Name,
		policy.FrequencyID,
		policy.BillingInterval,
		policy.ModelID,
		policy.AdvanceDays,
		policy.IsActive,
		policy.UpdatedAt,
		policy.CompanyID,
		policy.BillingPolicyID,
	)
	if err != nil {
		r.logger.Error("failed to update billing policy", zap.Error(err))
		return fmt.Errorf("update billing policy: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("billing policy not found or already deleted")
	}
	return nil
}

func (r *billingPolicyRepository) Delete(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) error {
	// Hard delete (permanent)
	query := `DELETE FROM subscription.billing_policies WHERE company_id = $1 AND billing_policy_id = $2`
	result, err := db.ExecContext(ctx, query, companyID, billingPolicyID)
	if err != nil {
		r.logger.Error("failed to delete billing policy", zap.Error(err))
		return fmt.Errorf("delete billing policy: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("billing policy not found")
	}
	return nil
}

// -------------------------------------------------------------------------
// Status / Lifecycle
// -------------------------------------------------------------------------

func (r *billingPolicyRepository) Activate(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) error {
	query := `
		UPDATE subscription.billing_policies
		SET is_active = true, updated_at = $1
		WHERE company_id = $2 AND billing_policy_id = $3 AND deleted_at IS NULL
	`
	_, err := db.ExecContext(ctx, query, time.Now(), companyID, billingPolicyID)
	if err != nil {
		r.logger.Error("failed to activate billing policy", zap.Error(err))
		return fmt.Errorf("activate billing policy: %w", err)
	}
	return nil
}

func (r *billingPolicyRepository) Deactivate(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) error {
	query := `
		UPDATE subscription.billing_policies
		SET is_active = false, updated_at = $1
		WHERE company_id = $2 AND billing_policy_id = $3 AND deleted_at IS NULL
	`
	_, err := db.ExecContext(ctx, query, time.Now(), companyID, billingPolicyID)
	if err != nil {
		r.logger.Error("failed to deactivate billing policy", zap.Error(err))
		return fmt.Errorf("deactivate billing policy: %w", err)
	}
	return nil
}

func (r *billingPolicyRepository) SoftDelete(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) error {
	query := `
		UPDATE subscription.billing_policies
		SET deleted_at = $1, updated_at = $2
		WHERE company_id = $3 AND billing_policy_id = $4 AND deleted_at IS NULL
	`
	now := time.Now()
	result, err := db.ExecContext(ctx, query, now, now, companyID, billingPolicyID)
	if err != nil {
		r.logger.Error("failed to soft delete billing policy", zap.Error(err))
		return fmt.Errorf("soft delete billing policy: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("billing policy not found or already deleted")
	}
	return nil
}
func (r *billingPolicyRepository) Restore(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) error {
	query := `
		UPDATE subscription.billing_policies
		SET deleted_at = NULL, updated_at = $1
		WHERE company_id = $2 AND billing_policy_id = $3
	`
	_, err := db.ExecContext(ctx, query, time.Now(), companyID, billingPolicyID)
	if err != nil {
		r.logger.Error("failed to restore billing policy", zap.Error(err))
		return fmt.Errorf("restore billing policy: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Validation
// -------------------------------------------------------------------------

func (r *billingPolicyRepository) Exists(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.billing_policies WHERE company_id = $1 AND billing_policy_id = $2 AND deleted_at IS NULL)`
	err := db.QueryRowContext(ctx, query, companyID, billingPolicyID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check existence: %w", err)
	}
	return exists, nil
}

func (r *billingPolicyRepository) ExistsByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.billing_policies WHERE company_id = $1 AND name = $2 AND deleted_at IS NULL)`
	err := db.QueryRowContext(ctx, query, companyID, name).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check existence by name: %w", err)
	}
	return exists, nil
}

func (r *billingPolicyRepository) IsActive(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) (bool, error) {
	var active bool
	query := `SELECT is_active FROM subscription.billing_policies WHERE company_id = $1 AND billing_policy_id = $2 AND deleted_at IS NULL`
	err := db.QueryRowContext(ctx, query, companyID, billingPolicyID).Scan(&active)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("check active status: %w", err)
	}
	return active, nil
}

// -------------------------------------------------------------------------
// Querying
// -------------------------------------------------------------------------

func (r *billingPolicyRepository) List(ctx context.Context, db DBTX, filter BillingPolicyFilter, pagination Pagination, sort Sort) ([]*models.BillingPolicy, int64, error) {
	// Build WHERE clause
	whereClause, args := r.buildFilterClause(filter)

	// Build ORDER BY
	order := "ORDER BY created_at DESC" // default
	if sort.Field != "" {
		dir := strings.ToUpper(sort.Direction)
		if dir != "ASC" && dir != "DESC" {
			dir = "ASC"
		}
		order = fmt.Sprintf("ORDER BY %s %s", sort.Field, dir)
	}

	// Build LIMIT / OFFSET
	limitOffset := ""
	if pagination.Limit > 0 {
		limitOffset = fmt.Sprintf("LIMIT %d OFFSET %d", pagination.Limit, pagination.Offset)
	}

	// Count query
	countQuery := fmt.Sprintf(`
		SELECT COUNT(*) FROM subscription.billing_policies
		WHERE %s
	`, whereClause)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		r.logger.Error("failed to count billing policies", zap.Error(err))
		return nil, 0, fmt.Errorf("count billing policies: %w", err)
	}
	if total == 0 {
		return []*models.BillingPolicy{}, 0, nil
	}

	// Data query
	query := fmt.Sprintf(`
		SELECT billing_policy_id, company_id, name, frequency_id, billing_interval,
		       model_id, advance_days, is_active, created_at, updated_at, deleted_at
		FROM subscription.billing_policies
		WHERE %s
		%s
		%s
	`, whereClause, order, limitOffset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list billing policies", zap.Error(err))
		return nil, 0, fmt.Errorf("list billing policies: %w", err)
	}
	defer rows.Close()

	var policies []*models.BillingPolicy
	for rows.Next() {
		var p models.BillingPolicy
		if err := rows.Scan(
			&p.BillingPolicyID,
			&p.CompanyID,
			&p.Name,
			&p.FrequencyID,
			&p.BillingInterval,
			&p.ModelID,
			&p.AdvanceDays,
			&p.IsActive,
			&p.CreatedAt,
			&p.UpdatedAt,
			&p.DeletedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan billing policy: %w", err)
		}
		policies = append(policies, &p)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", err)
	}
	return policies, total, nil
}

func (r *billingPolicyRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.BillingPolicy, int64, error) {
	searchTerm := "%" + query + "%"
	baseSQL := `
		FROM subscription.billing_policies
		WHERE company_id = $1
		  AND deleted_at IS NULL
		  AND (name ILIKE $2 OR CAST(billing_policy_id AS TEXT) ILIKE $2)
	`
	// Count
	countQuery := "SELECT COUNT(*) " + baseSQL
	var total int64
	err := db.QueryRowContext(ctx, countQuery, companyID, searchTerm).Scan(&total)
	if err != nil {
		r.logger.Error("failed to count search results", zap.Error(err))
		return nil, 0, fmt.Errorf("count search billing policies: %w", err)
	}
	if total == 0 {
		return []*models.BillingPolicy{}, 0, nil
	}

	// Data
	dataQuery := `
		SELECT billing_policy_id, company_id, name, frequency_id, billing_interval,
		       model_id, advance_days, is_active, created_at, updated_at, deleted_at
	` + baseSQL + `
		ORDER BY name
		LIMIT $3 OFFSET $4
	`
	rows, err := db.QueryContext(ctx, dataQuery, companyID, searchTerm, limit, offset)
	if err != nil {
		r.logger.Error("failed to search billing policies", zap.Error(err))
		return nil, 0, fmt.Errorf("search billing policies: %w", err)
	}
	defer rows.Close()

	var policies []*models.BillingPolicy
	for rows.Next() {
		var p models.BillingPolicy
		if err := rows.Scan(
			&p.BillingPolicyID,
			&p.CompanyID,
			&p.Name,
			&p.FrequencyID,
			&p.BillingInterval,
			&p.ModelID,
			&p.AdvanceDays,
			&p.IsActive,
			&p.CreatedAt,
			&p.UpdatedAt,
			&p.DeletedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan search result: %w", err)
		}
		policies = append(policies, &p)
	}
	return policies, total, rows.Err()
}

func (r *billingPolicyRepository) GetActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.BillingPolicy, error) {
	query := `
		SELECT billing_policy_id, company_id, name, frequency_id, billing_interval,
		       model_id, advance_days, is_active, created_at, updated_at, deleted_at
		FROM subscription.billing_policies
		WHERE company_id = $1 AND is_active = true AND deleted_at IS NULL
		ORDER BY name
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		r.logger.Error("failed to get active billing policies", zap.Error(err))
		return nil, fmt.Errorf("get active billing policies: %w", err)
	}
	defer rows.Close()

	var policies []*models.BillingPolicy
	for rows.Next() {
		var p models.BillingPolicy
		if err := rows.Scan(
			&p.BillingPolicyID,
			&p.CompanyID,
			&p.Name,
			&p.FrequencyID,
			&p.BillingInterval,
			&p.ModelID,
			&p.AdvanceDays,
			&p.IsActive,
			&p.CreatedAt,
			&p.UpdatedAt,
			&p.DeletedAt,
		); err != nil {
			return nil, fmt.Errorf("scan active policy: %w", err)
		}
		policies = append(policies, &p)
	}
	return policies, rows.Err()
}

// -------------------------------------------------------------------------
// Locking
// -------------------------------------------------------------------------

func (r *billingPolicyRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) (*models.BillingPolicy, error) {
	query := `
		SELECT billing_policy_id, company_id, name, frequency_id, billing_interval,
		       model_id, advance_days, is_active, created_at, updated_at, deleted_at
		FROM subscription.billing_policies
		WHERE company_id = $1 AND billing_policy_id = $2 AND deleted_at IS NULL
		FOR UPDATE
	`
	var policy models.BillingPolicy
	err := db.QueryRowContext(ctx, query, companyID, billingPolicyID).Scan(
		&policy.BillingPolicyID,
		&policy.CompanyID,
		&policy.Name,
		&policy.FrequencyID,
		&policy.BillingInterval,
		&policy.ModelID,
		&policy.AdvanceDays,
		&policy.IsActive,
		&policy.CreatedAt,
		&policy.UpdatedAt,
		&policy.DeletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get billing policy for update", zap.Error(err))
		return nil, fmt.Errorf("get billing policy for update: %w", err)
	}
	return &policy, nil
}

// -------------------------------------------------------------------------
// Helper: build filter clause
// -------------------------------------------------------------------------

func (r *billingPolicyRepository) buildFilterClause(filter BillingPolicyFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	argIdx := 1

	// CompanyID is always required
	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", argIdx))
		args = append(args, filter.CompanyID)
		argIdx++
	}

	// PolicyIDs
	if len(filter.PolicyIDs) > 0 {
		placeholders := make([]string, len(filter.PolicyIDs))
		for i, id := range filter.PolicyIDs {
			placeholders[i] = fmt.Sprintf("$%d", argIdx)
			args = append(args, id)
			argIdx++
		}
		conditions = append(conditions, fmt.Sprintf("billing_policy_id IN (%s)", strings.Join(placeholders, ",")))
	}

	// Name
	if filter.Name != nil {
		conditions = append(conditions, fmt.Sprintf("name = $%d", argIdx))
		args = append(args, *filter.Name)
		argIdx++
	}

	// FrequencyID
	if filter.FrequencyID != nil {
		conditions = append(conditions, fmt.Sprintf("frequency_id = $%d", argIdx))
		args = append(args, *filter.FrequencyID)
		argIdx++
	}

	// ModelID
	if filter.ModelID != nil {
		conditions = append(conditions, fmt.Sprintf("model_id = $%d", argIdx))
		args = append(args, *filter.ModelID)
		argIdx++
	}

	// BillingInterval range
	if filter.BillingIntervalMin != nil {
		conditions = append(conditions, fmt.Sprintf("billing_interval >= $%d", argIdx))
		args = append(args, *filter.BillingIntervalMin)
		argIdx++
	}
	if filter.BillingIntervalMax != nil {
		conditions = append(conditions, fmt.Sprintf("billing_interval <= $%d", argIdx))
		args = append(args, *filter.BillingIntervalMax)
		argIdx++
	}

	// AdvanceDays range
	if filter.AdvanceDaysMin != nil {
		conditions = append(conditions, fmt.Sprintf("advance_days >= $%d", argIdx))
		args = append(args, *filter.AdvanceDaysMin)
		argIdx++
	}
	if filter.AdvanceDaysMax != nil {
		conditions = append(conditions, fmt.Sprintf("advance_days <= $%d", argIdx))
		args = append(args, *filter.AdvanceDaysMax)
		argIdx++
	}

	// IsActive
	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argIdx))
		args = append(args, *filter.IsActive)
		argIdx++
	}

	// Created range
	if filter.CreatedFrom != nil {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", argIdx))
		args = append(args, *filter.CreatedFrom)
		argIdx++
	}
	if filter.CreatedTo != nil {
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", argIdx))
		args = append(args, *filter.CreatedTo)
		argIdx++
	}

	// Updated range
	if filter.UpdatedFrom != nil {
		conditions = append(conditions, fmt.Sprintf("updated_at >= $%d", argIdx))
		args = append(args, *filter.UpdatedFrom)
		argIdx++
	}
	if filter.UpdatedTo != nil {
		conditions = append(conditions, fmt.Sprintf("updated_at <= $%d", argIdx))
		args = append(args, *filter.UpdatedTo)
		argIdx++
	}

	// Soft-deleted records are excluded by default (we never include deleted_at IS NOT NULL in filter)
	// But we can add explicit condition if needed; for now we only list non-deleted.
	conditions = append(conditions, "deleted_at IS NULL")

	whereClause := strings.Join(conditions, " AND ")
	if whereClause == "" {
		whereClause = "1=1"
	}
	return whereClause, args
}
