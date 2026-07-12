// FILE: repository/renewal_policy_repository.go

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
)

// Pagination defines limit and offset for list queries.

// RenewalPolicyRepository defines the data access interface for renewal policies.
type RenewalPolicyRepository interface {
	// -------------------------------------------------------------------------
	// CRUD
	// -------------------------------------------------------------------------

	Create(ctx context.Context, db DBTX, policy *models.RenewalPolicy) error
	GetByID(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) (*models.RenewalPolicy, error)
	GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.RenewalPolicy, error)
	Update(ctx context.Context, db DBTX, policy *models.RenewalPolicy) error
	Delete(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) error

	// -------------------------------------------------------------------------
	// Status / Lifecycle
	// -------------------------------------------------------------------------

	Activate(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) error
	Deactivate(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) error

	SoftDelete(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) error
	Restore(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) error

	// -------------------------------------------------------------------------
	// Validation
	// -------------------------------------------------------------------------

	Exists(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) (bool, error)
	ExistsByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error)
	IsActive(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) (bool, error)

	// -------------------------------------------------------------------------
	// Querying
	// -------------------------------------------------------------------------

	List(ctx context.Context, db DBTX, filter RenewalPolicyFilter, p Pagination, s Sort) ([]*models.RenewalPolicy, int64, error)
	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.RenewalPolicy, int64, error)

	GetActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.RenewalPolicy, error)

	GetAutoRenewPolicies(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.RenewalPolicy, error)
	GetManualRenewPolicies(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.RenewalPolicy, error)

	// -------------------------------------------------------------------------
	// Locking
	// -------------------------------------------------------------------------

	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) (*models.RenewalPolicy, error)
}

// RenewalPolicyFilter defines filter options for List queries.
type RenewalPolicyFilter struct {
	CompanyID uuid.UUID

	PolicyIDs []uuid.UUID

	Name *string

	AutoRenew *bool

	GraceDaysMin *int
	GraceDaysMax *int

	LateFeePercentMin *decimal.Decimal
	LateFeePercentMax *decimal.Decimal

	NoticeDaysMin *int
	NoticeDaysMax *int

	IsActive *bool

	CreatedFrom *time.Time
	CreatedTo   *time.Time

	UpdatedFrom *time.Time
	UpdatedTo   *time.Time
}

type renewalPolicyRepository struct {
	logger *zap.Logger
}

// NewRenewalPolicyRepository creates a new RenewalPolicyRepository.
func NewRenewalPolicyRepository(logger *zap.Logger) RenewalPolicyRepository {
	return &renewalPolicyRepository{
		logger: logger.Named("subscription_renewal_policy_repo"),
	}
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (r *renewalPolicyRepository) Create(ctx context.Context, db DBTX, policy *models.RenewalPolicy) error {
	query := `
		INSERT INTO subscription.renewal_policies (
			renewal_policy_id, company_id, name, auto_renew, grace_days,
			late_fee_percent, notice_days, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	now := time.Now()
	_, err := db.ExecContext(ctx, query,
		policy.RenewalPolicyID,
		policy.CompanyID,
		policy.Name,
		policy.AutoRenew,
		policy.GraceDays,
		policy.LateFeePercent,
		policy.NoticeDays,
		policy.IsActive,
		now,
		now,
	)
	if err != nil {
		r.logger.Error("failed to create renewal policy", zap.Error(err))
		return fmt.Errorf("create renewal policy: %w", err)
	}
	policy.CreatedAt = now
	policy.UpdatedAt = now
	return nil
}

func (r *renewalPolicyRepository) GetByID(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) (*models.RenewalPolicy, error) {
	query := `
		SELECT renewal_policy_id, company_id, name, auto_renew, grace_days,
		       late_fee_percent, notice_days, is_active, created_at, updated_at, deleted_at
		FROM subscription.renewal_policies
		WHERE company_id = $1 AND renewal_policy_id = $2
	`
	var policy models.RenewalPolicy
	var deletedAt sql.NullTime
	err := db.QueryRowContext(ctx, query, companyID, renewalPolicyID).Scan(
		&policy.RenewalPolicyID,
		&policy.CompanyID,
		&policy.Name,
		&policy.AutoRenew,
		&policy.GraceDays,
		&policy.LateFeePercent,
		&policy.NoticeDays,
		&policy.IsActive,
		&policy.CreatedAt,
		&policy.UpdatedAt,
		&deletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get renewal policy by ID", zap.Error(err))
		return nil, fmt.Errorf("get renewal policy by ID: %w", err)
	}
	if deletedAt.Valid {
		policy.DeletedAt = &deletedAt.Time
	}
	return &policy, nil
}

func (r *renewalPolicyRepository) GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.RenewalPolicy, error) {
	query := `
		SELECT renewal_policy_id, company_id, name, auto_renew, grace_days,
		       late_fee_percent, notice_days, is_active, created_at, updated_at, deleted_at
		FROM subscription.renewal_policies
		WHERE company_id = $1 AND name = $2
	`
	var policy models.RenewalPolicy
	var deletedAt sql.NullTime
	err := db.QueryRowContext(ctx, query, companyID, name).Scan(
		&policy.RenewalPolicyID,
		&policy.CompanyID,
		&policy.Name,
		&policy.AutoRenew,
		&policy.GraceDays,
		&policy.LateFeePercent,
		&policy.NoticeDays,
		&policy.IsActive,
		&policy.CreatedAt,
		&policy.UpdatedAt,
		&deletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get renewal policy by name", zap.String("name", name), zap.Error(err))
		return nil, fmt.Errorf("get renewal policy by name: %w", err)
	}
	if deletedAt.Valid {
		policy.DeletedAt = &deletedAt.Time
	}
	return &policy, nil
}

func (r *renewalPolicyRepository) Update(ctx context.Context, db DBTX, policy *models.RenewalPolicy) error {
	query := `
		UPDATE subscription.renewal_policies
		SET name = $1,
		    auto_renew = $2,
		    grace_days = $3,
		    late_fee_percent = $4,
		    notice_days = $5,
		    is_active = $6,
		    updated_at = $7
		WHERE company_id = $8 AND renewal_policy_id = $9
	`
	now := time.Now()
	_, err := db.ExecContext(ctx, query,
		policy.Name,
		policy.AutoRenew,
		policy.GraceDays,
		policy.LateFeePercent,
		policy.NoticeDays,
		policy.IsActive,
		now,
		policy.CompanyID,
		policy.RenewalPolicyID,
	)
	if err != nil {
		r.logger.Error("failed to update renewal policy", zap.Error(err))
		return fmt.Errorf("update renewal policy: %w", err)
	}
	policy.UpdatedAt = now
	return nil
}

func (r *renewalPolicyRepository) Delete(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) error {
	query := `DELETE FROM subscription.renewal_policies WHERE company_id = $1 AND renewal_policy_id = $2`
	result, err := db.ExecContext(ctx, query, companyID, renewalPolicyID)
	if err != nil {
		r.logger.Error("failed to delete renewal policy", zap.Error(err))
		return fmt.Errorf("delete renewal policy: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return nil // not found, but we don't treat as error
	}
	return nil
}

// -------------------------------------------------------------------------
// Status / Lifecycle
// -------------------------------------------------------------------------

func (r *renewalPolicyRepository) Activate(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) error {
	query := `UPDATE subscription.renewal_policies SET is_active = true, updated_at = NOW() WHERE company_id = $1 AND renewal_policy_id = $2`
	_, err := db.ExecContext(ctx, query, companyID, renewalPolicyID)
	if err != nil {
		r.logger.Error("failed to activate renewal policy", zap.Error(err))
		return fmt.Errorf("activate renewal policy: %w", err)
	}
	return nil
}

func (r *renewalPolicyRepository) Deactivate(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) error {
	query := `UPDATE subscription.renewal_policies SET is_active = false, updated_at = NOW() WHERE company_id = $1 AND renewal_policy_id = $2`
	_, err := db.ExecContext(ctx, query, companyID, renewalPolicyID)
	if err != nil {
		r.logger.Error("failed to deactivate renewal policy", zap.Error(err))
		return fmt.Errorf("deactivate renewal policy: %w", err)
	}
	return nil
}

func (r *renewalPolicyRepository) SoftDelete(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) error {
	query := `UPDATE subscription.renewal_policies SET deleted_at = NOW(), updated_at = NOW() WHERE company_id = $1 AND renewal_policy_id = $2 AND deleted_at IS NULL`
	_, err := db.ExecContext(ctx, query, companyID, renewalPolicyID)
	if err != nil {
		r.logger.Error("failed to soft delete renewal policy", zap.Error(err))
		return fmt.Errorf("soft delete renewal policy: %w", err)
	}
	return nil
}

func (r *renewalPolicyRepository) Restore(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) error {
	query := `UPDATE subscription.renewal_policies SET deleted_at = NULL, updated_at = NOW() WHERE company_id = $1 AND renewal_policy_id = $2`
	_, err := db.ExecContext(ctx, query, companyID, renewalPolicyID)
	if err != nil {
		r.logger.Error("failed to restore renewal policy", zap.Error(err))
		return fmt.Errorf("restore renewal policy: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Validation
// -------------------------------------------------------------------------

func (r *renewalPolicyRepository) Exists(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS (SELECT 1 FROM subscription.renewal_policies WHERE company_id = $1 AND renewal_policy_id = $2)`
	err := db.QueryRowContext(ctx, query, companyID, renewalPolicyID).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check renewal policy existence", zap.Error(err))
		return false, fmt.Errorf("exists renewal policy: %w", err)
	}
	return exists, nil
}

func (r *renewalPolicyRepository) ExistsByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS (SELECT 1 FROM subscription.renewal_policies WHERE company_id = $1 AND name = $2 AND deleted_at IS NULL)`
	err := db.QueryRowContext(ctx, query, companyID, name).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check renewal policy by name", zap.Error(err))
		return false, fmt.Errorf("exists by name: %w", err)
	}
	return exists, nil
}

func (r *renewalPolicyRepository) IsActive(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) (bool, error) {
	var isActive bool
	query := `SELECT is_active FROM subscription.renewal_policies WHERE company_id = $1 AND renewal_policy_id = $2 AND deleted_at IS NULL`
	err := db.QueryRowContext(ctx, query, companyID, renewalPolicyID).Scan(&isActive)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		r.logger.Error("failed to get is_active", zap.Error(err))
		return false, fmt.Errorf("is active: %w", err)
	}
	return isActive, nil
}

// -------------------------------------------------------------------------
// Querying
// -------------------------------------------------------------------------

func (r *renewalPolicyRepository) List(ctx context.Context, db DBTX, filter RenewalPolicyFilter, p Pagination, s Sort) ([]*models.RenewalPolicy, int64, error) {
	// Build WHERE clause
	conditions := []string{"company_id = $1"}
	args := []interface{}{filter.CompanyID}
	argIdx := 2

	if len(filter.PolicyIDs) > 0 {
		placeholders := make([]string, len(filter.PolicyIDs))
		for i, id := range filter.PolicyIDs {
			placeholders[i] = fmt.Sprintf("$%d", argIdx)
			args = append(args, id)
			argIdx++
		}
		conditions = append(conditions, fmt.Sprintf("renewal_policy_id IN (%s)", strings.Join(placeholders, ",")))
	}

	if filter.Name != nil {
		conditions = append(conditions, fmt.Sprintf("name = $%d", argIdx))
		args = append(args, *filter.Name)
		argIdx++
	}

	if filter.AutoRenew != nil {
		conditions = append(conditions, fmt.Sprintf("auto_renew = $%d", argIdx))
		args = append(args, *filter.AutoRenew)
		argIdx++
	}

	if filter.GraceDaysMin != nil {
		conditions = append(conditions, fmt.Sprintf("grace_days >= $%d", argIdx))
		args = append(args, *filter.GraceDaysMin)
		argIdx++
	}
	if filter.GraceDaysMax != nil {
		conditions = append(conditions, fmt.Sprintf("grace_days <= $%d", argIdx))
		args = append(args, *filter.GraceDaysMax)
		argIdx++
	}

	if filter.LateFeePercentMin != nil {
		conditions = append(conditions, fmt.Sprintf("late_fee_percent >= $%d", argIdx))
		args = append(args, *filter.LateFeePercentMin)
		argIdx++
	}
	if filter.LateFeePercentMax != nil {
		conditions = append(conditions, fmt.Sprintf("late_fee_percent <= $%d", argIdx))
		args = append(args, *filter.LateFeePercentMax)
		argIdx++
	}

	if filter.NoticeDaysMin != nil {
		conditions = append(conditions, fmt.Sprintf("notice_days >= $%d", argIdx))
		args = append(args, *filter.NoticeDaysMin)
		argIdx++
	}
	if filter.NoticeDaysMax != nil {
		conditions = append(conditions, fmt.Sprintf("notice_days <= $%d", argIdx))
		args = append(args, *filter.NoticeDaysMax)
		argIdx++
	}

	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argIdx))
		args = append(args, *filter.IsActive)
		argIdx++
	}

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

	// Exclude soft-deleted by default (unless you want to include them, but filters don't have a deleted flag)
	conditions = append(conditions, "deleted_at IS NULL")

	whereClause := strings.Join(conditions, " AND ")

	// Build ORDER BY
	orderClause := ""
	if s.Field != "" {
		dir := "ASC"
		if strings.ToUpper(s.Direction) == "DESC" {
			dir = "DESC"
		}
		// Validate field to prevent SQL injection (whitelist)
		allowedFields := map[string]bool{
			"renewal_policy_id": true,
			"name":              true,
			"auto_renew":        true,
			"grace_days":        true,
			"late_fee_percent":  true,
			"notice_days":       true,
			"is_active":         true,
			"created_at":        true,
			"updated_at":        true,
		}
		if allowedFields[s.Field] {
			orderClause = fmt.Sprintf(" ORDER BY %s %s", s.Field, dir)
		}
	}

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM subscription.renewal_policies WHERE %s", whereClause)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		r.logger.Error("failed to count renewal policies", zap.Error(err))
		return nil, 0, fmt.Errorf("count renewal policies: %w", err)
	}

	// Main query
	query := fmt.Sprintf(`
		SELECT renewal_policy_id, company_id, name, auto_renew, grace_days,
		       late_fee_percent, notice_days, is_active, created_at, updated_at, deleted_at
		FROM subscription.renewal_policies
		WHERE %s
		%s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderClause, argIdx, argIdx+1)

	args = append(args, p.Limit, p.Offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list renewal policies", zap.Error(err))
		return nil, 0, fmt.Errorf("list renewal policies: %w", err)
	}
	defer rows.Close()

	var policies []*models.RenewalPolicy
	for rows.Next() {
		var p models.RenewalPolicy
		var deletedAt sql.NullTime
		err := rows.Scan(
			&p.RenewalPolicyID,
			&p.CompanyID,
			&p.Name,
			&p.AutoRenew,
			&p.GraceDays,
			&p.LateFeePercent,
			&p.NoticeDays,
			&p.IsActive,
			&p.CreatedAt,
			&p.UpdatedAt,
			&deletedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan renewal policy: %w", err)
		}
		if deletedAt.Valid {
			p.DeletedAt = &deletedAt.Time
		}
		policies = append(policies, &p)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", err)
	}
	return policies, total, nil
}

func (r *renewalPolicyRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.RenewalPolicy, int64, error) {
	// Simple search by name (case-insensitive)
	searchTerm := "%" + query + "%"

	countQuery := `
		SELECT COUNT(*)
		FROM subscription.renewal_policies
		WHERE company_id = $1 AND deleted_at IS NULL AND name ILIKE $2
	`
	var total int64
	err := db.QueryRowContext(ctx, countQuery, companyID, searchTerm).Scan(&total)
	if err != nil {
		r.logger.Error("failed to count search results", zap.Error(err))
		return nil, 0, fmt.Errorf("count search: %w", err)
	}

	mainQuery := `
		SELECT renewal_policy_id, company_id, name, auto_renew, grace_days,
		       late_fee_percent, notice_days, is_active, created_at, updated_at, deleted_at
		FROM subscription.renewal_policies
		WHERE company_id = $1 AND deleted_at IS NULL AND name ILIKE $2
		ORDER BY name
		LIMIT $3 OFFSET $4
	`
	rows, err := db.QueryContext(ctx, mainQuery, companyID, searchTerm, limit, offset)
	if err != nil {
		r.logger.Error("failed to search renewal policies", zap.Error(err))
		return nil, 0, fmt.Errorf("search: %w", err)
	}
	defer rows.Close()

	var policies []*models.RenewalPolicy
	for rows.Next() {
		var p models.RenewalPolicy
		var deletedAt sql.NullTime
		err := rows.Scan(
			&p.RenewalPolicyID,
			&p.CompanyID,
			&p.Name,
			&p.AutoRenew,
			&p.GraceDays,
			&p.LateFeePercent,
			&p.NoticeDays,
			&p.IsActive,
			&p.CreatedAt,
			&p.UpdatedAt,
			&deletedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan search result: %w", err)
		}
		if deletedAt.Valid {
			p.DeletedAt = &deletedAt.Time
		}
		policies = append(policies, &p)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", err)
	}
	return policies, total, nil
}

func (r *renewalPolicyRepository) GetActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.RenewalPolicy, error) {
	query := `
		SELECT renewal_policy_id, company_id, name, auto_renew, grace_days,
		       late_fee_percent, notice_days, is_active, created_at, updated_at, deleted_at
		FROM subscription.renewal_policies
		WHERE company_id = $1 AND is_active = true AND deleted_at IS NULL
		ORDER BY name
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		r.logger.Error("failed to get active renewal policies", zap.Error(err))
		return nil, fmt.Errorf("get active: %w", err)
	}
	defer rows.Close()

	var policies []*models.RenewalPolicy
	for rows.Next() {
		var p models.RenewalPolicy
		var deletedAt sql.NullTime
		err := rows.Scan(
			&p.RenewalPolicyID,
			&p.CompanyID,
			&p.Name,
			&p.AutoRenew,
			&p.GraceDays,
			&p.LateFeePercent,
			&p.NoticeDays,
			&p.IsActive,
			&p.CreatedAt,
			&p.UpdatedAt,
			&deletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan active policy: %w", err)
		}
		if deletedAt.Valid {
			p.DeletedAt = &deletedAt.Time
		}
		policies = append(policies, &p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return policies, nil
}

func (r *renewalPolicyRepository) GetAutoRenewPolicies(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.RenewalPolicy, error) {
	query := `
		SELECT renewal_policy_id, company_id, name, auto_renew, grace_days,
		       late_fee_percent, notice_days, is_active, created_at, updated_at, deleted_at
		FROM subscription.renewal_policies
		WHERE company_id = $1 AND auto_renew = true AND is_active = true AND deleted_at IS NULL
		ORDER BY name
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		r.logger.Error("failed to get auto-renew policies", zap.Error(err))
		return nil, fmt.Errorf("get auto-renew policies: %w", err)
	}
	defer rows.Close()

	var policies []*models.RenewalPolicy
	for rows.Next() {
		var p models.RenewalPolicy
		var deletedAt sql.NullTime
		err := rows.Scan(
			&p.RenewalPolicyID,
			&p.CompanyID,
			&p.Name,
			&p.AutoRenew,
			&p.GraceDays,
			&p.LateFeePercent,
			&p.NoticeDays,
			&p.IsActive,
			&p.CreatedAt,
			&p.UpdatedAt,
			&deletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan auto-renew policy: %w", err)
		}
		if deletedAt.Valid {
			p.DeletedAt = &deletedAt.Time
		}
		policies = append(policies, &p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return policies, nil
}

func (r *renewalPolicyRepository) GetManualRenewPolicies(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.RenewalPolicy, error) {
	query := `
		SELECT renewal_policy_id, company_id, name, auto_renew, grace_days,
		       late_fee_percent, notice_days, is_active, created_at, updated_at, deleted_at
		FROM subscription.renewal_policies
		WHERE company_id = $1 AND auto_renew = false AND is_active = true AND deleted_at IS NULL
		ORDER BY name
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		r.logger.Error("failed to get manual-renew policies", zap.Error(err))
		return nil, fmt.Errorf("get manual-renew policies: %w", err)
	}
	defer rows.Close()

	var policies []*models.RenewalPolicy
	for rows.Next() {
		var p models.RenewalPolicy
		var deletedAt sql.NullTime
		err := rows.Scan(
			&p.RenewalPolicyID,
			&p.CompanyID,
			&p.Name,
			&p.AutoRenew,
			&p.GraceDays,
			&p.LateFeePercent,
			&p.NoticeDays,
			&p.IsActive,
			&p.CreatedAt,
			&p.UpdatedAt,
			&deletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan manual-renew policy: %w", err)
		}
		if deletedAt.Valid {
			p.DeletedAt = &deletedAt.Time
		}
		policies = append(policies, &p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return policies, nil
}

// -------------------------------------------------------------------------
// Locking
// -------------------------------------------------------------------------

func (r *renewalPolicyRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) (*models.RenewalPolicy, error) {
	query := `
		SELECT renewal_policy_id, company_id, name, auto_renew, grace_days,
		       late_fee_percent, notice_days, is_active, created_at, updated_at, deleted_at
		FROM subscription.renewal_policies
		WHERE company_id = $1 AND renewal_policy_id = $2
		FOR UPDATE
	`
	var policy models.RenewalPolicy
	var deletedAt sql.NullTime
	err := db.QueryRowContext(ctx, query, companyID, renewalPolicyID).Scan(
		&policy.RenewalPolicyID,
		&policy.CompanyID,
		&policy.Name,
		&policy.AutoRenew,
		&policy.GraceDays,
		&policy.LateFeePercent,
		&policy.NoticeDays,
		&policy.IsActive,
		&policy.CreatedAt,
		&policy.UpdatedAt,
		&deletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get renewal policy for update", zap.Error(err))
		return nil, fmt.Errorf("get by id for update: %w", err)
	}
	if deletedAt.Valid {
		policy.DeletedAt = &deletedAt.Time
	}
	return &policy, nil
}
