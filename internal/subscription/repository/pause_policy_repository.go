// FILE: repository/pause_policy_repository.go

package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"auth-service/internal/subscription/models"

	"go.uber.org/zap"
)

// -------------------------------------------------------------------------
// PausePolicyRepository Interface
// -------------------------------------------------------------------------

type PausePolicyRepository interface {
	// -------------------------------------------------------------------------
	// CRUD
	// -------------------------------------------------------------------------

	Create(ctx context.Context, db DBTX, policy *models.PausePolicy) error
	GetByID(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) (*models.PausePolicy, error)
	GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.PausePolicy, error)
	Update(ctx context.Context, db DBTX, policy *models.PausePolicy) error
	Delete(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) error

	// -------------------------------------------------------------------------
	// Status / Lifecycle
	// -------------------------------------------------------------------------

	Activate(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) error
	Deactivate(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) error

	SoftDelete(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) error
	Restore(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) error

	// -------------------------------------------------------------------------
	// Validation
	// -------------------------------------------------------------------------

	Exists(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) (bool, error)
	ExistsByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error)
	IsActive(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) (bool, error)

	// -------------------------------------------------------------------------
	// Querying
	// -------------------------------------------------------------------------

	List(ctx context.Context, db DBTX, filter PausePolicyFilter, p Pagination, s Sort) ([]*models.PausePolicy, int64, error)
	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.PausePolicy, int64, error)

	GetActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.PausePolicy, error)

	GetByMaxPauseDays(ctx context.Context, db DBTX, companyID uuid.UUID, maxPauseDays int) ([]*models.PausePolicy, error)
	GetByAllowedReason(ctx context.Context, db DBTX, companyID uuid.UUID, reason string) ([]*models.PausePolicy, error)

	// -------------------------------------------------------------------------
	// Locking
	// -------------------------------------------------------------------------

	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) (*models.PausePolicy, error)
}

// -------------------------------------------------------------------------
// Filter, Pagination, Sort
// -------------------------------------------------------------------------

type PausePolicyFilter struct {
	CompanyID       uuid.UUID
	PolicyIDs       []uuid.UUID
	Name            *string
	MaxPauseDaysMin *int
	MaxPauseDaysMax *int
	MaxPauseDays    *int // <-- new field for exact match
	FreezeDaysMin   *int
	FreezeDaysMax   *int
	AllowedReason   *string
	IsActive        *bool
	CreatedFrom     *time.Time
	CreatedTo       *time.Time
	UpdatedFrom     *time.Time
	UpdatedTo       *time.Time
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type pausePolicyRepository struct {
	logger *zap.Logger
}

func NewPausePolicyRepository(logger *zap.Logger) PausePolicyRepository {
	return &pausePolicyRepository{
		logger: logger.Named("subscription_pause_policy_repo"),
	}
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (r *pausePolicyRepository) Create(ctx context.Context, db DBTX, policy *models.PausePolicy) error {
	query := `
		INSERT INTO subscription.pause_policies (
			pause_policy_id, company_id, name, max_pause_days, allowed_reasons, freeze_days,
			is_active, created_at, updated_at, deleted_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	_, err := db.ExecContext(ctx, query,
		policy.PausePolicyID,
		policy.CompanyID,
		policy.Name,
		policy.MaxPauseDays,
		pq.Array(policy.AllowedReasons),
		policy.FreezeDays,
		policy.IsActive,
		policy.CreatedAt,
		policy.UpdatedAt,
		policy.DeletedAt,
	)
	if err != nil {
		r.logger.Error("failed to create pause policy", zap.Error(err))
		return fmt.Errorf("create pause policy: %w", err)
	}
	return nil
}

func (r *pausePolicyRepository) GetByID(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) (*models.PausePolicy, error) {
	query := `
		SELECT pause_policy_id, company_id, name, max_pause_days, allowed_reasons, freeze_days,
		       is_active, created_at, updated_at, deleted_at
		FROM subscription.pause_policies
		WHERE company_id = $1 AND pause_policy_id = $2
	`
	var policy models.PausePolicy
	var reasons pq.StringArray // this implements sql.Scanner
	err := db.QueryRowContext(ctx, query, companyID, pausePolicyID).Scan(
		&policy.PausePolicyID,
		&policy.CompanyID,
		&policy.Name,
		&policy.MaxPauseDays,
		&reasons,
		&policy.FreezeDays,
		&policy.IsActive,
		&policy.CreatedAt,
		&policy.UpdatedAt,
		&policy.DeletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get pause policy by ID", zap.Error(err))
		return nil, fmt.Errorf("get pause policy by ID: %w", err)
	}
	policy.AllowedReasons = []string(reasons)
	return &policy, nil
}

func (r *pausePolicyRepository) GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.PausePolicy, error) {
	query := `
		SELECT pause_policy_id, company_id, name, max_pause_days, allowed_reasons, freeze_days,
		       is_active, created_at, updated_at, deleted_at
		FROM subscription.pause_policies
		WHERE company_id = $1 AND name = $2
	`
	var policy models.PausePolicy
	var reasons pq.StringArray
	err := db.QueryRowContext(ctx, query, companyID, name).Scan(
		&policy.PausePolicyID,
		&policy.CompanyID,
		&policy.Name,
		&policy.MaxPauseDays,
		&reasons,
		&policy.FreezeDays,
		&policy.IsActive,
		&policy.CreatedAt,
		&policy.UpdatedAt,
		&policy.DeletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get pause policy by name", zap.String("name", name), zap.Error(err))
		return nil, fmt.Errorf("get pause policy by name: %w", err)
	}
	policy.AllowedReasons = []string(reasons)
	return &policy, nil
}

func (r *pausePolicyRepository) Update(ctx context.Context, db DBTX, policy *models.PausePolicy) error {
	query := `
		UPDATE subscription.pause_policies
		SET name = $1,
		    max_pause_days = $2,
		    allowed_reasons = $3,
		    freeze_days = $4,
		    is_active = $5,
		    updated_at = $6,
		    deleted_at = $7
		WHERE company_id = $8 AND pause_policy_id = $9
	`
	_, err := db.ExecContext(ctx, query,
		policy.Name,
		policy.MaxPauseDays,
		pq.Array(policy.AllowedReasons),
		policy.FreezeDays,
		policy.IsActive,
		policy.UpdatedAt,
		policy.DeletedAt,
		policy.CompanyID,
		policy.PausePolicyID,
	)
	if err != nil {
		r.logger.Error("failed to update pause policy", zap.Error(err))
		return fmt.Errorf("update pause policy: %w", err)
	}
	return nil
}

func (r *pausePolicyRepository) Delete(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) error {
	query := `DELETE FROM subscription.pause_policies WHERE company_id = $1 AND pause_policy_id = $2`
	_, err := db.ExecContext(ctx, query, companyID, pausePolicyID)
	if err != nil {
		r.logger.Error("failed to delete pause policy", zap.Error(err))
		return fmt.Errorf("delete pause policy: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Status / Lifecycle
// -------------------------------------------------------------------------

func (r *pausePolicyRepository) Activate(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) error {
	query := `UPDATE subscription.pause_policies SET is_active = true, updated_at = NOW() WHERE company_id = $1 AND pause_policy_id = $2`
	_, err := db.ExecContext(ctx, query, companyID, pausePolicyID)
	if err != nil {
		r.logger.Error("failed to activate pause policy", zap.Error(err))
		return fmt.Errorf("activate pause policy: %w", err)
	}
	return nil
}

func (r *pausePolicyRepository) Deactivate(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) error {
	query := `UPDATE subscription.pause_policies SET is_active = false, updated_at = NOW() WHERE company_id = $1 AND pause_policy_id = $2`
	_, err := db.ExecContext(ctx, query, companyID, pausePolicyID)
	if err != nil {
		r.logger.Error("failed to deactivate pause policy", zap.Error(err))
		return fmt.Errorf("deactivate pause policy: %w", err)
	}
	return nil
}

func (r *pausePolicyRepository) SoftDelete(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) error {
	query := `UPDATE subscription.pause_policies SET deleted_at = NOW() WHERE company_id = $1 AND pause_policy_id = $2`
	_, err := db.ExecContext(ctx, query, companyID, pausePolicyID)
	if err != nil {
		r.logger.Error("failed to soft delete pause policy", zap.Error(err))
		return fmt.Errorf("soft delete pause policy: %w", err)
	}
	return nil
}

func (r *pausePolicyRepository) Restore(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) error {
	query := `UPDATE subscription.pause_policies SET deleted_at = NULL WHERE company_id = $1 AND pause_policy_id = $2`
	_, err := db.ExecContext(ctx, query, companyID, pausePolicyID)
	if err != nil {
		r.logger.Error("failed to restore pause policy", zap.Error(err))
		return fmt.Errorf("restore pause policy: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Validation
// -------------------------------------------------------------------------

func (r *pausePolicyRepository) Exists(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.pause_policies WHERE company_id = $1 AND pause_policy_id = $2 AND deleted_at IS NULL)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, pausePolicyID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check exist: %w", err)
	}
	return exists, nil
}

func (r *pausePolicyRepository) ExistsByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.pause_policies WHERE company_id = $1 AND name = $2 AND deleted_at IS NULL)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, name).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check exist by name: %w", err)
	}
	return exists, nil
}

func (r *pausePolicyRepository) IsActive(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) (bool, error) {
	query := `SELECT is_active FROM subscription.pause_policies WHERE company_id = $1 AND pause_policy_id = $2 AND deleted_at IS NULL`
	var active bool
	err := db.QueryRowContext(ctx, query, companyID, pausePolicyID).Scan(&active)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("check is active: %w", err)
	}
	return active, nil
}

// -------------------------------------------------------------------------
// Querying
// -------------------------------------------------------------------------

func (r *pausePolicyRepository) List(ctx context.Context, db DBTX, filter PausePolicyFilter, p Pagination, s Sort) ([]*models.PausePolicy, int64, error) {
	where, args := r.buildFilterConditions(filter)
	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	// Count total
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.pause_policies %s`, whereClause)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count pause policies: %w", err)
	}
	if total == 0 {
		return []*models.PausePolicy{}, 0, nil
	}

	// Build sort
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
		SELECT pause_policy_id, company_id, name, max_pause_days, allowed_reasons, freeze_days,
		       is_active, created_at, updated_at, deleted_at
		FROM subscription.pause_policies
		%s %s
		LIMIT $%d OFFSET $%d
	`, whereClause, sortClause, len(args)+1, len(args)+2)

	limitArgs := append(args, p.Limit, p.Offset)
	rows, err := db.QueryContext(ctx, query, limitArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list pause policies: %w", err)
	}
	defer rows.Close()

	var policies []*models.PausePolicy
	for rows.Next() {
		var policy models.PausePolicy
		var reasons pq.StringArray
		err := rows.Scan(
			&policy.PausePolicyID,
			&policy.CompanyID,
			&policy.Name,
			&policy.MaxPauseDays,
			&reasons,
			&policy.FreezeDays,
			&policy.IsActive,
			&policy.CreatedAt,
			&policy.UpdatedAt,
			&policy.DeletedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan pause policy: %w", err)
		}
		policy.AllowedReasons = []string(reasons)
		policies = append(policies, &policy)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", err)
	}
	return policies, total, nil
}

func (r *pausePolicyRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.PausePolicy, int64, error) {
	searchPattern := "%" + query + "%"
	where := "company_id = $1 AND deleted_at IS NULL AND name ILIKE $2"
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.pause_policies WHERE %s`, where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, companyID, searchPattern).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count search pause policies: %w", err)
	}
	if total == 0 {
		return []*models.PausePolicy{}, 0, nil
	}

	dataQuery := fmt.Sprintf(`
		SELECT pause_policy_id, company_id, name, max_pause_days, allowed_reasons, freeze_days,
		       is_active, created_at, updated_at, deleted_at
		FROM subscription.pause_policies
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, 3, 4)

	rows, err := db.QueryContext(ctx, dataQuery, companyID, searchPattern, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("search pause policies: %w", err)
	}
	defer rows.Close()

	var policies []*models.PausePolicy
	for rows.Next() {
		var policy models.PausePolicy
		var reasons pq.StringArray
		err := rows.Scan(
			&policy.PausePolicyID,
			&policy.CompanyID,
			&policy.Name,
			&policy.MaxPauseDays,
			&reasons,
			&policy.FreezeDays,
			&policy.IsActive,
			&policy.CreatedAt,
			&policy.UpdatedAt,
			&policy.DeletedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan pause policy: %w", err)
		}
		policy.AllowedReasons = []string(reasons)
		policies = append(policies, &policy)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", err)
	}
	return policies, total, nil
}

func (r *pausePolicyRepository) GetActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.PausePolicy, error) {
	query := `
		SELECT pause_policy_id, company_id, name, max_pause_days, allowed_reasons, freeze_days,
		       is_active, created_at, updated_at, deleted_at
		FROM subscription.pause_policies
		WHERE company_id = $1 AND is_active = true AND deleted_at IS NULL
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("get active pause policies: %w", err)
	}
	defer rows.Close()

	var policies []*models.PausePolicy
	for rows.Next() {
		var policy models.PausePolicy
		var reasons pq.StringArray
		err := rows.Scan(
			&policy.PausePolicyID,
			&policy.CompanyID,
			&policy.Name,
			&policy.MaxPauseDays,
			&reasons,
			&policy.FreezeDays,
			&policy.IsActive,
			&policy.CreatedAt,
			&policy.UpdatedAt,
			&policy.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan pause policy: %w", err)
		}
		policy.AllowedReasons = []string(reasons)
		policies = append(policies, &policy)
	}
	return policies, rows.Err()
}

func (r *pausePolicyRepository) GetByMaxPauseDays(ctx context.Context, db DBTX, companyID uuid.UUID, maxPauseDays int) ([]*models.PausePolicy, error) {
	query := `
		SELECT pause_policy_id, company_id, name, max_pause_days, allowed_reasons, freeze_days,
		       is_active, created_at, updated_at, deleted_at
		FROM subscription.pause_policies
		WHERE company_id = $1 AND max_pause_days >= $2 AND deleted_at IS NULL
		ORDER BY max_pause_days ASC
	`
	rows, err := db.QueryContext(ctx, query, companyID, maxPauseDays)
	if err != nil {
		return nil, fmt.Errorf("get by max pause days: %w", err)
	}
	defer rows.Close()

	var policies []*models.PausePolicy
	for rows.Next() {
		var policy models.PausePolicy
		var reasons pq.StringArray
		err := rows.Scan(
			&policy.PausePolicyID,
			&policy.CompanyID,
			&policy.Name,
			&policy.MaxPauseDays,
			&reasons,
			&policy.FreezeDays,
			&policy.IsActive,
			&policy.CreatedAt,
			&policy.UpdatedAt,
			&policy.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan pause policy: %w", err)
		}
		policy.AllowedReasons = []string(reasons)
		policies = append(policies, &policy)
	}
	return policies, rows.Err()
}

func (r *pausePolicyRepository) GetByAllowedReason(ctx context.Context, db DBTX, companyID uuid.UUID, reason string) ([]*models.PausePolicy, error) {
	query := `
		SELECT pause_policy_id, company_id, name, max_pause_days, allowed_reasons, freeze_days,
		       is_active, created_at, updated_at, deleted_at
		FROM subscription.pause_policies
		WHERE company_id = $1 AND $2 = ANY(allowed_reasons) AND deleted_at IS NULL
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, companyID, reason)
	if err != nil {
		return nil, fmt.Errorf("get by allowed reason: %w", err)
	}
	defer rows.Close()

	var policies []*models.PausePolicy
	for rows.Next() {
		var policy models.PausePolicy
		var reasons pq.StringArray
		err := rows.Scan(
			&policy.PausePolicyID,
			&policy.CompanyID,
			&policy.Name,
			&policy.MaxPauseDays,
			&reasons,
			&policy.FreezeDays,
			&policy.IsActive,
			&policy.CreatedAt,
			&policy.UpdatedAt,
			&policy.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan pause policy: %w", err)
		}
		policy.AllowedReasons = []string(reasons)
		policies = append(policies, &policy)
	}
	return policies, rows.Err()
}

// -------------------------------------------------------------------------
// Locking
// -------------------------------------------------------------------------

func (r *pausePolicyRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) (*models.PausePolicy, error) {
	query := `
		SELECT pause_policy_id, company_id, name, max_pause_days, allowed_reasons, freeze_days,
		       is_active, created_at, updated_at, deleted_at
		FROM subscription.pause_policies
		WHERE company_id = $1 AND pause_policy_id = $2
		FOR UPDATE
	`
	var policy models.PausePolicy
	var reasons pq.StringArray
	err := db.QueryRowContext(ctx, query, companyID, pausePolicyID).Scan(
		&policy.PausePolicyID,
		&policy.CompanyID,
		&policy.Name,
		&policy.MaxPauseDays,
		&reasons,
		&policy.FreezeDays,
		&policy.IsActive,
		&policy.CreatedAt,
		&policy.UpdatedAt,
		&policy.DeletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get pause policy for update", zap.Error(err))
		return nil, fmt.Errorf("get pause policy for update: %w", err)
	}
	policy.AllowedReasons = []string(reasons)
	return &policy, nil
}

// -------------------------------------------------------------------------
// Helper: build filter conditions
// -------------------------------------------------------------------------

func (r *pausePolicyRepository) buildFilterConditions(filter PausePolicyFilter) ([]string, []interface{}) {
	var conditions []string
	var args []interface{}
	argPos := 1
	if filter.MaxPauseDays != nil {
		conditions = append(conditions, fmt.Sprintf("max_pause_days = $%d", argPos))
		args = append(args, *filter.MaxPauseDays)
		argPos++
	}
	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", argPos))
		args = append(args, filter.CompanyID)
		argPos++
	}

	if len(filter.PolicyIDs) > 0 {
		placeholders := make([]string, len(filter.PolicyIDs))
		for i, id := range filter.PolicyIDs {
			placeholders[i] = fmt.Sprintf("$%d", argPos+i)
			args = append(args, id)
		}
		conditions = append(conditions, fmt.Sprintf("pause_policy_id IN (%s)", strings.Join(placeholders, ",")))
		argPos += len(filter.PolicyIDs)
	}

	if filter.Name != nil {
		conditions = append(conditions, fmt.Sprintf("name ILIKE $%d", argPos))
		args = append(args, "%"+*filter.Name+"%")
		argPos++
	}

	if filter.MaxPauseDaysMin != nil {
		conditions = append(conditions, fmt.Sprintf("max_pause_days >= $%d", argPos))
		args = append(args, *filter.MaxPauseDaysMin)
		argPos++
	}
	if filter.MaxPauseDaysMax != nil {
		conditions = append(conditions, fmt.Sprintf("max_pause_days <= $%d", argPos))
		args = append(args, *filter.MaxPauseDaysMax)
		argPos++
	}

	if filter.FreezeDaysMin != nil {
		conditions = append(conditions, fmt.Sprintf("freeze_days >= $%d", argPos))
		args = append(args, *filter.FreezeDaysMin)
		argPos++
	}
	if filter.FreezeDaysMax != nil {
		conditions = append(conditions, fmt.Sprintf("freeze_days <= $%d", argPos))
		args = append(args, *filter.FreezeDaysMax)
		argPos++
	}

	if filter.AllowedReason != nil {
		conditions = append(conditions, fmt.Sprintf("$%d = ANY(allowed_reasons)", argPos))
		args = append(args, *filter.AllowedReason)
		argPos++
	}

	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argPos))
		args = append(args, *filter.IsActive)
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

	conditions = append(conditions, "deleted_at IS NULL")
	return conditions, args
}
