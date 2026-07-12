// FILE: repository/proration_policy_repository.go

package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/subscription/models"
	"auth-service/internal/subscription/models/enums"

	"go.uber.org/zap"
)

// -------------------------------------------------------------------------
// ProrationPolicyRepository Interface
// -------------------------------------------------------------------------

type ProrationPolicyRepository interface {
	// -------------------------------------------------------------------------
	// CRUD
	// -------------------------------------------------------------------------

	Create(ctx context.Context, db DBTX, policy *models.ProrationPolicy) error
	GetByID(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) (*models.ProrationPolicy, error)
	GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.ProrationPolicy, error)
	Update(ctx context.Context, db DBTX, policy *models.ProrationPolicy) error
	Delete(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) error

	// -------------------------------------------------------------------------
	// Status / Lifecycle
	// -------------------------------------------------------------------------

	Activate(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) error
	Deactivate(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) error

	SoftDelete(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) error
	Restore(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) error

	// -------------------------------------------------------------------------
	// Validation
	// -------------------------------------------------------------------------

	Exists(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) (bool, error)
	ExistsByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error)
	IsActive(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) (bool, error)

	// -------------------------------------------------------------------------
	// Querying
	// -------------------------------------------------------------------------
	GetByNameWithDeleted(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.ProrationPolicy, error)

	List(ctx context.Context, db DBTX, filter ProrationPolicyFilter, p Pagination, s Sort) ([]*models.ProrationPolicy, int64, error)
	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.ProrationPolicy, int64, error)

	GetActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.ProrationPolicy, error)

	GetByUpgradeType(ctx context.Context, db DBTX, companyID uuid.UUID, upgradeType enums.UpgradeType) ([]*models.ProrationPolicy, error)
	GetByDowngradeType(ctx context.Context, db DBTX, companyID uuid.UUID, downgradeType enums.DowngradeType) ([]*models.ProrationPolicy, error)

	// -------------------------------------------------------------------------
	// Locking
	// -------------------------------------------------------------------------

	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) (*models.ProrationPolicy, error)
}

// -------------------------------------------------------------------------
// Filter, Pagination, Sort
// -------------------------------------------------------------------------

type ProrationPolicyFilter struct {
	CompanyID     uuid.UUID
	PolicyIDs     []uuid.UUID
	Name          *string
	UpgradeType   *enums.UpgradeType
	DowngradeType *enums.DowngradeType
	IsActive      *bool
	CreatedFrom   *time.Time
	CreatedTo     *time.Time
	UpdatedFrom   *time.Time
	UpdatedTo     *time.Time
}

// Pagination and Sort are defined in the same package or shared.
// They are re‑declared here for completeness if not imported.
// If you have a shared package, you can remove these.

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type prorationPolicyRepository struct {
	logger *zap.Logger
}

// NewProrationPolicyRepository creates a new ProrationPolicyRepository.
func NewProrationPolicyRepository(logger *zap.Logger) ProrationPolicyRepository {
	return &prorationPolicyRepository{
		logger: logger.Named("subscription_proration_policy_repo"),
	}
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (r *prorationPolicyRepository) Create(ctx context.Context, db DBTX, policy *models.ProrationPolicy) error {
	query := `
		INSERT INTO subscription.proration_policies (
			proration_policy_id, company_id, name, upgrade_type, downgrade_type,
			is_active, created_at, updated_at, deleted_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := db.ExecContext(ctx, query,
		policy.ProrationPolicyID,
		policy.CompanyID,
		policy.Name,
		string(policy.UpgradeType),
		string(policy.DowngradeType),
		policy.IsActive,
		policy.CreatedAt,
		policy.UpdatedAt,
		policy.DeletedAt,
	)
	if err != nil {
		r.logger.Error("failed to create proration policy", zap.Error(err))
		return fmt.Errorf("create proration policy: %w", err)
	}
	return nil
}

func (r *prorationPolicyRepository) GetByID(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) (*models.ProrationPolicy, error) {
	query := `
		SELECT proration_policy_id, company_id, name, upgrade_type, downgrade_type,
		       is_active, created_at, updated_at, deleted_at
		FROM subscription.proration_policies
		WHERE company_id = $1 AND proration_policy_id = $2
	`
	var policy models.ProrationPolicy
	var upgradeType, downgradeType string
	err := db.QueryRowContext(ctx, query, companyID, prorationPolicyID).Scan(
		&policy.ProrationPolicyID,
		&policy.CompanyID,
		&policy.Name,
		&upgradeType,
		&downgradeType,
		&policy.IsActive,
		&policy.CreatedAt,
		&policy.UpdatedAt,
		&policy.DeletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get proration policy by ID", zap.Error(err))
		return nil, fmt.Errorf("get proration policy by ID: %w", err)
	}
	policy.UpgradeType = enums.UpgradeType(upgradeType)
	policy.DowngradeType = enums.DowngradeType(downgradeType)
	return &policy, nil
}

func (r *prorationPolicyRepository) GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.ProrationPolicy, error) {
	query := `
		SELECT proration_policy_id, company_id, name, upgrade_type, downgrade_type,
		       is_active, created_at, updated_at, deleted_at
		FROM subscription.proration_policies
		WHERE company_id = $1 AND name = $2
	`
	var policy models.ProrationPolicy
	var upgradeType, downgradeType string
	err := db.QueryRowContext(ctx, query, companyID, name).Scan(
		&policy.ProrationPolicyID,
		&policy.CompanyID,
		&policy.Name,
		&upgradeType,
		&downgradeType,
		&policy.IsActive,
		&policy.CreatedAt,
		&policy.UpdatedAt,
		&policy.DeletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get proration policy by name", zap.String("name", name), zap.Error(err))
		return nil, fmt.Errorf("get proration policy by name: %w", err)
	}
	policy.UpgradeType = enums.UpgradeType(upgradeType)
	policy.DowngradeType = enums.DowngradeType(downgradeType)
	return &policy, nil
}

func (r *prorationPolicyRepository) Update(ctx context.Context, db DBTX, policy *models.ProrationPolicy) error {
	query := `
		UPDATE subscription.proration_policies
		SET name = $1,
		    upgrade_type = $2,
		    downgrade_type = $3,
		    is_active = $4,
		    updated_at = $5,
		    deleted_at = $6
		WHERE company_id = $7 AND proration_policy_id = $8
	`
	_, err := db.ExecContext(ctx, query,
		policy.Name,
		string(policy.UpgradeType),
		string(policy.DowngradeType),
		policy.IsActive,
		policy.UpdatedAt,
		policy.DeletedAt,
		policy.CompanyID,
		policy.ProrationPolicyID,
	)
	if err != nil {
		r.logger.Error("failed to update proration policy", zap.Error(err))
		return fmt.Errorf("update proration policy: %w", err)
	}
	return nil
}

func (r *prorationPolicyRepository) Delete(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) error {
	query := `DELETE FROM subscription.proration_policies WHERE company_id = $1 AND proration_policy_id = $2`
	result, err := db.ExecContext(ctx, query, companyID, prorationPolicyID)
	if err != nil {
		r.logger.Error("failed to delete proration policy", zap.Error(err))
		return fmt.Errorf("delete proration policy: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// -------------------------------------------------------------------------
// Status / Lifecycle
// -------------------------------------------------------------------------

func (r *prorationPolicyRepository) Activate(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) error {
	query := `UPDATE subscription.proration_policies SET is_active = true, updated_at = NOW() WHERE company_id = $1 AND proration_policy_id = $2`
	_, err := db.ExecContext(ctx, query, companyID, prorationPolicyID)
	if err != nil {
		r.logger.Error("failed to activate proration policy", zap.Error(err))
		return fmt.Errorf("activate proration policy: %w", err)
	}
	return nil
}

func (r *prorationPolicyRepository) Deactivate(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) error {
	query := `UPDATE subscription.proration_policies SET is_active = false, updated_at = NOW() WHERE company_id = $1 AND proration_policy_id = $2`
	_, err := db.ExecContext(ctx, query, companyID, prorationPolicyID)
	if err != nil {
		r.logger.Error("failed to deactivate proration policy", zap.Error(err))
		return fmt.Errorf("deactivate proration policy: %w", err)
	}
	return nil
}

func (r *prorationPolicyRepository) SoftDelete(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) error {
	query := `UPDATE subscription.proration_policies SET deleted_at = NOW() WHERE company_id = $1 AND proration_policy_id = $2`
	_, err := db.ExecContext(ctx, query, companyID, prorationPolicyID)
	if err != nil {
		r.logger.Error("failed to soft delete proration policy", zap.Error(err))
		return fmt.Errorf("soft delete proration policy: %w", err)
	}
	return nil
}

func (r *prorationPolicyRepository) Restore(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) error {
	query := `UPDATE subscription.proration_policies SET deleted_at = NULL WHERE company_id = $1 AND proration_policy_id = $2`
	_, err := db.ExecContext(ctx, query, companyID, prorationPolicyID)
	if err != nil {
		r.logger.Error("failed to restore proration policy", zap.Error(err))
		return fmt.Errorf("restore proration policy: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Validation
// -------------------------------------------------------------------------

func (r *prorationPolicyRepository) Exists(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.proration_policies WHERE company_id = $1 AND proration_policy_id = $2 AND deleted_at IS NULL)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, prorationPolicyID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check exist: %w", err)
	}
	return exists, nil
}

func (r *prorationPolicyRepository) ExistsByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.proration_policies WHERE company_id = $1 AND name = $2 AND deleted_at IS NULL)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, name).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check exist by name: %w", err)
	}
	return exists, nil
}

func (r *prorationPolicyRepository) IsActive(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) (bool, error) {
	query := `SELECT is_active FROM subscription.proration_policies WHERE company_id = $1 AND proration_policy_id = $2 AND deleted_at IS NULL`
	var active bool
	err := db.QueryRowContext(ctx, query, companyID, prorationPolicyID).Scan(&active)
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

func (r *prorationPolicyRepository) List(ctx context.Context, db DBTX, filter ProrationPolicyFilter, p Pagination, s Sort) ([]*models.ProrationPolicy, int64, error) {
	where, args := r.buildFilterConditions(filter)
	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	// Count total
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.proration_policies %s`, whereClause)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count proration policies: %w", err)
	}
	if total == 0 {
		return []*models.ProrationPolicy{}, 0, nil
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
		SELECT proration_policy_id, company_id, name, upgrade_type, downgrade_type,
		       is_active, created_at, updated_at, deleted_at
		FROM subscription.proration_policies
		%s %s
		LIMIT $%d OFFSET $%d
	`, whereClause, sortClause, len(args)+1, len(args)+2)

	limitArgs := append(args, p.Limit, p.Offset)
	rows, err := db.QueryContext(ctx, query, limitArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list proration policies: %w", err)
	}
	defer rows.Close()

	var policies []*models.ProrationPolicy
	for rows.Next() {
		var policy models.ProrationPolicy
		var upgradeType, downgradeType string
		err := rows.Scan(
			&policy.ProrationPolicyID,
			&policy.CompanyID,
			&policy.Name,
			&upgradeType,
			&downgradeType,
			&policy.IsActive,
			&policy.CreatedAt,
			&policy.UpdatedAt,
			&policy.DeletedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan proration policy: %w", err)
		}
		policy.UpgradeType = enums.UpgradeType(upgradeType)
		policy.DowngradeType = enums.DowngradeType(downgradeType)
		policies = append(policies, &policy)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", err)
	}
	return policies, total, nil
}

func (r *prorationPolicyRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.ProrationPolicy, int64, error) {
	searchPattern := "%" + query + "%"
	where := "company_id = $1 AND deleted_at IS NULL AND name ILIKE $2"
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.proration_policies WHERE %s`, where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, companyID, searchPattern).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count search proration policies: %w", err)
	}
	if total == 0 {
		return []*models.ProrationPolicy{}, 0, nil
	}

	dataQuery := fmt.Sprintf(`
		SELECT proration_policy_id, company_id, name, upgrade_type, downgrade_type,
		       is_active, created_at, updated_at, deleted_at
		FROM subscription.proration_policies
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, 3, 4)

	rows, err := db.QueryContext(ctx, dataQuery, companyID, searchPattern, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("search proration policies: %w", err)
	}
	defer rows.Close()

	var policies []*models.ProrationPolicy
	for rows.Next() {
		var policy models.ProrationPolicy
		var upgradeType, downgradeType string
		err := rows.Scan(
			&policy.ProrationPolicyID,
			&policy.CompanyID,
			&policy.Name,
			&upgradeType,
			&downgradeType,
			&policy.IsActive,
			&policy.CreatedAt,
			&policy.UpdatedAt,
			&policy.DeletedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan proration policy: %w", err)
		}
		policy.UpgradeType = enums.UpgradeType(upgradeType)
		policy.DowngradeType = enums.DowngradeType(downgradeType)
		policies = append(policies, &policy)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", err)
	}
	return policies, total, nil
}

func (r *prorationPolicyRepository) GetActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.ProrationPolicy, error) {
	query := `
		SELECT proration_policy_id, company_id, name, upgrade_type, downgrade_type,
		       is_active, created_at, updated_at, deleted_at
		FROM subscription.proration_policies
		WHERE company_id = $1 AND is_active = true AND deleted_at IS NULL
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("get active proration policies: %w", err)
	}
	defer rows.Close()

	var policies []*models.ProrationPolicy
	for rows.Next() {
		var policy models.ProrationPolicy
		var upgradeType, downgradeType string
		err := rows.Scan(
			&policy.ProrationPolicyID,
			&policy.CompanyID,
			&policy.Name,
			&upgradeType,
			&downgradeType,
			&policy.IsActive,
			&policy.CreatedAt,
			&policy.UpdatedAt,
			&policy.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan proration policy: %w", err)
		}
		policy.UpgradeType = enums.UpgradeType(upgradeType)
		policy.DowngradeType = enums.DowngradeType(downgradeType)
		policies = append(policies, &policy)
	}
	return policies, rows.Err()
}

func (r *prorationPolicyRepository) GetByUpgradeType(ctx context.Context, db DBTX, companyID uuid.UUID, upgradeType enums.UpgradeType) ([]*models.ProrationPolicy, error) {
	query := `
		SELECT proration_policy_id, company_id, name, upgrade_type, downgrade_type,
		       is_active, created_at, updated_at, deleted_at
		FROM subscription.proration_policies
		WHERE company_id = $1 AND upgrade_type = $2 AND deleted_at IS NULL
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, companyID, string(upgradeType))
	if err != nil {
		return nil, fmt.Errorf("get by upgrade type: %w", err)
	}
	defer rows.Close()

	var policies []*models.ProrationPolicy
	for rows.Next() {
		var policy models.ProrationPolicy
		var ut, dt string
		err := rows.Scan(
			&policy.ProrationPolicyID,
			&policy.CompanyID,
			&policy.Name,
			&ut,
			&dt,
			&policy.IsActive,
			&policy.CreatedAt,
			&policy.UpdatedAt,
			&policy.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan proration policy: %w", err)
		}
		policy.UpgradeType = enums.UpgradeType(ut)
		policy.DowngradeType = enums.DowngradeType(dt)
		policies = append(policies, &policy)
	}
	return policies, rows.Err()
}

func (r *prorationPolicyRepository) GetByDowngradeType(ctx context.Context, db DBTX, companyID uuid.UUID, downgradeType enums.DowngradeType) ([]*models.ProrationPolicy, error) {
	query := `
		SELECT proration_policy_id, company_id, name, upgrade_type, downgrade_type,
		       is_active, created_at, updated_at, deleted_at
		FROM subscription.proration_policies
		WHERE company_id = $1 AND downgrade_type = $2 AND deleted_at IS NULL
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, companyID, string(downgradeType))
	if err != nil {
		return nil, fmt.Errorf("get by downgrade type: %w", err)
	}
	defer rows.Close()

	var policies []*models.ProrationPolicy
	for rows.Next() {
		var policy models.ProrationPolicy
		var ut, dt string
		err := rows.Scan(
			&policy.ProrationPolicyID,
			&policy.CompanyID,
			&policy.Name,
			&ut,
			&dt,
			&policy.IsActive,
			&policy.CreatedAt,
			&policy.UpdatedAt,
			&policy.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan proration policy: %w", err)
		}
		policy.UpgradeType = enums.UpgradeType(ut)
		policy.DowngradeType = enums.DowngradeType(dt)
		policies = append(policies, &policy)
	}
	return policies, rows.Err()
}

// -------------------------------------------------------------------------
// Locking
// -------------------------------------------------------------------------

func (r *prorationPolicyRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) (*models.ProrationPolicy, error) {
	query := `
		SELECT proration_policy_id, company_id, name, upgrade_type, downgrade_type,
		       is_active, created_at, updated_at, deleted_at
		FROM subscription.proration_policies
		WHERE company_id = $1 AND proration_policy_id = $2
		FOR UPDATE
	`
	var policy models.ProrationPolicy
	var upgradeType, downgradeType string
	err := db.QueryRowContext(ctx, query, companyID, prorationPolicyID).Scan(
		&policy.ProrationPolicyID,
		&policy.CompanyID,
		&policy.Name,
		&upgradeType,
		&downgradeType,
		&policy.IsActive,
		&policy.CreatedAt,
		&policy.UpdatedAt,
		&policy.DeletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get proration policy for update", zap.Error(err))
		return nil, fmt.Errorf("get proration policy for update: %w", err)
	}
	policy.UpgradeType = enums.UpgradeType(upgradeType)
	policy.DowngradeType = enums.DowngradeType(downgradeType)
	return &policy, nil
}

// -------------------------------------------------------------------------
// Helper: build filter conditions
// -------------------------------------------------------------------------

func (r *prorationPolicyRepository) buildFilterConditions(filter ProrationPolicyFilter) ([]string, []interface{}) {
	var conditions []string
	var args []interface{}
	argPos := 1

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
		conditions = append(conditions, fmt.Sprintf("proration_policy_id IN (%s)", strings.Join(placeholders, ",")))
		argPos += len(filter.PolicyIDs)
	}

	if filter.Name != nil {
		conditions = append(conditions, fmt.Sprintf("name ILIKE $%d", argPos))
		args = append(args, "%"+*filter.Name+"%")
		argPos++
	}

	if filter.UpgradeType != nil {
		conditions = append(conditions, fmt.Sprintf("upgrade_type = $%d", argPos))
		args = append(args, string(*filter.UpgradeType))
		argPos++
	}

	if filter.DowngradeType != nil {
		conditions = append(conditions, fmt.Sprintf("downgrade_type = $%d", argPos))
		args = append(args, string(*filter.DowngradeType))
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

	// Always exclude soft-deleted records
	conditions = append(conditions, "deleted_at IS NULL")

	return conditions, args
}
func (r *prorationPolicyRepository) GetByNameWithDeleted(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.ProrationPolicy, error) {
	query := `
        SELECT proration_policy_id, company_id, name, upgrade_type, downgrade_type,
               is_active, created_at, updated_at, deleted_at
        FROM subscription.proration_policies
        WHERE company_id = $1 AND name = $2
    `
	var policy models.ProrationPolicy
	err := db.QueryRowContext(ctx, query, companyID, name).Scan(
		&policy.ProrationPolicyID,
		&policy.CompanyID,
		&policy.Name,
		&policy.UpgradeType,
		&policy.DowngradeType,
		&policy.IsActive,
		&policy.CreatedAt,
		&policy.UpdatedAt,
		&policy.DeletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get proration policy by name with deleted: %w", err)
	}
	return &policy, nil
}
