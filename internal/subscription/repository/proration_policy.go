// repository/proration_policy_repo.go
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/models"
)

type ProrationPolicyRepository interface {
	Create(ctx context.Context, db DBTX, policy *models.ProrationPolicy) error
	Update(ctx context.Context, db DBTX, policy *models.ProrationPolicy) error
	Delete(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) error

	GetByID(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) (*models.ProrationPolicy, error)
	GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.ProrationPolicy, error)

	List(ctx context.Context, db DBTX, filter ProrationPolicyFilter, p Pagination, s Sort) ([]*models.ProrationPolicy, int64, error)
	ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.ProrationPolicy, error)

	Exists(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) (bool, error)
	ExistsByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error)

	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit int, offset int) ([]*models.ProrationPolicy, int64, error)

	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) (*models.ProrationPolicy, error)
	GetDefault(ctx context.Context, db DBTX, companyID uuid.UUID) (*models.ProrationPolicy, error)
}

type ProrationPolicyFilter struct {
	CompanyID          uuid.UUID
	ProrationPolicyIDs []uuid.UUID
	Name               *string
	UpgradeType        *string
	DowngradeType      *string
	IsActive           *bool
}

type prorationPolicyRepository struct {
	logger *zap.Logger
}

func NewProrationPolicyRepository(logger *zap.Logger) ProrationPolicyRepository {
	return &prorationPolicyRepository{
		logger: logger.Named("subscription_proration_policy_repo"),
	}
}

const prorationPolicyTable = "subscription.proration_policies"

func (r *prorationPolicyRepository) scanProrationPolicy(s scanner) (*models.ProrationPolicy, error) {
	var p models.ProrationPolicy
	err := s.Scan(
		&p.ProrationPolicyID,
		&p.CompanyID,
		&p.Name,
		&p.UpgradeType,
		&p.DowngradeType,
		&p.IsActive,
		&p.CreatedAt,
		&p.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan proration policy: %w", err)
	}
	return &p, nil
}

func (r *prorationPolicyRepository) buildProrationPolicyFilter(filter ProrationPolicyFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}

	if len(filter.ProrationPolicyIDs) > 0 {
		placeholders := make([]string, len(filter.ProrationPolicyIDs))
		for i, id := range filter.ProrationPolicyIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("proration_policy_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.Name != nil {
		conds = append(conds, fmt.Sprintf("name = $%d", idx))
		args = append(args, *filter.Name)
		idx++
	}
	if filter.UpgradeType != nil {
		conds = append(conds, fmt.Sprintf("upgrade_type = $%d", idx))
		args = append(args, *filter.UpgradeType)
		idx++
	}
	if filter.DowngradeType != nil {
		conds = append(conds, fmt.Sprintf("downgrade_type = $%d", idx))
		args = append(args, *filter.DowngradeType)
		idx++
	}
	if filter.IsActive != nil {
		conds = append(conds, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

var prorationPolicyAllowedSort = map[string]bool{
	"proration_policy_id": true,
	"name":                true,
	"upgrade_type":        true,
	"downgrade_type":      true,
	"is_active":           true,
	"created_at":          true,
	"updated_at":          true,
}

// ---- CRUD ----

func (r *prorationPolicyRepository) Create(ctx context.Context, db DBTX, policy *models.ProrationPolicy) error {
	query := `
		INSERT INTO subscription.proration_policies (
			proration_policy_id, company_id, name, upgrade_type,
			downgrade_type, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		policy.ProrationPolicyID,
		policy.CompanyID,
		policy.Name,
		policy.UpgradeType,
		policy.DowngradeType,
		policy.IsActive,
	).Scan(&policy.CreatedAt, &policy.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create proration policy: %w", err)
	}
	return nil
}

func (r *prorationPolicyRepository) Update(ctx context.Context, db DBTX, policy *models.ProrationPolicy) error {
	query := `
		UPDATE subscription.proration_policies SET
			name = $3,
			upgrade_type = $4,
			downgrade_type = $5,
			is_active = $6,
			updated_at = NOW()
		WHERE proration_policy_id = $1 AND company_id = $2
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		policy.ProrationPolicyID,
		policy.CompanyID,
		policy.Name,
		policy.UpgradeType,
		policy.DowngradeType,
		policy.IsActive,
	).Scan(&policy.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return fmt.Errorf("update proration policy: %w", err)
	}
	return nil
}

func (r *prorationPolicyRepository) Delete(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) error {
	query := `DELETE FROM subscription.proration_policies WHERE proration_policy_id = $1 AND company_id = $2`
	result, err := db.ExecContext(ctx, query, prorationPolicyID, companyID)
	if err != nil {
		return fmt.Errorf("delete proration policy: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// ---- Single Fetch ----

func (r *prorationPolicyRepository) GetByID(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) (*models.ProrationPolicy, error) {
	query := `
		SELECT proration_policy_id, company_id, name, upgrade_type,
			downgrade_type, is_active, created_at, updated_at
		FROM subscription.proration_policies
		WHERE proration_policy_id = $1 AND company_id = $2
	`
	row := db.QueryRowContext(ctx, query, prorationPolicyID, companyID)
	return r.scanProrationPolicy(row)
}

func (r *prorationPolicyRepository) GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.ProrationPolicy, error) {
	query := `
		SELECT proration_policy_id, company_id, name, upgrade_type,
			downgrade_type, is_active, created_at, updated_at
		FROM subscription.proration_policies
		WHERE company_id = $1 AND name = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, name)
	return r.scanProrationPolicy(row)
}

// ---- Listing ----

func (r *prorationPolicyRepository) List(ctx context.Context, db DBTX, filter ProrationPolicyFilter, p Pagination, s Sort) ([]*models.ProrationPolicy, int64, error) {
	where, args := r.buildProrationPolicyFilter(filter)
	if where == "" {
		if filter.CompanyID == uuid.Nil {
			return nil, 0, fmt.Errorf("company_id is required in filter")
		}
		if !strings.Contains(where, "company_id") {
			where = "WHERE company_id = $1"
			args = []interface{}{filter.CompanyID}
		}
	}

	orderBy, err := validateSort(s, prorationPolicyAllowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY name"
	}

	limit, offset := validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", prorationPolicyTable, where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count proration policies: %w", err)
	}
	if total == 0 {
		return []*models.ProrationPolicy{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT proration_policy_id, company_id, name, upgrade_type,
			downgrade_type, is_active, created_at, updated_at
		FROM %s
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, prorationPolicyTable, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list proration policies: %w", err)
	}
	defer rows.Close()

	var result []*models.ProrationPolicy
	for rows.Next() {
		p, err := r.scanProrationPolicy(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, p)
	}
	return result, total, rows.Err()
}

func (r *prorationPolicyRepository) ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.ProrationPolicy, error) {
	filter := ProrationPolicyFilter{
		CompanyID: companyID,
		IsActive:  ptrBool(true),
	}
	policies, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{})
	return policies, err
}

// ---- Validation ----

func (r *prorationPolicyRepository) Exists(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.proration_policies WHERE proration_policy_id = $1 AND company_id = $2)`
	err := db.QueryRowContext(ctx, query, prorationPolicyID, companyID).Scan(&exists)
	return exists, err
}

func (r *prorationPolicyRepository) ExistsByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.proration_policies WHERE company_id = $1 AND name = $2)`
	err := db.QueryRowContext(ctx, query, companyID, name).Scan(&exists)
	return exists, err
}

// ---- Search ----

func (r *prorationPolicyRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit int, offset int) ([]*models.ProrationPolicy, int64, error) {
	pattern := "%" + query + "%"
	baseQuery := `
		SELECT proration_policy_id, company_id, name, upgrade_type,
			downgrade_type, is_active, created_at, updated_at
		FROM subscription.proration_policies
	`
	where := "WHERE company_id = $1 AND (name ILIKE $2)"
	args := []interface{}{companyID, pattern}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", prorationPolicyTable, where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search proration policies count: %w", err)
	}
	if total == 0 {
		return []*models.ProrationPolicy{}, 0, nil
	}

	querySQL := fmt.Sprintf(`%s %s ORDER BY name LIMIT $%d OFFSET $%d`, baseQuery, where, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search proration policies: %w", err)
	}
	defer rows.Close()

	var result []*models.ProrationPolicy
	for rows.Next() {
		p, err := r.scanProrationPolicy(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, p)
	}
	return result, total, rows.Err()
}

// ---- Locking ----

func (r *prorationPolicyRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, prorationPolicyID uuid.UUID) (*models.ProrationPolicy, error) {
	query := `
		SELECT proration_policy_id, company_id, name, upgrade_type,
			downgrade_type, is_active, created_at, updated_at
		FROM subscription.proration_policies
		WHERE proration_policy_id = $1 AND company_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, prorationPolicyID, companyID)
	return r.scanProrationPolicy(row)
}

// ---- GetDefault ----

func (r *prorationPolicyRepository) GetDefault(ctx context.Context, db DBTX, companyID uuid.UUID) (*models.ProrationPolicy, error) {
	filter := ProrationPolicyFilter{
		CompanyID: companyID,
		IsActive:  ptrBool(true),
	}
	policies, _, err := r.List(ctx, db, filter, Pagination{Limit: 1}, Sort{Field: "name", Direction: "ASC"})
	if err != nil {
		return nil, err
	}
	if len(policies) == 0 {
		return nil, errors.ErrNotFound
	}
	return policies[0], nil
}
