// repository/pause_policy_repo.go
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

type PausePolicyRepository interface {
	Create(ctx context.Context, db DBTX, policy *models.PausePolicy) error
	Update(ctx context.Context, db DBTX, policy *models.PausePolicy) error
	Delete(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) error

	GetByID(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) (*models.PausePolicy, error)
	GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.PausePolicy, error)

	List(ctx context.Context, db DBTX, filter PausePolicyFilter, p Pagination, s Sort) ([]*models.PausePolicy, int64, error)
	ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.PausePolicy, error)

	Exists(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) (bool, error)
	ExistsByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error)

	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit int, offset int) ([]*models.PausePolicy, int64, error)

	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) (*models.PausePolicy, error)
	GetDefault(ctx context.Context, db DBTX, companyID uuid.UUID) (*models.PausePolicy, error)
}

type PausePolicyFilter struct {
	CompanyID       uuid.UUID
	PausePolicyIDs  []uuid.UUID
	Name            *string
	IsActive        *bool
	MaxPauseDaysMin *int
	MaxPauseDaysMax *int
	FreezeDaysMin   *int
	FreezeDaysMax   *int
}

type pausePolicyRepository struct {
	logger *zap.Logger
}

func NewPausePolicyRepository(logger *zap.Logger) PausePolicyRepository {
	return &pausePolicyRepository{
		logger: logger.Named("subscription_pause_policy_repo"),
	}
}

const pausePolicyTable = "subscription.pause_policies"

func (r *pausePolicyRepository) scanPausePolicy(s scanner) (*models.PausePolicy, error) {
	var p models.PausePolicy
	var allowedReasons []string // PostgreSQL text[]
	var allowedReasonsStr string
	err := s.Scan(
		&p.PausePolicyID,
		&p.CompanyID,
		&p.Name,
		&p.MaxPauseDays,
		&allowedReasonsStr,
		&p.FreezeDays,
		&p.IsActive,
		&p.CreatedAt,
		&p.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan pause policy: %w", err)
	}
	if len(allowedReasonsStr) > 2 {
		trimmed := allowedReasonsStr[1 : len(allowedReasonsStr)-1]
		if trimmed != "" {
			allowedReasons = strings.Split(trimmed, ",")
		}
	}
	p.AllowedReasons = allowedReasons
	return &p, nil
}

func (r *pausePolicyRepository) buildPausePolicyFilter(filter PausePolicyFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}

	if len(filter.PausePolicyIDs) > 0 {
		placeholders := make([]string, len(filter.PausePolicyIDs))
		for i, id := range filter.PausePolicyIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("pause_policy_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.Name != nil {
		conds = append(conds, fmt.Sprintf("name = $%d", idx))
		args = append(args, *filter.Name)
		idx++
	}
	if filter.IsActive != nil {
		conds = append(conds, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}
	if filter.MaxPauseDaysMin != nil {
		conds = append(conds, fmt.Sprintf("max_pause_days >= $%d", idx))
		args = append(args, *filter.MaxPauseDaysMin)
		idx++
	}
	if filter.MaxPauseDaysMax != nil {
		conds = append(conds, fmt.Sprintf("max_pause_days <= $%d", idx))
		args = append(args, *filter.MaxPauseDaysMax)
		idx++
	}
	if filter.FreezeDaysMin != nil {
		conds = append(conds, fmt.Sprintf("freeze_days >= $%d", idx))
		args = append(args, *filter.FreezeDaysMin)
		idx++
	}
	if filter.FreezeDaysMax != nil {
		conds = append(conds, fmt.Sprintf("freeze_days <= $%d", idx))
		args = append(args, *filter.FreezeDaysMax)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

var pausePolicyAllowedSort = map[string]bool{
	"pause_policy_id": true,
	"name":            true,
	"max_pause_days":  true,
	"freeze_days":     true,
	"is_active":       true,
	"created_at":      true,
	"updated_at":      true,
}

// ---- CRUD ----

func (r *pausePolicyRepository) Create(ctx context.Context, db DBTX, policy *models.PausePolicy) error {
	// Convert AllowedReasons to PostgreSQL array string
	reasons := strings.Join(policy.AllowedReasons, ",")
	query := `
		INSERT INTO subscription.pause_policies (
			pause_policy_id, company_id, name, max_pause_days,
			allowed_reasons, freeze_days, is_active,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		policy.PausePolicyID,
		policy.CompanyID,
		policy.Name,
		policy.MaxPauseDays,
		reasons,
		policy.FreezeDays,
		policy.IsActive,
	).Scan(&policy.CreatedAt, &policy.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create pause policy: %w", err)
	}
	return nil
}

func (r *pausePolicyRepository) Update(ctx context.Context, db DBTX, policy *models.PausePolicy) error {
	reasons := strings.Join(policy.AllowedReasons, ",")
	query := `
		UPDATE subscription.pause_policies SET
			name = $3,
			max_pause_days = $4,
			allowed_reasons = $5,
			freeze_days = $6,
			is_active = $7,
			updated_at = NOW()
		WHERE pause_policy_id = $1 AND company_id = $2
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		policy.PausePolicyID,
		policy.CompanyID,
		policy.Name,
		policy.MaxPauseDays,
		reasons,
		policy.FreezeDays,
		policy.IsActive,
	).Scan(&policy.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return fmt.Errorf("update pause policy: %w", err)
	}
	return nil
}

func (r *pausePolicyRepository) Delete(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) error {
	query := `DELETE FROM subscription.pause_policies WHERE pause_policy_id = $1 AND company_id = $2`
	result, err := db.ExecContext(ctx, query, pausePolicyID, companyID)
	if err != nil {
		return fmt.Errorf("delete pause policy: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// ---- Single Fetch ----

func (r *pausePolicyRepository) GetByID(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) (*models.PausePolicy, error) {
	query := `
		SELECT pause_policy_id, company_id, name, max_pause_days,
			allowed_reasons, freeze_days, is_active,
			created_at, updated_at
		FROM subscription.pause_policies
		WHERE pause_policy_id = $1 AND company_id = $2
	`
	row := db.QueryRowContext(ctx, query, pausePolicyID, companyID)
	return r.scanPausePolicy(row)
}

func (r *pausePolicyRepository) GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.PausePolicy, error) {
	query := `
		SELECT pause_policy_id, company_id, name, max_pause_days,
			allowed_reasons, freeze_days, is_active,
			created_at, updated_at
		FROM subscription.pause_policies
		WHERE company_id = $1 AND name = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, name)
	return r.scanPausePolicy(row)
}

// ---- Listing ----

func (r *pausePolicyRepository) List(ctx context.Context, db DBTX, filter PausePolicyFilter, p Pagination, s Sort) ([]*models.PausePolicy, int64, error) {
	where, args := r.buildPausePolicyFilter(filter)
	if where == "" {
		if filter.CompanyID == uuid.Nil {
			return nil, 0, fmt.Errorf("company_id is required in filter")
		}
		if !strings.Contains(where, "company_id") {
			where = "WHERE company_id = $1"
			args = []interface{}{filter.CompanyID}
		}
	}

	orderBy, err := validateSort(s, pausePolicyAllowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY name"
	}

	limit, offset := validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", pausePolicyTable, where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count pause policies: %w", err)
	}
	if total == 0 {
		return []*models.PausePolicy{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT pause_policy_id, company_id, name, max_pause_days,
			allowed_reasons, freeze_days, is_active,
			created_at, updated_at
		FROM %s
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, pausePolicyTable, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list pause policies: %w", err)
	}
	defer rows.Close()

	var result []*models.PausePolicy
	for rows.Next() {
		p, err := r.scanPausePolicy(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, p)
	}
	return result, total, rows.Err()
}

func (r *pausePolicyRepository) ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.PausePolicy, error) {
	filter := PausePolicyFilter{
		CompanyID: companyID,
		IsActive:  ptrBool(true),
	}
	policies, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{})
	return policies, err
}

// ---- Validation ----

func (r *pausePolicyRepository) Exists(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.pause_policies WHERE pause_policy_id = $1 AND company_id = $2)`
	err := db.QueryRowContext(ctx, query, pausePolicyID, companyID).Scan(&exists)
	return exists, err
}

func (r *pausePolicyRepository) ExistsByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.pause_policies WHERE company_id = $1 AND name = $2)`
	err := db.QueryRowContext(ctx, query, companyID, name).Scan(&exists)
	return exists, err
}

// ---- Search ----

func (r *pausePolicyRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit int, offset int) ([]*models.PausePolicy, int64, error) {
	pattern := "%" + query + "%"
	baseQuery := `
		SELECT pause_policy_id, company_id, name, max_pause_days,
			allowed_reasons, freeze_days, is_active,
			created_at, updated_at
		FROM subscription.pause_policies
	`
	where := "WHERE company_id = $1 AND (name ILIKE $2)"
	args := []interface{}{companyID, pattern}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", pausePolicyTable, where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search pause policies count: %w", err)
	}
	if total == 0 {
		return []*models.PausePolicy{}, 0, nil
	}

	querySQL := fmt.Sprintf(`%s %s ORDER BY name LIMIT $%d OFFSET $%d`, baseQuery, where, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search pause policies: %w", err)
	}
	defer rows.Close()

	var result []*models.PausePolicy
	for rows.Next() {
		p, err := r.scanPausePolicy(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, p)
	}
	return result, total, rows.Err()
}

// ---- Locking ----

func (r *pausePolicyRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, pausePolicyID uuid.UUID) (*models.PausePolicy, error) {
	query := `
		SELECT pause_policy_id, company_id, name, max_pause_days,
			allowed_reasons, freeze_days, is_active,
			created_at, updated_at
		FROM subscription.pause_policies
		WHERE pause_policy_id = $1 AND company_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, pausePolicyID, companyID)
	return r.scanPausePolicy(row)
}

// ---- GetDefault ----

func (r *pausePolicyRepository) GetDefault(ctx context.Context, db DBTX, companyID uuid.UUID) (*models.PausePolicy, error) {
	filter := PausePolicyFilter{
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
