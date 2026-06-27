// repository/renewal_policy_repo.go
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

type RenewalPolicyRepository interface {
	Create(ctx context.Context, db DBTX, policy *models.RenewalPolicy) error
	Update(ctx context.Context, db DBTX, policy *models.RenewalPolicy) error
	Delete(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) error

	GetByID(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) (*models.RenewalPolicy, error)
	GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.RenewalPolicy, error)

	List(ctx context.Context, db DBTX, filter RenewalPolicyFilter, p Pagination, s Sort) ([]*models.RenewalPolicy, int64, error)
	ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.RenewalPolicy, error)

	Exists(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) (bool, error)
	ExistsByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error)

	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit int, offset int) ([]*models.RenewalPolicy, int64, error)

	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) (*models.RenewalPolicy, error)
	GetDefault(ctx context.Context, db DBTX, companyID uuid.UUID) (*models.RenewalPolicy, error)
}

type RenewalPolicyFilter struct {
	CompanyID         uuid.UUID
	RenewalPolicyIDs  []uuid.UUID
	Name              *string
	AutoRenew         *bool
	IsActive          *bool
	GraceDaysMin      *int
	GraceDaysMax      *int
	NoticeDaysMin     *int
	NoticeDaysMax     *int
	LateFeePercentMin *float64
	LateFeePercentMax *float64
}

type renewalPolicyRepository struct {
	logger *zap.Logger
}

func NewRenewalPolicyRepository(logger *zap.Logger) RenewalPolicyRepository {
	return &renewalPolicyRepository{
		logger: logger.Named("subscription_renewal_policy_repo"),
	}
}

const renewalPolicyTable = "subscription.renewal_policies"

func (r *renewalPolicyRepository) scanRenewalPolicy(s scanner) (*models.RenewalPolicy, error) {
	var p models.RenewalPolicy
	var lateFeePercent sql.NullFloat64
	err := s.Scan(
		&p.RenewalPolicyID,
		&p.CompanyID,
		&p.Name,
		&p.AutoRenew,
		&p.GraceDays,
		&lateFeePercent,
		&p.NoticeDays,
		&p.IsActive,
		&p.CreatedAt,
		&p.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan renewal policy: %w", err)
	}
	if lateFeePercent.Valid {
		p.LateFeePercent = lateFeePercent.Float64
	}
	return &p, nil
}

func (r *renewalPolicyRepository) buildRenewalPolicyFilter(filter RenewalPolicyFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	} else {
		// Require company_id
	}

	if len(filter.RenewalPolicyIDs) > 0 {
		placeholders := make([]string, len(filter.RenewalPolicyIDs))
		for i, id := range filter.RenewalPolicyIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("renewal_policy_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.Name != nil {
		conds = append(conds, fmt.Sprintf("name = $%d", idx))
		args = append(args, *filter.Name)
		idx++
	}
	if filter.AutoRenew != nil {
		conds = append(conds, fmt.Sprintf("auto_renew = $%d", idx))
		args = append(args, *filter.AutoRenew)
		idx++
	}
	if filter.IsActive != nil {
		conds = append(conds, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}
	if filter.GraceDaysMin != nil {
		conds = append(conds, fmt.Sprintf("grace_days >= $%d", idx))
		args = append(args, *filter.GraceDaysMin)
		idx++
	}
	if filter.GraceDaysMax != nil {
		conds = append(conds, fmt.Sprintf("grace_days <= $%d", idx))
		args = append(args, *filter.GraceDaysMax)
		idx++
	}
	if filter.NoticeDaysMin != nil {
		conds = append(conds, fmt.Sprintf("notice_days >= $%d", idx))
		args = append(args, *filter.NoticeDaysMin)
		idx++
	}
	if filter.NoticeDaysMax != nil {
		conds = append(conds, fmt.Sprintf("notice_days <= $%d", idx))
		args = append(args, *filter.NoticeDaysMax)
		idx++
	}
	if filter.LateFeePercentMin != nil {
		conds = append(conds, fmt.Sprintf("late_fee_percent >= $%d", idx))
		args = append(args, *filter.LateFeePercentMin)
		idx++
	}
	if filter.LateFeePercentMax != nil {
		conds = append(conds, fmt.Sprintf("late_fee_percent <= $%d", idx))
		args = append(args, *filter.LateFeePercentMax)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

var renewalPolicyAllowedSort = map[string]bool{
	"renewal_policy_id": true,
	"name":              true,
	"auto_renew":        true,
	"grace_days":        true,
	"notice_days":       true,
	"late_fee_percent":  true,
	"is_active":         true,
	"created_at":        true,
	"updated_at":        true,
}

// ---- CRUD ----

func (r *renewalPolicyRepository) Create(ctx context.Context, db DBTX, policy *models.RenewalPolicy) error {
	query := `
		INSERT INTO subscription.renewal_policies (
			renewal_policy_id, company_id, name, auto_renew,
			grace_days, late_fee_percent, notice_days, is_active,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		policy.RenewalPolicyID,
		policy.CompanyID,
		policy.Name,
		policy.AutoRenew,
		policy.GraceDays,
		policy.LateFeePercent,
		policy.NoticeDays,
		policy.IsActive,
	).Scan(&policy.CreatedAt, &policy.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create renewal policy: %w", err)
	}
	return nil
}

func (r *renewalPolicyRepository) Update(ctx context.Context, db DBTX, policy *models.RenewalPolicy) error {
	query := `
		UPDATE subscription.renewal_policies SET
			name = $3,
			auto_renew = $4,
			grace_days = $5,
			late_fee_percent = $6,
			notice_days = $7,
			is_active = $8,
			updated_at = NOW()
		WHERE renewal_policy_id = $1 AND company_id = $2
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		policy.RenewalPolicyID,
		policy.CompanyID,
		policy.Name,
		policy.AutoRenew,
		policy.GraceDays,
		policy.LateFeePercent,
		policy.NoticeDays,
		policy.IsActive,
	).Scan(&policy.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return fmt.Errorf("update renewal policy: %w", err)
	}
	return nil
}

func (r *renewalPolicyRepository) Delete(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) error {
	query := `DELETE FROM subscription.renewal_policies WHERE renewal_policy_id = $1 AND company_id = $2`
	result, err := db.ExecContext(ctx, query, renewalPolicyID, companyID)
	if err != nil {
		return fmt.Errorf("delete renewal policy: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// ---- Single Fetch ----

func (r *renewalPolicyRepository) GetByID(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) (*models.RenewalPolicy, error) {
	query := `
		SELECT renewal_policy_id, company_id, name, auto_renew,
			grace_days, late_fee_percent, notice_days, is_active,
			created_at, updated_at
		FROM subscription.renewal_policies
		WHERE renewal_policy_id = $1 AND company_id = $2
	`
	row := db.QueryRowContext(ctx, query, renewalPolicyID, companyID)
	return r.scanRenewalPolicy(row)
}

func (r *renewalPolicyRepository) GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.RenewalPolicy, error) {
	query := `
		SELECT renewal_policy_id, company_id, name, auto_renew,
			grace_days, late_fee_percent, notice_days, is_active,
			created_at, updated_at
		FROM subscription.renewal_policies
		WHERE company_id = $1 AND name = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, name)
	return r.scanRenewalPolicy(row)
}

// ---- Listing ----

func (r *renewalPolicyRepository) List(ctx context.Context, db DBTX, filter RenewalPolicyFilter, p Pagination, s Sort) ([]*models.RenewalPolicy, int64, error) {
	where, args := r.buildRenewalPolicyFilter(filter)
	if where == "" {
		if filter.CompanyID == uuid.Nil {
			return nil, 0, fmt.Errorf("company_id is required in filter")
		}
		// Ensure company_id is in WHERE
		if !strings.Contains(where, "company_id") {
			where = "WHERE company_id = $1"
			args = []interface{}{filter.CompanyID}
		}
	}

	orderBy, err := validateSort(s, renewalPolicyAllowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY name"
	}

	limit, offset := validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", renewalPolicyTable, where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count renewal policies: %w", err)
	}
	if total == 0 {
		return []*models.RenewalPolicy{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT renewal_policy_id, company_id, name, auto_renew,
			grace_days, late_fee_percent, notice_days, is_active,
			created_at, updated_at
		FROM %s
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, renewalPolicyTable, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list renewal policies: %w", err)
	}
	defer rows.Close()

	var result []*models.RenewalPolicy
	for rows.Next() {
		p, err := r.scanRenewalPolicy(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, p)
	}
	return result, total, rows.Err()
}

func (r *renewalPolicyRepository) ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.RenewalPolicy, error) {
	filter := RenewalPolicyFilter{
		CompanyID: companyID,
		IsActive:  ptrBool(true),
	}
	policies, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{})
	return policies, err
}

// ---- Validation ----

func (r *renewalPolicyRepository) Exists(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.renewal_policies WHERE renewal_policy_id = $1 AND company_id = $2)`
	err := db.QueryRowContext(ctx, query, renewalPolicyID, companyID).Scan(&exists)
	return exists, err
}

func (r *renewalPolicyRepository) ExistsByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.renewal_policies WHERE company_id = $1 AND name = $2)`
	err := db.QueryRowContext(ctx, query, companyID, name).Scan(&exists)
	return exists, err
}

// ---- Search ----

func (r *renewalPolicyRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit int, offset int) ([]*models.RenewalPolicy, int64, error) {
	pattern := "%" + query + "%"
	baseQuery := `
		SELECT renewal_policy_id, company_id, name, auto_renew,
			grace_days, late_fee_percent, notice_days, is_active,
			created_at, updated_at
		FROM subscription.renewal_policies
	`
	where := "WHERE company_id = $1 AND (name ILIKE $2)"
	args := []interface{}{companyID, pattern}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", renewalPolicyTable, where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search renewal policies count: %w", err)
	}
	if total == 0 {
		return []*models.RenewalPolicy{}, 0, nil
	}

	querySQL := fmt.Sprintf(`%s %s ORDER BY name LIMIT $%d OFFSET $%d`, baseQuery, where, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search renewal policies: %w", err)
	}
	defer rows.Close()

	var result []*models.RenewalPolicy
	for rows.Next() {
		p, err := r.scanRenewalPolicy(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, p)
	}
	return result, total, rows.Err()
}

// ---- Locking ----

func (r *renewalPolicyRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, renewalPolicyID uuid.UUID) (*models.RenewalPolicy, error) {
	query := `
		SELECT renewal_policy_id, company_id, name, auto_renew,
			grace_days, late_fee_percent, notice_days, is_active,
			created_at, updated_at
		FROM subscription.renewal_policies
		WHERE renewal_policy_id = $1 AND company_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, renewalPolicyID, companyID)
	return r.scanRenewalPolicy(row)
}

// ---- GetDefault ----

func (r *renewalPolicyRepository) GetDefault(ctx context.Context, db DBTX, companyID uuid.UUID) (*models.RenewalPolicy, error) {
	filter := RenewalPolicyFilter{
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
