// repository/billing_policy_repo.go
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

// BillingPolicyRepository defines the interface for billing policy persistence.
type BillingPolicyRepository interface {
	Create(ctx context.Context, db DBTX, policy *models.BillingPolicy) error
	Update(ctx context.Context, db DBTX, policy *models.BillingPolicy) error
	Delete(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) error

	GetByID(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) (*models.BillingPolicy, error)
	GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.BillingPolicy, error)

	List(ctx context.Context, db DBTX, filter BillingPolicyFilter, p Pagination, s Sort) ([]*models.BillingPolicy, int64, error)
	ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.BillingPolicy, error)

	Exists(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) (bool, error)
	ExistsByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error)

	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit int, offset int) ([]*models.BillingPolicy, int64, error)

	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) (*models.BillingPolicy, error)

	// GetDefault returns the default billing policy for the company.
	GetDefault(ctx context.Context, db DBTX, companyID uuid.UUID) (*models.BillingPolicy, error)
}

// BillingPolicyFilter defines filter criteria for listing billing policies.
type BillingPolicyFilter struct {
	CompanyID           uuid.UUID
	BillingPolicyIDs    []uuid.UUID
	BillingTypeID       *int16
	Name                *string
	IsActive            *bool
	AdvanceDaysMin      *int
	AdvanceDaysMax      *int
	BillingFrequencyMin *int
	BillingFrequencyMax *int
}

type billingPolicyRepository struct {
	logger *zap.Logger
}

func NewBillingPolicyRepository(logger *zap.Logger) BillingPolicyRepository {
	return &billingPolicyRepository{
		logger: logger.Named("subscription_billing_policy_repo"),
	}
}

const billingPolicyTable = "subscription.billing_policies"

// scanBillingPolicy scans a row into a BillingPolicy model.
func (r *billingPolicyRepository) scanBillingPolicy(s scanner) (*models.BillingPolicy, error) {
	var p models.BillingPolicy
	var billingFrequency sql.NullInt32
	err := s.Scan(
		&p.BillingPolicyID,
		&p.CompanyID,
		&p.Name,
		&p.BillingTypeID,
		&billingFrequency,
		&p.AdvanceDays,
		&p.IsActive,
		&p.CreatedAt,
		&p.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan billing policy: %w", err)
	}
	if billingFrequency.Valid {
		freq := int(billingFrequency.Int32)
		p.BillingFrequency = &freq
	}
	return &p, nil
}

// buildBillingPolicyFilter builds WHERE clause and arguments.
func (r *billingPolicyRepository) buildBillingPolicyFilter(filter BillingPolicyFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	// company_id is required
	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	} else {
		// To avoid listing across companies, we could panic or return error.
		// We'll treat empty companyID as no filter but it's better to require it.
	}

	if len(filter.BillingPolicyIDs) > 0 {
		placeholders := make([]string, len(filter.BillingPolicyIDs))
		for i, id := range filter.BillingPolicyIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("billing_policy_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.BillingTypeID != nil {
		conds = append(conds, fmt.Sprintf("billing_type_id = $%d", idx))
		args = append(args, *filter.BillingTypeID)
		idx++
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
	if filter.AdvanceDaysMin != nil {
		conds = append(conds, fmt.Sprintf("advance_days >= $%d", idx))
		args = append(args, *filter.AdvanceDaysMin)
		idx++
	}
	if filter.AdvanceDaysMax != nil {
		conds = append(conds, fmt.Sprintf("advance_days <= $%d", idx))
		args = append(args, *filter.AdvanceDaysMax)
		idx++
	}
	if filter.BillingFrequencyMin != nil {
		conds = append(conds, fmt.Sprintf("billing_frequency >= $%d", idx))
		args = append(args, *filter.BillingFrequencyMin)
		idx++
	}
	if filter.BillingFrequencyMax != nil {
		conds = append(conds, fmt.Sprintf("billing_frequency <= $%d", idx))
		args = append(args, *filter.BillingFrequencyMax)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// allowedSortFields for BillingPolicy
var billingPolicyAllowedSort = map[string]bool{
	"billing_policy_id": true,
	"name":              true,
	"billing_type_id":   true,
	"advance_days":      true,
	"billing_frequency": true,
	"is_active":         true,
	"created_at":        true,
	"updated_at":        true,
}

// ---- CRUD ----

func (r *billingPolicyRepository) Create(ctx context.Context, db DBTX, policy *models.BillingPolicy) error {
	query := `
		INSERT INTO subscription.billing_policies (
			billing_policy_id, company_id, name, billing_type_id,
			billing_frequency, advance_days, is_active,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		policy.BillingPolicyID,
		policy.CompanyID,
		policy.Name,
		policy.BillingTypeID,
		policy.BillingFrequency,
		policy.AdvanceDays,
		policy.IsActive,
	).Scan(&policy.CreatedAt, &policy.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create billing policy: %w", err)
	}
	return nil
}

func (r *billingPolicyRepository) Update(ctx context.Context, db DBTX, policy *models.BillingPolicy) error {
	query := `
		UPDATE subscription.billing_policies SET
			name = $3,
			billing_type_id = $4,
			billing_frequency = $5,
			advance_days = $6,
			is_active = $7,
			updated_at = NOW()
		WHERE billing_policy_id = $1 AND company_id = $2
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		policy.BillingPolicyID,
		policy.CompanyID,
		policy.Name,
		policy.BillingTypeID,
		policy.BillingFrequency,
		policy.AdvanceDays,
		policy.IsActive,
	).Scan(&policy.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return fmt.Errorf("update billing policy: %w", err)
	}
	return nil
}

func (r *billingPolicyRepository) Delete(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) error {
	query := `DELETE FROM subscription.billing_policies WHERE billing_policy_id = $1 AND company_id = $2`
	result, err := db.ExecContext(ctx, query, billingPolicyID, companyID)
	if err != nil {
		return fmt.Errorf("delete billing policy: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// ---- Single Fetch ----

func (r *billingPolicyRepository) GetByID(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) (*models.BillingPolicy, error) {
	query := `
		SELECT billing_policy_id, company_id, name, billing_type_id,
			billing_frequency, advance_days, is_active,
			created_at, updated_at
		FROM subscription.billing_policies
		WHERE billing_policy_id = $1 AND company_id = $2
	`
	row := db.QueryRowContext(ctx, query, billingPolicyID, companyID)
	return r.scanBillingPolicy(row)
}

func (r *billingPolicyRepository) GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.BillingPolicy, error) {
	query := `
		SELECT billing_policy_id, company_id, name, billing_type_id,
			billing_frequency, advance_days, is_active,
			created_at, updated_at
		FROM subscription.billing_policies
		WHERE company_id = $1 AND name = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, name)
	return r.scanBillingPolicy(row)
}

// ---- Listing ----

func (r *billingPolicyRepository) List(ctx context.Context, db DBTX, filter BillingPolicyFilter, p Pagination, s Sort) ([]*models.BillingPolicy, int64, error) {
	where, args := r.buildBillingPolicyFilter(filter)
	if where == "" {
		// company_id is required; if missing, we can return error or assume all?
		// To be safe, we require company_id in filter.
		if filter.CompanyID == uuid.Nil {
			return nil, 0, fmt.Errorf("company_id is required in filter")
		}
		// If no other conditions, we still need to filter by company_id.
		// The build function already added company_id if present.
		// If for some reason it's not added, we add it manually.
		if !strings.Contains(where, "company_id") {
			where = "WHERE company_id = $1"
			args = []interface{}{filter.CompanyID}
		}
	}

	orderBy, err := validateSort(s, billingPolicyAllowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY name"
	}

	limit, offset := validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", billingPolicyTable, where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count billing policies: %w", err)
	}
	if total == 0 {
		return []*models.BillingPolicy{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT billing_policy_id, company_id, name, billing_type_id,
			billing_frequency, advance_days, is_active,
			created_at, updated_at
		FROM %s
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, billingPolicyTable, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list billing policies: %w", err)
	}
	defer rows.Close()

	var result []*models.BillingPolicy
	for rows.Next() {
		p, err := r.scanBillingPolicy(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, p)
	}
	return result, total, rows.Err()
}

func (r *billingPolicyRepository) ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.BillingPolicy, error) {
	filter := BillingPolicyFilter{
		CompanyID: companyID,
		IsActive:  ptrBool(true),
	}
	policies, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{})
	return policies, err
}

// ---- Validation ----

func (r *billingPolicyRepository) Exists(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.billing_policies WHERE billing_policy_id = $1 AND company_id = $2)`
	err := db.QueryRowContext(ctx, query, billingPolicyID, companyID).Scan(&exists)
	return exists, err
}

func (r *billingPolicyRepository) ExistsByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.billing_policies WHERE company_id = $1 AND name = $2)`
	err := db.QueryRowContext(ctx, query, companyID, name).Scan(&exists)
	return exists, err
}

// ---- Search ----

func (r *billingPolicyRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit int, offset int) ([]*models.BillingPolicy, int64, error) {
	pattern := "%" + query + "%"
	baseQuery := `
		SELECT billing_policy_id, company_id, name, billing_type_id,
			billing_frequency, advance_days, is_active,
			created_at, updated_at
		FROM subscription.billing_policies
	`
	where := "WHERE company_id = $1 AND (name ILIKE $2)"
	args := []interface{}{companyID, pattern}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM subscription.billing_policies %s", where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search billing policies count: %w", err)
	}
	if total == 0 {
		return []*models.BillingPolicy{}, 0, nil
	}

	querySQL := fmt.Sprintf(`%s %s ORDER BY name LIMIT $%d OFFSET $%d`, baseQuery, where, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search billing policies: %w", err)
	}
	defer rows.Close()

	var result []*models.BillingPolicy
	for rows.Next() {
		p, err := r.scanBillingPolicy(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, p)
	}
	return result, total, rows.Err()
}

// ---- Locking ----

func (r *billingPolicyRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, billingPolicyID uuid.UUID) (*models.BillingPolicy, error) {
	query := `
		SELECT billing_policy_id, company_id, name, billing_type_id,
			billing_frequency, advance_days, is_active,
			created_at, updated_at
		FROM subscription.billing_policies
		WHERE billing_policy_id = $1 AND company_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, billingPolicyID, companyID)
	return r.scanBillingPolicy(row)
}

// ---- GetDefault ----

func (r *billingPolicyRepository) GetDefault(ctx context.Context, db DBTX, companyID uuid.UUID) (*models.BillingPolicy, error) {
	// If there is a specific default flag, we could filter by is_default.
	// Since we don't have that, we return the first active policy ordered by name.
	filter := BillingPolicyFilter{
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

// helper to get bool pointer
func ptrBool(b bool) *bool {
	return &b
}
