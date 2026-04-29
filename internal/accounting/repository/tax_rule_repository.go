package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"

	"auth-service/internal/accounting/models/tax"
	"auth-service/internal/util"
)

type TaxRuleFilter struct {
	CompanyID uuid.UUID
	AppliesTo string
	IsActive  *bool
	Search    string
}

type TaxRuleBundle struct {
	Rule       *tax.TaxRule
	Version    *tax.TaxRuleVersion
	Conditions []*tax.TaxCondition
	Actions    []*tax.TaxAction
}

type TaxRuleRepository interface {
	Create(ctx context.Context, db DBTX, rule *tax.TaxRule) error
	Update(ctx context.Context, db DBTX, rule *tax.TaxRule) error
	GetByID(ctx context.Context, db DBTX, companyID, id uuid.UUID) (*tax.TaxRule, error)
	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, id uuid.UUID) (*tax.TaxRule, error)
	List(ctx context.Context, db DBTX, filter TaxRuleFilter, p Pagination, s Sort) ([]*tax.TaxRule, error)
	Count(ctx context.Context, db DBTX, filter TaxRuleFilter) (int64, error)
	GetByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*tax.TaxRule, error)
	SetActive(ctx context.Context, db DBTX, companyID, id uuid.UUID, isActive bool, updatedBy *uuid.UUID) error
	Delete(ctx context.Context, db DBTX, companyID, id uuid.UUID, deletedBy *uuid.UUID) error
	CreateVersion(ctx context.Context, db DBTX, v *tax.TaxRuleVersion) error
	GetCurrentVersion(ctx context.Context, db DBTX, companyID, taxRuleID uuid.UUID) (*tax.TaxRuleVersion, error)
	GetVersions(ctx context.Context, db DBTX, companyID, taxRuleID uuid.UUID) ([]*tax.TaxRuleVersion, error)
	SetCurrentVersion(ctx context.Context, db DBTX, companyID, taxRuleID uuid.UUID, version int) error
	CloneVersion(ctx context.Context, db DBTX, companyID, ruleID uuid.UUID, createdBy *uuid.UUID) (*tax.TaxRuleVersion, error)
	AddCondition(ctx context.Context, db DBTX, companyID uuid.UUID, c *tax.TaxCondition) error
	BulkAddConditions(ctx context.Context, db DBTX, companyID uuid.UUID, conditions []*tax.TaxCondition) error
	GetConditions(ctx context.Context, db DBTX, companyID, taxRuleID uuid.UUID) ([]*tax.TaxCondition, error)
	ClearConditions(ctx context.Context, db DBTX, companyID, taxRuleID uuid.UUID) error
	AddAction(ctx context.Context, db DBTX, companyID uuid.UUID, a *tax.TaxAction) error
	BulkAddActions(ctx context.Context, db DBTX, companyID uuid.UUID, actions []*tax.TaxAction) error
	GetActions(ctx context.Context, db DBTX, companyID, taxRuleID uuid.UUID) ([]*tax.TaxAction, error)
	ClearActions(ctx context.Context, db DBTX, companyID, taxRuleID uuid.UUID) error
	GetApplicableRules(ctx context.Context, db DBTX, companyID uuid.UUID, appliesTo string) ([]*TaxRuleBundle, error)
	GetApplicableRulesWithLimit(ctx context.Context, db DBTX, companyID uuid.UUID, appliesTo string, limit int) ([]*TaxRuleBundle, error)
	BulkGetCurrentVersions(ctx context.Context, db DBTX, companyID uuid.UUID, ruleIDs []uuid.UUID) (map[uuid.UUID]*tax.TaxRuleVersion, error)
	Exists(ctx context.Context, db DBTX, companyID uuid.UUID, ruleName string) (bool, error)
	CheckUsage(ctx context.Context, db DBTX, companyID, ruleID uuid.UUID) (bool, error)
}

type taxRuleRepository struct {
	logger *zap.Logger
}

func NewTaxRuleRepository(logger *zap.Logger) TaxRuleRepository {
	return &taxRuleRepository{logger: logger.Named("tax_rule_repo")}
}

var allowedTaxRuleSortFields = map[string]bool{
	"rule_name": true, "applies_to": true, "priority": true,
	"is_active": true, "created_at": true, "updated_at": true,
}

func (r *taxRuleRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "priority"
	}
	if !allowedTaxRuleSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY %s %s", field, dir), nil
}

func (r *taxRuleRepository) validatePagination(p Pagination) (int, int) {
	limit := p.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := p.Offset
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func (r *taxRuleRepository) buildTaxRuleFilter(filter TaxRuleFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.AppliesTo != "" {
		conditions = append(conditions, fmt.Sprintf("(applies_to = $%d OR applies_to = 'both')", idx))
		args = append(args, filter.AppliesTo)
		idx++
	}
	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("rule_name ILIKE $%d", idx))
		args = append(args, "%"+filter.Search+"%")
		idx++
	}
	conditions = append(conditions, "deleted_at IS NULL")
	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *taxRuleRepository) scanTaxRule(scanner interface {
	Scan(dest ...interface{}) error
}) (*tax.TaxRule, error) {
	var rule tax.TaxRule
	var createdBy, updatedBy uuid.NullUUID
	var deletedAt sql.NullTime
	err := scanner.Scan(
		&rule.TaxRuleID, &rule.CompanyID, &rule.RuleName, &rule.AppliesTo,
		&rule.Priority, &rule.IsActive, &rule.CreatedAt, &rule.UpdatedAt,
		&createdBy, &updatedBy, &deletedAt,
	)
	if err != nil {
		return nil, err
	}
	if createdBy.Valid {
		rule.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		rule.UpdatedBy = &updatedBy.UUID
	}
	if deletedAt.Valid {
		rule.DeletedAt = &deletedAt.Time
	}
	return &rule, nil
}

func (r *taxRuleRepository) Create(ctx context.Context, db DBTX, rule *tax.TaxRule) error {
	query := `
		INSERT INTO accounting.tax_rules (
			tax_rule_id, company_id, rule_name, applies_to, priority,
			is_active, created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW(), $7, $8)
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		rule.TaxRuleID, rule.CompanyID, rule.RuleName, rule.AppliesTo,
		rule.Priority, rule.IsActive, rule.CreatedBy, rule.UpdatedBy,
	).Scan(&rule.CreatedAt, &rule.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create tax rule",
			util.String("company_id", rule.CompanyID.String()),
			util.String("name", rule.RuleName),
			util.ErrorField(err))
		return fmt.Errorf("create tax rule: %w", err)
	}
	return nil
}

func (r *taxRuleRepository) Update(ctx context.Context, db DBTX, rule *tax.TaxRule) error {
	query := `
		UPDATE accounting.tax_rules
		SET rule_name = $2,
		    applies_to = $3,
		    priority = $4,
		    is_active = $5,
		    updated_by = $6,
		    updated_at = NOW()
		WHERE tax_rule_id = $1 AND company_id = $7 AND deleted_at IS NULL
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		rule.TaxRuleID, rule.RuleName, rule.AppliesTo,
		rule.Priority, rule.IsActive, rule.UpdatedBy, rule.CompanyID,
	).Scan(&rule.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		r.logger.Error("failed to update tax rule",
			util.String("id", rule.TaxRuleID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update tax rule: %w", err)
	}
	return nil
}

func (r *taxRuleRepository) GetByID(ctx context.Context, db DBTX, companyID, id uuid.UUID) (*tax.TaxRule, error) {
	query := `
		SELECT tax_rule_id, company_id, rule_name, applies_to, priority,
		       is_active, created_at, updated_at, created_by, updated_by, deleted_at
		FROM accounting.tax_rules
		WHERE tax_rule_id = $1 AND company_id = $2 AND deleted_at IS NULL
	`
	var rule tax.TaxRule
	var createdBy, updatedBy uuid.NullUUID
	var deletedAt sql.NullTime
	err := db.QueryRowContext(ctx, query, id, companyID).Scan(
		&rule.TaxRuleID, &rule.CompanyID, &rule.RuleName, &rule.AppliesTo,
		&rule.Priority, &rule.IsActive, &rule.CreatedAt, &rule.UpdatedAt,
		&createdBy, &updatedBy, &deletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get tax rule by ID",
			util.String("id", id.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get tax rule by ID: %w", err)
	}
	if createdBy.Valid {
		rule.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		rule.UpdatedBy = &updatedBy.UUID
	}
	if deletedAt.Valid {
		rule.DeletedAt = &deletedAt.Time
	}
	return &rule, nil
}

func (r *taxRuleRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, id uuid.UUID) (*tax.TaxRule, error) {
	query := `
		SELECT tax_rule_id, company_id, rule_name, applies_to, priority,
		       is_active, created_at, updated_at, created_by, updated_by, deleted_at
		FROM accounting.tax_rules
		WHERE tax_rule_id = $1 AND company_id = $2 AND deleted_at IS NULL
		FOR UPDATE
	`
	var rule tax.TaxRule
	var createdBy, updatedBy uuid.NullUUID
	var deletedAt sql.NullTime
	err := db.QueryRowContext(ctx, query, id, companyID).Scan(
		&rule.TaxRuleID, &rule.CompanyID, &rule.RuleName, &rule.AppliesTo,
		&rule.Priority, &rule.IsActive, &rule.CreatedAt, &rule.UpdatedAt,
		&createdBy, &updatedBy, &deletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get tax rule for update",
			util.String("id", id.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get tax rule for update: %w", err)
	}
	if createdBy.Valid {
		rule.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		rule.UpdatedBy = &updatedBy.UUID
	}
	if deletedAt.Valid {
		rule.DeletedAt = &deletedAt.Time
	}
	return &rule, nil
}

func (r *taxRuleRepository) List(ctx context.Context, db DBTX, filter TaxRuleFilter, p Pagination, s Sort) ([]*tax.TaxRule, error) {
	where, args := r.buildTaxRuleFilter(filter)
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT tax_rule_id, company_id, rule_name, applies_to, priority,
		       is_active, created_at, updated_at, created_by, updated_by, deleted_at
		FROM accounting.tax_rules
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list tax rules",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list tax rules: %w", err)
	}
	defer rows.Close()

	var result []*tax.TaxRule
	for rows.Next() {
		rule, err := r.scanTaxRule(rows)
		if err != nil {
			return nil, fmt.Errorf("scan tax rule: %w", err)
		}
		result = append(result, rule)
	}
	return result, rows.Err()
}

func (r *taxRuleRepository) Count(ctx context.Context, db DBTX, filter TaxRuleFilter) (int64, error) {
	where, args := r.buildTaxRuleFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM accounting.tax_rules %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count tax rules",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count tax rules: %w", err)
	}
	return count, nil
}

func (r *taxRuleRepository) GetByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*tax.TaxRule, error) {
	return r.List(ctx, db, TaxRuleFilter{CompanyID: companyID}, Pagination{Limit: 1000}, Sort{Field: "priority", Direction: "DESC"})
}

func (r *taxRuleRepository) SetActive(ctx context.Context, db DBTX, companyID, id uuid.UUID, isActive bool, updatedBy *uuid.UUID) error {
	query := `
		UPDATE accounting.tax_rules
		SET is_active = $2, updated_by = $3, updated_at = NOW()
		WHERE tax_rule_id = $1 AND company_id = $4 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, id, isActive, updatedBy, companyID)
	if err != nil {
		r.logger.Error("failed to set tax rule active status",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("set tax rule active: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *taxRuleRepository) Delete(ctx context.Context, db DBTX, companyID, id uuid.UUID, deletedBy *uuid.UUID) error {
	used, err := r.CheckUsage(ctx, db, companyID, id)
	if err != nil {
		return err
	}
	if used {
		return fmt.Errorf("tax rule %s is referenced in tax transactions and cannot be deleted", id)
	}
	query := `
		UPDATE accounting.tax_rules
		SET deleted_at = NOW(), updated_by = $2, updated_at = NOW()
		WHERE tax_rule_id = $1 AND company_id = $3 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, id, deletedBy, companyID)
	if err != nil {
		r.logger.Error("failed to delete tax rule",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete tax rule: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *taxRuleRepository) CreateVersion(ctx context.Context, db DBTX, v *tax.TaxRuleVersion) error {
	tx, ok := db.(*sql.Tx)
	if !ok {
		return fmt.Errorf("CreateVersion requires a transaction")
	}

	// Lock the tax_rule row to prevent concurrent version creation
	var dummy int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM accounting.tax_rules WHERE tax_rule_id = $1 FOR UPDATE`, v.TaxRuleID).Scan(&dummy)
	if err != nil {
		return fmt.Errorf("lock tax rule: %w", err)
	}

	var nextVersion int
	err = tx.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(version), 0) + 1
		FROM accounting.tax_rule_versions
		WHERE tax_rule_id = $1
		FOR UPDATE
	`, v.TaxRuleID).Scan(&nextVersion)
	if err != nil {
		return fmt.Errorf("get next version: %w", err)
	}
	v.Version = nextVersion
	v.IsCurrent = true

	// Unset current on previous version
	_, err = tx.ExecContext(ctx, `
		UPDATE accounting.tax_rule_versions
		SET is_current = false
		WHERE tax_rule_id = $1
	`, v.TaxRuleID)
	if err != nil {
		return fmt.Errorf("unset current versions: %w", err)
	}

	// Insert new version
	_, err = tx.ExecContext(ctx, `
		INSERT INTO accounting.tax_rule_versions (
			version_id, tax_rule_id, version, rule_json, is_current, created_at, created_by
		) VALUES ($1, $2, $3, $4, $5, NOW(), $6)
	`, v.VersionID, v.TaxRuleID, v.Version, v.RuleJSON, v.IsCurrent, v.CreatedBy)
	if err != nil {
		return fmt.Errorf("insert version: %w", err)
	}
	return nil
}

func (r *taxRuleRepository) GetCurrentVersion(ctx context.Context, db DBTX, companyID, taxRuleID uuid.UUID) (*tax.TaxRuleVersion, error) {
	query := `
		SELECT version_id, tax_rule_id, version, rule_json, is_current,
		       created_at, created_by
		FROM accounting.tax_rule_versions
		WHERE tax_rule_id = $1 AND is_current = true
	`
	var v tax.TaxRuleVersion
	var createdBy uuid.NullUUID
	err := db.QueryRowContext(ctx, query, taxRuleID).Scan(
		&v.VersionID, &v.TaxRuleID, &v.Version, &v.RuleJSON, &v.IsCurrent,
		&v.CreatedAt, &createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get current version",
			util.String("rule_id", taxRuleID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get current version: %w", err)
	}
	if createdBy.Valid {
		v.CreatedBy = &createdBy.UUID
	}
	return &v, nil
}

func (r *taxRuleRepository) GetVersions(ctx context.Context, db DBTX, companyID, taxRuleID uuid.UUID) ([]*tax.TaxRuleVersion, error) {
	query := `
		SELECT version_id, tax_rule_id, version, rule_json, is_current,
		       created_at, created_by
		FROM accounting.tax_rule_versions
		WHERE tax_rule_id = $1
		ORDER BY version DESC
	`
	rows, err := db.QueryContext(ctx, query, taxRuleID)
	if err != nil {
		r.logger.Error("failed to get versions",
			util.String("rule_id", taxRuleID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get versions: %w", err)
	}
	defer rows.Close()

	var versions []*tax.TaxRuleVersion
	for rows.Next() {
		var v tax.TaxRuleVersion
		var createdBy uuid.NullUUID
		if err := rows.Scan(
			&v.VersionID, &v.TaxRuleID, &v.Version, &v.RuleJSON, &v.IsCurrent,
			&v.CreatedAt, &createdBy,
		); err != nil {
			return nil, fmt.Errorf("scan version: %w", err)
		}
		if createdBy.Valid {
			v.CreatedBy = &createdBy.UUID
		}
		versions = append(versions, &v)
	}
	return versions, rows.Err()
}

func (r *taxRuleRepository) SetCurrentVersion(ctx context.Context, db DBTX, companyID, taxRuleID uuid.UUID, version int) error {
	tx, ok := db.(*sql.Tx)
	if !ok {
		return fmt.Errorf("SetCurrentVersion requires a transaction")
	}
	_, err := tx.ExecContext(ctx, `
		UPDATE accounting.tax_rule_versions
		SET is_current = false
		WHERE tax_rule_id = $1
	`, taxRuleID)
	if err != nil {
		return fmt.Errorf("unset current versions: %w", err)
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE accounting.tax_rule_versions
		SET is_current = true
		WHERE tax_rule_id = $1 AND version = $2
	`, taxRuleID, version)
	if err != nil {
		return fmt.Errorf("set current version: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		// ✅ FIX: return shared ErrNotFound instead of custom error string
		return ErrNotFound
	}
	return nil
}

func (r *taxRuleRepository) CloneVersion(ctx context.Context, db DBTX, companyID, ruleID uuid.UUID, createdBy *uuid.UUID) (*tax.TaxRuleVersion, error) {
	current, err := r.GetCurrentVersion(ctx, db, companyID, ruleID)
	if err != nil {
		return nil, err
	}
	clone := &tax.TaxRuleVersion{
		VersionID: uuid.New(),
		TaxRuleID: ruleID,
		RuleJSON:  current.RuleJSON,
		IsCurrent: false,
		CreatedBy: createdBy,
	}
	if err := r.CreateVersion(ctx, db, clone); err != nil {
		return nil, err
	}
	return clone, nil
}

// Conditions

func (r *taxRuleRepository) AddCondition(ctx context.Context, db DBTX, companyID uuid.UUID, c *tax.TaxCondition) error {
	query := `
		INSERT INTO accounting.tax_conditions (
			condition_id, tax_rule_id, field_name, operator,
			value_text, value_numeric, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, NOW())
	`
	_, err := db.ExecContext(ctx, query,
		c.ConditionID, c.TaxRuleID, c.FieldName, c.Operator,
		c.ValueText, c.ValueNumeric,
	)
	if err != nil {
		r.logger.Error("failed to add condition",
			util.String("rule_id", c.TaxRuleID.String()),
			util.String("field", c.FieldName),
			util.ErrorField(err))
		return fmt.Errorf("add condition: %w", err)
	}
	return nil
}

func (r *taxRuleRepository) BulkAddConditions(ctx context.Context, db DBTX, companyID uuid.UUID, conditions []*tax.TaxCondition) error {
	if len(conditions) == 0 {
		return nil
	}
	stmt, err := db.PrepareContext(ctx, `
		INSERT INTO accounting.tax_conditions (
			condition_id, tax_rule_id, field_name, operator,
			value_text, value_numeric, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, NOW())
	`)
	if err != nil {
		return fmt.Errorf("prepare bulk conditions: %w", err)
	}
	defer stmt.Close()

	for _, c := range conditions {
		if _, err := stmt.ExecContext(ctx,
			c.ConditionID, c.TaxRuleID, c.FieldName, c.Operator,
			c.ValueText, c.ValueNumeric,
		); err != nil {
			r.logger.Error("bulk add condition failed",
				util.String("rule_id", c.TaxRuleID.String()),
				util.ErrorField(err))
			return fmt.Errorf("bulk add condition: %w", err)
		}
	}
	return nil
}

func (r *taxRuleRepository) GetConditions(ctx context.Context, db DBTX, companyID, taxRuleID uuid.UUID) ([]*tax.TaxCondition, error) {
	query := `
		SELECT condition_id, tax_rule_id, field_name, operator,
		       value_text, value_numeric, created_at
		FROM accounting.tax_conditions
		WHERE tax_rule_id = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, taxRuleID)
	if err != nil {
		r.logger.Error("failed to get conditions",
			util.String("rule_id", taxRuleID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get conditions: %w", err)
	}
	defer rows.Close()

	var conditions []*tax.TaxCondition
	for rows.Next() {
		var c tax.TaxCondition
		if err := rows.Scan(&c.ConditionID, &c.TaxRuleID, &c.FieldName, &c.Operator,
			&c.ValueText, &c.ValueNumeric, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan condition: %w", err)
		}
		conditions = append(conditions, &c)
	}
	return conditions, rows.Err()
}

func (r *taxRuleRepository) ClearConditions(ctx context.Context, db DBTX, companyID, taxRuleID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM accounting.tax_conditions WHERE tax_rule_id = $1`, taxRuleID)
	if err != nil {
		r.logger.Error("failed to clear conditions",
			util.String("rule_id", taxRuleID.String()),
			util.ErrorField(err))
		return fmt.Errorf("clear conditions: %w", err)
	}
	return nil
}

// Actions

func (r *taxRuleRepository) AddAction(ctx context.Context, db DBTX, companyID uuid.UUID, a *tax.TaxAction) error {
	query := `
		INSERT INTO accounting.tax_actions (
			action_id, tax_rule_id, tax_rate_id, action_type,
			calculation_basis, created_at
		) VALUES ($1, $2, $3, $4, $5, NOW())
	`
	_, err := db.ExecContext(ctx, query,
		a.ActionID, a.TaxRuleID, a.TaxRateID, a.ActionType, a.CalculationBasis,
	)
	if err != nil {
		r.logger.Error("failed to add action",
			util.String("rule_id", a.TaxRuleID.String()),
			util.String("action_type", a.ActionType),
			util.ErrorField(err))
		return fmt.Errorf("add action: %w", err)
	}
	return nil
}

func (r *taxRuleRepository) BulkAddActions(ctx context.Context, db DBTX, companyID uuid.UUID, actions []*tax.TaxAction) error {
	if len(actions) == 0 {
		return nil
	}
	stmt, err := db.PrepareContext(ctx, `
		INSERT INTO accounting.tax_actions (
			action_id, tax_rule_id, tax_rate_id, action_type,
			calculation_basis, created_at
		) VALUES ($1, $2, $3, $4, $5, NOW())
	`)
	if err != nil {
		return fmt.Errorf("prepare bulk actions: %w", err)
	}
	defer stmt.Close()

	for _, a := range actions {
		if _, err := stmt.ExecContext(ctx,
			a.ActionID, a.TaxRuleID, a.TaxRateID, a.ActionType, a.CalculationBasis,
		); err != nil {
			r.logger.Error("bulk add action failed",
				util.String("rule_id", a.TaxRuleID.String()),
				util.ErrorField(err))
			return fmt.Errorf("bulk add action: %w", err)
		}
	}
	return nil
}

func (r *taxRuleRepository) GetActions(ctx context.Context, db DBTX, companyID, taxRuleID uuid.UUID) ([]*tax.TaxAction, error) {
	query := `
		SELECT action_id, tax_rule_id, tax_rate_id, action_type,
		       calculation_basis, created_at
		FROM accounting.tax_actions
		WHERE tax_rule_id = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, taxRuleID)
	if err != nil {
		r.logger.Error("failed to get actions",
			util.String("rule_id", taxRuleID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get actions: %w", err)
	}
	defer rows.Close()

	var actions []*tax.TaxAction
	for rows.Next() {
		var a tax.TaxAction
		if err := rows.Scan(&a.ActionID, &a.TaxRuleID, &a.TaxRateID, &a.ActionType,
			&a.CalculationBasis, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan action: %w", err)
		}
		actions = append(actions, &a)
	}
	return actions, rows.Err()
}

func (r *taxRuleRepository) ClearActions(ctx context.Context, db DBTX, companyID, taxRuleID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM accounting.tax_actions WHERE tax_rule_id = $1`, taxRuleID)
	if err != nil {
		r.logger.Error("failed to clear actions",
			util.String("rule_id", taxRuleID.String()),
			util.ErrorField(err))
		return fmt.Errorf("clear actions: %w", err)
	}
	return nil
}

// Applicable rules (with ANY array performance)

func (r *taxRuleRepository) GetApplicableRules(ctx context.Context, db DBTX, companyID uuid.UUID, appliesTo string) ([]*TaxRuleBundle, error) {
	return r.GetApplicableRulesWithLimit(ctx, db, companyID, appliesTo, 0)
}

func (r *taxRuleRepository) GetApplicableRulesWithLimit(ctx context.Context, db DBTX, companyID uuid.UUID, appliesTo string, limit int) ([]*TaxRuleBundle, error) {
	query := `
		SELECT tr.tax_rule_id, tr.company_id, tr.rule_name, tr.applies_to, tr.priority,
		       tr.is_active, tr.created_at, tr.updated_at, tr.created_by, tr.updated_by, tr.deleted_at,
		       trv.version_id, trv.version, trv.rule_json, trv.is_current, trv.created_at, trv.created_by
		FROM accounting.tax_rules tr
		INNER JOIN accounting.tax_rule_versions trv ON tr.tax_rule_id = trv.tax_rule_id
		WHERE tr.company_id = $1
		  AND tr.is_active = true
		  AND tr.deleted_at IS NULL
		  AND trv.is_current = true
		  AND (tr.applies_to = $2 OR tr.applies_to = 'both')
		ORDER BY tr.priority DESC
	`
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := db.QueryContext(ctx, query, companyID, appliesTo)
	if err != nil {
		r.logger.Error("failed to get applicable rules",
			util.String("company_id", companyID.String()),
			util.String("applies_to", appliesTo),
			util.ErrorField(err))
		return nil, fmt.Errorf("get applicable rules: %w", err)
	}
	defer rows.Close()

	var rules []*tax.TaxRule
	var versions []*tax.TaxRuleVersion
	ruleIDs := []uuid.UUID{}

	for rows.Next() {
		var rule tax.TaxRule
		var createdBy, updatedBy uuid.NullUUID
		var deletedAt sql.NullTime
		var version tax.TaxRuleVersion
		var versionCreatedBy uuid.NullUUID

		if err := rows.Scan(
			&rule.TaxRuleID, &rule.CompanyID, &rule.RuleName, &rule.AppliesTo, &rule.Priority,
			&rule.IsActive, &rule.CreatedAt, &rule.UpdatedAt, &createdBy, &updatedBy, &deletedAt,
			&version.VersionID, &version.Version, &version.RuleJSON, &version.IsCurrent,
			&version.CreatedAt, &versionCreatedBy,
		); err != nil {
			return nil, fmt.Errorf("scan rule bundle: %w", err)
		}
		if createdBy.Valid {
			rule.CreatedBy = &createdBy.UUID
		}
		if updatedBy.Valid {
			rule.UpdatedBy = &updatedBy.UUID
		}
		if deletedAt.Valid {
			rule.DeletedAt = &deletedAt.Time
		}
		if versionCreatedBy.Valid {
			version.CreatedBy = &versionCreatedBy.UUID
		}
		version.TaxRuleID = rule.TaxRuleID
		rules = append(rules, &rule)
		versions = append(versions, &version)
		ruleIDs = append(ruleIDs, rule.TaxRuleID)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return []*TaxRuleBundle{}, nil
	}

	conditionsMap, err := r.bulkGetConditions(ctx, db, ruleIDs)
	if err != nil {
		return nil, fmt.Errorf("bulk get conditions: %w", err)
	}
	actionsMap, err := r.bulkGetActions(ctx, db, ruleIDs)
	if err != nil {
		return nil, fmt.Errorf("bulk get actions: %w", err)
	}

	bundles := make([]*TaxRuleBundle, len(rules))
	for i, rule := range rules {
		cond := conditionsMap[rule.TaxRuleID]
		if cond == nil {
			cond = []*tax.TaxCondition{}
		}
		act := actionsMap[rule.TaxRuleID]
		if act == nil {
			act = []*tax.TaxAction{}
		}
		bundles[i] = &TaxRuleBundle{
			Rule:       rule,
			Version:    versions[i],
			Conditions: cond,
			Actions:    act,
		}
	}
	return bundles, nil
}

func (r *taxRuleRepository) bulkGetConditions(ctx context.Context, db DBTX, ruleIDs []uuid.UUID) (map[uuid.UUID][]*tax.TaxCondition, error) {
	if len(ruleIDs) == 0 {
		return map[uuid.UUID][]*tax.TaxCondition{}, nil
	}
	query := `
		SELECT condition_id, tax_rule_id, field_name, operator,
		       value_text, value_numeric, created_at
		FROM accounting.tax_conditions
		WHERE tax_rule_id = ANY($1)
		ORDER BY tax_rule_id, created_at
	`
	rows, err := db.QueryContext(ctx, query, pq.Array(ruleIDs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[uuid.UUID][]*tax.TaxCondition)
	for rows.Next() {
		var c tax.TaxCondition
		if err := rows.Scan(&c.ConditionID, &c.TaxRuleID, &c.FieldName, &c.Operator,
			&c.ValueText, &c.ValueNumeric, &c.CreatedAt); err != nil {
			return nil, err
		}
		result[c.TaxRuleID] = append(result[c.TaxRuleID], &c)
	}
	return result, rows.Err()
}

func (r *taxRuleRepository) bulkGetActions(ctx context.Context, db DBTX, ruleIDs []uuid.UUID) (map[uuid.UUID][]*tax.TaxAction, error) {
	if len(ruleIDs) == 0 {
		return map[uuid.UUID][]*tax.TaxAction{}, nil
	}
	query := `
		SELECT action_id, tax_rule_id, tax_rate_id, action_type,
		       calculation_basis, created_at
		FROM accounting.tax_actions
		WHERE tax_rule_id = ANY($1)
		ORDER BY tax_rule_id, created_at
	`
	rows, err := db.QueryContext(ctx, query, pq.Array(ruleIDs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[uuid.UUID][]*tax.TaxAction)
	for rows.Next() {
		var a tax.TaxAction
		if err := rows.Scan(&a.ActionID, &a.TaxRuleID, &a.TaxRateID, &a.ActionType,
			&a.CalculationBasis, &a.CreatedAt); err != nil {
			return nil, err
		}
		result[a.TaxRuleID] = append(result[a.TaxRuleID], &a)
	}
	return result, rows.Err()
}

func (r *taxRuleRepository) BulkGetCurrentVersions(ctx context.Context, db DBTX, companyID uuid.UUID, ruleIDs []uuid.UUID) (map[uuid.UUID]*tax.TaxRuleVersion, error) {
	if len(ruleIDs) == 0 {
		return map[uuid.UUID]*tax.TaxRuleVersion{}, nil
	}
	query := `
		SELECT version_id, tax_rule_id, version, rule_json, is_current,
		       created_at, created_by
		FROM accounting.tax_rule_versions
		WHERE tax_rule_id = ANY($1) AND is_current = true
	`
	rows, err := db.QueryContext(ctx, query, pq.Array(ruleIDs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[uuid.UUID]*tax.TaxRuleVersion)
	for rows.Next() {
		var v tax.TaxRuleVersion
		var createdBy uuid.NullUUID
		if err := rows.Scan(&v.VersionID, &v.TaxRuleID, &v.Version, &v.RuleJSON, &v.IsCurrent,
			&v.CreatedAt, &createdBy); err != nil {
			return nil, err
		}
		if createdBy.Valid {
			v.CreatedBy = &createdBy.UUID
		}
		result[v.TaxRuleID] = &v
	}
	return result, rows.Err()
}

// Utility

func (r *taxRuleRepository) Exists(ctx context.Context, db DBTX, companyID uuid.UUID, ruleName string) (bool, error) {
	var exists bool
	err := db.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM accounting.tax_rules
			WHERE company_id = $1 AND rule_name = $2 AND deleted_at IS NULL
		)
	`, companyID, ruleName).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check existence",
			util.String("company_id", companyID.String()),
			util.String("rule_name", ruleName),
			util.ErrorField(err))
		return false, fmt.Errorf("exists tax rule: %w", err)
	}
	return exists, nil
}

func (r *taxRuleRepository) CheckUsage(ctx context.Context, db DBTX, companyID, ruleID uuid.UUID) (bool, error) {
	var exists bool
	err := db.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM accounting.tax_transactions
			WHERE tax_rule_id = $1 AND company_id = $2
		)
	`, ruleID, companyID).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check usage",
			util.String("rule_id", ruleID.String()),
			util.ErrorField(err))
		return false, fmt.Errorf("check usage: %w", err)
	}
	return exists, nil
}
