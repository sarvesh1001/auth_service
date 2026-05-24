package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	salesErrors "auth-service/internal/sales/errors"
	"auth-service/internal/sales/models/discount"
)

// -------------------------------------------------------------------------
// Interface
// -------------------------------------------------------------------------

type StackingRuleRepository interface {
	Create(ctx context.Context, db DBTX, rule *discount.DiscountStackingRule) error
	GetByID(ctx context.Context, db DBTX, companyID, ruleID uuid.UUID) (*discount.DiscountStackingRule, error)
	Update(ctx context.Context, db DBTX, rule *discount.DiscountStackingRule) error
	Delete(ctx context.Context, db DBTX, companyID, ruleID uuid.UUID) error
	GetForPrimary(ctx context.Context, db DBTX, companyID, discountID uuid.UUID, discountType string) (*discount.DiscountStackingRule, error)
	ValidateCombination(ctx context.Context, db DBTX, companyID uuid.UUID, discountTypes []string, discountIDs []uuid.UUID) error
	List(ctx context.Context, db DBTX, filter StackingRuleFilter, p Pagination, s Sort) ([]*discount.DiscountStackingRule, int64, error)
	Exists(ctx context.Context, db DBTX, companyID, ruleID uuid.UUID) (bool, error)
}

type StackingRuleFilter struct {
	CompanyID           uuid.UUID
	IDs                 []uuid.UUID
	IsActive            *bool
	PrimaryDiscountType *string
	PrimaryDiscountID   *uuid.UUID
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type stackingRuleRepository struct {
	logger *zap.Logger
}

func NewStackingRuleRepository(logger *zap.Logger) StackingRuleRepository {
	return &stackingRuleRepository{
		logger: logger.Named("sales_stacking_rule_repo"),
	}
}

// Helpers

func (r *stackingRuleRepository) nullUUIDParam(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func (r *stackingRuleRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
	if s.Field == "" {
		return "", nil
	}
	if !allowed[s.Field] {
		return "", fmt.Errorf("invalid sort field: %s", s.Field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "ASC"
	}
	return fmt.Sprintf("ORDER BY %s %s", s.Field, dir), nil
}

func (r *stackingRuleRepository) validatePagination(p Pagination) (int, int) {
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

func (r *stackingRuleRepository) buildFilter(filter StackingRuleFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if len(filter.IDs) > 0 {
		placeholders := make([]string, len(filter.IDs))
		for i, id := range filter.IDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("rule_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.IsActive != nil {
		conds = append(conds, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}
	if filter.PrimaryDiscountType != nil {
		conds = append(conds, fmt.Sprintf("primary_discount_type = $%d", idx))
		args = append(args, *filter.PrimaryDiscountType)
		idx++
	}
	if filter.PrimaryDiscountID != nil {
		conds = append(conds, fmt.Sprintf("primary_discount_id = $%d", idx))
		args = append(args, *filter.PrimaryDiscountID)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

func (r *stackingRuleRepository) scanStackingRule(s scanner) (*discount.DiscountStackingRule, error) {
	var rule discount.DiscountStackingRule
	var allowedTypesJSON []byte
	var maxTotalDiscount sql.NullString
	var createdBy, updatedBy uuid.NullUUID

	err := s.Scan(
		&rule.RuleID,
		&rule.CompanyID,
		&rule.RuleName,
		&rule.IsActive,
		&rule.PrimaryDiscountType,
		&rule.PrimaryDiscountID,
		&allowedTypesJSON,
		&maxTotalDiscount,
		&rule.CreatedAt,
		&rule.UpdatedAt,
		&createdBy,
		&updatedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, salesErrors.ErrNotFound
		}
		return nil, fmt.Errorf("scan stacking rule: %w", err)
	}
	if allowedTypesJSON != nil {
		rule.AllowedTypes = allowedTypesJSON
	}
	if maxTotalDiscount.Valid {
		val, _ := decimal.NewFromString(maxTotalDiscount.String)
		rule.MaxTotalDiscount = &val
	}
	if createdBy.Valid {
		rule.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		rule.UpdatedBy = &updatedBy.UUID
	}
	return &rule, nil
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (r *stackingRuleRepository) Create(ctx context.Context, db DBTX, rule *discount.DiscountStackingRule) error {
	query := `
		INSERT INTO sales.discount_stacking_rules (
			rule_id, company_id, rule_name, is_active, primary_discount_type,
			primary_discount_id, allowed_types, max_total_discount, created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW(), $9, $10)
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		rule.RuleID,
		rule.CompanyID,
		rule.RuleName,
		rule.IsActive,
		rule.PrimaryDiscountType,
		rule.PrimaryDiscountID,
		rule.AllowedTypes,
		rule.MaxTotalDiscount,
		r.nullUUIDParam(rule.CreatedBy),
		r.nullUUIDParam(rule.UpdatedBy),
	).Scan(&rule.CreatedAt, &rule.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create stacking rule", zap.Error(err))
		return fmt.Errorf("create stacking rule: %w", err)
	}
	return nil
}

func (r *stackingRuleRepository) GetByID(ctx context.Context, db DBTX, companyID, ruleID uuid.UUID) (*discount.DiscountStackingRule, error) {
	query := `
		SELECT rule_id, company_id, rule_name, is_active, primary_discount_type,
			primary_discount_id, allowed_types, max_total_discount, created_at, updated_at, created_by, updated_by
		FROM sales.discount_stacking_rules
		WHERE rule_id = $1 AND company_id = $2
	`
	row := db.QueryRowContext(ctx, query, ruleID, companyID)
	return r.scanStackingRule(row)
}

func (r *stackingRuleRepository) Update(ctx context.Context, db DBTX, rule *discount.DiscountStackingRule) error {
	query := `
		UPDATE sales.discount_stacking_rules
		SET rule_name = $3,
			is_active = $4,
			primary_discount_type = $5,
			primary_discount_id = $6,
			allowed_types = $7,
			max_total_discount = $8,
			updated_at = NOW(),
			updated_by = $9
		WHERE rule_id = $1 AND company_id = $2
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		rule.RuleID,
		rule.CompanyID,
		rule.RuleName,
		rule.IsActive,
		rule.PrimaryDiscountType,
		rule.PrimaryDiscountID,
		rule.AllowedTypes,
		rule.MaxTotalDiscount,
		r.nullUUIDParam(rule.UpdatedBy),
	).Scan(&rule.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to update stacking rule", zap.Error(err))
		return fmt.Errorf("update stacking rule: %w", err)
	}
	return nil
}

func (r *stackingRuleRepository) Delete(ctx context.Context, db DBTX, companyID, ruleID uuid.UUID) error {
	query := `DELETE FROM sales.discount_stacking_rules WHERE rule_id = $1 AND company_id = $2`
	result, err := db.ExecContext(ctx, query, ruleID, companyID)
	if err != nil {
		return fmt.Errorf("delete stacking rule: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

func (r *stackingRuleRepository) GetForPrimary(ctx context.Context, db DBTX, companyID, discountID uuid.UUID, discountType string) (*discount.DiscountStackingRule, error) {
	query := `
		SELECT rule_id, company_id, rule_name, is_active, primary_discount_type,
			primary_discount_id, allowed_types, max_total_discount, created_at, updated_at, created_by, updated_by
		FROM sales.discount_stacking_rules
		WHERE company_id = $1 AND primary_discount_id = $2 AND primary_discount_type = $3 AND is_active = true
	`
	row := db.QueryRowContext(ctx, query, companyID, discountID, discountType)
	return r.scanStackingRule(row)
}

func (r *stackingRuleRepository) ValidateCombination(ctx context.Context, db DBTX, companyID uuid.UUID, discountTypes []string, discountIDs []uuid.UUID) error {
	// Simple validation: check if any pair is explicitly excluded in discount_exclusions.
	// Also check stacking rules: for each primary, ensure secondary types are allowed.
	// Implementation depends on business logic. Here we provide a basic check.
	if len(discountTypes) != len(discountIDs) || len(discountTypes) < 2 {
		return nil
	}
	// For each pair, check exclusion table.
	for i := 0; i < len(discountTypes)-1; i++ {
		for j := i + 1; j < len(discountTypes); j++ {
			// Check both orders
			excluded, err := r.isExcludedPair(ctx, db, companyID, discountTypes[i], discountIDs[i], discountTypes[j], discountIDs[j])
			if err != nil {
				return err
			}
			if excluded {
				return fmt.Errorf("discount combination not allowed: %s(%s) and %s(%s) are excluded",
					discountTypes[i], discountIDs[i].String(), discountTypes[j], discountIDs[j].String())
			}
		}
	}
	return nil
}

// internal helper to check exclusion (cross-call to exclusion repository)
func (r *stackingRuleRepository) isExcludedPair(ctx context.Context, db DBTX, companyID uuid.UUID, typeA string, idA uuid.UUID, typeB string, idB uuid.UUID) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(
			SELECT 1 FROM sales.discount_exclusions
			WHERE company_id = $1
				AND ((discount_type_a = $2 AND discount_id_a = $3 AND discount_type_b = $4 AND discount_id_b = $5)
				  OR (discount_type_a = $4 AND discount_id_a = $5 AND discount_type_b = $2 AND discount_id_b = $3))
		)
	`
	err := db.QueryRowContext(ctx, query, companyID, typeA, idA, typeB, idB).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check exclusion: %w", err)
	}
	return exists, nil
}

func (r *stackingRuleRepository) List(ctx context.Context, db DBTX, filter StackingRuleFilter, p Pagination, s Sort) ([]*discount.DiscountStackingRule, int64, error) {
	where, args := r.buildFilter(filter)
	if where == "" && filter.CompanyID == uuid.Nil {
		return nil, 0, fmt.Errorf("list requires company_id filter")
	}
	if filter.CompanyID != uuid.Nil && where == "" {
		where = "WHERE company_id = $1"
		args = []interface{}{filter.CompanyID}
	}
	allowedSort := map[string]bool{
		"rule_name":             true,
		"primary_discount_type": true,
		"created_at":            true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY created_at DESC"
	}
	limit, offset := r.validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sales.discount_stacking_rules %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count stacking rules: %w", err)
	}
	if total == 0 {
		return []*discount.DiscountStackingRule{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT rule_id, company_id, rule_name, is_active, primary_discount_type,
			primary_discount_id, allowed_types, max_total_discount, created_at, updated_at, created_by, updated_by
		FROM sales.discount_stacking_rules
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list stacking rules: %w", err)
	}
	defer rows.Close()

	var result []*discount.DiscountStackingRule
	for rows.Next() {
		rule, err := r.scanStackingRule(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, rule)
	}
	return result, total, rows.Err()
}

func (r *stackingRuleRepository) Exists(ctx context.Context, db DBTX, companyID, ruleID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.discount_stacking_rules WHERE rule_id = $1 AND company_id = $2)`
	err := db.QueryRowContext(ctx, query, ruleID, companyID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists stacking rule: %w", err)
	}
	return exists, nil
}
