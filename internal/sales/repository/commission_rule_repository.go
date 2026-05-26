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

	salesErrors "auth-service/internal/sales/errors"
	"auth-service/internal/sales/models"
	"auth-service/internal/sales/models/enums"
)

// -------------------------------------------------------------------------
// Interface
// -------------------------------------------------------------------------

type CommissionRuleRepository interface {
	Create(ctx context.Context, db DBTX, rule *models.CommissionRule) error
	GetByID(ctx context.Context, db DBTX, companyID, ruleID uuid.UUID) (*models.CommissionRule, error)
	Update(ctx context.Context, db DBTX, rule *models.CommissionRule) error
	Delete(ctx context.Context, db DBTX, companyID, ruleID uuid.UUID) error
	DeleteByPlan(ctx context.Context, db DBTX, companyID, planID uuid.UUID) error
	GetByPlan(ctx context.Context, db DBTX, companyID, planID uuid.UUID) ([]*models.CommissionRule, error)
	Exists(ctx context.Context, db DBTX, companyID, ruleID uuid.UUID) (bool, error)
	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, ruleID uuid.UUID) (*models.CommissionRule, error)
}

// CommissionRuleFilter is used for List operations if needed (optional, can add later)
type CommissionRuleFilter struct {
	CompanyID   uuid.UUID
	PlanID      *uuid.UUID
	RuleType    *enums.CommissionRuleType
	AppliesTo   *enums.CommissionBaseType
	ProductID   *uuid.UUID
	IsActive    *bool // note: CommissionRule doesn't have IsActive – depends on Plan's is_active; optional
	EffectiveAt *time.Time
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type commissionRuleRepository struct {
	logger *zap.Logger
}

func NewCommissionRuleRepository(logger *zap.Logger) CommissionRuleRepository {
	return &commissionRuleRepository{
		logger: logger.Named("sales_commission_rule_repo"),
	}
}

// Helpers

func (r *commissionRuleRepository) nullUUIDParam(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func (r *commissionRuleRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *commissionRuleRepository) validatePagination(p Pagination) (int, int) {
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

// scanCommissionRule scans a single row into a CommissionRule model
func (r *commissionRuleRepository) scanCommissionRule(s scanner) (*models.CommissionRule, error) {
	var rule models.CommissionRule
	var ruleTypeStr, appliesToStr string
	var productID, createdBy, updatedBy uuid.NullUUID
	var tierMinStr, tierMaxStr sql.NullString

	err := s.Scan(
		&rule.RuleID,
		&rule.CompanyID,
		&rule.PlanID,
		&ruleTypeStr,
		&appliesToStr,
		&productID,
		&tierMinStr,
		&tierMaxStr,
		&rule.Rate,
		&rule.IsPercentage,
		&rule.Priority,
		&rule.CreatedAt,
		&rule.UpdatedAt,
		&createdBy,
		&updatedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, salesErrors.ErrNotFound
		}
		return nil, fmt.Errorf("scan commission rule: %w", err)
	}

	rule.RuleType = enums.CommissionRuleType(ruleTypeStr)
	rule.AppliesTo = enums.CommissionBaseType(appliesToStr)

	if productID.Valid {
		rule.ProductID = &productID.UUID
	}
	if tierMinStr.Valid {
		val, err := decimal.NewFromString(tierMinStr.String)
		if err == nil {
			rule.TierMin = &val
		}
	}
	if tierMaxStr.Valid {
		val, err := decimal.NewFromString(tierMaxStr.String)
		if err == nil {
			rule.TierMax = &val
		}
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

func (r *commissionRuleRepository) Create(ctx context.Context, db DBTX, rule *models.CommissionRule) error {
	query := `
		INSERT INTO sales.commission_rules (
			rule_id, company_id, plan_id, rule_type, applies_to, product_id,
			tier_min, tier_max, rate, is_percentage, priority,
			created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW(), $12, $13)
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		rule.RuleID,
		rule.CompanyID,
		rule.PlanID,
		string(rule.RuleType),
		string(rule.AppliesTo),
		r.nullUUIDParam(rule.ProductID),
		rule.TierMin,
		rule.TierMax,
		rule.Rate,
		rule.IsPercentage,
		rule.Priority,
		r.nullUUIDParam(rule.CreatedBy),
		r.nullUUIDParam(rule.UpdatedBy),
	).Scan(&rule.CreatedAt, &rule.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create commission rule", zap.Error(err))
		return fmt.Errorf("create commission rule: %w", err)
	}
	return nil
}

func (r *commissionRuleRepository) GetByID(ctx context.Context, db DBTX, companyID, ruleID uuid.UUID) (*models.CommissionRule, error) {
	query := `
		SELECT rule_id, company_id, plan_id, rule_type, applies_to, product_id,
			tier_min, tier_max, rate, is_percentage, priority,
			created_at, updated_at, created_by, updated_by
		FROM sales.commission_rules
		WHERE rule_id = $1 AND company_id = $2
	`
	row := db.QueryRowContext(ctx, query, ruleID, companyID)
	return r.scanCommissionRule(row)
}

func (r *commissionRuleRepository) Update(ctx context.Context, db DBTX, rule *models.CommissionRule) error {
	query := `
		UPDATE sales.commission_rules
		SET rule_type = $3,
			applies_to = $4,
			product_id = $5,
			tier_min = $6,
			tier_max = $7,
			rate = $8,
			is_percentage = $9,
			priority = $10,
			updated_at = NOW(),
			updated_by = $11
		WHERE rule_id = $1 AND company_id = $2
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		rule.RuleID,
		rule.CompanyID,
		string(rule.RuleType),
		string(rule.AppliesTo),
		r.nullUUIDParam(rule.ProductID),
		rule.TierMin,
		rule.TierMax,
		rule.Rate,
		rule.IsPercentage,
		rule.Priority,
		r.nullUUIDParam(rule.UpdatedBy),
	).Scan(&rule.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to update commission rule", zap.Error(err))
		return fmt.Errorf("update commission rule: %w", err)
	}
	return nil
}

func (r *commissionRuleRepository) Delete(ctx context.Context, db DBTX, companyID, ruleID uuid.UUID) error {
	query := `DELETE FROM sales.commission_rules WHERE rule_id = $1 AND company_id = $2`
	result, err := db.ExecContext(ctx, query, ruleID, companyID)
	if err != nil {
		return fmt.Errorf("delete commission rule: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return salesErrors.ErrNotFound
	}
	return nil
}

func (r *commissionRuleRepository) DeleteByPlan(ctx context.Context, db DBTX, companyID, planID uuid.UUID) error {
	query := `DELETE FROM sales.commission_rules WHERE plan_id = $1 AND company_id = $2`
	_, err := db.ExecContext(ctx, query, planID, companyID)
	if err != nil {
		return fmt.Errorf("delete rules by plan: %w", err)
	}
	// rows affected may be 0 – that's fine
	return nil
}

func (r *commissionRuleRepository) GetByPlan(ctx context.Context, db DBTX, companyID, planID uuid.UUID) ([]*models.CommissionRule, error) {
	query := `
		SELECT rule_id, company_id, plan_id, rule_type, applies_to, product_id,
			tier_min, tier_max, rate, is_percentage, priority,
			created_at, updated_at, created_by, updated_by
		FROM sales.commission_rules
		WHERE company_id = $1 AND plan_id = $2
		ORDER BY priority ASC, created_at ASC
	`
	rows, err := db.QueryContext(ctx, query, companyID, planID)
	if err != nil {
		return nil, fmt.Errorf("get rules by plan: %w", err)
	}
	defer rows.Close()

	var rules []*models.CommissionRule
	for rows.Next() {
		rule, err := r.scanCommissionRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

func (r *commissionRuleRepository) Exists(ctx context.Context, db DBTX, companyID, ruleID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.commission_rules WHERE rule_id = $1 AND company_id = $2)`
	err := db.QueryRowContext(ctx, query, ruleID, companyID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists commission rule: %w", err)
	}
	return exists, nil
}

func (r *commissionRuleRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, ruleID uuid.UUID) (*models.CommissionRule, error) {
	query := `
		SELECT rule_id, company_id, plan_id, rule_type, applies_to, product_id,
			tier_min, tier_max, rate, is_percentage, priority,
			created_at, updated_at, created_by, updated_by
		FROM sales.commission_rules
		WHERE rule_id = $1 AND company_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, ruleID, companyID)
	return r.scanCommissionRule(row)
}
