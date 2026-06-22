package repository

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"gorm.io/datatypes"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/sales/errors"
	"auth-service/internal/sales/models/discount"
	"auth-service/internal/sales/models/enums"
)

// -------------------------------------------------------------------------
// Interfaces and supporting types
// -------------------------------------------------------------------------
type PromotionFilter struct {
	CompanyID     uuid.UUID
	PromotionIDs  []uuid.UUID
	IsActive      *bool
	Name          *string
	MinPriority   *int
	MaxPriority   *int
	DiscountTypes []enums.DiscountType
	StartDateFrom *time.Time
	StartDateTo   *time.Time
	EndDateFrom   *time.Time
	EndDateTo     *time.Time
	CreatedFrom   *time.Time
	CreatedTo     *time.Time
	UpdatedFrom   *time.Time
	UpdatedTo     *time.Time
}

type PromotionRepository interface {
	// CRUD
	Create(ctx context.Context, db DBTX, promotion *discount.Promotion, rules []*discount.PromotionRule) error
	GetByID(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID) (*discount.Promotion, error)
	Update(ctx context.Context, db DBTX, promotion *discount.Promotion) error
	Delete(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID) error
	Exists(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID) (bool, error)
	GetTopPromotionsByUsage(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*PromotionAnalyticsAggregate, error)
	GetTopPromotionsByDiscountAmount(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*PromotionAnalyticsAggregate, error)

	// Status / lifecycle
	SetActiveStatus(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID, isActive bool, updatedBy *uuid.UUID) error
	IsActive(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID) (bool, error)
	IsExpired(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID, at time.Time) (bool, error)

	// Stacking type
	GetStackingType(ctx context.Context, db DBTX, promotionID uuid.UUID) (string, error)

	// Promotion rules
	AddRules(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID, rules []*discount.PromotionRule) error
	ReplaceRules(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID, rules []*discount.PromotionRule) error
	DeleteRule(ctx context.Context, db DBTX, companyID, promotionID, ruleID uuid.UUID) error
	GetRules(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID) ([]*discount.PromotionRule, error)
	GetRuleByID(ctx context.Context, db DBTX, companyID, promotionID, ruleID uuid.UUID) (*discount.PromotionRule, error)
	ExistsRule(ctx context.Context, db DBTX, companyID, promotionID, ruleID uuid.UUID) (bool, error)

	// Validation / applicability
	GetApplicablePromotions(ctx context.Context, db DBTX, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) ([]*discount.Promotion, error)
	GetApplicableRules(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) ([]*discount.PromotionRule, error)
	IsApplicableForOrderAmount(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID, orderAmount decimal.Decimal) (bool, error)
	IsApplicableForProduct(ctx context.Context, db DBTX, companyID, promotionID, productID uuid.UUID) (bool, error)
	IsApplicableForCustomer(ctx context.Context, db DBTX, companyID, promotionID, customerID uuid.UUID) (bool, error)
	ValidatePromotion(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) error

	// Discount calculation
	CalculateDiscount(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) (decimal.Decimal, error)
	GetMaximumDiscount(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID, orderAmount decimal.Decimal) (decimal.Decimal, error)

	// Listing / search
	List(ctx context.Context, db DBTX, filter PromotionFilter, p Pagination, s Sort) ([]*discount.Promotion, int64, error)
	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*discount.Promotion, int64, error)
	GetActivePromotions(ctx context.Context, db DBTX, companyID uuid.UUID, at time.Time) ([]*discount.Promotion, error)
	GetExpiredPromotions(ctx context.Context, db DBTX, companyID uuid.UUID, at time.Time) ([]*discount.Promotion, error)
	GetPromotionsStartingSoon(ctx context.Context, db DBTX, companyID uuid.UUID, before time.Time) ([]*discount.Promotion, error)
	GetPromotionsEndingSoon(ctx context.Context, db DBTX, companyID uuid.UUID, before time.Time) ([]*discount.Promotion, error)

	// Analytics / reporting
	GetTotalDiscountGiven(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetUnusedPromotions(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*discount.Promotion, error)

	// Concurrency / locking
	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID) (*discount.Promotion, error)
	GetRuleByIDForUpdate(ctx context.Context, db DBTX, companyID, promotionID, ruleID uuid.UUID) (*discount.PromotionRule, error)

	// Bulk find
	FindByIDs(ctx context.Context, db DBTX, companyID uuid.UUID, ids []uuid.UUID) ([]*discount.Promotion, error)
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type promotionRepository struct {
	logger *zap.Logger
}

func NewPromotionRepository(logger *zap.Logger) PromotionRepository {
	return &promotionRepository{
		logger: logger.Named("sales_promotion_repo"),
	}
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

func (r *promotionRepository) nullUUIDParam(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func (r *promotionRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *promotionRepository) validatePagination(p Pagination) (int, int) {
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

// buildPromotionFilter now always includes deleted_at IS NULL to exclude soft-deleted promotions.
func (r *promotionRepository) buildPromotionFilter(filter PromotionFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	// Always exclude soft-deleted promotions
	conds = append(conds, "deleted_at IS NULL")

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if len(filter.PromotionIDs) > 0 {
		placeholders := make([]string, len(filter.PromotionIDs))
		for i, id := range filter.PromotionIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("promotion_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.IsActive != nil {
		conds = append(conds, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}
	if filter.Name != nil {
		conds = append(conds, fmt.Sprintf("name ILIKE $%d", idx))
		args = append(args, "%"+*filter.Name+"%")
		idx++
	}
	if filter.MinPriority != nil {
		conds = append(conds, fmt.Sprintf("priority >= $%d", idx))
		args = append(args, *filter.MinPriority)
		idx++
	}
	if filter.MaxPriority != nil {
		conds = append(conds, fmt.Sprintf("priority <= $%d", idx))
		args = append(args, *filter.MaxPriority)
		idx++
	}
	if len(filter.DiscountTypes) > 0 {
		placeholders := make([]string, len(filter.DiscountTypes))
		for i, dt := range filter.DiscountTypes {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, dt.String())
			idx++
		}
		conds = append(conds, fmt.Sprintf("discount_type IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.StartDateFrom != nil {
		conds = append(conds, fmt.Sprintf("start_date >= $%d", idx))
		args = append(args, *filter.StartDateFrom)
		idx++
	}
	if filter.StartDateTo != nil {
		conds = append(conds, fmt.Sprintf("start_date <= $%d", idx))
		args = append(args, *filter.StartDateTo)
		idx++
	}
	if filter.EndDateFrom != nil {
		conds = append(conds, fmt.Sprintf("end_date >= $%d", idx))
		args = append(args, *filter.EndDateFrom)
		idx++
	}
	if filter.EndDateTo != nil {
		conds = append(conds, fmt.Sprintf("end_date <= $%d", idx))
		args = append(args, *filter.EndDateTo)
		idx++
	}
	if filter.CreatedFrom != nil {
		conds = append(conds, fmt.Sprintf("created_at >= $%d", idx))
		args = append(args, *filter.CreatedFrom)
		idx++
	}
	if filter.CreatedTo != nil {
		conds = append(conds, fmt.Sprintf("created_at <= $%d", idx))
		args = append(args, *filter.CreatedTo)
		idx++
	}
	if filter.UpdatedFrom != nil {
		conds = append(conds, fmt.Sprintf("updated_at >= $%d", idx))
		args = append(args, *filter.UpdatedFrom)
		idx++
	}
	if filter.UpdatedTo != nil {
		conds = append(conds, fmt.Sprintf("updated_at <= $%d", idx))
		args = append(args, *filter.UpdatedTo)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// scanPromotion now includes usage_limit, per_user_limit, and deleted_at.
func (r *promotionRepository) scanPromotion(s scanner) (*discount.Promotion, error) {
	var p discount.Promotion
	var createdBy, updatedBy uuid.NullUUID
	var priority sql.NullInt32
	var usageLimit, perUserLimit sql.NullInt32
	var deletedAt sql.NullTime

	err := s.Scan(
		&p.PromotionID,
		&p.CompanyID,
		&p.Name,
		&p.Description,
		&p.StartDate,
		&p.EndDate,
		&p.IsActive,
		&priority,
		&p.StackingType,
		&usageLimit,
		&perUserLimit,
		&deletedAt,
		&p.CreatedAt,
		&p.UpdatedAt,
		&createdBy,
		&updatedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan promotion: %w", err)
	}
	if priority.Valid {
		p.Priority = new(int)
		*p.Priority = int(priority.Int32)
	}
	if usageLimit.Valid {
		val := int(usageLimit.Int32)
		p.UsageLimit = &val
	}
	if perUserLimit.Valid {
		val := int(perUserLimit.Int32)
		p.PerUserLimit = &val
	}
	if deletedAt.Valid {
		p.DeletedAt = &deletedAt.Time
	}
	if createdBy.Valid {
		p.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		p.UpdatedBy = &updatedBy.UUID
	}
	return &p, nil
}

// scanPromotionRule unchanged.
func (r *promotionRepository) scanPromotionRule(s scanner) (*discount.PromotionRule, error) {
	var rule discount.PromotionRule
	var maxDiscount sql.NullString
	var ruleConfigJSON []byte

	err := s.Scan(
		&rule.RuleID,
		&rule.PromotionID,
		&rule.RuleType,
		&ruleConfigJSON,
		&rule.DiscountType,
		&rule.DiscountValue,
		&maxDiscount,
		&rule.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan promotion rule: %w", err)
	}
	if len(ruleConfigJSON) > 0 {
		rule.RuleConfig = datatypes.JSON(ruleConfigJSON)
	}
	if maxDiscount.Valid {
		val, err := decimal.NewFromString(maxDiscount.String)
		if err == nil {
			rule.MaxDiscount = &val
		}
	}
	return &rule, nil
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (r *promotionRepository) Create(ctx context.Context, db DBTX, promotion *discount.Promotion, rules []*discount.PromotionRule) error {
	logger := r.logger.With(
		zap.String("method", "Create"),
		zap.String("promotion_id", promotion.PromotionID.String()),
	)
	logger.Info("inserting promotion")

	queryPromo := `
		INSERT INTO sales.promotions (
			promotion_id, company_id, name, description,
			start_date, end_date, is_active, priority, stacking_type,
			usage_limit, per_user_limit,
			created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW(), $12, $13)
		RETURNING created_at, updated_at
	`
	var priority interface{}
	if promotion.Priority != nil {
		priority = *promotion.Priority
	} else {
		priority = nil
	}
	err := db.QueryRowContext(ctx, queryPromo,
		promotion.PromotionID,
		promotion.CompanyID,
		promotion.Name,
		promotion.Description,
		promotion.StartDate,
		promotion.EndDate,
		promotion.IsActive,
		priority,
		promotion.StackingType,
		promotion.UsageLimit,
		promotion.PerUserLimit,
		r.nullUUIDParam(promotion.CreatedBy),
		r.nullUUIDParam(promotion.UpdatedBy),
	).Scan(&promotion.CreatedAt, &promotion.UpdatedAt)
	if err != nil {
		logger.Error("failed to insert promotion", zap.Error(err))
		return fmt.Errorf("create promotion: %w", err)
	}
	logger.Info("promotion inserted",
		zap.Time("created_at", promotion.CreatedAt),
		zap.Time("updated_at", promotion.UpdatedAt))

	// ---- Insert rules if any ----
	if len(rules) > 0 {
		logger.Info("adding rules", zap.Int("rule_count", len(rules)))
		if err := r.AddRules(ctx, db, promotion.CompanyID, promotion.PromotionID, rules); err != nil {
			logger.Error("failed to add rules", zap.Error(err))
			return err
		}
		logger.Info("rules added successfully")
	} else {
		logger.Info("no rules to add")
	}
	// -----------------------------

	return nil
}

func (r *promotionRepository) GetByID(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID) (*discount.Promotion, error) {
	query := `
		SELECT promotion_id, company_id, name, description,
		       start_date, end_date, is_active, priority, stacking_type,
		       usage_limit, per_user_limit, deleted_at,
		       created_at, updated_at, created_by, updated_by
		FROM sales.promotions
		WHERE company_id = $1 AND promotion_id = $2 AND deleted_at IS NULL
	`
	row := db.QueryRowContext(ctx, query, companyID, promotionID)
	return r.scanPromotion(row)
}

func (r *promotionRepository) Update(ctx context.Context, db DBTX, promotion *discount.Promotion) error {
	query := `
		UPDATE sales.promotions SET
			name = $3,
			description = $4,
			start_date = $5,
			end_date = $6,
			is_active = $7,
			priority = $8,
			stacking_type = $9,
			usage_limit = $10,
			per_user_limit = $11,
			updated_at = NOW(),
			updated_by = $12
		WHERE promotion_id = $1 AND company_id = $2 AND deleted_at IS NULL
		RETURNING updated_at
	`
	var priority interface{}
	if promotion.Priority != nil {
		priority = *promotion.Priority
	} else {
		priority = nil
	}
	err := db.QueryRowContext(ctx, query,
		promotion.PromotionID,
		promotion.CompanyID,
		promotion.Name,
		promotion.Description,
		promotion.StartDate,
		promotion.EndDate,
		promotion.IsActive,
		priority,
		promotion.StackingType,
		promotion.UsageLimit,
		promotion.PerUserLimit,
		r.nullUUIDParam(promotion.UpdatedBy),
	).Scan(&promotion.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return fmt.Errorf("update promotion: %w", err)
	}
	return nil
}

// Delete performs soft delete by setting deleted_at.
func (r *promotionRepository) Delete(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID) error {
	query := `UPDATE sales.promotions SET deleted_at = NOW() WHERE company_id = $1 AND promotion_id = $2 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, companyID, promotionID)
	if err != nil {
		return fmt.Errorf("soft delete promotion: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *promotionRepository) Exists(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.promotions WHERE company_id = $1 AND promotion_id = $2 AND deleted_at IS NULL)`
	err := db.QueryRowContext(ctx, query, companyID, promotionID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists promotion: %w", err)
	}
	return exists, nil
}

// -------------------------------------------------------------------------
// Status / lifecycle
// -------------------------------------------------------------------------

func (r *promotionRepository) SetActiveStatus(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID, isActive bool, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.promotions
		SET is_active = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND promotion_id = $2 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, companyID, promotionID, isActive, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("set active status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *promotionRepository) IsActive(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID) (bool, error) {
	var active bool
	query := `SELECT is_active FROM sales.promotions WHERE company_id = $1 AND promotion_id = $2 AND deleted_at IS NULL`
	err := db.QueryRowContext(ctx, query, companyID, promotionID).Scan(&active)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, errors.ErrNotFound
		}
		return false, fmt.Errorf("is active: %w", err)
	}
	return active, nil
}

func (r *promotionRepository) IsExpired(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID, at time.Time) (bool, error) {
	var expired bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.promotions WHERE company_id = $1 AND promotion_id = $2 AND deleted_at IS NULL AND end_date < $3)`
	err := db.QueryRowContext(ctx, query, companyID, promotionID, at).Scan(&expired)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, errors.ErrNotFound
		}
		return false, fmt.Errorf("is expired: %w", err)
	}
	return expired, nil
}

func (r *promotionRepository) GetStackingType(ctx context.Context, db DBTX, promotionID uuid.UUID) (string, error) {
	var stackingType string
	query := `SELECT stacking_type FROM sales.promotions WHERE promotion_id = $1 AND deleted_at IS NULL`
	err := db.QueryRowContext(ctx, query, promotionID).Scan(&stackingType)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.ErrNotFound
		}
		return "", fmt.Errorf("get stacking type: %w", err)
	}
	return stackingType, nil
}

// -------------------------------------------------------------------------
// Promotion rules
// -------------------------------------------------------------------------

func (r *promotionRepository) AddRules(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID, rules []*discount.PromotionRule) error {
	for _, rule := range rules {
		query := `
			INSERT INTO sales.promotion_rules (
				rule_id, promotion_id, rule_type, rule_config,
				discount_type, discount_value, max_discount, created_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		`
		var maxDiscount interface{}
		if rule.MaxDiscount != nil {
			maxDiscount = rule.MaxDiscount.String()
		} else {
			maxDiscount = nil
		}
		ruleConfigJSON, err := rule.RuleConfig.MarshalJSON()
		if err != nil {
			return fmt.Errorf("marshal rule config: %w", err)
		}
		_, err = db.ExecContext(ctx, query,
			rule.RuleID,
			promotionID,
			rule.RuleType,
			ruleConfigJSON,
			rule.DiscountType.String(),
			rule.DiscountValue,
			maxDiscount,
		)
		if err != nil {
			return fmt.Errorf("insert promotion rule: %w", err)
		}
	}
	return nil
}

func (r *promotionRepository) ReplaceRules(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID, rules []*discount.PromotionRule) error {
	_, err := db.ExecContext(ctx, `DELETE FROM sales.promotion_rules WHERE promotion_id = $1`, promotionID)
	if err != nil {
		return fmt.Errorf("delete old rules: %w", err)
	}
	if len(rules) == 0 {
		return nil
	}
	return r.AddRules(ctx, db, companyID, promotionID, rules)
}

func (r *promotionRepository) DeleteRule(ctx context.Context, db DBTX, companyID, promotionID, ruleID uuid.UUID) error {
	query := `
		DELETE FROM sales.promotion_rules
		WHERE rule_id = $1
		AND promotion_id = $2
		AND promotion_id IN (SELECT promotion_id FROM sales.promotions WHERE company_id = $3 AND deleted_at IS NULL)
	`
	result, err := db.ExecContext(ctx, query, ruleID, promotionID, companyID)
	if err != nil {
		return fmt.Errorf("delete rule: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *promotionRepository) GetRules(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID) ([]*discount.PromotionRule, error) {
	query := `
		SELECT pr.rule_id, pr.promotion_id, pr.rule_type, pr.rule_config,
		       pr.discount_type, pr.discount_value, pr.max_discount, pr.created_at
		FROM sales.promotion_rules pr
		JOIN sales.promotions p ON pr.promotion_id = p.promotion_id
		WHERE p.company_id = $1 AND pr.promotion_id = $2 AND p.deleted_at IS NULL
		ORDER BY pr.created_at
	`
	rows, err := db.QueryContext(ctx, query, companyID, promotionID)
	if err != nil {
		return nil, fmt.Errorf("get rules: %w", err)
	}
	defer rows.Close()
	var result []*discount.PromotionRule
	for rows.Next() {
		rule, err := r.scanPromotionRule(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, rule)
	}
	return result, rows.Err()
}

func (r *promotionRepository) GetRuleByID(ctx context.Context, db DBTX, companyID, promotionID, ruleID uuid.UUID) (*discount.PromotionRule, error) {
	query := `
		SELECT pr.rule_id, pr.promotion_id, pr.rule_type, pr.rule_config,
		       pr.discount_type, pr.discount_value, pr.max_discount, pr.created_at
		FROM sales.promotion_rules pr
		JOIN sales.promotions p ON pr.promotion_id = p.promotion_id
		WHERE p.company_id = $1 AND pr.promotion_id = $2 AND pr.rule_id = $3 AND p.deleted_at IS NULL
	`
	row := db.QueryRowContext(ctx, query, companyID, promotionID, ruleID)
	return r.scanPromotionRule(row)
}

func (r *promotionRepository) ExistsRule(ctx context.Context, db DBTX, companyID, promotionID, ruleID uuid.UUID) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(
			SELECT 1 FROM sales.promotion_rules pr
			JOIN sales.promotions p ON pr.promotion_id = p.promotion_id
			WHERE p.company_id = $1 AND pr.promotion_id = $2 AND pr.rule_id = $3 AND p.deleted_at IS NULL
		)
	`
	err := db.QueryRowContext(ctx, query, companyID, promotionID, ruleID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists rule: %w", err)
	}
	return exists, nil
}

// -------------------------------------------------------------------------
// Validation / applicability
// -------------------------------------------------------------------------

func (r *promotionRepository) GetApplicablePromotions(ctx context.Context, db DBTX, companyID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) ([]*discount.Promotion, error) {
	query := `
		SELECT promotion_id, company_id, name, description,
		       start_date, end_date, is_active, priority, stacking_type,
		       usage_limit, per_user_limit, deleted_at,
		       created_at, updated_at, created_by, updated_by
		FROM sales.promotions
		WHERE company_id = $1
		AND is_active = true
		AND start_date <= $2
		AND end_date >= $2
		AND deleted_at IS NULL
		ORDER BY priority DESC, start_date ASC
	`
	rows, err := db.QueryContext(ctx, query, companyID, at)
	if err != nil {
		return nil, fmt.Errorf("get applicable promotions: %w", err)
	}
	defer rows.Close()
	var promotions []*discount.Promotion
	for rows.Next() {
		p, err := r.scanPromotion(rows)
		if err != nil {
			return nil, err
		}
		promotions = append(promotions, p)
	}
	return promotions, rows.Err()
}

func (r *promotionRepository) GetApplicableRules(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) ([]*discount.PromotionRule, error) {
	return r.GetRules(ctx, db, companyID, promotionID)
}

func (r *promotionRepository) IsApplicableForOrderAmount(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID, orderAmount decimal.Decimal) (bool, error) {
	exists, err := r.Exists(ctx, db, companyID, promotionID)
	return exists, err
}

func (r *promotionRepository) IsApplicableForProduct(ctx context.Context, db DBTX, companyID, promotionID, productID uuid.UUID) (bool, error) {
	return true, nil
}

func (r *promotionRepository) IsApplicableForCustomer(ctx context.Context, db DBTX, companyID, promotionID, customerID uuid.UUID) (bool, error) {
	return true, nil
}

func (r *promotionRepository) ValidatePromotion(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) error {
	promo, err := r.GetByID(ctx, db, companyID, promotionID)
	if err != nil {
		return err
	}
	if !promo.IsActive {
		return errors.ErrPromotionInactive
	}
	if at.Before(promo.StartDate) || at.After(promo.EndDate) {
		return errors.ErrPromotionInactive
	}
	return nil
}

// -------------------------------------------------------------------------
// Discount calculation
// -------------------------------------------------------------------------

func (r *promotionRepository) CalculateDiscount(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID, customerID *uuid.UUID, productIDs []uuid.UUID, orderAmount decimal.Decimal, at time.Time) (decimal.Decimal, error) {
	rules, err := r.GetRules(ctx, db, companyID, promotionID)
	if err != nil || len(rules) == 0 {
		return decimal.Zero, err
	}
	rule := rules[0]
	discount := rule.DiscountValue
	if rule.MaxDiscount != nil && discount.GreaterThan(*rule.MaxDiscount) {
		discount = *rule.MaxDiscount
	}
	if rule.DiscountType == enums.DiscountTypePercentage {
		discount = orderAmount.Mul(rule.DiscountValue.Div(decimal.NewFromInt(100)))
	}
	return discount, nil
}

func (r *promotionRepository) GetMaximumDiscount(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID, orderAmount decimal.Decimal) (decimal.Decimal, error) {
	rules, err := r.GetRules(ctx, db, companyID, promotionID)
	if err != nil {
		return decimal.Zero, err
	}
	var maxDiscount decimal.Decimal
	for _, rule := range rules {
		discount := rule.DiscountValue
		if rule.MaxDiscount != nil && discount.GreaterThan(*rule.MaxDiscount) {
			discount = *rule.MaxDiscount
		}
		if rule.DiscountType == enums.DiscountTypePercentage {
			discount = orderAmount.Mul(rule.DiscountValue.Div(decimal.NewFromInt(100)))
		}
		if discount.GreaterThan(maxDiscount) {
			maxDiscount = discount
		}
	}
	return maxDiscount, nil
}

// -------------------------------------------------------------------------
// Listing / search
// -------------------------------------------------------------------------

func (r *promotionRepository) List(ctx context.Context, db DBTX, filter PromotionFilter, p Pagination, s Sort) ([]*discount.Promotion, int64, error) {
	where, args := r.buildPromotionFilter(filter)
	if where == "" {
		return nil, 0, fmt.Errorf("list requires at least company_id filter")
	}
	allowedSort := map[string]bool{
		"name":       true,
		"start_date": true,
		"end_date":   true,
		"is_active":  true,
		"priority":   true,
		"created_at": true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY start_date DESC"
	}
	limit, offset := r.validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sales.promotions %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count promotions: %w", err)
	}
	if total == 0 {
		return []*discount.Promotion{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT promotion_id, company_id, name, description,
		       start_date, end_date, is_active, priority, stacking_type,
		       usage_limit, per_user_limit, deleted_at,
		       created_at, updated_at, created_by, updated_by
		FROM sales.promotions
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list promotions: %w", err)
	}
	defer rows.Close()

	var result []*discount.Promotion
	for rows.Next() {
		p, err := r.scanPromotion(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, p)
	}
	return result, total, rows.Err()
}

func (r *promotionRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, queryStr string, limit, offset int) ([]*discount.Promotion, int64, error) {
	searchPattern := "%" + queryStr + "%"
	baseArgs := []interface{}{companyID, searchPattern, searchPattern}
	countQuery := `
		SELECT COUNT(*)
		FROM sales.promotions
		WHERE company_id = $1
		AND deleted_at IS NULL
		AND (name ILIKE $2 OR description ILIKE $3)
	`
	var total int64
	err := db.QueryRowContext(ctx, countQuery, baseArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search count: %w", err)
	}
	if total == 0 {
		return []*discount.Promotion{}, 0, nil
	}

	dataQuery := `
		SELECT promotion_id, company_id, name, description,
		       start_date, end_date, is_active, priority, stacking_type,
		       usage_limit, per_user_limit, deleted_at,
		       created_at, updated_at, created_by, updated_by
		FROM sales.promotions
		WHERE company_id = $1
		AND deleted_at IS NULL
		AND (name ILIKE $2 OR description ILIKE $3)
		ORDER BY name ASC
		LIMIT $4 OFFSET $5
	`
	args := append(baseArgs, limit, offset)
	rows, err := db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search data: %w", err)
	}
	defer rows.Close()

	var result []*discount.Promotion
	for rows.Next() {
		p, err := r.scanPromotion(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, p)
	}
	return result, total, rows.Err()
}

func (r *promotionRepository) GetActivePromotions(ctx context.Context, db DBTX, companyID uuid.UUID, at time.Time) ([]*discount.Promotion, error) {
	query := `
		SELECT promotion_id, company_id, name, description,
		       start_date, end_date, is_active, priority, stacking_type,
		       usage_limit, per_user_limit, deleted_at,
		       created_at, updated_at, created_by, updated_by
		FROM sales.promotions
		WHERE company_id = $1
		AND deleted_at IS NULL
		AND is_active = true
		AND start_date <= $2
		AND end_date >= $2
		ORDER BY priority DESC, start_date ASC
	`
	rows, err := db.QueryContext(ctx, query, companyID, at)
	if err != nil {
		return nil, fmt.Errorf("get active promotions: %w", err)
	}
	defer rows.Close()
	var result []*discount.Promotion
	for rows.Next() {
		p, err := r.scanPromotion(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

func (r *promotionRepository) GetExpiredPromotions(ctx context.Context, db DBTX, companyID uuid.UUID, at time.Time) ([]*discount.Promotion, error) {
	query := `
		SELECT promotion_id, company_id, name, description,
		       start_date, end_date, is_active, priority, stacking_type,
		       usage_limit, per_user_limit, deleted_at,
		       created_at, updated_at, created_by, updated_by
		FROM sales.promotions
		WHERE company_id = $1
		AND deleted_at IS NULL
		AND end_date < $2
		ORDER BY end_date DESC
	`
	rows, err := db.QueryContext(ctx, query, companyID, at)
	if err != nil {
		return nil, fmt.Errorf("get expired promotions: %w", err)
	}
	defer rows.Close()
	var result []*discount.Promotion
	for rows.Next() {
		p, err := r.scanPromotion(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

func (r *promotionRepository) GetPromotionsStartingSoon(ctx context.Context, db DBTX, companyID uuid.UUID, before time.Time) ([]*discount.Promotion, error) {
	query := `
		SELECT promotion_id, company_id, name, description,
		       start_date, end_date, is_active, priority, stacking_type,
		       usage_limit, per_user_limit, deleted_at,
		       created_at, updated_at, created_by, updated_by
		FROM sales.promotions
		WHERE company_id = $1
		AND deleted_at IS NULL
		AND is_active = true
		AND start_date > NOW()
		AND start_date <= $2
		ORDER BY start_date ASC
	`
	rows, err := db.QueryContext(ctx, query, companyID, before)
	if err != nil {
		return nil, fmt.Errorf("get promotions starting soon: %w", err)
	}
	defer rows.Close()
	var result []*discount.Promotion
	for rows.Next() {
		p, err := r.scanPromotion(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

func (r *promotionRepository) GetPromotionsEndingSoon(ctx context.Context, db DBTX, companyID uuid.UUID, before time.Time) ([]*discount.Promotion, error) {
	query := `
		SELECT promotion_id, company_id, name, description,
		       start_date, end_date, is_active, priority, stacking_type,
		       usage_limit, per_user_limit, deleted_at,
		       created_at, updated_at, created_by, updated_by
		FROM sales.promotions
		WHERE company_id = $1
		AND deleted_at IS NULL
		AND is_active = true
		AND end_date >= NOW()
		AND end_date <= $2
		ORDER BY end_date ASC
	`
	rows, err := db.QueryContext(ctx, query, companyID, before)
	if err != nil {
		return nil, fmt.Errorf("get promotions ending soon: %w", err)
	}
	defer rows.Close()
	var result []*discount.Promotion
	for rows.Next() {
		p, err := r.scanPromotion(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

// -------------------------------------------------------------------------
// Analytics / reporting
// -------------------------------------------------------------------------

func (r *promotionRepository) GetTotalDiscountGiven(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	query := `
		SELECT COALESCE(SUM(amount), 0)
		FROM sales.discount_applications
		WHERE discount_type = 'promotion'
		AND discount_id IN (SELECT promotion_id FROM sales.promotions WHERE company_id = $1 AND deleted_at IS NULL)
	`
	args := []interface{}{companyID}
	if from != nil {
		query += " AND created_at >= $2"
		args = append(args, *from)
	}
	if to != nil {
		pos := len(args) + 1
		query += fmt.Sprintf(" AND created_at <= $%d", pos)
		args = append(args, *to)
	}
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get total discount given: %w", err)
	}
	return total, nil
}

func (r *promotionRepository) GetUnusedPromotions(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*discount.Promotion, error) {
	query := `
		SELECT p.promotion_id, p.company_id, p.name, p.description,
		       p.start_date, p.end_date, p.is_active, p.priority, p.stacking_type,
		       p.usage_limit, p.per_user_limit, p.deleted_at,
		       p.created_at, p.updated_at, p.created_by, p.updated_by
		FROM sales.promotions p
		LEFT JOIN sales.discount_applications da ON p.promotion_id = da.discount_id AND da.discount_type = 'promotion'
		WHERE p.company_id = $1 AND p.deleted_at IS NULL AND da.application_id IS NULL
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("get unused promotions: %w", err)
	}
	defer rows.Close()
	var result []*discount.Promotion
	for rows.Next() {
		p, err := r.scanPromotion(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

// -------------------------------------------------------------------------
// Concurrency / locking
// -------------------------------------------------------------------------

func (r *promotionRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, promotionID uuid.UUID) (*discount.Promotion, error) {
	query := `
		SELECT promotion_id, company_id, name, description,
		       start_date, end_date, is_active, priority, stacking_type,
		       usage_limit, per_user_limit, deleted_at,
		       created_at, updated_at, created_by, updated_by
		FROM sales.promotions
		WHERE company_id = $1 AND promotion_id = $2 AND deleted_at IS NULL
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, companyID, promotionID)
	return r.scanPromotion(row)
}

func (r *promotionRepository) GetRuleByIDForUpdate(ctx context.Context, db DBTX, companyID, promotionID, ruleID uuid.UUID) (*discount.PromotionRule, error) {
	query := `
		SELECT pr.rule_id, pr.promotion_id, pr.rule_type, pr.rule_config,
		       pr.discount_type, pr.discount_value, pr.max_discount, pr.created_at
		FROM sales.promotion_rules pr
		JOIN sales.promotions p ON pr.promotion_id = p.promotion_id
		WHERE p.company_id = $1 AND pr.promotion_id = $2 AND pr.rule_id = $3 AND p.deleted_at IS NULL
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, companyID, promotionID, ruleID)
	return r.scanPromotionRule(row)
}

// FindByIDs retrieves multiple promotions by their IDs, excluding soft-deleted ones.
func (r *promotionRepository) FindByIDs(ctx context.Context, db DBTX, companyID uuid.UUID, ids []uuid.UUID) ([]*discount.Promotion, error) {
	if len(ids) == 0 {
		return []*discount.Promotion{}, nil
	}

	placeholders := make([]string, len(ids))
	args := make([]interface{}, 0, len(ids)+1)
	args = append(args, companyID)
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args = append(args, id)
	}

	query := fmt.Sprintf(`
		SELECT promotion_id, company_id, name, description,
		       start_date, end_date, is_active, priority, stacking_type,
		       usage_limit, per_user_limit, deleted_at,
		       created_at, updated_at, created_by, updated_by
		FROM sales.promotions
		WHERE company_id = $1 AND promotion_id IN (%s) AND deleted_at IS NULL
	`, strings.Join(placeholders, ","))

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("find promotions by ids: %w", err)
	}
	defer rows.Close()

	var promotions []*discount.Promotion
	for rows.Next() {
		p, err := r.scanPromotion(rows)
		if err != nil {
			return nil, err
		}
		promotions = append(promotions, p)
	}
	return promotions, rows.Err()
}

// GetTopPromotionsByUsage returns the top N promotions by usage count (number of times applied),
// optionally filtered by date range.

// PromotionAnalyticsAggregate holds promotion data with usage metrics.
type PromotionAnalyticsAggregate struct {
	Promotion     *discount.Promotion
	UsageCount    int64
	TotalDiscount decimal.Decimal
}

func (r *promotionRepository) GetTopPromotionsByUsage(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*PromotionAnalyticsAggregate, error) {
	query := `
        SELECT discount_id, COUNT(*) as usage_count
        FROM sales.discount_applications
        WHERE company_id = $1
          AND discount_type = 'promotion'
          AND discount_id IS NOT NULL
    `
	args := []interface{}{companyID}
	paramIdx := 2

	if from != nil {
		query += fmt.Sprintf(" AND created_at >= $%d", paramIdx)
		args = append(args, *from)
		paramIdx++
	}
	if to != nil {
		query += fmt.Sprintf(" AND created_at <= $%d", paramIdx)
		args = append(args, *to)
		paramIdx++
	}

	query += fmt.Sprintf(`
        GROUP BY discount_id
        ORDER BY usage_count DESC
        LIMIT $%d
    `, paramIdx)
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get top promotions by usage: %w", err)
	}
	defer rows.Close()

	var ids []uuid.UUID
	usageMap := make(map[uuid.UUID]int64)

	for rows.Next() {
		var id uuid.UUID
		var count int64
		if err := rows.Scan(&id, &count); err != nil {
			return nil, err
		}
		ids = append(ids, id)
		usageMap[id] = count
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(ids) == 0 {
		return []*PromotionAnalyticsAggregate{}, nil
	}

	promotions, err := r.FindByIDs(ctx, db, companyID, ids)
	if err != nil {
		return nil, err
	}

	aggregates := make([]*PromotionAnalyticsAggregate, 0, len(promotions))
	for _, p := range promotions {
		aggregates = append(aggregates, &PromotionAnalyticsAggregate{
			Promotion:  p,
			UsageCount: usageMap[p.PromotionID],
		})
	}

	sort.Slice(aggregates, func(i, j int) bool {
		return aggregates[i].UsageCount > aggregates[j].UsageCount
	})

	return aggregates, nil
}

func (r *promotionRepository) GetTopPromotionsByDiscountAmount(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*PromotionAnalyticsAggregate, error) {
	query := `
        SELECT discount_id, COALESCE(SUM(amount), 0) as total_discount
        FROM sales.discount_applications
        WHERE company_id = $1
          AND discount_type = 'promotion'
          AND discount_id IS NOT NULL
    `
	args := []interface{}{companyID}
	paramIdx := 2

	if from != nil {
		query += fmt.Sprintf(" AND created_at >= $%d", paramIdx)
		args = append(args, *from)
		paramIdx++
	}
	if to != nil {
		query += fmt.Sprintf(" AND created_at <= $%d", paramIdx)
		args = append(args, *to)
		paramIdx++
	}

	query += fmt.Sprintf(`
        GROUP BY discount_id
        ORDER BY total_discount DESC
        LIMIT $%d
    `, paramIdx)
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get top promotions by discount amount: %w", err)
	}
	defer rows.Close()

	var ids []uuid.UUID
	discountMap := make(map[uuid.UUID]decimal.Decimal)

	for rows.Next() {
		var id uuid.UUID
		var total decimal.Decimal
		if err := rows.Scan(&id, &total); err != nil {
			return nil, err
		}
		ids = append(ids, id)
		discountMap[id] = total
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(ids) == 0 {
		return []*PromotionAnalyticsAggregate{}, nil
	}

	promotions, err := r.FindByIDs(ctx, db, companyID, ids)
	if err != nil {
		return nil, err
	}

	aggregates := make([]*PromotionAnalyticsAggregate, 0, len(promotions))
	for _, p := range promotions {
		aggregates = append(aggregates, &PromotionAnalyticsAggregate{
			Promotion:     p,
			TotalDiscount: discountMap[p.PromotionID],
		})
	}

	sort.Slice(aggregates, func(i, j int) bool {
		return aggregates[i].TotalDiscount.GreaterThan(aggregates[j].TotalDiscount)
	})

	return aggregates, nil
}
