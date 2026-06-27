// repository/usage_repository.go
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

	"auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/models"
)

// ---------------------------------------------------------------------
// UsageRepository Interface (as given)
// ---------------------------------------------------------------------

type UsageRepository interface {
	Create(ctx context.Context, db DBTX, usage *models.Usage) error
	Update(ctx context.Context, db DBTX, usage *models.Usage) error
	Delete(ctx context.Context, db DBTX, companyID, usageID uuid.UUID) error // companyID used for auth check via join

	GetByID(ctx context.Context, db DBTX, companyID, usageID uuid.UUID) (*models.Usage, error)
	GetBySubscription(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) ([]*models.Usage, error)
	GetByFeature(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, featureKey string) (*models.Usage, error)

	List(ctx context.Context, db DBTX, filter UsageFilter, p Pagination, s Sort) ([]*models.Usage, int64, error)
	ListExceeded(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Usage, error)
	ListNearLimit(ctx context.Context, db DBTX, companyID uuid.UUID, percentage int) ([]*models.Usage, error)

	IncrementUsage(ctx context.Context, db DBTX, companyID, usageID uuid.UUID, quantity decimal.Decimal) error
	DecrementUsage(ctx context.Context, db DBTX, companyID, usageID uuid.UUID, quantity decimal.Decimal) error
	ResetUsage(ctx context.Context, db DBTX, companyID, usageID uuid.UUID) error
	UpdateLimit(ctx context.Context, db DBTX, companyID, usageID uuid.UUID, limit decimal.Decimal) error

	Exists(ctx context.Context, db DBTX, companyID, usageID uuid.UUID) (bool, error)
	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.Usage, int64, error)

	GetTotalUsage(ctx context.Context, db DBTX, companyID uuid.UUID, featureKey string) (decimal.Decimal, error)
	GetUsagePercentage(ctx context.Context, db DBTX, companyID, usageID uuid.UUID) (decimal.Decimal, error)

	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, usageID uuid.UUID) (*models.Usage, error)
}

type UsageFilter struct {
	CompanyID          uuid.UUID
	UsageIDs           []uuid.UUID
	SubscriptionID     *uuid.UUID
	SubscriptionItemID *uuid.UUID
	FeatureKey         *string
	IsUnlimited        *bool
	IsExceeded         *bool
	UsageFrom          *decimal.Decimal
	UsageTo            *decimal.Decimal
	LimitFrom          *decimal.Decimal
	LimitTo            *decimal.Decimal
	ResetFrom          *time.Time
	ResetTo            *time.Time
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------

type usageRepository struct {
	logger *zap.Logger
}

func NewUsageRepository(logger *zap.Logger) UsageRepository {
	return &usageRepository{
		logger: logger.Named("subscription_usage_repo"),
	}
}

const usageTable = "subscription.usages"

// scanUsage expects columns: usage_id, subscription_item_id, feature_key,
// quantity_used, period_start, period_end, recorded_at, source_type, source_id, created_by
func (r *usageRepository) scanUsage(s scanner) (*models.Usage, error) {
	var u models.Usage
	var sourceType sql.NullString
	var sourceID sql.NullString
	var createdBy sql.NullString

	err := s.Scan(
		&u.UsageID,
		&u.SubscriptionItemID,
		&u.FeatureKey,
		&u.QuantityUsed,
		&u.PeriodStart,
		&u.PeriodEnd,
		&u.RecordedAt,
		&sourceType,
		&sourceID,
		&createdBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan usage: %w", err)
	}
	if sourceType.Valid {
		u.SourceType = &sourceType.String
	}
	if sourceID.Valid {
		if uid, err := uuid.Parse(sourceID.String); err == nil {
			u.SourceID = &uid
		}
	}
	if createdBy.Valid {
		if uid, err := uuid.Parse(createdBy.String); err == nil {
			u.CreatedBy = &uid
		}
	}
	return &u, nil
}

// buildUsageFilter builds WHERE clause and args for UsageFilter.
// CompanyID is handled by joining with subscription_items -> subscriptions.
func (r *usageRepository) buildUsageFilter(filter UsageFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		// handled via join in List method
	}
	if len(filter.UsageIDs) > 0 {
		placeholders := make([]string, len(filter.UsageIDs))
		for i, id := range filter.UsageIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("u.usage_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.SubscriptionItemID != nil {
		conds = append(conds, fmt.Sprintf("u.subscription_item_id = $%d", idx))
		args = append(args, *filter.SubscriptionItemID)
		idx++
	}
	if filter.FeatureKey != nil {
		conds = append(conds, fmt.Sprintf("u.feature_key = $%d", idx))
		args = append(args, *filter.FeatureKey)
		idx++
	}
	if filter.UsageFrom != nil {
		conds = append(conds, fmt.Sprintf("u.quantity_used >= $%d", idx))
		args = append(args, *filter.UsageFrom)
		idx++
	}
	if filter.UsageTo != nil {
		conds = append(conds, fmt.Sprintf("u.quantity_used <= $%d", idx))
		args = append(args, *filter.UsageTo)
		idx++
	}
	if filter.ResetFrom != nil {
		conds = append(conds, fmt.Sprintf("u.period_start >= $%d", idx))
		args = append(args, *filter.ResetFrom)
		idx++
	}
	if filter.ResetTo != nil {
		conds = append(conds, fmt.Sprintf("u.period_start <= $%d", idx))
		args = append(args, *filter.ResetTo)
		idx++
	}
	// Filters that need joins (IsExceeded, IsUnlimited, LimitFrom/To, SubscriptionID) are handled in List method.

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

var usageAllowedSort = map[string]bool{
	"usage_id":      true,
	"feature_key":   true,
	"quantity_used": true,
	"period_start":  true,
	"period_end":    true,
	"recorded_at":   true,
	"source_type":   true,
}

// ---------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------

func (r *usageRepository) Create(ctx context.Context, db DBTX, usage *models.Usage) error {
	query := `
		INSERT INTO subscription.usages (
			usage_id, subscription_item_id, feature_key,
			quantity_used, period_start, period_end, recorded_at,
			source_type, source_id, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	_, err := db.ExecContext(ctx, query,
		usage.UsageID,
		usage.SubscriptionItemID,
		usage.FeatureKey,
		usage.QuantityUsed,
		usage.PeriodStart,
		usage.PeriodEnd,
		usage.RecordedAt,
		nullString(usage.SourceType),
		nullUUID(usage.SourceID),
		nullUUID(usage.CreatedBy),
	)
	if err != nil {
		return fmt.Errorf("create usage: %w", err)
	}
	return nil
}

func (r *usageRepository) Update(ctx context.Context, db DBTX, usage *models.Usage) error {
	query := `
		UPDATE subscription.usages
		SET subscription_item_id = $2,
			feature_key = $3,
			quantity_used = $4,
			period_start = $5,
			period_end = $6,
			recorded_at = $7,
			source_type = $8,
			source_id = $9,
			created_by = $10
		WHERE usage_id = $1
	`
	result, err := db.ExecContext(ctx, query,
		usage.UsageID,
		usage.SubscriptionItemID,
		usage.FeatureKey,
		usage.QuantityUsed,
		usage.PeriodStart,
		usage.PeriodEnd,
		usage.RecordedAt,
		nullString(usage.SourceType),
		nullUUID(usage.SourceID),
		nullUUID(usage.CreatedBy),
	)
	if err != nil {
		return fmt.Errorf("update usage: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *usageRepository) Delete(ctx context.Context, db DBTX, companyID, usageID uuid.UUID) error {
	// Need to verify company via join
	query := `
		DELETE FROM subscription.usages u
		USING subscription.subscription_items si
		WHERE u.subscription_item_id = si.sub_item_id
		AND si.subscription_id IN (SELECT subscription_id FROM subscription.subscriptions WHERE company_id = $1)
		AND u.usage_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, usageID)
	if err != nil {
		return fmt.Errorf("delete usage: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------
// Single Fetch
// ---------------------------------------------------------------------

func (r *usageRepository) GetByID(ctx context.Context, db DBTX, companyID, usageID uuid.UUID) (*models.Usage, error) {
	query := `
		SELECT u.usage_id, u.subscription_item_id, u.feature_key,
			u.quantity_used, u.period_start, u.period_end, u.recorded_at,
			u.source_type, u.source_id, u.created_by
		FROM subscription.usages u
		JOIN subscription.subscription_items si ON u.subscription_item_id = si.sub_item_id
		JOIN subscription.subscriptions s ON si.subscription_id = s.subscription_id
		WHERE u.usage_id = $1 AND s.company_id = $2
	`
	row := db.QueryRowContext(ctx, query, usageID, companyID)
	return r.scanUsage(row)
}

func (r *usageRepository) GetBySubscription(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) ([]*models.Usage, error) {
	query := `
		SELECT u.usage_id, u.subscription_item_id, u.feature_key,
			u.quantity_used, u.period_start, u.period_end, u.recorded_at,
			u.source_type, u.source_id, u.created_by
		FROM subscription.usages u
		JOIN subscription.subscription_items si ON u.subscription_item_id = si.sub_item_id
		JOIN subscription.subscriptions s ON si.subscription_id = s.subscription_id
		WHERE si.subscription_id = $1 AND s.company_id = $2
		ORDER BY u.period_start DESC
	`
	rows, err := db.QueryContext(ctx, query, subscriptionID, companyID)
	if err != nil {
		return nil, fmt.Errorf("get usage by subscription: %w", err)
	}
	defer rows.Close()
	var result []*models.Usage
	for rows.Next() {
		u, err := r.scanUsage(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, u)
	}
	return result, rows.Err()
}

func (r *usageRepository) GetByFeature(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID, featureKey string) (*models.Usage, error) {
	query := `
		SELECT u.usage_id, u.subscription_item_id, u.feature_key,
			u.quantity_used, u.period_start, u.period_end, u.recorded_at,
			u.source_type, u.source_id, u.created_by
		FROM subscription.usages u
		JOIN subscription.subscription_items si ON u.subscription_item_id = si.sub_item_id
		JOIN subscription.subscriptions s ON si.subscription_id = s.subscription_id
		WHERE si.subscription_id = $1 AND u.feature_key = $2 AND s.company_id = $3
		ORDER BY u.period_start DESC
		LIMIT 1
	`
	row := db.QueryRowContext(ctx, query, subscriptionID, featureKey, companyID)
	return r.scanUsage(row)
}

// ---------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------

func (r *usageRepository) List(ctx context.Context, db DBTX, filter UsageFilter, p Pagination, s Sort) ([]*models.Usage, int64, error) {
	// Build the base from with necessary joins for company and advanced filters
	from := "subscription.usages u"
	joins := []string{
		"JOIN subscription.subscription_items si ON u.subscription_item_id = si.sub_item_id",
		"JOIN subscription.subscriptions s ON si.subscription_id = s.subscription_id",
	}
	whereCond := "s.company_id = $1"
	args := []interface{}{filter.CompanyID}
	idx := 2

	if filter.SubscriptionID != nil {
		whereCond += fmt.Sprintf(" AND si.subscription_id = $%d", idx)
		args = append(args, *filter.SubscriptionID)
		idx++
	}
	if filter.SubscriptionItemID != nil {
		whereCond += fmt.Sprintf(" AND u.subscription_item_id = $%d", idx)
		args = append(args, *filter.SubscriptionItemID)
		idx++
	}
	if filter.FeatureKey != nil {
		whereCond += fmt.Sprintf(" AND u.feature_key = $%d", idx)
		args = append(args, *filter.FeatureKey)
		idx++
	}
	if filter.UsageFrom != nil {
		whereCond += fmt.Sprintf(" AND u.quantity_used >= $%d", idx)
		args = append(args, *filter.UsageFrom)
		idx++
	}
	if filter.UsageTo != nil {
		whereCond += fmt.Sprintf(" AND u.quantity_used <= $%d", idx)
		args = append(args, *filter.UsageTo)
		idx++
	}
	if filter.ResetFrom != nil {
		whereCond += fmt.Sprintf(" AND u.period_start >= $%d", idx)
		args = append(args, *filter.ResetFrom)
		idx++
	}
	if filter.ResetTo != nil {
		whereCond += fmt.Sprintf(" AND u.period_start <= $%d", idx)
		args = append(args, *filter.ResetTo)
		idx++
	}
	if len(filter.UsageIDs) > 0 {
		placeholders := make([]string, len(filter.UsageIDs))
		for i, id := range filter.UsageIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		whereCond += fmt.Sprintf(" AND u.usage_id IN (%s)", strings.Join(placeholders, ","))
	}

	// Advanced filters that require entitlements join
	var extraJoins []string
	if filter.IsExceeded != nil || filter.IsUnlimited != nil || filter.LimitFrom != nil || filter.LimitTo != nil {
		extraJoins = append(extraJoins, `
			JOIN subscription.plan_items pi ON si.plan_item_id = pi.plan_item_id
			JOIN subscription.entitlements e ON pi.plan_item_id = e.plan_item_id AND e.feature_key = u.feature_key
		`)
		if filter.IsUnlimited != nil {
			if *filter.IsUnlimited {
				whereCond += " AND e.limit_value IS NULL"
			} else {
				whereCond += " AND e.limit_value IS NOT NULL"
			}
		}
		if filter.IsExceeded != nil && *filter.IsExceeded {
			whereCond += " AND u.quantity_used > COALESCE(e.limit_value, 0)"
		}
		if filter.LimitFrom != nil {
			whereCond += fmt.Sprintf(" AND COALESCE(e.limit_value, 0) >= $%d", idx)
			args = append(args, *filter.LimitFrom)
			idx++
		}
		if filter.LimitTo != nil {
			whereCond += fmt.Sprintf(" AND COALESCE(e.limit_value, 0) <= $%d", idx)
			args = append(args, *filter.LimitTo)
			idx++
		}
	}

	fullFrom := from + " " + strings.Join(joins, " ") + " " + strings.Join(extraJoins, " ")
	whereClause := "WHERE " + whereCond

	orderBy, err := validateSort(s, usageAllowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY u.period_start DESC"
	}
	limit, offset := validatePagination(p)

	// Count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", fullFrom, whereClause)
	var total int64
	if err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count usage: %w", err)
	}
	if total == 0 {
		return []*models.Usage{}, 0, nil
	}

	// Data
	query := fmt.Sprintf(`
		SELECT u.usage_id, u.subscription_item_id, u.feature_key,
			u.quantity_used, u.period_start, u.period_end, u.recorded_at,
			u.source_type, u.source_id, u.created_by
		FROM %s
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, fullFrom, whereClause, orderBy, idx, idx+1)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list usage: %w", err)
	}
	defer rows.Close()

	var result []*models.Usage
	for rows.Next() {
		u, err := r.scanUsage(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, u)
	}
	return result, total, rows.Err()
}

// ListExceeded returns usage records where quantity_used > limit.
func (r *usageRepository) ListExceeded(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Usage, error) {
	query := `
		SELECT u.usage_id, u.subscription_item_id, u.feature_key,
			u.quantity_used, u.period_start, u.period_end, u.recorded_at,
			u.source_type, u.source_id, u.created_by
		FROM subscription.usages u
		JOIN subscription.subscription_items si ON u.subscription_item_id = si.sub_item_id
		JOIN subscription.subscriptions s ON si.subscription_id = s.subscription_id
		JOIN subscription.plan_items pi ON si.plan_item_id = pi.plan_item_id
		JOIN subscription.entitlements e ON pi.plan_item_id = e.plan_item_id AND e.feature_key = u.feature_key
		WHERE s.company_id = $1
		AND e.limit_value IS NOT NULL
		AND u.quantity_used > e.limit_value
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("list exceeded usage: %w", err)
	}
	defer rows.Close()
	var result []*models.Usage
	for rows.Next() {
		u, err := r.scanUsage(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, u)
	}
	return result, rows.Err()
}

// ListNearLimit returns usage records where usage is within percentage% of limit.
func (r *usageRepository) ListNearLimit(ctx context.Context, db DBTX, companyID uuid.UUID, percentage int) ([]*models.Usage, error) {
	if percentage < 0 || percentage > 100 {
		return nil, fmt.Errorf("percentage must be between 0 and 100")
	}
	query := `
		SELECT u.usage_id, u.subscription_item_id, u.feature_key,
			u.quantity_used, u.period_start, u.period_end, u.recorded_at,
			u.source_type, u.source_id, u.created_by
		FROM subscription.usages u
		JOIN subscription.subscription_items si ON u.subscription_item_id = si.sub_item_id
		JOIN subscription.subscriptions s ON si.subscription_id = s.subscription_id
		JOIN subscription.plan_items pi ON si.plan_item_id = pi.plan_item_id
		JOIN subscription.entitlements e ON pi.plan_item_id = e.plan_item_id AND e.feature_key = u.feature_key
		WHERE s.company_id = $1
		AND e.limit_value IS NOT NULL
		AND e.limit_value > 0
		AND u.quantity_used >= (e.limit_value * ($2::numeric / 100))
	`
	rows, err := db.QueryContext(ctx, query, companyID, percentage)
	if err != nil {
		return nil, fmt.Errorf("list near limit usage: %w", err)
	}
	defer rows.Close()
	var result []*models.Usage
	for rows.Next() {
		u, err := r.scanUsage(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, u)
	}
	return result, rows.Err()
}

// ---------------------------------------------------------------------
// Usage Operations
// ---------------------------------------------------------------------

func (r *usageRepository) IncrementUsage(ctx context.Context, db DBTX, companyID, usageID uuid.UUID, quantity decimal.Decimal) error {
	query := `
		UPDATE subscription.usages u
		SET quantity_used = quantity_used + $3
		FROM subscription.subscription_items si
		JOIN subscription.subscriptions s ON si.subscription_id = s.subscription_id
		WHERE u.subscription_item_id = si.sub_item_id
		AND s.company_id = $1
		AND u.usage_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, usageID, quantity)
	if err != nil {
		return fmt.Errorf("increment usage: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *usageRepository) DecrementUsage(ctx context.Context, db DBTX, companyID, usageID uuid.UUID, quantity decimal.Decimal) error {
	query := `
		UPDATE subscription.usages u
		SET quantity_used = GREATEST(quantity_used - $3, 0)
		FROM subscription.subscription_items si
		JOIN subscription.subscriptions s ON si.subscription_id = s.subscription_id
		WHERE u.subscription_item_id = si.sub_item_id
		AND s.company_id = $1
		AND u.usage_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, usageID, quantity)
	if err != nil {
		return fmt.Errorf("decrement usage: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *usageRepository) ResetUsage(ctx context.Context, db DBTX, companyID, usageID uuid.UUID) error {
	query := `
		UPDATE subscription.usages u
		SET quantity_used = 0
		FROM subscription.subscription_items si
		JOIN subscription.subscriptions s ON si.subscription_id = s.subscription_id
		WHERE u.subscription_item_id = si.sub_item_id
		AND s.company_id = $1
		AND u.usage_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, usageID)
	if err != nil {
		return fmt.Errorf("reset usage: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *usageRepository) UpdateLimit(ctx context.Context, db DBTX, companyID, usageID uuid.UUID, limit decimal.Decimal) error {
	// Limit is stored in entitlements, not usages.
	// This is not directly supported; we'll return an error.
	return fmt.Errorf("UpdateLimit not implemented for UsageRepository; update entitlement directly")
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

func (r *usageRepository) Exists(ctx context.Context, db DBTX, companyID, usageID uuid.UUID) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(
			SELECT 1 FROM subscription.usages u
			JOIN subscription.subscription_items si ON u.subscription_item_id = si.sub_item_id
			JOIN subscription.subscriptions s ON si.subscription_id = s.subscription_id
			WHERE u.usage_id = $1 AND s.company_id = $2
		)
	`
	err := db.QueryRowContext(ctx, query, usageID, companyID).Scan(&exists)
	return exists, err
}

// ---------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------

func (r *usageRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.Usage, int64, error) {
	pattern := "%" + query + "%"
	where := `
		JOIN subscription.subscription_items si ON u.subscription_item_id = si.sub_item_id
		JOIN subscription.subscriptions s ON si.subscription_id = s.subscription_id
		WHERE s.company_id = $1
		AND (u.feature_key ILIKE $2 OR u.source_type ILIKE $2)
	`
	args := []interface{}{companyID, pattern}
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM subscription.usages u %s", where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search usage count: %w", err)
	}
	if total == 0 {
		return []*models.Usage{}, 0, nil
	}
	baseQuery := `
		SELECT u.usage_id, u.subscription_item_id, u.feature_key,
			u.quantity_used, u.period_start, u.period_end, u.recorded_at,
			u.source_type, u.source_id, u.created_by
		FROM subscription.usages u
	`
	querySQL := fmt.Sprintf(`%s %s ORDER BY u.period_start DESC LIMIT $%d OFFSET $%d`, baseQuery, where, len(args)+1, len(args)+2)
	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search usage: %w", err)
	}
	defer rows.Close()
	var result []*models.Usage
	for rows.Next() {
		u, err := r.scanUsage(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, u)
	}
	return result, total, rows.Err()
}

// ---------------------------------------------------------------------
// Analytics
// ---------------------------------------------------------------------

func (r *usageRepository) GetTotalUsage(ctx context.Context, db DBTX, companyID uuid.UUID, featureKey string) (decimal.Decimal, error) {
	var total decimal.Decimal
	query := `
		SELECT COALESCE(SUM(u.quantity_used), 0)
		FROM subscription.usages u
		JOIN subscription.subscription_items si ON u.subscription_item_id = si.sub_item_id
		JOIN subscription.subscriptions s ON si.subscription_id = s.subscription_id
		WHERE s.company_id = $1 AND u.feature_key = $2
	`
	err := db.QueryRowContext(ctx, query, companyID, featureKey).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get total usage: %w", err)
	}
	return total, nil
}

func (r *usageRepository) GetUsagePercentage(ctx context.Context, db DBTX, companyID, usageID uuid.UUID) (decimal.Decimal, error) {
	query := `
		SELECT
			CASE
				WHEN e.limit_value IS NULL OR e.limit_value = 0 THEN 0
				ELSE (u.quantity_used / e.limit_value) * 100
			END
		FROM subscription.usages u
		JOIN subscription.subscription_items si ON u.subscription_item_id = si.sub_item_id
		JOIN subscription.subscriptions s ON si.subscription_id = s.subscription_id
		JOIN subscription.plan_items pi ON si.plan_item_id = pi.plan_item_id
		JOIN subscription.entitlements e ON pi.plan_item_id = e.plan_item_id AND e.feature_key = u.feature_key
		WHERE u.usage_id = $1 AND s.company_id = $2
	`
	var percentage decimal.Decimal
	err := db.QueryRowContext(ctx, query, usageID, companyID).Scan(&percentage)
	if err != nil {
		if err == sql.ErrNoRows {
			return decimal.Zero, errors.ErrNotFound
		}
		return decimal.Zero, fmt.Errorf("get usage percentage: %w", err)
	}
	return percentage, nil
}

// ---------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------

func (r *usageRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, usageID uuid.UUID) (*models.Usage, error) {
	query := `
		SELECT u.usage_id, u.subscription_item_id, u.feature_key,
			u.quantity_used, u.period_start, u.period_end, u.recorded_at,
			u.source_type, u.source_id, u.created_by
		FROM subscription.usages u
		JOIN subscription.subscription_items si ON u.subscription_item_id = si.sub_item_id
		JOIN subscription.subscriptions s ON si.subscription_id = s.subscription_id
		WHERE u.usage_id = $1 AND s.company_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, usageID, companyID)
	return r.scanUsage(row)
}
