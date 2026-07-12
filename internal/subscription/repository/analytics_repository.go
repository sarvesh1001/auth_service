// FILE: repository/analytics_repository.go

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

	"auth-service/internal/subscription/models"
	"auth-service/internal/subscription/models/enums"
)

// -------------------------------------------------------------------------
// AnalyticsRepository Interface
// -------------------------------------------------------------------------

type AnalyticsRepository interface {
	// -------------------------------------------------------------------------
	// Subscription KPIs
	// -------------------------------------------------------------------------
	InsertPausePolicyUsageFact(ctx context.Context, tx *sql.Tx, fact *models.PausePolicyUsageFact) error
	IncrementDailyPausePolicyMetrics(ctx context.Context, tx *sql.Tx, companyID, pausePolicyID uuid.UUID, date time.Time, delta *models.DailyPausePolicyMetricsDelta) error
	GetPausePolicyMetrics(ctx context.Context, db DBTX, filter AnalyticsFilter, pausePolicyID uuid.UUID) (*models.PausePolicyAnalyticsMetric, error)
	InsertPlanChangeFact(ctx context.Context, tx *sql.Tx, fact *models.PlanChangeFact) error
	IncrementDailyPlanChangeMetrics(ctx context.Context, tx *sql.Tx, companyID, planID uuid.UUID, date time.Time, delta *models.PlanChangeDelta) error
	GetPlanChangeMetrics(ctx context.Context, db DBTX, filter AnalyticsFilter, planID uuid.UUID) (*models.PlanChangeMetricsSummary, error)
	GetPlanChangeTrend(ctx context.Context, db DBTX, filter AnalyticsFilter, planID uuid.UUID, groupBy AnalyticsGroupBy) ([]*models.PlanChangeTrendMetric, error)

	GetSubscriptionMetrics(
		ctx context.Context,
		db DBTX,
		filter AnalyticsFilter,
	) (*models.SubscriptionMetrics, error)

	GetSubscriptionStatusBreakdown(
		ctx context.Context,
		db DBTX,
		filter AnalyticsFilter,
	) ([]*models.SubscriptionStatusMetric, error)

	GetSubscriptionGrowth(
		ctx context.Context,
		db DBTX,
		filter AnalyticsFilter,
		groupBy AnalyticsGroupBy,
	) ([]*models.SubscriptionGrowthMetric, error)
	InsertEntitlementUsageFact(ctx context.Context, tx *sql.Tx, fact *models.EntitlementUsageFact) error
	IncrementDailyEntitlementMetrics(ctx context.Context, tx *sql.Tx, companyID uuid.UUID, featureKey string, date time.Time, delta *models.DailyEntitlementMetricsDelta) error
	GetEntitlementMetrics(ctx context.Context, db DBTX, filter AnalyticsFilter, featureKey string) (*models.EntitlementAnalyticsMetric, error)

	// -------------------------------------------------------------------------
	// Revenue
	// -------------------------------------------------------------------------
	// Renewal Policy Analytics
	InsertRenewalPolicyUsageFact(ctx context.Context, tx *sql.Tx, fact *models.RenewalPolicyUsageFact) error
	IncrementDailyRenewalPolicyMetrics(ctx context.Context, tx *sql.Tx, companyID, renewalPolicyID uuid.UUID, date time.Time, delta *models.DailyRenewalPolicyMetricsDelta) error
	GetRenewalPolicyMetrics(ctx context.Context, db DBTX, filter AnalyticsFilter, renewalPolicyID uuid.UUID) (*models.RenewalPolicyAnalyticsMetric, error)

	GetRevenueMetrics(
		ctx context.Context,
		db DBTX,
		filter AnalyticsFilter,
	) (*models.RevenueMetrics, error)

	GetRevenueTrend(
		ctx context.Context,
		db DBTX,
		filter AnalyticsFilter,
		groupBy AnalyticsGroupBy,
	) ([]*models.RevenueTrendMetric, error)

	GetMRR(
		ctx context.Context,
		db DBTX,
		filter AnalyticsFilter,
	) (decimal.Decimal, error)

	GetARR(
		ctx context.Context,
		db DBTX,
		filter AnalyticsFilter,
	) (decimal.Decimal, error)

	GetAverageRevenuePerCustomer(
		ctx context.Context,
		db DBTX,
		filter AnalyticsFilter,
	) (decimal.Decimal, error)

	// -------------------------------------------------------------------------
	// Churn / Retention
	// -------------------------------------------------------------------------

	GetChurnMetrics(
		ctx context.Context,
		db DBTX,
		filter AnalyticsFilter,
	) (*models.ChurnMetrics, error)

	GetRetentionMetrics(
		ctx context.Context,
		db DBTX,
		filter AnalyticsFilter,
	) (*models.RetentionMetrics, error)

	// -------------------------------------------------------------------------
	// Trials
	// -------------------------------------------------------------------------

	GetTrialMetrics(
		ctx context.Context,
		db DBTX,
		filter AnalyticsFilter,
	) (*models.TrialMetrics, error)

	GetTrialConversionRate(
		ctx context.Context,
		db DBTX,
		filter AnalyticsFilter,
	) (decimal.Decimal, error)

	// -------------------------------------------------------------------------
	// Renewals
	// -------------------------------------------------------------------------

	GetRenewalMetrics(
		ctx context.Context,
		db DBTX,
		filter AnalyticsFilter,
	) (*models.RenewalMetrics, error)

	GetUpcomingRenewals(
		ctx context.Context,
		db DBTX,
		filter AnalyticsFilter,
		before time.Time,
	) ([]*models.SubscriptionRenewalMetric, error)

	// -------------------------------------------------------------------------
	// Usage
	// -------------------------------------------------------------------------

	GetUsageMetrics(
		ctx context.Context,
		db DBTX,
		filter AnalyticsFilter,
	) (*models.UsageMetrics, error)

	GetTopFeatures(
		ctx context.Context,
		db DBTX,
		filter AnalyticsFilter,
		limit int,
	) ([]*models.FeatureUsageMetric, error)
	InsertBenefitUsageFact(ctx context.Context, tx *sql.Tx, fact *models.BenefitUsageFact) error
	IncrementDailyBenefitMetrics(ctx context.Context, tx *sql.Tx, companyID, benefitID uuid.UUID, date time.Time, delta *models.DailyBenefitMetricsDelta) error
	GetBenefitMetrics(ctx context.Context, db DBTX, filter AnalyticsFilter, benefitID uuid.UUID) (*models.BenefitAnalyticsMetric, error)
	GetTopPlans(
		ctx context.Context,
		db DBTX,
		filter AnalyticsFilter,
		limit int,
	) ([]*models.PlanAnalyticsMetric, error)

	GetTopAddons(
		ctx context.Context,
		db DBTX,
		filter AnalyticsFilter,
		limit int,
	) ([]*models.AddonAnalyticsMetric, error)

	// -------------------------------------------------------------------------
	// Customer
	// -------------------------------------------------------------------------
	InsertBillingPolicyUsageFact(ctx context.Context, tx *sql.Tx, fact *models.BillingPolicyUsageFact) error
	IncrementDailyBillingPolicyMetrics(ctx context.Context, tx *sql.Tx, companyID, billingPolicyID uuid.UUID, date time.Time, delta *models.DailyBillingPolicyMetricsDelta) error
	GetBillingPolicyMetrics(ctx context.Context, db DBTX, filter AnalyticsFilter, billingPolicyID uuid.UUID) (*models.BillingPolicyAnalyticsMetric, error)

	GetTopCustomers(
		ctx context.Context,
		db DBTX,
		filter AnalyticsFilter,
		limit int,
	) ([]*models.CustomerAnalyticsMetric, error)

	GetCustomerLifetimeValue(
		ctx context.Context,
		db DBTX,
		filter AnalyticsFilter,
		customerID uuid.UUID,
	) (decimal.Decimal, error)

	// -------------------------------------------------------------------------
	// Dashboard
	// -------------------------------------------------------------------------

	GetDashboard(
		ctx context.Context,
		db DBTX,
		filter AnalyticsFilter,
	) (*models.SubscriptionDashboard, error)

	// -------------------------------------------------------------------------
	// Write methods for analytics ingestion (event-driven)
	// -------------------------------------------------------------------------

	InsertSubscriptionFact(ctx context.Context, tx *sql.Tx, fact *models.SubscriptionFact) error
	IncrementDailySubscriptionMetrics(ctx context.Context, tx *sql.Tx, companyID uuid.UUID, date time.Time, delta *DailySubscriptionMetricsDelta) error
	IncrementDailyPlanMetrics(ctx context.Context, tx *sql.Tx, companyID, planID uuid.UUID, date time.Time, delta *DailyPlanMetricsDelta) error
	// -------------------------------------------------------------------------
	// Addon Analytics (new)
	// -------------------------------------------------------------------------

	InsertAddonUsageFact(ctx context.Context, tx *sql.Tx, fact *models.AddonUsageFact) error
	IncrementDailyAddonMetrics(ctx context.Context, tx *sql.Tx, companyID, addonID uuid.UUID, date time.Time, delta *models.DailyAddonMetricsDelta) error

	// Optional query for a single addon's aggregated metrics
	GetAddonMetrics(ctx context.Context, db DBTX, filter AnalyticsFilter, addonID uuid.UUID) (*models.AddonAnalyticsMetric, error)
}

// -------------------------------------------------------------------------
// Types
// -------------------------------------------------------------------------

type AnalyticsFilter struct {
	CompanyID      uuid.UUID
	PlanID         *uuid.UUID
	CustomerID     *uuid.UUID
	SubscriptionID *uuid.UUID
	StartDate      *time.Time
	EndDate        *time.Time
	IncludeDeleted bool
}

type AnalyticsGroupBy string

const (
	AnalyticsGroupByDay   AnalyticsGroupBy = "day"
	AnalyticsGroupByWeek  AnalyticsGroupBy = "week"
	AnalyticsGroupByMonth AnalyticsGroupBy = "month"
	AnalyticsGroupByYear  AnalyticsGroupBy = "year"
)

// DailySubscriptionMetricsDelta represents incremental changes to daily subscription metrics.
type DailySubscriptionMetricsDelta struct {
	NewSubscriptions       int
	ActiveSubscriptions    int
	CancelledSubscriptions int
	ExpiredSubscriptions   int
	PausedSubscriptions    int
	TrialStarts            int
	TrialConversions       int
	TrialExpirations       int
	MRR                    decimal.Decimal
	ARR                    decimal.Decimal
}

// DailyPlanMetricsDelta represents incremental changes to daily plan metrics.
type DailyPlanMetricsDelta struct {
	ActiveCount int
	NewCount    int
	MRR         decimal.Decimal
	ARR         decimal.Decimal
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type analyticsRepository struct {
	logger *zap.Logger
}

func NewAnalyticsRepository(logger *zap.Logger) AnalyticsRepository {
	return &analyticsRepository{
		logger: logger.Named("subscription_analytics_repo"),
	}
}

// -------------------------------------------------------------------------
// Helper: build date filter and base conditions
// -------------------------------------------------------------------------

func (r *analyticsRepository) buildConditions(filter AnalyticsFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	argIdx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", argIdx))
		args = append(args, filter.CompanyID)
		argIdx++
	}

	if filter.PlanID != nil {
		conds = append(conds, fmt.Sprintf("plan_id = $%d", argIdx))
		args = append(args, *filter.PlanID)
		argIdx++
	}

	if filter.CustomerID != nil {
		conds = append(conds, fmt.Sprintf("customer_id = $%d", argIdx))
		args = append(args, *filter.CustomerID)
		argIdx++
	}

	if filter.SubscriptionID != nil {
		conds = append(conds, fmt.Sprintf("subscription_id = $%d", argIdx))
		args = append(args, *filter.SubscriptionID)
		argIdx++
	}

	if !filter.IncludeDeleted {
		conds = append(conds, "deleted_at IS NULL")
	}

	return strings.Join(conds, " AND "), args
}

func getDateRangeSQL(column string, from, to *time.Time) (string, int) {
	var parts []string
	count := 0
	if from != nil {
		parts = append(parts, fmt.Sprintf("%s >= $%d", column, count+1))
		count++
	}
	if to != nil {
		parts = append(parts, fmt.Sprintf("%s <= $%d", column, count+1))
		count++
	}
	if len(parts) == 0 {
		return "", 0
	}
	return " AND " + strings.Join(parts, " AND "), count
}

// -------------------------------------------------------------------------
// Subscription KPIs
// -------------------------------------------------------------------------

func (r *analyticsRepository) GetSubscriptionMetrics(
	ctx context.Context,
	db DBTX,
	filter AnalyticsFilter,
) (*models.SubscriptionMetrics, error) {
	where, baseArgs := r.buildConditions(filter)
	if where != "" {
		where = "WHERE " + where
	}

	query := fmt.Sprintf(`
		SELECT
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE status = '%s') AS active,
			COUNT(*) FILTER (WHERE status = '%s') AS paused,
			COUNT(*) FILTER (WHERE status = '%s') AS expired,
			COUNT(*) FILTER (WHERE status = '%s') AS cancelled,
			COUNT(*) FILTER (WHERE status = '%s') AS trial,
			COUNT(*) FILTER (WHERE status = '%s') AS pending
		FROM subscription.subscriptions
		%s
	`, enums.SubStatusActive, enums.SubStatusPaused, enums.SubStatusExpired,
		enums.SubStatusCancelled, enums.SubStatusTrial, enums.SubStatusPending,
		where)

	var metrics models.SubscriptionMetrics
	err := db.QueryRowContext(ctx, query, baseArgs...).Scan(
		&metrics.Total,
		&metrics.Active,
		&metrics.Paused,
		&metrics.Expired,
		&metrics.Cancelled,
		&metrics.Trial,
		&metrics.Pending,
	)
	if err != nil {
		r.logger.Error("failed to get subscription metrics", zap.Error(err))
		return nil, fmt.Errorf("get subscription metrics: %w", err)
	}
	return &metrics, nil
}

func (r *analyticsRepository) GetSubscriptionStatusBreakdown(
	ctx context.Context,
	db DBTX,
	filter AnalyticsFilter,
) ([]*models.SubscriptionStatusMetric, error) {
	where, args := r.buildConditions(filter)
	if where != "" {
		where = "WHERE " + where
	}
	query := fmt.Sprintf(`
		SELECT status, COUNT(*) AS count
		FROM subscription.subscriptions
		%s
		GROUP BY status
		ORDER BY count DESC
	`, where)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get status breakdown: %w", err)
	}
	defer rows.Close()

	var results []*models.SubscriptionStatusMetric
	for rows.Next() {
		var status string
		var count int64
		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("scan status breakdown: %w", err)
		}
		results = append(results, &models.SubscriptionStatusMetric{
			Status: enums.SubscriptionStatus(status),
			Count:  count,
		})
	}
	return results, rows.Err()
}

func (r *analyticsRepository) GetSubscriptionGrowth(
	ctx context.Context,
	db DBTX,
	filter AnalyticsFilter,
	groupBy AnalyticsGroupBy,
) ([]*models.SubscriptionGrowthMetric, error) {
	where, args := r.buildConditions(filter)
	if where != "" {
		where = "WHERE " + where
	}
	dateSQL, dateCount := getDateRangeSQL("created_at", filter.StartDate, filter.EndDate)
	if dateCount > 0 {
		if filter.StartDate != nil {
			args = append(args, *filter.StartDate)
		}
		if filter.EndDate != nil {
			args = append(args, *filter.EndDate)
		}
		where += dateSQL
	}

	var trunc string
	switch groupBy {
	case AnalyticsGroupByDay:
		trunc = "DATE(created_at)"
	case AnalyticsGroupByWeek:
		trunc = "DATE_TRUNC('week', created_at)"
	case AnalyticsGroupByMonth:
		trunc = "DATE_TRUNC('month', created_at)"
	case AnalyticsGroupByYear:
		trunc = "DATE_TRUNC('year', created_at)"
	default:
		trunc = "DATE(created_at)"
	}

	query := fmt.Sprintf(`
		SELECT
			%s AS period,
			COUNT(*) AS new_subscriptions,
			COUNT(*) FILTER (WHERE status = '%s') AS active_at_period
		FROM subscription.subscriptions
		%s
		GROUP BY period
		ORDER BY period
	`, trunc, enums.SubStatusActive, where)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get subscription growth: %w", err)
	}
	defer rows.Close()

	var results []*models.SubscriptionGrowthMetric
	for rows.Next() {
		var period time.Time
		var newSubs int64
		var activeAtPeriod int64
		if err := rows.Scan(&period, &newSubs, &activeAtPeriod); err != nil {
			return nil, fmt.Errorf("scan growth metric: %w", err)
		}
		results = append(results, &models.SubscriptionGrowthMetric{
			Period:           period,
			NewSubscriptions: newSubs,
			ActiveAtPeriod:   activeAtPeriod,
		})
	}
	return results, rows.Err()
}

// -------------------------------------------------------------------------
// Revenue
// -------------------------------------------------------------------------

func (r *analyticsRepository) GetRevenueMetrics(
	ctx context.Context,
	db DBTX,
	filter AnalyticsFilter,
) (*models.RevenueMetrics, error) {
	where, args := r.buildConditions(filter)
	statusFilter := fmt.Sprintf("s.status IN ('%s', '%s', '%s')", enums.SubStatusActive, enums.SubStatusTrial, enums.SubStatusPaused)
	if where != "" {
		where = where + " AND " + statusFilter
	} else {
		where = "WHERE " + statusFilter
	}

	dateSQL, dateCount := getDateRangeSQL("s.created_at", filter.StartDate, filter.EndDate)
	if dateCount > 0 {
		if filter.StartDate != nil {
			args = append(args, *filter.StartDate)
		}
		if filter.EndDate != nil {
			args = append(args, *filter.EndDate)
		}
		where += dateSQL
	}

	query := fmt.Sprintf(`
		SELECT
			COALESCE(SUM(si.total_price), 0) AS total_revenue,
			COUNT(DISTINCT s.subscription_id) AS active_subscriptions,
			COUNT(DISTINCT s.customer_id) AS active_customers,
			COALESCE(AVG(si.total_price), 0) AS avg_revenue_per_subscription,
			COALESCE(AVG(si.quantity), 0) AS avg_quantity
		FROM subscription.subscriptions s
		INNER JOIN subscription.subscription_items si ON s.subscription_id = si.subscription_id
		%s
	`, where)

	var metrics models.RevenueMetrics
	err := db.QueryRowContext(ctx, query, args...).Scan(
		&metrics.TotalRevenue,
		&metrics.ActiveSubscriptions,
		&metrics.ActiveCustomers,
		&metrics.AverageRevenuePerSubscription,
		&metrics.AverageQuantity,
	)
	if err != nil {
		r.logger.Error("failed to get revenue metrics", zap.Error(err))
		return nil, fmt.Errorf("get revenue metrics: %w", err)
	}
	return &metrics, nil
}

func (r *analyticsRepository) GetRevenueTrend(
	ctx context.Context,
	db DBTX,
	filter AnalyticsFilter,
	groupBy AnalyticsGroupBy,
) ([]*models.RevenueTrendMetric, error) {
	where, args := r.buildConditions(filter)
	statusFilter := fmt.Sprintf("s.status IN ('%s', '%s')", enums.SubStatusActive, enums.SubStatusTrial)
	if where != "" {
		where = where + " AND " + statusFilter
	} else {
		where = "WHERE " + statusFilter
	}

	dateSQL, dateCount := getDateRangeSQL("s.created_at", filter.StartDate, filter.EndDate)
	if dateCount > 0 {
		if filter.StartDate != nil {
			args = append(args, *filter.StartDate)
		}
		if filter.EndDate != nil {
			args = append(args, *filter.EndDate)
		}
		where += dateSQL
	}

	var trunc string
	switch groupBy {
	case AnalyticsGroupByDay:
		trunc = "DATE(s.created_at)"
	case AnalyticsGroupByWeek:
		trunc = "DATE_TRUNC('week', s.created_at)"
	case AnalyticsGroupByMonth:
		trunc = "DATE_TRUNC('month', s.created_at)"
	case AnalyticsGroupByYear:
		trunc = "DATE_TRUNC('year', s.created_at)"
	default:
		trunc = "DATE(s.created_at)"
	}

	query := fmt.Sprintf(`
		SELECT
			%s AS period,
			COALESCE(SUM(si.total_price), 0) AS revenue,
			COUNT(DISTINCT s.subscription_id) AS subscription_count
		FROM subscription.subscriptions s
		INNER JOIN subscription.subscription_items si ON s.subscription_id = si.subscription_id
		%s
		GROUP BY period
		ORDER BY period
	`, trunc, where)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get revenue trend: %w", err)
	}
	defer rows.Close()

	var results []*models.RevenueTrendMetric
	for rows.Next() {
		var period time.Time
		var revenue decimal.Decimal
		var count int64
		if err := rows.Scan(&period, &revenue, &count); err != nil {
			return nil, fmt.Errorf("scan revenue trend: %w", err)
		}
		results = append(results, &models.RevenueTrendMetric{
			Period:            period,
			Revenue:           revenue,
			SubscriptionCount: count,
		})
	}
	return results, rows.Err()
}

func (r *analyticsRepository) GetMRR(
	ctx context.Context,
	db DBTX,
	filter AnalyticsFilter,
) (decimal.Decimal, error) {
	where, args := r.buildConditions(filter)
	statusFilter := fmt.Sprintf("status = '%s'", enums.SubStatusActive)
	if where != "" {
		where = where + " AND " + statusFilter
	} else {
		where = "WHERE " + statusFilter
	}

	query := fmt.Sprintf(`
		SELECT COALESCE(SUM(si.total_price), 0)
		FROM subscription.subscriptions s
		INNER JOIN subscription.subscription_items si ON s.subscription_id = si.subscription_id
		%s
	`, where)

	var mrr decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&mrr)
	if err != nil {
		r.logger.Error("failed to get MRR", zap.Error(err))
		return decimal.Zero, fmt.Errorf("get MRR: %w", err)
	}
	return mrr, nil
}

func (r *analyticsRepository) GetARR(
	ctx context.Context,
	db DBTX,
	filter AnalyticsFilter,
) (decimal.Decimal, error) {
	mrr, err := r.GetMRR(ctx, db, filter)
	if err != nil {
		return decimal.Zero, err
	}
	return mrr.Mul(decimal.NewFromInt(12)), nil
}

func (r *analyticsRepository) GetAverageRevenuePerCustomer(
	ctx context.Context,
	db DBTX,
	filter AnalyticsFilter,
) (decimal.Decimal, error) {
	where, args := r.buildConditions(filter)
	statusFilter := fmt.Sprintf("s.status IN ('%s', '%s')", enums.SubStatusActive, enums.SubStatusTrial)
	if where != "" {
		where = where + " AND " + statusFilter
	} else {
		where = "WHERE " + statusFilter
	}
	query := fmt.Sprintf(`
		SELECT
			COALESCE(SUM(si.total_price) / NULLIF(COUNT(DISTINCT s.customer_id), 0), 0)
		FROM subscription.subscriptions s
		INNER JOIN subscription.subscription_items si ON s.subscription_id = si.subscription_id
		%s
	`, where)

	var avg decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&avg)
	if err != nil {
		r.logger.Error("failed to get avg revenue per customer", zap.Error(err))
		return decimal.Zero, fmt.Errorf("get average revenue per customer: %w", err)
	}
	return avg, nil
}

// -------------------------------------------------------------------------
// Churn / Retention
// -------------------------------------------------------------------------

func (r *analyticsRepository) GetChurnMetrics(
	ctx context.Context,
	db DBTX,
	filter AnalyticsFilter,
) (*models.ChurnMetrics, error) {
	where, args := r.buildConditions(filter)
	start := filter.StartDate
	end := filter.EndDate
	if start == nil {
		t := time.Now().AddDate(0, -1, 0)
		start = &t
	}
	if end == nil {
		t := time.Now()
		end = &t
	}
	dateSQL, dateCount := getDateRangeSQL("cancelled_at", start, end)
	if dateCount > 0 {
		if start != nil {
			args = append(args, *start)
		}
		if end != nil {
			args = append(args, *end)
		}
		where += dateSQL
	}
	statusFilter := fmt.Sprintf("status IN ('%s', '%s')", enums.SubStatusCancelled, enums.SubStatusExpired)
	if where != "" {
		where = where + " AND " + statusFilter
	} else {
		where = "WHERE " + statusFilter
	}

	query := fmt.Sprintf(`
		SELECT
			COUNT(*) AS churned_subscriptions,
			COUNT(DISTINCT customer_id) AS churned_customers,
			COALESCE(SUM(si.total_price), 0) AS lost_revenue
		FROM subscription.subscriptions s
		LEFT JOIN subscription.subscription_items si ON s.subscription_id = si.subscription_id
		%s
	`, where)

	var metrics models.ChurnMetrics
	err := db.QueryRowContext(ctx, query, args...).Scan(
		&metrics.ChurnedSubscriptions,
		&metrics.ChurnedCustomers,
		&metrics.LostRevenue,
	)
	if err != nil {
		r.logger.Error("failed to get churn metrics", zap.Error(err))
		return nil, fmt.Errorf("get churn metrics: %w", err)
	}

	startActive, err := r.getActiveCountAt(ctx, db, filter.CompanyID, *start)
	if err != nil {
		r.logger.Warn("failed to get active count at start", zap.Error(err))
		metrics.ChurnRate = decimal.Zero
	} else if startActive > 0 {
		metrics.ChurnRate = decimal.NewFromInt(metrics.ChurnedSubscriptions).Div(decimal.NewFromInt(startActive)).Mul(decimal.NewFromInt(100))
	}
	return &metrics, nil
}

func (r *analyticsRepository) GetRetentionMetrics(
	ctx context.Context,
	db DBTX,
	filter AnalyticsFilter,
) (*models.RetentionMetrics, error) {
	query := `
		SELECT COUNT(*) FROM subscription.subscriptions
		WHERE company_id = $1 AND status = $2 AND created_at < NOW() - INTERVAL '30 days' AND deleted_at IS NULL
	`
	var total int64
	err := db.QueryRowContext(ctx, query, filter.CompanyID, enums.SubStatusActive).Scan(&total)
	if err != nil {
		return nil, fmt.Errorf("get retention total: %w", err)
	}
	return &models.RetentionMetrics{
		TotalActive:          total,
		RenewedSubscriptions: 0,
		RetentionRate:        decimal.Zero,
	}, nil
}

func (r *analyticsRepository) getActiveCountAt(ctx context.Context, db DBTX, companyID uuid.UUID, at time.Time) (int64, error) {
	query := `
		SELECT COUNT(*)
		FROM subscription.subscriptions
		WHERE company_id = $1 AND status = $2 AND start_date <= $3 AND (end_date IS NULL OR end_date > $3) AND deleted_at IS NULL
	`
	var count int64
	err := db.QueryRowContext(ctx, query, companyID, enums.SubStatusActive, at).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// -------------------------------------------------------------------------
// Trials
// -------------------------------------------------------------------------

func (r *analyticsRepository) GetTrialMetrics(
	ctx context.Context,
	db DBTX,
	filter AnalyticsFilter,
) (*models.TrialMetrics, error) {
	where, args := r.buildConditions(filter)
	dateSQL, dateCount := getDateRangeSQL("trial_end", filter.StartDate, filter.EndDate)
	if dateCount > 0 {
		if filter.StartDate != nil {
			args = append(args, *filter.StartDate)
		}
		if filter.EndDate != nil {
			args = append(args, *filter.EndDate)
		}
		where += dateSQL
	}

	query := fmt.Sprintf(`
		SELECT
			COUNT(*) FILTER (WHERE trial_end IS NOT NULL) AS trials_started,
			COUNT(*) FILTER (WHERE status = '%s' AND trial_end IS NOT NULL) AS trials_converted,
			COUNT(*) FILTER (WHERE status = '%s' AND trial_end IS NOT NULL) AS trials_expired,
			COALESCE(AVG(EXTRACT(DAY FROM (trial_end - start_date))), 0) AS avg_trial_duration_days
		FROM subscription.subscriptions
		%s
	`, enums.SubStatusActive, enums.SubStatusExpired, where)

	var metrics models.TrialMetrics
	err := db.QueryRowContext(ctx, query, args...).Scan(
		&metrics.TrialsStarted,
		&metrics.TrialsConverted,
		&metrics.TrialsExpired,
		&metrics.AverageTrialDurationDays,
	)
	if err != nil {
		r.logger.Error("failed to get trial metrics", zap.Error(err))
		return nil, fmt.Errorf("get trial metrics: %w", err)
	}
	metrics.ConversionRate = decimal.Zero
	if metrics.TrialsStarted > 0 {
		metrics.ConversionRate = decimal.NewFromInt(metrics.TrialsConverted).Div(decimal.NewFromInt(metrics.TrialsStarted)).Mul(decimal.NewFromInt(100))
	}
	return &metrics, nil
}

func (r *analyticsRepository) GetTrialConversionRate(
	ctx context.Context,
	db DBTX,
	filter AnalyticsFilter,
) (decimal.Decimal, error) {
	metrics, err := r.GetTrialMetrics(ctx, db, filter)
	if err != nil {
		return decimal.Zero, err
	}
	return metrics.ConversionRate, nil
}

// -------------------------------------------------------------------------
// Renewals
// -------------------------------------------------------------------------

func (r *analyticsRepository) GetRenewalMetrics(
	ctx context.Context,
	db DBTX,
	filter AnalyticsFilter,
) (*models.RenewalMetrics, error) {
	where, args := r.buildConditions(filter)
	dateSQL, dateCount := getDateRangeSQL("updated_at", filter.StartDate, filter.EndDate)
	if dateCount > 0 {
		if filter.StartDate != nil {
			args = append(args, *filter.StartDate)
		}
		if filter.EndDate != nil {
			args = append(args, *filter.EndDate)
		}
		where += dateSQL
	}
	if where != "" {
		where = where + " AND version > 1"
	} else {
		where = "WHERE version > 1"
	}

	query := fmt.Sprintf(`
		SELECT COUNT(*) AS renewed_subscriptions
		FROM subscription.subscriptions
		%s
	`, where)

	var renewed int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&renewed)
	if err != nil {
		return nil, fmt.Errorf("get renewal metrics: %w", err)
	}
	return &models.RenewalMetrics{
		RenewedSubscriptions: renewed,
		RenewalRate:          decimal.Zero,
	}, nil
}

func (r *analyticsRepository) GetUpcomingRenewals(
	ctx context.Context,
	db DBTX,
	filter AnalyticsFilter,
	before time.Time,
) ([]*models.SubscriptionRenewalMetric, error) {
	where, args := r.buildConditions(filter)
	statusFilter := fmt.Sprintf("status = '%s' AND auto_renew = true AND end_date <= $%d", enums.SubStatusActive, len(args)+1)
	if where != "" {
		where = where + " AND " + statusFilter
	} else {
		where = "WHERE " + statusFilter
	}
	args = append(args, before)

	query := fmt.Sprintf(`
		SELECT subscription_id, customer_id, end_date
		FROM subscription.subscriptions
		%s
		ORDER BY end_date
	`, where)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get upcoming renewals: %w", err)
	}
	defer rows.Close()

	var results []*models.SubscriptionRenewalMetric
	for rows.Next() {
		var subID, custID uuid.UUID
		var endDate time.Time
		if err := rows.Scan(&subID, &custID, &endDate); err != nil {
			return nil, fmt.Errorf("scan renewal metric: %w", err)
		}
		results = append(results, &models.SubscriptionRenewalMetric{
			SubscriptionID: subID,
			CustomerID:     custID,
			EndDate:        endDate,
		})
	}
	return results, rows.Err()
}

// -------------------------------------------------------------------------
// Usage
// -------------------------------------------------------------------------

func (r *analyticsRepository) GetUsageMetrics(
	ctx context.Context,
	db DBTX,
	filter AnalyticsFilter,
) (*models.UsageMetrics, error) {
	where, args := r.buildConditions(filter)
	dateSQL, dateCount := getDateRangeSQL("u.period_start", filter.StartDate, filter.EndDate)
	if dateCount > 0 {
		if filter.StartDate != nil {
			args = append(args, *filter.StartDate)
		}
		if filter.EndDate != nil {
			args = append(args, *filter.EndDate)
		}
		where += dateSQL
	}

	query := fmt.Sprintf(`
		SELECT
			COUNT(DISTINCT u.usage_id) AS total_usage_events,
			COALESCE(SUM(u.quantity_used), 0) AS total_quantity_used,
			COUNT(DISTINCT u.feature_key) AS distinct_features_used,
			COUNT(DISTINCT s.subscription_id) AS active_subscriptions_with_usage
		FROM subscription.usages u
		INNER JOIN subscription.subscription_items si ON u.subscription_item_id = si.sub_item_id
		INNER JOIN subscription.subscriptions s ON si.subscription_id = s.subscription_id
		%s
	`, where)

	var metrics models.UsageMetrics
	err := db.QueryRowContext(ctx, query, args...).Scan(
		&metrics.TotalUsageEvents,
		&metrics.TotalQuantityUsed,
		&metrics.DistinctFeaturesUsed,
		&metrics.ActiveSubscriptionsWithUsage,
	)
	if err != nil {
		r.logger.Error("failed to get usage metrics", zap.Error(err))
		return nil, fmt.Errorf("get usage metrics: %w", err)
	}
	return &metrics, nil
}

func (r *analyticsRepository) GetTopFeatures(
	ctx context.Context,
	db DBTX,
	filter AnalyticsFilter,
	limit int,
) ([]*models.FeatureUsageMetric, error) {
	where, args := r.buildConditions(filter)
	dateSQL, dateCount := getDateRangeSQL("u.period_start", filter.StartDate, filter.EndDate)
	if dateCount > 0 {
		if filter.StartDate != nil {
			args = append(args, *filter.StartDate)
		}
		if filter.EndDate != nil {
			args = append(args, *filter.EndDate)
		}
		where += dateSQL
	}

	query := fmt.Sprintf(`
		SELECT
			u.feature_key,
			COUNT(*) AS usage_count,
			COALESCE(SUM(u.quantity_used), 0) AS total_quantity,
			COUNT(DISTINCT s.subscription_id) AS subscription_count
		FROM subscription.usages u
		INNER JOIN subscription.subscription_items si ON u.subscription_item_id = si.sub_item_id
		INNER JOIN subscription.subscriptions s ON si.subscription_id = s.subscription_id
		%s
		GROUP BY u.feature_key
		ORDER BY total_quantity DESC
		LIMIT $%d
	`, where, len(args)+1)
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get top features: %w", err)
	}
	defer rows.Close()

	var results []*models.FeatureUsageMetric
	for rows.Next() {
		var key string
		var count int64
		var totalQty decimal.Decimal
		var subCount int64
		if err := rows.Scan(&key, &count, &totalQty, &subCount); err != nil {
			return nil, fmt.Errorf("scan feature metric: %w", err)
		}
		results = append(results, &models.FeatureUsageMetric{
			FeatureKey:        key,
			UsageCount:        count,
			TotalQuantity:     totalQty,
			SubscriptionCount: subCount,
		})
	}
	return results, rows.Err()
}

func (r *analyticsRepository) GetTopPlans(
	ctx context.Context,
	db DBTX,
	filter AnalyticsFilter,
	limit int,
) ([]*models.PlanAnalyticsMetric, error) {
	where, args := r.buildConditions(filter)
	query := fmt.Sprintf(`
		SELECT
			p.plan_id,
			p.name AS plan_name,
			COUNT(DISTINCT s.subscription_id) AS subscription_count,
			COALESCE(SUM(si.total_price), 0) AS total_revenue,
			COUNT(DISTINCT s.customer_id) AS customer_count
		FROM subscription.subscriptions s
		INNER JOIN subscription.plans p ON s.plan_id = p.plan_id
		LEFT JOIN subscription.subscription_items si ON s.subscription_id = si.subscription_id
		%s
		GROUP BY p.plan_id, p.name
		ORDER BY total_revenue DESC
		LIMIT $%d
	`, where, len(args)+1)
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get top plans: %w", err)
	}
	defer rows.Close()

	var results []*models.PlanAnalyticsMetric
	for rows.Next() {
		var planID uuid.UUID
		var name string
		var subCount int64
		var revenue decimal.Decimal
		var custCount int64
		if err := rows.Scan(&planID, &name, &subCount, &revenue, &custCount); err != nil {
			return nil, fmt.Errorf("scan plan metric: %w", err)
		}
		results = append(results, &models.PlanAnalyticsMetric{
			PlanID:            planID,
			PlanName:          name,
			SubscriptionCount: subCount,
			TotalRevenue:      revenue,
			CustomerCount:     custCount,
		})
	}
	return results, rows.Err()
}

func (r *analyticsRepository) GetTopAddons(
	ctx context.Context,
	db DBTX,
	filter AnalyticsFilter,
	limit int,
) ([]*models.AddonAnalyticsMetric, error) {
	where, args := r.buildConditions(filter)
	query := fmt.Sprintf(`
		SELECT
			a.addon_id,
			a.name AS addon_name,
			COUNT(DISTINCT si.sub_item_id) AS usage_count,
			COALESCE(SUM(si.total_price), 0) AS total_revenue,
			COUNT(DISTINCT s.subscription_id) AS subscription_count
		FROM subscription.subscription_items si
		INNER JOIN subscription.addons a ON si.addon_id = a.addon_id
		INNER JOIN subscription.subscriptions s ON si.subscription_id = s.subscription_id
		%s
		GROUP BY a.addon_id, a.name
		ORDER BY total_revenue DESC
		LIMIT $%d
	`, where, len(args)+1)
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get top addons: %w", err)
	}
	defer rows.Close()

	var results []*models.AddonAnalyticsMetric
	for rows.Next() {
		var addonID uuid.UUID
		var name string
		var usageCount int64
		var revenue decimal.Decimal
		var subCount int64
		if err := rows.Scan(&addonID, &name, &usageCount, &revenue, &subCount); err != nil {
			return nil, fmt.Errorf("scan addon metric: %w", err)
		}
		results = append(results, &models.AddonAnalyticsMetric{
			AddonID:           addonID,
			AddonName:         name,
			UsageCount:        usageCount,
			TotalRevenue:      revenue,
			SubscriptionCount: subCount,
		})
	}
	return results, rows.Err()
}

// -------------------------------------------------------------------------
// Customer
// -------------------------------------------------------------------------

func (r *analyticsRepository) GetTopCustomers(
	ctx context.Context,
	db DBTX,
	filter AnalyticsFilter,
	limit int,
) ([]*models.CustomerAnalyticsMetric, error) {
	where, args := r.buildConditions(filter)
	query := fmt.Sprintf(`
		SELECT
			s.customer_id,
			COUNT(DISTINCT s.subscription_id) AS subscription_count,
			COALESCE(SUM(si.total_price), 0) AS total_spent,
			MAX(s.created_at) AS last_subscription_date
		FROM subscription.subscriptions s
		LEFT JOIN subscription.subscription_items si ON s.subscription_id = si.subscription_id
		%s
		GROUP BY s.customer_id
		ORDER BY total_spent DESC
		LIMIT $%d
	`, where, len(args)+1)
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get top customers: %w", err)
	}
	defer rows.Close()

	var results []*models.CustomerAnalyticsMetric
	for rows.Next() {
		var custID uuid.UUID
		var subCount int64
		var totalSpent decimal.Decimal
		var lastDate *time.Time
		if err := rows.Scan(&custID, &subCount, &totalSpent, &lastDate); err != nil {
			return nil, fmt.Errorf("scan customer metric: %w", err)
		}
		results = append(results, &models.CustomerAnalyticsMetric{
			CustomerID:           custID,
			SubscriptionCount:    subCount,
			TotalSpent:           totalSpent,
			LastSubscriptionDate: lastDate,
		})
	}
	return results, rows.Err()
}

func (r *analyticsRepository) GetCustomerLifetimeValue(
	ctx context.Context,
	db DBTX,
	filter AnalyticsFilter,
	customerID uuid.UUID,
) (decimal.Decimal, error) {
	where, args := r.buildConditions(filter)
	custCond := fmt.Sprintf("s.customer_id = $%d", len(args)+1)
	if where != "" {
		where = where + " AND " + custCond
	} else {
		where = "WHERE " + custCond
	}
	args = append(args, customerID)

	query := fmt.Sprintf(`
		SELECT COALESCE(SUM(si.total_price), 0)
		FROM subscription.subscriptions s
		LEFT JOIN subscription.subscription_items si ON s.subscription_id = si.subscription_id
		%s
	`, where)

	var ltv decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&ltv)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get customer LTV: %w", err)
	}
	return ltv, nil
}

// -------------------------------------------------------------------------
// Dashboard
// -------------------------------------------------------------------------

func (r *analyticsRepository) GetDashboard(
	ctx context.Context,
	db DBTX,
	filter AnalyticsFilter,
) (*models.SubscriptionDashboard, error) {
	dashboard := &models.SubscriptionDashboard{}

	subMetrics, err := r.GetSubscriptionMetrics(ctx, db, filter)
	if err != nil {
		r.logger.Warn("failed to get subscription metrics for dashboard", zap.Error(err))
	} else {
		dashboard.SubscriptionMetrics = subMetrics
	}

	revMetrics, err := r.GetRevenueMetrics(ctx, db, filter)
	if err != nil {
		r.logger.Warn("failed to get revenue metrics for dashboard", zap.Error(err))
	} else {
		dashboard.RevenueMetrics = revMetrics
	}

	mrr, err := r.GetMRR(ctx, db, filter)
	if err != nil {
		r.logger.Warn("failed to get MRR for dashboard", zap.Error(err))
	} else {
		dashboard.MRR = mrr
	}

	arr, err := r.GetARR(ctx, db, filter)
	if err != nil {
		r.logger.Warn("failed to get ARR for dashboard", zap.Error(err))
	} else {
		dashboard.ARR = arr
	}

	churnFilter := filter
	if churnFilter.StartDate == nil {
		t := time.Now().AddDate(0, -1, 0)
		churnFilter.StartDate = &t
	}
	if churnFilter.EndDate == nil {
		t := time.Now()
		churnFilter.EndDate = &t
	}
	churn, err := r.GetChurnMetrics(ctx, db, churnFilter)
	if err != nil {
		r.logger.Warn("failed to get churn metrics for dashboard", zap.Error(err))
	} else {
		dashboard.ChurnMetrics = churn
	}

	trial, err := r.GetTrialMetrics(ctx, db, filter)
	if err != nil {
		r.logger.Warn("failed to get trial metrics for dashboard", zap.Error(err))
	} else {
		dashboard.TrialMetrics = trial
	}

	topFeatures, err := r.GetTopFeatures(ctx, db, filter, 5)
	if err != nil {
		r.logger.Warn("failed to get top features for dashboard", zap.Error(err))
	} else {
		dashboard.TopFeatures = topFeatures
	}

	topPlans, err := r.GetTopPlans(ctx, db, filter, 5)
	if err != nil {
		r.logger.Warn("failed to get top plans for dashboard", zap.Error(err))
	} else {
		dashboard.TopPlans = topPlans
	}

	renewalFilter := filter
	before := time.Now().AddDate(0, 0, 7)
	upcoming, err := r.GetUpcomingRenewals(ctx, db, renewalFilter, before)
	if err != nil {
		r.logger.Warn("failed to get upcoming renewals for dashboard", zap.Error(err))
	} else {
		dashboard.UpcomingRenewals = upcoming
	}

	return dashboard, nil
}

// -------------------------------------------------------------------------
// Write Methods (Analytics Ingestion)
// -------------------------------------------------------------------------

func (r *analyticsRepository) InsertSubscriptionFact(ctx context.Context, tx *sql.Tx, fact *models.SubscriptionFact) error {
	query := `
		INSERT INTO subscription_analytics.subscription_fact (
			fact_id, company_id, subscription_id, event_date, event_type,
			plan_id, customer_id, old_status_id, new_status_id, mrr_change, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	_, err := tx.ExecContext(ctx, query,
		uuid.New(),
		fact.CompanyID,
		fact.SubscriptionID,
		fact.EventDate,
		fact.EventType,
		fact.PlanID,
		fact.CustomerID,
		fact.OldStatusID,
		fact.NewStatusID,
		fact.MRRChange,
		fact.Metadata,
	)
	return err
}

func (r *analyticsRepository) IncrementDailySubscriptionMetrics(ctx context.Context, tx *sql.Tx, companyID uuid.UUID, date time.Time, delta *DailySubscriptionMetricsDelta) error {
	query := `
		INSERT INTO subscription_analytics.daily_subscription_metrics (
			company_id, date, new_subscriptions, active_subscriptions,
			cancelled_subscriptions, expired_subscriptions, paused_subscriptions,
			trial_starts, trial_conversions, trial_expirations,
			mrr, arr, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
		ON CONFLICT (company_id, date) DO UPDATE SET
			new_subscriptions = daily_subscription_metrics.new_subscriptions + EXCLUDED.new_subscriptions,
			active_subscriptions = daily_subscription_metrics.active_subscriptions + EXCLUDED.active_subscriptions,
			cancelled_subscriptions = daily_subscription_metrics.cancelled_subscriptions + EXCLUDED.cancelled_subscriptions,
			expired_subscriptions = daily_subscription_metrics.expired_subscriptions + EXCLUDED.expired_subscriptions,
			paused_subscriptions = daily_subscription_metrics.paused_subscriptions + EXCLUDED.paused_subscriptions,
			trial_starts = daily_subscription_metrics.trial_starts + EXCLUDED.trial_starts,
			trial_conversions = daily_subscription_metrics.trial_conversions + EXCLUDED.trial_conversions,
			trial_expirations = daily_subscription_metrics.trial_expirations + EXCLUDED.trial_expirations,
			mrr = daily_subscription_metrics.mrr + EXCLUDED.mrr,
			arr = daily_subscription_metrics.arr + EXCLUDED.arr,
			updated_at = NOW()
	`
	_, err := tx.ExecContext(ctx, query,
		companyID,
		date,
		delta.NewSubscriptions,
		delta.ActiveSubscriptions,
		delta.CancelledSubscriptions,
		delta.ExpiredSubscriptions,
		delta.PausedSubscriptions,
		delta.TrialStarts,
		delta.TrialConversions,
		delta.TrialExpirations,
		delta.MRR,
		delta.ARR,
	)
	return err
}

func (r *analyticsRepository) IncrementDailyPlanMetrics(ctx context.Context, tx *sql.Tx, companyID, planID uuid.UUID, date time.Time, delta *DailyPlanMetricsDelta) error {
	query := `
		INSERT INTO subscription_analytics.daily_plan_metrics (
			company_id, plan_id, date, active_count, new_count, mrr, arr, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		ON CONFLICT (company_id, plan_id, date) DO UPDATE SET
			active_count = daily_plan_metrics.active_count + EXCLUDED.active_count,
			new_count = daily_plan_metrics.new_count + EXCLUDED.new_count,
			mrr = daily_plan_metrics.mrr + EXCLUDED.mrr,
			arr = daily_plan_metrics.arr + EXCLUDED.arr,
			updated_at = NOW()
	`
	_, err := tx.ExecContext(ctx, query,
		companyID,
		planID,
		date,
		delta.ActiveCount,
		delta.NewCount,
		delta.MRR,
		delta.ARR,
	)
	return err
}

// -------------------------------------------------------------------------
// Addon Analytics Implementation
// -------------------------------------------------------------------------

// InsertAddonUsageFact stores a usage record for an addon.
func (r *analyticsRepository) InsertAddonUsageFact(ctx context.Context, tx *sql.Tx, fact *models.AddonUsageFact) error {
	query := `
		INSERT INTO subscription_analytics.addon_usage_fact (
			fact_id, company_id, addon_id, subscription_id, quantity, usage_date
		) VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := tx.ExecContext(ctx, query,
		uuid.New(),
		fact.CompanyID,
		fact.AddonID,
		fact.SubscriptionID,
		fact.Quantity,
		fact.UsageDate,
	)
	return err
}

// IncrementDailyAddonMetrics upserts daily aggregated metrics for an addon.
func (r *analyticsRepository) IncrementDailyAddonMetrics(ctx context.Context, tx *sql.Tx, companyID, addonID uuid.UUID, date time.Time, delta *models.DailyAddonMetricsDelta) error {
	query := `
		INSERT INTO subscription_analytics.daily_addon_metrics (
			company_id, addon_id, date, active_count, new_count, revenue, mrr, arr, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
		ON CONFLICT (company_id, addon_id, date) DO UPDATE SET
			active_count = daily_addon_metrics.active_count + EXCLUDED.active_count,
			new_count = daily_addon_metrics.new_count + EXCLUDED.new_count,
			revenue = daily_addon_metrics.revenue + EXCLUDED.revenue,
			mrr = daily_addon_metrics.mrr + EXCLUDED.mrr,
			arr = daily_addon_metrics.arr + EXCLUDED.arr,
			updated_at = NOW()
	`
	_, err := tx.ExecContext(ctx, query,
		companyID,
		addonID,
		date,
		delta.ActiveCount,
		delta.NewCount,
		delta.Revenue,
		delta.MRR,
		delta.ARR,
	)
	return err
}

// GetAddonMetrics retrieves aggregated metrics for a specific addon.
func (r *analyticsRepository) GetAddonMetrics(ctx context.Context, db DBTX, filter AnalyticsFilter, addonID uuid.UUID) (*models.AddonAnalyticsMetric, error) {
	where, args := r.buildConditions(filter)
	addonCond := fmt.Sprintf("a.addon_id = $%d", len(args)+1)
	if where != "" {
		where = where + " AND " + addonCond
	} else {
		where = "WHERE " + addonCond
	}
	args = append(args, addonID)

	query := fmt.Sprintf(`
		SELECT
			a.addon_id,
			a.name AS addon_name,
			COUNT(DISTINCT si.sub_item_id) AS usage_count,
			COALESCE(SUM(si.total_price), 0) AS total_revenue,
			COUNT(DISTINCT s.subscription_id) AS subscription_count
		FROM subscription.subscription_items si
		INNER JOIN subscription.addons a ON si.addon_id = a.addon_id
		INNER JOIN subscription.subscriptions s ON si.subscription_id = s.subscription_id
		%s
		GROUP BY a.addon_id, a.name
	`, where)

	var metric models.AddonAnalyticsMetric
	err := db.QueryRowContext(ctx, query, args...).Scan(
		&metric.AddonID,
		&metric.AddonName,
		&metric.UsageCount,
		&metric.TotalRevenue,
		&metric.SubscriptionCount,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get addon metrics: %w", err)
	}
	return &metric, nil
}

// -------------------------------------------------------------------------
// Benefit Analytics Implementation
// -------------------------------------------------------------------------

func (r *analyticsRepository) InsertBenefitUsageFact(ctx context.Context, tx *sql.Tx, fact *models.BenefitUsageFact) error {
	query := `
		INSERT INTO subscription_analytics.benefit_usage_fact (
			fact_id, company_id, benefit_id, subscription_id, benefit_type, quantity, usage_date
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := tx.ExecContext(ctx, query,
		uuid.New(),
		fact.CompanyID,
		fact.BenefitID,
		fact.SubscriptionID,
		fact.BenefitType,
		fact.Quantity,
		fact.UsageDate,
	)
	return err
}

// IncrementDailyBenefitMetrics upserts daily aggregated metrics for a benefit.
func (r *analyticsRepository) IncrementDailyBenefitMetrics(ctx context.Context, tx *sql.Tx, companyID, benefitID uuid.UUID, date time.Time, delta *models.DailyBenefitMetricsDelta) error {
	query := `
		INSERT INTO subscription_analytics.daily_benefit_metrics (
			company_id, benefit_id, date, active_count, new_count, updated_at
		) VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (company_id, benefit_id, date) DO UPDATE SET
			active_count = daily_benefit_metrics.active_count + EXCLUDED.active_count,
			new_count = daily_benefit_metrics.new_count + EXCLUDED.new_count,
			updated_at = NOW()
	`
	_, err := tx.ExecContext(ctx, query,
		companyID,
		benefitID,
		date,
		delta.ActiveCount,
		delta.NewCount,
	)
	return err
}

// GetBenefitMetrics retrieves aggregated metrics for a specific benefit.
func (r *analyticsRepository) GetBenefitMetrics(ctx context.Context, db DBTX, filter AnalyticsFilter, benefitID uuid.UUID) (*models.BenefitAnalyticsMetric, error) {
	where, args := r.buildConditions(filter)
	benefitCond := fmt.Sprintf("b.benefit_id = $%d", len(args)+1)
	if where != "" {
		where = where + " AND " + benefitCond
	} else {
		where = "WHERE " + benefitCond
	}
	args = append(args, benefitID)

	query := fmt.Sprintf(`
		SELECT
			b.benefit_id,
			b.benefit_type,
			COUNT(DISTINCT s.subscription_id) AS subscription_count,
			COUNT(DISTINCT si.sub_item_id) AS usage_count
		FROM subscription.benefits b
		INNER JOIN subscription.plan_items pi ON b.plan_item_id = pi.plan_item_id
		LEFT JOIN subscription.subscription_items si ON pi.plan_item_id = si.plan_item_id
		LEFT JOIN subscription.subscriptions s ON si.subscription_id = s.subscription_id
		%s
		GROUP BY b.benefit_id, b.benefit_type
	`, where)

	var metric models.BenefitAnalyticsMetric
	err := db.QueryRowContext(ctx, query, args...).Scan(
		&metric.BenefitID,
		&metric.BenefitType,
		&metric.SubscriptionCount,
		&metric.UsageCount,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get benefit metrics: %w", err)
	}
	return &metric, nil
}

// -------------------------------------------------------------------------
// Billing Policy Analytics Implementation
// -------------------------------------------------------------------------

// InsertBillingPolicyUsageFact stores a usage record for a billing policy.
func (r *analyticsRepository) InsertBillingPolicyUsageFact(ctx context.Context, tx *sql.Tx, fact *models.BillingPolicyUsageFact) error {
	query := `
		INSERT INTO subscription_analytics.billing_policy_usage_fact (
			fact_id, company_id, billing_policy_id, entity_type, entity_id, usage_date
		) VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := tx.ExecContext(ctx, query,
		uuid.New(),
		fact.CompanyID,
		fact.BillingPolicyID,
		fact.EntityType,
		fact.EntityID,
		fact.UsageDate,
	)
	return err
}

// IncrementDailyBillingPolicyMetrics upserts daily aggregated metrics for a billing policy.
func (r *analyticsRepository) IncrementDailyBillingPolicyMetrics(ctx context.Context, tx *sql.Tx, companyID, billingPolicyID uuid.UUID, date time.Time, delta *models.DailyBillingPolicyMetricsDelta) error {
	query := `
		INSERT INTO subscription_analytics.daily_billing_policy_metrics (
			company_id, billing_policy_id, date, active_count, new_count, updated_at
		) VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (company_id, billing_policy_id, date) DO UPDATE SET
			active_count = daily_billing_policy_metrics.active_count + EXCLUDED.active_count,
			new_count = daily_billing_policy_metrics.new_count + EXCLUDED.new_count,
			updated_at = NOW()
	`
	_, err := tx.ExecContext(ctx, query,
		companyID,
		billingPolicyID,
		date,
		delta.ActiveCount,
		delta.NewCount,
	)
	return err
}

// GetBillingPolicyMetrics retrieves aggregated metrics for a specific billing policy.
func (r *analyticsRepository) GetBillingPolicyMetrics(ctx context.Context, db DBTX, filter AnalyticsFilter, billingPolicyID uuid.UUID) (*models.BillingPolicyAnalyticsMetric, error) {
	where, args := r.buildConditions(filter)
	bpCond := fmt.Sprintf("bp.billing_policy_id = $%d", len(args)+1)
	if where != "" {
		where = where + " AND " + bpCond
	} else {
		where = "WHERE " + bpCond
	}
	args = append(args, billingPolicyID)

	// To get the policy name, join with the billing_policies table.
	query := fmt.Sprintf(`
		SELECT
			bp.billing_policy_id,
			bp.name AS billing_policy_name,
			COALESCE(SUM(dm.active_count), 0) AS active_count,
			COALESCE(SUM(dm.new_count), 0) AS new_count,
			MAX(dm.updated_at) AS updated_at
		FROM subscription.billing_policies bp
		LEFT JOIN subscription_analytics.daily_billing_policy_metrics dm
			ON bp.billing_policy_id = dm.billing_policy_id
			AND bp.company_id = dm.company_id
		%s
		GROUP BY bp.billing_policy_id, bp.name
	`, where)

	var metric models.BillingPolicyAnalyticsMetric
	err := db.QueryRowContext(ctx, query, args...).Scan(
		&metric.BillingPolicyID,
		&metric.BillingPolicyName,
		&metric.ActiveCount,
		&metric.NewCount,
		&metric.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get billing policy metrics: %w", err)
	}
	return &metric, nil
}

// -------------------------------------------------------------------------
// Renewal Policy Analytics Implementation
// -------------------------------------------------------------------------

// InsertRenewalPolicyUsageFact stores a usage record for a renewal policy.
func (r *analyticsRepository) InsertRenewalPolicyUsageFact(ctx context.Context, tx *sql.Tx, fact *models.RenewalPolicyUsageFact) error {
	query := `
		INSERT INTO subscription_analytics.renewal_policy_usage_fact (
			fact_id, company_id, renewal_policy_id, plan_id, usage_date
		) VALUES ($1, $2, $3, $4, $5)
	`
	_, err := tx.ExecContext(ctx, query,
		uuid.New(),
		fact.CompanyID,
		fact.RenewalPolicyID,
		fact.PlanID,
		fact.UsageDate,
	)
	return err
}

// IncrementDailyRenewalPolicyMetrics upserts daily aggregated metrics for a renewal policy.
func (r *analyticsRepository) IncrementDailyRenewalPolicyMetrics(ctx context.Context, tx *sql.Tx, companyID, renewalPolicyID uuid.UUID, date time.Time, delta *models.DailyRenewalPolicyMetricsDelta) error {
	query := `
		INSERT INTO subscription_analytics.daily_renewal_policy_metrics (
			company_id, renewal_policy_id, date, active_count, new_count, updated_at
		) VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (company_id, renewal_policy_id, date) DO UPDATE SET
			active_count = daily_renewal_policy_metrics.active_count + EXCLUDED.active_count,
			new_count = daily_renewal_policy_metrics.new_count + EXCLUDED.new_count,
			updated_at = NOW()
	`
	_, err := tx.ExecContext(ctx, query,
		companyID,
		renewalPolicyID,
		date,
		delta.ActiveCount,
		delta.NewCount,
	)
	return err
}

// GetRenewalPolicyMetrics retrieves aggregated metrics for a specific renewal policy.
func (r *analyticsRepository) GetRenewalPolicyMetrics(ctx context.Context, db DBTX, filter AnalyticsFilter, renewalPolicyID uuid.UUID) (*models.RenewalPolicyAnalyticsMetric, error) {
	where, args := r.buildConditions(filter)
	rpCond := fmt.Sprintf("rp.renewal_policy_id = $%d", len(args)+1)
	if where != "" {
		where = where + " AND " + rpCond
	} else {
		where = "WHERE " + rpCond
	}
	args = append(args, renewalPolicyID)

	// Join with renewal_policies to get the policy name.
	query := fmt.Sprintf(`
		SELECT
			rp.renewal_policy_id,
			rp.name AS renewal_policy_name,
			COALESCE(SUM(dm.active_count), 0) AS active_count,
			COALESCE(SUM(dm.new_count), 0) AS new_count,
			MAX(dm.updated_at) AS updated_at
		FROM subscription.renewal_policies rp
		LEFT JOIN subscription_analytics.daily_renewal_policy_metrics dm
			ON rp.renewal_policy_id = dm.renewal_policy_id
			AND rp.company_id = dm.company_id
		%s
		GROUP BY rp.renewal_policy_id, rp.name
	`, where)

	var metric models.RenewalPolicyAnalyticsMetric
	err := db.QueryRowContext(ctx, query, args...).Scan(
		&metric.RenewalPolicyID,
		&metric.RenewalPolicyName,
		&metric.ActiveCount,
		&metric.NewCount,
		&metric.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get renewal policy metrics: %w", err)
	}
	return &metric, nil
}

// -------------------------------------------------------------------------
// Pause Policy Analytics Implementation
// -------------------------------------------------------------------------

// InsertPausePolicyUsageFact stores a usage record for a pause policy.
func (r *analyticsRepository) InsertPausePolicyUsageFact(ctx context.Context, tx *sql.Tx, fact *models.PausePolicyUsageFact) error {
	query := `
		INSERT INTO subscription_analytics.pause_policy_usage_fact (
			fact_id, company_id, pause_policy_id, entity_type, entity_id, usage_date
		) VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := tx.ExecContext(ctx, query,
		uuid.New(),
		fact.CompanyID,
		fact.PausePolicyID,
		fact.EntityType,
		fact.EntityID,
		fact.UsageDate,
	)
	return err
}

// IncrementDailyPausePolicyMetrics upserts daily aggregated metrics for a pause policy.
func (r *analyticsRepository) IncrementDailyPausePolicyMetrics(ctx context.Context, tx *sql.Tx, companyID, pausePolicyID uuid.UUID, date time.Time, delta *models.DailyPausePolicyMetricsDelta) error {
	query := `
		INSERT INTO subscription_analytics.daily_pause_policy_metrics (
			company_id, pause_policy_id, date,
			active_count, new_count,
			paused_subscriptions_count,
			pause_events_count, resume_events_count,
			avg_pause_duration_days,
			updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
		ON CONFLICT (company_id, pause_policy_id, date) DO UPDATE SET
			active_count = daily_pause_policy_metrics.active_count + EXCLUDED.active_count,
			new_count = daily_pause_policy_metrics.new_count + EXCLUDED.new_count,
			paused_subscriptions_count = daily_pause_policy_metrics.paused_subscriptions_count + EXCLUDED.paused_subscriptions_count,
			pause_events_count = daily_pause_policy_metrics.pause_events_count + EXCLUDED.pause_events_count,
			resume_events_count = daily_pause_policy_metrics.resume_events_count + EXCLUDED.resume_events_count,
			avg_pause_duration_days = (daily_pause_policy_metrics.avg_pause_duration_days * daily_pause_policy_metrics.pause_events_count + EXCLUDED.avg_pause_duration_days * EXCLUDED.pause_events_count) / NULLIF(daily_pause_policy_metrics.pause_events_count + EXCLUDED.pause_events_count, 0),
			updated_at = NOW()
	`
	_, err := tx.ExecContext(ctx, query,
		companyID,
		pausePolicyID,
		date,
		delta.ActiveCount,
		delta.NewCount,
		delta.PausedSubscriptionsCount,
		delta.PauseEventsCount,
		delta.ResumeEventsCount,
		delta.AvgPauseDurationDays,
	)
	return err
}

// GetPausePolicyMetrics retrieves aggregated metrics for a specific pause policy.
func (r *analyticsRepository) GetPausePolicyMetrics(ctx context.Context, db DBTX, filter AnalyticsFilter, pausePolicyID uuid.UUID) (*models.PausePolicyAnalyticsMetric, error) {
	where, args := r.buildConditions(filter)
	ppCond := fmt.Sprintf("pp.pause_policy_id = $%d", len(args)+1)
	if where != "" {
		where = where + " AND " + ppCond
	} else {
		where = "WHERE " + ppCond
	}
	args = append(args, pausePolicyID)

	// Join with pause_policies to get the policy name.
	query := fmt.Sprintf(`
		SELECT
			pp.pause_policy_id,
			pp.name AS pause_policy_name,
			COALESCE(SUM(dm.active_count), 0) AS active_count,
			COALESCE(SUM(dm.new_count), 0) AS new_count,
			COALESCE(SUM(dm.paused_subscriptions_count), 0) AS paused_subscriptions_count,
			COALESCE(SUM(dm.pause_events_count), 0) AS pause_events_count,
			COALESCE(SUM(dm.resume_events_count), 0) AS resume_events_count,
			COALESCE(AVG(dm.avg_pause_duration_days), 0) AS avg_pause_duration_days,
			MAX(dm.updated_at) AS updated_at
		FROM subscription.pause_policies pp
		LEFT JOIN subscription_analytics.daily_pause_policy_metrics dm
			ON pp.pause_policy_id = dm.pause_policy_id
			AND pp.company_id = dm.company_id
		%s
		GROUP BY pp.pause_policy_id, pp.name
	`, where)

	var metric models.PausePolicyAnalyticsMetric
	err := db.QueryRowContext(ctx, query, args...).Scan(
		&metric.PausePolicyID,
		&metric.PausePolicyName,
		&metric.ActiveCount,
		&metric.NewCount,
		&metric.PausedSubscriptionsCount,
		&metric.PauseEventsCount,
		&metric.ResumeEventsCount,
		&metric.AvgPauseDurationDays,
		&metric.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get pause policy metrics: %w", err)
	}
	return &metric, nil
}

// -------------------------------------------------------------------------
// Entitlement Analytics Implementation
// -------------------------------------------------------------------------

// InsertEntitlementUsageFact stores a fact that an entitlement was granted to a subscription.
func (r *analyticsRepository) InsertEntitlementUsageFact(ctx context.Context, tx *sql.Tx, fact *models.EntitlementUsageFact) error {
	query := `
		INSERT INTO subscription_analytics.entitlement_usage_fact (
			fact_id, company_id, subscription_id, plan_item_id, feature_key,
			limit_value, limit_period, is_enabled, grant_date
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := tx.ExecContext(ctx, query,
		uuid.New(),
		fact.CompanyID,
		fact.SubscriptionID,
		fact.PlanItemID,
		fact.FeatureKey,
		fact.LimitValue,
		fact.LimitPeriod,
		fact.IsEnabled,
		fact.GrantDate,
	)
	return err
}

// IncrementDailyEntitlementMetrics upserts daily aggregated metrics for a feature.
func (r *analyticsRepository) IncrementDailyEntitlementMetrics(ctx context.Context, tx *sql.Tx, companyID uuid.UUID, featureKey string, date time.Time, delta *models.DailyEntitlementMetricsDelta) error {
	query := `
		INSERT INTO subscription_analytics.daily_entitlement_metrics (
			company_id, feature_key, date, active_count, new_count, updated_at
		) VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (company_id, feature_key, date) DO UPDATE SET
			active_count = daily_entitlement_metrics.active_count + EXCLUDED.active_count,
			new_count = daily_entitlement_metrics.new_count + EXCLUDED.new_count,
			updated_at = NOW()
	`
	_, err := tx.ExecContext(ctx, query,
		companyID,
		featureKey,
		date,
		delta.ActiveCount,
		delta.NewCount,
	)
	return err
}

// GetEntitlementMetrics retrieves aggregated metrics for a specific feature.
func (r *analyticsRepository) GetEntitlementMetrics(ctx context.Context, db DBTX, filter AnalyticsFilter, featureKey string) (*models.EntitlementAnalyticsMetric, error) {
	where, args := r.buildConditions(filter)
	featureCond := fmt.Sprintf("feature_key = $%d", len(args)+1)
	if where != "" {
		where = where + " AND " + featureCond
	} else {
		where = "WHERE " + featureCond
	}
	args = append(args, featureKey)

	// Optional: add date range filter if needed (currently not added, but you could add it via filter.StartDate/EndDate)
	// The metrics table already has date; we can filter on that if needed.

	query := fmt.Sprintf(`
		SELECT
			COALESCE(SUM(active_count), 0) AS active_count,
			COALESCE(SUM(new_count), 0) AS new_count
		FROM subscription_analytics.daily_entitlement_metrics
		%s
	`, where)

	var metric models.EntitlementAnalyticsMetric
	metric.FeatureKey = featureKey
	err := db.QueryRowContext(ctx, query, args...).Scan(
		&metric.ActiveCount,
		&metric.NewCount,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return &metric, nil // return zero values if no data
		}
		return nil, fmt.Errorf("get entitlement metrics: %w", err)
	}
	return &metric, nil
}

// -------------------------------------------------------------------------
// Plan Change Analytics
// -------------------------------------------------------------------------

// InsertPlanChangeFact stores a plan change event.
func (r *analyticsRepository) InsertPlanChangeFact(ctx context.Context, tx *sql.Tx, fact *models.PlanChangeFact) error {
	query := `
		INSERT INTO subscription_analytics.plan_change_fact (
			fact_id, company_id, subscription_id, old_plan_id, new_plan_id,
			change_type, change_date, old_plan_version, new_plan_version,
			mrr_delta, performed_by, reason
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`
	_, err := tx.ExecContext(ctx, query,
		uuid.New(),
		fact.CompanyID,
		fact.SubscriptionID,
		fact.OldPlanID,
		fact.NewPlanID,
		fact.ChangeType,
		fact.ChangeDate,
		fact.OldPlanVersion,
		fact.NewPlanVersion,
		fact.MRRDelta,
		fact.PerformedBy,
		fact.Reason,
	)
	return err
}

// IncrementDailyPlanChangeMetrics upserts daily aggregated metrics for a plan.
func (r *analyticsRepository) IncrementDailyPlanChangeMetrics(ctx context.Context, tx *sql.Tx, companyID, planID uuid.UUID, date time.Time, delta *models.PlanChangeDelta) error {
	query := `
		INSERT INTO subscription_analytics.daily_plan_change_metrics (
			company_id, plan_id, date,
			upgrade_in_count, upgrade_out_count,
			downgrade_in_count, downgrade_out_count,
			lateral_in_count, lateral_out_count,
			net_change, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
		ON CONFLICT (company_id, plan_id, date) DO UPDATE SET
			upgrade_in_count = daily_plan_change_metrics.upgrade_in_count + EXCLUDED.upgrade_in_count,
			upgrade_out_count = daily_plan_change_metrics.upgrade_out_count + EXCLUDED.upgrade_out_count,
			downgrade_in_count = daily_plan_change_metrics.downgrade_in_count + EXCLUDED.downgrade_in_count,
			downgrade_out_count = daily_plan_change_metrics.downgrade_out_count + EXCLUDED.downgrade_out_count,
			lateral_in_count = daily_plan_change_metrics.lateral_in_count + EXCLUDED.lateral_in_count,
			lateral_out_count = daily_plan_change_metrics.lateral_out_count + EXCLUDED.lateral_out_count,
			net_change = daily_plan_change_metrics.net_change + EXCLUDED.net_change,
			updated_at = NOW()
	`
	_, err := tx.ExecContext(ctx, query,
		companyID,
		planID,
		date,
		delta.UpgradeInCount,
		delta.UpgradeOutCount,
		delta.DowngradeInCount,
		delta.DowngradeOutCount,
		delta.LateralInCount,
		delta.LateralOutCount,
		delta.NetChange,
	)
	return err
}

// GetPlanChangeMetrics returns aggregated change metrics for a specific plan over the filter's date range.
// GetPlanChangeMetrics returns aggregated change metrics for a specific plan over the filter's date range.
func (r *analyticsRepository) GetPlanChangeMetrics(ctx context.Context, db DBTX, filter AnalyticsFilter, planID uuid.UUID) (*models.PlanChangeMetricsSummary, error) {
	where, args := r.buildConditions(filter)
	planCond := fmt.Sprintf("plan_id = $%d", len(args)+1)
	if where != "" {
		where = where + " AND " + planCond
	} else {
		where = "WHERE " + planCond
	}
	args = append(args, planID)

	dateSQL, dateCount := getDateRangeSQL("date", filter.StartDate, filter.EndDate)
	if dateCount > 0 {
		if filter.StartDate != nil {
			args = append(args, *filter.StartDate)
		}
		if filter.EndDate != nil {
			args = append(args, *filter.EndDate)
		}
		where += dateSQL
	}

	// Build join query to get plan name and aggregated metrics.
	joinQuery := fmt.Sprintf(`
		SELECT
			p.name,
			COALESCE(SUM(d.upgrade_in_count), 0) AS upgrade_in,
			COALESCE(SUM(d.upgrade_out_count), 0) AS upgrade_out,
			COALESCE(SUM(d.downgrade_in_count), 0) AS downgrade_in,
			COALESCE(SUM(d.downgrade_out_count), 0) AS downgrade_out,
			COALESCE(SUM(d.lateral_in_count), 0) AS lateral_in,
			COALESCE(SUM(d.lateral_out_count), 0) AS lateral_out,
			COALESCE(SUM(d.net_change), 0) AS net_change,
			COUNT(*) AS days_with_data
		FROM subscription_analytics.daily_plan_change_metrics d
		INNER JOIN subscription.plans p ON d.plan_id = p.plan_id AND d.company_id = p.company_id
		%s
		GROUP BY p.name
	`, where)

	var summary models.PlanChangeMetricsSummary
	summary.PlanID = planID

	var name string
	var days int64
	err := db.QueryRowContext(ctx, joinQuery, args...).Scan(
		&name,
		&summary.TotalUpgradeIn,
		&summary.TotalUpgradeOut,
		&summary.TotalDowngradeIn,
		&summary.TotalDowngradeOut,
		&summary.TotalLateralIn,
		&summary.TotalLateralOut,
		&summary.NetChange,
		&days,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get plan change metrics: %w", err)
	}
	summary.PlanName = name
	if days > 0 {
		summary.AverageDailyNetChange = float64(summary.NetChange) / float64(days)
	}
	return &summary, nil
}

// GetPlanChangeTrend returns daily change metrics for a plan grouped by time period.
func (r *analyticsRepository) GetPlanChangeTrend(ctx context.Context, db DBTX, filter AnalyticsFilter, planID uuid.UUID, groupBy AnalyticsGroupBy) ([]*models.PlanChangeTrendMetric, error) {
	where, args := r.buildConditions(filter)
	planCond := fmt.Sprintf("plan_id = $%d", len(args)+1)
	if where != "" {
		where = where + " AND " + planCond
	} else {
		where = "WHERE " + planCond
	}
	args = append(args, planID)

	dateSQL, dateCount := getDateRangeSQL("date", filter.StartDate, filter.EndDate)
	if dateCount > 0 {
		if filter.StartDate != nil {
			args = append(args, *filter.StartDate)
		}
		if filter.EndDate != nil {
			args = append(args, *filter.EndDate)
		}
		where += dateSQL
	}

	var trunc string
	switch groupBy {
	case AnalyticsGroupByDay:
		trunc = "date"
	case AnalyticsGroupByWeek:
		trunc = "DATE_TRUNC('week', date)"
	case AnalyticsGroupByMonth:
		trunc = "DATE_TRUNC('month', date)"
	case AnalyticsGroupByYear:
		trunc = "DATE_TRUNC('year', date)"
	default:
		trunc = "date"
	}

	query := fmt.Sprintf(`
		SELECT
			%s AS period,
			SUM(upgrade_in_count) AS upgrade_in,
			SUM(upgrade_out_count) AS upgrade_out,
			SUM(downgrade_in_count) AS downgrade_in,
			SUM(downgrade_out_count) AS downgrade_out,
			SUM(lateral_in_count) AS lateral_in,
			SUM(lateral_out_count) AS lateral_out,
			SUM(net_change) AS net_change
		FROM subscription_analytics.daily_plan_change_metrics
		%s
		GROUP BY period
		ORDER BY period
	`, trunc, where)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get plan change trend: %w", err)
	}
	defer rows.Close()

	var results []*models.PlanChangeTrendMetric
	for rows.Next() {
		var period time.Time
		var metric models.PlanChangeTrendMetric
		if err := rows.Scan(
			&period,
			&metric.UpgradeIn,
			&metric.UpgradeOut,
			&metric.DowngradeIn,
			&metric.DowngradeOut,
			&metric.LateralIn,
			&metric.LateralOut,
			&metric.NetChange,
		); err != nil {
			return nil, fmt.Errorf("scan plan change trend: %w", err)
		}
		metric.Period = period
		results = append(results, &metric)
	}
	return results, rows.Err()
}
