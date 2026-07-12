// service/analytics_query_service.go

package service

import (
	"auth-service/internal/subscription/models"
	"auth-service/internal/subscription/repository"
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AnalyticsQueryService defines the read-only analytics operations.
type AnalyticsQueryService interface {
	GetDashboard(ctx context.Context, filter repository.AnalyticsFilter) (*models.SubscriptionDashboard, error)
	GetSubscriptionMetrics(ctx context.Context, filter repository.AnalyticsFilter) (*models.SubscriptionMetrics, error)
	GetRevenueMetrics(ctx context.Context, filter repository.AnalyticsFilter) (*models.RevenueMetrics, error)
	GetMRR(ctx context.Context, filter repository.AnalyticsFilter) (string, error) // returns decimal as string
	GetARR(ctx context.Context, filter repository.AnalyticsFilter) (string, error)
	GetChurnMetrics(ctx context.Context, filter repository.AnalyticsFilter) (*models.ChurnMetrics, error)
	GetTrialMetrics(ctx context.Context, filter repository.AnalyticsFilter) (*models.TrialMetrics, error)
	GetTopPlans(ctx context.Context, filter repository.AnalyticsFilter, limit int) ([]*models.PlanAnalyticsMetric, error)
	GetTopAddons(ctx context.Context, filter repository.AnalyticsFilter, limit int) ([]*models.AddonAnalyticsMetric, error)
	GetTopCustomers(ctx context.Context, filter repository.AnalyticsFilter, limit int) ([]*models.CustomerAnalyticsMetric, error)
	GetUsageMetrics(ctx context.Context, filter repository.AnalyticsFilter) (*models.UsageMetrics, error)
	GetTopFeatures(ctx context.Context, filter repository.AnalyticsFilter, limit int) ([]*models.FeatureUsageMetric, error)
	GetRenewalMetrics(ctx context.Context, filter repository.AnalyticsFilter) (*models.RenewalMetrics, error)
	GetUpcomingRenewals(ctx context.Context, filter repository.AnalyticsFilter, beforeDays int) ([]*models.SubscriptionRenewalMetric, error)
	GetPlanChangeMetrics(ctx context.Context, filter repository.AnalyticsFilter, planID string) (*models.PlanChangeMetricsSummary, error)
	GetPlanChangeTrend(ctx context.Context, filter repository.AnalyticsFilter, planID string, groupBy repository.AnalyticsGroupBy) ([]*models.PlanChangeTrendMetric, error)
}

type analyticsQueryService struct {
	repo   repository.AnalyticsRepository
	db     *sql.DB
	logger *zap.Logger
}

// NewAnalyticsQueryService creates a new instance of the query service.
func NewAnalyticsQueryService(
	repo repository.AnalyticsRepository,
	db *sql.DB,
	logger *zap.Logger,
) AnalyticsQueryService {
	return &analyticsQueryService{
		repo:   repo,
		db:     db,
		logger: logger.Named("analytics_query_service"),
	}
}

// GetDashboard returns a full dashboard summary.
func (s *analyticsQueryService) GetDashboard(ctx context.Context, filter repository.AnalyticsFilter) (*models.SubscriptionDashboard, error) {
	return s.repo.GetDashboard(ctx, s.db, filter)
}

// GetSubscriptionMetrics returns counts by subscription status.
func (s *analyticsQueryService) GetSubscriptionMetrics(ctx context.Context, filter repository.AnalyticsFilter) (*models.SubscriptionMetrics, error) {
	return s.repo.GetSubscriptionMetrics(ctx, s.db, filter)
}

// GetRevenueMetrics returns revenue aggregates.
func (s *analyticsQueryService) GetRevenueMetrics(ctx context.Context, filter repository.AnalyticsFilter) (*models.RevenueMetrics, error) {
	return s.repo.GetRevenueMetrics(ctx, s.db, filter)
}

// GetMRR returns the Monthly Recurring Revenue as a string.
func (s *analyticsQueryService) GetMRR(ctx context.Context, filter repository.AnalyticsFilter) (string, error) {
	mrr, err := s.repo.GetMRR(ctx, s.db, filter)
	if err != nil {
		return "", err
	}
	return mrr.String(), nil
}

// GetARR returns the Annual Recurring Revenue as a string.
func (s *analyticsQueryService) GetARR(ctx context.Context, filter repository.AnalyticsFilter) (string, error) {
	arr, err := s.repo.GetARR(ctx, s.db, filter)
	if err != nil {
		return "", err
	}
	return arr.String(), nil
}

// GetChurnMetrics returns churn statistics.
func (s *analyticsQueryService) GetChurnMetrics(ctx context.Context, filter repository.AnalyticsFilter) (*models.ChurnMetrics, error) {
	return s.repo.GetChurnMetrics(ctx, s.db, filter)
}

// GetTrialMetrics returns trial conversion and expiration data.
func (s *analyticsQueryService) GetTrialMetrics(ctx context.Context, filter repository.AnalyticsFilter) (*models.TrialMetrics, error) {
	return s.repo.GetTrialMetrics(ctx, s.db, filter)
}

// GetTopPlans returns the most popular plans.
func (s *analyticsQueryService) GetTopPlans(ctx context.Context, filter repository.AnalyticsFilter, limit int) ([]*models.PlanAnalyticsMetric, error) {
	return s.repo.GetTopPlans(ctx, s.db, filter, limit)
}

// GetTopAddons returns the most used add-ons.
func (s *analyticsQueryService) GetTopAddons(ctx context.Context, filter repository.AnalyticsFilter, limit int) ([]*models.AddonAnalyticsMetric, error) {
	return s.repo.GetTopAddons(ctx, s.db, filter, limit)
}

// GetTopCustomers returns customers with the highest spend.
func (s *analyticsQueryService) GetTopCustomers(ctx context.Context, filter repository.AnalyticsFilter, limit int) ([]*models.CustomerAnalyticsMetric, error) {
	return s.repo.GetTopCustomers(ctx, s.db, filter, limit)
}

// GetUsageMetrics returns usage aggregations.
func (s *analyticsQueryService) GetUsageMetrics(ctx context.Context, filter repository.AnalyticsFilter) (*models.UsageMetrics, error) {
	return s.repo.GetUsageMetrics(ctx, s.db, filter)
}

// GetTopFeatures returns features with the highest usage.
func (s *analyticsQueryService) GetTopFeatures(ctx context.Context, filter repository.AnalyticsFilter, limit int) ([]*models.FeatureUsageMetric, error) {
	return s.repo.GetTopFeatures(ctx, s.db, filter, limit)
}

// GetRenewalMetrics returns renewal counts.
func (s *analyticsQueryService) GetRenewalMetrics(ctx context.Context, filter repository.AnalyticsFilter) (*models.RenewalMetrics, error) {
	return s.repo.GetRenewalMetrics(ctx, s.db, filter)
}

// GetUpcomingRenewals returns subscriptions that will renew within the next 'beforeDays' days.
func (s *analyticsQueryService) GetUpcomingRenewals(ctx context.Context, filter repository.AnalyticsFilter, beforeDays int) ([]*models.SubscriptionRenewalMetric, error) {
	// Calculate the cutoff date: now + beforeDays
	cutoff := time.Now().AddDate(0, 0, beforeDays)
	return s.repo.GetUpcomingRenewals(ctx, s.db, filter, cutoff)
}

// GetPlanChangeMetrics returns aggregate plan change statistics for a given plan.
func (s *analyticsQueryService) GetPlanChangeMetrics(ctx context.Context, filter repository.AnalyticsFilter, planID string) (*models.PlanChangeMetricsSummary, error) {
	planUUID, err := uuid.Parse(planID)
	if err != nil {
		return nil, err
	}
	return s.repo.GetPlanChangeMetrics(ctx, s.db, filter, planUUID)
}

// GetPlanChangeTrend returns plan change trends over time.
func (s *analyticsQueryService) GetPlanChangeTrend(ctx context.Context, filter repository.AnalyticsFilter, planID string, groupBy repository.AnalyticsGroupBy) ([]*models.PlanChangeTrendMetric, error) {
	planUUID, err := uuid.Parse(planID)
	if err != nil {
		return nil, err
	}
	return s.repo.GetPlanChangeTrend(ctx, s.db, filter, planUUID, groupBy)
}
