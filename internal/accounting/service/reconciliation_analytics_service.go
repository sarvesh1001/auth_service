package service

import (
	"context"
	"time"

	"auth-service/internal/accounting/models/analytics"
	"auth-service/internal/accounting/repository"
	"auth-service/internal/client"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type ReconciliationAnalyticsService interface {
	RefreshDailyStats(ctx context.Context, targetDate time.Time) error
	RefreshDifferenceTrends(ctx context.Context, companyID uuid.UUID, date time.Time) error
}

type reconciliationAnalyticsService struct {
	analyticsRepo repository.AnalyticsRepository
	pgClient      *client.PostgresClient
	logger        *zap.Logger
}

func NewReconciliationAnalyticsService(
	analyticsRepo repository.AnalyticsRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) ReconciliationAnalyticsService {
	return &reconciliationAnalyticsService{
		analyticsRepo: analyticsRepo,
		pgClient:      pgClient,
		logger:        logger.Named("reconciliation_analytics"),
	}
}

// RefreshDailyStats aggregates batch metrics into daily stats.
func (s *reconciliationAnalyticsService) RefreshDailyStats(ctx context.Context, targetDate time.Time) error {
	logger := s.logger.With(zap.Time("target_date", targetDate))

	query := `
		SELECT
			company_id,
			reconciliation_type,
			COUNT(*) as batches_started,
			COUNT(completed_at) as batches_completed,
			SUM(total_items) as total_items_processed,
			SUM(matched_items) as total_matched,
			SUM(unmatched_items) as total_unmatched,
			SUM(ignored_items) as total_ignored,
			AVG(match_rate) as avg_match_rate,
			AVG(completion_duration_seconds) as avg_completion_seconds,
			SUM(total_differences) as differences_created,
			SUM(resolved_differences) as differences_resolved,
			SUM(total_adjustments) as adjustments_created,
			SUM(adjustment_amount) as total_adjustment_amount
		FROM accounting.analytics_reconciliation_batch_metrics
		WHERE DATE(created_at) = $1
		GROUP BY company_id, reconciliation_type
	`
	rows, err := s.pgClient.DB.QueryContext(ctx, query, targetDate)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			companyID             uuid.UUID
			reconciliationType    string
			batchesStarted        int
			batchesCompleted      int
			totalItemsProcessed   int
			totalMatched          int
			totalUnmatched        int
			totalIgnored          int
			avgMatchRate          float64
			avgCompletionSeconds  *float64
			differencesCreated    int
			differencesResolved   int
			adjustmentsCreated    int
			totalAdjustmentAmount float64
		)
		err := rows.Scan(
			&companyID, &reconciliationType,
			&batchesStarted, &batchesCompleted,
			&totalItemsProcessed, &totalMatched, &totalUnmatched, &totalIgnored,
			&avgMatchRate, &avgCompletionSeconds,
			&differencesCreated, &differencesResolved,
			&adjustmentsCreated, &totalAdjustmentAmount,
		)
		if err != nil {
			logger.Error("failed to scan daily aggregation", zap.Error(err))
			continue
		}

		avgSecs := 0
		if avgCompletionSeconds != nil {
			avgSecs = int(*avgCompletionSeconds)
		}

		stats := &analytics.ReconciliationDailyStats{
			StatID:                uuid.New(),
			CompanyID:             companyID,
			ReconciliationType:    reconciliationType,
			Date:                  targetDate,
			BatchesStarted:        batchesStarted,
			BatchesCompleted:      batchesCompleted,
			TotalItemsProcessed:   totalItemsProcessed,
			TotalMatched:          totalMatched,
			TotalUnmatched:        totalUnmatched,
			TotalIgnored:          totalIgnored,
			AvgMatchRate:          avgMatchRate,
			AvgCompletionSeconds:  avgSecs,
			DifferencesCreated:    differencesCreated,
			DifferencesResolved:   differencesResolved,
			AdjustmentsCreated:    adjustmentsCreated,
			TotalAdjustmentAmount: totalAdjustmentAmount,
		}
		if err := s.analyticsRepo.UpsertReconciliationDailyStats(ctx, s.pgClient.DB, stats); err != nil {
			logger.Error("failed to upsert daily stats", zap.Error(err))
		}
	}
	return nil
}

// RefreshDifferenceTrends aggregates unresolved differences by issue type and inserts into analytics_reconciliation_diff_trends.
func (s *reconciliationAnalyticsService) RefreshDifferenceTrends(ctx context.Context, companyID uuid.UUID, date time.Time) error {
	logger := s.logger.With(zap.String("method", "RefreshDifferenceTrends"), zap.String("company_id", companyID.String()), zap.Time("date", date))

	// Aggregate unresolved differences created on the given date.
	query := `
		SELECT
			issue_type,
			COUNT(*) as diff_count,
			SUM(expected_amount) as total_expected,
			SUM(actual_amount) as total_actual
		FROM accounting.reconciliation_differences
		WHERE company_id = $1 AND DATE(created_at) = $2 AND resolved = false
		GROUP BY issue_type
	`
	rows, err := s.pgClient.DB.QueryContext(ctx, query, companyID, date)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var issueType string
		var count int
		var totalExpected, totalActual float64
		if err := rows.Scan(&issueType, &count, &totalExpected, &totalActual); err != nil {
			logger.Error("failed to scan difference aggregation", zap.Error(err))
			continue
		}

		trend := &analytics.ReconciliationDiffTrends{
			TrendID:             uuid.New(),
			CompanyID:           companyID,
			BatchID:             nil, // aggregated across batches
			IssueType:           issueType,
			Date:                date,
			Count:               count,
			TotalExpectedAmount: totalExpected, // float64
			TotalActualAmount:   totalActual,   // float64
		}
		if err := s.analyticsRepo.InsertReconciliationDiffTrend(ctx, s.pgClient.DB, trend); err != nil {
			logger.Error("failed to insert difference trend", zap.Error(err))
		}
	}
	return nil
}
