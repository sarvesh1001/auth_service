// FILE: ./repository/analytics_repository.go

package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/accounting/models"
	"auth-service/internal/accounting/models/analytics"
	"auth-service/internal/util"
)

// =====================================================
// FILTERS
// =====================================================

type DailySummaryFilter struct {
	CompanyID uuid.UUID
	AccountID *uuid.UUID
	FromDate  *time.Time
	ToDate    *time.Time
}

type SnapshotFilter struct {
	CompanyID    uuid.UUID
	AccountID    *uuid.UUID
	SnapshotDate *time.Time
	FromDate     *time.Time
	ToDate       *time.Time
	FiscalYear   *int
	Period       *int
}

type JournalMetricFilter struct {
	CompanyID   uuid.UUID
	JournalType *string
	FromDate    *time.Time
	ToDate      *time.Time
}

type TaxSummaryFilter struct {
	CompanyID uuid.UUID
	TaxRateID *uuid.UUID
	FromDate  *time.Time
	ToDate    *time.Time
}

type CashflowFilter struct {
	CompanyID uuid.UUID
	FromDate  *time.Time
	ToDate    *time.Time
}

// =====================================================
// ANALYTICS REPOSITORY INTERFACE
// =====================================================

type AnalyticsRepository interface {
	// Daily Account Summary
	UpsertDailySummary(ctx context.Context, db DBTX, summary *analytics.DailyAccountSummary) error
	GetDailySummary(ctx context.Context, db DBTX, summaryID uuid.UUID) (*analytics.DailyAccountSummary, error)
	GetDailySummaryByKey(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, date time.Time) (*analytics.DailyAccountSummary, error)
	ListDailySummaries(ctx context.Context, db DBTX, filter DailySummaryFilter, p Pagination, s Sort) ([]*analytics.DailyAccountSummary, error)
	DeleteDailySummary(ctx context.Context, db DBTX, summaryID uuid.UUID) error
	DeleteDailySummariesByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) error
	InvalidateDailySummaries(ctx context.Context, db DBTX, companyID uuid.UUID, fromDate, toDate *time.Time) error

	// Account Snapshots
	UpsertSnapshot(ctx context.Context, db DBTX, snapshot *analytics.AccountSnapshot) error
	GetSnapshot(ctx context.Context, db DBTX, snapshotID uuid.UUID) (*analytics.AccountSnapshot, error)
	GetSnapshotByKey(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, snapshotDate time.Time) (*analytics.AccountSnapshot, error)
	ListSnapshots(ctx context.Context, db DBTX, filter SnapshotFilter, p Pagination, s Sort) ([]*analytics.AccountSnapshot, error)
	DeleteSnapshot(ctx context.Context, db DBTX, snapshotID uuid.UUID) error
	DeleteSnapshotsByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) error

	// Journal Metrics
	UpsertJournalMetric(ctx context.Context, db DBTX, metric *analytics.JournalMetric) error
	GetJournalMetric(ctx context.Context, db DBTX, metricID uuid.UUID) (*analytics.JournalMetric, error)
	GetJournalMetricByKey(ctx context.Context, db DBTX, companyID uuid.UUID, journalType string, date time.Time) (*analytics.JournalMetric, error)
	ListJournalMetrics(ctx context.Context, db DBTX, filter JournalMetricFilter, p Pagination, s Sort) ([]*analytics.JournalMetric, error)
	DeleteJournalMetric(ctx context.Context, db DBTX, metricID uuid.UUID) error
	DeleteJournalMetricsByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) error

	// Tax Summary
	UpsertTaxSummary(ctx context.Context, db DBTX, summary *analytics.TaxSummary) error
	GetTaxSummary(ctx context.Context, db DBTX, summaryID uuid.UUID) (*analytics.TaxSummary, error)
	GetTaxSummaryByKey(ctx context.Context, db DBTX, companyID uuid.UUID, taxRateID *uuid.UUID, date time.Time) (*analytics.TaxSummary, error)
	ListTaxSummaries(ctx context.Context, db DBTX, filter TaxSummaryFilter, p Pagination, s Sort) ([]*analytics.TaxSummary, error)
	DeleteTaxSummary(ctx context.Context, db DBTX, summaryID uuid.UUID) error
	DeleteTaxSummariesByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) error
	InvalidateTaxSummaries(ctx context.Context, db DBTX, companyID uuid.UUID, fromDate, toDate *time.Time) error

	// Cashflow
	UpsertCashflow(ctx context.Context, db DBTX, cashflow *analytics.Cashflow) error
	GetCashflow(ctx context.Context, db DBTX, cashflowID uuid.UUID) (*analytics.Cashflow, error)
	GetCashflowByKey(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time) (*analytics.Cashflow, error)
	ListCashflows(ctx context.Context, db DBTX, filter CashflowFilter, p Pagination, s Sort) ([]*analytics.Cashflow, error)
	DeleteCashflow(ctx context.Context, db DBTX, cashflowID uuid.UUID) error
	DeleteCashflowsByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) error
	TryMarkEventProcessed(
		ctx context.Context,
		db DBTX,
		eventID string,
		consumerGroup string,
	) (bool, error) // Snapshot Calculation
	CalculateAndStoreSnapshotBulk(ctx context.Context, db DBTX, companyID uuid.UUID, snapshotDate time.Time) error

	// Reconciliation Analytics
	GetReconciliationBatchMetrics(ctx context.Context, db DBTX, batchID uuid.UUID) (*analytics.ReconciliationBatchMetrics, error)
	ListReconciliationBatchMetrics(ctx context.Context, db DBTX, companyID uuid.UUID, limit, offset int) ([]*analytics.ReconciliationBatchMetrics, error)
	UpsertReconciliationDailyStats(ctx context.Context, db DBTX, stats *analytics.ReconciliationDailyStats) error
	GetReconciliationDailyStats(ctx context.Context, db DBTX, companyID uuid.UUID, reconciliationType string, date time.Time) (*analytics.ReconciliationDailyStats, error)
	ListReconciliationDailyStats(ctx context.Context, db DBTX, companyID uuid.UUID, fromDate, toDate time.Time) ([]*analytics.ReconciliationDailyStats, error)
	InsertReconciliationDiffTrend(ctx context.Context, db DBTX, trend *analytics.ReconciliationDiffTrends) error
	ListReconciliationDiffTrends(ctx context.Context, db DBTX, companyID uuid.UUID, fromDate, toDate time.Time) ([]*analytics.ReconciliationDiffTrends, error)

	// === NEW METHODS (Source of truth from ledger) ===
	GetAccountBalanceFromLedger(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, asOf time.Time) (decimal.Decimal, error)
	GetTrialBalance(ctx context.Context, db DBTX, companyID uuid.UUID, fromDate, toDate time.Time) ([]*models.TrialBalanceRow, error)
	GetAccountBalanceByFiscalPeriod(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, fiscalYear, period int) (decimal.Decimal, error)
	RecomputeRunningBalance(ctx context.Context, db DBTX, accountID uuid.UUID) error
}

// =====================================================
// IMPLEMENTATION
// =====================================================

type analyticsRepository struct {
	logger *zap.Logger
}

func NewAnalyticsRepository(logger *zap.Logger) AnalyticsRepository {
	return &analyticsRepository{
		logger: logger.Named("analytics_repo"),
	}
}

// =====================================================
// HELPERS (sort & pagination)
// =====================================================

var allowedDailySummarySortFields = map[string]bool{
	"date":         true,
	"total_debit":  true,
	"total_credit": true,
	"net_movement": true,
	"created_at":   true,
}

var allowedSnapshotSortFields = map[string]bool{
	"snapshot_date": true,
	"balance":       true,
	"fiscal_year":   true,
	"period":        true,
	"created_at":    true,
}

var allowedJournalMetricSortFields = map[string]bool{
	"date":          true,
	"journal_type":  true,
	"total_entries": true,
	"total_amount":  true,
	"created_at":    true,
}

var allowedTaxSummarySortFields = map[string]bool{
	"date":              true,
	"total_taxable":     true,
	"total_tax":         true,
	"transaction_count": true,
	"created_at":        true,
}

var allowedCashflowSortFields = map[string]bool{
	"date":         true,
	"inflow":       true,
	"outflow":      true,
	"net_cashflow": true,
	"created_at":   true,
}

func (r *analyticsRepository) validateSort(allowed map[string]bool, s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "date"
	}
	if !allowed[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY %s %s", field, dir), nil
}

func (r *analyticsRepository) validatePagination(p Pagination) (int, int) {
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

// =====================================================
// 1. DAILY ACCOUNT SUMMARY
// =====================================================

func (r *analyticsRepository) UpsertDailySummary(ctx context.Context, db DBTX, s *analytics.DailyAccountSummary) error {
	query := `
		INSERT INTO accounting.analytics_daily_account_summary (
			summary_id, company_id, account_id, date,
			total_debit, total_credit, transaction_count, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		ON CONFLICT (company_id, account_id, date)
		DO UPDATE SET
			total_debit = EXCLUDED.total_debit,
			total_credit = EXCLUDED.total_credit,
			transaction_count = EXCLUDED.transaction_count
		RETURNING created_at
	`
	err := db.QueryRowContext(ctx, query,
		s.SummaryID, s.CompanyID, s.AccountID, s.Date,
		s.TotalDebit, s.TotalCredit, s.TransactionCount,
	).Scan(&s.CreatedAt)
	if err != nil {
		r.logger.Error("failed to upsert daily summary",
			util.String("company_id", s.CompanyID.String()),
			util.String("account_id", s.AccountID.String()),
			util.Time("date", s.Date),
			util.ErrorField(err))
		return fmt.Errorf("upsert daily summary: %w", err)
	}
	return nil
}

func (r *analyticsRepository) GetDailySummary(ctx context.Context, db DBTX, summaryID uuid.UUID) (*analytics.DailyAccountSummary, error) {
	query := `
		SELECT summary_id, company_id, account_id, date,
		       total_debit, total_credit, net_movement, transaction_count, created_at
		FROM accounting.analytics_daily_account_summary
		WHERE summary_id = $1
	`
	var s analytics.DailyAccountSummary
	err := db.QueryRowContext(ctx, query, summaryID).Scan(
		&s.SummaryID, &s.CompanyID, &s.AccountID, &s.Date,
		&s.TotalDebit, &s.TotalCredit, &s.NetMovement, &s.TransactionCount, &s.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get daily summary",
			util.String("summary_id", summaryID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get daily summary: %w", err)
	}
	return &s, nil
}

func (r *analyticsRepository) GetDailySummaryByKey(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, date time.Time) (*analytics.DailyAccountSummary, error) {
	query := `
		SELECT summary_id, company_id, account_id, date,
		       total_debit, total_credit, net_movement, transaction_count, created_at
		FROM accounting.analytics_daily_account_summary
		WHERE company_id = $1 AND account_id = $2 AND date = $3
	`
	var s analytics.DailyAccountSummary
	err := db.QueryRowContext(ctx, query, companyID, accountID, date).Scan(
		&s.SummaryID, &s.CompanyID, &s.AccountID, &s.Date,
		&s.TotalDebit, &s.TotalCredit, &s.NetMovement, &s.TransactionCount, &s.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get daily summary by key",
			util.String("company_id", companyID.String()),
			util.String("account_id", accountID.String()),
			util.Time("date", date),
			util.ErrorField(err))
		return nil, fmt.Errorf("get daily summary by key: %w", err)
	}
	return &s, nil
}

func (r *analyticsRepository) ListDailySummaries(ctx context.Context, db DBTX, filter DailySummaryFilter, p Pagination, s Sort) ([]*analytics.DailyAccountSummary, error) {
	where, args := r.buildDailySummaryFilter(filter)
	orderBy, err := r.validateSort(allowedDailySummarySortFields, s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT summary_id, company_id, account_id, date,
		       total_debit, total_credit, net_movement, transaction_count, created_at
		FROM accounting.analytics_daily_account_summary
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list daily summaries",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list daily summaries: %w", err)
	}
	defer rows.Close()

	var results []*analytics.DailyAccountSummary
	for rows.Next() {
		var s analytics.DailyAccountSummary
		err := rows.Scan(
			&s.SummaryID, &s.CompanyID, &s.AccountID, &s.Date,
			&s.TotalDebit, &s.TotalCredit, &s.NetMovement, &s.TransactionCount, &s.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan daily summary: %w", err)
		}
		results = append(results, &s)
	}
	return results, nil
}

func (r *analyticsRepository) DeleteDailySummary(ctx context.Context, db DBTX, summaryID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM accounting.analytics_daily_account_summary WHERE summary_id = $1`, summaryID)
	if err != nil {
		r.logger.Error("failed to delete daily summary",
			util.String("summary_id", summaryID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete daily summary: %w", err)
	}
	return nil
}

func (r *analyticsRepository) DeleteDailySummariesByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM accounting.analytics_daily_account_summary WHERE company_id = $1`, companyID)
	if err != nil {
		r.logger.Error("failed to delete daily summaries by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete daily summaries by company: %w", err)
	}
	return nil
}

func (r *analyticsRepository) InvalidateDailySummaries(ctx context.Context, db DBTX, companyID uuid.UUID, fromDate, toDate *time.Time) error {
	query := `
		DELETE FROM accounting.analytics_daily_account_summary
		WHERE company_id = $1
		  AND ($2::date IS NULL OR date >= $2)
		  AND ($3::date IS NULL OR date <= $3)
	`
	_, err := db.ExecContext(ctx, query, companyID, fromDate, toDate)
	if err != nil {
		r.logger.Error("failed to invalidate daily summaries",
			util.String("company_id", companyID.String()),
			util.Any("from_date", fromDate),
			util.Any("to_date", toDate),
			util.ErrorField(err))
		return fmt.Errorf("invalidate daily summaries: %w", err)
	}
	return nil
}

func (r *analyticsRepository) buildDailySummaryFilter(filter DailySummaryFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.AccountID != nil {
		conditions = append(conditions, fmt.Sprintf("account_id = $%d", idx))
		args = append(args, *filter.AccountID)
		idx++
	}
	if filter.FromDate != nil {
		conditions = append(conditions, fmt.Sprintf("date >= $%d", idx))
		args = append(args, *filter.FromDate)
		idx++
	}
	if filter.ToDate != nil {
		conditions = append(conditions, fmt.Sprintf("date <= $%d", idx))
		args = append(args, *filter.ToDate)
		idx++
	}
	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

// =====================================================
// 2. ACCOUNT SNAPSHOTS
// =====================================================

func (r *analyticsRepository) UpsertSnapshot(ctx context.Context, db DBTX, s *analytics.AccountSnapshot) error {
	query := `
		INSERT INTO accounting.analytics_account_snapshots (
			snapshot_id, company_id, account_id, snapshot_date,
			balance, fiscal_year, period, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		ON CONFLICT (company_id, account_id, snapshot_date)
		DO UPDATE SET
			balance = EXCLUDED.balance,
			fiscal_year = EXCLUDED.fiscal_year,
			period = EXCLUDED.period
		RETURNING created_at
	`
	err := db.QueryRowContext(ctx, query,
		s.SnapshotID, s.CompanyID, s.AccountID, s.SnapshotDate,
		s.Balance, s.FiscalYear, s.Period,
	).Scan(&s.CreatedAt)
	if err != nil {
		r.logger.Error("failed to upsert snapshot",
			util.String("company_id", s.CompanyID.String()),
			util.String("account_id", s.AccountID.String()),
			util.Time("snapshot_date", s.SnapshotDate),
			util.ErrorField(err))
		return fmt.Errorf("upsert snapshot: %w", err)
	}
	return nil
}

func (r *analyticsRepository) GetSnapshot(ctx context.Context, db DBTX, snapshotID uuid.UUID) (*analytics.AccountSnapshot, error) {
	query := `
		SELECT snapshot_id, company_id, account_id, snapshot_date,
		       balance, fiscal_year, period, created_at
		FROM accounting.analytics_account_snapshots
		WHERE snapshot_id = $1
	`
	var s analytics.AccountSnapshot
	err := db.QueryRowContext(ctx, query, snapshotID).Scan(
		&s.SnapshotID, &s.CompanyID, &s.AccountID, &s.SnapshotDate,
		&s.Balance, &s.FiscalYear, &s.Period, &s.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get snapshot",
			util.String("snapshot_id", snapshotID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get snapshot: %w", err)
	}
	return &s, nil
}

func (r *analyticsRepository) GetSnapshotByKey(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, snapshotDate time.Time) (*analytics.AccountSnapshot, error) {
	query := `
		SELECT snapshot_id, company_id, account_id, snapshot_date,
		       balance, fiscal_year, period, created_at
		FROM accounting.analytics_account_snapshots
		WHERE company_id = $1 AND account_id = $2 AND snapshot_date = $3
	`
	var s analytics.AccountSnapshot
	err := db.QueryRowContext(ctx, query, companyID, accountID, snapshotDate).Scan(
		&s.SnapshotID, &s.CompanyID, &s.AccountID, &s.SnapshotDate,
		&s.Balance, &s.FiscalYear, &s.Period, &s.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get snapshot by key",
			util.String("company_id", companyID.String()),
			util.String("account_id", accountID.String()),
			util.Time("snapshot_date", snapshotDate),
			util.ErrorField(err))
		return nil, fmt.Errorf("get snapshot by key: %w", err)
	}
	return &s, nil
}

func (r *analyticsRepository) ListSnapshots(ctx context.Context, db DBTX, filter SnapshotFilter, p Pagination, s Sort) ([]*analytics.AccountSnapshot, error) {
	where, args := r.buildSnapshotFilter(filter)
	orderBy, err := r.validateSort(allowedSnapshotSortFields, s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT snapshot_id, company_id, account_id, snapshot_date,
		       balance, fiscal_year, period, created_at
		FROM accounting.analytics_account_snapshots
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list snapshots",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list snapshots: %w", err)
	}
	defer rows.Close()

	var results []*analytics.AccountSnapshot
	for rows.Next() {
		var s analytics.AccountSnapshot
		err := rows.Scan(
			&s.SnapshotID, &s.CompanyID, &s.AccountID, &s.SnapshotDate,
			&s.Balance, &s.FiscalYear, &s.Period, &s.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan snapshot: %w", err)
		}
		results = append(results, &s)
	}
	return results, nil
}

func (r *analyticsRepository) DeleteSnapshot(ctx context.Context, db DBTX, snapshotID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM accounting.analytics_account_snapshots WHERE snapshot_id = $1`, snapshotID)
	if err != nil {
		r.logger.Error("failed to delete snapshot",
			util.String("snapshot_id", snapshotID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete snapshot: %w", err)
	}
	return nil
}

func (r *analyticsRepository) DeleteSnapshotsByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM accounting.analytics_account_snapshots WHERE company_id = $1`, companyID)
	if err != nil {
		r.logger.Error("failed to delete snapshots by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete snapshots by company: %w", err)
	}
	return nil
}

func (r *analyticsRepository) buildSnapshotFilter(filter SnapshotFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.AccountID != nil {
		conditions = append(conditions, fmt.Sprintf("account_id = $%d", idx))
		args = append(args, *filter.AccountID)
		idx++
	}
	if filter.SnapshotDate != nil {
		conditions = append(conditions, fmt.Sprintf("snapshot_date = $%d", idx))
		args = append(args, *filter.SnapshotDate)
		idx++
	}
	if filter.FromDate != nil {
		conditions = append(conditions, fmt.Sprintf("snapshot_date >= $%d", idx))
		args = append(args, *filter.FromDate)
		idx++
	}
	if filter.ToDate != nil {
		conditions = append(conditions, fmt.Sprintf("snapshot_date <= $%d", idx))
		args = append(args, *filter.ToDate)
		idx++
	}
	if filter.FiscalYear != nil {
		conditions = append(conditions, fmt.Sprintf("fiscal_year = $%d", idx))
		args = append(args, *filter.FiscalYear)
		idx++
	}
	if filter.Period != nil {
		conditions = append(conditions, fmt.Sprintf("period = $%d", idx))
		args = append(args, *filter.Period)
		idx++
	}
	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

// =====================================================
// 3. JOURNAL METRICS
// =====================================================

func (r *analyticsRepository) UpsertJournalMetric(ctx context.Context, db DBTX, m *analytics.JournalMetric) error {
	query := `
		INSERT INTO accounting.analytics_journal_metrics (
			metric_id, company_id, journal_type, date,
			total_entries, total_amount, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, NOW())
		ON CONFLICT (company_id, journal_type, date)
		DO UPDATE SET
			total_entries = EXCLUDED.total_entries,
			total_amount = EXCLUDED.total_amount
		RETURNING created_at
	`
	err := db.QueryRowContext(ctx, query,
		m.MetricID, m.CompanyID, m.JournalType, m.Date,
		m.TotalEntries, m.TotalAmount,
	).Scan(&m.CreatedAt)
	if err != nil {
		journalTypeLog := "nil"
		if m.JournalType != nil {
			journalTypeLog = *m.JournalType
		}
		r.logger.Error("failed to upsert journal metric",
			util.String("company_id", m.CompanyID.String()),
			util.String("journal_type", journalTypeLog),
			util.Time("date", m.Date),
			util.ErrorField(err))
		return fmt.Errorf("upsert journal metric: %w", err)
	}
	return nil
}

func (r *analyticsRepository) GetJournalMetric(ctx context.Context, db DBTX, metricID uuid.UUID) (*analytics.JournalMetric, error) {
	query := `
		SELECT metric_id, company_id, journal_type, date,
		       total_entries, total_amount, created_at
		FROM accounting.analytics_journal_metrics
		WHERE metric_id = $1
	`
	var m analytics.JournalMetric
	err := db.QueryRowContext(ctx, query, metricID).Scan(
		&m.MetricID, &m.CompanyID, &m.JournalType, &m.Date,
		&m.TotalEntries, &m.TotalAmount, &m.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get journal metric",
			util.String("metric_id", metricID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get journal metric: %w", err)
	}
	return &m, nil
}

func (r *analyticsRepository) GetJournalMetricByKey(ctx context.Context, db DBTX, companyID uuid.UUID, journalType string, date time.Time) (*analytics.JournalMetric, error) {
	query := `
		SELECT metric_id, company_id, journal_type, date,
		       total_entries, total_amount, created_at
		FROM accounting.analytics_journal_metrics
		WHERE company_id = $1 AND journal_type = $2 AND date = $3
	`
	var m analytics.JournalMetric
	err := db.QueryRowContext(ctx, query, companyID, journalType, date).Scan(
		&m.MetricID, &m.CompanyID, &m.JournalType, &m.Date,
		&m.TotalEntries, &m.TotalAmount, &m.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get journal metric by key",
			util.String("company_id", companyID.String()),
			util.String("journal_type", journalType),
			util.Time("date", date),
			util.ErrorField(err))
		return nil, fmt.Errorf("get journal metric by key: %w", err)
	}
	return &m, nil
}

func (r *analyticsRepository) ListJournalMetrics(ctx context.Context, db DBTX, filter JournalMetricFilter, p Pagination, s Sort) ([]*analytics.JournalMetric, error) {
	where, args := r.buildJournalMetricFilter(filter)
	orderBy, err := r.validateSort(allowedJournalMetricSortFields, s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT metric_id, company_id, journal_type, date,
		       total_entries, total_amount, created_at
		FROM accounting.analytics_journal_metrics
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list journal metrics",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list journal metrics: %w", err)
	}
	defer rows.Close()

	var results []*analytics.JournalMetric
	for rows.Next() {
		var m analytics.JournalMetric
		err := rows.Scan(
			&m.MetricID, &m.CompanyID, &m.JournalType, &m.Date,
			&m.TotalEntries, &m.TotalAmount, &m.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan journal metric: %w", err)
		}
		results = append(results, &m)
	}
	return results, nil
}

func (r *analyticsRepository) DeleteJournalMetric(ctx context.Context, db DBTX, metricID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM accounting.analytics_journal_metrics WHERE metric_id = $1`, metricID)
	if err != nil {
		r.logger.Error("failed to delete journal metric",
			util.String("metric_id", metricID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete journal metric: %w", err)
	}
	return nil
}

func (r *analyticsRepository) DeleteJournalMetricsByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM accounting.analytics_journal_metrics WHERE company_id = $1`, companyID)
	if err != nil {
		r.logger.Error("failed to delete journal metrics by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete journal metrics by company: %w", err)
	}
	return nil
}

func (r *analyticsRepository) buildJournalMetricFilter(filter JournalMetricFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.JournalType != nil {
		conditions = append(conditions, fmt.Sprintf("journal_type = $%d", idx))
		args = append(args, *filter.JournalType)
		idx++
	}
	if filter.FromDate != nil {
		conditions = append(conditions, fmt.Sprintf("date >= $%d", idx))
		args = append(args, *filter.FromDate)
		idx++
	}
	if filter.ToDate != nil {
		conditions = append(conditions, fmt.Sprintf("date <= $%d", idx))
		args = append(args, *filter.ToDate)
		idx++
	}
	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

// =====================================================
// 4. TAX SUMMARY
// =====================================================

func (r *analyticsRepository) UpsertTaxSummary(ctx context.Context, db DBTX, s *analytics.TaxSummary) error {
	query := `
		INSERT INTO accounting.analytics_tax_summary (
			summary_id, company_id, tax_rate_id, date,
			total_taxable, total_tax, transaction_count, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		ON CONFLICT (company_id, tax_rate_id, date)
		DO UPDATE SET
			total_taxable = EXCLUDED.total_taxable,
			total_tax = EXCLUDED.total_tax,
			transaction_count = EXCLUDED.transaction_count
		RETURNING created_at
	`
	err := db.QueryRowContext(ctx, query,
		s.SummaryID, s.CompanyID, s.TaxRateID, s.Date,
		s.TotalTaxable, s.TotalTax, s.TransactionCount,
	).Scan(&s.CreatedAt)
	if err != nil {
		taxRateLog := "nil"
		if s.TaxRateID != nil {
			taxRateLog = s.TaxRateID.String()
		}
		r.logger.Error("failed to upsert tax summary",
			util.String("company_id", s.CompanyID.String()),
			util.String("tax_rate_id", taxRateLog),
			util.Time("date", s.Date),
			util.ErrorField(err))
		return fmt.Errorf("upsert tax summary: %w", err)
	}
	return nil
}

func (r *analyticsRepository) GetTaxSummary(ctx context.Context, db DBTX, summaryID uuid.UUID) (*analytics.TaxSummary, error) {
	query := `
		SELECT summary_id, company_id, tax_rate_id, date,
		       total_taxable, total_tax, transaction_count, created_at
		FROM accounting.analytics_tax_summary
		WHERE summary_id = $1
	`
	var s analytics.TaxSummary
	err := db.QueryRowContext(ctx, query, summaryID).Scan(
		&s.SummaryID, &s.CompanyID, &s.TaxRateID, &s.Date,
		&s.TotalTaxable, &s.TotalTax, &s.TransactionCount, &s.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get tax summary",
			util.String("summary_id", summaryID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get tax summary: %w", err)
	}
	return &s, nil
}

func (r *analyticsRepository) GetTaxSummaryByKey(ctx context.Context, db DBTX, companyID uuid.UUID, taxRateID *uuid.UUID, date time.Time) (*analytics.TaxSummary, error) {
	query := `
		SELECT summary_id, company_id, tax_rate_id, date,
		       total_taxable, total_tax, transaction_count, created_at
		FROM accounting.analytics_tax_summary
		WHERE company_id = $1 AND tax_rate_id IS NOT DISTINCT FROM $2 AND date = $3
	`
	var s analytics.TaxSummary
	err := db.QueryRowContext(ctx, query, companyID, taxRateID, date).Scan(
		&s.SummaryID, &s.CompanyID, &s.TaxRateID, &s.Date,
		&s.TotalTaxable, &s.TotalTax, &s.TransactionCount, &s.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		taxRateLog := "nil"
		if taxRateID != nil {
			taxRateLog = taxRateID.String()
		}
		r.logger.Error("failed to get tax summary by key",
			util.String("company_id", companyID.String()),
			util.String("tax_rate_id", taxRateLog),
			util.Time("date", date),
			util.ErrorField(err))
		return nil, fmt.Errorf("get tax summary by key: %w", err)
	}
	return &s, nil
}

func (r *analyticsRepository) ListTaxSummaries(ctx context.Context, db DBTX, filter TaxSummaryFilter, p Pagination, s Sort) ([]*analytics.TaxSummary, error) {
	where, args := r.buildTaxSummaryFilter(filter)
	orderBy, err := r.validateSort(allowedTaxSummarySortFields, s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT summary_id, company_id, tax_rate_id, date,
		       total_taxable, total_tax, transaction_count, created_at
		FROM accounting.analytics_tax_summary
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list tax summaries",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list tax summaries: %w", err)
	}
	defer rows.Close()

	var results []*analytics.TaxSummary
	for rows.Next() {
		var s analytics.TaxSummary
		err := rows.Scan(
			&s.SummaryID, &s.CompanyID, &s.TaxRateID, &s.Date,
			&s.TotalTaxable, &s.TotalTax, &s.TransactionCount, &s.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan tax summary: %w", err)
		}
		results = append(results, &s)
	}
	return results, nil
}

func (r *analyticsRepository) DeleteTaxSummary(ctx context.Context, db DBTX, summaryID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM accounting.analytics_tax_summary WHERE summary_id = $1`, summaryID)
	if err != nil {
		r.logger.Error("failed to delete tax summary",
			util.String("summary_id", summaryID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete tax summary: %w", err)
	}
	return nil
}

func (r *analyticsRepository) DeleteTaxSummariesByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM accounting.analytics_tax_summary WHERE company_id = $1`, companyID)
	if err != nil {
		r.logger.Error("failed to delete tax summaries by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete tax summaries by company: %w", err)
	}
	return nil
}

func (r *analyticsRepository) InvalidateTaxSummaries(ctx context.Context, db DBTX, companyID uuid.UUID, fromDate, toDate *time.Time) error {
	query := `
		DELETE FROM accounting.analytics_tax_summary
		WHERE company_id = $1
		  AND ($2::date IS NULL OR date >= $2)
		  AND ($3::date IS NULL OR date <= $3)
	`
	_, err := db.ExecContext(ctx, query, companyID, fromDate, toDate)
	if err != nil {
		r.logger.Error("failed to invalidate tax summaries",
			util.String("company_id", companyID.String()),
			util.Any("from_date", fromDate),
			util.Any("to_date", toDate),
			util.ErrorField(err))
		return fmt.Errorf("invalidate tax summaries: %w", err)
	}
	return nil
}

func (r *analyticsRepository) buildTaxSummaryFilter(filter TaxSummaryFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.TaxRateID != nil {
		conditions = append(conditions, fmt.Sprintf("tax_rate_id = $%d", idx))
		args = append(args, *filter.TaxRateID)
		idx++
	}
	if filter.FromDate != nil {
		conditions = append(conditions, fmt.Sprintf("date >= $%d", idx))
		args = append(args, *filter.FromDate)
		idx++
	}
	if filter.ToDate != nil {
		conditions = append(conditions, fmt.Sprintf("date <= $%d", idx))
		args = append(args, *filter.ToDate)
		idx++
	}
	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

// =====================================================
// 5. CASHFLOW
// =====================================================

func (r *analyticsRepository) UpsertCashflow(ctx context.Context, db DBTX, c *analytics.Cashflow) error {
	query := `
		INSERT INTO accounting.analytics_cashflow (
			cashflow_id, company_id, date, inflow, outflow, created_at
		) VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (company_id, date)
		DO UPDATE SET
			inflow = EXCLUDED.inflow,
			outflow = EXCLUDED.outflow
		RETURNING created_at
	`
	err := db.QueryRowContext(ctx, query,
		c.CashflowID, c.CompanyID, c.Date, c.Inflow, c.Outflow,
	).Scan(&c.CreatedAt)
	if err != nil {
		r.logger.Error("failed to upsert cashflow",
			util.String("company_id", c.CompanyID.String()),
			util.Time("date", c.Date),
			util.ErrorField(err))
		return fmt.Errorf("upsert cashflow: %w", err)
	}
	return nil
}

func (r *analyticsRepository) GetCashflow(ctx context.Context, db DBTX, cashflowID uuid.UUID) (*analytics.Cashflow, error) {
	query := `
		SELECT cashflow_id, company_id, date, inflow, outflow, net_cashflow, created_at
		FROM accounting.analytics_cashflow
		WHERE cashflow_id = $1
	`
	var c analytics.Cashflow
	err := db.QueryRowContext(ctx, query, cashflowID).Scan(
		&c.CashflowID, &c.CompanyID, &c.Date, &c.Inflow, &c.Outflow, &c.NetCashflow, &c.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get cashflow",
			util.String("cashflow_id", cashflowID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get cashflow: %w", err)
	}
	return &c, nil
}

func (r *analyticsRepository) GetCashflowByKey(ctx context.Context, db DBTX, companyID uuid.UUID, date time.Time) (*analytics.Cashflow, error) {
	query := `
		SELECT cashflow_id, company_id, date, inflow, outflow, net_cashflow, created_at
		FROM accounting.analytics_cashflow
		WHERE company_id = $1 AND date = $2
	`
	var c analytics.Cashflow
	err := db.QueryRowContext(ctx, query, companyID, date).Scan(
		&c.CashflowID, &c.CompanyID, &c.Date, &c.Inflow, &c.Outflow, &c.NetCashflow, &c.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get cashflow by key",
			util.String("company_id", companyID.String()),
			util.Time("date", date),
			util.ErrorField(err))
		return nil, fmt.Errorf("get cashflow by key: %w", err)
	}
	return &c, nil
}

func (r *analyticsRepository) ListCashflows(ctx context.Context, db DBTX, filter CashflowFilter, p Pagination, s Sort) ([]*analytics.Cashflow, error) {
	where, args := r.buildCashflowFilter(filter)
	orderBy, err := r.validateSort(allowedCashflowSortFields, s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT cashflow_id, company_id, date, inflow, outflow, net_cashflow, created_at
		FROM accounting.analytics_cashflow
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list cashflows",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list cashflows: %w", err)
	}
	defer rows.Close()

	var results []*analytics.Cashflow
	for rows.Next() {
		var c analytics.Cashflow
		err := rows.Scan(
			&c.CashflowID, &c.CompanyID, &c.Date, &c.Inflow, &c.Outflow, &c.NetCashflow, &c.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan cashflow: %w", err)
		}
		results = append(results, &c)
	}
	return results, nil
}

func (r *analyticsRepository) DeleteCashflow(ctx context.Context, db DBTX, cashflowID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM accounting.analytics_cashflow WHERE cashflow_id = $1`, cashflowID)
	if err != nil {
		r.logger.Error("failed to delete cashflow",
			util.String("cashflow_id", cashflowID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete cashflow: %w", err)
	}
	return nil
}

func (r *analyticsRepository) DeleteCashflowsByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM accounting.analytics_cashflow WHERE company_id = $1`, companyID)
	if err != nil {
		r.logger.Error("failed to delete cashflows by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete cashflows by company: %w", err)
	}
	return nil
}

func (r *analyticsRepository) buildCashflowFilter(filter CashflowFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.FromDate != nil {
		conditions = append(conditions, fmt.Sprintf("date >= $%d", idx))
		args = append(args, *filter.FromDate)
		idx++
	}
	if filter.ToDate != nil {
		conditions = append(conditions, fmt.Sprintf("date <= $%d", idx))
		args = append(args, *filter.ToDate)
		idx++
	}
	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

// =====================================================
// 6. BULK SNAPSHOT CALCULATION (CORRECTED)
// =====================================================

// CalculateAndStoreSnapshotBulk computes account balances up to snapshotDate for ALL accounts
// using a single INSERT ... SELECT with proper account‑type logic and posted filtering.
func (r *analyticsRepository) CalculateAndStoreSnapshotBulk(ctx context.Context, db DBTX, companyID uuid.UUID, snapshotDate time.Time) error {
	query := `
		INSERT INTO accounting.analytics_account_snapshots (snapshot_id, company_id, account_id, snapshot_date, balance, created_at)
		SELECT
			gen_random_uuid(),
			a.company_id,
			a.account_id,
			$2,
			COALESCE(SUM(
				CASE
					WHEN a.account_type IN ('asset', 'expense') THEN jl.debit_amount - jl.credit_amount
					ELSE jl.credit_amount - jl.debit_amount
				END
			), 0) AS balance,
			NOW()
		FROM accounting.accounts a
		JOIN accounting.journal_lines jl ON a.account_id = jl.account_id
		JOIN accounting.journal_entries je ON jl.journal_entry_id = je.journal_entry_id
			AND je.company_id = a.company_id
			AND je.status = 'posted'
			AND je.entry_date <= $2
		WHERE a.company_id = $1
		  AND a.deleted_at IS NULL
		GROUP BY a.company_id, a.account_id
		ON CONFLICT (company_id, account_id, snapshot_date)
		DO UPDATE SET
			balance = EXCLUDED.balance,
			created_at = NOW()
	`
	_, err := db.ExecContext(ctx, query, companyID, snapshotDate)
	if err != nil {
		r.logger.Error("failed to calculate and store snapshots in bulk",
			util.String("company_id", companyID.String()),
			util.Time("snapshot_date", snapshotDate),
			util.ErrorField(err))
		return fmt.Errorf("bulk snapshot calculation: %w", err)
	}
	return nil
}

// =====================================================
// 7. RECONCILIATION BATCH METRICS
// =====================================================

func (r *analyticsRepository) GetReconciliationBatchMetrics(ctx context.Context, db DBTX, batchID uuid.UUID) (*analytics.ReconciliationBatchMetrics, error) {
	query := `
		SELECT metric_id, batch_id, company_id, reconciliation_type,
		       total_items, matched_items, unmatched_items, ignored_items, match_rate,
		       started_at, completed_at, completion_duration_seconds,
		       total_differences, resolved_differences, total_adjustments, adjustment_amount,
		       created_at, updated_at
		FROM accounting.analytics_reconciliation_batch_metrics
		WHERE batch_id = $1
	`
	var m analytics.ReconciliationBatchMetrics
	err := db.QueryRowContext(ctx, query, batchID).Scan(
		&m.MetricID, &m.BatchID, &m.CompanyID, &m.ReconciliationType,
		&m.TotalItems, &m.MatchedItems, &m.UnmatchedItems, &m.IgnoredItems, &m.MatchRate,
		&m.StartedAt, &m.CompletedAt, &m.CompletionDurationSeconds,
		&m.TotalDifferences, &m.ResolvedDifferences, &m.TotalAdjustments, &m.AdjustmentAmount,
		&m.CreatedAt, &m.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get reconciliation batch metrics: %w", err)
	}
	return &m, nil
}

func (r *analyticsRepository) ListReconciliationBatchMetrics(ctx context.Context, db DBTX, companyID uuid.UUID, limit, offset int) ([]*analytics.ReconciliationBatchMetrics, error) {
	query := `
		SELECT metric_id, batch_id, company_id, reconciliation_type,
		       total_items, matched_items, unmatched_items, ignored_items, match_rate,
		       started_at, completed_at, completion_duration_seconds,
		       total_differences, resolved_differences, total_adjustments, adjustment_amount,
		       created_at, updated_at
		FROM accounting.analytics_reconciliation_batch_metrics
		WHERE company_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	rows, err := db.QueryContext(ctx, query, companyID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list reconciliation batch metrics: %w", err)
	}
	defer rows.Close()

	var results []*analytics.ReconciliationBatchMetrics
	for rows.Next() {
		var m analytics.ReconciliationBatchMetrics
		err := rows.Scan(
			&m.MetricID, &m.BatchID, &m.CompanyID, &m.ReconciliationType,
			&m.TotalItems, &m.MatchedItems, &m.UnmatchedItems, &m.IgnoredItems, &m.MatchRate,
			&m.StartedAt, &m.CompletedAt, &m.CompletionDurationSeconds,
			&m.TotalDifferences, &m.ResolvedDifferences, &m.TotalAdjustments, &m.AdjustmentAmount,
			&m.CreatedAt, &m.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan batch metrics: %w", err)
		}
		results = append(results, &m)
	}
	return results, nil
}

// =====================================================
// 8. RECONCILIATION DAILY STATS
// =====================================================

func (r *analyticsRepository) UpsertReconciliationDailyStats(ctx context.Context, db DBTX, stats *analytics.ReconciliationDailyStats) error {
	query := `
		INSERT INTO accounting.analytics_reconciliation_daily_stats (
			stat_id, company_id, reconciliation_type, date,
			batches_started, batches_completed,
			total_items_processed, total_matched, total_unmatched, total_ignored,
			avg_match_rate, avg_completion_seconds,
			differences_created, differences_resolved,
			adjustments_created, total_adjustment_amount,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW(), NOW())
		ON CONFLICT (company_id, reconciliation_type, date) DO UPDATE SET
			batches_started = EXCLUDED.batches_started,
			batches_completed = EXCLUDED.batches_completed,
			total_items_processed = EXCLUDED.total_items_processed,
			total_matched = EXCLUDED.total_matched,
			total_unmatched = EXCLUDED.total_unmatched,
			total_ignored = EXCLUDED.total_ignored,
			avg_match_rate = EXCLUDED.avg_match_rate,
			avg_completion_seconds = EXCLUDED.avg_completion_seconds,
			differences_created = EXCLUDED.differences_created,
			differences_resolved = EXCLUDED.differences_resolved,
			adjustments_created = EXCLUDED.adjustments_created,
			total_adjustment_amount = EXCLUDED.total_adjustment_amount,
			updated_at = NOW()
	`
	_, err := db.ExecContext(ctx, query,
		stats.StatID, stats.CompanyID, stats.ReconciliationType, stats.Date,
		stats.BatchesStarted, stats.BatchesCompleted,
		stats.TotalItemsProcessed, stats.TotalMatched, stats.TotalUnmatched, stats.TotalIgnored,
		stats.AvgMatchRate, stats.AvgCompletionSeconds,
		stats.DifferencesCreated, stats.DifferencesResolved,
		stats.AdjustmentsCreated, stats.TotalAdjustmentAmount,
	)
	if err != nil {
		return fmt.Errorf("upsert reconciliation daily stats: %w", err)
	}
	return nil
}

func (r *analyticsRepository) GetReconciliationDailyStats(ctx context.Context, db DBTX, companyID uuid.UUID, reconciliationType string, date time.Time) (*analytics.ReconciliationDailyStats, error) {
	query := `
		SELECT stat_id, company_id, reconciliation_type, date,
		       batches_started, batches_completed,
		       total_items_processed, total_matched, total_unmatched, total_ignored,
		       avg_match_rate, avg_completion_seconds,
		       differences_created, differences_resolved,
		       adjustments_created, total_adjustment_amount,
		       created_at, updated_at
		FROM accounting.analytics_reconciliation_daily_stats
		WHERE company_id = $1 AND reconciliation_type = $2 AND date = $3
	`
	var s analytics.ReconciliationDailyStats
	err := db.QueryRowContext(ctx, query, companyID, reconciliationType, date).Scan(
		&s.StatID, &s.CompanyID, &s.ReconciliationType, &s.Date,
		&s.BatchesStarted, &s.BatchesCompleted,
		&s.TotalItemsProcessed, &s.TotalMatched, &s.TotalUnmatched, &s.TotalIgnored,
		&s.AvgMatchRate, &s.AvgCompletionSeconds,
		&s.DifferencesCreated, &s.DifferencesResolved,
		&s.AdjustmentsCreated, &s.TotalAdjustmentAmount,
		&s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get reconciliation daily stats: %w", err)
	}
	return &s, nil
}

func (r *analyticsRepository) ListReconciliationDailyStats(ctx context.Context, db DBTX, companyID uuid.UUID, fromDate, toDate time.Time) ([]*analytics.ReconciliationDailyStats, error) {
	query := `
		SELECT stat_id, company_id, reconciliation_type, date,
		       batches_started, batches_completed,
		       total_items_processed, total_matched, total_unmatched, total_ignored,
		       avg_match_rate, avg_completion_seconds,
		       differences_created, differences_resolved,
		       adjustments_created, total_adjustment_amount,
		       created_at, updated_at
		FROM accounting.analytics_reconciliation_daily_stats
		WHERE company_id = $1 AND date BETWEEN $2 AND $3
		ORDER BY date DESC
	`
	rows, err := db.QueryContext(ctx, query, companyID, fromDate, toDate)
	if err != nil {
		return nil, fmt.Errorf("list reconciliation daily stats: %w", err)
	}
	defer rows.Close()

	var results []*analytics.ReconciliationDailyStats
	for rows.Next() {
		var s analytics.ReconciliationDailyStats
		err := rows.Scan(
			&s.StatID, &s.CompanyID, &s.ReconciliationType, &s.Date,
			&s.BatchesStarted, &s.BatchesCompleted,
			&s.TotalItemsProcessed, &s.TotalMatched, &s.TotalUnmatched, &s.TotalIgnored,
			&s.AvgMatchRate, &s.AvgCompletionSeconds,
			&s.DifferencesCreated, &s.DifferencesResolved,
			&s.AdjustmentsCreated, &s.TotalAdjustmentAmount,
			&s.CreatedAt, &s.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan daily stats: %w", err)
		}
		results = append(results, &s)
	}
	return results, nil
}

// =====================================================
// 9. RECONCILIATION DIFFERENCE TRENDS (UPDATED TO DECIMAL)
// =====================================================

func (r *analyticsRepository) InsertReconciliationDiffTrend(ctx context.Context, db DBTX, trend *analytics.ReconciliationDiffTrends) error {
	query := `
		INSERT INTO accounting.analytics_reconciliation_diff_trends (
			trend_id, company_id, batch_id, issue_type, date,
			count, total_expected_amount, total_actual_amount, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
	`
	_, err := db.ExecContext(ctx, query,
		trend.TrendID, trend.CompanyID, trend.BatchID, trend.IssueType, trend.Date,
		trend.Count, trend.TotalExpectedAmount, trend.TotalActualAmount,
	)
	if err != nil {
		return fmt.Errorf("insert reconciliation diff trend: %w", err)
	}
	return nil
}

func (r *analyticsRepository) ListReconciliationDiffTrends(ctx context.Context, db DBTX, companyID uuid.UUID, fromDate, toDate time.Time) ([]*analytics.ReconciliationDiffTrends, error) {
	query := `
		SELECT trend_id, company_id, batch_id, issue_type, date,
		       count, total_expected_amount, total_actual_amount, total_variance, created_at
		FROM accounting.analytics_reconciliation_diff_trends
		WHERE company_id = $1 AND date BETWEEN $2 AND $3
		ORDER BY date DESC
	`
	rows, err := db.QueryContext(ctx, query, companyID, fromDate, toDate)
	if err != nil {
		return nil, fmt.Errorf("list reconciliation diff trends: %w", err)
	}
	defer rows.Close()

	var results []*analytics.ReconciliationDiffTrends
	for rows.Next() {
		var t analytics.ReconciliationDiffTrends
		err := rows.Scan(
			&t.TrendID, &t.CompanyID, &t.BatchID, &t.IssueType, &t.Date,
			&t.Count, &t.TotalExpectedAmount, &t.TotalActualAmount, &t.TotalVariance, &t.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan diff trend: %w", err)
		}
		results = append(results, &t)
	}
	return results, nil
}

// =====================================================
// 10. NEW METHODS (Source of truth from ledger)
// =====================================================

// GetAccountBalanceFromLedger returns the net balance of an account up to a given date,
// respecting the account type direction.
func (r *analyticsRepository) GetAccountBalanceFromLedger(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, asOf time.Time) (decimal.Decimal, error) {
	query := `
		SELECT COALESCE(SUM(
			CASE
				WHEN a.account_type IN ('asset', 'expense') THEN le.debit_amount - le.credit_amount
				ELSE le.credit_amount - le.debit_amount
			END
		), 0)
		FROM accounting.ledger_entries le
		JOIN accounting.accounts a ON le.account_id = a.account_id
		WHERE le.company_id = $1
		  AND le.account_id = $2
		  AND le.entry_date <= $3
	`
	var balance decimal.Decimal
	err := db.QueryRowContext(ctx, query, companyID, accountID, asOf).Scan(&balance)
	if err != nil {
		r.logger.Error("failed to get account balance from ledger",
			util.String("company_id", companyID.String()),
			util.String("account_id", accountID.String()),
			util.Time("as_of", asOf),
			util.ErrorField(err))
		return decimal.Zero, fmt.Errorf("get account balance from ledger: %w", err)
	}
	return balance, nil
}

// GetTrialBalance returns debit/credit totals per account for a period.
func (r *analyticsRepository) GetTrialBalance(ctx context.Context, db DBTX, companyID uuid.UUID, fromDate, toDate time.Time) ([]*models.TrialBalanceRow, error) {
	query := `
		SELECT
			a.account_id,
			a.account_name,
			COALESCE(SUM(jl.debit_amount), 0) AS debit_total,
			COALESCE(SUM(jl.credit_amount), 0) AS credit_total,
			CASE
				WHEN a.account_type IN ('asset', 'expense') THEN
					COALESCE(SUM(jl.debit_amount), 0) - COALESCE(SUM(jl.credit_amount), 0)
				ELSE
					COALESCE(SUM(jl.credit_amount), 0) - COALESCE(SUM(jl.debit_amount), 0)
			END AS balance
		FROM accounting.accounts a
		LEFT JOIN accounting.journal_lines jl ON a.account_id = jl.account_id
		LEFT JOIN accounting.journal_entries je ON jl.journal_entry_id = je.journal_entry_id
			AND je.status = 'posted'
			AND je.entry_date BETWEEN $2 AND $3
		WHERE a.company_id = $1 AND a.deleted_at IS NULL
		GROUP BY a.account_id, a.account_name, a.account_type
		ORDER BY a.account_code
	`
	rows, err := db.QueryContext(ctx, query, companyID, fromDate, toDate)
	if err != nil {
		r.logger.Error("failed to get trial balance",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get trial balance: %w", err)
	}
	defer rows.Close()

	var results []*models.TrialBalanceRow
	for rows.Next() {
		var row models.TrialBalanceRow
		err := rows.Scan(&row.AccountID, &row.AccountName, &row.DebitTotal, &row.CreditTotal, &row.Balance)
		if err != nil {
			return nil, fmt.Errorf("scan trial balance row: %w", err)
		}
		results = append(results, &row)
	}
	return results, nil
}

// GetAccountBalanceByFiscalPeriod returns balance for a specific fiscal year and period.
func (r *analyticsRepository) GetAccountBalanceByFiscalPeriod(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, fiscalYear, period int) (decimal.Decimal, error) {
	query := `
		SELECT closing_balance
		FROM accounting.account_balances
		WHERE company_id = $1 AND account_id = $2 AND fiscal_year = $3 AND period = $4
	`
	var balance decimal.Decimal
	err := db.QueryRowContext(ctx, query, companyID, accountID, fiscalYear, period).Scan(&balance)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return decimal.Zero, nil // no balance recorded yet, treat as zero
		}
		r.logger.Error("failed to get balance by fiscal period",
			util.String("company_id", companyID.String()),
			util.String("account_id", accountID.String()),
			util.Int("fiscal_year", fiscalYear),
			util.Int("period", period),
			util.ErrorField(err))
		return decimal.Zero, fmt.Errorf("get balance by fiscal period: %w", err)
	}
	return balance, nil
}

// RecomputeRunningBalance recomputes the running_balance column for a given account
// over all its ledger entries, ordered by entry_date and created_at.
func (r *analyticsRepository) RecomputeRunningBalance(ctx context.Context, db DBTX, accountID uuid.UUID) error {
	query := `
		WITH ordered AS (
			SELECT ledger_entry_id,
			       debit_amount,
			       credit_amount,
			       ROW_NUMBER() OVER (ORDER BY entry_date, created_at, ledger_entry_id) AS rn
			FROM accounting.ledger_entries
			WHERE account_id = $1
		),
		balanced AS (
			SELECT ledger_entry_id,
			       debit_amount,
			       credit_amount,
			       SUM(debit_amount - credit_amount) OVER (ORDER BY rn) AS running
			FROM ordered
		)
		UPDATE accounting.ledger_entries
		SET running_balance = balanced.running
		FROM balanced
		WHERE ledger_entries.ledger_entry_id = balanced.ledger_entry_id
	`
	_, err := db.ExecContext(ctx, query, accountID)
	if err != nil {
		r.logger.Error("failed to recompute running balance",
			util.String("account_id", accountID.String()),
			util.ErrorField(err))
		return fmt.Errorf("recompute running balance: %w", err)
	}
	return nil
}

// =====================================================
// 11. KAFKA IDEMPOTENCY
// =====================================================
func (r *analyticsRepository) TryMarkEventProcessed(
	ctx context.Context,
	db DBTX,
	eventID string,
	consumerGroup string,
) (bool, error) {

	query := `
		INSERT INTO accounting.processed_events (event_id, consumer_group)
		VALUES ($1, $2)
		ON CONFLICT (event_id, consumer_group) DO NOTHING
		RETURNING event_id
	`

	var id string
	err := db.QueryRowContext(ctx, query, eventID, consumerGroup).Scan(&id)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil // already processed
		}
		return false, err
	}

	return true, nil // first time
}
