package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/accounting/events"
	"auth-service/internal/accounting/models/analytics"
	"auth-service/internal/accounting/models/settings"
	"auth-service/internal/accounting/repository"
	"auth-service/internal/client"
)

// AccountingAnalyticsService defines the interface for processing accounting analytics events
// and retrieving analytics data.
type AccountingAnalyticsService interface {
	// Event processing methods
	ProcessJournalEvent(ctx context.Context, eventType string, payload []byte) error
	ProcessLedgerEvent(ctx context.Context, eventType string, payload []byte) error
	ProcessAccountEvent(ctx context.Context, eventType string, payload []byte) error
	ProcessSettingsEvent(ctx context.Context, eventType string, settings *settings.AccountingSettings) error

	// Query methods for DailyAccountSummary
	GetDailySummary(ctx context.Context, companyID, summaryID uuid.UUID) (*analytics.DailyAccountSummary, error)
	ListDailySummaries(ctx context.Context, companyID uuid.UUID, filter repository.DailySummaryFilter, pagination repository.Pagination, sort repository.Sort) ([]*analytics.DailyAccountSummary, error)

	// Query methods for AccountSnapshot
	GetSnapshot(ctx context.Context, companyID, snapshotID uuid.UUID) (*analytics.AccountSnapshot, error)
	ListSnapshots(ctx context.Context, companyID uuid.UUID, filter repository.SnapshotFilter, pagination repository.Pagination, sort repository.Sort) ([]*analytics.AccountSnapshot, error)

	// Query methods for JournalMetric
	GetJournalMetric(ctx context.Context, companyID, metricID uuid.UUID) (*analytics.JournalMetric, error)
	ListJournalMetrics(ctx context.Context, companyID uuid.UUID, filter repository.JournalMetricFilter, pagination repository.Pagination, sort repository.Sort) ([]*analytics.JournalMetric, error)

	// Query methods for Cashflow
	GetCashflow(ctx context.Context, companyID, cashflowID uuid.UUID) (*analytics.Cashflow, error)
	ListCashflows(ctx context.Context, companyID uuid.UUID, filter repository.CashflowFilter, pagination repository.Pagination, sort repository.Sort) ([]*analytics.Cashflow, error)
}

type accountingAnalyticsService struct {
	analyticsRepo repository.AnalyticsRepository
	pgClient      *client.PostgresClient
	logger        *zap.Logger
}

// NewAccountingAnalyticsService creates a new accounting analytics service.
func NewAccountingAnalyticsService(
	repo repository.AnalyticsRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) AccountingAnalyticsService {
	return &accountingAnalyticsService{
		analyticsRepo: repo,
		pgClient:      pgClient,
		logger:        logger.Named("accounting_analytics"),
	}
}

// ---------------------------------------------------------------------
// Journal event processing
// ---------------------------------------------------------------------

func (s *accountingAnalyticsService) ProcessJournalEvent(
	ctx context.Context,
	eventType string,
	payload []byte,
) error {
	logger := s.logger.With(zap.String("event_type", eventType))

	var evt events.JournalEventPayload
	if err := json.Unmarshal(payload, &evt); err != nil {
		logger.Error("failed to unmarshal journal event payload", zap.Error(err))
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	companyID, err := uuid.Parse(evt.CompanyID)
	if err != nil {
		logger.Error("invalid company_id in event", zap.String("company_id", evt.CompanyID), zap.Error(err))
		return fmt.Errorf("invalid company_id: %w", err)
	}

	entryDate := evt.EntryDate
	db := s.pgClient.DB

	switch eventType {
	case events.EventJournalCreated, events.EventJournalUpdated, events.EventJournalPosted, events.EventJournalReversed:
		if err := s.processJournalLines(ctx, db, companyID, entryDate, evt.JournalType, evt.Lines); err != nil {
			logger.Error("failed to process journal lines", zap.Error(err))
			return err
		}
		if err := s.updateJournalMetric(ctx, db, companyID, evt.JournalType, entryDate, evt.TotalDebit); err != nil {
			logger.Error("failed to update journal metric", zap.Error(err))
		}
		if err := s.updateAccountSnapshots(ctx, db, companyID, entryDate); err != nil {
			logger.Error("failed to update account snapshots", zap.Error(err))
		}
	default:
		logger.Debug("ignored event type")
	}

	return nil
}

func (s *accountingAnalyticsService) processJournalLines(
	ctx context.Context,
	db repository.DBTX,
	companyID uuid.UUID,
	entryDate time.Time,
	journalType string,
	lines []events.LinePayload,
) error {
	for _, line := range lines {
		accountID, err := uuid.Parse(line.AccountID)
		if err != nil {
			s.logger.Error("invalid account_id in line", zap.String("account_id", line.AccountID), zap.Error(err))
			continue
		}

		debit, err := decimal.NewFromString(line.DebitAmount)
		if err != nil {
			s.logger.Error("invalid debit amount", zap.String("debit", line.DebitAmount), zap.Error(err))
			continue
		}

		credit, err := decimal.NewFromString(line.CreditAmount)
		if err != nil {
			s.logger.Error("invalid credit amount", zap.String("credit", line.CreditAmount), zap.Error(err))
			continue
		}

		netMovement := debit.Sub(credit)
		summary := &analytics.DailyAccountSummary{
			SummaryID:        uuid.New(),
			CompanyID:        companyID,
			AccountID:        accountID,
			Date:             entryDate,
			TotalDebit:       debit,
			TotalCredit:      credit,
			NetMovement:      netMovement,
			TransactionCount: 1,
		}

		if err := s.analyticsRepo.UpsertDailySummary(ctx, db, summary); err != nil {
			s.logger.Error("failed to upsert daily summary",
				zap.String("account_id", line.AccountID),
				zap.Error(err))
		}
	}
	return nil
}

func (s *accountingAnalyticsService) updateJournalMetric(
	ctx context.Context,
	db repository.DBTX,
	companyID uuid.UUID,
	journalType string,
	date time.Time,
	totalAmountStr string,
) error {
	totalAmount, err := decimal.NewFromString(totalAmountStr)
	if err != nil {
		return fmt.Errorf("parse total amount: %w", err)
	}

	metric := &analytics.JournalMetric{
		MetricID:     uuid.New(),
		CompanyID:    companyID,
		JournalType:  &journalType,
		Date:         date,
		TotalEntries: 1,
		TotalAmount:  totalAmount,
	}
	return s.analyticsRepo.UpsertJournalMetric(ctx, db, metric)
}

func (s *accountingAnalyticsService) updateAccountSnapshots(
	ctx context.Context,
	db repository.DBTX,
	companyID uuid.UUID,
	date time.Time,
) error {
	// Use the optimised bulk version instead of per‑account loops
	return s.analyticsRepo.CalculateAndStoreSnapshotBulk(ctx, db, companyID, date)
}

// ---------------------------------------------------------------------
// Ledger event processing
// ---------------------------------------------------------------------

func (s *accountingAnalyticsService) ProcessLedgerEvent(
	ctx context.Context,
	eventType string,
	payload []byte,
) error {
	logger := s.logger.With(zap.String("event_type", eventType))

	var evt events.LedgerEventPayload
	if err := json.Unmarshal(payload, &evt); err != nil {
		logger.Error("failed to unmarshal ledger event payload", zap.Error(err))
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	companyID, err := uuid.Parse(evt.CompanyID)
	if err != nil {
		logger.Error("invalid company_id in event", zap.String("company_id", evt.CompanyID), zap.Error(err))
		return fmt.Errorf("invalid company_id: %w", err)
	}

	db := s.pgClient.DB

	switch eventType {
	case events.EventLedgerUpdated, events.EventLedgerReversed:
		for _, entry := range evt.Entries {
			accountID, err := uuid.Parse(entry.AccountID)
			if err != nil {
				logger.Error("invalid account_id in ledger entry", zap.String("account_id", entry.AccountID), zap.Error(err))
				continue
			}

			balanceAfter, err := decimal.NewFromString(entry.BalanceAfter)
			if err != nil {
				logger.Error("invalid balance_after", zap.String("balance_after", entry.BalanceAfter), zap.Error(err))
				continue
			}

			// 1. Store account snapshot
			snapshot := &analytics.AccountSnapshot{
				SnapshotID:   uuid.New(),
				CompanyID:    companyID,
				AccountID:    accountID,
				SnapshotDate: evt.PostingDate,
				Balance:      balanceAfter,
				FiscalYear:   &entry.FiscalYear,
				Period:       &entry.Period,
			}
			if err := s.analyticsRepo.UpsertSnapshot(ctx, db, snapshot); err != nil {
				logger.Error("failed to upsert account snapshot",
					zap.String("account_id", entry.AccountID),
					zap.Error(err))
			}

			// 2. Update cashflow if account is a cash account (real DB lookup)
			isCash, err := s.isCashAccount(ctx, db, accountID)
			if err != nil {
				logger.Error("failed to check if account is cash account",
					zap.String("account_id", entry.AccountID),
					zap.Error(err))
				continue
			}
			if isCash {
				amount, err := decimal.NewFromString(entry.Amount)
				if err != nil {
					logger.Error("invalid amount", zap.String("amount", entry.Amount), zap.Error(err))
					continue
				}
				var inflow, outflow decimal.Decimal
				if amount.GreaterThan(decimal.Zero) {
					inflow = amount
					outflow = decimal.Zero
				} else {
					inflow = decimal.Zero
					outflow = amount.Neg()
				}
				cashflow := &analytics.Cashflow{
					CashflowID:  uuid.New(),
					CompanyID:   companyID,
					Date:        evt.PostingDate,
					Inflow:      inflow,
					Outflow:     outflow,
					NetCashflow: amount,
				}
				if err := s.analyticsRepo.UpsertCashflow(ctx, db, cashflow); err != nil {
					logger.Error("failed to upsert cashflow",
						zap.String("account_id", entry.AccountID),
						zap.Error(err))
				}
			}
		}
	default:
		logger.Debug("ignored ledger event type")
	}

	return nil
}

// isCashAccount queries the accounts table to determine if an account is a cash/bank account.
// A cash account is defined as: account_type = 'asset' AND (account_code or account_name contains 'cash' or 'bank').
func (s *accountingAnalyticsService) isCashAccount(ctx context.Context, db repository.DBTX, accountID uuid.UUID) (bool, error) {
	var accountType, accountCode, accountName string
	query := `SELECT account_type, account_code, account_name FROM accounting.accounts WHERE account_id = $1 AND deleted_at IS NULL`
	err := db.QueryRowContext(ctx, query, accountID).Scan(&accountType, &accountCode, &accountName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Account not found – treat as non‑cash
			return false, nil
		}
		return false, fmt.Errorf("fetch account %s: %w", accountID, err)
	}
	if accountType != "asset" {
		return false, nil
	}
	lowerCode := strings.ToLower(accountCode)
	lowerName := strings.ToLower(accountName)
	return strings.Contains(lowerCode, "cash") || strings.Contains(lowerName, "cash") ||
		strings.Contains(lowerCode, "bank") || strings.Contains(lowerName, "bank"), nil
}

// ---------------------------------------------------------------------
// Accounting Settings event processing
// ---------------------------------------------------------------------

// ProcessSettingsEvent handles accounting settings events.
// It logs the change, invalidates affected analytics, and warns about required recomputations.
func (s *accountingAnalyticsService) ProcessSettingsEvent(
	ctx context.Context,
	eventType string,
	settings *settings.AccountingSettings,
) error {
	logger := s.logger.With(
		zap.String("event_type", eventType),
		zap.String("company_id", settings.CompanyID.String()),
		zap.Int("fiscal_year_start_month", settings.FiscalYearStartMonth),
		zap.String("currency_code", settings.CurrencyCode),
		zap.String("tax_scheme", settings.TaxScheme),
		zap.Bool("allow_intercompany_journal", settings.AllowIntercompanyJournal),
		zap.Bool("auto_generate_reversals", settings.AutoGenerateReversals),
	)

	logger.Info("processing accounting settings event")

	// Invalidate tax summaries when tax scheme changes (safety: invalidate all)
	if err := s.analyticsRepo.InvalidateTaxSummaries(ctx, s.pgClient.DB, settings.CompanyID, nil, nil); err != nil {
		logger.Error("failed to invalidate tax summaries after settings change", zap.Error(err))
	}

	logger.Warn("fiscal year start month change may require account balance recomputation",
		zap.Int("new_start_month", settings.FiscalYearStartMonth))

	if settings.CurrencyCode != "" {
		logger.Info("currency code updated – consider refreshing exchange rates",
			zap.String("new_currency", settings.CurrencyCode))
	}

	logger.Debug("settings flags updated",
		zap.Bool("allow_intercompany_journal", settings.AllowIntercompanyJournal),
		zap.Bool("auto_generate_reversals", settings.AutoGenerateReversals))

	return nil
}

// ProcessAccountEvent handles account events (create, update, move, status change, delete).
func (s *accountingAnalyticsService) ProcessAccountEvent(
	ctx context.Context,
	eventType string,
	payload []byte,
) error {
	logger := s.logger.With(zap.String("event_type", eventType))

	var evt events.AccountPayload
	if err := json.Unmarshal(payload, &evt); err != nil {
		logger.Error("failed to unmarshal account event payload", zap.Error(err))
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	logger.Info("processing account event",
		zap.String("account_id", evt.AccountID),
		zap.String("account_code", evt.AccountCode),
		zap.String("account_type", evt.AccountType),
		zap.Bool("is_active", evt.IsActive),
	)

	switch eventType {
	case events.EventAccountCreated:
		// No immediate analytics impact – new account has zero balance.
	case events.EventAccountUpdated:
		logger.Info("account type may have changed – consider invalidating balance caches",
			zap.String("account_id", evt.AccountID))
	case events.EventAccountStatusChanged:
		logger.Info("account status changed – may affect active account lists")
	case events.EventAccountMoved:
		logger.Info("account parent changed – hierarchical roll‑ups may be outdated")
	case events.EventAccountDeleted:
		logger.Info("account soft‑deleted – removing from active analytics sets")
		// Optionally, call a repository method to clean up analytics data for this account.
		// e.g., s.analyticsRepo.DeleteDailySummariesByAccount(ctx, s.pgClient.DB, accountID)
	default:
		logger.Debug("ignored account event type")
	}

	return nil
}

// ---------------------------------------------------------------------
// Query method implementations
// ---------------------------------------------------------------------

// GetDailySummary retrieves a daily summary by ID (and verifies company ownership).
func (s *accountingAnalyticsService) GetDailySummary(ctx context.Context, companyID, summaryID uuid.UUID) (*analytics.DailyAccountSummary, error) {
	summary, err := s.analyticsRepo.GetDailySummary(ctx, s.pgClient.DB, summaryID)
	if err != nil {
		return nil, err
	}
	if summary.CompanyID != companyID {
		return nil, fmt.Errorf("daily summary does not belong to company %s", companyID)
	}
	return summary, nil
}

// ListDailySummaries lists daily summaries for a company with filtering, pagination and sorting.
func (s *accountingAnalyticsService) ListDailySummaries(ctx context.Context, companyID uuid.UUID, filter repository.DailySummaryFilter, pagination repository.Pagination, sort repository.Sort) ([]*analytics.DailyAccountSummary, error) {
	filter.CompanyID = companyID
	return s.analyticsRepo.ListDailySummaries(ctx, s.pgClient.DB, filter, pagination, sort)
}

// GetSnapshot retrieves an account snapshot by ID (and verifies company ownership).
func (s *accountingAnalyticsService) GetSnapshot(ctx context.Context, companyID, snapshotID uuid.UUID) (*analytics.AccountSnapshot, error) {
	snapshot, err := s.analyticsRepo.GetSnapshot(ctx, s.pgClient.DB, snapshotID)
	if err != nil {
		return nil, err
	}
	if snapshot.CompanyID != companyID {
		return nil, fmt.Errorf("snapshot does not belong to company %s", companyID)
	}
	return snapshot, nil
}

// ListSnapshots lists account snapshots for a company with filtering, pagination and sorting.
func (s *accountingAnalyticsService) ListSnapshots(ctx context.Context, companyID uuid.UUID, filter repository.SnapshotFilter, pagination repository.Pagination, sort repository.Sort) ([]*analytics.AccountSnapshot, error) {
	filter.CompanyID = companyID
	return s.analyticsRepo.ListSnapshots(ctx, s.pgClient.DB, filter, pagination, sort)
}

// GetJournalMetric retrieves a journal metric by ID (and verifies company ownership).
func (s *accountingAnalyticsService) GetJournalMetric(ctx context.Context, companyID, metricID uuid.UUID) (*analytics.JournalMetric, error) {
	metric, err := s.analyticsRepo.GetJournalMetric(ctx, s.pgClient.DB, metricID)
	if err != nil {
		return nil, err
	}
	if metric.CompanyID != companyID {
		return nil, fmt.Errorf("journal metric does not belong to company %s", companyID)
	}
	return metric, nil
}

// ListJournalMetrics lists journal metrics for a company with filtering, pagination and sorting.
func (s *accountingAnalyticsService) ListJournalMetrics(ctx context.Context, companyID uuid.UUID, filter repository.JournalMetricFilter, pagination repository.Pagination, sort repository.Sort) ([]*analytics.JournalMetric, error) {
	filter.CompanyID = companyID
	return s.analyticsRepo.ListJournalMetrics(ctx, s.pgClient.DB, filter, pagination, sort)
}

// GetCashflow retrieves a cashflow record by ID (and verifies company ownership).
func (s *accountingAnalyticsService) GetCashflow(ctx context.Context, companyID, cashflowID uuid.UUID) (*analytics.Cashflow, error) {
	cashflow, err := s.analyticsRepo.GetCashflow(ctx, s.pgClient.DB, cashflowID)
	if err != nil {
		return nil, err
	}
	if cashflow.CompanyID != companyID {
		return nil, fmt.Errorf("cashflow does not belong to company %s", companyID)
	}
	return cashflow, nil
}

// ListCashflows lists cashflow records for a company with filtering, pagination and sorting.
func (s *accountingAnalyticsService) ListCashflows(ctx context.Context, companyID uuid.UUID, filter repository.CashflowFilter, pagination repository.Pagination, sort repository.Sort) ([]*analytics.Cashflow, error) {
	filter.CompanyID = companyID
	return s.analyticsRepo.ListCashflows(ctx, s.pgClient.DB, filter, pagination, sort)
}
