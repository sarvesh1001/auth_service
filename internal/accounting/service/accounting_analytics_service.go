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
	"auth-service/internal/accounting/repository"
	"auth-service/internal/client"
)

type AccountingAnalyticsService interface {
	ProcessJournalEvent(ctx context.Context, eventType string, payload []byte) error
	ProcessLedgerEvent(ctx context.Context, eventType string, payload []byte) error
}

type accountingAnalyticsService struct {
	analyticsRepo repository.AnalyticsRepository
	pgClient      *client.PostgresClient
	logger        *zap.Logger
}

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
