package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/accounting/events"
	"auth-service/internal/accounting/models"
	"auth-service/internal/accounting/models/enums"
	"auth-service/internal/accounting/repository"
	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
)

type LedgerService interface {
	PostJournalToLedger(ctx context.Context, tx repository.DBTX, entry *models.JournalEntry, lines []*models.JournalLine) error
	ReverseLedgerEntries(ctx context.Context, tx repository.DBTX, originalEntryID uuid.UUID, reversalEntry *models.JournalEntry) error
	GetAccountBalance(ctx context.Context, companyID, accountID uuid.UUID, fiscalYear, period int) (*models.AccountBalance, error)
	RecomputeBalances(ctx context.Context, companyID uuid.UUID, fiscalYear int) error

	// Reporting
	ComputeTrialBalance(ctx context.Context, companyID uuid.UUID, from, to time.Time) ([]*repository.TrialBalanceRow, error)
	ComputePAndL(ctx context.Context, companyID uuid.UUID, from, to time.Time) ([]*repository.PAndLRow, error)
	ComputeBalanceSheet(ctx context.Context, companyID uuid.UUID, asOf time.Time) ([]*repository.BalanceSheetRow, error)
	GetAccountLedger(ctx context.Context, companyID, accountID uuid.UUID, from, to time.Time) ([]*repository.LedgerEntry, error)
	CheckImbalance(ctx context.Context, companyID uuid.UUID, from, to time.Time) error
	UpdateRunningBalances(ctx context.Context, companyID, accountID uuid.UUID) error
}

type ledgerService struct {
	ledgerRepo       repository.LedgerRepository
	journalRepo      repository.JournalRepository
	settingsRepo     repository.AccountingSettingsRepository
	periodLockRepo   repository.PeriodLockRepository
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
}

func NewLedgerService(
	ledgerRepo repository.LedgerRepository,
	journalRepo repository.JournalRepository,
	settingsRepo repository.AccountingSettingsRepository,
	periodLockRepo repository.PeriodLockRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
) LedgerService {
	return &ledgerService{
		ledgerRepo:       ledgerRepo,
		journalRepo:      journalRepo,
		settingsRepo:     settingsRepo,
		periodLockRepo:   periodLockRepo,
		pgClient:         pgClient,
		logger:           logger.Named("ledger_service"),
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
	}
}

// --------------------------------------------------------------------------
// PostJournalToLedger – with period lock final guard and running balance update
// --------------------------------------------------------------------------
func (s *ledgerService) PostJournalToLedger(
	ctx context.Context,
	tx repository.DBTX,
	entry *models.JournalEntry,
	lines []*models.JournalLine,
) error {
	logger := s.logger.With(
		zap.String("method", "PostJournalToLedger"),
		zap.String("journal_id", entry.JournalEntryID.String()),
	)

	fiscalYear, period, err := s.getFiscalPeriod(ctx, entry.CompanyID, entry.EntryDate)
	if err != nil {
		return fmt.Errorf("get fiscal period: %w", err)
	}

	locked, err := s.periodLockRepo.IsLocked(ctx, tx, entry.CompanyID, fiscalYear, period)
	if err != nil {
		return fmt.Errorf("check period lock: %w", err)
	}
	if locked {
		if s.auditService != nil {
			_ = s.auditService.LogAction(ctx, nil, &entry.CompanyID, "ledger", "error", "post_blocked_by_lock",
				&entry.JournalEntryID, "system", nil, nil, nil, map[string]interface{}{
					"fiscal_year": fiscalYear,
					"period":      period,
					"reason":      "period_locked",
				})
		}
		return fmt.Errorf("cannot post to locked period %d-%d", fiscalYear, period)
	}

	accountIDs := make([]uuid.UUID, len(lines))
	for i, line := range lines {
		accountIDs[i] = line.AccountID
	}
	accTypeMap, err := s.ledgerRepo.GetAccountTypesMap(ctx, tx, accountIDs)
	if err != nil {
		return fmt.Errorf("batch get account types: %w", err)
	}

	for _, line := range lines {
		le := &models.LedgerEntry{
			LedgerEntryID:  uuid.New(),
			CompanyID:      entry.CompanyID,
			JournalEntryID: entry.JournalEntryID,
			JournalLineID:  line.JournalLineID,
			AccountID:      line.AccountID,
			EntryDate:      entry.EntryDate,
			DebitAmount:    line.DebitAmount,
			CreditAmount:   line.CreditAmount,
			IsReversal:     entry.ReversalOf != nil,
		}
		if err := s.ledgerRepo.CreateLedgerEntry(ctx, tx, le); err != nil {
			return fmt.Errorf("insert ledger entry for line %s: %w", line.JournalLineID, err)
		}
	}

	for _, line := range lines {
		if err := s.ledgerRepo.EnsureBalance(ctx, tx, entry.CompanyID, line.AccountID, fiscalYear, period); err != nil {
			return fmt.Errorf("ensure balance for account %s: %w", line.AccountID, err)
		}
	}

	eventPayload := events.LedgerEventPayload{
		CompanyID:   entry.CompanyID.String(),
		JournalID:   entry.JournalEntryID.String(),
		PostingDate: entry.EntryDate,
		Entries:     []events.LedgerEntryPayload{},
	}

	for _, line := range lines {
		accType, ok := accTypeMap[line.AccountID]
		if !ok {
			return fmt.Errorf("account type not found for %s", line.AccountID)
		}

		var delta decimal.Decimal
		if accType == enums.AccountTypeAsset || accType == enums.AccountTypeExpense {
			delta = line.DebitAmount.Sub(line.CreditAmount)
		} else {
			delta = line.CreditAmount.Sub(line.DebitAmount)
		}

		if err := s.ledgerRepo.AtomicAddToBalance(ctx, tx, entry.CompanyID, line.AccountID, fiscalYear, period, delta); err != nil {
			return fmt.Errorf("atomic add to balance for account %s: %w", line.AccountID, err)
		}

		balance, err := s.ledgerRepo.GetBalance(ctx, tx, entry.CompanyID, line.AccountID, fiscalYear, period)
		if err != nil {
			return fmt.Errorf("get balance after update for account %s: %w", line.AccountID, err)
		}

		eventPayload.Entries = append(eventPayload.Entries, events.LedgerEntryPayload{
			AccountID:     line.AccountID.String(),
			Amount:        delta.String(),
			BalanceBefore: balance.OpeningBalance.String(),
			BalanceAfter:  balance.ClosingBalance.String(),
			FiscalYear:    fiscalYear,
			Period:        period,
		})
	}

	for _, line := range lines {
		if err := s.ledgerRepo.UpdateRunningBalances(ctx, tx, entry.CompanyID, line.AccountID); err != nil {
			s.logger.Warn("failed to update running balance",
				zap.String("account_id", line.AccountID.String()),
				zap.Error(err))
		}
	}

	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("expected *sql.Tx for outbox, got %T", tx)
	}
	payloadBytes, err := json.Marshal(eventPayload)
	if err != nil {
		return fmt.Errorf("marshal ledger event payload: %w", err)
	}
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "ledger",
		AggregateID:   entry.JournalEntryID.String(),
		EventType:     events.EventLedgerUpdated,
		Topic:         TopicAccountingEvents,
		Payload:       payloadBytes,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, sqlTx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	logger.Info("posted journal to ledger (inserted entries, updated balances, running balances)",
		zap.Int("line_count", len(lines)),
		zap.Int("fiscal_year", fiscalYear),
		zap.Int("period", period))
	return nil
}

// --------------------------------------------------------------------------
// ReverseLedgerEntries – reuses PostJournalToLedger
// --------------------------------------------------------------------------
func (s *ledgerService) ReverseLedgerEntries(
	ctx context.Context,
	tx repository.DBTX,
	originalEntryID uuid.UUID,
	reversalEntry *models.JournalEntry,
) error {
	logger := s.logger.With(
		zap.String("method", "ReverseLedgerEntries"),
		zap.String("original_id", originalEntryID.String()),
		zap.String("reversal_id", reversalEntry.JournalEntryID.String()),
	)

	reversalLines, err := s.journalRepo.GetLines(ctx, tx, reversalEntry.JournalEntryID)
	if err != nil {
		return fmt.Errorf("get reversal lines: %w", err)
	}
	logger.Info("reversing ledger entries", zap.Int("line_count", len(reversalLines)))
	return s.PostJournalToLedger(ctx, tx, reversalEntry, reversalLines)
}

// --------------------------------------------------------------------------
// GetAccountBalance – direct repository call
// --------------------------------------------------------------------------
func (s *ledgerService) GetAccountBalance(
	ctx context.Context,
	companyID, accountID uuid.UUID,
	fiscalYear, period int,
) (*models.AccountBalance, error) {
	return s.ledgerRepo.GetBalance(ctx, s.pgClient.DB, companyID, accountID, fiscalYear, period)
}

// --------------------------------------------------------------------------
// RecomputeBalances – full fiscal year recompute
// --------------------------------------------------------------------------
func (s *ledgerService) RecomputeBalances(ctx context.Context, companyID uuid.UUID, fiscalYear int) error {
	s.logger.Info("recomputing balances for company",
		zap.String("company_id", companyID.String()),
		zap.Int("fiscal_year", fiscalYear))
	return s.ledgerRepo.RecomputeCompany(ctx, s.pgClient.DB, companyID, fiscalYear)
}

// --------------------------------------------------------------------------
// Reporting methods
// --------------------------------------------------------------------------
func (s *ledgerService) ComputeTrialBalance(ctx context.Context, companyID uuid.UUID, from, to time.Time) ([]*repository.TrialBalanceRow, error) {
	return s.ledgerRepo.ComputeTrialBalance(ctx, s.pgClient.DB, companyID, from, to)
}

func (s *ledgerService) ComputePAndL(ctx context.Context, companyID uuid.UUID, from, to time.Time) ([]*repository.PAndLRow, error) {
	return s.ledgerRepo.ComputePAndL(ctx, s.pgClient.DB, companyID, from, to)
}

// ComputeBalanceSheet returns assets, liabilities, equity and appends current year earnings (YTD net profit)
func (s *ledgerService) ComputeBalanceSheet(ctx context.Context, companyID uuid.UUID, asOf time.Time) ([]*repository.BalanceSheetRow, error) {
	// 1. Get the base balance sheet (real accounts)
	rows, err := s.ledgerRepo.ComputeBalanceSheet(ctx, s.pgClient.DB, companyID, asOf)
	if err != nil {
		return nil, err
	}

	// 2. Fetch fiscal year start month
	startMonth, err := s.ledgerRepo.GetFiscalYearStartMonth(ctx, s.pgClient.DB, companyID)
	if err != nil {
		s.logger.Warn("failed to get fiscal year start month, skipping current year earnings", zap.Error(err))
		return rows, nil // fallback: return without synthetic row
	}

	// 3. Determine fiscal year start date based on asOf
	fiscalYear := asOf.Year()
	fiscalStart := time.Date(fiscalYear, time.Month(startMonth), 1, 0, 0, 0, 0, time.UTC)
	if asOf.Before(fiscalStart) {
		fiscalYear--
		fiscalStart = time.Date(fiscalYear, time.Month(startMonth), 1, 0, 0, 0, 0, time.UTC)
	}

	// 4. Compute YTD net profit (inclusive of asOf date)
	// Because ComputePAndL uses "entry_date < $3", we pass asOf+1 day to include asOf.
	asOfInclusive := asOf.AddDate(0, 0, 1)
	netProfit, err := s.computeNetProfitFromFiscalStart(ctx, companyID, fiscalStart, asOfInclusive)
	if err != nil {
		s.logger.Warn("failed to compute net profit for balance sheet", zap.Error(err))
		return rows, nil
	}

	// 5. Append synthetic equity row if non-zero
	if !netProfit.IsZero() {
		rows = append(rows, &repository.BalanceSheetRow{
			AccountID:   uuid.Nil, // sentinel
			AccountName: "Current Year Earnings",
			AccountType: "equity",
			Amount:      netProfit,
		})
	}

	return rows, nil
}

// computeNetProfitFromFiscalStart returns YTD net profit (revenue - expense) for interval [fiscalStart, toExclusive)
func (s *ledgerService) computeNetProfitFromFiscalStart(ctx context.Context, companyID uuid.UUID, fiscalStart, toExclusive time.Time) (decimal.Decimal, error) {
	pnlRows, err := s.ledgerRepo.ComputePAndL(ctx, s.pgClient.DB, companyID, fiscalStart, toExclusive)
	if err != nil {
		return decimal.Zero, err
	}
	netProfit := decimal.Zero
	for _, row := range pnlRows {
		if row.AccountType == "revenue" {
			netProfit = netProfit.Add(row.Amount)
		} else if row.AccountType == "expense" {
			netProfit = netProfit.Sub(row.Amount)
		}
	}
	return netProfit, nil
}

func (s *ledgerService) GetAccountLedger(ctx context.Context, companyID, accountID uuid.UUID, from, to time.Time) ([]*repository.LedgerEntry, error) {
	return s.ledgerRepo.GetAccountLedger(ctx, s.pgClient.DB, companyID, accountID, from, to)
}

func (s *ledgerService) CheckImbalance(ctx context.Context, companyID uuid.UUID, from, to time.Time) error {
	imbalance, debit, credit, err := s.ledgerRepo.CheckImbalance(ctx, s.pgClient.DB, companyID, from, to)
	if err != nil {
		return err
	}
	if imbalance {
		return fmt.Errorf("ledger imbalance detected: total debit=%s, total credit=%s", debit, credit)
	}
	return nil
}

func (s *ledgerService) UpdateRunningBalances(ctx context.Context, companyID, accountID uuid.UUID) error {
	return s.ledgerRepo.UpdateRunningBalances(ctx, s.pgClient.DB, companyID, accountID)
}

// --------------------------------------------------------------------------
// Helper: get fiscal year/period from company settings
// --------------------------------------------------------------------------
func (s *ledgerService) getFiscalPeriod(ctx context.Context, companyID uuid.UUID, date time.Time) (int, int, error) {
	return s.settingsRepo.GetFiscalYear(ctx, s.pgClient.DB, companyID, date)
}
