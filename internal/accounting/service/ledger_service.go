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
	"auth-service/internal/accounting/repository"
	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
)

// LedgerService defines ledger operations.
type LedgerService interface {
	PostJournalToLedger(ctx context.Context, tx repository.DBTX, entry *models.JournalEntry, lines []*models.JournalLine) error
	ReverseLedgerEntries(ctx context.Context, tx repository.DBTX, originalEntryID uuid.UUID, reversalEntry *models.JournalEntry) error
	GetAccountBalance(ctx context.Context, companyID, accountID uuid.UUID, fiscalYear, period int) (*models.AccountBalance, error)
	RecomputeBalances(ctx context.Context, companyID uuid.UUID, fiscalYear int) error
}

type ledgerService struct {
	ledgerRepo       repository.LedgerRepository
	journalRepo      repository.JournalRepository
	settingsRepo     repository.AccountingSettingsRepository // added
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
}

// NewLedgerService creates a new ledger service.
func NewLedgerService(
	ledgerRepo repository.LedgerRepository,
	journalRepo repository.JournalRepository,
	settingsRepo repository.AccountingSettingsRepository, // new parameter
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
		pgClient:         pgClient,
		logger:           logger.Named("ledger_service"),
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
	}
}

// PostJournalToLedger updates account balances based on journal lines.
// Assumes it is called within an existing transaction.
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

	// Determine fiscal year and period from entry date using company settings
	fiscalYear, period, err := s.getFiscalPeriod(ctx, entry.CompanyID, entry.EntryDate)
	if err != nil {
		return fmt.Errorf("get fiscal period: %w", err)
	}

	// Prepare event payload
	eventPayload := events.LedgerEventPayload{
		CompanyID:   entry.CompanyID.String(),
		JournalID:   entry.JournalEntryID.String(),
		PostingDate: entry.EntryDate,
		Entries:     []events.LedgerEntryPayload{},
	}

	// Process each line
	for _, line := range lines {
		// Determine amount change: debit increases asset/expense, credit increases liability/equity/revenue.
		// We'll treat amount as positive for debit, negative for credit.
		var amountDelta decimal.Decimal
		if !line.DebitAmount.IsZero() {
			amountDelta = line.DebitAmount
		} else {
			amountDelta = line.CreditAmount.Neg()
		}

		// Get current balance
		currentBalance, err := s.ledgerRepo.GetBalance(ctx, tx, entry.CompanyID, line.AccountID, fiscalYear, period)
		if err != nil {
			return fmt.Errorf("get current balance for account %s: %w", line.AccountID, err)
		}

		var newBalance decimal.Decimal
		var openingBalance decimal.Decimal
		if currentBalance == nil {
			// No existing balance – assume opening balance = 0
			openingBalance = decimal.Zero
			newBalance = amountDelta
		} else {
			openingBalance = currentBalance.ClosingBalance
			newBalance = currentBalance.ClosingBalance.Add(amountDelta)
		}

		// Upsert balance
		balance := &models.AccountBalance{
			BalanceID:      uuid.New(),
			CompanyID:      entry.CompanyID,
			AccountID:      line.AccountID,
			FiscalYear:     fiscalYear,
			Period:         period,
			OpeningBalance: openingBalance,
			ClosingBalance: newBalance,
			IsRecomputed:   false,
		}
		if err := s.ledgerRepo.UpsertBalance(ctx, tx, balance); err != nil {
			return fmt.Errorf("upsert balance for account %s: %w", line.AccountID, err)
		}

		// Append to event payload
		eventPayload.Entries = append(eventPayload.Entries, events.LedgerEntryPayload{
			AccountID:     line.AccountID.String(),
			Amount:        amountDelta.String(),
			BalanceBefore: openingBalance.String(),
			BalanceAfter:  newBalance.String(),
			FiscalYear:    fiscalYear,
			Period:        period,
		})
	}

	// Store outbox event for ledger update
	payloadBytes, _ := json.Marshal(eventPayload)
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("expected *sql.Tx, got %T", tx)
	}
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "ledger",
		AggregateID:   entry.JournalEntryID.String(),
		EventType:     events.EventLedgerUpdated,
		Payload:       payloadBytes,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, sqlTx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	logger.Info("posted journal to ledger", zap.Int("line_count", len(lines)))
	return nil
}

// ReverseLedgerEntries reverts the ledger impact of a reversed journal entry.
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

	// Get reversal lines (the opposite of original)
	reversalLines, err := s.journalRepo.GetLines(ctx, tx, reversalEntry.JournalEntryID)
	if err != nil {
		return fmt.Errorf("get reversal lines: %w", err)
	}

	logger.Info("reversing ledger entries", zap.Int("line_count", len(reversalLines)))
	return s.PostJournalToLedger(ctx, tx, reversalEntry, reversalLines)
}

// GetAccountBalance retrieves the balance for a specific account at a given fiscal period.
func (s *ledgerService) GetAccountBalance(
	ctx context.Context,
	companyID, accountID uuid.UUID,
	fiscalYear, period int,
) (*models.AccountBalance, error) {
	return s.ledgerRepo.GetBalance(ctx, s.pgClient.DB, companyID, accountID, fiscalYear, period)
}

// RecomputeBalances recalculates all balances for a company in a fiscal year from journal entries.
func (s *ledgerService) RecomputeBalances(ctx context.Context, companyID uuid.UUID, fiscalYear int) error {
	s.logger.Info("recomputing balances for company", zap.String("company_id", companyID.String()), zap.Int("fiscal_year", fiscalYear))
	return s.ledgerRepo.RecomputeCompany(ctx, s.pgClient.DB, companyID, fiscalYear)
}

// getFiscalPeriod returns the fiscal year and period for a given date using the company's accounting settings.
func (s *ledgerService) getFiscalPeriod(ctx context.Context, companyID uuid.UUID, date time.Time) (int, int, error) {
	// Use the settings repository to compute fiscal year/period
	fiscalYear, period, err := s.settingsRepo.GetFiscalYear(ctx, s.pgClient.DB, companyID, date)
	if err != nil {
		s.logger.Error("failed to get fiscal period",
			zap.String("company_id", companyID.String()),
			zap.Time("date", date),
			zap.Error(err))
		return 0, 0, fmt.Errorf("get fiscal period: %w", err)
	}
	return fiscalYear, period, nil
}
