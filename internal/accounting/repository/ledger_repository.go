package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/accounting/models"
	"auth-service/internal/accounting/models/enums"
	"auth-service/internal/util"
)

// =====================================================
// DTOs (all amounts decimal.Decimal)
// =====================================================

type TrialBalanceRow struct {
	AccountID   uuid.UUID       `json:"account_id"`
	AccountCode string          `json:"account_code"`
	AccountName string          `json:"account_name"`
	Debit       decimal.Decimal `json:"debit"`
	Credit      decimal.Decimal `json:"credit"`
}

type PAndLRow struct {
	AccountID   uuid.UUID       `json:"account_id"`
	AccountName string          `json:"account_name"`
	AccountType string          `json:"account_type"`
	Amount      decimal.Decimal `json:"amount"`
}

type BalanceSheetRow struct {
	AccountID   uuid.UUID       `json:"account_id"`
	AccountName string          `json:"account_name"`
	AccountType string          `json:"account_type"`
	Amount      decimal.Decimal `json:"amount"`
}

type LedgerEntry struct {
	JournalEntryID uuid.UUID       `json:"journal_entry_id"`
	Date           time.Time       `json:"date"`
	Reference      *string         `json:"reference,omitempty"`
	Description    *string         `json:"description,omitempty"`
	Debit          decimal.Decimal `json:"debit"`
	Credit         decimal.Decimal `json:"credit"`
	RunningBalance decimal.Decimal `json:"running_balance"`
}

// =====================================================
// INTERFACE
// =====================================================

type LedgerRepository interface {
	// Balances (snapshots)
	UpsertBalance(ctx context.Context, db DBTX, b *models.AccountBalance) error
	GetBalance(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, fiscalYear, period int) (*models.AccountBalance, error)
	GetBalancesByAccount(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, fiscalYear int) ([]*models.AccountBalance, error)
	GetBalancesByCompany(ctx context.Context, db DBTX, companyID uuid.UUID, fiscalYear, period int) ([]*models.AccountBalance, error)
	MarkRecomputed(ctx context.Context, db DBTX, companyID uuid.UUID, fiscalYear, period int) error
	EnsureBalance(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, fiscalYear, period int) error
	CreateLedgerEntry(ctx context.Context, db DBTX, le *models.LedgerEntry) error
	GetFiscalYearStartMonth(ctx context.Context, db DBTX, companyID uuid.UUID) (int, error)

	// Computation from ledger (using dates)
	ComputeAccountBalance(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, from, to time.Time) (opening, debit, credit, closing decimal.Decimal, err error)
	ComputeTrialBalance(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) ([]*TrialBalanceRow, error)
	ComputePAndL(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) ([]*PAndLRow, error)
	ComputeBalanceSheet(ctx context.Context, db DBTX, companyID uuid.UUID, asOf time.Time) ([]*BalanceSheetRow, error)
	GetAccountTypesMap(ctx context.Context, db DBTX, accountIDs []uuid.UUID) (map[uuid.UUID]string, error)
	AtomicAddToBalance(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, fiscalYear, period int, delta decimal.Decimal) error

	// Ledger (account statement) – uses precomputed running_balance
	GetAccountLedger(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, from, to time.Time) ([]*LedgerEntry, error)
	GetAccountOpeningBalance(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, before time.Time) (decimal.Decimal, error)

	// Fiscal‑optimised queries (use indexes)
	GetAccountMovementByPeriod(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, fiscalYear, period int) (debit, credit decimal.Decimal, err error)
	GetClosingBalance(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, fiscalYear, period int) (decimal.Decimal, error)
	HasLedgerEntries(ctx context.Context, db DBTX, journalEntryID uuid.UUID) (bool, error)

	// Recompute (efficient)
	RecomputeAccount(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, fiscalYear int) error
	RecomputePeriod(ctx context.Context, db DBTX, companyID uuid.UUID, fiscalYear, period int) error
	RecomputeCompany(ctx context.Context, db DBTX, companyID uuid.UUID, fiscalYear int) error

	// Maintenance
	UpdateRunningBalances(ctx context.Context, db DBTX, companyID, accountID uuid.UUID) error

	// Validation
	CheckImbalance(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) (bool, decimal.Decimal, decimal.Decimal, error)

	// Legacy (but still used)
	SumAccountMovement(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, from, to time.Time) (debit, credit decimal.Decimal, err error)
}

// =====================================================
// IMPLEMENTATION
// =====================================================

type ledgerRepository struct {
	logger *zap.Logger
}

func NewLedgerRepository(logger *zap.Logger) LedgerRepository {
	return &ledgerRepository{
		logger: logger.Named("ledger_repo"),
	}
}

// -----------------------------------------------------------------
// BALANCES
// -----------------------------------------------------------------

func (r *ledgerRepository) UpsertBalance(ctx context.Context, db DBTX, b *models.AccountBalance) error {
	query := `
		INSERT INTO accounting.account_balances (
			balance_id, company_id, account_id, fiscal_year, period,
			opening_balance, closing_balance, is_recomputed,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
		ON CONFLICT (company_id, account_id, fiscal_year, period)
		DO UPDATE SET
			opening_balance = EXCLUDED.opening_balance,
			closing_balance = EXCLUDED.closing_balance,
			is_recomputed = EXCLUDED.is_recomputed,
			updated_at = NOW()
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		b.BalanceID, b.CompanyID, b.AccountID, b.FiscalYear, b.Period,
		b.OpeningBalance, b.ClosingBalance, b.IsRecomputed,
	).Scan(&b.CreatedAt, &b.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to upsert account balance", util.ErrorField(err))
		return fmt.Errorf("upsert balance: %w", err)
	}
	return nil
}

func (r *ledgerRepository) GetBalance(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, fiscalYear, period int) (*models.AccountBalance, error) {
	query := `
		SELECT balance_id, company_id, account_id, fiscal_year, period,
		       opening_balance, closing_balance, is_recomputed,
		       created_at, updated_at
		FROM accounting.account_balances
		WHERE company_id = $1 AND account_id = $2 AND fiscal_year = $3 AND period = $4
	`
	var b models.AccountBalance
	err := db.QueryRowContext(ctx, query, companyID, accountID, fiscalYear, period).Scan(
		&b.BalanceID, &b.CompanyID, &b.AccountID, &b.FiscalYear, &b.Period,
		&b.OpeningBalance, &b.ClosingBalance, &b.IsRecomputed,
		&b.CreatedAt, &b.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get balance: %w", err)
	}
	return &b, nil
}

func (r *ledgerRepository) GetBalancesByAccount(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, fiscalYear int) ([]*models.AccountBalance, error) {
	query := `
		SELECT balance_id, company_id, account_id, fiscal_year, period,
		       opening_balance, closing_balance, is_recomputed,
		       created_at, updated_at
		FROM accounting.account_balances
		WHERE company_id = $1 AND account_id = $2 AND fiscal_year = $3
		ORDER BY period
	`
	rows, err := db.QueryContext(ctx, query, companyID, accountID, fiscalYear)
	if err != nil {
		return nil, fmt.Errorf("get balances by account: %w", err)
	}
	defer rows.Close()
	var balances []*models.AccountBalance
	for rows.Next() {
		var b models.AccountBalance
		if err := rows.Scan(&b.BalanceID, &b.CompanyID, &b.AccountID, &b.FiscalYear, &b.Period,
			&b.OpeningBalance, &b.ClosingBalance, &b.IsRecomputed, &b.CreatedAt, &b.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan balance: %w", err)
		}
		balances = append(balances, &b)
	}
	return balances, nil
}

func (r *ledgerRepository) GetBalancesByCompany(ctx context.Context, db DBTX, companyID uuid.UUID, fiscalYear, period int) ([]*models.AccountBalance, error) {
	query := `
		SELECT balance_id, company_id, account_id, fiscal_year, period,
		       opening_balance, closing_balance, is_recomputed,
		       created_at, updated_at
		FROM accounting.account_balances
		WHERE company_id = $1 AND fiscal_year = $2 AND period = $3
	`
	rows, err := db.QueryContext(ctx, query, companyID, fiscalYear, period)
	if err != nil {
		return nil, fmt.Errorf("get balances by company: %w", err)
	}
	defer rows.Close()
	var balances []*models.AccountBalance
	for rows.Next() {
		var b models.AccountBalance
		if err := rows.Scan(&b.BalanceID, &b.CompanyID, &b.AccountID, &b.FiscalYear, &b.Period,
			&b.OpeningBalance, &b.ClosingBalance, &b.IsRecomputed, &b.CreatedAt, &b.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan balance: %w", err)
		}
		balances = append(balances, &b)
	}
	return balances, nil
}

func (r *ledgerRepository) MarkRecomputed(ctx context.Context, db DBTX, companyID uuid.UUID, fiscalYear, period int) error {
	_, err := db.ExecContext(ctx, `
		UPDATE accounting.account_balances
		SET is_recomputed = true, updated_at = NOW()
		WHERE company_id = $1 AND fiscal_year = $2 AND period = $3
	`, companyID, fiscalYear, period)
	if err != nil {
		return fmt.Errorf("mark recomputed: %w", err)
	}
	return nil
}

func (r *ledgerRepository) EnsureBalance(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, fiscalYear, period int) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO accounting.account_balances (
			balance_id, company_id, account_id, fiscal_year, period,
			opening_balance, closing_balance, is_recomputed, created_at, updated_at
		) VALUES (gen_random_uuid(), $1, $2, $3, $4, 0, 0, false, NOW(), NOW())
		ON CONFLICT (company_id, account_id, fiscal_year, period) DO NOTHING
	`, companyID, accountID, fiscalYear, period)
	if err != nil {
		return fmt.Errorf("ensure balance: %w", err)
	}
	return nil
}

// -----------------------------------------------------------------
// COMPUTATION – all queries now half‑open intervals + company filter
// -----------------------------------------------------------------

func (r *ledgerRepository) getAccountType(ctx context.Context, db DBTX, accountID uuid.UUID) (string, error) {
	var accType string
	err := db.QueryRowContext(ctx, `SELECT account_type FROM accounting.accounts WHERE account_id = $1 AND deleted_at IS NULL`, accountID).Scan(&accType)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return accType, nil
}

func (r *ledgerRepository) ComputeAccountBalance(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, from, to time.Time) (opening, debit, credit, closing decimal.Decimal, err error) {
	accType, err := r.getAccountType(ctx, db, accountID)
	if err != nil {
		return decimal.Zero, decimal.Zero, decimal.Zero, decimal.Zero, err
	}
	opening, err = r.GetAccountOpeningBalance(ctx, db, companyID, accountID, from)
	if err != nil {
		return decimal.Zero, decimal.Zero, decimal.Zero, decimal.Zero, fmt.Errorf("opening balance: %w", err)
	}
	debit, credit, err = r.SumAccountMovement(ctx, db, companyID, accountID, from, to)
	if err != nil {
		return decimal.Zero, decimal.Zero, decimal.Zero, decimal.Zero, fmt.Errorf("movement: %w", err)
	}
	if accType == enums.AccountTypeAsset || accType == enums.AccountTypeExpense {
		closing = opening.Add(debit).Sub(credit)
	} else {
		closing = opening.Add(credit).Sub(debit)
	}
	return opening, debit, credit, closing, nil
}

func (r *ledgerRepository) ComputeTrialBalance(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) ([]*TrialBalanceRow, error) {
	query := `
		SELECT
			a.account_id,
			a.account_code,
			a.account_name,
			COALESCE(SUM(le.debit_amount), 0) AS total_debit,
			COALESCE(SUM(le.credit_amount), 0) AS total_credit
		FROM accounting.accounts a
		LEFT JOIN accounting.ledger_entries le
			ON a.account_id = le.account_id
			AND le.company_id = $1
			AND le.entry_date >= $2
			AND le.entry_date < $3
		WHERE a.company_id = $1 AND a.deleted_at IS NULL
		GROUP BY a.account_id, a.account_code, a.account_name
		ORDER BY a.account_code
	`
	rows, err := db.QueryContext(ctx, query, companyID, from, to)
	if err != nil {
		return nil, fmt.Errorf("compute trial balance: %w", err)
	}
	defer rows.Close()
	var result []*TrialBalanceRow
	for rows.Next() {
		var row TrialBalanceRow
		if err := rows.Scan(&row.AccountID, &row.AccountCode, &row.AccountName, &row.Debit, &row.Credit); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		result = append(result, &row)
	}
	return result, nil
}

func (r *ledgerRepository) ComputePAndL(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) ([]*PAndLRow, error) {
	query := `
		SELECT
			a.account_id,
			a.account_name,
			a.account_type,
			COALESCE(SUM(le.debit_amount), 0) AS total_debit,
			COALESCE(SUM(le.credit_amount), 0) AS total_credit
		FROM accounting.accounts a
		LEFT JOIN accounting.ledger_entries le
			ON a.account_id = le.account_id
			AND le.company_id = $1
			AND le.entry_date >= $2
			AND le.entry_date < $3
		WHERE a.company_id = $1
		  AND a.deleted_at IS NULL
		  AND a.account_type IN ('revenue', 'expense')
		GROUP BY a.account_id, a.account_name, a.account_type
	`
	rows, err := db.QueryContext(ctx, query, companyID, from, to)
	if err != nil {
		return nil, fmt.Errorf("compute P&L: %w", err)
	}
	defer rows.Close()
	var result []*PAndLRow
	for rows.Next() {
		var accID uuid.UUID
		var accName, accType string
		var totalDebit, totalCredit decimal.Decimal
		if err := rows.Scan(&accID, &accName, &accType, &totalDebit, &totalCredit); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		var amount decimal.Decimal
		if accType == enums.AccountTypeRevenue {
			amount = totalCredit.Sub(totalDebit)
		} else {
			amount = totalDebit.Sub(totalCredit)
		}
		result = append(result, &PAndLRow{
			AccountID:   accID,
			AccountName: accName,
			AccountType: accType,
			Amount:      amount,
		})
	}
	return result, nil
}

func (r *ledgerRepository) ComputeBalanceSheet(ctx context.Context, db DBTX, companyID uuid.UUID, asOf time.Time) ([]*BalanceSheetRow, error) {
	query := `
		WITH movements AS (
			SELECT
				le.account_id,
				COALESCE(SUM(le.debit_amount), 0) AS total_debit,
				COALESCE(SUM(le.credit_amount), 0) AS total_credit
			FROM accounting.ledger_entries le
			WHERE le.company_id = $1
			  AND le.entry_date < $2
			  AND le.account_id IN (
				  SELECT account_id FROM accounting.accounts
				  WHERE company_id = $1 AND deleted_at IS NULL
				    AND account_type IN ('asset', 'liability', 'equity')
			  )
			GROUP BY le.account_id
		)
		SELECT
			a.account_id,
			a.account_name,
			a.account_type,
			CASE
				WHEN a.account_type IN ('asset', 'expense') THEN
					COALESCE(m.total_debit, 0) - COALESCE(m.total_credit, 0)
				ELSE
					COALESCE(m.total_credit, 0) - COALESCE(m.total_debit, 0)
			END AS balance
		FROM accounting.accounts a
		LEFT JOIN movements m ON a.account_id = m.account_id
		WHERE a.company_id = $1
		  AND a.deleted_at IS NULL
		  AND a.account_type IN ('asset', 'liability', 'equity')
		ORDER BY a.account_type, a.account_code
	`
	rows, err := db.QueryContext(ctx, query, companyID, asOf)
	if err != nil {
		return nil, fmt.Errorf("compute balance sheet: %w", err)
	}
	defer rows.Close()
	var result []*BalanceSheetRow
	for rows.Next() {
		var row BalanceSheetRow
		if err := rows.Scan(&row.AccountID, &row.AccountName, &row.AccountType, &row.Amount); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		result = append(result, &row)
	}
	return result, nil
}

// -----------------------------------------------------------------
// LEDGER (account statement) – uses running_balance from DB
// -----------------------------------------------------------------

func (r *ledgerRepository) GetAccountLedger(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, from, to time.Time) ([]*LedgerEntry, error) {
	query := `
		SELECT
			le.journal_entry_id,
			le.entry_date,
			je.reference,
			je.description,
			le.debit_amount,
			le.credit_amount,
			le.running_balance
		FROM accounting.ledger_entries le
		JOIN accounting.journal_entries je ON le.journal_entry_id = je.journal_entry_id
		WHERE le.account_id = $1
		  AND le.company_id = $2
		  AND le.entry_date >= $3
		  AND le.entry_date < $4
		ORDER BY le.entry_date, le.created_at
	`
	rows, err := db.QueryContext(ctx, query, accountID, companyID, from, to)
	if err != nil {
		return nil, fmt.Errorf("get account ledger: %w", err)
	}
	defer rows.Close()
	var entries []*LedgerEntry
	for rows.Next() {
		var e LedgerEntry
		if err := rows.Scan(&e.JournalEntryID, &e.Date, &e.Reference, &e.Description, &e.Debit, &e.Credit, &e.RunningBalance); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		entries = append(entries, &e)
	}
	return entries, nil
}

func (r *ledgerRepository) GetAccountOpeningBalance(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, before time.Time) (decimal.Decimal, error) {
	query := `
		SELECT COALESCE(SUM(
			CASE
				WHEN a.account_type IN ('asset', 'expense')
					THEN le.debit_amount - le.credit_amount
				ELSE
					le.credit_amount - le.debit_amount
			END
		), 0)
		FROM accounting.ledger_entries le
		JOIN accounting.accounts a ON le.account_id = a.account_id
		WHERE le.account_id = $1
		  AND le.company_id = $2
		  AND le.entry_date < $3
	`
	var balance decimal.Decimal
	err := db.QueryRowContext(ctx, query, accountID, companyID, before).Scan(&balance)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return decimal.Zero, fmt.Errorf("get opening balance: %w", err)
	}
	return balance, nil
}

// -----------------------------------------------------------------
// FISCAL‑OPTIMISED QUERIES (use indexes)
// -----------------------------------------------------------------

func (r *ledgerRepository) GetAccountMovementByPeriod(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, fiscalYear, period int) (debit, credit decimal.Decimal, err error) {
	query := `
		SELECT COALESCE(SUM(debit_amount), 0), COALESCE(SUM(credit_amount), 0)
		FROM accounting.ledger_entries
		WHERE account_id = $1
		  AND company_id = $2
		  AND fiscal_year = $3
		  AND period = $4
	`
	err = db.QueryRowContext(ctx, query, accountID, companyID, fiscalYear, period).Scan(&debit, &credit)
	if err != nil {
		return decimal.Zero, decimal.Zero, fmt.Errorf("get movement by period: %w", err)
	}
	return debit, credit, nil
}

func (r *ledgerRepository) GetClosingBalance(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, fiscalYear, period int) (decimal.Decimal, error) {
	bal, err := r.GetBalance(ctx, db, companyID, accountID, fiscalYear, period)
	if err == nil {
		return bal.ClosingBalance, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return decimal.Zero, err
	}
	// fallback: compute on the fly using fiscal periods
	debit, credit, err := r.GetAccountMovementByPeriod(ctx, db, companyID, accountID, fiscalYear, period)
	if err != nil {
		return decimal.Zero, err
	}
	opening, err := r.getOpeningFromPreviousPeriod(ctx, db, companyID, accountID, fiscalYear, period)
	if err != nil {
		return decimal.Zero, err
	}
	accType, err := r.getAccountType(ctx, db, accountID)
	if err != nil {
		return decimal.Zero, err
	}
	if accType == enums.AccountTypeAsset || accType == enums.AccountTypeExpense {
		return opening.Add(debit).Sub(credit), nil
	}
	return opening.Add(credit).Sub(debit), nil
}

// helper for fallback
func (r *ledgerRepository) getOpeningFromPreviousPeriod(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, fiscalYear, period int) (decimal.Decimal, error) {
	if period == 1 {
		// opening of fiscal year = balance before fiscal year start
		startMonth, err := r.getFiscalYearStartMonth(ctx, db, companyID)
		if err != nil {
			return decimal.Zero, err
		}
		fiscalStart := time.Date(fiscalYear, time.Month(startMonth), 1, 0, 0, 0, 0, time.UTC)
		return r.GetAccountOpeningBalance(ctx, db, companyID, accountID, fiscalStart)
	}
	prevBal, err := r.GetBalance(ctx, db, companyID, accountID, fiscalYear, period-1)
	if err != nil {
		return decimal.Zero, err
	}
	return prevBal.ClosingBalance, nil
}

func (r *ledgerRepository) HasLedgerEntries(ctx context.Context, db DBTX, journalEntryID uuid.UUID) (bool, error) {
	var exists bool
	err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM accounting.ledger_entries WHERE journal_entry_id = $1)`, journalEntryID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("has ledger entries: %w", err)
	}
	return exists, nil
}

// -----------------------------------------------------------------
// RECOMPUTATION (efficient, no O(n²))
// -----------------------------------------------------------------

func (r *ledgerRepository) RecomputeAccount(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, fiscalYear int) error {
	startMonth, err := r.getFiscalYearStartMonth(ctx, db, companyID)
	if err != nil {
		return err
	}
	fiscalStart := time.Date(fiscalYear, time.Month(startMonth), 1, 0, 0, 0, 0, time.UTC)
	opening, err := r.GetAccountOpeningBalance(ctx, db, companyID, accountID, fiscalStart)
	if err != nil {
		return fmt.Errorf("opening balance: %w", err)
	}
	for period := 1; period <= 12; period++ {
		debit, credit, err := r.GetAccountMovementByPeriod(ctx, db, companyID, accountID, fiscalYear, period)
		if err != nil {
			return fmt.Errorf("movement period %d: %w", period, err)
		}
		accType, err := r.getAccountType(ctx, db, accountID)
		if err != nil {
			return err
		}
		var closing decimal.Decimal
		if accType == enums.AccountTypeAsset || accType == enums.AccountTypeExpense {
			closing = opening.Add(debit).Sub(credit)
		} else {
			closing = opening.Add(credit).Sub(debit)
		}
		balance := &models.AccountBalance{
			BalanceID:      uuid.New(),
			CompanyID:      companyID,
			AccountID:      accountID,
			FiscalYear:     fiscalYear,
			Period:         period,
			OpeningBalance: opening,
			ClosingBalance: closing,
			IsRecomputed:   true,
		}
		if err := r.UpsertBalance(ctx, db, balance); err != nil {
			return fmt.Errorf("upsert period %d: %w", period, err)
		}
		opening = closing
	}
	return nil
}

// RecomputePeriod recomputes ONLY the given period (fast)
func (r *ledgerRepository) RecomputePeriod(ctx context.Context, db DBTX, companyID uuid.UUID, fiscalYear, period int) error {
	accounts, err := r.getAllAccountIDs(ctx, db, companyID)
	if err != nil {
		return err
	}
	for _, accID := range accounts {
		if err := r.recomputeSinglePeriod(ctx, db, companyID, accID, fiscalYear, period); err != nil {
			return fmt.Errorf("recompute account %s period %d: %w", accID, period, err)
		}
	}
	return nil
}

func (r *ledgerRepository) recomputeSinglePeriod(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, fiscalYear, period int) error {
	// get opening = previous period closing
	var opening decimal.Decimal
	if period == 1 {
		startMonth, err := r.getFiscalYearStartMonth(ctx, db, companyID)
		if err != nil {
			return err
		}
		fiscalStart := time.Date(fiscalYear, time.Month(startMonth), 1, 0, 0, 0, 0, time.UTC)
		opening, err = r.GetAccountOpeningBalance(ctx, db, companyID, accountID, fiscalStart)
		if err != nil {
			return err
		}
	} else {
		prev, err := r.GetBalance(ctx, db, companyID, accountID, fiscalYear, period-1)
		if err != nil {
			return err
		}
		opening = prev.ClosingBalance
	}
	debit, credit, err := r.GetAccountMovementByPeriod(ctx, db, companyID, accountID, fiscalYear, period)
	if err != nil {
		return err
	}
	accType, err := r.getAccountType(ctx, db, accountID)
	if err != nil {
		return err
	}
	var closing decimal.Decimal
	if accType == enums.AccountTypeAsset || accType == enums.AccountTypeExpense {
		closing = opening.Add(debit).Sub(credit)
	} else {
		closing = opening.Add(credit).Sub(debit)
	}
	balance := &models.AccountBalance{
		BalanceID:      uuid.New(),
		CompanyID:      companyID,
		AccountID:      accountID,
		FiscalYear:     fiscalYear,
		Period:         period,
		OpeningBalance: opening,
		ClosingBalance: closing,
		IsRecomputed:   true,
	}
	return r.UpsertBalance(ctx, db, balance)
}

func (r *ledgerRepository) RecomputeCompany(ctx context.Context, db DBTX, companyID uuid.UUID, fiscalYear int) error {
	for period := 1; period <= 12; period++ {
		if err := r.RecomputePeriod(ctx, db, companyID, fiscalYear, period); err != nil {
			return fmt.Errorf("recompute period %d: %w", period, err)
		}
	}
	return nil
}

// -----------------------------------------------------------------
// MAINTENANCE
// -----------------------------------------------------------------

// FIXED: added company_id filter + deterministic order
func (r *ledgerRepository) UpdateRunningBalances(ctx context.Context, db DBTX, companyID, accountID uuid.UUID) error {
	query := `
		WITH ordered AS (
			SELECT le.ledger_entry_id,
			       SUM(CASE
				       WHEN a.account_type IN ('asset', 'expense')
					   THEN le.debit_amount - le.credit_amount
					   ELSE le.credit_amount - le.debit_amount
			       END) OVER (ORDER BY le.entry_date, le.created_at, le.ledger_entry_id) AS new_running
			FROM accounting.ledger_entries le
			JOIN accounting.accounts a ON le.account_id = a.account_id
			WHERE le.account_id = $1
			  AND le.company_id = $2
		)
		UPDATE accounting.ledger_entries
		SET running_balance = ordered.new_running
		FROM ordered
		WHERE ledger_entries.ledger_entry_id = ordered.ledger_entry_id
	`
	_, err := db.ExecContext(ctx, query, accountID, companyID)
	if err != nil {
		return fmt.Errorf("update running balances: %w", err)
	}
	return nil
}

// -----------------------------------------------------------------
// VALIDATION
// -----------------------------------------------------------------

func (r *ledgerRepository) CheckImbalance(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) (bool, decimal.Decimal, decimal.Decimal, error) {
	var totalDebit, totalCredit decimal.Decimal
	err := db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(debit_amount), 0), COALESCE(SUM(credit_amount), 0)
		FROM accounting.ledger_entries
		WHERE company_id = $1 AND entry_date >= $2 AND entry_date < $3
	`, companyID, from, to).Scan(&totalDebit, &totalCredit)
	if err != nil {
		return false, decimal.Zero, decimal.Zero, fmt.Errorf("check imbalance: %w", err)
	}
	return !totalDebit.Equal(totalCredit), totalDebit, totalCredit, nil
}

// -----------------------------------------------------------------
// LEGACY / HELPER
// -----------------------------------------------------------------

func (r *ledgerRepository) SumAccountMovement(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, from, to time.Time) (debit, credit decimal.Decimal, err error) {
	err = db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(debit_amount), 0), COALESCE(SUM(credit_amount), 0)
		FROM accounting.ledger_entries
		WHERE account_id = $1
		  AND company_id = $2
		  AND entry_date >= $3
		  AND entry_date < $4
	`, accountID, companyID, from, to).Scan(&debit, &credit)
	if err != nil {
		return decimal.Zero, decimal.Zero, fmt.Errorf("sum movement: %w", err)
	}
	return debit, credit, nil
}

// -----------------------------------------------------------------
// PRIVATE HELPERS
// -----------------------------------------------------------------

func (r *ledgerRepository) getFiscalYearStartMonth(ctx context.Context, db DBTX, companyID uuid.UUID) (int, error) {
	var startMonth int
	err := db.QueryRowContext(ctx, `SELECT fiscal_year_start_month FROM accounting.accounting_settings WHERE company_id = $1`, companyID).Scan(&startMonth)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNotFound
		}
		return 0, fmt.Errorf("get fiscal year start month: %w", err)
	}
	return startMonth, nil
}

func (r *ledgerRepository) getAllAccountIDs(ctx context.Context, db DBTX, companyID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := db.QueryContext(ctx, `SELECT account_id FROM accounting.accounts WHERE company_id = $1 AND deleted_at IS NULL`, companyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// GetAccountTypesMap returns a map of account ID to account type for the given IDs.
// Only returns non‑deleted accounts; missing IDs will not appear in the map.
func (r *ledgerRepository) GetAccountTypesMap(ctx context.Context, db DBTX, accountIDs []uuid.UUID) (map[uuid.UUID]string, error) {
	if len(accountIDs) == 0 {
		return map[uuid.UUID]string{}, nil
	}
	query := `
		SELECT account_id, account_type
		FROM accounting.accounts
		WHERE account_id = ANY($1) AND deleted_at IS NULL
	`
	rows, err := db.QueryContext(ctx, query, pq.Array(accountIDs))
	if err != nil {
		return nil, fmt.Errorf("query account types: %w", err)
	}
	defer rows.Close()
	result := make(map[uuid.UUID]string, len(accountIDs))
	for rows.Next() {
		var id uuid.UUID
		var accType string
		if err := rows.Scan(&id, &accType); err != nil {
			return nil, fmt.Errorf("scan account type: %w", err)
		}
		result[id] = accType
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// AtomicAddToBalance atomically adds delta to the closing_balance of an account balance.
// If the balance row does not exist, it is created with opening_balance = 0 and closing_balance = delta.
func (r *ledgerRepository) AtomicAddToBalance(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, fiscalYear, period int, delta decimal.Decimal) error {
	query := `
		INSERT INTO accounting.account_balances (
			balance_id, company_id, account_id, fiscal_year, period,
			opening_balance, closing_balance, is_recomputed,
			created_at, updated_at
		) VALUES (
			gen_random_uuid(), $1, $2, $3, $4,
			0, $5, false, NOW(), NOW()
		)
		ON CONFLICT (company_id, account_id, fiscal_year, period)
		DO UPDATE SET
			closing_balance = account_balances.closing_balance + EXCLUDED.closing_balance,
			updated_at = NOW()
	`
	_, err := db.ExecContext(ctx, query, companyID, accountID, fiscalYear, period, delta)
	if err != nil {
		r.logger.Error("atomic add to balance failed",
			zap.String("company_id", companyID.String()),
			zap.String("account_id", accountID.String()),
			zap.Int("fiscal_year", fiscalYear),
			zap.Int("period", period),
			zap.String("delta", delta.String()),
			zap.Error(err))
		return fmt.Errorf("atomic add to balance: %w", err)
	}
	return nil
}

// repository/ledger_repository.go
func (r *ledgerRepository) CreateLedgerEntry(ctx context.Context, db DBTX, le *models.LedgerEntry) error {
	query := `
		INSERT INTO accounting.ledger_entries (
			ledger_entry_id, company_id, journal_entry_id, journal_line_id,
			account_id, entry_date, debit_amount, credit_amount,
			running_balance, is_reversal, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
	`
	_, err := db.ExecContext(ctx, query,
		le.LedgerEntryID, le.CompanyID, le.JournalEntryID, le.JournalLineID,
		le.AccountID, le.EntryDate, le.DebitAmount, le.CreditAmount,
		le.RunningBalance, le.IsReversal,
	)
	if err != nil {
		return fmt.Errorf("create ledger entry: %w", err)
	}
	return nil
}

func (r *ledgerRepository) GetFiscalYearStartMonth(ctx context.Context, db DBTX, companyID uuid.UUID) (int, error) {
	return r.getFiscalYearStartMonth(ctx, db, companyID)
}
