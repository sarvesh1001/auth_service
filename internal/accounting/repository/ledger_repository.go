package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/accounting/models"
	"auth-service/internal/accounting/models/enums"
	"auth-service/internal/util"
)

// =====================================================
// SUPPORTING TYPES
// =====================================================

// TrialBalanceRow represents a line in the trial balance report.
type TrialBalanceRow struct {
	AccountID   uuid.UUID `json:"account_id"`
	AccountCode string    `json:"account_code"`
	AccountName string    `json:"account_name"`
	Debit       float64   `json:"debit"`
	Credit      float64   `json:"credit"`
}

// PAndLRow represents a line in the Profit & Loss statement.
type PAndLRow struct {
	AccountID   uuid.UUID `json:"account_id"`
	AccountName string    `json:"account_name"`
	AccountType string    `json:"account_type"`
	Amount      float64   `json:"amount"` // positive = expense/revenue magnitude
}

// BalanceSheetRow represents a line in the Balance Sheet.
type BalanceSheetRow struct {
	AccountID   uuid.UUID `json:"account_id"`
	AccountName string    `json:"account_name"`
	AccountType string    `json:"account_type"`
	Amount      float64   `json:"amount"`
}

// LedgerEntry is a single line in an account statement (ledger).
type LedgerEntry struct {
	JournalEntryID uuid.UUID `json:"journal_entry_id"`
	Date           time.Time `json:"date"`
	Reference      *string   `json:"reference,omitempty"`
	Description    *string   `json:"description,omitempty"`
	Debit          float64   `json:"debit"`
	Credit         float64   `json:"credit"`
	RunningBalance float64   `json:"running_balance"`
}

// =====================================================
// LEDGER REPOSITORY INTERFACE
// =====================================================

// LedgerRepository defines all ledger and balance operations.
type LedgerRepository interface {
	// Balances (stored snapshots)
	UpsertBalance(ctx context.Context, db DBTX, b *models.AccountBalance) error
	GetBalance(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, fiscalYear, period int) (*models.AccountBalance, error)
	GetBalancesByAccount(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, fiscalYear int) ([]*models.AccountBalance, error)
	GetBalancesByCompany(ctx context.Context, db DBTX, companyID uuid.UUID, fiscalYear, period int) ([]*models.AccountBalance, error)
	MarkRecomputed(ctx context.Context, db DBTX, companyID uuid.UUID, fiscalYear, period int) error

	// Computation (from journal)
	ComputeAccountBalance(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, from, to time.Time) (opening float64, debit float64, credit float64, closing float64, err error)
	ComputeTrialBalance(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) ([]*TrialBalanceRow, error)
	ComputePAndL(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) ([]*PAndLRow, error)
	ComputeBalanceSheet(ctx context.Context, db DBTX, companyID uuid.UUID, asOf time.Time) ([]*BalanceSheetRow, error)

	// Ledger (account statement)
	GetAccountLedger(ctx context.Context, db DBTX, accountID uuid.UUID, from, to time.Time) ([]*LedgerEntry, error)
	GetAccountOpeningBalance(ctx context.Context, db DBTX, accountID uuid.UUID, before time.Time) (float64, error)

	// Recompuation
	RecomputeAccount(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, fiscalYear int) error
	RecomputePeriod(ctx context.Context, db DBTX, companyID uuid.UUID, fiscalYear, period int) error
	RecomputeCompany(ctx context.Context, db DBTX, companyID uuid.UUID, fiscalYear int) error

	// Validation / consistency
	CheckImbalance(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) (bool, float64, float64, error)

	// Performance helpers
	SumAccountMovement(ctx context.Context, db DBTX, accountID uuid.UUID, from, to time.Time) (debit float64, credit float64, err error)
}

// =====================================================
// IMPLEMENTATION
// =====================================================

type ledgerRepository struct {
	logger *zap.Logger
}

// NewLedgerRepository creates a new ledger repository instance.
func NewLedgerRepository(logger *zap.Logger) LedgerRepository {
	return &ledgerRepository{
		logger: logger.Named("ledger_repo"),
	}
}

// =====================================================
// BALANCES (STORED SNAPSHOTS)
// =====================================================

// UpsertBalance inserts or updates an account balance snapshot.
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
		r.logger.Error("failed to upsert account balance",
			util.String("company_id", b.CompanyID.String()),
			util.String("account_id", b.AccountID.String()),
			util.Int("fiscal_year", b.FiscalYear),
			util.Int("period", b.Period),
			util.ErrorField(err))
		return fmt.Errorf("upsert balance: %w", err)
	}
	return nil
}

// GetBalance retrieves a stored balance snapshot for a specific account and period.
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
			return nil, nil
		}
		r.logger.Error("failed to get balance",
			util.String("company_id", companyID.String()),
			util.String("account_id", accountID.String()),
			util.Int("fiscal_year", fiscalYear),
			util.Int("period", period),
			util.ErrorField(err))
		return nil, fmt.Errorf("get balance: %w", err)
	}
	return &b, nil
}

// GetBalancesByAccount returns all balances for an account in a given fiscal year.
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
		r.logger.Error("failed to get balances by account",
			util.String("company_id", companyID.String()),
			util.String("account_id", accountID.String()),
			util.Int("fiscal_year", fiscalYear),
			util.ErrorField(err))
		return nil, fmt.Errorf("get balances by account: %w", err)
	}
	defer rows.Close()

	var balances []*models.AccountBalance
	for rows.Next() {
		var b models.AccountBalance
		if err := rows.Scan(
			&b.BalanceID, &b.CompanyID, &b.AccountID, &b.FiscalYear, &b.Period,
			&b.OpeningBalance, &b.ClosingBalance, &b.IsRecomputed,
			&b.CreatedAt, &b.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan balance: %w", err)
		}
		balances = append(balances, &b)
	}
	return balances, nil
}

// GetBalancesByCompany returns all balances for a company in a specific period (all accounts).
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
		r.logger.Error("failed to get balances by company",
			util.String("company_id", companyID.String()),
			util.Int("fiscal_year", fiscalYear),
			util.Int("period", period),
			util.ErrorField(err))
		return nil, fmt.Errorf("get balances by company: %w", err)
	}
	defer rows.Close()

	var balances []*models.AccountBalance
	for rows.Next() {
		var b models.AccountBalance
		if err := rows.Scan(
			&b.BalanceID, &b.CompanyID, &b.AccountID, &b.FiscalYear, &b.Period,
			&b.OpeningBalance, &b.ClosingBalance, &b.IsRecomputed,
			&b.CreatedAt, &b.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan balance: %w", err)
		}
		balances = append(balances, &b)
	}
	return balances, nil
}

// MarkRecomputed marks all balances for a given period as recomputed.
func (r *ledgerRepository) MarkRecomputed(ctx context.Context, db DBTX, companyID uuid.UUID, fiscalYear, period int) error {
	query := `
		UPDATE accounting.account_balances
		SET is_recomputed = true, updated_at = NOW()
		WHERE company_id = $1 AND fiscal_year = $2 AND period = $3
	`
	result, err := db.ExecContext(ctx, query, companyID, fiscalYear, period)
	if err != nil {
		r.logger.Error("failed to mark recomputed",
			util.String("company_id", companyID.String()),
			util.Int("fiscal_year", fiscalYear),
			util.Int("period", period),
			util.ErrorField(err))
		return fmt.Errorf("mark recomputed: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		r.logger.Warn("no balances found to mark recomputed",
			util.String("company_id", companyID.String()),
			util.Int("fiscal_year", fiscalYear),
			util.Int("period", period))
	}
	return nil
}

// =====================================================
// COMPUTATION (FROM JOURNAL)
// =====================================================

// getAccountType retrieves the account type for a given account ID.
func (r *ledgerRepository) getAccountType(ctx context.Context, db DBTX, accountID uuid.UUID) (string, error) {
	query := `SELECT account_type FROM accounting.accounts WHERE account_id = $1 AND deleted_at IS NULL`
	var accType string
	err := db.QueryRowContext(ctx, query, accountID).Scan(&accType)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("account %s not found", accountID)
		}
		return "", err
	}
	return accType, nil
}

// ComputeAccountBalance returns opening, total debit, total credit, and closing balance for an account over a date range.
func (r *ledgerRepository) ComputeAccountBalance(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, from, to time.Time) (opening float64, debit float64, credit float64, closing float64, err error) {
	// Get account type to compute closing correctly
	accType, err := r.getAccountType(ctx, db, accountID)
	if err != nil {
		return 0, 0, 0, 0, err
	}

	// Opening balance = sum of all movements before 'from'
	opening, err = r.GetAccountOpeningBalance(ctx, db, accountID, from)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("compute opening balance: %w", err)
	}

	// Sum movements in period
	debit, credit, err = r.SumAccountMovement(ctx, db, accountID, from, to)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("compute period movement: %w", err)
	}

	// Use decimal for precision
	openingDec := decimal.NewFromFloat(opening)
	debitDec := decimal.NewFromFloat(debit)
	creditDec := decimal.NewFromFloat(credit)

	var closingDec decimal.Decimal
	if accType == enums.AccountTypeAsset || accType == enums.AccountTypeExpense {
		closingDec = openingDec.Add(debitDec).Sub(creditDec)
	} else {
		closingDec = openingDec.Add(creditDec).Sub(debitDec)
	}
	closing, _ = closingDec.Float64()

	return opening, debit, credit, closing, nil
}

// ComputeTrialBalance returns the trial balance for a given date range.
func (r *ledgerRepository) ComputeTrialBalance(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) ([]*TrialBalanceRow, error) {
	query := `
		SELECT
			a.account_id,
			a.account_code,
			a.account_name,
			COALESCE(SUM(jl.debit_amount), 0) AS total_debit,
			COALESCE(SUM(jl.credit_amount), 0) AS total_credit
		FROM accounting.accounts a
		LEFT JOIN accounting.journal_lines jl ON a.account_id = jl.account_id
		LEFT JOIN accounting.journal_entries je ON jl.journal_entry_id = je.journal_entry_id
			AND je.status = 'posted'
			AND je.entry_date BETWEEN $2 AND $3
		WHERE a.company_id = $1 AND a.deleted_at IS NULL
		GROUP BY a.account_id, a.account_code, a.account_name
		ORDER BY a.account_code
	`
	rows, err := db.QueryContext(ctx, query, companyID, from, to)
	if err != nil {
		r.logger.Error("failed to compute trial balance",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("compute trial balance: %w", err)
	}
	defer rows.Close()

	var rowsOut []*TrialBalanceRow
	for rows.Next() {
		var row TrialBalanceRow
		if err := rows.Scan(&row.AccountID, &row.AccountCode, &row.AccountName, &row.Debit, &row.Credit); err != nil {
			return nil, fmt.Errorf("scan trial balance row: %w", err)
		}
		rowsOut = append(rowsOut, &row)
	}
	return rowsOut, nil
}

// ComputePAndL returns the Profit & Loss statement rows.
func (r *ledgerRepository) ComputePAndL(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) ([]*PAndLRow, error) {
	query := `
		SELECT
			a.account_id,
			a.account_name,
			a.account_type,
			COALESCE(SUM(jl.debit_amount), 0) AS total_debit,
			COALESCE(SUM(jl.credit_amount), 0) AS total_credit
		FROM accounting.accounts a
		LEFT JOIN accounting.journal_lines jl ON a.account_id = jl.account_id
		LEFT JOIN accounting.journal_entries je ON jl.journal_entry_id = je.journal_entry_id
			AND je.status = 'posted'
			AND je.entry_date BETWEEN $2 AND $3
		WHERE a.company_id = $1
		  AND a.deleted_at IS NULL
		  AND a.account_type IN ('revenue', 'expense')
		GROUP BY a.account_id, a.account_name, a.account_type
	`
	rows, err := db.QueryContext(ctx, query, companyID, from, to)
	if err != nil {
		r.logger.Error("failed to compute P&L",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("compute P&L: %w", err)
	}
	defer rows.Close()

	var rowsOut []*PAndLRow
	for rows.Next() {
		var accID uuid.UUID
		var accName, accType string
		var totalDebit, totalCredit float64
		if err := rows.Scan(&accID, &accName, &accType, &totalDebit, &totalCredit); err != nil {
			return nil, fmt.Errorf("scan P&L row: %w", err)
		}
		var amount float64
		if accType == enums.AccountTypeRevenue {
			// Revenue: net credit (credit - debit)
			amount = totalCredit - totalDebit
		} else { // Expense
			// Expense: net debit (debit - credit)
			amount = totalDebit - totalCredit
		}
		rowsOut = append(rowsOut, &PAndLRow{
			AccountID:   accID,
			AccountName: accName,
			AccountType: accType,
			Amount:      amount,
		})
	}
	return rowsOut, nil
}

// ComputeBalanceSheet returns the Balance Sheet rows as of a specific date.
func (r *ledgerRepository) ComputeBalanceSheet(ctx context.Context, db DBTX, companyID uuid.UUID, asOf time.Time) ([]*BalanceSheetRow, error) {
	// We need closing balance for each asset, liability, equity account.
	query := `
		WITH movements AS (
			SELECT
				jl.account_id,
				COALESCE(SUM(jl.debit_amount), 0) AS total_debit,
				COALESCE(SUM(jl.credit_amount), 0) AS total_credit
			FROM accounting.journal_lines jl
			JOIN accounting.journal_entries je ON jl.journal_entry_id = je.journal_entry_id
			WHERE je.status = 'posted'
			  AND je.entry_date <= $2
			  AND jl.account_id IN (
				  SELECT account_id FROM accounting.accounts
				  WHERE company_id = $1 AND deleted_at IS NULL
				    AND account_type IN ('asset', 'liability', 'equity')
			  )
			GROUP BY jl.account_id
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
		r.logger.Error("failed to compute balance sheet",
			util.String("company_id", companyID.String()),
			util.Time("as_of", asOf),
			util.ErrorField(err))
		return nil, fmt.Errorf("compute balance sheet: %w", err)
	}
	defer rows.Close()

	var rowsOut []*BalanceSheetRow
	for rows.Next() {
		var row BalanceSheetRow
		if err := rows.Scan(&row.AccountID, &row.AccountName, &row.AccountType, &row.Amount); err != nil {
			return nil, fmt.Errorf("scan balance sheet row: %w", err)
		}
		rowsOut = append(rowsOut, &row)
	}
	return rowsOut, nil
}

// =====================================================
// LEDGER (ACCOUNT STATEMENT)
// =====================================================

// GetAccountLedger returns all journal entries for an account with running balance.
func (r *ledgerRepository) GetAccountLedger(ctx context.Context, db DBTX, accountID uuid.UUID, from, to time.Time) ([]*LedgerEntry, error) {
	// Use window function to compute running balance based on account type.
	query := `
		SELECT
			je.journal_entry_id,
			je.entry_date,
			je.reference,
			je.description,
			jl.debit_amount,
			jl.credit_amount,
			SUM(
				CASE
					WHEN a.account_type IN ('asset', 'expense') THEN jl.debit_amount - jl.credit_amount
					ELSE jl.credit_amount - jl.debit_amount
				END
			) OVER (ORDER BY je.entry_date, je.created_at, jl.line_number) AS running_balance
		FROM accounting.journal_lines jl
		JOIN accounting.journal_entries je ON jl.journal_entry_id = je.journal_entry_id
		JOIN accounting.accounts a ON jl.account_id = a.account_id
		WHERE jl.account_id = $1
		  AND je.status = 'posted'
		  AND je.entry_date BETWEEN $2 AND $3
		ORDER BY je.entry_date, je.created_at, jl.line_number
	`
	rows, err := db.QueryContext(ctx, query, accountID, from, to)
	if err != nil {
		r.logger.Error("failed to get account ledger",
			util.String("account_id", accountID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get account ledger: %w", err)
	}
	defer rows.Close()

	var entries []*LedgerEntry
	for rows.Next() {
		var e LedgerEntry
		if err := rows.Scan(
			&e.JournalEntryID, &e.Date, &e.Reference, &e.Description,
			&e.Debit, &e.Credit, &e.RunningBalance,
		); err != nil {
			return nil, fmt.Errorf("scan ledger entry: %w", err)
		}
		entries = append(entries, &e)
	}
	return entries, nil
}

// GetAccountOpeningBalance returns the balance of an account before a given date.
func (r *ledgerRepository) GetAccountOpeningBalance(ctx context.Context, db DBTX, accountID uuid.UUID, before time.Time) (float64, error) {
	// Get account type to compute balance correctly
	accType, err := r.getAccountType(ctx, db, accountID)
	if err != nil {
		return 0, err
	}

	query := `
		SELECT
			COALESCE(SUM(
				CASE
					WHEN $2 IN ('asset', 'expense') THEN jl.debit_amount - jl.credit_amount
					ELSE jl.credit_amount - jl.debit_amount
				END
			), 0) AS balance
		FROM accounting.journal_lines jl
		JOIN accounting.journal_entries je ON jl.journal_entry_id = je.journal_entry_id
		WHERE jl.account_id = $1
		  AND je.status = 'posted'
		  AND je.entry_date < $3
	`
	var balance float64
	err = db.QueryRowContext(ctx, query, accountID, accType, before).Scan(&balance)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		r.logger.Error("failed to get opening balance",
			util.String("account_id", accountID.String()),
			util.ErrorField(err))
		return 0, fmt.Errorf("get opening balance: %w", err)
	}
	return balance, nil
}

// =====================================================
// RECOMPUTATION
// =====================================================

// RecomputeAccount recomputes all period balances for a single account in a fiscal year.
func (r *ledgerRepository) RecomputeAccount(ctx context.Context, db DBTX, companyID, accountID uuid.UUID, fiscalYear int) error {
	// For simplicity, assume fiscal year = calendar year.
	periodStart := time.Date(fiscalYear, 1, 1, 0, 0, 0, 0, time.UTC)

	// Get account type
	accType, err := r.getAccountType(ctx, db, accountID)
	if err != nil {
		return err
	}

	// Opening balance before fiscal year
	opening, err := r.GetAccountOpeningBalance(ctx, db, accountID, periodStart)
	if err != nil {
		return fmt.Errorf("get opening for recompute: %w", err)
	}
	openingDec := decimal.NewFromFloat(opening)

	// For each period (1..12), compute movement and closing
	for period := 1; period <= 12; period++ {
		// Period date range
		from := time.Date(fiscalYear, time.Month(period), 1, 0, 0, 0, 0, time.UTC)
		to := from.AddDate(0, 1, -1).Truncate(24 * time.Hour).Add(23*time.Hour + 59*time.Minute + 59*time.Second)

		// Sum movements in period
		debit, credit, err := r.SumAccountMovement(ctx, db, accountID, from, to)
		if err != nil {
			return fmt.Errorf("sum movement period %d: %w", period, err)
		}
		debitDec := decimal.NewFromFloat(debit)
		creditDec := decimal.NewFromFloat(credit)

		var closingDec decimal.Decimal
		if accType == enums.AccountTypeAsset || accType == enums.AccountTypeExpense {
			closingDec = openingDec.Add(debitDec).Sub(creditDec)
		} else {
			closingDec = openingDec.Add(creditDec).Sub(debitDec)
		}
		// Convert to float64 for model (if model uses float64; adjust if needed)
		_, _ = closingDec.Float64()

		// Upsert balance (model uses decimal.Decimal – assign directly)
		balance := &models.AccountBalance{
			BalanceID:      uuid.New(),
			CompanyID:      companyID,
			AccountID:      accountID,
			FiscalYear:     fiscalYear,
			Period:         period,
			OpeningBalance: openingDec, // decimal.Decimal
			ClosingBalance: closingDec,
			IsRecomputed:   true,
		}
		if err := r.UpsertBalance(ctx, db, balance); err != nil {
			return fmt.Errorf("upsert balance period %d: %w", period, err)
		}

		// Next period opening = current closing
		openingDec = closingDec
	}
	return nil
}

// RecomputePeriod recomputes balances for all accounts for a specific period.
func (r *ledgerRepository) RecomputePeriod(ctx context.Context, db DBTX, companyID uuid.UUID, fiscalYear, period int) error {
	// Get all active account IDs for the company
	accounts, err := r.getAllAccountIDs(ctx, db, companyID)
	if err != nil {
		return err
	}
	for _, accID := range accounts {
		if err := r.RecomputeAccount(ctx, db, companyID, accID, fiscalYear); err != nil {
			r.logger.Error("failed to recompute account for period",
				util.String("account_id", accID.String()),
				util.Int("period", period),
				util.ErrorField(err))
			return fmt.Errorf("recompute account %s for period %d: %w", accID, period, err)
		}
	}
	return nil
}

// RecomputeCompany recomputes all accounts for all periods in a fiscal year.
func (r *ledgerRepository) RecomputeCompany(ctx context.Context, db DBTX, companyID uuid.UUID, fiscalYear int) error {
	for period := 1; period <= 12; period++ {
		if err := r.RecomputePeriod(ctx, db, companyID, fiscalYear, period); err != nil {
			return fmt.Errorf("recompute period %d: %w", period, err)
		}
	}
	return nil
}

// Helper: get all active account IDs for a company.
func (r *ledgerRepository) getAllAccountIDs(ctx context.Context, db DBTX, companyID uuid.UUID) ([]uuid.UUID, error) {
	query := `SELECT account_id FROM accounting.accounts WHERE company_id = $1 AND deleted_at IS NULL`
	rows, err := db.QueryContext(ctx, query, companyID)
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

// =====================================================
// VALIDATION / CONSISTENCY
// =====================================================

// CheckImbalance returns true if total debits != total credits for a period.
func (r *ledgerRepository) CheckImbalance(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) (bool, float64, float64, error) {
	query := `
		SELECT
			COALESCE(SUM(jl.debit_amount), 0) AS total_debit,
			COALESCE(SUM(jl.credit_amount), 0) AS total_credit
		FROM accounting.journal_lines jl
		JOIN accounting.journal_entries je ON jl.journal_entry_id = je.journal_entry_id
		WHERE je.company_id = $1
		  AND je.status = 'posted'
		  AND je.entry_date BETWEEN $2 AND $3
	`
	var totalDebit, totalCredit float64
	err := db.QueryRowContext(ctx, query, companyID, from, to).Scan(&totalDebit, &totalCredit)
	if err != nil {
		r.logger.Error("failed to check imbalance",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return false, 0, 0, fmt.Errorf("check imbalance: %w", err)
	}
	imbalance := totalDebit != totalCredit
	return imbalance, totalDebit, totalCredit, nil
}

// =====================================================
// PERFORMANCE HELPERS
// =====================================================

// SumAccountMovement returns total debit and credit for an account in a date range.
func (r *ledgerRepository) SumAccountMovement(ctx context.Context, db DBTX, accountID uuid.UUID, from, to time.Time) (debit float64, credit float64, err error) {
	query := `
		SELECT
			COALESCE(SUM(jl.debit_amount), 0) AS total_debit,
			COALESCE(SUM(jl.credit_amount), 0) AS total_credit
		FROM accounting.journal_lines jl
		JOIN accounting.journal_entries je ON jl.journal_entry_id = je.journal_entry_id
		WHERE jl.account_id = $1
		  AND je.status = 'posted'
		  AND je.entry_date BETWEEN $2 AND $3
	`
	err = db.QueryRowContext(ctx, query, accountID, from, to).Scan(&debit, &credit)
	if err != nil {
		r.logger.Error("failed to sum account movement",
			util.String("account_id", accountID.String()),
			util.ErrorField(err))
		return 0, 0, fmt.Errorf("sum movement: %w", err)
	}
	return debit, credit, nil
}
