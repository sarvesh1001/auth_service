package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/accounting/models"
	"auth-service/internal/accounting/repository"
	"auth-service/internal/client"
)

// AccountingQueryService provides read‑only queries for reports and dashboards.
type AccountingQueryService struct {
	journalRepo    repository.JournalRepository
	ledgerRepo     repository.LedgerRepository
	taxTxRepo      repository.TaxTransactionRepository
	complianceRepo repository.ComplianceRepository
	analyticsRepo  repository.AnalyticsRepository
	pgClient       *client.PostgresClient
	logger         *zap.Logger
}

// NewAccountingQueryService creates a new query service.
func NewAccountingQueryService(
	journalRepo repository.JournalRepository,
	ledgerRepo repository.LedgerRepository,
	taxTxRepo repository.TaxTransactionRepository,
	complianceRepo repository.ComplianceRepository,
	analyticsRepo repository.AnalyticsRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) *AccountingQueryService {
	return &AccountingQueryService{
		journalRepo:    journalRepo,
		ledgerRepo:     ledgerRepo,
		taxTxRepo:      taxTxRepo,
		complianceRepo: complianceRepo,
		analyticsRepo:  analyticsRepo,
		pgClient:       pgClient,
		logger:         logger.Named("accounting_query_service"),
	}
}

// ---------------------------------------------------------------------
// Trial Balance
// ---------------------------------------------------------------------

type TrialBalanceEntry struct {
	AccountID      uuid.UUID       `json:"account_id"`
	AccountCode    string          `json:"account_code"`
	AccountName    string          `json:"account_name"`
	AccountType    string          `json:"account_type"`
	OpeningBalance decimal.Decimal `json:"opening_balance"`
	TotalDebit     decimal.Decimal `json:"total_debit"`
	TotalCredit    decimal.Decimal `json:"total_credit"`
	ClosingBalance decimal.Decimal `json:"closing_balance"`
}

// GetTrialBalance returns trial balance from account_balance table.
// GetTrialBalance returns trial balance entries, total debit, total credit, and error.
func (s *AccountingQueryService) GetTrialBalance(
	ctx context.Context,
	companyID uuid.UUID,
	fiscalYear int,
	period int,
) ([]TrialBalanceEntry, decimal.Decimal, decimal.Decimal, error) {
	query := `
		SELECT
			b.account_id,
			a.account_code,
			a.account_name,
			a.account_type,
			b.opening_balance,
			COALESCE(b.total_debit, 0) AS total_debit,
			COALESCE(b.total_credit, 0) AS total_credit,
			b.closing_balance
		FROM accounting.account_balance b
		JOIN accounting.accounts a ON b.account_id = a.account_id
		WHERE b.company_id = $1
		  AND b.fiscal_year = $2
		  AND b.period = $3
		  AND a.deleted_at IS NULL   -- ← added soft-delete filter
		ORDER BY a.account_code
	`

	rows, err := s.pgClient.DB.QueryContext(ctx, query, companyID, fiscalYear, period)
	if err != nil {
		return nil, decimal.Zero, decimal.Zero, fmt.Errorf("query trial balance: %w", err)
	}
	defer rows.Close()

	var entries []TrialBalanceEntry
	var totalDebit, totalCredit decimal.Decimal

	for rows.Next() {
		var e TrialBalanceEntry
		err := rows.Scan(
			&e.AccountID, &e.AccountCode, &e.AccountName, &e.AccountType,
			&e.OpeningBalance, &e.TotalDebit, &e.TotalCredit, &e.ClosingBalance,
		)
		if err != nil {
			return nil, decimal.Zero, decimal.Zero, fmt.Errorf("scan row: %w", err)
		}
		entries = append(entries, e)

		// ✅ FIX: sum the debit/credit columns, not the closing balance sign
		totalDebit = totalDebit.Add(e.TotalDebit)
		totalCredit = totalCredit.Add(e.TotalCredit)
	}

	return entries, totalDebit, totalCredit, nil
}

// ---------------------------------------------------------------------
// General Ledger (Account Statement)
// ---------------------------------------------------------------------

type GeneralLedgerEntry struct {
	Date           time.Time       `json:"date"`
	JournalID      uuid.UUID       `json:"journal_id"`
	JournalType    string          `json:"journal_type"`
	Reference      *string         `json:"reference,omitempty"`
	Description    *string         `json:"description,omitempty"`
	DebitAmount    decimal.Decimal `json:"debit_amount"`
	CreditAmount   decimal.Decimal `json:"credit_amount"`
	RunningBalance decimal.Decimal `json:"running_balance"`
}

// GetGeneralLedger returns all journal lines for an account with running balance.
func (s *AccountingQueryService) GetGeneralLedger(
	ctx context.Context,
	companyID, accountID uuid.UUID,
	startDate, endDate time.Time,
) ([]GeneralLedgerEntry, decimal.Decimal, error) {
	openingBalance, err := s.getAccountBalanceAsOf(ctx, companyID, accountID, startDate.Add(-time.Nanosecond))
	if err != nil {
		return nil, decimal.Zero, fmt.Errorf("get opening balance: %w", err)
	}

	query := `
		SELECT
			j.entry_date,
			j.journal_entry_id,
			j.journal_type,
			j.reference,
			j.description,
			l.debit_amount,
			l.credit_amount
		FROM accounting.journal_lines l
		JOIN accounting.journal_entries j ON l.journal_entry_id = j.journal_entry_id
		WHERE j.company_id = $1
		  AND l.account_id = $2
		  AND j.entry_date BETWEEN $3 AND $4
		  AND j.status = 'posted'
		  AND j.deleted_at IS NULL   -- if you have soft-delete on journal_entries
		ORDER BY j.entry_date, j.journal_entry_id, l.line_number   -- ✅ stable order
	`

	rows, err := s.pgClient.DB.QueryContext(ctx, query, companyID, accountID, startDate, endDate)
	if err != nil {
		return nil, decimal.Zero, fmt.Errorf("query ledger lines: %w", err)
	}
	defer rows.Close()

	entries := make([]GeneralLedgerEntry, 0)
	balance := openingBalance

	for rows.Next() {
		var e GeneralLedgerEntry
		err := rows.Scan(
			&e.Date, &e.JournalID, &e.JournalType, &e.Reference, &e.Description,
			&e.DebitAmount, &e.CreditAmount,
		)
		if err != nil {
			return nil, decimal.Zero, fmt.Errorf("scan row: %w", err)
		}
		balance = balance.Add(e.DebitAmount).Sub(e.CreditAmount)
		e.RunningBalance = balance
		entries = append(entries, e)
	}
	return entries, openingBalance, nil
}

// getAccountBalanceAsOf calculates balance up to a given date by aggregating journal lines.
func (s *AccountingQueryService) getAccountBalanceAsOf(ctx context.Context, companyID, accountID uuid.UUID, asOf time.Time) (decimal.Decimal, error) {
	query := `
		SELECT COALESCE(SUM(l.debit_amount - l.credit_amount), 0)
		FROM accounting.journal_lines l
		JOIN accounting.journal_entries j ON l.journal_entry_id = j.journal_entry_id
		WHERE j.company_id = $1 AND l.account_id = $2 
		  AND j.entry_date <= $3
		  AND j.status = 'posted'
	`
	var balance decimal.Decimal
	err := s.pgClient.DB.QueryRowContext(ctx, query, companyID, accountID, asOf).Scan(&balance)
	if err != nil {
		return decimal.Zero, fmt.Errorf("compute balance: %w", err)
	}
	return balance, nil
}

// ---------------------------------------------------------------------
// Balance Sheet (using account_snapshot table)
// ---------------------------------------------------------------------

type AccountBalanceSnapshot struct {
	AccountID   uuid.UUID       `json:"account_id"`
	AccountCode string          `json:"account_code"`
	AccountName string          `json:"account_name"`
	AccountType string          `json:"account_type"`
	Balance     decimal.Decimal `json:"balance"`
}

// GetBalanceSheet returns assets, liabilities, equity as of a given date using account_snapshot.
func (s *AccountingQueryService) GetBalanceSheet(
	ctx context.Context,
	companyID uuid.UUID,
	asOf time.Time,
) (assets, liabilities, equity []AccountBalanceSnapshot, totalAssets, totalLiabilities, totalEquity decimal.Decimal, err error) {
	// ✅ corrected table name
	query := `
		SELECT
			s.account_id,
			a.account_code,
			a.account_name,
			a.account_type,
			s.balance
		FROM accounting.analytics_account_snapshots s
		JOIN accounting.accounts a ON s.account_id = a.account_id
		WHERE s.company_id = $1
		  AND s.snapshot_date = $2
		  AND a.deleted_at IS NULL
		ORDER BY a.account_code
	`

	rows, err := s.pgClient.DB.QueryContext(ctx, query, companyID, asOf)
	if err != nil {
		// fallback to dynamic calculation
		return s.calcBalanceSheetDynamic(ctx, companyID, asOf)
	}
	defer rows.Close()

	for rows.Next() {
		var snap AccountBalanceSnapshot
		err := rows.Scan(&snap.AccountID, &snap.AccountCode, &snap.AccountName, &snap.AccountType, &snap.Balance)
		if err != nil {
			return nil, nil, nil, decimal.Zero, decimal.Zero, decimal.Zero, fmt.Errorf("scan snapshot: %w", err)
		}
		switch snap.AccountType {
		case "asset":
			assets = append(assets, snap)
			totalAssets = totalAssets.Add(snap.Balance)
		case "liability":
			liabilities = append(liabilities, snap)
			totalLiabilities = totalLiabilities.Add(snap.Balance)
		case "equity":
			equity = append(equity, snap)
			totalEquity = totalEquity.Add(snap.Balance)
		}
	}
	return assets, liabilities, equity, totalAssets, totalLiabilities, totalEquity, nil
}

// calcBalanceSheetDynamic fallback – aggregates from journal lines directly.
func (s *AccountingQueryService) calcBalanceSheetDynamic(ctx context.Context, companyID uuid.UUID, asOf time.Time) ([]AccountBalanceSnapshot, []AccountBalanceSnapshot, []AccountBalanceSnapshot, decimal.Decimal, decimal.Decimal, decimal.Decimal, error) {
	// Get all active accounts for the company
	queryAccounts := `
		SELECT account_id, account_code, account_name, account_type
		FROM accounting.accounts
		WHERE company_id = $1 AND deleted_at IS NULL AND is_active = true
	`
	rows, err := s.pgClient.DB.QueryContext(ctx, queryAccounts, companyID)
	if err != nil {
		return nil, nil, nil, decimal.Zero, decimal.Zero, decimal.Zero, fmt.Errorf("get accounts: %w", err)
	}
	defer rows.Close()

	var assets, liabilities, equity []AccountBalanceSnapshot
	var totalAssets, totalLiabilities, totalEquity decimal.Decimal

	for rows.Next() {
		var acc AccountBalanceSnapshot
		err := rows.Scan(&acc.AccountID, &acc.AccountCode, &acc.AccountName, &acc.AccountType)
		if err != nil {
			continue
		}
		balance, err := s.getAccountBalanceAsOf(ctx, companyID, acc.AccountID, asOf)
		if err != nil {
			continue
		}
		if balance.IsZero() {
			continue
		}
		acc.Balance = balance
		switch acc.AccountType {
		case "asset":
			assets = append(assets, acc)
			totalAssets = totalAssets.Add(balance)
		case "liability":
			liabilities = append(liabilities, acc)
			totalLiabilities = totalLiabilities.Add(balance)
		case "equity":
			equity = append(equity, acc)
			totalEquity = totalEquity.Add(balance)
		}
	}
	return assets, liabilities, equity, totalAssets, totalLiabilities, totalEquity, nil
}

// ---------------------------------------------------------------------
// Income Statement
// ---------------------------------------------------------------------

type IncomeStatementEntry struct {
	AccountID   uuid.UUID       `json:"account_id"`
	AccountCode string          `json:"account_code"`
	AccountName string          `json:"account_name"`
	Amount      decimal.Decimal `json:"amount"`
}

// GetIncomeStatement returns revenue and expenses for a period using daily summaries.
func (s *AccountingQueryService) GetIncomeStatement(
	ctx context.Context,
	companyID uuid.UUID,
	fiscalYear, period int,
) (revenues, expenses []IncomeStatementEntry, totalRevenue, totalExpense, netIncome decimal.Decimal, err error) {
	// ✅ corrected table name
	query := `
		SELECT
			a.account_id,
			a.account_code,
			a.account_name,
			a.account_type,
			SUM(d.net_movement) AS net_movement
		FROM accounting.analytics_daily_account_summary d
		JOIN accounting.accounts a ON d.account_id = a.account_id
		WHERE d.company_id = $1
		  AND EXTRACT(YEAR FROM d.date) = $2
		  AND EXTRACT(MONTH FROM d.date) = $3
		  AND a.deleted_at IS NULL
		GROUP BY a.account_id, a.account_code, a.account_name, a.account_type
		HAVING a.account_type IN ('revenue', 'expense')
	`

	rows, err := s.pgClient.DB.QueryContext(ctx, query, companyID, fiscalYear, period)
	if err != nil {
		return nil, nil, decimal.Zero, decimal.Zero, decimal.Zero, fmt.Errorf("query income statement: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var entry IncomeStatementEntry
		var accType string
		var net decimal.Decimal
		err := rows.Scan(&entry.AccountID, &entry.AccountCode, &entry.AccountName, &accType, &net)
		if err != nil {
			return nil, nil, decimal.Zero, decimal.Zero, decimal.Zero, fmt.Errorf("scan row: %w", err)
		}
		entry.Amount = net
		if accType == "revenue" {
			revenues = append(revenues, entry)
			totalRevenue = totalRevenue.Add(net)
		} else {
			expenses = append(expenses, entry)
			totalExpense = totalExpense.Add(net)
		}
	}
	netIncome = totalRevenue.Sub(totalExpense)
	return revenues, expenses, totalRevenue, totalExpense, netIncome, nil
}

// ---------------------------------------------------------------------
// Cash Flow Statement (using cashflow table)
// ---------------------------------------------------------------------

type CashFlowEntry struct {
	Category string          `json:"category"`
	Amount   decimal.Decimal `json:"amount"`
}

// GetCashFlowStatement returns operating, investing, financing cash flows.
func (s *AccountingQueryService) GetCashFlowStatement(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) (operating, investing, financing decimal.Decimal, err error) {
	// ✅ corrected table name
	query := `
		SELECT category, SUM(amount) as total
		FROM accounting.analytics_cashflow
		WHERE company_id = $1 AND date BETWEEN $2 AND $3
		GROUP BY category
	`

	rows, err := s.pgClient.DB.QueryContext(ctx, query, companyID, startDate, endDate)
	if err != nil {
		return decimal.Zero, decimal.Zero, decimal.Zero, fmt.Errorf("query cashflow: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var cat string
		var amt decimal.Decimal
		if err := rows.Scan(&cat, &amt); err != nil {
			continue
		}
		switch cat {
		case "operating":
			operating = operating.Add(amt)
		case "investing":
			investing = investing.Add(amt)
		case "financing":
			financing = financing.Add(amt)
		}
	}
	return operating, investing, financing, nil
}

// ---------------------------------------------------------------------
// Tax Summary
// ---------------------------------------------------------------------

type TaxSummaryResult struct {
	TaxRateID     *uuid.UUID      `json:"tax_rate_id,omitempty"`
	TaxRateName   string          `json:"tax_rate_name"`
	TaxableAmount decimal.Decimal `json:"taxable_amount"`
	TaxAmount     decimal.Decimal `json:"tax_amount"`
}

// GetTaxSummary aggregates tax transactions by rate.
func (s *AccountingQueryService) GetTaxSummary(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) ([]TaxSummaryResult, decimal.Decimal, error) {
	query := `
		SELECT 
			tax_rate_id, tax_rate_name, 
			SUM(taxable_amount) AS total_taxable, 
			SUM(tax_amount) AS total_tax
		FROM accounting.tax_transactions
		WHERE company_id = $1 AND transaction_date BETWEEN $2 AND $3
		GROUP BY tax_rate_id, tax_rate_name
	`
	rows, err := s.pgClient.DB.QueryContext(ctx, query, companyID, startDate, endDate)
	if err != nil {
		return nil, decimal.Zero, fmt.Errorf("query tax summary: %w", err)
	}
	defer rows.Close()

	var results []TaxSummaryResult
	var totalTax decimal.Decimal
	for rows.Next() {
		var r TaxSummaryResult
		var rateID *uuid.UUID
		var rateName string
		err := rows.Scan(&rateID, &rateName, &r.TaxableAmount, &r.TaxAmount)
		if err != nil {
			return nil, decimal.Zero, fmt.Errorf("scan row: %w", err)
		}
		r.TaxRateID = rateID
		r.TaxRateName = rateName
		results = append(results, r)
		totalTax = totalTax.Add(r.TaxAmount)
	}
	return results, totalTax, nil
}

// ---------------------------------------------------------------------
// Compliance Returns List
// ---------------------------------------------------------------------

type ComplianceReturnSummary struct {
	ReturnID       uuid.UUID       `json:"return_id"`
	ReturnType     string          `json:"return_type"`
	PeriodStart    time.Time       `json:"period_start"`
	PeriodEnd      time.Time       `json:"period_end"`
	Status         string          `json:"status"`
	TotalLiability decimal.Decimal `json:"total_liability"`
	FiledAt        *time.Time      `json:"filed_at,omitempty"`
}

// ListComplianceReturns returns compliance returns for a company.
func (s *AccountingQueryService) ListComplianceReturns(
	ctx context.Context,
	companyID uuid.UUID,
	status string,
	year int,
	limit, offset int,
) ([]ComplianceReturnSummary, int64, error) {
	// Build filter conditions
	where := "company_id = $1"
	args := []interface{}{companyID}
	idx := 2
	if status != "" {
		where += fmt.Sprintf(" AND status = $%d", idx)
		args = append(args, status)
		idx++
	}
	if year > 0 {
		where += fmt.Sprintf(" AND EXTRACT(YEAR FROM period_start) = $%d", idx)
		args = append(args, year)
		idx++
	}
	// Count query
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM compliance.returns WHERE %s", where)
	var total int64
	err := s.pgClient.DB.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count returns: %w", err)
	}
	if total == 0 {
		return []ComplianceReturnSummary{}, 0, nil
	}
	// Data query
	dataQuery := fmt.Sprintf(`
		SELECT return_id, return_type, period_start, period_end, status, total_liability, filed_at
		FROM compliance.returns
		WHERE %s
		ORDER BY period_start DESC
		LIMIT $%d OFFSET $%d
	`, where, idx, idx+1)
	args = append(args, limit, offset)
	rows, err := s.pgClient.DB.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query returns: %w", err)
	}
	defer rows.Close()

	var summaries []ComplianceReturnSummary
	for rows.Next() {
		var s ComplianceReturnSummary
		err := rows.Scan(&s.ReturnID, &s.ReturnType, &s.PeriodStart, &s.PeriodEnd, &s.Status, &s.TotalLiability, &s.FiledAt)
		if err != nil {
			return nil, 0, fmt.Errorf("scan row: %w", err)
		}
		summaries = append(summaries, s)
	}
	return summaries, total, nil
}

// GetJournalEntryWithLines returns a full journal entry with its lines.
func (s *AccountingQueryService) GetJournalEntryWithLines(ctx context.Context, journalID uuid.UUID) (*models.JournalEntry, []*models.JournalLine, error) {
	entry, err := s.journalRepo.GetByID(ctx, s.pgClient.DB, journalID)
	if err != nil {
		return nil, nil, err
	}
	if entry == nil {
		return nil, nil, ErrNotFound
	}
	lines, err := s.journalRepo.GetLines(ctx, s.pgClient.DB, journalID)
	if err != nil {
		return nil, nil, err
	}
	return entry, lines, nil
}
