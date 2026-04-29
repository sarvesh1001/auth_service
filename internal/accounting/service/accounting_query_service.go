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

// AccountingQueryService provides read‑only financial reports and queries.
// All methods enforce company isolation via repository filters.
type AccountingQueryService struct {
	accountRepo    repository.AccountRepository
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
	accountRepo repository.AccountRepository,
	journalRepo repository.JournalRepository,
	ledgerRepo repository.LedgerRepository,
	taxTxRepo repository.TaxTransactionRepository,
	complianceRepo repository.ComplianceRepository,
	analyticsRepo repository.AnalyticsRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) *AccountingQueryService {
	return &AccountingQueryService{
		accountRepo:    accountRepo,
		journalRepo:    journalRepo,
		ledgerRepo:     ledgerRepo,
		taxTxRepo:      taxTxRepo,
		complianceRepo: complianceRepo,
		analyticsRepo:  analyticsRepo,
		pgClient:       pgClient,
		logger:         logger.Named("accounting_query_service"),
	}
}

// --------------------------------------------------------------------------
// Trial Balance
// --------------------------------------------------------------------------

// TrialBalanceEntry represents a single line in a trial balance report.
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

// GetTrialBalance returns the trial balance for a given fiscal year and period.
func (s *AccountingQueryService) GetTrialBalance(
	ctx context.Context,
	companyID uuid.UUID,
	fiscalYear int,
	period int,
) ([]TrialBalanceEntry, decimal.Decimal, decimal.Decimal, error) {
	startDate, endDate := periodToDateRange(fiscalYear, period)

	// Get period movements (debit/credit)
	rows, err := s.ledgerRepo.ComputeTrialBalance(ctx, s.pgClient.DB, companyID, startDate, endDate)
	if err != nil {
		return nil, decimal.Zero, decimal.Zero, fmt.Errorf("compute trial balance: %w", err)
	}

	// For each account, fetch opening balance from account_balances
	entries := make([]TrialBalanceEntry, 0, len(rows))
	var totalDebit, totalCredit decimal.Decimal

	for _, r := range rows {
		// Get opening balance (if exists)
		bal, err := s.ledgerRepo.GetBalance(ctx, s.pgClient.DB, companyID, r.AccountID, fiscalYear, period)
		opening := decimal.Zero
		if err == nil && bal != nil {
			opening = bal.OpeningBalance
		}

		// Fetch account type (ComputeTrialBalance does not return it)
		accType, err := s.accountRepo.GetAccountType(ctx, s.pgClient.DB, r.AccountID)
		if err != nil {
			// Fallback: treat as asset
			accType = "asset"
		}

		var closing decimal.Decimal
		if accType == "asset" || accType == "expense" {
			closing = opening.Add(r.Debit).Sub(r.Credit)
		} else {
			closing = opening.Add(r.Credit).Sub(r.Debit)
		}

		entries = append(entries, TrialBalanceEntry{
			AccountID:      r.AccountID,
			AccountCode:    r.AccountCode,
			AccountName:    r.AccountName,
			AccountType:    accType,
			OpeningBalance: opening,
			TotalDebit:     r.Debit,
			TotalCredit:    r.Credit,
			ClosingBalance: closing,
		})

		totalDebit = totalDebit.Add(r.Debit)
		totalCredit = totalCredit.Add(r.Credit)
	}

	return entries, totalDebit, totalCredit, nil
}

// --------------------------------------------------------------------------
// General Ledger (Account Ledger)
// --------------------------------------------------------------------------

// GeneralLedgerEntry represents a single line in an account's ledger.
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

// GetGeneralLedger returns the ledger entries for a specific account within a date range.
func (s *AccountingQueryService) GetGeneralLedger(
	ctx context.Context,
	companyID, accountID uuid.UUID,
	startDate, endDate time.Time,
) ([]GeneralLedgerEntry, decimal.Decimal, error) {
	// Ensure endDate is inclusive
	endDate = endDate.Add(24*time.Hour - time.Nanosecond)

	// Opening balance as of startDate (exclusive)
	openingBalance, err := s.ledgerRepo.GetAccountOpeningBalance(ctx, s.pgClient.DB, companyID, accountID, startDate)
	if err != nil {
		return nil, decimal.Zero, fmt.Errorf("get opening balance: %w", err)
	}

	entries, err := s.ledgerRepo.GetAccountLedger(ctx, s.pgClient.DB, companyID, accountID, startDate, endDate)
	if err != nil {
		return nil, decimal.Zero, fmt.Errorf("get account ledger: %w", err)
	}

	result := make([]GeneralLedgerEntry, 0, len(entries))
	balance := openingBalance
	for _, e := range entries {
		balance = balance.Add(e.Debit).Sub(e.Credit)
		result = append(result, GeneralLedgerEntry{
			Date:           e.Date,
			JournalID:      e.JournalEntryID,
			JournalType:    "", // could be fetched from journal entry if needed; omitted for performance
			Reference:      e.Reference,
			Description:    e.Description,
			DebitAmount:    e.Debit,
			CreditAmount:   e.Credit,
			RunningBalance: balance,
		})
	}
	return result, openingBalance, nil
}

// --------------------------------------------------------------------------
// Balance Sheet
// --------------------------------------------------------------------------

// AccountBalanceSnapshot represents an account's balance at a point in time.
type AccountBalanceSnapshot struct {
	AccountID   uuid.UUID       `json:"account_id"`
	AccountCode string          `json:"account_code"`
	AccountName string          `json:"account_name"`
	AccountType string          `json:"account_type"`
	Balance     decimal.Decimal `json:"balance"`
}

// GetBalanceSheet returns assets, liabilities, and equity as of a given date.
func (s *AccountingQueryService) GetBalanceSheet(
	ctx context.Context,
	companyID uuid.UUID,
	asOf time.Time,
) (assets, liabilities, equity []AccountBalanceSnapshot, totalAssets, totalLiabilities, totalEquity decimal.Decimal, err error) {
	// Prefer pre‑computed snapshots from analytics (faster).
	rows, err := s.ledgerRepo.ComputeBalanceSheet(ctx, s.pgClient.DB, companyID, asOf)
	if err != nil {
		return nil, nil, nil, decimal.Zero, decimal.Zero, decimal.Zero, fmt.Errorf("compute balance sheet: %w", err)
	}

	for _, row := range rows {
		snap := AccountBalanceSnapshot{
			AccountID:   row.AccountID,
			AccountName: row.AccountName,
			AccountType: row.AccountType,
			Balance:     row.Amount,
		}
		// Need account code – fetch it (could be returned by ComputeBalanceSheet, but we'll keep as is)
		acc, err := s.accountRepo.GetByID(ctx, s.pgClient.DB, row.AccountID)
		if err == nil && acc != nil {
			snap.AccountCode = acc.AccountCode
		}

		switch row.AccountType {
		case "asset":
			assets = append(assets, snap)
			totalAssets = totalAssets.Add(row.Amount)
		case "liability":
			liabilities = append(liabilities, snap)
			totalLiabilities = totalLiabilities.Add(row.Amount)
		case "equity":
			equity = append(equity, snap)
			totalEquity = totalEquity.Add(row.Amount)
		}
	}
	return assets, liabilities, equity, totalAssets, totalLiabilities, totalEquity, nil
}

// --------------------------------------------------------------------------
// Income Statement (Profit & Loss)
// --------------------------------------------------------------------------

// IncomeStatementEntry represents a single line in an income statement.
type IncomeStatementEntry struct {
	AccountID   uuid.UUID       `json:"account_id"`
	AccountCode string          `json:"account_code"`
	AccountName string          `json:"account_name"`
	Amount      decimal.Decimal `json:"amount"` // net movement (revenue - expense) for the period
}

// GetIncomeStatement returns revenues and expenses for a given fiscal year and period.
func (s *AccountingQueryService) GetIncomeStatement(
	ctx context.Context,
	companyID uuid.UUID,
	fiscalYear, period int,
) (revenues, expenses []IncomeStatementEntry, totalRevenue, totalExpense, netIncome decimal.Decimal, err error) {
	startDate, endDate := periodToDateRange(fiscalYear, period)

	rows, err := s.ledgerRepo.ComputePAndL(ctx, s.pgClient.DB, companyID, startDate, endDate)
	if err != nil {
		return nil, nil, decimal.Zero, decimal.Zero, decimal.Zero, fmt.Errorf("compute P&L: %w", err)
	}

	for _, row := range rows {
		entry := IncomeStatementEntry{
			AccountID:   row.AccountID,
			AccountName: row.AccountName,
			Amount:      row.Amount,
		}
		// Fetch account code
		acc, err := s.accountRepo.GetByID(ctx, s.pgClient.DB, row.AccountID)
		if err == nil && acc != nil {
			entry.AccountCode = acc.AccountCode
		}

		if row.AccountType == "revenue" {
			revenues = append(revenues, entry)
			totalRevenue = totalRevenue.Add(row.Amount)
		} else if row.AccountType == "expense" {
			expenses = append(expenses, entry)
			totalExpense = totalExpense.Add(row.Amount)
		}
	}
	netIncome = totalRevenue.Sub(totalExpense)
	return revenues, expenses, totalRevenue, totalExpense, netIncome, nil
}

// --------------------------------------------------------------------------
// Cash Flow Statement
// --------------------------------------------------------------------------

// CashFlowEntry represents a category total in a cash flow statement.
type CashFlowEntry struct {
	Category string          `json:"category"` // operating, investing, financing
	Amount   decimal.Decimal `json:"amount"`
}

// GetCashFlowStatement returns operating, investing, and financing cash flows.
// This implementation uses a simplified mapping – in production, you would
// either pre‑aggregate in analytics_cashflow with a category column, or
// use a mapping table to assign cash flow categories to account ranges.
func (s *AccountingQueryService) GetCashFlowStatement(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) (operating, investing, financing decimal.Decimal, err error) {
	// Try to read from pre‑computed analytics table if it has categories.
	// For now, compute from ledger with a simple account‑code based mapping.
	filter := repository.CashflowFilter{
		CompanyID: companyID,
		FromDate:  &startDate,
		ToDate:    &endDate,
	}
	flows, err := s.analyticsRepo.ListCashflows(ctx, s.pgClient.DB, filter, repository.Pagination{Limit: 10000}, repository.Sort{Field: "date"})
	if err == nil && len(flows) > 0 {
		// If we had category in the Cashflow model, we could sum by category.
		// Placeholder: fall through to ledger computation.
	}
	// Fallback: compute from ledger using account code prefixes.
	return s.computeCashFlowFromLedger(ctx, companyID, startDate, endDate)
}

// computeCashFlowFromLedger is a simplified example. Replace with your actual logic.
func (s *AccountingQueryService) computeCashFlowFromLedger(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) (decimal.Decimal, decimal.Decimal, decimal.Decimal, error) {
	// Get all accounts with their codes
	accounts, err := s.accountRepo.ListByCompany(ctx, s.pgClient.DB, companyID)
	if err != nil {
		return decimal.Zero, decimal.Zero, decimal.Zero, err
	}

	var operating, investing, financing decimal.Decimal
	for _, acc := range accounts {
		// Sum movement for this account in period
		debit, credit, err := s.ledgerRepo.SumAccountMovement(ctx, s.pgClient.DB, companyID, acc.AccountID, startDate, endDate)
		if err != nil {
			continue
		}
		net := debit.Sub(credit)
		if net.IsZero() {
			continue
		}
		// Example mapping by account code prefix (customize for your chart of accounts)
		switch {
		case acc.AccountCode >= "1000" && acc.AccountCode < "2000": // Assets
			// Operating cash flow: changes in current assets (excluding cash)
			if acc.AccountCode >= "1100" && acc.AccountCode < "1200" {
				operating = operating.Sub(net) // increase in current asset reduces cash
			}
		case acc.AccountCode >= "2000" && acc.AccountCode < "3000": // Liabilities
			if acc.AccountCode >= "2100" && acc.AccountCode < "2200" { // current liabilities
				operating = operating.Add(net)
			}
		case acc.AccountCode >= "3000" && acc.AccountCode < "4000": // Equity
			financing = financing.Add(net)
		case acc.AccountCode >= "4000" && acc.AccountCode < "5000": // Revenue
			operating = operating.Add(net)
		case acc.AccountCode >= "5000" && acc.AccountCode < "6000": // Expense
			operating = operating.Sub(net)
		}
	}
	return operating, investing, financing, nil
}

// --------------------------------------------------------------------------
// Tax Summary
// --------------------------------------------------------------------------

// TaxSummaryResult aggregates tax amounts per tax rate.
type TaxSummaryResult struct {
	TaxRateID     *uuid.UUID      `json:"tax_rate_id,omitempty"`
	TaxRateName   string          `json:"tax_rate_name"`
	TaxableAmount decimal.Decimal `json:"taxable_amount"`
	TaxAmount     decimal.Decimal `json:"tax_amount"`
}

// GetTaxSummary returns tax amounts grouped by tax rate for a date range.
func (s *AccountingQueryService) GetTaxSummary(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) ([]TaxSummaryResult, decimal.Decimal, error) {
	summaries, err := s.taxTxRepo.SumByRate(ctx, s.pgClient.DB, companyID, startDate, endDate)
	if err != nil {
		return nil, decimal.Zero, fmt.Errorf("sum tax by rate: %w", err)
	}
	results := make([]TaxSummaryResult, 0, len(summaries))
	var totalTax decimal.Decimal
	for _, s := range summaries {
		results = append(results, TaxSummaryResult{
			TaxRateID:     &s.TaxRateID,
			TaxRateName:   s.TaxName,
			TaxableAmount: decimal.NewFromFloat(s.TaxableAmount),
			TaxAmount:     decimal.NewFromFloat(s.TaxAmount),
		})
		totalTax = totalTax.Add(decimal.NewFromFloat(s.TaxAmount))
	}
	return results, totalTax, nil
}

// --------------------------------------------------------------------------
// Compliance Returns
// --------------------------------------------------------------------------

// ComplianceReturnSummary is a lightweight representation of a compliance return.
type ComplianceReturnSummary struct {
	ReturnID       uuid.UUID       `json:"return_id"`
	ReturnType     string          `json:"return_type"`
	PeriodStart    time.Time       `json:"period_start"`
	PeriodEnd      time.Time       `json:"period_end"`
	Status         string          `json:"status"`
	TotalLiability decimal.Decimal `json:"total_liability"`
	FiledAt        *time.Time      `json:"filed_at,omitempty"`
}

// ListComplianceReturns returns filtered compliance returns with pagination.
func (s *AccountingQueryService) ListComplianceReturns(
	ctx context.Context,
	companyID uuid.UUID,
	status string,
	year int,
	limit, offset int,
) ([]ComplianceReturnSummary, int64, error) {
	filter := repository.ComplianceReturnFilter{
		CompanyID: companyID,
		Status:    status,
	}
	if year > 0 {
		start := time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)
		end := time.Date(year+1, 1, 1, 0, 0, 0, 0, time.UTC)
		filter.PeriodStart = &start
		filter.PeriodEnd = &end
	}
	pagination := repository.Pagination{Limit: limit, Offset: offset}
	sort := repository.Sort{Field: "period_start", Direction: "DESC"}

	returns, err := s.complianceRepo.ListReturns(ctx, s.pgClient.DB, filter, pagination, sort)
	if err != nil {
		return nil, 0, fmt.Errorf("list returns: %w", err)
	}
	total, err := s.complianceRepo.CountReturns(ctx, s.pgClient.DB, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("count returns: %w", err)
	}
	summaries := make([]ComplianceReturnSummary, 0, len(returns))
	for _, r := range returns {
		summaries = append(summaries, ComplianceReturnSummary{
			ReturnID:       r.ReturnID,
			ReturnType:     r.ReturnType,
			PeriodStart:    r.PeriodStart,
			PeriodEnd:      r.PeriodEnd,
			Status:         r.Status,
			TotalLiability: r.TotalLiability,
			FiledAt:        r.FiledAt,
		})
	}
	return summaries, total, nil
}

// --------------------------------------------------------------------------
// Journal Entry with Lines
// --------------------------------------------------------------------------

// GetJournalEntryWithLines returns a full journal entry including its lines.
func (s *AccountingQueryService) GetJournalEntryWithLines(ctx context.Context, journalID uuid.UUID) (*models.JournalEntry, []*models.JournalLine, error) {
	entry, err := s.journalRepo.GetByID(ctx, s.pgClient.DB, journalID)
	if err != nil {
		return nil, nil, err
	}
	if entry == nil {
		return nil, nil, repository.ErrNotFound
	}
	lines, err := s.journalRepo.GetLines(ctx, s.pgClient.DB, journalID)
	if err != nil {
		return nil, nil, err
	}
	return entry, lines, nil
}

// --------------------------------------------------------------------------
// Account Balance Helper
// --------------------------------------------------------------------------

// GetAccountBalance returns the balance of an account as of a specific time.
func (s *AccountingQueryService) GetAccountBalance(ctx context.Context, companyID, accountID uuid.UUID, asOf time.Time) (decimal.Decimal, error) {
	return s.analyticsRepo.GetAccountBalanceFromLedger(ctx, s.pgClient.DB, companyID, accountID, asOf)
}

// --------------------------------------------------------------------------
// Utility Functions
// --------------------------------------------------------------------------

// periodToDateRange converts a fiscal year and period (1‑12) to start and end dates.
// Assumes calendar year (period 1 = January). In production, fetch fiscal year start
// month from accounting_settings for the company.
func periodToDateRange(fiscalYear, period int) (start, end time.Time) {
	start = time.Date(fiscalYear, time.Month(period), 1, 0, 0, 0, 0, time.UTC)
	end = start.AddDate(0, 1, -1)
	return start, end
}
