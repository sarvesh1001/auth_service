package service

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
	"auth-service/internal/accounting/repository"
	"auth-service/internal/infrastructure/audit"
)

// =============================================================================
// 1. Interface
// =============================================================================

type AccountingRuleEngine interface {
	ValidateJournal(ctx context.Context, tx repository.DBTX, req CreateJournalRequest) error
	ValidateBeforePost(ctx context.Context, tx repository.DBTX, entry *models.JournalEntry, lines []*models.JournalLine) error
	IsPeriodLocked(ctx context.Context, tx repository.DBTX, companyID uuid.UUID, entryDate time.Time) (bool, error)
	IsDuplicate(ctx context.Context, tx repository.DBTX, req CreateJournalRequest) (bool, error)
}

// =============================================================================
// 2. Implementation
// =============================================================================

type ruleEngine struct {
	ledgerRepo     repository.LedgerRepository
	journalRepo    repository.JournalRepository
	settingsRepo   repository.AccountingSettingsRepository
	periodLockRepo repository.PeriodLockRepository
	auditService   *audit.AuditService
	logger         *zap.Logger
}

func NewRuleEngine(
	ledgerRepo repository.LedgerRepository,
	journalRepo repository.JournalRepository,
	settingsRepo repository.AccountingSettingsRepository,
	periodLockRepo repository.PeriodLockRepository,
	auditService *audit.AuditService,
	logger *zap.Logger,
) AccountingRuleEngine {
	return &ruleEngine{
		ledgerRepo:     ledgerRepo,
		journalRepo:    journalRepo,
		settingsRepo:   settingsRepo,
		periodLockRepo: periodLockRepo,
		auditService:   auditService,
		logger:         logger.Named("rule_engine"),
	}
}

// Helper to extract *sql.Tx from DBTX (must be called within a transaction)
func (e *ruleEngine) getSQLTx(tx repository.DBTX) (*sql.Tx, error) {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("expected *sql.Tx, got %T", tx)
	}
	return sqlTx, nil
}

// =============================================================================
// 3. Core Validation Methods (Router + Context-Aware)
// =============================================================================

// ValidateJournal routes to normal or reconciliation validation based on ContextType.
func (e *ruleEngine) ValidateJournal(ctx context.Context, tx repository.DBTX, req CreateJournalRequest) error {
	if req.ContextType == "reconciliation" {
		return e.validateReconciliationJournal(ctx, tx, req)
	}
	return e.validateNormalJournal(ctx, tx, req)
}

// validateNormalJournal contains the original strict accounting rules.
func (e *ruleEngine) validateNormalJournal(ctx context.Context, tx repository.DBTX, req CreateJournalRequest) error {
	// 1. Same account used multiple times? (allow contra: same account, different sides)
	if err := e.checkSameAccountWithSide(req); err != nil {
		e.auditRuleViolation(ctx, tx, req.CompanyID, "same_account_multiple_times", err.Error(), req)
		return err
	}

	// 2. Fetch account types
	accountIDs := e.extractAccountIDs(req)
	accTypes, err := e.ledgerRepo.GetAccountTypesMap(ctx, tx, accountIDs)
	if err != nil {
		return fmt.Errorf("fetch account types: %w", err)
	}
	if len(accTypes) != len(accountIDs) {
		err := errors.New("some accounts not found or inactive")
		e.auditRuleViolation(ctx, tx, req.CompanyID, "account_not_found", err.Error(), req)
		return err
	}

	// 3. At least two different account types
	if err := e.checkAccountTypeVariety(accTypes); err != nil {
		e.auditRuleViolation(ctx, tx, req.CompanyID, "insufficient_account_types", err.Error(), req)
		return err
	}

	// 4. Natural balance rules
	if err := e.checkNaturalBalance(req, accTypes); err != nil {
		e.auditRuleViolation(ctx, tx, req.CompanyID, "natural_balance_violation", err.Error(), req)
		return err
	}

	// 5. Source-based business rules
	if err := e.validateSourceRules(req, accTypes); err != nil {
		e.auditRuleViolation(ctx, tx, req.CompanyID, "source_rule_violation", err.Error(), req)
		return err
	}

	// 6. Combination matrix (warning only)
	_ = e.checkCombinationMatrix(req, accTypes)

	return nil
}

// validateReconciliationJournal applies relaxed rules for system-generated reconciliation adjustments.
func (e *ruleEngine) validateReconciliationJournal(ctx context.Context, tx repository.DBTX, req CreateJournalRequest) error {
	if err := e.checkSameAccountWithSide(req); err != nil {
		e.auditRuleViolation(ctx, tx, req.CompanyID, "same_account_multiple_times", err.Error(), req)
		return err
	}
	totalDebit, totalCredit := e.sumAmounts(req)
	if !totalDebit.Equal(totalCredit) {
		e.auditRuleViolation(ctx, tx, req.CompanyID, "debit_credit_mismatch",
			fmt.Sprintf("debits=%s credits=%s", totalDebit, totalCredit), req)
		return ErrDebitCreditMismatch
	}
	if len(req.Lines) == 0 {
		err := fmt.Errorf("%w: at least one journal line is required", ErrInvalidInput)
		e.auditRuleViolation(ctx, tx, req.CompanyID, "no_lines", err.Error(), req)
		return err
	}
	accountIDs := e.extractAccountIDs(req)
	accTypes, err := e.ledgerRepo.GetAccountTypesMap(ctx, tx, accountIDs)
	if err != nil {
		return fmt.Errorf("fetch account types: %w", err)
	}
	if len(accTypes) != len(accountIDs) {
		err := errors.New("some accounts not found or inactive")
		e.auditRuleViolation(ctx, tx, req.CompanyID, "account_not_found", err.Error(), req)
		return err
	}

	// Optional: warn but don't fail on natural balance violations
	if err := e.checkNaturalBalance(req, accTypes); err != nil {
		ref := "(no reference)"
		if req.Reference != nil {
			ref = *req.Reference
		}
		e.logger.Warn("reconciliation journal violates natural balance",
			zap.String("error", err.Error()),
			zap.String("journal_ref", ref))
		// Do NOT return error – allow the adjustment
	}

	_ = e.checkCombinationMatrix(req, accTypes)
	return nil
}

// ValidateBeforePost is shared by both normal and reconciliation journals.
func (e *ruleEngine) ValidateBeforePost(ctx context.Context, tx repository.DBTX, entry *models.JournalEntry, lines []*models.JournalLine) error {
	// Period lock check
	locked, err := e.IsPeriodLocked(ctx, tx, entry.CompanyID, entry.EntryDate)
	if err != nil {
		return err
	}
	if locked {
		sqlTx, _ := e.getSQLTx(tx)
		e.auditService.LogAction(ctx, sqlTx, &entry.CompanyID, "accounting", "error", "post_blocked",
			&entry.JournalEntryID, "user", entry.UpdatedBy, nil, nil, map[string]interface{}{
				"reason": "period_locked",
				"date":   entry.EntryDate,
			})
		return ErrPeriodLocked
	}
	return nil
}

func (e *ruleEngine) IsPeriodLocked(ctx context.Context, tx repository.DBTX, companyID uuid.UUID, entryDate time.Time) (bool, error) {
	settings, err := e.settingsRepo.GetByCompany(ctx, tx, companyID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("get accounting settings: %w", err)
	}
	fiscalYear, period, err := computeFiscalPeriod(entryDate, settings.FiscalYearStartMonth)
	if err != nil {
		return false, err
	}
	return e.periodLockRepo.IsLocked(ctx, tx, companyID, fiscalYear, period)
}

func (e *ruleEngine) IsDuplicate(ctx context.Context, tx repository.DBTX, req CreateJournalRequest) (bool, error) {
	window := time.Now().Add(-5 * time.Minute)
	filter := repository.JournalFilter{
		CompanyID: req.CompanyID,
		FromDate:  &window,
	}
	entries, err := e.journalRepo.List(ctx, tx, filter, repository.Pagination{Limit: 20}, repository.Sort{Field: "created_at", Direction: "DESC"})
	if err != nil {
		return false, fmt.Errorf("list recent journals: %w", err)
	}
	for _, existing := range entries {
		if existing.Reference != nil && req.Reference != nil && *existing.Reference == *req.Reference {
			return true, nil
		}
	}
	return false, nil
}

// =============================================================================
// 4. Helper Validation Functions
// =============================================================================

func (e *ruleEngine) checkSameAccountWithSide(req CreateJournalRequest) error {
	type sideInfo struct {
		debitCount  int
		creditCount int
	}
	accountUsage := make(map[uuid.UUID]sideInfo)

	for _, line := range req.Lines {
		info := accountUsage[line.AccountID]
		if line.DebitAmount.GreaterThan(decimal.Zero) {
			info.debitCount++
		}
		if line.CreditAmount.GreaterThan(decimal.Zero) {
			info.creditCount++
		}
		accountUsage[line.AccountID] = info
	}

	for accID, info := range accountUsage {
		if info.debitCount > 1 || info.creditCount > 1 {
			return fmt.Errorf("%w: account %v appears multiple times on same side", ErrSameAccountUsedMultipleTimes, accID)
		}
	}
	return nil
}

func (e *ruleEngine) extractAccountIDs(req CreateJournalRequest) []uuid.UUID {
	ids := make([]uuid.UUID, 0, len(req.Lines))
	seen := make(map[uuid.UUID]bool)
	for _, line := range req.Lines {
		if !seen[line.AccountID] {
			seen[line.AccountID] = true
			ids = append(ids, line.AccountID)
		}
	}
	return ids
}

func (e *ruleEngine) checkAccountTypeVariety(accTypes map[uuid.UUID]string) error {
	typeSet := make(map[string]bool)
	for _, t := range accTypes {
		typeSet[t] = true
	}
	if len(typeSet) < 2 {
		return ErrInvalidAccountCombination
	}
	return nil
}

func (e *ruleEngine) checkNaturalBalance(req CreateJournalRequest, accTypes map[uuid.UUID]string) error {
	for _, line := range req.Lines {
		accType := accTypes[line.AccountID]
		switch accType {
		case enums.AccountTypeRevenue:
			if line.DebitAmount.GreaterThan(decimal.Zero) {
				return ErrRevenueCannotBeDebited
			}
		case enums.AccountTypeExpense:
			if line.CreditAmount.GreaterThan(decimal.Zero) {
				return ErrExpenseCannotBeCredited
			}
		}
	}
	return nil
}

func (e *ruleEngine) validateSourceRules(req CreateJournalRequest, accTypes map[uuid.UUID]string) error {
	if req.SourceType == nil || req.SourceID == nil {
		return nil
	}

	switch *req.SourceType {
	case "invoice":
		hasReceivable, hasRevenue := false, false
		for _, line := range req.Lines {
			t := accTypes[line.AccountID]
			if t == enums.AccountTypeAsset {
				hasReceivable = true
			}
			if t == enums.AccountTypeRevenue {
				hasRevenue = true
			}
		}
		if !hasReceivable || !hasRevenue {
			return ErrInvalidInvoiceJournal
		}
	case "payment":
		hasCash, hasARorAP := false, false
		for _, line := range req.Lines {
			t := accTypes[line.AccountID]
			if t == enums.AccountTypeAsset {
				hasCash = true
			}
			if t == enums.AccountTypeAsset || t == enums.AccountTypeLiability {
				hasARorAP = true
			}
		}
		if !hasCash || !hasARorAP {
			return ErrInvalidPaymentJournal
		}
	case "expense":
		hasExpense, hasCashOrLiability := false, false
		for _, line := range req.Lines {
			t := accTypes[line.AccountID]
			if t == enums.AccountTypeExpense {
				hasExpense = true
			}
			if t == enums.AccountTypeAsset || t == enums.AccountTypeLiability {
				hasCashOrLiability = true
			}
		}
		if !hasExpense || !hasCashOrLiability {
			return ErrInvalidExpenseJournal
		}
	}
	return nil
}

func (e *ruleEngine) checkCombinationMatrix(req CreateJournalRequest, accTypes map[uuid.UUID]string) error {
	allowedPairs := map[string]map[string]bool{
		enums.AccountTypeAsset: {
			enums.AccountTypeLiability: true,
			enums.AccountTypeEquity:    true,
			enums.AccountTypeRevenue:   true,
			enums.AccountTypeExpense:   true,
		},
		enums.AccountTypeLiability: {
			enums.AccountTypeAsset:   true,
			enums.AccountTypeEquity:  true,
			enums.AccountTypeExpense: true,
		},
		enums.AccountTypeEquity: {
			enums.AccountTypeAsset:     true,
			enums.AccountTypeLiability: true,
			enums.AccountTypeExpense:   true,
		},
		enums.AccountTypeRevenue: {
			enums.AccountTypeAsset:     true,
			enums.AccountTypeLiability: true,
		},
		enums.AccountTypeExpense: {
			enums.AccountTypeAsset:     true,
			enums.AccountTypeLiability: true,
			enums.AccountTypeEquity:    true,
		},
	}

	typesList := make([]string, len(req.Lines))
	for i, line := range req.Lines {
		typesList[i] = accTypes[line.AccountID]
	}
	for i, t1 := range typesList {
		for j, t2 := range typesList {
			if i == j {
				continue
			}
			if allowed, ok := allowedPairs[t1][t2]; !ok || !allowed {
				e.logger.Warn("suspicious account combination",
					zap.String("type1", t1), zap.String("type2", t2))
			}
		}
	}
	return nil
}

// sumAmounts returns total debit and total credit from the request lines.
func (e *ruleEngine) sumAmounts(req CreateJournalRequest) (decimal.Decimal, decimal.Decimal) {
	totalDebit := decimal.Zero
	totalCredit := decimal.Zero
	for _, line := range req.Lines {
		totalDebit = totalDebit.Add(line.DebitAmount)
		totalCredit = totalCredit.Add(line.CreditAmount)
	}
	return totalDebit, totalCredit
}

// =============================================================================
// 5. Audit Helper
// =============================================================================

func (e *ruleEngine) auditRuleViolation(ctx context.Context, tx repository.DBTX, companyID uuid.UUID, rule string, details string, req CreateJournalRequest) {
	if e.auditService == nil {
		return
	}
	sqlTx, err := e.getSQLTx(tx)
	if err != nil {
		e.logger.Warn("could not get sql.Tx for audit", zap.Error(err))
		return
	}
	_ = e.auditService.LogAction(ctx, sqlTx, &companyID, "accounting", "rule_violation", "journal_validation",
		nil, "system", nil, nil, nil, map[string]interface{}{
			"rule":    rule,
			"details": details,
			"journal": map[string]interface{}{
				"journal_type": req.JournalType,
				"reference":    req.Reference,
				"lines_count":  len(req.Lines),
			},
		})
}

// =============================================================================
// 6. Utility Functions
// =============================================================================

func computeFiscalPeriod(date time.Time, startMonth int) (int, int, error) {
	if startMonth < 1 || startMonth > 12 {
		return 0, 0, fmt.Errorf("invalid start month: %d", startMonth)
	}
	year := date.Year()
	month := int(date.Month())
	var fiscalYear, period int
	if month >= startMonth {
		fiscalYear = year
		period = month - startMonth + 1
	} else {
		fiscalYear = year - 1
		period = 12 - startMonth + month + 1
	}
	return fiscalYear, period, nil
}

// =============================================================================
// 7. Rule Engine Specific Errors
// =============================================================================

var (
	ErrSameAccountUsedMultipleTimes = errors.New("same account appears multiple times on the same side")
	ErrInvalidAccountCombination    = errors.New("invalid account combination for journal entry")
	ErrRevenueCannotBeDebited       = errors.New("revenue accounts cannot be debited in standard journals")
	ErrExpenseCannotBeCredited      = errors.New("expense accounts cannot be credited in standard journals")
	ErrInvalidInvoiceJournal        = errors.New("invoice journal must contain Accounts Receivable (asset) and Revenue")
	ErrInvalidPaymentJournal        = errors.New("payment journal must contain Cash/Bank (asset) and AR/AP (asset/liability)")
	ErrInvalidExpenseJournal        = errors.New("expense journal must contain an Expense account and Cash/Liability")
	ErrPeriodLocked                 = errors.New("accounting period is locked, cannot post")
	ErrDuplicateTransaction         = errors.New("duplicate transaction detected")
	ErrDebitCreditMismatch          = errors.New("total debits do not equal total credits") // added for reconciliation
)
