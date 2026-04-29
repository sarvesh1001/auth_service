package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/accounting/events"
	"auth-service/internal/accounting/models/tax"
	"auth-service/internal/accounting/repository"
	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
)

// RuleExecutionStrategy defines how multiple matched rules are handled.
type RuleExecutionStrategy string

const (
	FirstMatch RuleExecutionStrategy = "first_match" // stop after first matched rule
	AllMatch   RuleExecutionStrategy = "all_match"   // apply all matched rules
)

// TaxComputationInput is the context for tax calculation.
type TaxComputationInput struct {
	Amount          decimal.Decimal        `json:"amount"`
	Currency        string                 `json:"currency"`
	TransactionType string                 `json:"transaction_type"`
	ProductType     string                 `json:"product_type"`
	CustomerType    string                 `json:"customer_type"`
	Jurisdiction    string                 `json:"jurisdiction"`
	Date            time.Time              `json:"date"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// TaxLineItem represents a single tax component.
type TaxLineItem struct {
	TaxRateID     *uuid.UUID      `json:"tax_rate_id"`
	TaxableAmount decimal.Decimal `json:"taxable_amount"`
	TaxAmount     decimal.Decimal `json:"tax_amount"`
	LineType      string          `json:"line_type"`
	Description   *string         `json:"description,omitempty"`
}

// TaxResult is a simplified single‑rate result (kept for compatibility).
type TaxResult struct {
	TaxableAmount decimal.Decimal
	TaxAmount     decimal.Decimal
	TaxRateID     uuid.UUID
	TaxRateName   string
	RatePercent   decimal.Decimal
}

// CreateTaxTransactionRequest is used to record a tax transaction.
type CreateTaxTransactionRequest struct {
	CompanyID          uuid.UUID
	TransactionType    string
	TransactionID      uuid.UUID
	TaxRuleID          *uuid.UUID
	TaxRateID          *uuid.UUID
	TaxableAmount      decimal.Decimal
	TaxAmount          decimal.Decimal
	Currency           string
	ExchangeRate       decimal.Decimal
	BaseCurrencyAmount decimal.Decimal
	TransactionDate    time.Time
}

// EvaluatedRule contains the result of rule evaluation.
type EvaluatedRule struct {
	RuleID   uuid.UUID
	Priority int
	Matched  bool
	Actions  []*tax.TaxAction
}

// TaxSummary aggregates tax amounts over a period.
type TaxSummary struct {
	TotalTaxable decimal.Decimal
	TotalTax     decimal.Decimal
	ByRate       []*repository.TaxRateSummary
	ByRule       []*repository.TaxRuleSummary
}

// TaxReturn represents a tax filing document.
type TaxReturn struct {
	CompanyID uuid.UUID
	FromDate  time.Time
	ToDate    time.Time
	Summary   *TaxSummary
	FiledAt   *time.Time
}

// Pagination and Sort aliases.
type Pagination = repository.Pagination
type Sort = repository.Sort

// TaxEngineService defines the complete tax engine API.
type TaxEngineService interface {
	// Core computation
	ComputeTax(ctx context.Context, companyID uuid.UUID, amount decimal.Decimal, taxRateID *uuid.UUID) (*TaxResult, error)
	ComputeTaxBreakdown(ctx context.Context, companyID uuid.UUID, input TaxComputationInput) ([]TaxLineItem, error)
	ComputePeriodLiability(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) (decimal.Decimal, []TaxLineItem, error)
	ComputeBulkTax(ctx context.Context, companyID uuid.UUID, inputs []TaxComputationInput) ([]*TaxResult, error)

	// Rule engine (time‑travel support)
	EvaluateRules(ctx context.Context, companyID uuid.UUID, appliesTo string, data map[string]interface{}) ([]*EvaluatedRule, error)
	ApplyRules(ctx context.Context, input TaxComputationInput, rules []*EvaluatedRule) (*TaxResult, error)
	GetApplicableRulesForTransaction(ctx context.Context, companyID uuid.UUID, appliesTo string) ([]*repository.TaxRuleBundle, error)
	GetApplicableRulesForTransactionAsOf(ctx context.Context, companyID uuid.UUID, appliesTo string, effectiveDate time.Time) ([]*repository.TaxRuleBundle, error)

	// Profile resolution
	GetDefaultTaxProfile(ctx context.Context, companyID uuid.UUID) (*tax.TaxProfile, error)
	GetTaxProfileForTransaction(ctx context.Context, companyID uuid.UUID, data map[string]interface{}) (*tax.TaxProfile, error)

	// Tax rate resolution
	GetApplicableTaxRate(ctx context.Context, companyID uuid.UUID, date time.Time) (*tax.TaxRate, error)
	GetApplicableTaxRates(ctx context.Context, companyID uuid.UUID, input TaxComputationInput) ([]*tax.TaxRate, error)

	// Tax transaction management
	CreateTaxTransaction(ctx context.Context, req CreateTaxTransactionRequest) (*tax.TaxTransaction, error)
	BulkCreateTaxTransactions(ctx context.Context, reqs []CreateTaxTransactionRequest) ([]*tax.TaxTransaction, error)
	VoidTaxTransaction(ctx context.Context, transactionType string, transactionID uuid.UUID, reason string) error
	AdjustTaxTransaction(ctx context.Context, transactionID uuid.UUID, newAmount decimal.Decimal, reason string) error
	GetTransactionTaxBreakdown(ctx context.Context, transactionType string, transactionID uuid.UUID) ([]*tax.TaxTransaction, error)

	// Tax profile admin
	CreateTaxProfile(ctx context.Context, p *tax.TaxProfile) error
	UpdateTaxProfile(ctx context.Context, p *tax.TaxProfile) error
	SetDefaultTaxProfile(ctx context.Context, companyID uuid.UUID, profileID uuid.UUID) error
	SetTaxProfileActive(ctx context.Context, profileID uuid.UUID, isActive bool) error
	ListTaxProfiles(ctx context.Context, companyID uuid.UUID) ([]*tax.TaxProfile, error)
	DeleteTaxProfile(ctx context.Context, companyID, id uuid.UUID, deletedBy *uuid.UUID) error

	// Tax rate admin
	CreateTaxRate(ctx context.Context, r *tax.TaxRate) error
	UpdateTaxRate(ctx context.Context, r *tax.TaxRate) error
	CloseOpenRates(ctx context.Context, companyID uuid.UUID, taxName string, beforeDate time.Time, updatedBy *uuid.UUID) error
	ListTaxRates(ctx context.Context, filter repository.TaxRateFilter, pagination Pagination, sort Sort) ([]*tax.TaxRate, int64, error)
	DeleteTaxRate(ctx context.Context, companyID, id uuid.UUID, deletedBy *uuid.UUID) error

	// Tax rule admin (with versioning)
	CreateTaxRule(ctx context.Context, rule *tax.TaxRule, conditions []*tax.TaxCondition, actions []*tax.TaxAction) error
	UpdateTaxRule(ctx context.Context, rule *tax.TaxRule, conditions []*tax.TaxCondition, actions []*tax.TaxAction) error
	CreateRuleVersion(ctx context.Context, tx repository.DBTX, ruleID uuid.UUID, ruleJSON []byte) error
	SetRuleVersion(ctx context.Context, companyID, ruleID uuid.UUID, version int) error
	GetRuleBundle(ctx context.Context, companyID, ruleID uuid.UUID) (*repository.TaxRuleBundle, error)
	DeleteTaxRule(ctx context.Context, companyID, id uuid.UUID, deletedBy *uuid.UUID) error

	// Reporting & compliance
	GetTaxSummary(ctx context.Context, companyID uuid.UUID, from, to time.Time) (*TaxSummary, error)
	GenerateTaxReturn(ctx context.Context, companyID uuid.UUID, from, to time.Time) (*TaxReturn, error)

	// Validation
	ValidateTaxRate(ctx context.Context, companyID uuid.UUID, taxRateID uuid.UUID) error
}

type taxEngineService struct {
	taxProfileRepo     repository.TaxProfileRepository
	taxRateRepo        repository.TaxRateRepository
	taxRuleRepo        repository.TaxRuleRepository
	taxTransactionRepo repository.TaxTransactionRepository
	pgClient           *client.PostgresClient
	logger             *zap.Logger
	outboxRepo         outbox.Repository
	idempotencyStore   idempotency.Store
	auditService       *audit.AuditService
	condEvaluator      *ConditionEvaluator
}

// NewTaxEngineService creates a new instance.
func NewTaxEngineService(
	taxProfileRepo repository.TaxProfileRepository,
	taxRateRepo repository.TaxRateRepository,
	taxRuleRepo repository.TaxRuleRepository,
	taxTransactionRepo repository.TaxTransactionRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
) TaxEngineService {
	return &taxEngineService{
		taxProfileRepo:     taxProfileRepo,
		taxRateRepo:        taxRateRepo,
		taxRuleRepo:        taxRuleRepo,
		taxTransactionRepo: taxTransactionRepo,
		pgClient:           pgClient,
		logger:             logger.Named("tax_engine_service"),
		outboxRepo:         outboxRepo,
		idempotencyStore:   idempotencyStore,
		auditService:       auditService,
		condEvaluator:      &ConditionEvaluator{},
	}
}

// ----------------------------------------------------------------------
// Core Computation
// ----------------------------------------------------------------------

func (s *taxEngineService) ComputeTax(ctx context.Context, companyID uuid.UUID, amount decimal.Decimal, taxRateID *uuid.UUID) (*TaxResult, error) {
	input := TaxComputationInput{
		Amount:          amount,
		Currency:        "USD",
		TransactionType: "sales",
		Date:            time.Now(),
	}
	if taxRateID != nil {
		rate, err := s.taxRateRepo.GetByID(ctx, s.pgClient.DB, *taxRateID)
		if err != nil || rate == nil {
			return nil, fmt.Errorf("%w: tax rate %s", ErrNotFound, taxRateID)
		}
		taxAmt := amount.Mul(rate.RatePercentage).Div(decimal.NewFromInt(100))
		return &TaxResult{
			TaxableAmount: amount,
			TaxAmount:     taxAmt,
			TaxRateID:     rate.TaxRateID,
			TaxRateName:   rate.TaxName,
			RatePercent:   rate.RatePercentage,
		}, nil
	}
	return s.computeTaxWithInput(ctx, companyID, input)
}

func (s *taxEngineService) computeTaxWithInput(ctx context.Context, companyID uuid.UUID, input TaxComputationInput) (*TaxResult, error) {
	items, err := s.ComputeTaxBreakdown(ctx, companyID, input)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("no tax computed")
	}
	first := items[0]
	var rateID uuid.UUID
	if first.TaxRateID != nil {
		rateID = *first.TaxRateID
	}
	return &TaxResult{
		TaxableAmount: first.TaxableAmount,
		TaxAmount:     first.TaxAmount,
		TaxRateID:     rateID,
		TaxRateName:   first.LineType,
		RatePercent:   decimal.Zero,
	}, nil
}

func (s *taxEngineService) ComputeTaxBreakdown(ctx context.Context, companyID uuid.UUID, input TaxComputationInput) ([]TaxLineItem, error) {
	profile, err := s.GetTaxProfileForTransaction(ctx, companyID, input.Metadata)
	if err != nil || profile == nil {
		return nil, fmt.Errorf("%w: no tax profile for company %s", ErrNotFound, companyID)
	}
	appliesTo := input.TransactionType
	if appliesTo == "" {
		appliesTo = "sales"
	}
	bundles, err := s.GetApplicableRulesForTransactionAsOf(ctx, companyID, appliesTo, input.Date)
	if err != nil {
		return nil, fmt.Errorf("get applicable rules: %w", err)
	}
	sort.SliceStable(bundles, func(i, j int) bool {
		return bundles[i].Rule.Priority > bundles[j].Rule.Priority
	})
	strategy := FirstMatch
	if profile.Settings != nil {
		var settings map[string]interface{}
		_ = json.Unmarshal(profile.Settings, &settings)
		if strat, ok := settings["rule_execution_strategy"].(string); ok && strat == "all_match" {
			strategy = AllMatch
		}
	}
	ctxData := buildContextData(input)
	var allActions []*tax.TaxAction
	for _, bundle := range bundles {
		matched, err := s.evaluateRuleConditions(bundle, ctxData)
		if err != nil {
			s.logger.Warn("rule evaluation error",
				zap.String("rule_id", bundle.Rule.TaxRuleID.String()),
				zap.Error(err))
			continue
		}
		if matched {
			allActions = append(allActions, bundle.Actions...)
			if strategy == FirstMatch {
				break
			}
		}
	}
	items, err := s.applyActions(ctx, input, allActions, profile)
	if err != nil {
		return nil, err
	}
	return mergeTaxLineItems(items), nil
}

func (s *taxEngineService) ComputePeriodLiability(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) (decimal.Decimal, []TaxLineItem, error) {
	transactions, err := s.taxTransactionRepo.GetForReturn(ctx, s.pgClient.DB, companyID, startDate, endDate)
	if err != nil {
		return decimal.Zero, nil, fmt.Errorf("get tax transactions: %w", err)
	}
	total := decimal.Zero
	rateMap := make(map[uuid.UUID]TaxLineItem)
	for _, tx := range transactions {
		total = total.Add(tx.TaxAmount)
		if tx.TaxRateID != nil {
			item := rateMap[*tx.TaxRateID]
			item.TaxableAmount = item.TaxableAmount.Add(tx.TaxableAmount)
			item.TaxAmount = item.TaxAmount.Add(tx.TaxAmount)
			item.TaxRateID = tx.TaxRateID
			rateMap[*tx.TaxRateID] = item
		}
	}
	lines := make([]TaxLineItem, 0, len(rateMap))
	for _, item := range rateMap {
		lines = append(lines, item)
	}
	return total, lines, nil
}

func (s *taxEngineService) ComputeBulkTax(ctx context.Context, companyID uuid.UUID, inputs []TaxComputationInput) ([]*TaxResult, error) {
	results := make([]*TaxResult, len(inputs))
	for i, inp := range inputs {
		res, err := s.computeTaxWithInput(ctx, companyID, inp)
		if err != nil {
			return nil, fmt.Errorf("failed at input %d: %w", i, err)
		}
		results[i] = res
	}
	return results, nil
}

// ----------------------------------------------------------------------
// Rule Engine
// ----------------------------------------------------------------------

func (s *taxEngineService) evaluateRuleConditions(bundle *repository.TaxRuleBundle, data map[string]interface{}) (bool, error) {
	for _, cond := range bundle.Conditions {
		ok, err := s.condEvaluator.Evaluate(cond, data)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

func (s *taxEngineService) applyActions(ctx context.Context, input TaxComputationInput, actions []*tax.TaxAction, profile *tax.TaxProfile) ([]TaxLineItem, error) {
	if len(actions) == 0 && profile != nil && profile.DefaultTaxRateID != nil {
		rate, err := s.taxRateRepo.GetByID(ctx, s.pgClient.DB, *profile.DefaultTaxRateID)
		if err == nil && rate != nil {
			taxable := s.modifyTaxableAmount(input.Amount, actions, "default")
			taxAmount := taxable.Mul(rate.RatePercentage).Div(decimal.NewFromInt(100))
			return []TaxLineItem{{
				TaxRateID:     &rate.TaxRateID,
				TaxableAmount: taxable,
				TaxAmount:     taxAmount,
				LineType:      rate.TaxName,
			}}, nil
		}
		return nil, fmt.Errorf("no tax actions and no default tax rate")
	}
	var items []TaxLineItem
	accumulatedTaxable := input.Amount
	for _, act := range actions {
		if act.ActionType == "reduce_base" {
			accumulatedTaxable = accumulatedTaxable.Mul(decimal.NewFromFloat(0.9))
		}
	}
	for _, act := range actions {
		switch act.ActionType {
		case "apply_rate":
			rate, err := s.taxRateRepo.GetByID(ctx, s.pgClient.DB, act.TaxRateID)
			if err != nil || rate == nil {
				s.logger.Warn("rate not found for action", zap.String("rate_id", act.TaxRateID.String()))
				continue
			}
			var taxable decimal.Decimal
			if act.CalculationBasis == "taxable_value" {
				taxable = accumulatedTaxable
			} else {
				taxable = input.Amount
			}
			taxAmount := taxable.Mul(rate.RatePercentage).Div(decimal.NewFromInt(100))
			items = append(items, TaxLineItem{
				TaxRateID:     &rate.TaxRateID,
				TaxableAmount: taxable,
				TaxAmount:     taxAmount,
				LineType:      rate.TaxName,
			})
		case "exempt":
			items = append(items, TaxLineItem{
				TaxRateID:     nil,
				TaxableAmount: input.Amount,
				TaxAmount:     decimal.Zero,
				LineType:      "exempt",
				Description:   stringPtr("Tax exempt by rule"),
			})
		case "reduce_base":
		case "override_amount":
			s.logger.Warn("override_amount action not implemented")
		}
	}
	return items, nil
}

func (s *taxEngineService) modifyTaxableAmount(original decimal.Decimal, actions []*tax.TaxAction, context string) decimal.Decimal {
	modified := original
	for _, act := range actions {
		if act.ActionType == "reduce_base" {
			modified = modified.Mul(decimal.NewFromFloat(0.9))
		}
	}
	return modified
}

func (s *taxEngineService) EvaluateRules(ctx context.Context, companyID uuid.UUID, appliesTo string, data map[string]interface{}) ([]*EvaluatedRule, error) {
	return s.EvaluateRulesAsOf(ctx, companyID, appliesTo, data, time.Now())
}

func (s *taxEngineService) EvaluateRulesAsOf(ctx context.Context, companyID uuid.UUID, appliesTo string, data map[string]interface{}, effectiveDate time.Time) ([]*EvaluatedRule, error) {
	bundles, err := s.GetApplicableRulesForTransactionAsOf(ctx, companyID, appliesTo, effectiveDate)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(bundles, func(i, j int) bool {
		return bundles[i].Rule.Priority > bundles[j].Rule.Priority
	})
	var results []*EvaluatedRule
	for _, b := range bundles {
		matched, err := s.evaluateRuleConditions(b, data)
		if err != nil {
			return nil, err
		}
		results = append(results, &EvaluatedRule{
			RuleID:   b.Rule.TaxRuleID,
			Priority: b.Rule.Priority,
			Matched:  matched,
			Actions:  b.Actions,
		})
	}
	return results, nil
}

func (s *taxEngineService) ApplyRules(ctx context.Context, input TaxComputationInput, rules []*EvaluatedRule) (*TaxResult, error) {
	for _, r := range rules {
		if r.Matched {
			items, err := s.applyActions(ctx, input, r.Actions, nil)
			if err != nil {
				return nil, err
			}
			if len(items) > 0 {
				first := items[0]
				var rateID uuid.UUID
				if first.TaxRateID != nil {
					rateID = *first.TaxRateID
				}
				return &TaxResult{
					TaxableAmount: first.TaxableAmount,
					TaxAmount:     first.TaxAmount,
					TaxRateID:     rateID,
					TaxRateName:   first.LineType,
					RatePercent:   decimal.Zero,
				}, nil
			}
		}
	}
	return nil, ErrRuleEvaluationFailed
}

func (s *taxEngineService) GetApplicableRulesForTransaction(ctx context.Context, companyID uuid.UUID, appliesTo string) ([]*repository.TaxRuleBundle, error) {
	return s.GetApplicableRulesForTransactionAsOf(ctx, companyID, appliesTo, time.Now())
}

func (s *taxEngineService) GetApplicableRulesForTransactionAsOf(ctx context.Context, companyID uuid.UUID, appliesTo string, effectiveDate time.Time) ([]*repository.TaxRuleBundle, error) {
	return s.taxRuleRepo.GetApplicableRules(ctx, s.pgClient.DB, companyID, appliesTo)
}

// ----------------------------------------------------------------------
// Profile Resolution
// ----------------------------------------------------------------------

func (s *taxEngineService) GetDefaultTaxProfile(ctx context.Context, companyID uuid.UUID) (*tax.TaxProfile, error) {
	return s.taxProfileRepo.GetDefaultProfile(ctx, s.pgClient.DB, companyID)
}

func (s *taxEngineService) GetTaxProfileForTransaction(ctx context.Context, companyID uuid.UUID, data map[string]interface{}) (*tax.TaxProfile, error) {
	if jurisdiction, ok := data["jurisdiction"].(string); ok && jurisdiction != "" {
		// Optionally fetch by jurisdiction; fallback to default.
	}
	return s.taxProfileRepo.GetDefaultProfile(ctx, s.pgClient.DB, companyID)
}

// ----------------------------------------------------------------------
// Tax Rate Resolution
// ----------------------------------------------------------------------

func (s *taxEngineService) GetApplicableTaxRate(ctx context.Context, companyID uuid.UUID, date time.Time) (*tax.TaxRate, error) {
	profile, err := s.GetDefaultTaxProfile(ctx, companyID)
	if err != nil || profile == nil {
		return nil, fmt.Errorf("%w: no default profile", ErrNotFound)
	}
	if profile.DefaultTaxRateID != nil {
		rate, err := s.taxRateRepo.GetByID(ctx, s.pgClient.DB, *profile.DefaultTaxRateID)
		if err == nil && rate != nil {
			return rate, nil
		}
	}
	taxName := "VAT"
	if len(profile.Settings) > 0 {
		var settings map[string]interface{}
		_ = json.Unmarshal(profile.Settings, &settings)
		if n, ok := settings["default_tax_name"].(string); ok && n != "" {
			taxName = n
		}
	}
	return s.taxRateRepo.GetApplicableRate(ctx, s.pgClient.DB, companyID, taxName, date)
}

func (s *taxEngineService) GetApplicableTaxRates(ctx context.Context, companyID uuid.UUID, input TaxComputationInput) ([]*tax.TaxRate, error) {
	active := true
	filter := repository.TaxRateFilter{CompanyID: companyID, IsActive: &active}
	return s.taxRateRepo.List(ctx, s.pgClient.DB, filter, repository.Pagination{Limit: 100}, repository.Sort{})
}

// ----------------------------------------------------------------------
// Tax Transaction Management
// ----------------------------------------------------------------------

func (s *taxEngineService) CreateTaxTransaction(ctx context.Context, req CreateTaxTransactionRequest) (*tax.TaxTransaction, error) {
	logger := s.logger.With(
		zap.String("method", "CreateTaxTransaction"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("transaction_id", req.TransactionID.String()),
	)
	if req.ExchangeRate.LessThanOrEqual(decimal.Zero) {
		return nil, fmt.Errorf("%w: exchange rate must be positive", ErrInvalidInput)
	}
	exists, err := s.taxTransactionRepo.ExistsForTransaction(ctx, s.pgClient.DB, req.TransactionType, req.TransactionID)
	if err != nil {
		return nil, fmt.Errorf("exists check: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("%w: tax transaction already exists for %s/%s", ErrDuplicate, req.TransactionType, req.TransactionID)
	}
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if idempotencyKey != "" {
		var existing *tax.TaxTransaction
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached response")
			return existing, nil
		}
	}
	taxTrans := &tax.TaxTransaction{
		TaxTransactionID:   uuid.New(),
		CompanyID:          req.CompanyID,
		TransactionType:    req.TransactionType,
		TransactionID:      req.TransactionID,
		TaxRuleID:          req.TaxRuleID,
		TaxRateID:          req.TaxRateID,
		TaxableAmount:      req.TaxableAmount,
		TaxAmount:          req.TaxAmount,
		Currency:           req.Currency,
		ExchangeRate:       req.ExchangeRate,
		BaseCurrencyAmount: decimal.Zero,
		TransactionDate:    req.TransactionDate,
		CreatedAt:          time.Now(),
	}
	if err := s.taxTransactionRepo.Create(ctx, tx, taxTrans); err != nil {
		return nil, fmt.Errorf("create tax transaction: %w", err)
	}
	payload, _ := json.Marshal(events.TaxTransactionPayload{
		TaxTransactionID: taxTrans.TaxTransactionID.String(),
		CompanyID:        taxTrans.CompanyID.String(),
		TransactionType:  taxTrans.TransactionType,
		TransactionID:    taxTrans.TransactionID.String(),
		TaxableAmount:    taxTrans.TaxableAmount.String(),
		TaxAmount:        taxTrans.TaxAmount.String(),
		TransactionDate:  taxTrans.TransactionDate,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "tax_transaction",
		AggregateID:   taxTrans.TaxTransactionID.String(),
		EventType:     events.EventTaxTransactionCreated,
		Topic:         TopicAccountingEvents,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}
	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, taxTrans)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "tax", "create", "tax_transaction",
			&taxTrans.TaxTransactionID, "system", nil, nil, nil, nil)
	}
	logger.Info("tax transaction created", zap.String("tax_transaction_id", taxTrans.TaxTransactionID.String()))
	return taxTrans, nil
}

func (s *taxEngineService) BulkCreateTaxTransactions(ctx context.Context, reqs []CreateTaxTransactionRequest) ([]*tax.TaxTransaction, error) {
	if len(reqs) == 0 {
		return nil, nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	transactions := make([]*tax.TaxTransaction, 0, len(reqs))
	for _, req := range reqs {
		if req.ExchangeRate.LessThanOrEqual(decimal.Zero) {
			return nil, fmt.Errorf("%w: exchange rate must be positive for transaction %s", ErrInvalidInput, req.TransactionID)
		}
		exists, err := s.taxTransactionRepo.ExistsForTransaction(ctx, tx, req.TransactionType, req.TransactionID)
		if err != nil {
			return nil, fmt.Errorf("exists check for %s: %w", req.TransactionID, err)
		}
		if exists {
			continue
		}
		tt := &tax.TaxTransaction{
			TaxTransactionID:   uuid.New(),
			CompanyID:          req.CompanyID,
			TransactionType:    req.TransactionType,
			TransactionID:      req.TransactionID,
			TaxRuleID:          req.TaxRuleID,
			TaxRateID:          req.TaxRateID,
			TaxableAmount:      req.TaxableAmount,
			TaxAmount:          req.TaxAmount,
			Currency:           req.Currency,
			ExchangeRate:       req.ExchangeRate,
			BaseCurrencyAmount: decimal.Zero,
			TransactionDate:    req.TransactionDate,
			CreatedAt:          time.Now(),
		}
		transactions = append(transactions, tt)
	}
	if len(transactions) > 0 {
		if err := s.taxTransactionRepo.BulkCreate(ctx, tx, transactions); err != nil {
			return nil, err
		}
		for _, tt := range transactions {
			payload, _ := json.Marshal(events.TaxTransactionPayload{
				TaxTransactionID: tt.TaxTransactionID.String(),
				CompanyID:        tt.CompanyID.String(),
				TransactionType:  tt.TransactionType,
				TransactionID:    tt.TransactionID.String(),
				TaxableAmount:    tt.TaxableAmount.String(),
				TaxAmount:        tt.TaxAmount.String(),
				TransactionDate:  tt.TransactionDate,
			})
			outboxEvent := &outbox.Event{
				EventID:       uuid.New().String(),
				AggregateType: "tax_transaction",
				AggregateID:   tt.TaxTransactionID.String(),
				EventType:     events.EventTaxTransactionCreated,
				Topic:         TopicAccountingEvents,
				Payload:       payload,
				Status:        "pending",
			}
			_ = s.outboxRepo.Store(ctx, tx, outboxEvent)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return transactions, nil
}

func (s *taxEngineService) VoidTaxTransaction(ctx context.Context, transactionType string, transactionID uuid.UUID, reason string) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.taxTransactionRepo.DeleteByTransaction(ctx, tx, transactionType, transactionID); err != nil {
		return err
	}
	_ = s.auditService.LogAction(ctx, tx, nil, "tax", "void", "tax_transaction", nil, "system", nil, nil, nil, map[string]interface{}{
		"transaction_type": transactionType,
		"transaction_id":   transactionID.String(),
		"reason":           reason,
	})
	return tx.Commit()
}

func (s *taxEngineService) AdjustTaxTransaction(ctx context.Context, transactionID uuid.UUID, newAmount decimal.Decimal, reason string) error {
	return fmt.Errorf("adjust tax transaction not implemented")
}

func (s *taxEngineService) GetTransactionTaxBreakdown(ctx context.Context, transactionType string, transactionID uuid.UUID) ([]*tax.TaxTransaction, error) {
	return s.taxTransactionRepo.GetByTransaction(ctx, s.pgClient.DB, transactionType, transactionID)
}

// ----------------------------------------------------------------------
// Tax Profile Admin
// ----------------------------------------------------------------------

func (s *taxEngineService) CreateTaxProfile(ctx context.Context, p *tax.TaxProfile) error {
	if p.TaxProfileID == uuid.Nil {
		p.TaxProfileID = uuid.New()
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.taxProfileRepo.Create(ctx, tx, p); err != nil {
		return err
	}
	payload, _ := json.Marshal(events.TaxProfilePayload{
		ProfileID:    p.TaxProfileID.String(),
		CompanyID:    p.CompanyID.String(),
		TaxRegime:    p.TaxRegime,
		Jurisdiction: p.Jurisdiction,
		IsActive:     p.IsActive,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "tax_profile",
		AggregateID:   p.TaxProfileID.String(),
		EventType:     events.EventTaxProfileCreated,
		Topic:         TopicAccountingEvents,
		Payload:       payload,
		Status:        "pending",
	}
	_ = s.outboxRepo.Store(ctx, tx, outboxEvent)
	if err := tx.Commit(); err != nil {
		return err
	}
	_ = s.auditService.LogAction(ctx, nil, &p.CompanyID, "tax", "create", "tax_profile", &p.TaxProfileID, "system", nil, nil, nil, nil)
	return nil
}

func (s *taxEngineService) UpdateTaxProfile(ctx context.Context, p *tax.TaxProfile) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.taxProfileRepo.Update(ctx, tx, p); err != nil {
		return err
	}
	payload, _ := json.Marshal(events.TaxProfilePayload{
		ProfileID:    p.TaxProfileID.String(),
		CompanyID:    p.CompanyID.String(),
		TaxRegime:    p.TaxRegime,
		Jurisdiction: p.Jurisdiction,
		IsActive:     p.IsActive,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "tax_profile",
		AggregateID:   p.TaxProfileID.String(),
		EventType:     events.EventTaxProfileUpdated,
		Topic:         TopicAccountingEvents,
		Payload:       payload,
		Status:        "pending",
	}
	_ = s.outboxRepo.Store(ctx, tx, outboxEvent)
	if err := tx.Commit(); err != nil {
		return err
	}
	_ = s.auditService.LogAction(ctx, nil, &p.CompanyID, "tax", "update", "tax_profile", &p.TaxProfileID, "system", nil, nil, nil, nil)
	return nil
}

func (s *taxEngineService) SetDefaultTaxProfile(ctx context.Context, companyID uuid.UUID, profileID uuid.UUID) error {
	profile, err := s.taxProfileRepo.GetByID(ctx, s.pgClient.DB, profileID)
	if err != nil || profile == nil {
		return ErrNotFound
	}
	var settings map[string]interface{}
	if len(profile.Settings) > 0 {
		_ = json.Unmarshal(profile.Settings, &settings)
	} else {
		settings = make(map[string]interface{})
	}
	settings["is_default"] = true
	newSettings, _ := json.Marshal(settings)
	return s.taxProfileRepo.UpdateSettings(ctx, s.pgClient.DB, profileID, newSettings, nil)
}

func (s *taxEngineService) SetTaxProfileActive(ctx context.Context, profileID uuid.UUID, isActive bool) error {
	return s.taxProfileRepo.SetActive(ctx, s.pgClient.DB, profileID, isActive, nil)
}

func (s *taxEngineService) ListTaxProfiles(ctx context.Context, companyID uuid.UUID) ([]*tax.TaxProfile, error) {
	return s.taxProfileRepo.GetByCompany(ctx, s.pgClient.DB, companyID)
}

func (s *taxEngineService) DeleteTaxProfile(ctx context.Context, companyID, id uuid.UUID, deletedBy *uuid.UUID) error {
	return s.taxProfileRepo.Delete(ctx, s.pgClient.DB, id, deletedBy)
}

// ----------------------------------------------------------------------
// Tax Rate Admin
// ----------------------------------------------------------------------

func (s *taxEngineService) CreateTaxRate(ctx context.Context, r *tax.TaxRate) error {
	if r.TaxRateID == uuid.Nil {
		r.TaxRateID = uuid.New()
	}
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	overlap, err := s.taxRateRepo.CheckOverlappingRates(ctx, tx, r.CompanyID, r.TaxName, r.EffectiveFrom, r.EffectiveTo, uuid.Nil)
	if err != nil {
		return err
	}
	if overlap {
		return fmt.Errorf("%w: overlapping rate period", ErrConflict)
	}
	if err := s.taxRateRepo.Create(ctx, tx, r); err != nil {
		return err
	}
	payload, _ := json.Marshal(events.TaxRatePayload{
		RateID:         r.TaxRateID.String(),
		CompanyID:      r.CompanyID.String(),
		TaxName:        r.TaxName,
		RatePercentage: r.RatePercentage.String(),
		EffectiveFrom:  r.EffectiveFrom,
		EffectiveTo:    r.EffectiveTo,
		IsActive:       r.IsActive,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "tax_rate",
		AggregateID:   r.TaxRateID.String(),
		EventType:     events.EventTaxRateCreated,
		Topic:         TopicAccountingEvents,
		Payload:       payload,
		Status:        "pending",
	}
	_ = s.outboxRepo.Store(ctx, tx, outboxEvent)
	if err := tx.Commit(); err != nil {
		return err
	}
	_ = s.auditService.LogAction(ctx, nil, &r.CompanyID, "tax", "create", "tax_rate", &r.TaxRateID, "system", nil, nil, nil, nil)
	return nil
}

func (s *taxEngineService) UpdateTaxRate(ctx context.Context, r *tax.TaxRate) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.taxRateRepo.Update(ctx, tx, r); err != nil {
		return err
	}
	payload, _ := json.Marshal(events.TaxRatePayload{
		RateID:         r.TaxRateID.String(),
		CompanyID:      r.CompanyID.String(),
		TaxName:        r.TaxName,
		RatePercentage: r.RatePercentage.String(),
		EffectiveFrom:  r.EffectiveFrom,
		EffectiveTo:    r.EffectiveTo,
		IsActive:       r.IsActive,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "tax_rate",
		AggregateID:   r.TaxRateID.String(),
		EventType:     events.EventTaxRateUpdated,
		Topic:         TopicAccountingEvents,
		Payload:       payload,
		Status:        "pending",
	}
	_ = s.outboxRepo.Store(ctx, tx, outboxEvent)
	if err := tx.Commit(); err != nil {
		return err
	}
	_ = s.auditService.LogAction(ctx, nil, &r.CompanyID, "tax", "update", "tax_rate", &r.TaxRateID, "system", nil, nil, nil, nil)
	return nil
}

func (s *taxEngineService) CloseOpenRates(ctx context.Context, companyID uuid.UUID, taxName string, beforeDate time.Time, updatedBy *uuid.UUID) error {
	return s.taxRateRepo.CloseOpenRates(ctx, s.pgClient.DB, companyID, taxName, beforeDate, updatedBy)
}

func (s *taxEngineService) ListTaxRates(ctx context.Context, filter repository.TaxRateFilter, pagination Pagination, sort Sort) ([]*tax.TaxRate, int64, error) {
	rates, err := s.taxRateRepo.List(ctx, s.pgClient.DB, filter, pagination, sort)
	if err != nil {
		return nil, 0, err
	}
	total, err := s.taxRateRepo.Count(ctx, s.pgClient.DB, filter)
	if err != nil {
		return nil, 0, err
	}
	return rates, total, nil
}

func (s *taxEngineService) DeleteTaxRate(ctx context.Context, companyID, id uuid.UUID, deletedBy *uuid.UUID) error {
	return s.taxRateRepo.Delete(ctx, s.pgClient.DB, id, deletedBy)
}

// ----------------------------------------------------------------------
// Tax Rule Admin (with versioning)
// ----------------------------------------------------------------------

func (s *taxEngineService) CreateTaxRule(ctx context.Context, rule *tax.TaxRule, conditions []*tax.TaxCondition, actions []*tax.TaxAction) error {
	if rule.TaxRuleID == uuid.Nil {
		rule.TaxRuleID = uuid.New()
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.taxRuleRepo.Create(ctx, tx, rule); err != nil {
		return err
	}
	ruleJSON, _ := json.Marshal(rule)
	version := &tax.TaxRuleVersion{
		VersionID: uuid.New(),
		TaxRuleID: rule.TaxRuleID,
		Version:   1,
		RuleJSON:  ruleJSON,
		IsCurrent: true,
		CreatedBy: rule.CreatedBy,
	}
	if err := s.taxRuleRepo.CreateVersion(ctx, tx, version); err != nil {
		return err
	}
	if len(conditions) > 0 {
		if err := s.taxRuleRepo.BulkAddConditions(ctx, tx, rule.CompanyID, conditions); err != nil {
			return err
		}
	}
	if len(actions) > 0 {
		if err := s.taxRuleRepo.BulkAddActions(ctx, tx, rule.CompanyID, actions); err != nil {
			return err
		}
	}
	payload, _ := json.Marshal(events.TaxRulePayload{
		RuleID:    rule.TaxRuleID.String(),
		CompanyID: rule.CompanyID.String(),
		RuleName:  rule.RuleName,
		AppliesTo: rule.AppliesTo,
		Priority:  rule.Priority,
		IsActive:  rule.IsActive,
		Version:   1,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "tax_rule",
		AggregateID:   rule.TaxRuleID.String(),
		EventType:     events.EventTaxRuleCreated,
		Topic:         TopicAccountingEvents,
		Payload:       payload,
		Status:        "pending",
	}
	_ = s.outboxRepo.Store(ctx, tx, outboxEvent)
	if err := tx.Commit(); err != nil {
		return err
	}
	_ = s.auditService.LogAction(ctx, nil, &rule.CompanyID, "tax", "create", "tax_rule", &rule.TaxRuleID, "system", nil, nil, nil, nil)
	return nil
}

func (s *taxEngineService) UpdateTaxRule(ctx context.Context, rule *tax.TaxRule, conditions []*tax.TaxCondition, actions []*tax.TaxAction) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.taxRuleRepo.Update(ctx, tx, rule); err != nil {
		return err
	}
	if err := s.taxRuleRepo.ClearConditions(ctx, tx, rule.CompanyID, rule.TaxRuleID); err != nil {
		return err
	}
	if err := s.taxRuleRepo.ClearActions(ctx, tx, rule.CompanyID, rule.TaxRuleID); err != nil {
		return err
	}
	if len(conditions) > 0 {
		if err := s.taxRuleRepo.BulkAddConditions(ctx, tx, rule.CompanyID, conditions); err != nil {
			return err
		}
	}
	if len(actions) > 0 {
		if err := s.taxRuleRepo.BulkAddActions(ctx, tx, rule.CompanyID, actions); err != nil {
			return err
		}
	}
	ruleJSON, _ := json.Marshal(rule)
	if err := s.CreateRuleVersion(ctx, tx, rule.TaxRuleID, ruleJSON); err != nil {
		return err
	}
	payload, _ := json.Marshal(events.TaxRulePayload{
		RuleID:    rule.TaxRuleID.String(),
		CompanyID: rule.CompanyID.String(),
		RuleName:  rule.RuleName,
		AppliesTo: rule.AppliesTo,
		Priority:  rule.Priority,
		IsActive:  rule.IsActive,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "tax_rule",
		AggregateID:   rule.TaxRuleID.String(),
		EventType:     events.EventTaxRuleUpdated,
		Topic:         TopicAccountingEvents,
		Payload:       payload,
		Status:        "pending",
	}
	_ = s.outboxRepo.Store(ctx, tx, outboxEvent)
	if err := tx.Commit(); err != nil {
		return err
	}
	_ = s.auditService.LogAction(ctx, nil, &rule.CompanyID, "tax", "update", "tax_rule", &rule.TaxRuleID, "system", nil, nil, nil, nil)
	return nil
}

func (s *taxEngineService) CreateRuleVersion(ctx context.Context, tx repository.DBTX, ruleID uuid.UUID, ruleJSON []byte) error {
	version := &tax.TaxRuleVersion{
		VersionID: uuid.New(),
		TaxRuleID: ruleID,
		RuleJSON:  ruleJSON,
	}
	return s.taxRuleRepo.CreateVersion(ctx, tx, version)
}

func (s *taxEngineService) SetRuleVersion(ctx context.Context, companyID, ruleID uuid.UUID, version int) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.taxRuleRepo.SetCurrentVersion(ctx, tx, companyID, ruleID, version); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *taxEngineService) GetRuleBundle(ctx context.Context, companyID, ruleID uuid.UUID) (*repository.TaxRuleBundle, error) {
	rule, err := s.taxRuleRepo.GetByID(ctx, s.pgClient.DB, companyID, ruleID)
	if err != nil || rule == nil {
		return nil, ErrNotFound
	}
	version, err := s.taxRuleRepo.GetCurrentVersion(ctx, s.pgClient.DB, companyID, ruleID)
	if err != nil {
		return nil, err
	}
	conditions, err := s.taxRuleRepo.GetConditions(ctx, s.pgClient.DB, companyID, ruleID)
	if err != nil {
		return nil, err
	}
	actions, err := s.taxRuleRepo.GetActions(ctx, s.pgClient.DB, companyID, ruleID)
	if err != nil {
		return nil, err
	}
	return &repository.TaxRuleBundle{
		Rule:       rule,
		Version:    version,
		Conditions: conditions,
		Actions:    actions,
	}, nil
}

func (s *taxEngineService) DeleteTaxRule(ctx context.Context, companyID, id uuid.UUID, deletedBy *uuid.UUID) error {
	return s.taxRuleRepo.Delete(ctx, s.pgClient.DB, companyID, id, deletedBy)
}

// ----------------------------------------------------------------------
// Reporting & Compliance
// ----------------------------------------------------------------------

func (s *taxEngineService) GetTaxSummary(ctx context.Context, companyID uuid.UUID, from, to time.Time) (*TaxSummary, error) {
	totalTaxable, totalTax, err := s.taxTransactionRepo.SumByPeriod(ctx, s.pgClient.DB, companyID, from, to)
	if err != nil {
		return nil, err
	}
	byRate, err := s.taxTransactionRepo.SumByRate(ctx, s.pgClient.DB, companyID, from, to)
	if err != nil {
		return nil, err
	}
	byRule, err := s.taxTransactionRepo.SumByRule(ctx, s.pgClient.DB, companyID, from, to)
	if err != nil {
		return nil, err
	}
	return &TaxSummary{
		TotalTaxable: decimal.NewFromFloat(totalTaxable),
		TotalTax:     decimal.NewFromFloat(totalTax),
		ByRate:       byRate,
		ByRule:       byRule,
	}, nil
}

func (s *taxEngineService) GenerateTaxReturn(ctx context.Context, companyID uuid.UUID, from, to time.Time) (*TaxReturn, error) {
	summary, err := s.GetTaxSummary(ctx, companyID, from, to)
	if err != nil {
		return nil, err
	}
	return &TaxReturn{
		CompanyID: companyID,
		FromDate:  from,
		ToDate:    to,
		Summary:   summary,
	}, nil
}

// ----------------------------------------------------------------------
// Validation
// ----------------------------------------------------------------------

func (s *taxEngineService) ValidateTaxRate(ctx context.Context, companyID uuid.UUID, taxRateID uuid.UUID) error {
	rate, err := s.taxRateRepo.GetByID(ctx, s.pgClient.DB, taxRateID)
	if err != nil || rate == nil {
		return ErrNotFound
	}
	if rate.CompanyID != companyID {
		return fmt.Errorf("%w: tax rate does not belong to company", ErrInvalidInput)
	}
	return nil
}

// ----------------------------------------------------------------------
// Helper Functions
// ----------------------------------------------------------------------

func buildContextData(input TaxComputationInput) map[string]interface{} {
	data := map[string]interface{}{
		"amount":           input.Amount,
		"currency":         input.Currency,
		"transaction_type": input.TransactionType,
		"product_type":     input.ProductType,
		"customer_type":    input.CustomerType,
		"jurisdiction":     input.Jurisdiction,
		"date":             input.Date,
	}
	for k, v := range input.Metadata {
		data[k] = v
	}
	return data
}

func mergeTaxLineItems(items []TaxLineItem) []TaxLineItem {
	merged := make(map[string]TaxLineItem)
	for _, item := range items {
		key := ""
		if item.TaxRateID != nil {
			key = item.TaxRateID.String()
		} else {
			key = item.LineType
		}
		if existing, ok := merged[key]; ok {
			existing.TaxableAmount = existing.TaxableAmount.Add(item.TaxableAmount)
			existing.TaxAmount = existing.TaxAmount.Add(item.TaxAmount)
			merged[key] = existing
		} else {
			merged[key] = item
		}
	}
	result := make([]TaxLineItem, 0, len(merged))
	for _, v := range merged {
		result = append(result, v)
	}
	return result
}
