package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	a "auth-service/internal/hr/service"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	RateTypeEmployee = "employee"
	RateTypeEmployer = "employer"

	ComponentTypeDeduction            = "deduction"
	ComponentTypeEmployerContribution = "employer_contribution"
)

type StatutoryEngine interface {
	Execute(ctx context.Context, input *StatutoryExecutionInput) (*StatutoryExecutionResult, error)
	Preview(ctx context.Context, input *StatutoryExecutionInput) (*StatutoryExecutionResult, error)
	ExecuteTx(ctx context.Context, input *StatutoryExecutionInput) (*StatutoryExecutionResult, error)
	CreateRuleSet(ctx context.Context, input *models.CreateRuleSetInput) error
	UpdateRuleSet(ctx context.Context, input *models.UpdateRuleSetInput) error
	ActivateRuleSet(ctx context.Context, ruleSetID uuid.UUID, actorID uuid.UUID) error
	DeactivateRuleSet(ctx context.Context, ruleSetID uuid.UUID, actorID uuid.UUID) error
	ListRuleSets(ctx context.Context, companyID uuid.UUID) ([]models.StatutoryRuleSet, error)
	CreateComponentDefinition(ctx context.Context, input *CreateComponentDefinitionInput) error
	UpdateComponentDefinition(ctx context.Context, input *UpdateComponentDefinitionInput) error
	ListComponentDefinitions(ctx context.Context, companyID uuid.UUID) ([]models.StatutoryComponentDefinition, error)
	SetContributionRule(ctx context.Context, input *models.CreateStatutoryContributionRuleInput) error
	BulkSetContributionRules(ctx context.Context, inputs []models.CreateStatutoryContributionRuleInput) error
	ListContributionRules(ctx context.Context, companyID uuid.UUID, statutoryCode string) ([]models.StatutoryContributionRule, error)
	DeactivateContributionRule(ctx context.Context, ruleID uuid.UUID, actorID uuid.UUID) error
	ValidateContributionCompleteness(ctx context.Context, companyID uuid.UUID, ruleSetID uuid.UUID) error
	ResolveActiveRuleSet(ctx context.Context, companyID uuid.UUID, asOf time.Time) (*models.StatutoryRuleSet, error)
	GenerateRuleHash(ctx context.Context, companyID uuid.UUID, ruleSetID uuid.UUID) (string, error)
	DeleteComponentDefinition(ctx context.Context, companyID uuid.UUID, statutoryCode string, actorID uuid.UUID) error
	CreateTaxSlab(ctx context.Context, input *CreateTaxSlabInput) error
	UpdateTaxSlab(ctx context.Context, input *UpdateTaxSlabInput) error
	DeactivateTaxSlab(ctx context.Context, slabID uuid.UUID, actorID uuid.UUID) error
	ListTaxSlabs(ctx context.Context, companyID uuid.UUID, statutoryCode string) ([]models.StatutoryTaxSlab, error)
	CreateDeductionLimit(ctx context.Context, input *CreateDeductionLimitInput) error
	UpdateDeductionLimit(ctx context.Context, input *UpdateDeductionLimitInput) error
	DeleteDeductionLimit(ctx context.Context, limitID uuid.UUID, actorID uuid.UUID) error
	ListDeductionLimits(ctx context.Context, companyID uuid.UUID, ruleSetID *uuid.UUID) ([]models.StatutoryDeductionLimit, error)
	CreateComponentMapping(ctx context.Context, input *CreateComponentMappingInput) error
	UpdateComponentMapping(ctx context.Context, input *UpdateComponentMappingInput) error
	DeactivateComponentMapping(ctx context.Context, mappingID uuid.UUID, actorID uuid.UUID) error
	ListComponentMappings(ctx context.Context, companyID uuid.UUID, statutoryCode *string) ([]models.StatutoryComponentMapping, error)
	BulkCreateComponentMappings(
		ctx context.Context,
		input *BulkCreateComponentMappingsInput,
	) error
}

type CreateComponentDefinitionInput struct {
	CompanyID        uuid.UUID
	StatutoryCode    string
	Description      string
	CountryCode      string
	CalculationBasis string
	HasEmployee      bool
	HasEmployer      bool
	ActorID          uuid.UUID
}

type UpdateComponentDefinitionInput struct {
	CompanyID        uuid.UUID
	StatutoryCode    string
	Description      string
	CalculationBasis string
	HasEmployee      bool
	HasEmployer      bool
	ActorID          uuid.UUID
}

type statutoryEngine struct {
	repo   repository.StatutoryRepository
	audit  *a.AuditService
	logger *zap.Logger
}

func NewStatutoryEngine(
	repo repository.StatutoryRepository,
	audit *a.AuditService,
	logger *zap.Logger,
) StatutoryEngine {
	return &statutoryEngine{
		repo:   repo,
		audit:  audit,
		logger: logger,
	}
}

func (s *statutoryEngine) CreateRuleSet(ctx context.Context, input *models.CreateRuleSetInput) error {
	if input == nil {
		return errors.New("nil input")
	}

	if input.CompanyID == uuid.Nil ||
		input.CountryCode == "" ||
		input.VersionLabel == "" ||
		input.ActorID == uuid.Nil {
		return errors.New("invalid rule set input")
	}

	if input.EffectiveFrom.IsZero() {
		return errors.New("effective_from is required")
	}

	// ---------------------------------------------------------
	// Validate existing rule set to avoid invalid date ranges
	// ---------------------------------------------------------
	existing, err := s.repo.ResolveRuleSet(ctx, input.CompanyID, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("failed to resolve existing rule set: %w", err)
	}

	if existing != nil {

		// Prevent creating rule set before current active rule set start
		if input.EffectiveFrom.Before(existing.EffectiveFrom) {
			return fmt.Errorf(
				"effective_from %s cannot be earlier than current rule set start %s",
				input.EffectiveFrom.Format(time.RFC3339),
				existing.EffectiveFrom.Format(time.RFC3339),
			)
		}

		// Prevent duplicate effective_from
		if input.EffectiveFrom.Equal(existing.EffectiveFrom) {
			return fmt.Errorf(
				"rule set with effective_from %s already exists",
				input.EffectiveFrom.Format(time.RFC3339),
			)
		}
	}

	// ---------------------------------------------------------
	// Build rule set
	// ---------------------------------------------------------
	ruleSet := &models.StatutoryRuleSet{
		RuleSetID:     uuid.New(),
		CompanyID:     input.CompanyID,
		CountryCode:   input.CountryCode,
		VersionLabel:  input.VersionLabel,
		EffectiveFrom: input.EffectiveFrom,
		IsActive:      true,
		CreatedBy:     &input.ActorID,
		CreatedAt:     time.Now().UTC(),
	}

	// ---------------------------------------------------------
	// Persist rule set
	// ---------------------------------------------------------
	if err := s.repo.CreateStatutoryRuleSet(ctx, ruleSet); err != nil {
		return fmt.Errorf("create rule set failed: %w", err)
	}

	// ---------------------------------------------------------
	// Audit log
	// ---------------------------------------------------------
	if s.audit != nil {
		_ = s.audit.LogAction(
			ctx,
			&input.CompanyID,
			"statutory",
			"rule_set_created",
			"statutory_rule_set",
			&ruleSet.RuleSetID,
			"admin",
			&input.ActorID,
			nil,
			nil,
			map[string]interface{}{
				"country_code":   input.CountryCode,
				"version_label":  input.VersionLabel,
				"effective_from": input.EffectiveFrom,
			},
		)
	}

	return nil
}

func (s *statutoryEngine) UpdateRuleSet(ctx context.Context, input *models.UpdateRuleSetInput) error {
	if input == nil {
		return errors.New("nil input")
	}
	if input.RuleSetID == uuid.Nil || input.CompanyID == uuid.Nil {
		return errors.New("invalid update input")
	}
	ruleSet := &models.StatutoryRuleSet{
		RuleSetID:     input.RuleSetID,
		CompanyID:     input.CompanyID,
		VersionLabel:  input.VersionLabel,
		EffectiveFrom: input.EffectiveFrom,
		EffectiveTo:   input.EffectiveTo,
		IsActive:      input.IsActive,
	}
	return s.repo.UpdateStatutoryRuleSet(ctx, ruleSet)
}

func (s *statutoryEngine) ActivateRuleSet(ctx context.Context, ruleSetID uuid.UUID, actorID uuid.UUID) error {
	if ruleSetID == uuid.Nil || actorID == uuid.Nil {
		return errors.New("invalid activate input")
	}
	return s.repo.WithTx(ctx, func(tx repository.StatutoryRepository) error {
		rs, err := tx.GetRuleSetByID(ctx, ruleSetID)
		if err != nil {
			return err
		}
		if rs == nil {
			return errors.New("rule set not found")
		}
		engine := &statutoryEngine{repo: tx}
		if err := engine.ValidateContributionCompleteness(ctx, rs.CompanyID, ruleSetID); err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
		if err := tx.DeactivateActiveRuleSetsByCountry(ctx, rs.CompanyID, rs.CountryCode, actorID); err != nil {
			return err
		}
		return tx.ActivateRuleSet(ctx, ruleSetID, actorID)
	})
}

func (s *statutoryEngine) DeactivateRuleSet(ctx context.Context, ruleSetID uuid.UUID, actorID uuid.UUID) error {
	if ruleSetID == uuid.Nil || actorID == uuid.Nil {
		return errors.New("invalid deactivate input")
	}
	return s.repo.DeactivateStatutoryRuleSet(ctx, ruleSetID, actorID)
}

func (s *statutoryEngine) ListRuleSets(ctx context.Context, companyID uuid.UUID) ([]models.StatutoryRuleSet, error) {
	if companyID == uuid.Nil {
		return nil, errors.New("invalid company id")
	}
	return s.repo.ListRuleSets(ctx, companyID)
}

func (s *statutoryEngine) ResolveActiveRuleSet(ctx context.Context, companyID uuid.UUID, asOf time.Time) (*models.StatutoryRuleSet, error) {
	return s.repo.ResolveRuleSet(ctx, companyID, asOf)
}

func (s *statutoryEngine) CreateComponentDefinition(
	ctx context.Context,
	input *CreateComponentDefinitionInput,
) error {

	if input.CompanyID == uuid.Nil ||
		input.StatutoryCode == "" ||
		input.CountryCode == "" ||
		input.ActorID == uuid.Nil {
		return errors.New("invalid component definition input")
	}

	// 🔴 CHECK IF EXISTS FIRST
	existing, err := s.repo.GetStatutoryComponentDefinition(
		ctx,
		input.CompanyID,
		input.StatutoryCode,
	)
	if err != nil {
		return err
	}

	if existing != nil {
		return fmt.Errorf(
			"statutory component definition already exists for company %s and code %s",
			input.CompanyID,
			input.StatutoryCode,
		)
	}

	def := &models.StatutoryComponentDefinition{
		CompanyID:               input.CompanyID,
		StatutoryCode:           input.StatutoryCode,
		Description:             input.Description,
		CountryCode:             input.CountryCode,
		CalculationBasis:        input.CalculationBasis,
		HasEmployeeContribution: input.HasEmployee,
		HasEmployerContribution: input.HasEmployer,
		CreatedAt:               time.Now().UTC(),
	}

	if err := s.repo.CreateStatutoryComponentDefinition(ctx, def); err != nil {
		return err
	}

	if s.audit != nil {
		_ = s.audit.LogAction(
			ctx,
			&input.CompanyID,
			"statutory",
			"component_definition_created",
			"statutory_component_definition",
			nil,
			"admin",
			&input.ActorID,
			nil,
			nil,
			map[string]interface{}{
				"statutory_code": input.StatutoryCode,
				"country_code":   input.CountryCode,
			},
		)
	}

	return nil
}

func (s *statutoryEngine) UpdateComponentDefinition(ctx context.Context, input *UpdateComponentDefinitionInput) error {
	if input.CompanyID == uuid.Nil || input.StatutoryCode == "" || input.ActorID == uuid.Nil {
		return errors.New("invalid component definition update input")
	}
	def := &models.StatutoryComponentDefinition{
		CompanyID:               input.CompanyID,
		StatutoryCode:           input.StatutoryCode,
		Description:             input.Description,
		CalculationBasis:        input.CalculationBasis,
		HasEmployeeContribution: input.HasEmployee,
		HasEmployerContribution: input.HasEmployer,
	}
	if err := s.repo.UpdateStatutoryComponentDefinition(ctx, def); err != nil {
		return err
	}
	if s.audit != nil {
		_ = s.audit.LogAction(
			ctx,
			&input.CompanyID,
			"statutory",
			"component_definition_updated",
			"statutory_component_definition",
			nil,
			"admin",
			&input.ActorID,
			nil,
			nil,
			map[string]interface{}{
				"statutory_code": input.StatutoryCode,
			},
		)
	}
	return nil
}

func (s *statutoryEngine) ListComponentDefinitions(ctx context.Context, companyID uuid.UUID) ([]models.StatutoryComponentDefinition, error) {
	if companyID == uuid.Nil {
		return nil, errors.New("company id required")
	}
	return s.repo.ListStatutoryComponentDefinitions(ctx, companyID)
}

func (s *statutoryEngine) SetContributionRule(ctx context.Context, input *models.CreateStatutoryContributionRuleInput) error {
	if input.CompanyID == uuid.Nil || input.RuleSetID == uuid.Nil || input.StatutoryCode == "" {
		return errors.New("invalid contribution rule input")
	}
	return s.repo.UpsertStatutoryContributionRule(ctx, *input)
}

func (s *statutoryEngine) BulkSetContributionRules(ctx context.Context, inputs []models.CreateStatutoryContributionRuleInput) error {
	if len(inputs) == 0 {
		return nil
	}
	return s.repo.WithTx(ctx, func(tx repository.StatutoryRepository) error {
		for _, in := range inputs {
			if err := tx.UpsertStatutoryContributionRule(ctx, in); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *statutoryEngine) ListContributionRules(ctx context.Context, companyID uuid.UUID, statutoryCode string) ([]models.StatutoryContributionRule, error) {
	if companyID == uuid.Nil {
		return nil, errors.New("company id required")
	}
	return s.repo.ListContributionRulesByStatutoryCode(ctx, companyID, statutoryCode)
}

func (s *statutoryEngine) DeactivateContributionRule(ctx context.Context, ruleID uuid.UUID, actorID uuid.UUID) error {
	if ruleID == uuid.Nil || actorID == uuid.Nil {
		return errors.New("invalid deactivation input")
	}
	return s.repo.DeactivateStatutoryContributionRule(ctx, ruleID, actorID)
}

func (s *statutoryEngine) ValidateContributionCompleteness(ctx context.Context, companyID uuid.UUID, ruleSetID uuid.UUID) error {
	rules, err := s.repo.LoadStatutoryContributionRulesByRuleSet(ctx, ruleSetID, companyID)
	if err != nil {
		return err
	}
	if len(rules) == 0 {
		return errors.New("no contribution rules found for rule set")
	}
	grouped := groupContributionRules(rules)
	for code, list := range grouped {
		def, err := s.repo.GetStatutoryComponentDefinition(ctx, companyID, code)
		if err != nil {
			return err
		}
		if def == nil {
			return fmt.Errorf("component definition missing for %s", code)
		}
		var hasEmp, hasEmpr bool
		for _, r := range list {
			if !r.IsActive {
				continue
			}
			switch r.ContributionSide {
			case models.ContributionSideEmployee:
				hasEmp = true
			case models.ContributionSideEmployer:
				hasEmpr = true
			}
			if r.CalculationType == models.CalculationTypePercentage || r.CalculationType == models.CalculationTypeFixed {
				if r.RateValue == nil {
					return fmt.Errorf("rate_value required for %s %s rule", code, r.ContributionSide)
				}
			}
			if r.CalculationType == models.CalculationTypeSlab {
				// slabs are validated separately
			}
		}
		if !def.HasEmployeeContribution && hasEmp {
			return fmt.Errorf("%s does not allow employee contribution", code)
		}
		if !def.HasEmployerContribution && hasEmpr {
			return fmt.Errorf("%s does not allow employer contribution", code)
		}
		if !hasEmp && !hasEmpr {
			return fmt.Errorf("no active contribution rule for %s", code)
		}
	}
	return nil
}

func (s *statutoryEngine) Execute(
	ctx context.Context,
	input *StatutoryExecutionInput,
) (*StatutoryExecutionResult, error) {
	var result *StatutoryExecutionResult
	err := s.repo.WithTx(ctx, func(txRepo repository.StatutoryRepository) error {
		engine := &statutoryEngine{
			repo:   txRepo,
			audit:  s.audit,
			logger: s.logger,
		}
		r, err := engine.ExecuteTx(ctx, input)
		if err != nil {
			return err
		}
		result = r
		return nil
	})
	return result, err
}

func (s *statutoryEngine) Preview(ctx context.Context, input *StatutoryExecutionInput) (*StatutoryExecutionResult, error) {
	return s.run(ctx, input)
}

func (s *statutoryEngine) run(ctx context.Context, input *StatutoryExecutionInput) (*StatutoryExecutionResult, error) {
	if input == nil {
		return nil, errors.New("nil execution input")
	}
	s.logger.Info("statutory_run_started",
		zap.String("company_id", input.CompanyID.String()),
		zap.String("user_id", input.UserID.String()),
		zap.Time("as_of", input.AsOf),
		zap.Time("period_start", input.PeriodStart),
		zap.Time("period_end", input.PeriodEnd),
		zap.Float64("tax_exempt_amount", input.TaxExemptAmount), // NEW
		zap.String("tax_regime", input.TaxRegime),               // NEW
		zap.Int("earnings_count", len(input.Earnings)),
	)

	ruleSet, err := s.repo.ResolveRuleSet(ctx, input.CompanyID, input.AsOf)
	if err != nil {
		s.logger.Error("resolve_rule_set_failed", zap.Error(err))
		return nil, err
	}
	if ruleSet == nil {
		s.logger.Warn("no_active_rule_set_found",
			zap.String("company_id", input.CompanyID.String()),
			zap.Time("as_of", input.AsOf),
		)
		return nil, errors.New("no active rule set")
	}
	s.logger.Info("rule_set_resolved",
		zap.String("rule_set_id", ruleSet.RuleSetID.String()),
		zap.String("version_label", ruleSet.VersionLabel),
	)

	profiles, err := s.repo.GetEmployeeStatutoryProfiles(ctx, input.CompanyID, input.UserID, input.AsOf)
	if err != nil {
		return nil, err
	}
	s.logger.Info("employee_profiles_loaded", zap.Int("profile_count", len(profiles)))

	validProfiles := filterProfilesByRuleSet(profiles, ruleSet.RuleSetID)
	s.logger.Info("valid_profiles_after_filter", zap.Int("valid_count", len(validProfiles)))

	mappings, err := s.repo.LoadStatutoryComponentMappingsByRuleSet(ctx, ruleSet.RuleSetID)
	if err != nil {
		return nil, err
	}

	rules, err := s.repo.LoadStatutoryContributionRulesByRuleSet(ctx, ruleSet.RuleSetID, input.CompanyID)
	if err != nil {
		return nil, err
	}

	slabs, err := s.repo.LoadTaxSlabsByRuleSet(ctx, ruleSet.RuleSetID)
	if err != nil {
		return nil, err
	}

	limits, err := s.repo.LoadDeductionLimitsByRuleSet(ctx, ruleSet.RuleSetID)
	if err != nil {
		return nil, err
	}

	s.logger.Info("rule_set_data_loaded",
		zap.Int("mappings_count", len(mappings)),
		zap.Int("rules_count", len(rules)),
		zap.Int("slabs_count", len(slabs)),
		zap.Int("limits_count", len(limits)),
	)

	hash, err := s.GenerateRuleHash(ctx, input.CompanyID, ruleSet.RuleSetID)
	if err != nil {
		return nil, err
	}

	// Load component definitions to know calculation_basis
	defs, err := s.repo.ListStatutoryComponentDefinitions(ctx, input.CompanyID)
	if err != nil {
		s.logger.Error("failed to load component definitions", zap.Error(err))
		return nil, fmt.Errorf("loading component definitions: %w", err)
	}
	defMap := make(map[string]models.StatutoryComponentDefinition)
	for _, d := range defs {
		defMap[d.StatutoryCode] = d
	}

	// Compute total gross earnings
	totalGross := 0.0
	for _, e := range input.Earnings {
		totalGross += e.Amount
	}

	earningMap := make(map[string]float64)
	for _, e := range input.Earnings {
		earningMap[e.ComponentCode] += e.Amount
	}

	mappingGroup := groupMappings(mappings)
	ruleGroup := groupContributionRules(rules)

	// Separate codes into pre‑tax and tax based on calculation_basis
	var preTaxCodes, taxCodes []string
	for code := range mappingGroup {
		if _, ok := defMap[code]; !ok {
			s.logger.Warn("statutory code missing definition", zap.String("code", code))
			continue
		}
		if defMap[code].CalculationBasis == "taxable_income" {
			taxCodes = append(taxCodes, code)
		} else {
			preTaxCodes = append(preTaxCodes, code)
		}
	}

	preTaxDeductions := 0.0
	result := &StatutoryExecutionResult{
		RuleSetID: ruleSet.RuleSetID,
		RuleHash:  hash,
	}

	// Process pre‑tax codes
	for _, code := range preTaxCodes {
		comps := mappingGroup[code]
		s.logger.Info("processing pre‑tax statutory code", zap.String("code", code), zap.Int("component_count", len(comps)))

		if !isOptedIn(code, validProfiles) {
			s.logger.Warn("statutory skipped not opted in", zap.String("code", code))
			continue
		}

		base := aggregateBase(comps, earningMap)
		if base <= 0 {
			s.logger.Warn("statutory skipped zero base", zap.String("code", code), zap.Float64("base", base))
			continue
		}

		codeRules := ruleGroup[code]
		if len(codeRules) == 0 {
			s.logger.Warn("statutory skipped no rules", zap.String("code", code))
			continue
		}

		var employeeAmt, employerAmt float64
		for _, r := range codeRules {
			if !r.IsActive {
				continue
			}
			calcBase := base
			if r.WageCeiling != nil && calcBase > *r.WageCeiling {
				calcBase = *r.WageCeiling
			}
			if r.MinThreshold != nil && calcBase < *r.MinThreshold {
				continue
			}

			var amount float64
			switch r.CalculationType {
			case models.CalculationTypePercentage:
				if r.RateValue != nil {
					amount = calcBase * (*r.RateValue) / 100
				}
			case models.CalculationTypeFixed:
				if r.RateValue != nil {
					amount = *r.RateValue
				}
			case models.CalculationTypeSlab:
				slabsForCode := filterSlabs(code, slabs)
				amount = slabCumulative(calcBase, input.YTDContext, code, slabsForCode)
			}
			amount = round2(amount)

			switch r.ContributionSide {
			case models.ContributionSideEmployee:
				employeeAmt += amount
			case models.ContributionSideEmployer:
				employerAmt += amount
			}
		}

		employeeAmt = enforceLimits(code, employeeAmt, input.YTDContext, limits)
		preTaxDeductions += employeeAmt

		s.logger.Info("statutory computed",
			zap.String("code", code),
			zap.Float64("base", base),
			zap.Float64("employee_amount", employeeAmt),
			zap.Float64("employer_amount", employerAmt),
		)

		if employeeAmt > 0 {
			result.EmployeeDeductions = append(result.EmployeeDeductions,
				&models.PayrollLedgerItem{
					ComponentCode: code,
					ComponentType: ComponentTypeDeduction,
					Amount:        employeeAmt,
				})
		}
		if employerAmt > 0 {
			result.EmployerContributions = append(result.EmployerContributions,
				&models.PayrollLedgerItem{
					ComponentCode: code,
					ComponentType: ComponentTypeEmployerContribution,
					Amount:        employerAmt,
				})
		}
		result.ContributionRecords = append(result.ContributionRecords,
			&models.EmployeeStatutoryContribution{
				CompanyID:      input.CompanyID,
				UserID:         input.UserID,
				StatutoryCode:  code,
				PeriodStart:    input.PeriodStart,
				PeriodEnd:      input.PeriodEnd,
				EmployeeAmount: employeeAmt,
				EmployerAmount: employerAmt,
				TotalAmount:    employeeAmt + employerAmt,
			})
		result.ComputationTrace = append(result.ComputationTrace,
			StatutoryTraceStep{
				StatutoryCode: code,
				BaseAmount:    base,
				EmployeeAmt:   employeeAmt,
				EmployerAmt:   employerAmt,
			})
	}

	// Process tax codes
	for _, code := range taxCodes {
		comps := mappingGroup[code]
		s.logger.Info("processing tax statutory code", zap.String("code", code), zap.Int("component_count", len(comps)))

		if !isOptedIn(code, validProfiles) {
			s.logger.Warn("statutory skipped not opted in", zap.String("code", code))
			continue
		}

		// For tax codes, base = totalGross - preTaxDeductions - TaxExemptAmount (NEW)
		taxBase := totalGross - preTaxDeductions - input.TaxExemptAmount
		if taxBase < 0 {
			taxBase = 0
		}

		codeRules := ruleGroup[code]
		if len(codeRules) == 0 {
			s.logger.Warn("statutory skipped no rules", zap.String("code", code))
			continue
		}

		var employeeAmt, employerAmt float64
		for _, r := range codeRules {
			if !r.IsActive {
				continue
			}
			// For tax, we still apply wage ceiling/min threshold if defined
			calcBase := taxBase
			if r.WageCeiling != nil && calcBase > *r.WageCeiling {
				calcBase = *r.WageCeiling
			}
			if r.MinThreshold != nil && calcBase < *r.MinThreshold {
				continue
			}

			var amount float64
			switch r.CalculationType {
			case models.CalculationTypePercentage:
				if r.RateValue != nil {
					amount = calcBase * (*r.RateValue) / 100
				}
			case models.CalculationTypeFixed:
				if r.RateValue != nil {
					amount = *r.RateValue
				}
			case models.CalculationTypeSlab:
				slabsForCode := filterSlabs(code, slabs)
				amount = slabCumulative(calcBase, input.YTDContext, code, slabsForCode)
			}
			amount = round2(amount)

			switch r.ContributionSide {
			case models.ContributionSideEmployee:
				employeeAmt += amount
			case models.ContributionSideEmployer:
				employerAmt += amount
			}
		}

		employeeAmt = enforceLimits(code, employeeAmt, input.YTDContext, limits)

		s.logger.Info("statutory computed (tax)",
			zap.String("code", code),
			zap.Float64("base", taxBase),
			zap.Float64("employee_amount", employeeAmt),
			zap.Float64("employer_amount", employerAmt),
		)

		if employeeAmt > 0 {
			result.EmployeeDeductions = append(result.EmployeeDeductions,
				&models.PayrollLedgerItem{
					ComponentCode: code,
					ComponentType: ComponentTypeDeduction,
					Amount:        employeeAmt,
				})
		}
		if employerAmt > 0 {
			result.EmployerContributions = append(result.EmployerContributions,
				&models.PayrollLedgerItem{
					ComponentCode: code,
					ComponentType: ComponentTypeEmployerContribution,
					Amount:        employerAmt,
				})
		}
		result.ContributionRecords = append(result.ContributionRecords,
			&models.EmployeeStatutoryContribution{
				CompanyID:      input.CompanyID,
				UserID:         input.UserID,
				StatutoryCode:  code,
				PeriodStart:    input.PeriodStart,
				PeriodEnd:      input.PeriodEnd,
				EmployeeAmount: employeeAmt,
				EmployerAmount: employerAmt,
				TotalAmount:    employeeAmt + employerAmt,
			})
		result.ComputationTrace = append(result.ComputationTrace,
			StatutoryTraceStep{
				StatutoryCode: code,
				BaseAmount:    taxBase,
				EmployeeAmt:   employeeAmt,
				EmployerAmt:   employerAmt,
			})
	}

	return result, nil
}

func (s *statutoryEngine) GenerateRuleHash(ctx context.Context, companyID uuid.UUID, ruleSetID uuid.UUID) (string, error) {
	rules, err := s.repo.LoadStatutoryContributionRulesByRuleSet(ctx, ruleSetID, companyID)
	if err != nil {
		return "", err
	}
	slabs, err := s.repo.LoadTaxSlabsByRuleSet(ctx, ruleSetID)
	if err != nil {
		return "", err
	}
	mappings, err := s.repo.LoadStatutoryComponentMappingsByRuleSet(ctx, ruleSetID)
	if err != nil {
		return "", err
	}
	limits, err := s.repo.LoadDeductionLimitsByRuleSet(ctx, ruleSetID)
	if err != nil {
		return "", err
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].StatutoryCode == rules[j].StatutoryCode {
			return rules[i].ContributionSide < rules[j].ContributionSide
		}
		return rules[i].StatutoryCode < rules[j].StatutoryCode
	})
	sort.Slice(slabs, func(i, j int) bool {
		return slabs[i].SlabOrder < slabs[j].SlabOrder
	})
	sort.Slice(mappings, func(i, j int) bool {
		if mappings[i].StatutoryCode == mappings[j].StatutoryCode {
			return mappings[i].ComponentCode < mappings[j].ComponentCode
		}
		return mappings[i].StatutoryCode < mappings[j].StatutoryCode
	})
	sort.Slice(limits, func(i, j int) bool {
		return limits[i].LimitCode < limits[j].LimitCode
	})
	payload := struct {
		ContributionRules []models.StatutoryContributionRule
		Slabs             []models.StatutoryTaxSlab
		Mappings          []models.StatutoryComponentMapping
		Limits            []models.StatutoryDeductionLimit
	}{
		ContributionRules: rules,
		Slabs:             slabs,
		Mappings:          mappings,
		Limits:            limits,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:]), nil
}

func groupMappings(m []models.StatutoryComponentMapping) map[string][]models.StatutoryComponentMapping {
	out := make(map[string][]models.StatutoryComponentMapping)
	for _, x := range m {
		out[x.StatutoryCode] = append(out[x.StatutoryCode], x)
	}
	return out
}

func groupContributionRules(rules []models.StatutoryContributionRule) map[string][]models.StatutoryContributionRule {
	out := make(map[string][]models.StatutoryContributionRule)
	for _, r := range rules {
		out[r.StatutoryCode] = append(out[r.StatutoryCode], r)
	}
	return out
}

func filterProfilesByRuleSet(profiles []models.EmployeeStatutoryProfile, ruleSetID uuid.UUID) []models.EmployeeStatutoryProfile {
	var out []models.EmployeeStatutoryProfile
	for _, p := range profiles {
		if p.RuleSetID == nil || *p.RuleSetID == ruleSetID {
			out = append(out, p)
		}
	}
	return out
}

func isOptedIn(code string, profiles []models.EmployeeStatutoryProfile) bool {
	for _, p := range profiles {
		if p.StatutoryCode == code && p.OptIn {
			return true
		}
	}
	return false
}

func aggregateBase(comps []models.StatutoryComponentMapping, earningMap map[string]float64) float64 {
	var total float64
	for _, c := range comps {
		total += earningMap[c.ComponentCode]
	}
	return total
}

func filterSlabs(code string, slabs []models.StatutoryTaxSlab) []models.StatutoryTaxSlab {
	var out []models.StatutoryTaxSlab
	for _, s := range slabs {
		if s.StatutoryCode == code && s.IsActive {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].SlabOrder < out[j].SlabOrder
	})
	return out
}

func slabCumulative(base float64, ytd *models.StatutoryYTDContext, code string, slabs []models.StatutoryTaxSlab) float64 {
	if ytd == nil {
		return calculateSlabTax(base, slabs)
	}
	ytdBase := ytd.YTDStatutoryBase[code]
	ytdTax := ytd.YTDStatutoryAmount[code]
	totalBase := ytdBase + base
	totalTax := calculateSlabTax(totalBase, slabs)
	return math.Max(0, totalTax-ytdTax)
}

func calculateSlabTax(income float64, slabs []models.StatutoryTaxSlab) float64 {
	var tax float64
	for _, s := range slabs {
		if income <= s.MinAmount {
			continue
		}
		upper := income
		if s.MaxAmount != nil && income > *s.MaxAmount {
			upper = *s.MaxAmount
		}
		taxable := upper - s.MinAmount
		if taxable < 0 {
			continue
		}
		if s.IsPercentage {
			tax += taxable * s.Rate / 100
		} else {
			tax += s.Rate
		}
	}
	return tax
}

func enforceLimits(code string, amount float64, ytd *models.StatutoryYTDContext, limits []models.StatutoryDeductionLimit) float64 {
	if ytd == nil {
		return amount
	}
	for _, l := range limits {
		if l.LimitCode != code {
			continue
		}
		used := ytd.YTDStatutoryAmount[code]
		if used+amount > l.LimitValue {
			return math.Max(0, l.LimitValue-used)
		}
	}
	return amount
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

func convertTraceToBreakdown(trace []StatutoryTraceStep) []models.StatutoryBreakdownItem {
	var out []models.StatutoryBreakdownItem
	for _, t := range trace {
		if t.EmployeeAmt > 0 {
			out = append(out, models.StatutoryBreakdownItem{
				StatutoryCode:    t.StatutoryCode,
				ContributionSide: models.ContributionSideEmployee,
				Amount:           t.EmployeeAmt,
			})
		}
		if t.EmployerAmt > 0 {
			out = append(out, models.StatutoryBreakdownItem{
				StatutoryCode:    t.StatutoryCode,
				ContributionSide: models.ContributionSideEmployer,
				Amount:           t.EmployerAmt,
			})
		}
	}
	return out
}

type StatutoryExecutionInput struct {
	PayrollRunID    uuid.UUID
	CompanyID       uuid.UUID
	UserID          uuid.UUID
	PeriodStart     time.Time
	PeriodEnd       time.Time
	AsOf            time.Time
	Earnings        []*models.PayrollLedgerItem
	YTDContext      *models.StatutoryYTDContext
	TaxExemptAmount float64 // NEW: total verified tax-exempt declarations for this period
	TaxRegime       string  // NEW: 'old' or 'new' (can be used for future enhancements)
	ActorID         uuid.UUID
}

type StatutoryExecutionResult struct {
	EmployeeDeductions    []*models.PayrollLedgerItem
	EmployerContributions []*models.PayrollLedgerItem
	ContributionRecords   []*models.EmployeeStatutoryContribution
	ComputationTrace      []StatutoryTraceStep
	RuleSetID             uuid.UUID
	RuleHash              string
}

type StatutoryTraceStep struct {
	StatutoryCode string
	BaseAmount    float64
	EmployeeAmt   float64
	EmployerAmt   float64
}

func (s *statutoryEngine) DeleteComponentDefinition(ctx context.Context, companyID uuid.UUID, statutoryCode string, actorID uuid.UUID) error {
	if companyID == uuid.Nil || statutoryCode == "" || actorID == uuid.Nil {
		return errors.New("invalid input for component definition deletion")
	}
	rules, err := s.repo.ListContributionRulesByStatutoryCode(ctx, companyID, statutoryCode)
	if err != nil {
		return err
	}
	if len(rules) > 0 {
		return fmt.Errorf("cannot delete: %d contribution rule(s) exist for this component", len(rules))
	}
	slabs, err := s.repo.ListTaxSlabsByStatutoryCode(ctx, companyID, statutoryCode)
	if err != nil {
		return err
	}
	if len(slabs) > 0 {
		return fmt.Errorf("cannot delete: %d tax slab(s) exist for this component", len(slabs))
	}
	mappings, err := s.repo.ListComponentMappings(ctx, companyID, &statutoryCode)
	if err != nil {
		return err
	}
	if len(mappings) > 0 {
		return fmt.Errorf("cannot delete: %d component mapping(s) exist for this component", len(mappings))
	}
	if err := s.repo.DeleteStatutoryComponentDefinition(ctx, companyID, statutoryCode); err != nil {
		return err
	}
	if s.audit != nil {
		_ = s.audit.LogAction(
			ctx,
			&companyID,
			"statutory",
			"component_definition_deleted",
			"statutory_component_definition",
			nil,
			"admin",
			&actorID,
			nil,
			nil,
			map[string]interface{}{
				"statutory_code": statutoryCode,
			},
		)
	}
	return nil
}

func (s *statutoryEngine) CreateTaxSlab(ctx context.Context, input *CreateTaxSlabInput) error {

	if input == nil ||
		input.CompanyID == uuid.Nil ||
		input.StatutoryCode == "" ||
		input.RuleSetID == uuid.Nil ||
		input.ActorID == uuid.Nil {
		return errors.New("invalid tax slab input")
	}

	// Validate component definition exists
	def, err := s.repo.GetStatutoryComponentDefinition(ctx, input.CompanyID, input.StatutoryCode)
	if err != nil {
		return err
	}
	if def == nil {
		return fmt.Errorf("statutory component definition %s not found", input.StatutoryCode)
	}

	// Validate rule set exists
	rs, err := s.repo.GetRuleSetByID(ctx, input.RuleSetID)
	if err != nil {
		return err
	}
	if rs == nil {
		return fmt.Errorf("rule set %s not found", input.RuleSetID)
	}

	// -------------------------------------------------------
	// CHECK DUPLICATE TAX SLAB BEFORE INSERT
	// -------------------------------------------------------

	existingSlabs, err := s.repo.ListTaxSlabsByStatutoryCode(ctx, input.CompanyID, input.StatutoryCode)
	if err != nil {
		return err
	}

	for _, slab := range existingSlabs {

		if slab.RuleSetID != nil &&
			*slab.RuleSetID == input.RuleSetID &&
			slab.IsActive &&
			slab.EffectiveFrom.Equal(input.EffectiveFrom) &&
			slab.MinAmount == input.MinAmount {

			maxEqual := false

			if slab.MaxAmount == nil && input.MaxAmount == nil {
				maxEqual = true
			}

			if slab.MaxAmount != nil && input.MaxAmount != nil {
				maxEqual = (*slab.MaxAmount == *input.MaxAmount)
			}

			if maxEqual {
				return fmt.Errorf(
					"tax slab already exists for %s with range %.2f - %v for rule_set %s",
					input.StatutoryCode,
					input.MinAmount,
					input.MaxAmount,
					input.RuleSetID,
				)
			}
		}
	}

	// -------------------------------------------------------
	// CREATE TAX SLAB
	// -------------------------------------------------------

	modelInput := models.CreateTaxSlabInput{
		CompanyID:     input.CompanyID,
		StatutoryCode: input.StatutoryCode,
		MinAmount:     input.MinAmount,
		MaxAmount:     input.MaxAmount,
		Rate:          input.Rate,
		IsPercentage:  input.IsPercentage,
		SlabOrder:     input.SlabOrder,
		EffectiveFrom: input.EffectiveFrom,
		RuleSetID:     input.RuleSetID,
		CreatedBy:     input.ActorID,
	}

	if err := s.repo.CreateTaxSlab(ctx, modelInput); err != nil {
		return err
	}

	// -------------------------------------------------------
	// AUDIT
	// -------------------------------------------------------

	if s.audit != nil {
		_ = s.audit.LogAction(
			ctx,
			&input.CompanyID,
			"statutory",
			"tax_slab_created",
			"company_tax_slab",
			nil,
			"admin",
			&input.ActorID,
			nil,
			nil,
			map[string]interface{}{
				"statutory_code": input.StatutoryCode,
				"rule_set_id":    input.RuleSetID.String(),
				"min_amount":     input.MinAmount,
				"max_amount":     input.MaxAmount,
			},
		)
	}

	return nil
}

func (s *statutoryEngine) UpdateTaxSlab(ctx context.Context, input *UpdateTaxSlabInput) error {
	if input == nil || input.SlabID == uuid.Nil || input.ActorID == uuid.Nil {
		return errors.New("invalid tax slab update input")
	}
	modelInput := models.UpdateTaxSlabInput{
		SlabID:        input.SlabID,
		MinAmount:     input.MinAmount,
		MaxAmount:     input.MaxAmount,
		Rate:          input.Rate,
		IsPercentage:  input.IsPercentage,
		SlabOrder:     input.SlabOrder,
		EffectiveFrom: input.EffectiveFrom,
		UpdatedBy:     input.ActorID,
	}
	if err := s.repo.UpdateTaxSlab(ctx, modelInput); err != nil {
		return err
	}
	if s.audit != nil {
		_ = s.audit.LogAction(
			ctx,
			nil,
			"statutory",
			"tax_slab_updated",
			"company_tax_slab",
			&input.SlabID,
			"admin",
			&input.ActorID,
			nil,
			nil,
			nil,
		)
	}
	return nil
}

func (s *statutoryEngine) DeactivateTaxSlab(ctx context.Context, slabID uuid.UUID, actorID uuid.UUID) error {
	if slabID == uuid.Nil || actorID == uuid.Nil {
		return errors.New("invalid deactivate tax slab input")
	}
	if err := s.repo.DeactivateTaxSlab(ctx, slabID, actorID); err != nil {
		return err
	}
	if s.audit != nil {
		_ = s.audit.LogAction(
			ctx,
			nil,
			"statutory",
			"tax_slab_deactivated",
			"company_tax_slab",
			&slabID,
			"admin",
			&actorID,
			nil,
			nil,
			nil,
		)
	}
	return nil
}

func (s *statutoryEngine) ListTaxSlabs(ctx context.Context, companyID uuid.UUID, statutoryCode string) ([]models.StatutoryTaxSlab, error) {
	if companyID == uuid.Nil || statutoryCode == "" {
		return nil, errors.New("company ID and statutory code required")
	}
	return s.repo.ListTaxSlabsByStatutoryCode(ctx, companyID, statutoryCode)
}

func (s *statutoryEngine) CreateDeductionLimit(ctx context.Context, input *CreateDeductionLimitInput) error {
	if input == nil || input.CompanyID == uuid.Nil || input.RuleSetID == uuid.Nil || input.LimitCode == "" || input.ActorID == uuid.Nil {
		return errors.New("invalid deduction limit input")
	}
	rs, err := s.repo.GetRuleSetByID(ctx, input.RuleSetID)
	if err != nil {
		return err
	}
	if rs == nil {
		return fmt.Errorf("rule set %s not found", input.RuleSetID)
	}
	limits, err := s.repo.ListDeductionLimits(ctx, input.CompanyID, &input.RuleSetID)
	if err != nil {
		return err
	}
	for _, l := range limits {
		if l.LimitCode == input.LimitCode {
			return fmt.Errorf("deduction limit with code %s already exists in this rule set", input.LimitCode)
		}
	}
	modelInput := models.CreateDeductionLimitInput{
		CompanyID:  input.CompanyID,
		RuleSetID:  input.RuleSetID,
		LimitCode:  input.LimitCode,
		LimitValue: input.LimitValue,
		Metadata:   input.Metadata,
	}
	if err := s.repo.CreateDeductionLimit(ctx, modelInput); err != nil {
		return err
	}
	if s.audit != nil {
		_ = s.audit.LogAction(
			ctx,
			&input.CompanyID,
			"statutory",
			"deduction_limit_created",
			"statutory_deduction_limit",
			nil,
			"admin",
			&input.ActorID,
			nil,
			nil,
			map[string]interface{}{
				"limit_code":  input.LimitCode,
				"rule_set_id": input.RuleSetID.String(),
				"limit_value": input.LimitValue,
			},
		)
	}
	return nil
}

func (s *statutoryEngine) UpdateDeductionLimit(ctx context.Context, input *UpdateDeductionLimitInput) error {
	if input == nil || input.LimitID == uuid.Nil || input.ActorID == uuid.Nil {
		return errors.New("invalid deduction limit update input")
	}
	modelInput := models.UpdateDeductionLimitInput{
		LimitID:    input.LimitID,
		LimitValue: input.LimitValue,
		Metadata:   input.Metadata,
	}
	if err := s.repo.UpdateDeductionLimit(ctx, modelInput); err != nil {
		return err
	}
	if s.audit != nil {
		_ = s.audit.LogAction(
			ctx,
			nil,
			"statutory",
			"deduction_limit_updated",
			"statutory_deduction_limit",
			&input.LimitID,
			"admin",
			&input.ActorID,
			nil,
			nil,
			nil,
		)
	}
	return nil
}

func (s *statutoryEngine) DeleteDeductionLimit(ctx context.Context, limitID uuid.UUID, actorID uuid.UUID) error {
	if limitID == uuid.Nil || actorID == uuid.Nil {
		return errors.New("invalid delete deduction limit input")
	}
	if err := s.repo.DeleteDeductionLimit(ctx, limitID); err != nil {
		return err
	}
	if s.audit != nil {
		_ = s.audit.LogAction(
			ctx,
			nil,
			"statutory",
			"deduction_limit_deleted",
			"statutory_deduction_limit",
			&limitID,
			"admin",
			&actorID,
			nil,
			nil,
			nil,
		)
	}
	return nil
}

func (s *statutoryEngine) ListDeductionLimits(ctx context.Context, companyID uuid.UUID, ruleSetID *uuid.UUID) ([]models.StatutoryDeductionLimit, error) {
	if companyID == uuid.Nil {
		return nil, errors.New("company ID required")
	}
	return s.repo.ListDeductionLimits(ctx, companyID, ruleSetID)
}

func (s *statutoryEngine) CreateComponentMapping(ctx context.Context, input *CreateComponentMappingInput) error {
	if input == nil || input.CompanyID == uuid.Nil || input.StatutoryCode == "" || input.ComponentCode == "" || input.RuleSetID == uuid.Nil || input.ActorID == uuid.Nil {
		return errors.New("invalid component mapping input")
	}
	def, err := s.repo.GetStatutoryComponentDefinition(ctx, input.CompanyID, input.StatutoryCode)
	if err != nil {
		return err
	}
	if def == nil {
		return fmt.Errorf("statutory component definition %s not found", input.StatutoryCode)
	}
	rs, err := s.repo.GetRuleSetByID(ctx, input.RuleSetID)
	if err != nil {
		return err
	}
	if rs == nil {
		return fmt.Errorf("rule set %s not found", input.RuleSetID)
	}
	mappings, err := s.repo.ListComponentMappings(ctx, input.CompanyID, &input.StatutoryCode)
	if err != nil {
		return err
	}
	for _, m := range mappings {
		if m.ComponentCode == input.ComponentCode && m.IsActive {
			return fmt.Errorf("active mapping already exists for %s → %s", input.StatutoryCode, input.ComponentCode)
		}
	}
	modelInput := models.CreateComponentMappingInput{
		CompanyID:     input.CompanyID,
		StatutoryCode: input.StatutoryCode,
		ComponentCode: input.ComponentCode,
		EffectiveFrom: input.EffectiveFrom,
		RuleSetID:     input.RuleSetID,
		CreatedBy:     input.ActorID,
	}
	if err := s.repo.CreateComponentMapping(ctx, modelInput); err != nil {
		return err
	}
	if s.audit != nil {
		_ = s.audit.LogAction(
			ctx,
			&input.CompanyID,
			"statutory",
			"component_mapping_created",
			"statutory_component_mapping",
			nil,
			"admin",
			&input.ActorID,
			nil,
			nil,
			map[string]interface{}{
				"statutory_code": input.StatutoryCode,
				"component_code": input.ComponentCode,
				"rule_set_id":    input.RuleSetID.String(),
			},
		)
	}
	return nil
}

func (s *statutoryEngine) UpdateComponentMapping(ctx context.Context, input *UpdateComponentMappingInput) error {
	if input == nil || input.MappingID == uuid.Nil || input.ActorID == uuid.Nil {
		return errors.New("invalid component mapping update input")
	}
	modelInput := models.UpdateComponentMappingInput{
		MappingID:     input.MappingID,
		ComponentCode: input.ComponentCode,
		EffectiveFrom: input.EffectiveFrom,
		Version:       input.Version,
		UpdatedBy:     input.ActorID,
	}
	if err := s.repo.UpdateComponentMapping(ctx, modelInput); err != nil {
		return err
	}
	if s.audit != nil {
		_ = s.audit.LogAction(
			ctx,
			nil,
			"statutory",
			"component_mapping_updated",
			"statutory_component_mapping",
			&input.MappingID,
			"admin",
			&input.ActorID,
			nil,
			nil,
			nil,
		)
	}
	return nil
}

func (s *statutoryEngine) DeactivateComponentMapping(ctx context.Context, mappingID uuid.UUID, actorID uuid.UUID) error {
	if mappingID == uuid.Nil || actorID == uuid.Nil {
		return errors.New("invalid deactivate component mapping input")
	}
	if err := s.repo.DeactivateComponentMapping(ctx, mappingID, actorID); err != nil {
		return err
	}
	if s.audit != nil {
		_ = s.audit.LogAction(
			ctx,
			nil,
			"statutory",
			"component_mapping_deactivated",
			"statutory_component_mapping",
			&mappingID,
			"admin",
			&actorID,
			nil,
			nil,
			nil,
		)
	}
	return nil
}

func (s *statutoryEngine) ListComponentMappings(ctx context.Context, companyID uuid.UUID, statutoryCode *string) ([]models.StatutoryComponentMapping, error) {
	if companyID == uuid.Nil {
		return nil, errors.New("company ID required")
	}
	return s.repo.ListComponentMappings(ctx, companyID, statutoryCode)
}

type CreateTaxSlabInput struct {
	CompanyID     uuid.UUID
	StatutoryCode string
	MinAmount     float64
	MaxAmount     *float64
	Rate          float64
	IsPercentage  bool
	SlabOrder     int
	EffectiveFrom time.Time
	RuleSetID     uuid.UUID
	ActorID       uuid.UUID
}

type UpdateTaxSlabInput struct {
	SlabID        uuid.UUID
	MinAmount     *float64
	MaxAmount     *float64
	Rate          *float64
	IsPercentage  *bool
	SlabOrder     *int
	EffectiveFrom *time.Time
	ActorID       uuid.UUID
}

type CreateDeductionLimitInput struct {
	CompanyID  uuid.UUID
	RuleSetID  uuid.UUID
	LimitCode  string
	LimitValue float64
	Metadata   map[string]interface{}
	ActorID    uuid.UUID
}

type UpdateDeductionLimitInput struct {
	LimitID    uuid.UUID
	LimitValue *float64
	Metadata   map[string]interface{}
	ActorID    uuid.UUID
}

type CreateComponentMappingInput struct {
	CompanyID     uuid.UUID
	StatutoryCode string
	ComponentCode string
	EffectiveFrom time.Time
	RuleSetID     uuid.UUID
	ActorID       uuid.UUID
}

type UpdateComponentMappingInput struct {
	MappingID     uuid.UUID
	ComponentCode *string
	EffectiveFrom *time.Time
	Version       int
	ActorID       uuid.UUID
}

func (s *statutoryEngine) ExecuteTx(
	ctx context.Context,
	input *StatutoryExecutionInput,
) (*StatutoryExecutionResult, error) {
	if input == nil {
		return nil, errors.New("statutory execution input is nil")
	}
	if input.CompanyID == uuid.Nil ||
		input.UserID == uuid.Nil ||
		input.PayrollRunID == uuid.Nil {
		return nil, errors.New("invalid execution input: missing required identifiers")
	}
	if input.ActorID == uuid.Nil {
		return nil, errors.New("actor_id required for statutory snapshot")
	}
	result, err := s.run(ctx, input)
	if err != nil {
		return nil, err
	}
	for _, c := range result.ContributionRecords {
		if err := s.repo.InsertEmployeeStatutoryContribution(ctx, c); err != nil {
			return nil, fmt.Errorf("failed to insert employee statutory contribution: %w", err)
		}
	}
	breakdown := convertTraceToBreakdown(result.ComputationTrace)
	snapshot := &models.StatutorySnapshot{
		SnapshotID:   uuid.New(),
		PayrollRunID: input.PayrollRunID,
		CompanyID:    input.CompanyID,
		UserID:       input.UserID,
		RuleSetID:    result.RuleSetID,
		RuleHash:     result.RuleHash,
		PeriodStart:  input.PeriodStart,
		PeriodEnd:    input.PeriodEnd,
		Breakdown:    breakdown,
		CreatedAt:    time.Now().UTC(),
		CreatedBy:    &input.ActorID,
	}
	if err := s.repo.InsertStatutorySnapshot(ctx, snapshot); err != nil {
		return nil, fmt.Errorf("failed to insert statutory snapshot: %w", err)
	}
	if s.audit != nil {
		metadata := map[string]interface{}{
			"user_id":       input.UserID.String(),
			"period_start":  input.PeriodStart,
			"period_end":    input.PeriodEnd,
			"rule_set_id":   result.RuleSetID.String(),
			"rule_hash":     result.RuleHash,
			"contributions": len(result.ContributionRecords),
		}
		_ = s.audit.LogAction(
			ctx,
			&input.CompanyID,
			"payroll",
			"statutory_execution_completed",
			"statutory_contribution",
			nil,
			"system",
			nil,
			nil,
			nil,
			metadata,
		)
	}
	return result, nil
}

type BulkCreateComponentMappingsInput struct {
	CompanyID      uuid.UUID
	StatutoryCode  string
	ComponentCodes []string
	EffectiveFrom  time.Time
	RuleSetID      uuid.UUID
	ActorID        uuid.UUID
}

func (s *statutoryEngine) BulkCreateComponentMappings(
	ctx context.Context,
	input *BulkCreateComponentMappingsInput,
) error {

	if input == nil ||
		input.CompanyID == uuid.Nil ||
		input.StatutoryCode == "" ||
		len(input.ComponentCodes) == 0 ||
		input.RuleSetID == uuid.Nil ||
		input.ActorID == uuid.Nil {
		return errors.New("invalid bulk component mapping input")
	}

	return s.repo.WithTx(ctx, func(tx repository.StatutoryRepository) error {

		// Validate definition
		def, err := tx.GetStatutoryComponentDefinition(ctx, input.CompanyID, input.StatutoryCode)
		if err != nil {
			return err
		}
		if def == nil {
			return fmt.Errorf("statutory component definition %s not found", input.StatutoryCode)
		}

		// Validate rule set
		rs, err := tx.GetRuleSetByID(ctx, input.RuleSetID)
		if err != nil {
			return err
		}
		if rs == nil {
			return fmt.Errorf("rule set %s not found", input.RuleSetID)
		}

		// Load existing mappings once (no N+1)
		existing, err := tx.ListComponentMappings(ctx, input.CompanyID, &input.StatutoryCode)
		if err != nil {
			return err
		}

		existingMap := make(map[string]bool)
		for _, m := range existing {
			if m.IsActive {
				existingMap[m.ComponentCode] = true
			}
		}

		for _, code := range input.ComponentCodes {

			if existingMap[code] {
				continue // skip duplicate safely
			}

			modelInput := models.CreateComponentMappingInput{
				CompanyID:     input.CompanyID,
				StatutoryCode: input.StatutoryCode,
				ComponentCode: code,
				EffectiveFrom: input.EffectiveFrom,
				RuleSetID:     input.RuleSetID,
				CreatedBy:     input.ActorID,
			}

			if err := tx.CreateComponentMapping(ctx, modelInput); err != nil {
				return err
			}
		}

		return nil
	})
}
