package repository

import (
	"context"
	"time"

	"auth-service/internal/hr/payroll/models"

	"github.com/google/uuid"
)

type StatutoryRepository interface {
	WithTx(ctx context.Context, fn func(StatutoryRepository) error) error

	// Rule set resolution
	ResolveRuleSet(ctx context.Context, companyID uuid.UUID, asOf time.Time) (*models.StatutoryRuleSet, error)

	// Loading rule set details
	LoadStatutoryComponentMappingsByRuleSet(ctx context.Context, ruleSetID uuid.UUID) ([]models.StatutoryComponentMapping, error)
	LoadTaxSlabsByRuleSet(ctx context.Context, ruleSetID uuid.UUID) ([]models.StatutoryTaxSlab, error)
	LoadDeductionLimitsByRuleSet(ctx context.Context, ruleSetID uuid.UUID) ([]models.StatutoryDeductionLimit, error)

	// Employee level data
	GetEmployeeStatutoryProfiles(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, asOf time.Time) ([]models.EmployeeStatutoryProfile, error)
	GetYTDStatutorySummary(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, statutoryCode string, financialYearStart, asOf time.Time) (*models.YTDStatutorySummary, error)
	InsertEmployeeStatutoryContribution(ctx context.Context, contribution *models.EmployeeStatutoryContribution) error
	InsertStatutorySnapshot(ctx context.Context, snapshot *models.StatutorySnapshot) error

	// Rule set lifecycle
	CreateStatutoryRuleSet(ctx context.Context, ruleSet *models.StatutoryRuleSet) error
	UpdateStatutoryRuleSet(ctx context.Context, ruleSet *models.StatutoryRuleSet) error
	DeactivateStatutoryRuleSet(ctx context.Context, ruleSetID uuid.UUID, deactivatedBy uuid.UUID) error
	GetRuleSetByID(ctx context.Context, ruleSetID uuid.UUID) (*models.StatutoryRuleSet, error)
	DeactivateActiveRuleSetsByCountry(ctx context.Context, companyID uuid.UUID, countryCode string, actorID uuid.UUID) error
	ActivateRuleSet(ctx context.Context, ruleSetID uuid.UUID, actorID uuid.UUID) error
	ListRuleSets(ctx context.Context, companyID uuid.UUID) ([]models.StatutoryRuleSet, error)

	// Health check
	HealthCheck(ctx context.Context) error

	// ===== statutory_component_definition (company-aware) =====
	CreateStatutoryComponentDefinition(ctx context.Context, def *models.StatutoryComponentDefinition) error
	UpdateStatutoryComponentDefinition(ctx context.Context, def *models.StatutoryComponentDefinition) error
	GetStatutoryComponentDefinition(ctx context.Context, companyID uuid.UUID, statutoryCode string) (*models.StatutoryComponentDefinition, error)
	ListStatutoryComponentDefinitions(ctx context.Context, companyID uuid.UUID) ([]models.StatutoryComponentDefinition, error)

	// ===== statutory_contribution_rule =====
	LoadStatutoryContributionRulesByRuleSet(ctx context.Context, ruleSetID uuid.UUID, companyID uuid.UUID) ([]models.StatutoryContributionRule, error)
	UpsertStatutoryContributionRule(ctx context.Context, input models.CreateStatutoryContributionRuleInput) error
	LoadActiveContributionRules(ctx context.Context, companyID uuid.UUID, asOf time.Time) ([]models.StatutoryContributionRule, error)
	GetStatutoryContributionRuleByID(ctx context.Context, ruleID uuid.UUID) (*models.StatutoryContributionRule, error)
	DeactivateStatutoryContributionRule(ctx context.Context, ruleID uuid.UUID, actorID uuid.UUID) error
	ListContributionRulesByStatutoryCode(ctx context.Context, companyID uuid.UUID, statutoryCode string) ([]models.StatutoryContributionRule, error)
	DeleteStatutoryComponentDefinition(ctx context.Context, companyID uuid.UUID, statutoryCode string) error

	// Tax Slab
	CreateTaxSlab(ctx context.Context, input models.CreateTaxSlabInput) error
	UpdateTaxSlab(ctx context.Context, input models.UpdateTaxSlabInput) error
	DeactivateTaxSlab(ctx context.Context, slabID uuid.UUID, deactivatedBy uuid.UUID) error
	ListTaxSlabsByStatutoryCode(ctx context.Context, companyID uuid.UUID, statutoryCode string) ([]models.StatutoryTaxSlab, error)

	// Deduction Limit
	CreateDeductionLimit(ctx context.Context, input models.CreateDeductionLimitInput) error
	UpdateDeductionLimit(ctx context.Context, input models.UpdateDeductionLimitInput) error
	DeleteDeductionLimit(ctx context.Context, limitID uuid.UUID) error
	ListDeductionLimits(ctx context.Context, companyID uuid.UUID, ruleSetID *uuid.UUID) ([]models.StatutoryDeductionLimit, error)

	// Component Mapping
	CreateComponentMapping(ctx context.Context, input models.CreateComponentMappingInput) error
	UpdateComponentMapping(ctx context.Context, input models.UpdateComponentMappingInput) error
	DeactivateComponentMapping(ctx context.Context, mappingID uuid.UUID, deactivatedBy uuid.UUID) error
	ListComponentMappings(ctx context.Context, companyID uuid.UUID, statutoryCode *string) ([]models.StatutoryComponentMapping, error)
}
