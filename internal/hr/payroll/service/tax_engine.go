package service

import (
	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	"auth-service/internal/util"
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// TaxEngine handles tax calculations
type TaxEngine interface {
	ApplyTaxRules(ctx context.Context, companyID uuid.UUID, componentCode string, amount float64) (float64, error)
	CalculateTaxForComponent(ctx context.Context, companyID uuid.UUID, componentCode string, baseAmount float64) (*models.CalculatedTax, error)
	EvaluateFormula(formula string, variables map[string]float64) (float64, error)
}

type taxEngine struct {
	repo   repository.PayrollRepository
	logger *zap.Logger
}

func NewTaxEngine(repo repository.PayrollRepository, logger *zap.Logger) TaxEngine {
	return &taxEngine{
		repo:   repo,
		logger: logger,
	}
}

func (t *taxEngine) ApplyTaxRules(
	ctx context.Context,
	companyID uuid.UUID,
	componentCode string,
	amount float64,
) (float64, error) {
	if amount <= 0 {
		return 0, nil
	}

	// Get tax rules for this component
	rules, err := t.repo.GetTaxRulesByComponent(ctx, companyID, componentCode)
	if err != nil {
		return 0, fmt.Errorf("failed to get tax rules: %w", err)
	}

	if len(rules) == 0 {
		t.logger.Debug("No tax rules found for component",
			util.String("company_id", companyID.String()),
			util.String("component", componentCode))
		return 0, nil
	}

	// Apply each rule (multiple rules can apply)
	var totalTax float64
	var appliedRules []string

	for _, rule := range rules {
		if !t.isRuleApplicable(rule, amount) {
			continue
		}

		taxAmount, err := t.calculateTaxAmount(rule, amount)
		if err != nil {
			t.logger.Warn("Failed to calculate tax using rule",
				util.String("rule_id", rule.TaxRuleID.String()),
				util.ErrorField(err))
			continue
		}

		// Apply min/max constraints
		taxAmount = t.applyConstraints(taxAmount, rule.MinAmount, rule.MaxAmount)

		totalTax += taxAmount
		appliedRules = append(appliedRules, rule.CalculationType)
	}

	t.logger.Debug("Tax calculation completed",
		util.String("component", componentCode),
		util.Float64("base_amount", amount),
		util.Float64("tax_amount", totalTax),
		util.Strings("applied_rules", appliedRules))

	return totalTax, nil
}

func (t *taxEngine) CalculateTaxForComponent(
	ctx context.Context,
	companyID uuid.UUID,
	componentCode string,
	baseAmount float64,
) (*models.CalculatedTax, error) {
	taxAmount, err := t.ApplyTaxRules(ctx, companyID, componentCode, baseAmount)
	if err != nil {
		return nil, err
	}

	// Get component details for description
	_, err = t.repo.GetComponent(ctx, componentCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get component details: %w", err)
	}

	return &models.CalculatedTax{
		ComponentCode: componentCode,
		Amount:        baseAmount,
		TaxAmount:     taxAmount,
		AppliedRule:   t.getAppliedRuleDescription(ctx, companyID, componentCode),
	}, nil
}

func (t *taxEngine) EvaluateFormula(formula string, variables map[string]float64) (float64, error) {
	if formula == "" {
		return 0, fmt.Errorf("formula is empty")
	}

	// Simple formula evaluation
	// For production, use a proper expression evaluator like govaluate
	// This is a simplified version

	// Replace variables with their values
	expr := formula
	for key, value := range variables {
		placeholder := fmt.Sprintf("{%s}", key)
		expr = strings.ReplaceAll(expr, placeholder, fmt.Sprintf("%f", value))
	}

	// Basic arithmetic evaluation
	// This is a very simple evaluator - for production use a proper library
	result, err := t.evaluateSimpleExpression(expr)
	if err != nil {
		return 0, fmt.Errorf("failed to evaluate formula: %w", err)
	}

	return result, nil
}

func (t *taxEngine) isRuleApplicable(rule *models.TaxRule, amount float64) bool {
	// Check if amount meets minimum threshold if specified
	if rule.MinAmount != nil && amount < *rule.MinAmount {
		return false
	}

	// Check if amount exceeds maximum if specified
	if rule.MaxAmount != nil && amount > *rule.MaxAmount {
		return false
	}

	return true
}

func (t *taxEngine) calculateTaxAmount(rule *models.TaxRule, amount float64) (float64, error) {
	switch rule.CalculationType {
	case models.CalculationTypeFlat:
		if rule.Value == nil {
			return 0, fmt.Errorf("flat calculation requires value")
		}
		return *rule.Value, nil

	case models.CalculationTypePercentage:
		if rule.Value == nil {
			return 0, fmt.Errorf("percentage calculation requires value")
		}
		return amount * (*rule.Value / 100), nil

	case models.CalculationTypeFormula:
		if rule.Formula == nil || *rule.Formula == "" {
			return 0, fmt.Errorf("formula calculation requires formula")
		}
		variables := map[string]float64{
			"amount": amount,
		}
		return t.EvaluateFormula(*rule.Formula, variables)

	default:
		return 0, fmt.Errorf("unsupported calculation type: %s", rule.CalculationType)
	}
}

func (t *taxEngine) applyConstraints(amount float64, minAmount, maxAmount *float64) float64 {
	// Apply minimum
	if minAmount != nil && amount < *minAmount {
		return *minAmount
	}

	// Apply maximum
	if maxAmount != nil && amount > *maxAmount {
		return *maxAmount
	}

	return amount
}

func (t *taxEngine) getAppliedRuleDescription(ctx context.Context, companyID uuid.UUID, componentCode string) string {
	rules, err := t.repo.GetTaxRulesByComponent(ctx, companyID, componentCode)
	if err != nil || len(rules) == 0 {
		return "no rules"
	}

	var descriptions []string
	for _, rule := range rules {
		desc := fmt.Sprintf("%s", rule.CalculationType)
		if rule.Value != nil {
			desc += fmt.Sprintf("(%.2f)", *rule.Value)
		}
		descriptions = append(descriptions, desc)
	}

	return strings.Join(descriptions, ", ")
}

func (t *taxEngine) evaluateSimpleExpression(expr string) (float64, error) {
	// Remove whitespace
	expr = strings.ReplaceAll(expr, " ", "")

	// This is a very basic evaluator - use a proper library in production
	// For now, just handle simple arithmetic with +, -, *, /
	// For production, consider using github.com/Knetic/govaluate

	// Simple parsing for demonstration
	// Split by operators (this is simplified)
	if strings.Contains(expr, "+") {
		parts := strings.Split(expr, "+")
		var sum float64
		for _, part := range parts {
			val, err := strconv.ParseFloat(part, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid expression part: %s", part)
			}
			sum += val
		}
		return sum, nil
	}

	// Parse as single number
	val, err := strconv.ParseFloat(expr, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid expression: %s", expr)
	}

	return val, nil
}

// Helper for clamping values
func clamp(value, min, max float64) float64 {
	return math.Max(min, math.Min(value, max))
}
