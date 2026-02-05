package service

import (
	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	"auth-service/internal/util"
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// CompensationResolver handles salary structure resolution
type CompensationResolver interface {
	ResolveCompensation(ctx context.Context, companyID, userID uuid.UUID, periodStart, periodEnd time.Time, payableDays float64) ([]*models.PayrollLedgerItem, error)
	ResolveBasicSalary(ctx context.Context, companyID, userID uuid.UUID, payableDays, totalDays float64) (float64, error)
	ResolveAllowances(ctx context.Context, companyID, userID uuid.UUID, basicSalary float64, payableDays, totalDays float64) ([]*models.PayrollLedgerItem, error)
	CalculateProratedAmount(monthlyAmount float64, payableDays, totalDays float64) float64
}

type compensationResolver struct {
	repo   repository.PayrollRepository
	logger *zap.Logger
}

func NewCompensationResolver(repo repository.PayrollRepository, logger *zap.Logger) CompensationResolver {
	return &compensationResolver{
		repo:   repo,
		logger: logger,
	}
}

func (c *compensationResolver) ResolveCompensation(
	ctx context.Context,
	companyID, userID uuid.UUID,
	periodStart, periodEnd time.Time,
	payableDays float64,
) ([]*models.PayrollLedgerItem, error) {
	startTime := time.Now()

	// Calculate total days in period
	totalDays := c.calculateTotalDaysInPeriod(periodStart, periodEnd)

	// Resolve basic salary
	basicSalary, err := c.ResolveBasicSalary(ctx, companyID, userID, payableDays, totalDays)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve basic salary: %w", err)
	}

	// Resolve allowances
	allowances, err := c.ResolveAllowances(ctx, companyID, userID, basicSalary, payableDays, totalDays)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve allowances: %w", err)
	}

	// Combine all compensation components
	var compensation []*models.PayrollLedgerItem

	// Add basic salary
	if basicSalary > 0 {
		basicComponent, err := c.repo.GetComponent(ctx, models.ComponentCodeBasic)
		if err != nil {
			return nil, fmt.Errorf("failed to get basic component: %w", err)
		}
		if basicComponent == nil {
			return nil, fmt.Errorf("basic component not found")
		}

		compensation = append(compensation, &models.PayrollLedgerItem{
			ComponentCode: models.ComponentCodeBasic,
			ComponentType: models.ComponentTypeEarning,
			Description:   basicComponent.Description,
			Amount:        basicSalary,
			IsTaxable:     basicComponent.IsTaxable,
		})
	}

	// Add allowances
	compensation = append(compensation, allowances...)

	c.logger.Debug("Compensation resolved",
		util.String("user_id", userID.String()),
		util.Float64("basic_salary", basicSalary),
		util.Int("allowances_count", len(allowances)),
		util.Duration("duration", time.Since(startTime)))

	return compensation, nil
}

func (c *compensationResolver) ResolveBasicSalary(
	ctx context.Context,
	companyID, userID uuid.UUID,
	payableDays, totalDays float64,
) (float64, error) {
	// Get employee's base salary
	// This should come from employee profile or salary structure
	// For now, using a placeholder - you need to implement this based on your data model
	monthlySalary, err := c.getEmployeeMonthlySalary(ctx, companyID, userID)
	if err != nil {
		return 0, fmt.Errorf("failed to get employee salary: %w", err)
	}

	// Prorate based on payable days
	proratedSalary := c.CalculateProratedAmount(monthlySalary, payableDays, totalDays)

	return proratedSalary, nil
}

func (c *compensationResolver) ResolveAllowances(
	ctx context.Context,
	companyID, userID uuid.UUID,
	basicSalary float64,
	payableDays, totalDays float64,
) ([]*models.PayrollLedgerItem, error) {
	var allowances []*models.PayrollLedgerItem

	// Get allowance components
	allowanceComponents, err := c.repo.GetComponents(ctx, models.ComponentFilter{
		ComponentType: util.StringPtr(models.ComponentTypeEarning),
		IsActive:      util.BoolPtr(true),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get allowance components: %w", err)
	}

	// Get employee allowance configuration
	employeeAllowances, err := c.getEmployeeAllowances(ctx, companyID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get employee allowances: %w", err)
	}

	// Calculate each allowance
	for _, component := range allowanceComponents {
		// Skip basic salary component
		if component.ComponentCode == models.ComponentCodeBasic {
			continue
		}

		// Check if employee has this allowance
		allowanceAmount, hasAllowance := employeeAllowances[component.ComponentCode]
		if !hasAllowance {
			continue
		}

		// Calculate allowance amount
		var amount float64

		switch component.ComponentCode {
		case models.ComponentCodeHRA:
			// HRA is typically 40-50% of basic salary
			amount = basicSalary * (allowanceAmount / 100)
		default:
			// Other allowances - prorated fixed amount
			amount = c.CalculateProratedAmount(allowanceAmount, payableDays, totalDays)
		}

		if amount > 0 {
			allowances = append(allowances, &models.PayrollLedgerItem{
				ComponentCode: component.ComponentCode,
				ComponentType: component.ComponentType,
				Description:   component.Description,
				Amount:        amount,
				IsTaxable:     component.IsTaxable,
			})
		}
	}

	return allowances, nil
}

func (c *compensationResolver) CalculateProratedAmount(monthlyAmount float64, payableDays, totalDays float64) float64 {
	if totalDays <= 0 {
		return 0
	}
	return (monthlyAmount / totalDays) * payableDays
}

func (c *compensationResolver) calculateTotalDaysInPeriod(periodStart, periodEnd time.Time) float64 {
	days := periodEnd.Sub(periodStart).Hours()/24 + 1
	return float64(int(days))
}

// Placeholder methods - you need to implement these based on your data model
func (c *compensationResolver) getEmployeeMonthlySalary(ctx context.Context, companyID, userID uuid.UUID) (float64, error) {
	// TODO: Implement based on your employee salary structure
	// This should query employee_profiles or a dedicated salary table
	// For now, return a placeholder value
	return 50000.00, nil
}

func (c *compensationResolver) getEmployeeAllowances(ctx context.Context, companyID, userID uuid.UUID) (map[string]float64, error) {
	// TODO: Implement based on your allowance configuration
	// This should query employee_allowances or similar table
	// For now, return placeholder values
	return map[string]float64{
		models.ComponentCodeHRA: 40.0, // 40% of basic for HRA
		"CONVEYANCE":            1600.00,
		"MEDICAL":               1250.00,
	}, nil
}
