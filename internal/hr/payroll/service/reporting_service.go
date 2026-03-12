package service

import (
	"context"
	"fmt"
	"time"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ReportingService defines the interface for generating payroll reports.
type ReportingService interface {
	// GenerateStatutoryChallan returns the statutory contribution summary for a payroll period.
	GenerateStatutoryChallan(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time) ([]StatutoryChallanEntry, error)

	// GeneratePayrollRegister returns a detailed employee‑wise payroll register for a period.
	// groupBy can be "department", "cost_centre", or "" (no grouping). Implementation can be extended.
	GeneratePayrollRegister(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time, groupBy string) ([]PayrollRegisterRow, error)
}

// StatutoryChallanEntry represents one line in a statutory challan (e.g., PF, ESI).
type StatutoryChallanEntry struct {
	StatutoryCode  string  `json:"statutory_code"`
	Description    string  `json:"description"` // optional, can be fetched from definitions
	EmployeeAmount float64 `json:"employee_amount"`
	EmployerAmount float64 `json:"employer_amount"`
	TotalAmount    float64 `json:"total_amount"`
}

// PayrollRegisterRow represents one employee's payroll details for a period.
type PayrollRegisterRow struct {
	UserID                uuid.UUID                `json:"user_id"`
	EmployeeID            string                   `json:"employee_id"`
	EmployeeName          string                   `json:"employee_name"`
	Department            string                   `json:"department,omitempty"`
	Position              string                   `json:"position,omitempty"`
	PayableDays           float64                  `json:"payable_days"`
	UnpaidDays            float64                  `json:"unpaid_days"`
	GrossAmount           float64                  `json:"gross_amount"`
	NetAmount             float64                  `json:"net_amount"`
	Earnings              []PayrollComponentDetail `json:"earnings"`
	Deductions            []PayrollComponentDetail `json:"deductions"`
	EmployerContributions []PayrollComponentDetail `json:"employer_contributions,omitempty"`
}

// PayrollComponentDetail represents a single payroll component amount for an employee.
type PayrollComponentDetail struct {
	ComponentCode string  `json:"component_code"`
	Description   string  `json:"description"`
	Amount        float64 `json:"amount"`
	IsTaxable     bool    `json:"is_taxable"`
}

// reportingService is the concrete implementation.
type reportingService struct {
	payrollRepo repository.PayrollRepository
	// We may need other repos for statutory definitions etc., but for now we use payrollRepo.
	logger *zap.Logger
}

// NewReportingService creates a new reporting service.
func NewReportingService(
	payrollRepo repository.PayrollRepository,
	logger *zap.Logger,
) ReportingService {
	return &reportingService{
		payrollRepo: payrollRepo,
		logger:      logger.Named("reporting_service"),
	}
}

// GenerateStatutoryChallan retrieves the aggregated statutory contributions for the given period.
func (s *reportingService) GenerateStatutoryChallan(
	ctx context.Context,
	companyID uuid.UUID,
	periodStart, periodEnd time.Time,
) ([]StatutoryChallanEntry, error) {
	// Find the payroll run for this exact period.
	run, err := s.payrollRepo.GetPayrollRunByPeriod(ctx, companyID, periodStart, periodEnd)
	if err != nil {
		s.logger.Error("failed to get payroll run by period",
			zap.String("company_id", companyID.String()),
			zap.Time("period_start", periodStart),
			zap.Time("period_end", periodEnd),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to fetch payroll run: %w", err)
	}
	if run == nil {
		s.logger.Warn("no payroll run found for the given period",
			zap.String("company_id", companyID.String()),
			zap.Time("period_start", periodStart),
			zap.Time("period_end", periodEnd),
		)
		return []StatutoryChallanEntry{}, nil
	}

	// Get statutory summary for the run.
	aggregates, err := s.payrollRepo.GetRunStatutorySummary(ctx, run.PayrollRunID)
	if err != nil {
		s.logger.Error("failed to get statutory summary",
			zap.String("run_id", run.PayrollRunID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to fetch statutory summary: %w", err)
	}

	// Convert to output DTOs.
	entries := make([]StatutoryChallanEntry, 0, len(aggregates))
	for _, agg := range aggregates {
		entries = append(entries, StatutoryChallanEntry{
			StatutoryCode:  agg.StatutoryCode,
			Description:    "", // could be enriched by fetching statutory definition
			EmployeeAmount: agg.EmployeeTotal,
			EmployerAmount: agg.EmployerTotal,
			TotalAmount:    agg.CombinedTotal,
		})
	}

	return entries, nil
}

// GeneratePayrollRegister produces a detailed employee‑wise payroll register.
// It uses GetPayrollItemDetail for each item, which may be inefficient for large runs.
// For production use with many employees, consider extending the repository to return
// all required data in bulk.
func (s *reportingService) GeneratePayrollRegister(
	ctx context.Context,
	companyID uuid.UUID,
	periodStart, periodEnd time.Time,
	groupBy string, // currently unused, kept for future extension
) ([]PayrollRegisterRow, error) {
	// Find the payroll run for this exact period.
	run, err := s.payrollRepo.GetPayrollRunByPeriod(ctx, companyID, periodStart, periodEnd)
	if err != nil {
		s.logger.Error("failed to get payroll run by period",
			zap.String("company_id", companyID.String()),
			zap.Time("period_start", periodStart),
			zap.Time("period_end", periodEnd),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to fetch payroll run: %w", err)
	}
	if run == nil {
		s.logger.Warn("no payroll run found for the given period",
			zap.String("company_id", companyID.String()),
			zap.Time("period_start", periodStart),
			zap.Time("period_end", periodEnd),
		)
		return []PayrollRegisterRow{}, nil
	}

	// Get all payroll items for the run (active, non‑superseded).
	items, err := s.payrollRepo.GetPayrollItemsByRun(ctx, run.PayrollRunID)
	if err != nil {
		s.logger.Error("failed to get payroll items",
			zap.String("run_id", run.PayrollRunID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to fetch payroll items: %w", err)
	}

	rows := make([]PayrollRegisterRow, 0, len(items))

	// For each item, fetch detailed information (including components and employee details).
	for _, item := range items {
		detail, err := s.payrollRepo.GetPayrollItemDetail(ctx, item.PayrollItemID)
		if err != nil {
			s.logger.Error("failed to get payroll item detail",
				zap.String("item_id", item.PayrollItemID.String()),
				zap.Error(err),
			)
			// Skip this employee or fail? For robustness, we skip and log.
			continue
		}
		if detail == nil {
			s.logger.Warn("payroll item detail not found",
				zap.String("item_id", item.PayrollItemID.String()),
			)
			continue
		}

		// Separate components into earnings, deductions, and employer contributions.
		var earnings, deductions, _ []PayrollComponentDetail
		for _, comp := range detail.Components {
			detail := PayrollComponentDetail{
				ComponentCode: comp.ComponentCode,
				Description:   comp.Description,
				Amount:        comp.Amount,
				IsTaxable:     comp.IsTaxable,
			}
			switch comp.ComponentType {
			case models.ComponentTypeEarning:
				earnings = append(earnings, detail)
			case models.ComponentTypeDeduction:
				deductions = append(deductions, detail)
			default:
				// Employer contributions are usually tracked separately in the ledger,
				// but if they are stored as a component type, handle accordingly.
				// For now, we treat any component with contribution_side = 'employer' as employer contribution,
				// but that field is not in the component summary. We may need to fetch that separately.
				// As a fallback, we put them in deductions or ignore.
				// To keep it simple, we put them in employer slice if component code suggests it.
				// In a real implementation, you might need to join with payroll_component to get contribution_side.
				// Since we don't have that here, we'll skip for now.
			}
		}

		row := PayrollRegisterRow{
			UserID:       detail.UserID,
			EmployeeID:   detail.EmployeeID,
			EmployeeName: detail.FullName,
			Department:   nullString(detail.DepartmentName),
			Position:     nullString(detail.PositionTitle),
			PayableDays:  detail.PayableDays,
			UnpaidDays:   detail.UnpaidDays,
			GrossAmount:  detail.GrossAmount,
			NetAmount:    detail.NetAmount,
			Earnings:     earnings,
			Deductions:   deductions,
			// EmployerContributions: employer, // left empty for now
		}
		rows = append(rows, row)
	}

	return rows, nil
}

// Helper to convert *string to string, handling nil.
func nullString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
