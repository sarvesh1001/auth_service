package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/locationctx"
)

// ReportingService defines the interface for generating payroll reports.
type ReportingService interface {
	GenerateStatutoryChallan(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time) ([]StatutoryChallanEntry, error)
	GeneratePayrollRegister(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time, groupBy string) ([]PayrollRegisterRow, error)
}

type StatutoryChallanEntry struct {
	StatutoryCode  string  `json:"statutory_code"`
	Description    string  `json:"description"`
	EmployeeAmount float64 `json:"employee_amount"`
	EmployerAmount float64 `json:"employer_amount"`
	TotalAmount    float64 `json:"total_amount"`
}

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

type PayrollComponentDetail struct {
	ComponentCode string  `json:"component_code"`
	Description   string  `json:"description"`
	Amount        float64 `json:"amount"`
	IsTaxable     bool    `json:"is_taxable"`
}

type reportingService struct {
	payrollRepo      repository.PayrollRepository
	auditService     *audit.AuditService
	idempotencyStore idempotency.Store
}

func NewReportingService(
	payrollRepo repository.PayrollRepository,
	auditService *audit.AuditService,
	idempotencyStore idempotency.Store,
) ReportingService {
	return &reportingService{
		payrollRepo:      payrollRepo,
		auditService:     auditService,
		idempotencyStore: idempotencyStore,
	}
}

// GenerateStatutoryChallan — aggregated statutory contributions for the period.
//
// Location: when the request is location-scoped, only contributions for
// employees whose snapshotted employment_location_id at run time matches are
// included. When scope is ALL (or missing), the whole company is returned.
func (s *reportingService) GenerateStatutoryChallan(
	ctx context.Context,
	companyID uuid.UUID,
	periodStart, periodEnd time.Time,
) ([]StatutoryChallanEntry, error) {
	run, err := s.payrollRepo.GetPayrollRunByPeriod(ctx, companyID, periodStart, periodEnd)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch payroll run: %w", err)
	}
	if run == nil {
		return []StatutoryChallanEntry{}, nil
	}

	// 👇 Location scope filter (nil = no filter)
	locFilter := locationctx.Filter(ctx)

	aggregates, err := s.payrollRepo.GetRunStatutorySummary(ctx, run.PayrollRunID, locFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch statutory summary: %w", err)
	}

	entries := make([]StatutoryChallanEntry, 0, len(aggregates))
	for _, agg := range aggregates {
		entries = append(entries, StatutoryChallanEntry{
			StatutoryCode:  agg.StatutoryCode,
			Description:    "",
			EmployeeAmount: agg.EmployeeTotal,
			EmployerAmount: agg.EmployerTotal,
			TotalAmount:    agg.CombinedTotal,
		})
	}

	ip, _ := ctx.Value("ip_address").(string)
	resultJSON, _ := json.Marshal(entries)
	_ = s.auditService.LogAction(
		ctx, nil, &companyID, "payroll", "report.statutory_challan", "payroll_run",
		&run.PayrollRunID, "system", nil, nil, resultJSON,
		map[string]interface{}{
			"ip":             ip,
			"period_start":   periodStart,
			"period_end":     periodEnd,
			"run_id":         run.PayrollRunID.String(),
			"location_scope": locationScopeLabel(locFilter),
		},
	)

	return entries, nil
}

// GeneratePayrollRegister — detailed employee-wise register.
//
// Location: when location-scoped, only items for employees whose snapshotted
// employment_location_id at run time matches are included.
func (s *reportingService) GeneratePayrollRegister(
	ctx context.Context,
	companyID uuid.UUID,
	periodStart, periodEnd time.Time,
	groupBy string,
) ([]PayrollRegisterRow, error) {
	run, err := s.payrollRepo.GetPayrollRunByPeriod(ctx, companyID, periodStart, periodEnd)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch payroll run: %w", err)
	}
	if run == nil {
		return []PayrollRegisterRow{}, nil
	}

	// 👇 Location scope filter
	locFilter := locationctx.Filter(ctx)

	items, err := s.payrollRepo.GetPayrollItemsByRun(ctx, run.PayrollRunID, locFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch payroll items: %w", err)
	}

	rows := make([]PayrollRegisterRow, 0, len(items))

	for _, item := range items {
		detail, err := s.payrollRepo.GetPayrollItemDetail(ctx, item.PayrollItemID)
		if err != nil || detail == nil {
			continue
		}

		var earnings, deductions []PayrollComponentDetail
		for _, comp := range detail.Components {
			detailDTO := PayrollComponentDetail{
				ComponentCode: comp.ComponentCode,
				Description:   comp.Description,
				Amount:        comp.Amount,
				IsTaxable:     comp.IsTaxable,
			}
			switch comp.ComponentType {
			case models.ComponentTypeEarning:
				earnings = append(earnings, detailDTO)
			case models.ComponentTypeDeduction:
				deductions = append(deductions, detailDTO)
			}
		}

		rows = append(rows, PayrollRegisterRow{
			UserID:       detail.UserID,
			EmployeeID:   detail.EmployeeID,
			EmployeeName: detail.FullName,
			Department:   safeString(detail.DepartmentName),
			Position:     safeString(detail.PositionTitle),
			PayableDays:  detail.PayableDays,
			UnpaidDays:   detail.UnpaidDays,
			GrossAmount:  detail.GrossAmount,
			NetAmount:    detail.NetAmount,
			Earnings:     earnings,
			Deductions:   deductions,
		})
	}

	ip, _ := ctx.Value("ip_address").(string)
	resultJSON, _ := json.Marshal(rows)
	_ = s.auditService.LogAction(
		ctx, nil, &companyID, "payroll", "report.payroll_register", "payroll_run",
		&run.PayrollRunID, "system", nil, nil, resultJSON,
		map[string]interface{}{
			"ip":             ip,
			"period_start":   periodStart,
			"period_end":     periodEnd,
			"group_by":       groupBy,
			"run_id":         run.PayrollRunID.String(),
			"row_count":      len(rows),
			"location_scope": locationScopeLabel(locFilter),
		},
	)

	return rows, nil
}

// safeString converts *string to string, handling nil.
func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// locationScopeLabel returns a human-readable label for audit metadata.
func locationScopeLabel(locID *uuid.UUID) string {
	if locID == nil {
		return "ALL"
	}
	return locID.String()
}
