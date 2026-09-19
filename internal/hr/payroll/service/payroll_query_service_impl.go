package service

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	hrRepo "auth-service/internal/hr/repository"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/locationctx"
)

// PDFGenerator abstracts the PDF creation logic.
type PDFGenerator interface {
	GeneratePayslipPDF(payslip *models.Payslip) ([]byte, error)
}

type payrollQueryService struct {
	payrollRepo  repository.PayrollRepository
	bankRepo     repository.BankDetailsRepository
	payslipRepo  repository.PayslipRepository
	employeeRepo hrRepo.EmployeeRepository // 👈 new
	pdfGenerator PDFGenerator
	audit        *audit.AuditService
}

func NewPayrollQueryService(
	payrollRepo repository.PayrollRepository,
	bankRepo repository.BankDetailsRepository,
	payslipRepo repository.PayslipRepository,
	employeeRepo hrRepo.EmployeeRepository, // 👈 new
	pdfGen PDFGenerator,
	audit *audit.AuditService,
) PayrollQueryService {
	return &payrollQueryService{
		payrollRepo:  payrollRepo,
		bankRepo:     bankRepo,
		payslipRepo:  payslipRepo,
		employeeRepo: employeeRepo,
		pdfGenerator: pdfGen,
		audit:        audit,
	}
}

// ensureEmployeeInScope — same helper pattern.
func (s *payrollQueryService) ensureEmployeeInScope(
	ctx context.Context,
	companyID, targetUserID uuid.UUID,
) error {
	if actorStr, ok := ctx.Value("user_id").(string); ok {
		if actorID, err := uuid.Parse(actorStr); err == nil && actorID == targetUserID {
			return nil
		}
	}
	locCtx, err := locationctx.FromContext(ctx)
	if err != nil {
		return nil // system call
	}
	if locCtx.Mode == locationctx.ScopeAll {
		return nil
	}
	empLoc, err := s.employeeRepo.GetEmploymentLocationID(ctx, companyID, targetUserID)
	if err != nil {
		return err
	}
	if empLoc == nil {
		return ErrEmployeeHasNoLocation
	}
	if *empLoc != *locCtx.LocationID {
		return ErrEmployeeOutsideScope
	}
	return nil
}

// ------------------------------------------------------------------
// Run-scoped reads — pass location filter through.
// ------------------------------------------------------------------

func (s *payrollQueryService) GetRunSummary(ctx context.Context, companyID, runID uuid.UUID) (*models.PayrollRunDashboard, error) {
	run, err := s.payrollRepo.GetPayrollRunByID(ctx, runID)
	if err != nil {
		return nil, err
	}
	if run == nil || run.CompanyID != companyID {
		return nil, fmt.Errorf("payroll run not found")
	}

	summary, err := s.payrollRepo.GetPayrollRunSummary(ctx, runID)
	if err != nil {
		return nil, err
	}

	// 👇 Location-scope: ledger summary reflects only the caller's scope.
	locFilter := locationctx.Filter(ctx)
	ledgerSummary, err := s.payrollRepo.GetLedgerSummaryByRun(ctx, runID, locFilter)
	if err != nil {
		return nil, err
	}

	var totalEmployer float64
	for _, l := range ledgerSummary {
		if l.ContributionSide == models.ContributionSideEmployer {
			totalEmployer += l.TotalAmount
		}
	}

	return &models.PayrollRunDashboard{
		RunID:           run.PayrollRunID,
		CompanyID:       run.CompanyID,
		PeriodStart:     run.PeriodStart,
		PeriodEnd:       run.PeriodEnd,
		Status:          run.Status,
		TotalEmployees:  summary.TotalEmployees,
		ProcessedCount:  derefInt(run.ProcessedCount),
		FailedCount:     derefInt(run.FailedCount),
		TotalGross:      summary.TotalGross,
		TotalNet:        summary.TotalNet,
		TotalDeductions: summary.TotalDeductions,
		TotalEmployer:   totalEmployer,
		CreatedAt:       run.CreatedAt,
	}, nil
}

func (s *payrollQueryService) ListRuns(ctx context.Context, filter models.PayrollRunFilter) ([]*models.PayrollRun, int64, error) {
	return s.payrollRepo.GetPayrollRuns(ctx, filter)
}

func (s *payrollQueryService) GetRunLedgerSummary(ctx context.Context, companyID, runID uuid.UUID) ([]*models.LedgerSummary, error) {
	run, err := s.payrollRepo.GetPayrollRunByID(ctx, runID)
	if err != nil || run == nil || run.CompanyID != companyID {
		return nil, fmt.Errorf("run not found or access denied")
	}
	locFilter := locationctx.Filter(ctx)
	return s.payrollRepo.GetLedgerSummaryByRun(ctx, runID, locFilter)
}

func (s *payrollQueryService) GetRunExecutionStatus(ctx context.Context, companyID, runID uuid.UUID) (*models.PayrollExecutionStatus, error) {
	run, err := s.payrollRepo.GetPayrollRunExecutionStatus(ctx, runID)
	if err != nil {
		return nil, err
	}
	if run == nil || run.CompanyID != companyID {
		return nil, fmt.Errorf("run not found")
	}
	total := derefInt(run.TotalEmployees)
	processed := derefInt(run.ProcessedCount)
	var pct float64
	if total > 0 {
		pct = (float64(processed) / float64(total)) * 100
	}
	return &models.PayrollExecutionStatus{
		RunID:          run.PayrollRunID,
		Status:         run.Status,
		TotalEmployees: total,
		ProcessedCount: processed,
		FailedCount:    derefInt(run.FailedCount),
		ProgressPct:    pct,
		LastUpdatedAt:  run.LastProcessedAt,
	}, nil
}

// ------------------------------------------------------------------
// Employee-scoped reads — validate target.
// ------------------------------------------------------------------

func (s *payrollQueryService) GetEmployeePayrollDetail(ctx context.Context, companyID, payrollItemID uuid.UUID) (*models.PayrollItemDetail, error) {
	detail, err := s.payrollRepo.GetPayrollItemDetail(ctx, payrollItemID)
	if err != nil {
		return nil, err
	}
	if detail == nil {
		return nil, fmt.Errorf("payroll item not found")
	}

	run, err := s.payrollRepo.GetPayrollRunByID(ctx, detail.PayrollRunID)
	if err != nil {
		return nil, err
	}
	if run == nil || run.CompanyID != companyID {
		return nil, fmt.Errorf("access denied")
	}

	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, companyID, detail.UserID); err != nil {
		return nil, err
	}

	ip, _ := ctx.Value("ip_address").(string)
	actorID := getUserIDFromContext(ctx)
	metadata := map[string]interface{}{
		"payroll_run_id": detail.PayrollRunID.String(),
		"user_id":        detail.UserID.String(),
		"period_start":   run.PeriodStart,
		"period_end":     run.PeriodEnd,
		"ip":             ip,
	}
	_ = s.audit.LogAction(ctx, nil, &companyID, "payroll", "payroll_detail_viewed", "payroll_item", &payrollItemID, "user", actorID, nil, nil, metadata)

	return detail, nil
}

func (s *payrollQueryService) ListEmployeesInRun(ctx context.Context, companyID, runID uuid.UUID) ([]*models.PayrollItem, error) {
	run, err := s.payrollRepo.GetPayrollRunByID(ctx, runID)
	if err != nil || run == nil || run.CompanyID != companyID {
		return nil, fmt.Errorf("run not found")
	}
	// 👇 Location-scoped read
	locFilter := locationctx.Filter(ctx)
	return s.payrollRepo.GetPayrollItemsByRun(ctx, runID, locFilter)
}

func (s *payrollQueryService) GetEmployeePayrollHistory(ctx context.Context, companyID, userID uuid.UUID, from, to time.Time) ([]*models.PayrollItemDetail, error) {
	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}
	return s.payrollRepo.GetEmployeePayrollHistory(ctx, companyID, userID, from, to)
}

func (s *payrollQueryService) GetEmployeeYTD(ctx context.Context, companyID, userID uuid.UUID, financialYearStart time.Time) (*models.EmployeeYTDSummary, error) {
	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}
	return s.payrollRepo.GetEmployeeYTDSummary(ctx, companyID, userID, financialYearStart, time.Now())
}

func (s *payrollQueryService) GetEmployeeStatutorySummary(ctx context.Context, companyID, userID uuid.UUID, financialYearStart time.Time) (*models.EmployeeStatutorySummary, error) {
	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}
	ytdCtx, err := s.payrollRepo.BuildStatutoryYTDContext(ctx, companyID, userID, financialYearStart)
	if err != nil {
		return nil, err
	}
	empMap := ytdCtx.YTDStatutoryAmount
	var totalEmp float64
	for _, v := range empMap {
		totalEmp += v
	}
	return &models.EmployeeStatutorySummary{
		UserID:                userID,
		EmployeeContributions: empMap,
		EmployerContributions: make(map[string]float64),
		TotalEmployee:         totalEmp,
		TotalEmployer:         0,
	}, nil
}

func (s *payrollQueryService) GetRunStatutorySummary(ctx context.Context, companyID, runID uuid.UUID) ([]*models.StatutoryAggregate, error) {
	run, err := s.payrollRepo.GetPayrollRunByID(ctx, runID)
	if err != nil || run == nil || run.CompanyID != companyID {
		return nil, fmt.Errorf("run not found")
	}
	locFilter := locationctx.Filter(ctx)
	return s.payrollRepo.GetRunStatutorySummary(ctx, runID, locFilter)
}

// ------------------------------------------------------------------
// Trends (company-level rollups)
// ------------------------------------------------------------------

func (s *payrollQueryService) GetCompanyPayrollTrend(ctx context.Context, companyID uuid.UUID, from, to time.Time) ([]*models.PayrollTrendPoint, error) {
	return s.payrollRepo.GetPayrollTrend(ctx, companyID, from, to)
}

func (s *payrollQueryService) GetComponentBreakdownTrend(ctx context.Context, companyID uuid.UUID, componentCode string, from, to time.Time) ([]*models.ComponentTrendPoint, error) {
	return s.payrollRepo.GetComponentTrend(ctx, companyID, componentCode, from, to)
}

func (s *payrollQueryService) GetEmployeePayslip(ctx context.Context, companyID, payrollItemID uuid.UUID) (*models.Payslip, error) {
	detail, err := s.GetEmployeePayrollDetail(ctx, companyID, payrollItemID)
	if err != nil {
		return nil, err
	}
	run, err := s.payrollRepo.GetPayrollRunByID(ctx, detail.PayrollRunID)
	if err != nil {
		return nil, err
	}
	payslip := &models.Payslip{
		PayslipID:    uuid.New(),
		CompanyID:    companyID,
		UserID:       detail.UserID,
		PayrollRunID: detail.PayrollRunID,
		PeriodStart:  run.PeriodStart,
		PeriodEnd:    run.PeriodEnd,
		GrossAmount:  detail.GrossAmount,
		NetAmount:    detail.NetAmount,
		GeneratedAt:  time.Now(),
	}
	for _, comp := range detail.Components {
		pc := models.PayslipComponent{
			Code:        comp.ComponentCode,
			Description: comp.Description,
			Amount:      comp.Amount,
		}
		if comp.ComponentType == models.ComponentTypeEarning {
			payslip.Earnings = append(payslip.Earnings, pc)
		} else {
			payslip.Deductions = append(payslip.Deductions, pc)
		}
		if comp.ComponentCode == "TDS" || comp.ComponentCode == "TAX" {
			payslip.TotalTax += comp.Amount
		}
	}
	return payslip, nil
}

// ------------------------------------------------------------------
// Exports
// ------------------------------------------------------------------

func (s *payrollQueryService) ExportRunToCSV(ctx context.Context, companyID, runID uuid.UUID) ([]byte, error) {
	run, err := s.payrollRepo.GetPayrollRunByID(ctx, runID)
	if err != nil || run == nil || run.CompanyID != companyID {
		return nil, fmt.Errorf("run not found")
	}

	locFilter := locationctx.Filter(ctx)
	items, err := s.payrollRepo.GetPayrollItemsByRun(ctx, runID, locFilter)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	_ = writer.Write([]string{"UserID", "GrossAmount", "NetAmount", "PayableDays", "UnpaidDays"})
	for _, item := range items {
		_ = writer.Write([]string{
			item.UserID.String(),
			fmt.Sprintf("%.2f", item.GrossAmount),
			fmt.Sprintf("%.2f", item.NetAmount),
			fmt.Sprintf("%.2f", item.PayableDays),
			fmt.Sprintf("%.2f", item.UnpaidDays),
		})
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}

	ip, _ := ctx.Value("ip_address").(string)
	actorID := getUserIDFromContext(ctx)
	metadata := map[string]interface{}{
		"period_start":   run.PeriodStart,
		"period_end":     run.PeriodEnd,
		"status":         run.Status,
		"record_count":   len(items),
		"ip":             ip,
		"location_scope": locationScopeLabel(locFilter),
	}
	_ = s.audit.LogAction(ctx, nil, &companyID, "payroll", "payroll_run_export", "payroll_run", &runID, "user", actorID, nil, nil, metadata)
	return buf.Bytes(), nil
}

// ExportBankFile — company-wide artifact; requires ALL scope.
func (s *payrollQueryService) ExportBankFile(ctx context.Context, companyID, runID uuid.UUID, bankFormat string) ([]byte, error) {
	run, err := s.payrollRepo.GetPayrollRunByID(ctx, runID)
	if err != nil || run == nil || run.CompanyID != companyID {
		return nil, fmt.Errorf("run not found")
	}
	if run.Status != models.PayrollStatusApproved && run.Status != models.PayrollStatusPaid {
		return nil, fmt.Errorf("run must be approved or paid to export bank file")
	}

	// 👇 Bank file is one CSV for the entire company — require ALL scope.
	locCtx, err := locationctx.FromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("location context missing: %w", err)
	}
	if locCtx.Mode != locationctx.ScopeAll {
		return nil, ErrCompanyWideScopeRequired
	}

	items, err := s.payrollRepo.GetPayrollItemsByRun(ctx, runID, nil)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("no payroll items found")
	}

	userIDs := make([]uuid.UUID, len(items))
	for i, item := range items {
		userIDs[i] = item.UserID
	}
	bankMap, err := s.bankRepo.GetBankDetailsForPayrollRun(ctx, companyID, userIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch bank details: %w", err)
	}

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	switch bankFormat {
	case "hdfc", "icici", "sbi":
		_ = writer.Write([]string{"EmployeeID", "AccountNumber", "IFSC", "Amount", "Narration"})
	default:
		_ = writer.Write([]string{"UserID", "AccountNumber", "IFSC", "Amount"})
	}

	for _, item := range items {
		bank, ok := bankMap[item.UserID]
		if !ok {
			continue
		}
		amount := item.NetAmount
		switch bankFormat {
		case "hdfc":
			_ = writer.Write([]string{
				"", bank.AccountNumber, bank.IFSCCode,
				fmt.Sprintf("%.0f", amount*100),
				fmt.Sprintf("Salary %s", run.PeriodStart.Format("Jan 2006")),
			})
		case "icici":
			_ = writer.Write([]string{
				bank.AccountNumber, bank.IFSCCode,
				fmt.Sprintf("%.2f", amount),
				fmt.Sprintf("Salary %s", run.PeriodStart.Format("Jan 2006")),
			})
		default:
			_ = writer.Write([]string{
				item.UserID.String(), bank.AccountNumber, bank.IFSCCode,
				fmt.Sprintf("%.2f", amount), "",
			})
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}

	ip, _ := ctx.Value("ip_address").(string)
	actorID := getUserIDFromContext(ctx)
	metadata := map[string]interface{}{
		"run_id":    runID.String(),
		"format":    bankFormat,
		"employees": len(items),
		"ip":        ip,
	}
	_ = s.audit.LogAction(ctx, nil, &companyID, "payroll", "bank_file_export", "payroll_run", &runID, "user", actorID, nil, nil, metadata)

	return buf.Bytes(), nil
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

func derefInt(v *int) int {
	if v == nil {
		return 0
	}
	return *v
}

func getUserIDFromContext(ctx context.Context) *uuid.UUID {
	return nil
}
