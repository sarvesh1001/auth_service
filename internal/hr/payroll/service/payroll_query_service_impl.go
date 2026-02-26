package service

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"time"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	a "auth-service/internal/hr/service" // audit service alias

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type payrollQueryService struct {
	payrollRepo repository.PayrollRepository
	audit       *a.AuditService
	logger      *zap.Logger
}

// NewPayrollQueryService creates a new payroll query service with audit support.
func NewPayrollQueryService(
	payrollRepo repository.PayrollRepository,
	audit *a.AuditService,
	logger *zap.Logger,
) PayrollQueryService {
	return &payrollQueryService{
		payrollRepo: payrollRepo,
		audit:       audit,
		logger:      logger.Named("payroll_query_service"),
	}
}

// GetRunSummary returns a dashboard summary for a specific payroll run.
func (s *payrollQueryService) GetRunSummary(
	ctx context.Context,
	companyID, runID uuid.UUID,
) (*models.PayrollRunDashboard, error) {
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

	ledgerSummary, err := s.payrollRepo.GetLedgerSummaryByRun(ctx, runID)
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

// ListRuns returns payroll runs with pagination and filtering.
func (s *payrollQueryService) ListRuns(
	ctx context.Context,
	filter models.PayrollRunFilter,
) ([]*models.PayrollRun, int64, error) {
	return s.payrollRepo.GetPayrollRuns(ctx, filter)
}

// GetRunLedgerSummary returns ledger summary for a run.
func (s *payrollQueryService) GetRunLedgerSummary(
	ctx context.Context,
	companyID, runID uuid.UUID,
) ([]*models.LedgerSummary, error) {
	run, err := s.payrollRepo.GetPayrollRunByID(ctx, runID)
	if err != nil || run == nil || run.CompanyID != companyID {
		return nil, fmt.Errorf("run not found or access denied")
	}
	return s.payrollRepo.GetLedgerSummaryByRun(ctx, runID)
}

// GetRunExecutionStatus returns the current execution status of a run.
func (s *payrollQueryService) GetRunExecutionStatus(
	ctx context.Context,
	companyID, runID uuid.UUID,
) (*models.PayrollExecutionStatus, error) {
	run, err := s.payrollRepo.GetPayrollRunByID(ctx, runID)
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

// GetEmployeePayrollDetail returns detailed payroll information for a single employee item.
// This is a sensitive operation, so it is audited.
func (s *payrollQueryService) GetEmployeePayrollDetail(
	ctx context.Context,
	companyID, payrollItemID uuid.UUID,
) (*models.PayrollItemDetail, error) {
	detail, err := s.payrollRepo.GetPayrollItemDetail(ctx, payrollItemID)
	if err != nil {
		return nil, err
	}
	if detail == nil {
		return nil, fmt.Errorf("payroll item not found")
	}

	// Validate company via the payroll run
	run, err := s.payrollRepo.GetPayrollRunByID(ctx, detail.PayrollRunID)
	if err != nil {
		return nil, err
	}
	if run == nil || run.CompanyID != companyID {
		return nil, fmt.Errorf("access denied")
	}

	// Audit access to detailed payroll information
	// TODO: Extract actorID from context (e.g., via auth middleware)
	// For now, we pass nil as actorID and log a warning if it's missing.
	actorID := getUserIDFromContext(ctx) // placeholder – implement as needed
	if actorID == nil {
		s.logger.Warn("No actor ID in context for GetEmployeePayrollDetail audit",
			zap.String("payroll_item_id", payrollItemID.String()))
	}

	metadata := map[string]interface{}{
		"payroll_run_id": detail.PayrollRunID.String(),
		"user_id":        detail.UserID.String(),
		"period_start":   run.PeriodStart,
		"period_end":     run.PeriodEnd,
	}
	if err := s.audit.LogAction(
		ctx,
		&companyID,
		"payroll",
		"payroll_detail_viewed",
		"payroll_item",
		&payrollItemID,
		"user", // or "admin" – adjust based on actual actor type
		actorID,
		nil,
		nil,
		metadata,
	); err != nil {
		s.logger.Error("Failed to audit payroll detail view",
			zap.String("payroll_item_id", payrollItemID.String()),
			zap.Error(err))
	}

	return detail, nil
}

// ListEmployeesInRun returns all payroll items for a given run.
func (s *payrollQueryService) ListEmployeesInRun(
	ctx context.Context,
	companyID, runID uuid.UUID,
) ([]*models.PayrollItem, error) {
	run, err := s.payrollRepo.GetPayrollRunByID(ctx, runID)
	if err != nil || run == nil || run.CompanyID != companyID {
		return nil, fmt.Errorf("run not found")
	}
	return s.payrollRepo.GetPayrollItemsByRun(ctx, runID)
}

// GetEmployeePayrollHistory returns historical payroll data for an employee.
func (s *payrollQueryService) GetEmployeePayrollHistory(
	ctx context.Context,
	companyID, userID uuid.UUID,
	from, to time.Time,
) ([]*models.PayrollItemDetail, error) {
	return s.payrollRepo.GetEmployeePayrollHistory(ctx, companyID, userID, from, to)
}

// GetEmployeeYTD returns year-to-date summary for an employee.
func (s *payrollQueryService) GetEmployeeYTD(
	ctx context.Context,
	companyID, userID uuid.UUID,
	financialYearStart time.Time,
) (*models.EmployeeYTDSummary, error) {
	return s.payrollRepo.GetEmployeeYTDSummary(ctx, companyID, userID, financialYearStart, time.Now())
}

// GetEmployeeStatutorySummary returns statutory contribution summary for an employee.
func (s *payrollQueryService) GetEmployeeStatutorySummary(
	ctx context.Context,
	companyID, userID uuid.UUID,
	financialYearStart time.Time,
) (*models.EmployeeStatutorySummary, error) {
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

// GetRunStatutorySummary returns aggregated statutory data for a run.
func (s *payrollQueryService) GetRunStatutorySummary(
	ctx context.Context,
	companyID, runID uuid.UUID,
) ([]*models.StatutoryAggregate, error) {
	run, err := s.payrollRepo.GetPayrollRunByID(ctx, runID)
	if err != nil || run == nil || run.CompanyID != companyID {
		return nil, fmt.Errorf("run not found")
	}
	return s.payrollRepo.GetRunStatutorySummary(ctx, runID)
}

// GetCompanyPayrollTrend returns trend data for company payroll over time.
func (s *payrollQueryService) GetCompanyPayrollTrend(
	ctx context.Context,
	companyID uuid.UUID,
	from, to time.Time,
) ([]*models.PayrollTrendPoint, error) {
	return s.payrollRepo.GetPayrollTrend(ctx, companyID, from, to)
}

// GetComponentBreakdownTrend returns trend data for a specific component.
func (s *payrollQueryService) GetComponentBreakdownTrend(
	ctx context.Context,
	companyID uuid.UUID,
	componentCode string,
	from, to time.Time,
) ([]*models.ComponentTrendPoint, error) {
	return s.payrollRepo.GetComponentTrend(ctx, companyID, componentCode, from, to)
}

// GetEmployeePayslip generates a payslip for a specific payroll item.
// This is a sensitive operation and is audited.
func (s *payrollQueryService) GetEmployeePayslip(
	ctx context.Context,
	companyID, payrollItemID uuid.UUID,
) (*models.Payslip, error) {
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

	// Audit payslip generation
	actorID := getUserIDFromContext(ctx) // placeholder
	if actorID == nil {
		s.logger.Warn("No actor ID in context for GetEmployeePayslip audit",
			zap.String("payroll_item_id", payrollItemID.String()))
	}

	metadata := map[string]interface{}{
		"payroll_run_id": detail.PayrollRunID.String(),
		"user_id":        detail.UserID.String(),
		"period_start":   run.PeriodStart,
		"period_end":     run.PeriodEnd,
	}
	if err := s.audit.LogAction(
		ctx,
		&companyID,
		"payroll",
		"payslip_viewed",
		"payslip",
		&payslip.PayslipID,
		"user",
		actorID,
		nil,
		nil,
		metadata,
	); err != nil {
		s.logger.Error("Failed to audit payslip view",
			zap.String("payslip_id", payslip.PayslipID.String()),
			zap.Error(err))
	}

	return payslip, nil
}

// ExportRunToCSV exports payroll run data as CSV.
// This is a data extraction operation and is audited.
func (s *payrollQueryService) ExportRunToCSV(
	ctx context.Context,
	companyID, runID uuid.UUID,
) ([]byte, error) {
	run, err := s.payrollRepo.GetPayrollRunByID(ctx, runID)
	if err != nil || run == nil || run.CompanyID != companyID {
		return nil, fmt.Errorf("run not found")
	}

	items, err := s.payrollRepo.GetPayrollItemsByRun(ctx, runID)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write header
	_ = writer.Write([]string{"UserID", "GrossAmount", "NetAmount", "PayableDays", "UnpaidDays"})

	// Write rows
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

	// Audit export
	actorID := getUserIDFromContext(ctx) // placeholder
	if actorID == nil {
		s.logger.Warn("No actor ID in context for ExportRunToCSV audit",
			zap.String("run_id", runID.String()))
	}

	metadata := map[string]interface{}{
		"period_start": run.PeriodStart,
		"period_end":   run.PeriodEnd,
		"status":       run.Status,
		"record_count": len(items),
	}
	if err := s.audit.LogAction(
		ctx,
		&companyID,
		"payroll",
		"payroll_run_export",
		"payroll_run",
		&runID,
		"user",
		actorID,
		nil,
		nil,
		metadata,
	); err != nil {
		s.logger.Error("Failed to audit payroll run export",
			zap.String("run_id", runID.String()),
			zap.Error(err))
	}

	return buf.Bytes(), nil
}

// derefInt safely dereferences an int pointer.
func derefInt(v *int) int {
	if v == nil {
		return 0
	}
	return *v
}

// getUserIDFromContext is a placeholder for extracting the current user ID from context.
// Implement this according to your auth middleware (e.g., using context values).
func getUserIDFromContext(ctx context.Context) *uuid.UUID {
	// Example: if val := ctx.Value("userID"); val != nil {
	//     if uid, ok := val.(uuid.UUID); ok {
	//         return &uid
	//     }
	// }
	return nil
}
