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

// PayrollQueryService defines the interface for payroll query operations.

type payrollQueryService struct {
	payrollRepo  repository.PayrollRepository
	bankRepo     repository.BankDetailsRepository
	payslipRepo  repository.PayslipRepository
	pdfGenerator PDFGenerator // interface for PDF generation (could be injected)
	audit        *a.AuditService
	logger       *zap.Logger
}

// PDFGenerator abstracts the PDF creation logic (to be implemented separately).
type PDFGenerator interface {
	GeneratePayslipPDF(payslip *models.Payslip) ([]byte, error)
}

// NewPayrollQueryService creates a new payroll query service with all required repositories.
func NewPayrollQueryService(
	payrollRepo repository.PayrollRepository,
	bankRepo repository.BankDetailsRepository,
	payslipRepo repository.PayslipRepository,
	pdfGen PDFGenerator,
	audit *a.AuditService,
	logger *zap.Logger,
) PayrollQueryService {
	return &payrollQueryService{
		payrollRepo:  payrollRepo,
		bankRepo:     bankRepo,
		payslipRepo:  payslipRepo,
		pdfGenerator: pdfGen,
		audit:        audit,
		logger:       logger.Named("payroll_query_service"),
	}
}

// ---------------------------------------------------------------------
// Existing methods (unchanged, but some may be enhanced)
// ---------------------------------------------------------------------

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

func (s *payrollQueryService) ListRuns(ctx context.Context, filter models.PayrollRunFilter) ([]*models.PayrollRun, int64, error) {
	return s.payrollRepo.GetPayrollRuns(ctx, filter)
}

func (s *payrollQueryService) GetRunLedgerSummary(ctx context.Context, companyID, runID uuid.UUID) ([]*models.LedgerSummary, error) {
	run, err := s.payrollRepo.GetPayrollRunByID(ctx, runID)
	if err != nil || run == nil || run.CompanyID != companyID {
		return nil, fmt.Errorf("run not found or access denied")
	}
	return s.payrollRepo.GetLedgerSummaryByRun(ctx, runID)
}

func (s *payrollQueryService) GetRunExecutionStatus(
	ctx context.Context,
	companyID,
	runID uuid.UUID,
) (*models.PayrollExecutionStatus, error) {

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

	// Audit
	actorID := getUserIDFromContext(ctx)
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
	_ = s.audit.LogAction(ctx, &companyID, "payroll", "payroll_detail_viewed", "payroll_item", &payrollItemID, "user", actorID, nil, nil, metadata)

	return detail, nil
}

func (s *payrollQueryService) ListEmployeesInRun(ctx context.Context, companyID, runID uuid.UUID) ([]*models.PayrollItem, error) {
	run, err := s.payrollRepo.GetPayrollRunByID(ctx, runID)
	if err != nil || run == nil || run.CompanyID != companyID {
		return nil, fmt.Errorf("run not found")
	}
	return s.payrollRepo.GetPayrollItemsByRun(ctx, runID)
}

func (s *payrollQueryService) GetEmployeePayrollHistory(ctx context.Context, companyID, userID uuid.UUID, from, to time.Time) ([]*models.PayrollItemDetail, error) {
	return s.payrollRepo.GetEmployeePayrollHistory(ctx, companyID, userID, from, to)
}

func (s *payrollQueryService) GetEmployeeYTD(ctx context.Context, companyID, userID uuid.UUID, financialYearStart time.Time) (*models.EmployeeYTDSummary, error) {
	return s.payrollRepo.GetEmployeeYTDSummary(ctx, companyID, userID, financialYearStart, time.Now())
}

func (s *payrollQueryService) GetEmployeeStatutorySummary(ctx context.Context, companyID, userID uuid.UUID, financialYearStart time.Time) (*models.EmployeeStatutorySummary, error) {
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
	return s.payrollRepo.GetRunStatutorySummary(ctx, runID)
}

func (s *payrollQueryService) GetCompanyPayrollTrend(ctx context.Context, companyID uuid.UUID, from, to time.Time) ([]*models.PayrollTrendPoint, error) {
	return s.payrollRepo.GetPayrollTrend(ctx, companyID, from, to)
}

func (s *payrollQueryService) GetComponentBreakdownTrend(ctx context.Context, companyID uuid.UUID, componentCode string, from, to time.Time) ([]*models.ComponentTrendPoint, error) {
	return s.payrollRepo.GetComponentTrend(ctx, companyID, componentCode, from, to)
}

// GetEmployeePayslip returns a data structure representation of a payslip.
// This method is kept for backward compatibility and as a data source for PDF generation.
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

// ExportRunToCSV exports basic payroll item data as CSV.
func (s *payrollQueryService) ExportRunToCSV(ctx context.Context, companyID, runID uuid.UUID) ([]byte, error) {
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
	// Audit
	actorID := getUserIDFromContext(ctx)
	metadata := map[string]interface{}{
		"period_start": run.PeriodStart,
		"period_end":   run.PeriodEnd,
		"status":       run.Status,
		"record_count": len(items),
	}
	_ = s.audit.LogAction(ctx, &companyID, "payroll", "payroll_run_export", "payroll_run", &runID, "user", actorID, nil, nil, metadata)
	return buf.Bytes(), nil
}

// ---------------------------------------------------------------------
// New methods for missing features
// ---------------------------------------------------------------------

// ExportBankFile generates a bank upload file (CSV) for a payroll run.
// bankFormat can be "hdfc", "icici", etc. (adjust as needed).
func (s *payrollQueryService) ExportBankFile(ctx context.Context, companyID, runID uuid.UUID, bankFormat string) ([]byte, error) {
	// 1. Verify run exists and is approved/paid.
	run, err := s.payrollRepo.GetPayrollRunByID(ctx, runID)
	if err != nil || run == nil || run.CompanyID != companyID {
		return nil, fmt.Errorf("run not found")
	}
	if run.Status != models.PayrollStatusApproved && run.Status != models.PayrollStatusPaid {
		return nil, fmt.Errorf("run must be approved or paid to export bank file")
	}

	// 2. Get all payroll items for the run.
	items, err := s.payrollRepo.GetPayrollItemsByRun(ctx, runID)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("no payroll items found for this run")
	}

	// 3. Collect user IDs.
	userIDs := make([]uuid.UUID, len(items))
	for i, item := range items {
		userIDs[i] = item.UserID
	}

	// 4. Fetch active bank details for all employees.
	bankMap, err := s.bankRepo.GetBankDetailsForPayrollRun(ctx, companyID, userIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch bank details: %w", err)
	}

	// 5. Build CSV according to format.
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write header based on format (simplified example; adapt to actual bank specs)
	switch bankFormat {
	case "hdfc", "icici", "sbi":
		_ = writer.Write([]string{"EmployeeID", "AccountNumber", "IFSC", "Amount", "Narration"})
	default:
		_ = writer.Write([]string{"UserID", "AccountNumber", "IFSC", "Amount"})
	}

	for _, item := range items {
		bank, ok := bankMap[item.UserID]
		if !ok {
			s.logger.Warn("No active bank details for user", zap.String("user_id", item.UserID.String()))
			continue // skip this employee (or you could return an error)
		}
		// Amount should be net amount (or gross depending on policy)
		amount := item.NetAmount
		// For HDFC/ICICI, you might need to format amount without decimals, etc.
		switch bankFormat {
		case "hdfc":
			// Example: Employee ID, Account Number, IFSC, Amount (as integer paise), Narration
			_ = writer.Write([]string{
				"", // employee code if available
				bank.AccountNumber,
				bank.IFSCCode,
				fmt.Sprintf("%.0f", amount*100), // amount in paise
				fmt.Sprintf("Salary %s", run.PeriodStart.Format("Jan 2006")),
			})
		case "icici":
			// Similar
			_ = writer.Write([]string{
				bank.AccountNumber,
				bank.IFSCCode,
				fmt.Sprintf("%.2f", amount),
				fmt.Sprintf("Salary %s", run.PeriodStart.Format("Jan 2006")),
			})
		default:
			_ = writer.Write([]string{
				item.UserID.String(),
				bank.AccountNumber,
				bank.IFSCCode,
				fmt.Sprintf("%.2f", amount),
				"",
			})
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}

	// Audit
	actorID := getUserIDFromContext(ctx)
	metadata := map[string]interface{}{
		"run_id":    runID.String(),
		"format":    bankFormat,
		"employees": len(items),
	}
	_ = s.audit.LogAction(ctx, &companyID, "payroll", "bank_file_export", "payroll_run", &runID, "user", actorID, nil, nil, metadata)

	return buf.Bytes(), nil
}

// GenerateAndStorePayslip creates a PDF payslip for a payroll item, stores it, and returns the S3 key.
func (s *payrollQueryService) GenerateAndStorePayslip(ctx context.Context, companyID, payrollItemID uuid.UUID) (string, error) {
	// 1. Get payslip data.
	payslipData, err := s.GetEmployeePayslip(ctx, companyID, payrollItemID)
	if err != nil {
		return "", err
	}

	// 2. Generate PDF using the injected generator.
	_, err = s.pdfGenerator.GeneratePayslipPDF(payslipData)
	if err != nil {
		return "", fmt.Errorf("failed to generate PDF: %w", err)
	}

	// 3. Store PDF (this example uses a dummy object key; you would upload to S3/minio).
	objectKey := fmt.Sprintf("payslips/%s/%s/%s.pdf",
		companyID.String(),
		payslipData.PeriodStart.Format("2006-01"),
		payslipData.UserID.String(),
	)
	// TODO: Actually upload pdfBytes to object storage.

	// 4. Save record in database.
	record := &models.PayslipRecord{
		PayslipID:    payslipData.PayslipID,
		PayrollRunID: payslipData.PayrollRunID,
		UserID:       payslipData.UserID,
		PDFObjectKey: objectKey,
		GeneratedAt:  payslipData.GeneratedAt,
	}
	if err := s.payslipRepo.Create(ctx, record); err != nil {
		return "", fmt.Errorf("failed to save payslip record: %w", err)
	}

	// 5. Audit
	actorID := getUserIDFromContext(ctx)
	metadata := map[string]interface{}{
		"payroll_run_id": payslipData.PayrollRunID.String(),
		"user_id":        payslipData.UserID.String(),
		"object_key":     objectKey,
	}
	_ = s.audit.LogAction(ctx, &companyID, "payroll", "payslip_generated", "payslip", &record.PayslipID, "user", actorID, nil, nil, metadata)

	return objectKey, nil
}

// GetMyPayslips returns all payslip records for the authenticated user in a date range.
func (s *payrollQueryService) GetMyPayslips(ctx context.Context, userID uuid.UUID, from, to time.Time) ([]models.PayslipRecord, error) {
	// In a real implementation, you would derive companyID from the user's context.
	// For simplicity, we assume the caller (handler) passes companyID separately.
	// This method is intended to be called with the authenticated user's ID.
	// You may need to modify the signature to include companyID.
	// We'll keep it as is and assume the handler provides it via a wrapper.
	// Alternatively, fetch companyID from user profile.
	return nil, fmt.Errorf("not implemented: requires companyID or user context")
}

// DownloadPayslip retrieves the PDF content for a given payslip ID.
func (s *payrollQueryService) DownloadPayslip(ctx context.Context, payslipID uuid.UUID) ([]byte, error) {
	// 1. Fetch payslip record.
	// Note: The repository currently doesn't have a GetByID method; you may need to add one.
	// For now, we'll use a placeholder.
	// record, err := s.payslipRepo.GetByID(ctx, payslipID)
	// if err != nil { return nil, err }
	// if record == nil { return nil, fmt.Errorf("payslip not found") }

	// 2. Retrieve from object storage.
	// data, err := s.objectStorage.Get(record.PDFObjectKey)
	// if err != nil { return nil, err }

	// 3. Audit access.
	// actorID := getUserIDFromContext(ctx)
	// _ = s.audit.LogAction(...)

	return nil, fmt.Errorf("DownloadPayslip not fully implemented")
}

// ---------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------

func derefInt(v *int) int {
	if v == nil {
		return 0
	}
	return *v
}

// getUserIDFromContext extracts the current user ID from context.
// Implement according to your auth middleware.
func getUserIDFromContext(ctx context.Context) *uuid.UUID {
	// Example: if uid, ok := ctx.Value("userID").(uuid.UUID); ok { return &uid }
	return nil
}
