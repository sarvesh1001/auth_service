package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
)

// BankExportService defines the interface for generating bank transfer files.
type BankExportService interface {
	// GenerateBankFile creates a bank file for a given payroll run.
	// format: "generic", "hdfc", "icici". Returns the file content and a filename.
	GenerateBankFile(ctx context.Context, companyID, payrollRunID uuid.UUID, format string) ([]byte, string, error)
}

type bankExportService struct {
	payrollRepo repository.PayrollRepository
	bankRepo    repository.BankDetailsRepository
	logger      *zap.Logger
}

// NewBankExportService creates a new instance of BankExportService.
func NewBankExportService(
	payrollRepo repository.PayrollRepository,
	bankRepo repository.BankDetailsRepository,
	logger *zap.Logger,
) BankExportService {
	return &bankExportService{
		payrollRepo: payrollRepo,
		bankRepo:    bankRepo,
		logger:      logger.Named("bank_export_service"),
	}
}

// GenerateBankFile implements BankExportService.
func (s *bankExportService) GenerateBankFile(ctx context.Context, companyID, payrollRunID uuid.UUID, format string) ([]byte, string, error) {
	// 1. Validate format
	if format != "generic" && format != "hdfc" && format != "icici" {
		return nil, "", fmt.Errorf("unsupported bank file format: %s", format)
	}

	// 2. Fetch payroll run and verify it's approved and belongs to the company.
	run, err := s.payrollRepo.GetPayrollRunByID(ctx, payrollRunID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get payroll run: %w", err)
	}
	if run == nil {
		return nil, "", fmt.Errorf("payroll run not found")
	}
	if run.CompanyID != companyID {
		return nil, "", fmt.Errorf("payroll run does not belong to this company")
	}
	if run.Status != models.PayrollStatusApproved {
		return nil, "", fmt.Errorf("payroll run must be approved to generate bank file, current status: %s", run.Status)
	}

	// 3. Fetch all active payroll items for the run.
	items, err := s.payrollRepo.GetPayrollItemsByRun(ctx, payrollRunID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get payroll items: %w", err)
	}
	if len(items) == 0 {
		return nil, "", fmt.Errorf("no payroll items found for this run")
	}

	// 4. Collect user IDs.
	userIDs := make([]uuid.UUID, len(items))
	for i, item := range items {
		userIDs[i] = item.UserID
	}

	// 5. Fetch active bank details for these users as of the run period end.
	bankMap, err := s.bankRepo.GetBankDetailsForPayrollRun(ctx, companyID, userIDs)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get bank details: %w", err)
	}

	// 6. Build rows, skipping employees without bank details.
	var rows [][]string
	for _, item := range items {
		bank, ok := bankMap[item.UserID]
		if !ok {
			s.logger.Warn("No active bank details found for employee, skipping",
				zap.String("user_id", item.UserID.String()),
				zap.String("payroll_run_id", payrollRunID.String()))
			continue
		}
		row, err := s.buildRow(format, bank, item.NetAmount)
		if err != nil {
			return nil, "", fmt.Errorf("failed to build row for user %s: %w", item.UserID, err)
		}
		rows = append(rows, row)
	}

	if len(rows) == 0 {
		return nil, "", fmt.Errorf("no employees with valid bank details found")
	}

	// 7. Generate the file content and filename.
	content, filename, err := s.generateFile(format, rows, run)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate file: %w", err)
	}

	s.logger.Info("Bank file generated successfully",
		zap.String("payroll_run_id", payrollRunID.String()),
		zap.String("format", format),
		zap.Int("employee_count", len(rows)),
	)

	return content, filename, nil
}

// buildRow returns the fields for one line in the bank file, depending on the format.
func (s *bankExportService) buildRow(format string, bank models.EmployeeBankDetails, amount float64) ([]string, error) {
	// All formats: we need account number, IFSC, amount, account holder, and a remark.
	// The order and header may differ.
	amountStr := fmt.Sprintf("%.2f", amount)

	switch format {
	case "generic":
		return []string{
			bank.AccountNumber,
			bank.IFSCCode,
			amountStr,
			bank.AccountHolder,
			"", // optional reference (could be employee ID, left blank)
		}, nil
	case "hdfc":
		// HDFC salary upload format typically: Employee Name, Account Number, IFSC Code, Amount, Remarks
		return []string{
			bank.AccountHolder,
			bank.AccountNumber,
			bank.IFSCCode,
			amountStr,
			"Salary",
		}, nil
	case "icici":
		// ICICI format often: Beneficiary Name, Account No, IFSC Code, Transfer Amount, Remarks
		return []string{
			bank.AccountHolder,
			bank.AccountNumber,
			bank.IFSCCode,
			amountStr,
			"Salary Payment",
		}, nil
	default:
		return nil, fmt.Errorf("unsupported format in buildRow: %s", format)
	}
}

// generateFile assembles the final CSV content and the filename.
func (s *bankExportService) generateFile(format string, rows [][]string, run *models.PayrollRun) ([]byte, string, error) {
	var sb strings.Builder

	// Add header if the format expects one.
	if header := s.getCSVHeader(format); header != nil {
		sb.WriteString(joinCSVRow(header))
		sb.WriteByte('\n')
	}

	// Write each data row.
	for _, row := range rows {
		sb.WriteString(joinCSVRow(row))
		sb.WriteByte('\n')
	}

	// Build filename: salary_YYYYMMDD_runIDshort_format.csv
	filename := fmt.Sprintf("salary_%s_%s_%s.csv",
		run.PeriodEnd.Format("20060102"),
		run.PayrollRunID.String()[:8],
		format,
	)

	return []byte(sb.String()), filename, nil
}

// getCSVHeader returns the column headers for the given format, or nil if none.
func (s *bankExportService) getCSVHeader(format string) []string {
	switch format {
	case "generic":
		return []string{"AccountNumber", "IFSCCode", "Amount", "AccountHolder", "Reference"}
	case "hdfc":
		return []string{"Employee Name", "Account Number", "IFSC Code", "Amount", "Remarks"}
	case "icici":
		return []string{"Beneficiary Name", "Account No", "IFSC Code", "Transfer Amount", "Remarks"}
	default:
		return nil
	}
}

// joinCSVRow quotes each field and joins them with commas.
// (For production, consider using a proper CSV writer to handle escaping.)
func joinCSVRow(fields []string) string {
	var quoted []string
	for _, f := range fields {
		// Simple quoting; assumes fields do not contain quotes themselves.
		quoted = append(quoted, `"`+f+`"`)
	}
	return strings.Join(quoted, ",")
}
