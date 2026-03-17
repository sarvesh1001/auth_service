package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
)

type BankExportService interface {
	ActivateBankDetails(ctx context.Context, bankDetailID uuid.UUID, actorID uuid.UUID) error
	// -------- BANK MANAGEMENT --------
	CreateBankDetails(ctx context.Context, bank *models.EmployeeBankDetails) error
	UpdateBankDetails(ctx context.Context, bank *models.EmployeeBankDetails) error
	DeactivateBankDetails(ctx context.Context, bankDetailID uuid.UUID, actorID uuid.UUID) error
	GetActiveBankDetails(ctx context.Context, companyID, userID uuid.UUID, asOf time.Time) (*models.EmployeeBankDetails, error)
	ListUserBankDetails(ctx context.Context, companyID, userID uuid.UUID) ([]models.EmployeeBankDetails, error)

	// -------- BANK EXPORT --------
	GenerateBankFile(ctx context.Context, companyID, payrollRunID uuid.UUID, format string) ([]byte, string, error)
}

type bankExportService struct {
	payrollRepo repository.PayrollRepository
	bankRepo    repository.BankDetailsRepository
	logger      *zap.Logger
}

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

////////////////////////////////////////////////////////////////////
//////////////////// BANK MANAGEMENT METHODS ///////////////////////
////////////////////////////////////////////////////////////////////

func (s *bankExportService) CreateBankDetails(ctx context.Context, bank *models.EmployeeBankDetails) error {

	if bank.CompanyID == uuid.Nil || bank.UserID == uuid.Nil {
		return fmt.Errorf("company_id and user_id are required")
	}

	if bank.AccountNumber == "" || bank.IFSCCode == "" {
		return fmt.Errorf("account number and IFSC code are required")
	}

	if bank.EffectiveFrom.IsZero() {
		bank.EffectiveFrom = time.Now().UTC()
	}

	if err := s.bankRepo.Create(ctx, bank); err != nil {
		return fmt.Errorf("create bank details: %w", err)
	}

	s.logger.Info("bank details created",
		zap.String("user_id", bank.UserID.String()),
		zap.String("bank_detail_id", bank.BankDetailID.String()),
	)

	return nil
}

func (s *bankExportService) UpdateBankDetails(ctx context.Context, bank *models.EmployeeBankDetails) error {

	if bank.BankDetailID == uuid.Nil {
		return fmt.Errorf("bank_detail_id is required")
	}

	err := s.bankRepo.Update(ctx, bank)
	if err != nil {
		return fmt.Errorf("update bank details: %w", err)
	}

	s.logger.Info("bank details updated",
		zap.String("bank_detail_id", bank.BankDetailID.String()),
	)

	return nil
}

func (s *bankExportService) DeactivateBankDetails(
	ctx context.Context,
	bankDetailID uuid.UUID,
	actorID uuid.UUID,
) error {

	if bankDetailID == uuid.Nil {
		return fmt.Errorf("bank_detail_id is required")
	}

	err := s.bankRepo.Deactivate(ctx, bankDetailID, actorID)
	if err != nil {
		return fmt.Errorf("deactivate bank details: %w", err)
	}

	s.logger.Info("bank details deactivated",
		zap.String("bank_detail_id", bankDetailID.String()),
		zap.String("actor_id", actorID.String()),
	)

	return nil
}

func (s *bankExportService) GetActiveBankDetails(
	ctx context.Context,
	companyID,
	userID uuid.UUID,
	asOf time.Time,
) (*models.EmployeeBankDetails, error) {

	bank, err := s.bankRepo.GetActiveByUser(ctx, companyID, userID, asOf)
	if err != nil {
		return nil, fmt.Errorf("get active bank details: %w", err)
	}

	return bank, nil
}

func (s *bankExportService) ListUserBankDetails(
	ctx context.Context,
	companyID,
	userID uuid.UUID,
) ([]models.EmployeeBankDetails, error) {

	list, err := s.bankRepo.ListByUser(ctx, companyID, userID)
	if err != nil {
		return nil, fmt.Errorf("list bank details: %w", err)
	}

	return list, nil
}

////////////////////////////////////////////////////////////////////
//////////////////// BANK EXPORT LOGIC /////////////////////////////
////////////////////////////////////////////////////////////////////

func (s *bankExportService) GenerateBankFile(
	ctx context.Context,
	companyID,
	payrollRunID uuid.UUID,
	format string,
) ([]byte, string, error) {

	if format != "generic" && format != "hdfc" && format != "icici" {
		return nil, "", fmt.Errorf("unsupported bank file format: %s", format)
	}

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
		return nil, "", fmt.Errorf("payroll run must be approved to generate bank file")
	}

	items, err := s.payrollRepo.GetPayrollItemsByRun(ctx, payrollRunID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get payroll items: %w", err)
	}

	if len(items) == 0 {
		return nil, "", fmt.Errorf("no payroll items found")
	}

	userIDs := make([]uuid.UUID, len(items))
	for i, item := range items {
		userIDs[i] = item.UserID
	}

	bankMap, err := s.bankRepo.GetBankDetailsForPayrollRun(ctx, companyID, userIDs)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get bank details: %w", err)
	}

	var rows [][]string

	for _, item := range items {

		bank, ok := bankMap[item.UserID]
		if !ok {
			s.logger.Warn("missing bank details",
				zap.String("user_id", item.UserID.String()),
			)
			continue
		}

		row, err := s.buildRow(format, bank, item.NetAmount)
		if err != nil {
			return nil, "", err
		}

		rows = append(rows, row)
	}

	if len(rows) == 0 {
		return nil, "", fmt.Errorf("no employees with valid bank details")
	}

	content, filename, err := s.generateFile(format, rows, run)
	if err != nil {
		return nil, "", err
	}

	return content, filename, nil
}

////////////////////////////////////////////////////////////////////
//////////////////// FILE GENERATION ///////////////////////////////
////////////////////////////////////////////////////////////////////

func (s *bankExportService) buildRow(format string, bank models.EmployeeBankDetails, amount float64) ([]string, error) {

	amountStr := fmt.Sprintf("%.2f", amount)

	switch format {

	case "generic":
		return []string{
			bank.AccountNumber,
			bank.IFSCCode,
			amountStr,
			bank.AccountHolder,
			"",
		}, nil

	case "hdfc":
		return []string{
			bank.AccountHolder,
			bank.AccountNumber,
			bank.IFSCCode,
			amountStr,
			"Salary",
		}, nil

	case "icici":
		return []string{
			bank.AccountHolder,
			bank.AccountNumber,
			bank.IFSCCode,
			amountStr,
			"Salary Payment",
		}, nil
	}

	return nil, fmt.Errorf("unsupported format")
}

func (s *bankExportService) generateFile(
	format string,
	rows [][]string,
	run *models.PayrollRun,
) ([]byte, string, error) {

	var sb strings.Builder

	if header := s.getCSVHeader(format); header != nil {
		sb.WriteString(joinCSVRow(header))
		sb.WriteByte('\n')
	}

	for _, row := range rows {
		sb.WriteString(joinCSVRow(row))
		sb.WriteByte('\n')
	}

	filename := fmt.Sprintf(
		"salary_%s_%s_%s.csv",
		run.PeriodEnd.Format("20060102"),
		run.PayrollRunID.String()[:8],
		format,
	)

	return []byte(sb.String()), filename, nil
}

func (s *bankExportService) getCSVHeader(format string) []string {

	switch format {

	case "generic":
		return []string{"AccountNumber", "IFSCCode", "Amount", "AccountHolder", "Reference"}

	case "hdfc":
		return []string{"Employee Name", "Account Number", "IFSC Code", "Amount", "Remarks"}

	case "icici":
		return []string{"Beneficiary Name", "Account No", "IFSC Code", "Transfer Amount", "Remarks"}
	}

	return nil
}

func joinCSVRow(fields []string) string {

	var quoted []string

	for _, f := range fields {
		quoted = append(quoted, `"`+f+`"`)
	}

	return strings.Join(quoted, ",")
}

func (s *bankExportService) ActivateBankDetails(
	ctx context.Context,
	bankDetailID uuid.UUID,
	actorID uuid.UUID,
) error {

	if bankDetailID == uuid.Nil {
		return fmt.Errorf("bank_detail_id is required")
	}

	err := s.bankRepo.Activate(ctx, bankDetailID, actorID)
	if err != nil {
		return fmt.Errorf("activate bank details: %w", err)
	}

	s.logger.Info("bank details activated",
		zap.String("bank_detail_id", bankDetailID.String()),
		zap.String("actor_id", actorID.String()),
	)

	return nil
}
