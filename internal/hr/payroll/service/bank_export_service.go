package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	hrRepo "auth-service/internal/hr/repository"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/locationctx"
)

type BankExportService interface {
	ActivateBankDetails(ctx context.Context, bankDetailID uuid.UUID, actorID uuid.UUID) error
	CreateBankDetails(ctx context.Context, bank *models.EmployeeBankDetails) error
	UpdateBankDetails(ctx context.Context, bank *models.EmployeeBankDetails) error
	DeactivateBankDetails(ctx context.Context, bankDetailID uuid.UUID, actorID uuid.UUID) error
	GetActiveBankDetails(ctx context.Context, companyID, userID uuid.UUID, asOf time.Time) (*models.EmployeeBankDetails, error)
	ListUserBankDetails(ctx context.Context, companyID, userID uuid.UUID) ([]models.EmployeeBankDetails, error)
	GenerateBankFile(ctx context.Context, companyID, payrollRunID uuid.UUID, format string) ([]byte, string, error)
}

type bankExportService struct {
	payrollRepo      repository.PayrollRepository
	bankRepo         repository.BankDetailsRepository
	employeeRepo     hrRepo.EmployeeRepository // 👈 new — for location lookup
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
}

func NewBankExportService(
	payrollRepo repository.PayrollRepository,
	bankRepo repository.BankDetailsRepository,
	employeeRepo hrRepo.EmployeeRepository, // 👈 new
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
) BankExportService {
	return &bankExportService{
		payrollRepo:      payrollRepo,
		bankRepo:         bankRepo,
		employeeRepo:     employeeRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
	}
}

// ensureEmployeeInScope verifies the target employee is within the caller's
// current location scope.
//
// Rules:
//   - Self-action (actor == target)  → always allowed
//   - No location context            → allowed (system call: worker, cron)
//   - ScopeAll                       → allowed
//   - ScopeLocation                  → target.employment_location_id must match
//   - Otherwise                      → ErrEmployeeOutsideScope / ErrEmployeeHasNoLocation
func (s *bankExportService) ensureEmployeeInScope(
	ctx context.Context,
	companyID, targetUserID uuid.UUID,
) error {
	// Self-action shortcut
	if actorStr, ok := ctx.Value("user_id").(string); ok {
		if actorID, err := uuid.Parse(actorStr); err == nil && actorID == targetUserID {
			return nil
		}
	}

	locCtx, err := locationctx.FromContext(ctx)
	if err != nil {
		// No location context → system call, allow.
		return nil
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

// CreateBankDetails – with idempotency, location scope, and audit
func (s *bankExportService) CreateBankDetails(ctx context.Context, bank *models.EmployeeBankDetails) error {
	if bank.CompanyID == uuid.Nil || bank.UserID == uuid.Nil {
		return fmt.Errorf("company_id and user_id are required")
	}

	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, bank.CompanyID, bank.UserID); err != nil {
		return err
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("bank_create-%s-%s", bank.UserID.String(), bank.AccountNumber)
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	if bank.AccountNumber == "" || bank.IFSCCode == "" {
		return fmt.Errorf("account number and IFSC code are required")
	}
	if bank.EffectiveFrom.IsZero() {
		bank.EffectiveFrom = time.Now().UTC()
	}
	if bank.BankDetailID == uuid.Nil {
		bank.BankDetailID = uuid.New()
	}

	beforeJSON, _ := json.Marshal(bank)
	if err := s.bankRepo.Create(ctx, bank); err != nil {
		return fmt.Errorf("create bank details: %w", err)
	}
	afterJSON, _ := json.Marshal(bank)

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&bank.CompanyID,
		"payroll",
		"bank_details.create",
		"employee_bank_details",
		&bank.BankDetailID,
		"user",
		&bank.UserID,
		beforeJSON,
		afterJSON,
		map[string]interface{}{
			"ip":      ip,
			"user_id": bank.UserID.String(),
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// UpdateBankDetails – with idempotency, location scope, and audit
func (s *bankExportService) UpdateBankDetails(ctx context.Context, bank *models.EmployeeBankDetails) error {
	if bank.BankDetailID == uuid.Nil {
		return fmt.Errorf("bank_detail_id is required")
	}

	// Load existing to know the target employee
	existing, err := s.bankRepo.GetByID(ctx, bank.BankDetailID)
	if err != nil {
		return fmt.Errorf("failed to get existing bank details: %w", err)
	}

	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, existing.CompanyID, existing.UserID); err != nil {
		return err
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("bank_update-%s", bank.BankDetailID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	beforeJSON, _ := json.Marshal(existing)
	if err := s.bankRepo.Update(ctx, bank); err != nil {
		return fmt.Errorf("update bank details: %w", err)
	}
	afterJSON, _ := json.Marshal(bank)

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&bank.CompanyID,
		"payroll",
		"bank_details.update",
		"employee_bank_details",
		&bank.BankDetailID,
		"user",
		nil,
		beforeJSON,
		afterJSON,
		map[string]interface{}{"ip": ip},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// DeactivateBankDetails – with idempotency + location scope
func (s *bankExportService) DeactivateBankDetails(ctx context.Context, bankDetailID uuid.UUID, actorID uuid.UUID) error {
	if bankDetailID == uuid.Nil {
		return fmt.Errorf("bank_detail_id is required")
	}

	existing, err := s.bankRepo.GetByID(ctx, bankDetailID)
	if err != nil {
		return fmt.Errorf("failed to get bank details: %w", err)
	}

	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, existing.CompanyID, existing.UserID); err != nil {
		return err
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("bank_deactivate-%s", bankDetailID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	beforeJSON, _ := json.Marshal(existing)
	if err := s.bankRepo.Deactivate(ctx, bankDetailID, actorID); err != nil {
		return fmt.Errorf("deactivate bank details: %w", err)
	}
	afterJSON, _ := json.Marshal(existing)

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&existing.CompanyID,
		"payroll",
		"bank_details.deactivate",
		"employee_bank_details",
		&bankDetailID,
		"user",
		&actorID,
		beforeJSON,
		afterJSON,
		map[string]interface{}{"ip": ip},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// ActivateBankDetails – with idempotency + location scope
func (s *bankExportService) ActivateBankDetails(ctx context.Context, bankDetailID uuid.UUID, actorID uuid.UUID) error {
	if bankDetailID == uuid.Nil {
		return fmt.Errorf("bank_detail_id is required")
	}

	existing, err := s.bankRepo.GetByID(ctx, bankDetailID)
	if err != nil {
		return fmt.Errorf("failed to get bank details: %w", err)
	}

	// 👇 Location scope check
	if err := s.ensureEmployeeInScope(ctx, existing.CompanyID, existing.UserID); err != nil {
		return err
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("bank_activate-%s", bankDetailID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	beforeJSON, _ := json.Marshal(existing)
	if err := s.bankRepo.Activate(ctx, bankDetailID, actorID); err != nil {
		return fmt.Errorf("activate bank details: %w", err)
	}
	afterJSON, _ := json.Marshal(existing)

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&existing.CompanyID,
		"payroll",
		"bank_details.activate",
		"employee_bank_details",
		&bankDetailID,
		"user",
		&actorID,
		beforeJSON,
		afterJSON,
		map[string]interface{}{"ip": ip},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// Read methods – single-employee scoped; no location filter needed
func (s *bankExportService) GetActiveBankDetails(ctx context.Context, companyID, userID uuid.UUID, asOf time.Time) (*models.EmployeeBankDetails, error) {
	return s.bankRepo.GetActiveByUser(ctx, companyID, userID, asOf)
}

func (s *bankExportService) ListUserBankDetails(ctx context.Context, companyID, userID uuid.UUID) ([]models.EmployeeBankDetails, error) {
	return s.bankRepo.ListByUser(ctx, companyID, userID)
}

// GenerateBankFile – company-wide artifact; requires ALL scope.
//
// A bank file is one CSV for the entire company's salary transfer. Generating
// it under a location-scoped request would produce an incomplete file. We
// therefore require the caller to hold company-wide scope.
func (s *bankExportService) GenerateBankFile(ctx context.Context, companyID, payrollRunID uuid.UUID, format string) ([]byte, string, error) {
	if format != "generic" && format != "hdfc" && format != "icici" {
		return nil, "", fmt.Errorf("unsupported bank file format: %s", format)
	}

	// 👇 Bank file is a company-wide artifact
	locCtx, err := locationctx.FromContext(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("location context missing: %w", err)
	}
	if locCtx.Mode != locationctx.ScopeAll {
		return nil, "", ErrCompanyWideScopeRequired
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

	// Pass nil for location: bank file contains all employees.
	items, err := s.payrollRepo.GetPayrollItemsByRun(ctx, payrollRunID, nil)
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

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&companyID,
		"payroll",
		"bank_file.export",
		"payroll_run",
		&payrollRunID,
		"system",
		nil,
		nil,
		nil,
		map[string]interface{}{
			"ip":         ip,
			"format":     format,
			"total_rows": len(rows),
		},
	)

	return content, filename, nil
}

// ----- helpers (unchanged) -----

func (s *bankExportService) buildRow(format string, bank models.EmployeeBankDetails, amount float64) ([]string, error) {
	amountStr := fmt.Sprintf("%.2f", amount)
	switch format {
	case "generic":
		return []string{bank.AccountNumber, bank.IFSCCode, amountStr, bank.AccountHolder, ""}, nil
	case "hdfc":
		return []string{bank.AccountHolder, bank.AccountNumber, bank.IFSCCode, amountStr, "Salary"}, nil
	case "icici":
		return []string{bank.AccountHolder, bank.AccountNumber, bank.IFSCCode, amountStr, "Salary Payment"}, nil
	}
	return nil, fmt.Errorf("unsupported format")
}

func (s *bankExportService) generateFile(format string, rows [][]string, run *models.PayrollRun) ([]byte, string, error) {
	var sb strings.Builder
	if header := s.getCSVHeader(format); header != nil {
		sb.WriteString(joinCSVRow(header))
		sb.WriteByte('\n')
	}
	for _, row := range rows {
		sb.WriteString(joinCSVRow(row))
		sb.WriteByte('\n')
	}
	filename := fmt.Sprintf("salary_%s_%s_%s.csv", run.PeriodEnd.Format("20060102"), run.PayrollRunID.String()[:8], format)
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
