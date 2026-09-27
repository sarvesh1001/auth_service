package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	hrRepo "auth-service/internal/hr/repository"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/locationctx"
)

// ---------------------------------------------------------------------
// LoanService interface
// ---------------------------------------------------------------------
type LoanService interface {
	CreateLoan(ctx context.Context, loan *models.EmployeeLoan, maxCTCPercent float64) (*models.EmployeeLoan, error)
	GetLoan(ctx context.Context, loanID uuid.UUID) (*models.EmployeeLoan, error)
	ListUserLoans(ctx context.Context, companyID, userID uuid.UUID, includeClosed bool) ([]models.EmployeeLoan, error)
	GetPendingEMIsForLoan(ctx context.Context, loanID uuid.UUID) ([]models.EmiTransaction, error)
	GetPendingEMIsForPayrollRun(ctx context.Context, payrollRunID uuid.UUID) ([]models.EmiTransaction, error)
	MarkEMIAsPaid(ctx context.Context, emiID uuid.UUID, paidDate time.Time, payrollRunID *uuid.UUID) error
	CloseLoan(ctx context.Context, loanID uuid.UUID, closureDate time.Time) error
	RecordManualPayment(ctx context.Context, loanID uuid.UUID, amount float64, penalty float64, paidAt time.Time, actorID uuid.UUID) error
	ListLoanPayments(ctx context.Context, loanID uuid.UUID) ([]models.LoanPayment, error)
	ListLoanPaymentsByPayrollRun(ctx context.Context, payrollRunID uuid.UUID) ([]models.LoanPayment, error)
	CalculateEMI(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, principal float64, totalEmis int, maxCTCPercent float64, interestRate *float64, interestType *string) (*EMICalculationResult, error)
}

// EMICalculationResult
type EMICalculationResult struct {
	Principal      float64 `json:"principal"`
	InterestRate   float64 `json:"interest_rate"`
	InterestType   string  `json:"interest_type"`
	TotalInterest  float64 `json:"total_interest"`
	TotalRepayment float64 `json:"total_repayment"`
	RecommendedEMI float64 `json:"recommended_emi"`
	MaxAllowedEMI  float64 `json:"max_allowed_emi"`
	SalaryCTC      float64 `json:"salary_ctc"`
	TotalMonths    int     `json:"total_months"`
	MaxCTCPercent  float64 `json:"max_ctc_percent"`
	WithinLimit    bool    `json:"within_limit"`
}

// loanService implementation
type loanService struct {
	repo             repository.LoanRepository
	componentRepo    repository.ComponentRepository
	settingsRepo     repository.CompanySettingsRepository
	compensationSvc  CompensationService
	employeeRepo     hrRepo.EmployeeRepository
	idempotencyStore idempotency.Store
	audit            *audit.AuditService
	logger           *zap.Logger
}

func NewLoanService(
	repo repository.LoanRepository,
	componentRepo repository.ComponentRepository,
	settingsRepo repository.CompanySettingsRepository,
	compensationSvc CompensationService,
	employeeRepo hrRepo.EmployeeRepository,
	idempotencyStore idempotency.Store,
	audit *audit.AuditService,
	logger *zap.Logger,
) LoanService {
	return &loanService{
		repo:             repo,
		componentRepo:    componentRepo,
		settingsRepo:     settingsRepo,
		compensationSvc:  compensationSvc,
		employeeRepo:     employeeRepo,
		idempotencyStore: idempotencyStore,
		audit:            audit,
		logger:           logger.Named("loan_service"),
	}
}

// ensureEmployeeInScope — same helper as other payroll services.
func (s *loanService) ensureEmployeeInScope(
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

// ---------------------------------------------------------------------
// Helper functions for nil pointers
// ---------------------------------------------------------------------
func getFloat(v *float64) float64 {
	if v == nil {
		return 0
	}
	return *v
}

func getString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

// ---------------------------------------------------------------------
// CalculateEMI
// ---------------------------------------------------------------------
func (s *loanService) CalculateEMI(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	principal float64,
	totalEmis int,
	maxCTCPercent float64,
	interestRate *float64,
	interestType *string,
) (*EMICalculationResult, error) {
	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}

	if principal <= 0 {
		return nil, errors.New("principal must be positive")
	}
	if totalEmis <= 0 {
		return nil, errors.New("total_emis must be positive")
	}

	salary, err := s.compensationSvc.GetCurrentSalary(ctx, companyID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch employee salary: %w", err)
	}
	if salary == nil {
		return nil, errors.New("no active salary found for employee")
	}
	ctc := salary.MonthlyCTC

	if maxCTCPercent <= 0 {
		maxCTCPercent = 20
	}
	maxAllowed := ctc * (maxCTCPercent / 100)
	months := float64(totalEmis)

	var emi float64
	var totalInterest float64
	var totalRepayment float64

	if interestRate == nil || *interestRate == 0 {
		emi = principal / months
		totalInterest = 0
		totalRepayment = principal
	} else {
		rate := *interestRate / 100
		if interestType != nil && *interestType == "flat" {
			years := months / 12
			totalInterest = principal * rate * years
			totalRepayment = principal + totalInterest
			emi = totalRepayment / months
		} else if interestType != nil && *interestType == "compound" {
			monthlyRate := rate / 12
			pow := math.Pow(1+monthlyRate, months)
			emi = principal * monthlyRate * pow / (pow - 1)
			totalRepayment = emi * months
			totalInterest = totalRepayment - principal
		} else {
			return nil, errors.New("invalid interest_type (must be 'flat' or 'compound')")
		}
	}

	emi = math.Round(emi*100) / 100
	totalInterest = math.Round(totalInterest*100) / 100
	totalRepayment = math.Round(totalRepayment*100) / 100

	result := &EMICalculationResult{
		Principal:      principal,
		InterestRate:   getFloat(interestRate),
		InterestType:   getString(interestType),
		TotalInterest:  totalInterest,
		TotalRepayment: totalRepayment,
		RecommendedEMI: emi,
		MaxAllowedEMI:  maxAllowed,
		SalaryCTC:      ctc,
		TotalMonths:    totalEmis,
		MaxCTCPercent:  maxCTCPercent,
		WithinLimit:    emi <= maxAllowed,
	}

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx, nil, &companyID, "loan", "emi_preview", "emi_calculation",
		nil, "system", nil, nil, nil,
		map[string]interface{}{
			"ip":           ip,
			"user_id":      userID.String(),
			"principal":    principal,
			"emi":          emi,
			"within_limit": emi <= maxAllowed,
		},
	)

	return result, nil
}

// ---------------------------------------------------------------------
// CreateLoan
// ---------------------------------------------------------------------
func (s *loanService) CreateLoan(
	ctx context.Context,
	loan *models.EmployeeLoan,
	maxCTCPercent float64,
) (*models.EmployeeLoan, error) {
	if err := s.ensureEmployeeInScope(ctx, loan.CompanyID, loan.UserID); err != nil {
		return nil, err
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("create_loan-%s-%s", loan.UserID.String(), uuid.New().String())
	}
	var cached *models.EmployeeLoan
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	if loan.CompanyID == uuid.Nil || loan.UserID == uuid.Nil {
		return nil, errors.New("company_id and user_id are required")
	}
	if loan.LoanType == "" {
		return nil, errors.New("loan_type is required")
	}
	if loan.PrincipalAmount <= 0 {
		return nil, errors.New("principal_amount must be positive")
	}
	if loan.TotalEmis <= 0 {
		return nil, errors.New("total_emis must be positive")
	}
	if loan.DisbursedAt.IsZero() {
		return nil, errors.New("disbursed_at is required")
	}
	if loan.FirstEmiDate.IsZero() {
		return nil, errors.New("first_emi_date is required")
	}
	if loan.FirstEmiDate.Before(loan.DisbursedAt) {
		return nil, errors.New("first_emi_date cannot be before disbursed_at")
	}

	// Resolve component: explicit code wins, else company default.
	code := loan.ComponentCode
	if code == "" {
		settings, err := s.settingsRepo.GetPayrollSettings(ctx, loan.CompanyID)
		if err != nil {
			return nil, fmt.Errorf("failed to get company payroll settings: %w", err)
		}
		if settings.DefaultLoanComponentCode == nil || *settings.DefaultLoanComponentCode == "" {
			return nil, errors.New("no loan component provided and no company default set")
		}
		code = *settings.DefaultLoanComponentCode
	}
	comp, err := s.componentRepo.GetComponent(ctx, loan.CompanyID, code)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch component %s: %w", code, err)
	}
	if comp == nil {
		return nil, fmt.Errorf("component %s not found for company", code)
	}
	if comp.ComponentType != models.ComponentTypeDeduction {
		return nil, fmt.Errorf("component %s is of type %s, but loan EMIs must be a deduction", code, comp.ComponentType)
	}
	componentID := comp.ComponentID
	loan.ComponentID = &componentID
	loan.ComponentCode = comp.ComponentCode

	if maxCTCPercent <= 0 {
		maxCTCPercent = 20
	}
	calc, err := s.CalculateEMI(
		ctx, loan.CompanyID, loan.UserID,
		loan.PrincipalAmount, loan.TotalEmis, maxCTCPercent,
		loan.InterestRate, loan.InterestType,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to validate EMI against salary: %w", err)
	}

	if loan.EmiAmount <= 0 {
		loan.EmiAmount = calc.RecommendedEMI
	}
	if loan.EmiAmount > calc.MaxAllowedEMI {
		return nil, fmt.Errorf("EMI %.2f exceeds allowed limit %.2f (%.0f%% of monthly salary %.2f)",
			loan.EmiAmount, calc.MaxAllowedEMI, calc.MaxCTCPercent, calc.SalaryCTC)
	}
	if loan.EmiAmount > loan.PrincipalAmount {
		return nil, errors.New("emi cannot exceed principal amount")
	}
	if loan.PrincipalAmount > calc.SalaryCTC*6 {
		return nil, fmt.Errorf("loan amount %.2f exceeds allowed maximum based on salary (6× monthly CTC = %.2f)",
			loan.PrincipalAmount, calc.SalaryCTC*6)
	}

	loan.Status = models.LoanStatusActive
	loan.EmisPaid = 0
	loan.ClosureDate = nil
	loan.OutstandingBalance = loan.PrincipalAmount

	beforeJSON, _ := json.Marshal(loan)
	if err := s.repo.CreateLoan(ctx, loan); err != nil {
		s.logger.Error("failed to create loan", zap.Error(err))
		return nil, fmt.Errorf("create loan: %w", err)
	}

	if err := s.generateEMISchedule(ctx, loan); err != nil {
		s.logger.Error("failed to generate EMI schedule", zap.String("loan_id", loan.LoanID.String()), zap.Error(err))
	}

	afterJSON, _ := json.Marshal(loan)

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx, nil, &loan.CompanyID, "loan", "loan_created", "employee_loan",
		&loan.LoanID, "admin", loan.CreatedBy, beforeJSON, afterJSON,
		map[string]interface{}{
			"ip":              ip,
			"loan_type":       loan.LoanType,
			"principal":       loan.PrincipalAmount,
			"emi":             loan.EmiAmount,
			"total_emis":      loan.TotalEmis,
			"component_code":  comp.ComponentCode,
			"within_limit":    calc.WithinLimit,
			"max_ctc_percent": calc.MaxCTCPercent,
			"interest_rate":   calc.InterestRate,
			"interest_type":   calc.InterestType,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, loan)
	return loan, nil
}

func (s *loanService) generateEMISchedule(ctx context.Context, loan *models.EmployeeLoan) error {
	for i := 0; i < loan.TotalEmis; i++ {
		dueDate := loan.FirstEmiDate.AddDate(0, i, 0)
		emi := &models.EmiTransaction{
			LoanID:            loan.LoanID,
			DueDate:           dueDate,
			Amount:            loan.EmiAmount,
			PaidAmount:        0,
			PenaltyAmount:     0,
			OutstandingAmount: loan.EmiAmount,
			PaymentStatus:     "pending",
			Status:            models.EmiStatusPending,
		}
		if err := s.repo.CreateEMI(ctx, emi); err != nil {
			return fmt.Errorf("failed to create EMI for month %d: %w", i+1, err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------
// MarkEMIAsPaid
// ---------------------------------------------------------------------
func (s *loanService) MarkEMIAsPaid(
	ctx context.Context,
	emiID uuid.UUID,
	paidDate time.Time,
	payrollRunID *uuid.UUID,
) error {
	emi, err := s.repo.GetEMIByID(ctx, emiID)
	if err != nil {
		return fmt.Errorf("failed to fetch EMI: %w", err)
	}
	if emi == nil {
		return errors.New("EMI not found")
	}

	loan, err := s.repo.GetLoanByID(ctx, emi.LoanID)
	if err != nil || loan == nil {
		return errors.New("loan not found for EMI")
	}

	if err := s.ensureEmployeeInScope(ctx, loan.CompanyID, loan.UserID); err != nil {
		return err
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("emi_paid-%s", emiID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	if emi.Status != models.EmiStatusPending {
		return fmt.Errorf("EMI is not pending (current status: %s)", emi.Status)
	}

	tx, err := s.repo.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	source := "manual"
	if payrollRunID != nil {
		source = "payroll"
	}

	err = s.repo.ProcessEMIPaymentTx(ctx, tx, emiID, emi.LoanID, paidDate, emi.Amount, 0, payrollRunID, source)
	if err != nil {
		return fmt.Errorf("failed to process EMI payment: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return err
	}

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx, nil, &loan.CompanyID, "loan", "emi_paid", "emi_transaction",
		&emiID, "system", nil, nil, nil,
		map[string]interface{}{
			"ip":             ip,
			"source":         source,
			"payroll_run_id": payrollRunID,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// ---------------------------------------------------------------------
// CloseLoan
// ---------------------------------------------------------------------
func (s *loanService) CloseLoan(ctx context.Context, loanID uuid.UUID, closureDate time.Time) error {
	loan, err := s.repo.GetLoanByID(ctx, loanID)
	if err != nil {
		return fmt.Errorf("failed to fetch loan: %w", err)
	}
	if loan == nil {
		return errors.New("loan not found")
	}

	if err := s.ensureEmployeeInScope(ctx, loan.CompanyID, loan.UserID); err != nil {
		return err
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("close_loan-%s", loanID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	if loan.Status != models.LoanStatusActive {
		return fmt.Errorf("loan is not active (current status: %s)", loan.Status)
	}

	beforeJSON, _ := json.Marshal(loan)

	loan.Status = models.LoanStatusClosed
	loan.ClosureDate = &closureDate
	if err := s.repo.UpdateLoan(ctx, loan); err != nil {
		return fmt.Errorf("failed to update loan: %w", err)
	}

	pending, err := s.repo.GetPendingEMIsForLoan(ctx, loanID)
	if err != nil {
		return fmt.Errorf("failed to fetch pending EMIs: %w", err)
	}
	for _, emi := range pending {
		emi.Status = models.EmiStatusWaived
		if err := s.repo.UpdateEMI(ctx, &emi); err != nil {
			s.logger.Error("failed to update EMI to waived", zap.String("emi_id", emi.EmiID.String()), zap.Error(err))
		}
	}

	afterJSON, _ := json.Marshal(loan)

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx, nil, &loan.CompanyID, "loan", "loan_closed", "employee_loan",
		&loanID, "system", nil, beforeJSON, afterJSON,
		map[string]interface{}{
			"ip":           ip,
			"closure_date": closureDate,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// ---------------------------------------------------------------------
// RecordManualPayment
// ---------------------------------------------------------------------
func (s *loanService) RecordManualPayment(
	ctx context.Context,
	loanID uuid.UUID,
	amount float64,
	penalty float64,
	paidAt time.Time,
	actorID uuid.UUID,
) error {
	loan, err := s.repo.GetLoanByID(ctx, loanID)
	if err != nil {
		return fmt.Errorf("failed to fetch loan: %w", err)
	}
	if loan == nil {
		return errors.New("loan not found")
	}

	if err := s.ensureEmployeeInScope(ctx, loan.CompanyID, loan.UserID); err != nil {
		return err
	}

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("manual_payment-%s-%s", loanID.String(), uuid.New().String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	payment := &models.LoanPayment{
		LoanID:    loanID,
		Amount:    amount,
		Penalty:   penalty,
		PaidAt:    paidAt,
		Source:    "manual",
		CreatedAt: time.Now().UTC(),
	}
	if err := s.repo.CreateLoanPayment(ctx, payment); err != nil {
		return fmt.Errorf("failed to create loan payment: %w", err)
	}
	if err := s.repo.ApplyLoanPayment(ctx, loanID, amount); err != nil {
		return fmt.Errorf("failed to apply loan payment: %w", err)
	}

	ip, _ := ctx.Value("ip_address").(string)
	_ = s.audit.LogAction(
		ctx, nil, &loan.CompanyID, "loan", "manual_payment", "loan_payment",
		&payment.PaymentID, "admin", &actorID, nil, nil,
		map[string]interface{}{
			"ip":      ip,
			"loan_id": loanID.String(),
			"amount":  amount,
			"penalty": penalty,
		},
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// ---------------------------------------------------------------------
// Read-only methods
// ---------------------------------------------------------------------
func (s *loanService) GetLoan(ctx context.Context, loanID uuid.UUID) (*models.EmployeeLoan, error) {
	loan, err := s.repo.GetLoanByID(ctx, loanID)
	if err != nil {
		s.logger.Error("failed to get loan", zap.String("loan_id", loanID.String()), zap.Error(err))
		return nil, fmt.Errorf("get loan: %w", err)
	}
	return loan, nil
}

func (s *loanService) ListUserLoans(ctx context.Context, companyID, userID uuid.UUID, includeClosed bool) ([]models.EmployeeLoan, error) {
	loans, err := s.repo.ListLoansByUser(ctx, companyID, userID, includeClosed)
	if err != nil {
		s.logger.Error("failed to list user loans", zap.Error(err))
		return nil, fmt.Errorf("list user loans: %w", err)
	}
	return loans, nil
}

func (s *loanService) GetPendingEMIsForLoan(ctx context.Context, loanID uuid.UUID) ([]models.EmiTransaction, error) {
	return s.repo.GetPendingEMIsForLoan(ctx, loanID)
}

func (s *loanService) GetPendingEMIsForPayrollRun(ctx context.Context, payrollRunID uuid.UUID) ([]models.EmiTransaction, error) {
	return s.repo.GetEMIsForPayrollRun(ctx, payrollRunID, nil)
}

func (s *loanService) ListLoanPayments(ctx context.Context, loanID uuid.UUID) ([]models.LoanPayment, error) {
	return s.repo.ListLoanPayments(ctx, loanID)
}

func (s *loanService) ListLoanPaymentsByPayrollRun(ctx context.Context, payrollRunID uuid.UUID) ([]models.LoanPayment, error) {
	return s.repo.ListLoanPaymentsByPayrollRun(ctx, payrollRunID)
}
