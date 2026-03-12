package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	a "auth-service/internal/hr/service" // audit service

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------
// LoanService interface (MODIFIED: CalculateEMI signature includes interest)
// ---------------------------------------------------------------------
type LoanService interface {
	// CreateLoan creates a new loan and generates its EMI schedule.
	// maxCTCPercent is the maximum allowed percentage of the employee's monthly CTC
	// that the EMI can consume. If ≤ 0, it defaults to 20%.
	CreateLoan(ctx context.Context, loan *models.EmployeeLoan, maxCTCPercent float64) (*models.EmployeeLoan, error)

	// GetLoan returns a loan by its ID.
	GetLoan(ctx context.Context, loanID uuid.UUID) (*models.EmployeeLoan, error)

	// ListUserLoans returns all loans for a given user, optionally including closed ones.
	ListUserLoans(ctx context.Context, companyID, userID uuid.UUID, includeClosed bool) ([]models.EmployeeLoan, error)

	// GetPendingEMIsForLoan returns all pending EMIs for a specific loan.
	GetPendingEMIsForLoan(ctx context.Context, loanID uuid.UUID) ([]models.EmiTransaction, error)

	// GetPendingEMIsForPayrollRun returns all pending EMIs that fall within the period of a payroll run.
	GetPendingEMIsForPayrollRun(ctx context.Context, payrollRunID uuid.UUID) ([]models.EmiTransaction, error)

	// MarkEMIAsPaid marks an EMI as paid, updates the loan's paid count, and closes the loan if fully paid.
	MarkEMIAsPaid(ctx context.Context, emiID uuid.UUID, paidDate time.Time, payrollRunID *uuid.UUID) error

	// CloseLoan manually closes a loan (e.g., early settlement) and marks all remaining EMIs as waived.
	CloseLoan(ctx context.Context, loanID uuid.UUID, closureDate time.Time) error

	// RecordManualPayment records a manual loan payment (not tied to an EMI) and updates the outstanding balance.
	RecordManualPayment(
		ctx context.Context,
		loanID uuid.UUID,
		amount float64,
		penalty float64,
		paidAt time.Time,
		actorID uuid.UUID,
	) error

	// ListLoanPayments returns all payment ledger entries for a loan.
	ListLoanPayments(ctx context.Context, loanID uuid.UUID) ([]models.LoanPayment, error)

	// ListLoanPaymentsByPayrollRun returns all loan payments associated with a payroll run.
	ListLoanPaymentsByPayrollRun(ctx context.Context, payrollRunID uuid.UUID) ([]models.LoanPayment, error)

	// CalculateEMI provides an EMI preview for the frontend, returning recommended EMI,
	// maximum allowed based on salary, and whether the recommended amount is within the limit.
	// MODIFIED: now accepts interestRate and interestType.
	CalculateEMI(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		principal float64,
		totalEmis int,
		maxCTCPercent float64,
		interestRate *float64,
		interestType *string,
	) (*EMICalculationResult, error)
}

// EMICalculationResult holds the result of an EMI preview calculation.
// MODIFIED: added InterestRate, InterestType, TotalInterest, TotalRepayment.
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

// loanService implements LoanService.
type loanService struct {
	repo            repository.LoanRepository
	componentRepo   repository.ComponentRepository
	settingsRepo    repository.CompanySettingsRepository
	compensationSvc CompensationService
	audit           *a.AuditService
	logger          *zap.Logger
}

// NewLoanService creates a new loan service instance.
func NewLoanService(
	repo repository.LoanRepository,
	componentRepo repository.ComponentRepository,
	settingsRepo repository.CompanySettingsRepository,
	compensationSvc CompensationService,
	audit *a.AuditService,
	logger *zap.Logger,
) LoanService {
	return &loanService{
		repo:            repo,
		componentRepo:   componentRepo,
		settingsRepo:    settingsRepo,
		compensationSvc: compensationSvc,
		audit:           audit,
		logger:          logger.Named("loan_service"),
	}
}

// ---------------------------------------------------------------------
// Helper functions for nil pointers (NEW)
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
// EMI Preview – MODIFIED to support interest calculations
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

	if principal <= 0 {
		return nil, errors.New("principal must be positive")
	}
	if totalEmis <= 0 {
		return nil, errors.New("total_emis must be positive")
	}

	// Fetch employee's current monthly CTC
	salary, err := s.compensationSvc.GetCurrentSalary(ctx, companyID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch employee salary: %w", err)
	}
	if salary == nil {
		return nil, errors.New("no active salary found for employee")
	}
	ctc := salary.MonthlyCTC

	// Determine max allowed percent
	if maxCTCPercent <= 0 {
		maxCTCPercent = 20 // default fallback
	}
	maxAllowed := ctc * (maxCTCPercent / 100)

	months := float64(totalEmis)

	var emi float64
	var totalInterest float64
	var totalRepayment float64

	// =============================
	// INTEREST CALCULATION (NEW)
	// =============================
	if interestRate == nil || *interestRate == 0 {
		// Interest‑free loan
		emi = principal / months
		totalInterest = 0
		totalRepayment = principal
	} else {
		rate := *interestRate / 100

		if interestType != nil && *interestType == "flat" {
			// Flat interest: Interest = P * r * years
			years := months / 12
			totalInterest = principal * rate * years
			totalRepayment = principal + totalInterest
			emi = totalRepayment / months
		} else if interestType != nil && *interestType == "compound" {
			// Compound (reducing balance) EMI: standard formula
			monthlyRate := rate / 12
			pow := math.Pow(1+monthlyRate, months)
			emi = principal * monthlyRate * pow / (pow - 1)
			totalRepayment = emi * months
			totalInterest = totalRepayment - principal
		} else {
			return nil, errors.New("invalid interest_type (must be 'flat' or 'compound')")
		}
	}

	// Round to two decimals for readability
	emi = math.Round(emi*100) / 100
	totalInterest = math.Round(totalInterest*100) / 100
	totalRepayment = math.Round(totalRepayment*100) / 100

	return &EMICalculationResult{
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
	}, nil
}

// ---------------------------------------------------------------------
// CreateLoan – MODIFIED to pass interest fields to CalculateEMI
// ---------------------------------------------------------------------
func (s *loanService) CreateLoan(
	ctx context.Context,
	loan *models.EmployeeLoan,
	maxCTCPercent float64,
) (*models.EmployeeLoan, error) {
	// Basic validation
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

	// Component code handling
	code := loan.ComponentCode
	if code == "" {
		settings, err := s.settingsRepo.GetPayrollSettings(ctx, loan.CompanyID)
		if err != nil {
			return nil, fmt.Errorf("failed to get company payroll settings: %w", err)
		}
		if settings.DefaultLoanComponent == nil || *settings.DefaultLoanComponent == "" {
			return nil, errors.New("no loan component provided and no company default set")
		}
		code = *settings.DefaultLoanComponent
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
	loan.ComponentCode = code

	// --- EMI calculation & cap validation (using provided maxCTCPercent) ---
	if maxCTCPercent <= 0 {
		maxCTCPercent = 20 // fallback
	}
	// MODIFIED: pass interest fields to CalculateEMI
	calc, err := s.CalculateEMI(
		ctx,
		loan.CompanyID,
		loan.UserID,
		loan.PrincipalAmount,
		loan.TotalEmis,
		maxCTCPercent,
		loan.InterestRate,
		loan.InterestType,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to validate EMI against salary: %w", err)
	}

	// If EMI not provided, use recommended value
	if loan.EmiAmount <= 0 {
		loan.EmiAmount = calc.RecommendedEMI
		s.logger.Info("auto‑calculated EMI",
			zap.String("user_id", loan.UserID.String()),
			zap.Float64("principal", loan.PrincipalAmount),
			zap.Float64("emi", loan.EmiAmount))
	}

	// Always check that the EMI (whether provided or auto) is within the cap
	if loan.EmiAmount > calc.MaxAllowedEMI {
		return nil, fmt.Errorf(
			"EMI %.2f exceeds allowed limit %.2f (%.0f%% of monthly salary %.2f)",
			loan.EmiAmount, calc.MaxAllowedEMI, calc.MaxCTCPercent, calc.SalaryCTC,
		)
	}

	// EMI cannot exceed principal
	if loan.EmiAmount > loan.PrincipalAmount {
		return nil, errors.New("emi cannot exceed principal amount")
	}

	// Optional: principal not more than 6× salary
	if loan.PrincipalAmount > calc.SalaryCTC*6 {
		return nil, fmt.Errorf(
			"loan amount %.2f exceeds allowed maximum based on salary (6× monthly CTC = %.2f)",
			loan.PrincipalAmount, calc.SalaryCTC*6,
		)
	}

	// Set default values
	loan.Status = models.LoanStatusActive
	loan.EmisPaid = 0
	loan.ClosureDate = nil
	loan.OutstandingBalance = loan.PrincipalAmount

	// Create loan in repository
	if err := s.repo.CreateLoan(ctx, loan); err != nil {
		s.logger.Error("failed to create loan",
			zap.String("company_id", loan.CompanyID.String()),
			zap.String("user_id", loan.UserID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("create loan: %w", err)
	}

	// Generate EMI schedule
	if err := s.generateEMISchedule(ctx, loan); err != nil {
		s.logger.Error("failed to generate EMI schedule, loan created without EMIs",
			zap.String("loan_id", loan.LoanID.String()),
			zap.Error(err),
		)
	}

	// Audit log – MODIFIED to include interest fields
	if s.audit != nil {
		after, _ := json.Marshal(loan)
		_ = s.audit.LogAction(ctx, &loan.CompanyID, "loan", "loan_created",
			"employee_loan", &loan.LoanID, "admin", loan.CreatedBy,
			nil, after, map[string]interface{}{
				"loan_type":       loan.LoanType,
				"principal":       loan.PrincipalAmount,
				"emi":             loan.EmiAmount,
				"total_emis":      loan.TotalEmis,
				"component_code":  loan.ComponentCode,
				"within_limit":    calc.WithinLimit,
				"max_ctc_percent": calc.MaxCTCPercent,
				"interest_rate":   calc.InterestRate, // NEW
				"interest_type":   calc.InterestType, // NEW
			})
	}

	return loan, nil
}

// generateEMISchedule creates pending EMI transactions (unchanged – uses loan.EmiAmount)
func (s *loanService) generateEMISchedule(ctx context.Context, loan *models.EmployeeLoan) error {
	for i := 0; i < loan.TotalEmis; i++ {
		dueDate := loan.FirstEmiDate.AddDate(0, i, 0) // same day each month
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
// Existing methods (unchanged)
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
		s.logger.Error("failed to list user loans",
			zap.String("company_id", companyID.String()),
			zap.String("user_id", userID.String()),
			zap.Error(err))
		return nil, fmt.Errorf("list user loans: %w", err)
	}
	return loans, nil
}

func (s *loanService) GetPendingEMIsForLoan(ctx context.Context, loanID uuid.UUID) ([]models.EmiTransaction, error) {
	emis, err := s.repo.GetPendingEMIsForLoan(ctx, loanID)
	if err != nil {
		s.logger.Error("failed to get pending EMIs for loan",
			zap.String("loan_id", loanID.String()),
			zap.Error(err))
		return nil, fmt.Errorf("get pending EMIs: %w", err)
	}
	return emis, nil
}

func (s *loanService) GetPendingEMIsForPayrollRun(ctx context.Context, payrollRunID uuid.UUID) ([]models.EmiTransaction, error) {
	emis, err := s.repo.GetEMIsForPayrollRun(ctx, payrollRunID)
	if err != nil {
		s.logger.Error("failed to get EMIs for payroll run",
			zap.String("payroll_run_id", payrollRunID.String()),
			zap.Error(err))
		return nil, fmt.Errorf("get EMIs for payroll run: %w", err)
	}
	return emis, nil
}

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

	err = s.repo.ProcessEMIPaymentTx(
		ctx,
		tx,
		emiID,
		emi.LoanID,
		paidDate,
		emi.Amount,
		0,
		payrollRunID,
		source,
	)

	if err != nil {
		return fmt.Errorf("failed to process EMI payment: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return err
	}

	if s.audit != nil {

		metadata := map[string]interface{}{
			"emi_id": emiID.String(),
			"source": source,
		}

		if payrollRunID != nil {
			metadata["payroll_run_id"] = payrollRunID.String()
		}

		loan, _ := s.repo.GetLoanByID(ctx, emi.LoanID)

		if loan != nil {
			_ = s.audit.LogAction(
				ctx,
				&loan.CompanyID,
				"loan",
				"emi_paid",
				"emi_transaction",
				&emiID,
				"system",
				nil,
				nil,
				nil,
				metadata,
			)
		}
	}

	return nil
}

func (s *loanService) CloseLoan(ctx context.Context, loanID uuid.UUID, closureDate time.Time) error {
	loan, err := s.repo.GetLoanByID(ctx, loanID)
	if err != nil {
		return fmt.Errorf("failed to fetch loan: %w", err)
	}
	if loan == nil {
		return errors.New("loan not found")
	}
	if loan.Status != models.LoanStatusActive {
		return fmt.Errorf("loan is not active (current status: %s)", loan.Status)
	}

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
			s.logger.Error("failed to update EMI to waived",
				zap.String("emi_id", emi.EmiID.String()),
				zap.Error(err))
		}
	}

	if s.audit != nil {
		_ = s.audit.LogAction(ctx, &loan.CompanyID, "loan", "loan_closed",
			"employee_loan", &loanID, "system", nil, nil, nil,
			map[string]interface{}{"closure_date": closureDate})
	}

	return nil
}

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

	if s.audit != nil {
		_ = s.audit.LogAction(
			ctx,
			&loan.CompanyID,
			"loan",
			"manual_payment",
			"loan_payment",
			&payment.PaymentID,
			"admin",
			&actorID,
			nil,
			nil,
			map[string]interface{}{
				"loan_id": loanID.String(),
				"amount":  amount,
				"penalty": penalty,
			},
		)
	}

	return nil
}

func (s *loanService) ListLoanPayments(ctx context.Context, loanID uuid.UUID) ([]models.LoanPayment, error) {
	return s.repo.ListLoanPayments(ctx, loanID)
}

func (s *loanService) ListLoanPaymentsByPayrollRun(ctx context.Context, payrollRunID uuid.UUID) ([]models.LoanPayment, error) {
	return s.repo.ListLoanPaymentsByPayrollRun(ctx, payrollRunID)
}
