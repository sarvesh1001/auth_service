// File: internal/repository/loan.go
package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/util"
)

// LoanRepository defines methods for managing employee loans, EMIs, and loan payments.
type LoanRepository interface {
	// EMI methods
	GetEMIByID(ctx context.Context, emiID uuid.UUID) (*models.EmiTransaction, error)
	UpdateEMI(ctx context.Context, emi *models.EmiTransaction) error
	CreateEMI(ctx context.Context, emi *models.EmiTransaction) error
	GetPendingEMIsForLoan(ctx context.Context, loanID uuid.UUID) ([]models.EmiTransaction, error)
	GetEMIsForPayrollRun(ctx context.Context, payrollRunID uuid.UUID) ([]models.EmiTransaction, error)
	// MarkEMIAsPaid marks an EMI as fully paid, recording the paid amount, penalty, and remaining balance.
	MarkEMIAsPaid(ctx context.Context, emiID uuid.UUID, paidDate time.Time, paidAmount, penalty float64, payrollRunID *uuid.UUID) error
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)
	// Legacy method – returns only EMI data (no component code)
	GetPendingEMIsForEmployeeInPeriod(ctx context.Context, companyID, userID uuid.UUID, startDate, endDate time.Time) ([]models.EmiTransaction, error)
	// New method – returns EMI data together with the loan’s component code for efficient payroll processing
	GetPendingEMIsForEmployeeInPeriodWithDetails(ctx context.Context, companyID, userID uuid.UUID, startDate, endDate time.Time) ([]LoanEmiDetail, error)

	// Loan methods
	CreateLoan(ctx context.Context, loan *models.EmployeeLoan) error
	UpdateLoan(ctx context.Context, loan *models.EmployeeLoan) error
	GetLoanByID(ctx context.Context, loanID uuid.UUID) (*models.EmployeeLoan, error)
	ListLoansByUser(ctx context.Context, companyID, userID uuid.UUID, includeClosed bool) ([]models.EmployeeLoan, error)
	ListActiveLoans(ctx context.Context, companyID uuid.UUID, asOf time.Time) ([]models.EmployeeLoan, error)

	// Loan Payment ledger methods
	CreateLoanPayment(ctx context.Context, payment *models.LoanPayment) error
	ListLoanPayments(ctx context.Context, loanID uuid.UUID) ([]models.LoanPayment, error)
	ListLoanPaymentsByPayrollRun(ctx context.Context, payrollRunID uuid.UUID) ([]models.LoanPayment, error)

	// NEW: Apply a payment to the loan (reduce outstanding balance, increment emis_paid)
	ApplyLoanPayment(ctx context.Context, loanID uuid.UUID, amount float64) error

	// NEW: Atomic processing of an EMI payment – updates EMI, creates ledger, and updates loan in one transaction
	ProcessEMIPaymentTx(
		ctx context.Context,
		tx *sql.Tx,
		emiID uuid.UUID,
		loanID uuid.UUID,
		paidDate time.Time,
		paidAmount float64,
		penalty float64,
		payrollRunID *uuid.UUID,
		source string,
	) error
}

// loanRepository is the Postgres implementation of LoanRepository.
type loanRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

// NewLoanRepository creates a new loan repository.
func NewLoanRepository(postgresClient *client.PostgresClient, logger *zap.Logger) LoanRepository {
	return &loanRepository{
		client: postgresClient,
		logger: logger,
	}
}

// ---------------------------------------------------------------------
// Loan methods (with new fields: interest_type, outstanding_balance)
// ---------------------------------------------------------------------

func (r *loanRepository) CreateLoan(ctx context.Context, loan *models.EmployeeLoan) error {
	query := `
		INSERT INTO payroll.employee_loan (
			loan_id, company_id, user_id, loan_type,
			principal_amount, emi_amount, interest_rate,
			interest_type,
			total_emis, emis_paid,
			outstanding_balance,
			disbursed_at,
			first_emi_date,
			closure_date,
			status,
			component_code,
			created_at,
			created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
	`

	if loan.LoanID == uuid.Nil {
		loan.LoanID = uuid.New()
	}
	if loan.CreatedAt.IsZero() {
		loan.CreatedAt = time.Now().UTC()
	}
	if loan.EmisPaid == 0 {
		loan.EmisPaid = 0
	}
	if loan.Status == "" {
		loan.Status = models.LoanStatusActive
	}
	if loan.OutstandingBalance == 0 {
		loan.OutstandingBalance = loan.PrincipalAmount
	}

	_, err := r.client.Exec(ctx, query,
		loan.LoanID,
		loan.CompanyID,
		loan.UserID,
		loan.LoanType,
		loan.PrincipalAmount,
		loan.EmiAmount,
		nullFloat64(loan.InterestRate),
		loan.InterestType,
		loan.TotalEmis,
		loan.EmisPaid,
		loan.OutstandingBalance,
		loan.DisbursedAt,
		loan.FirstEmiDate,
		nullTime(loan.ClosureDate),
		loan.Status,
		loan.ComponentCode,
		loan.CreatedAt,
		nullUUID(loan.CreatedBy),
	)
	if err != nil {
		r.logger.Error("Failed to create employee loan",
			util.String("loan_id", loan.LoanID.String()),
			util.String("company_id", loan.CompanyID.String()),
			util.String("user_id", loan.UserID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to create loan: %w", err)
	}
	return nil
}

func (r *loanRepository) UpdateLoan(ctx context.Context, loan *models.EmployeeLoan) error {
	query := `
		UPDATE payroll.employee_loan
		SET
			loan_type = $1,
			principal_amount = $2,
			emi_amount = $3,
			interest_rate = $4,
			interest_type = $5,
			total_emis = $6,
			emis_paid = $7,
			outstanding_balance = $8,
			disbursed_at = $9,
			first_emi_date = $10,
			closure_date = $11,
			status = $12,
			component_code = $13
		WHERE loan_id = $14
	`

	result, err := r.client.Exec(ctx, query,
		loan.LoanType,
		loan.PrincipalAmount,
		loan.EmiAmount,
		nullFloat64(loan.InterestRate),
		loan.InterestType,
		loan.TotalEmis,
		loan.EmisPaid,
		loan.OutstandingBalance,
		loan.DisbursedAt,
		loan.FirstEmiDate,
		nullTime(loan.ClosureDate),
		loan.Status,
		loan.ComponentCode,
		loan.LoanID,
	)
	if err != nil {
		r.logger.Error("Failed to update employee loan",
			util.String("loan_id", loan.LoanID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to update loan: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("loan not found")
	}
	return nil
}

func (r *loanRepository) GetLoanByID(ctx context.Context, loanID uuid.UUID) (*models.EmployeeLoan, error) {
	query := `
		SELECT
			loan_id, company_id, user_id, loan_type,
			principal_amount, emi_amount, interest_rate,
			interest_type,
			total_emis, emis_paid,
			outstanding_balance,
			disbursed_at,
			first_emi_date,
			closure_date,
			status,
			component_code,
			created_at,
			created_by
		FROM payroll.employee_loan
		WHERE loan_id = $1
	`

	row := r.client.QueryRow(ctx, query, loanID)
	return r.scanLoan(row)
}

func (r *loanRepository) ListLoansByUser(ctx context.Context, companyID, userID uuid.UUID, includeClosed bool) ([]models.EmployeeLoan, error) {
	query := `
		SELECT
			loan_id, company_id, user_id, loan_type,
			principal_amount, emi_amount, interest_rate,
			interest_type,
			total_emis, emis_paid,
			outstanding_balance,
			disbursed_at,
			first_emi_date,
			closure_date,
			status,
			component_code,
			created_at,
			created_by
		FROM payroll.employee_loan
		WHERE company_id = $1 AND user_id = $2
	`
	args := []interface{}{companyID, userID}
	if !includeClosed {
		query += " AND status = 'active'"
	}
	query += " ORDER BY disbursed_at DESC"

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		r.logger.Error("Failed to list loans by user",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to list loans: %w", err)
	}
	defer rows.Close()
	return r.scanLoans(rows)
}

func (r *loanRepository) ListActiveLoans(ctx context.Context, companyID uuid.UUID, asOf time.Time) ([]models.EmployeeLoan, error) {
	query := `
		SELECT
			loan_id, company_id, user_id, loan_type,
			principal_amount, emi_amount, interest_rate,
			interest_type,
			total_emis, emis_paid,
			outstanding_balance,
			disbursed_at,
			first_emi_date,
			closure_date,
			status,
			component_code,
			created_at,
			created_by
		FROM payroll.employee_loan
		WHERE company_id = $1
		  AND status = 'active'
		  AND disbursed_at <= $2
		  AND (closure_date IS NULL OR closure_date >= $2)
		ORDER BY user_id, disbursed_at
	`

	rows, err := r.client.Query(ctx, query, companyID, asOf)
	if err != nil {
		r.logger.Error("Failed to list active loans",
			util.String("company_id", companyID.String()),
			util.Time("as_of", asOf),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to list active loans: %w", err)
	}
	defer rows.Close()
	return r.scanLoans(rows)
}

// ---------------------------------------------------------------------
// Loan Payment application (new method)
// ---------------------------------------------------------------------

func (r *loanRepository) ApplyLoanPayment(ctx context.Context, loanID uuid.UUID, amount float64) error {
	query := `
		UPDATE payroll.employee_loan
		SET
			outstanding_balance = outstanding_balance - $1,
			emis_paid = emis_paid + 1
		WHERE loan_id = $2
	`

	result, err := r.client.Exec(ctx, query, amount, loanID)
	if err != nil {
		r.logger.Error("Failed to apply loan payment",
			util.String("loan_id", loanID.String()),
			util.Float64("amount", amount),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to apply loan payment: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("loan not found")
	}
	return nil
}

// ---------------------------------------------------------------------
// Atomic EMI Payment Processing (UPDATED with GREATEST and auto‑closure)
// ---------------------------------------------------------------------

func (r *loanRepository) ProcessEMIPaymentTx(
	ctx context.Context,
	tx *sql.Tx,
	emiID uuid.UUID,
	loanID uuid.UUID,
	paidDate time.Time,
	paidAmount float64,
	penalty float64,
	payrollRunID *uuid.UUID,
	source string,
) error {

	// 1️⃣ Update EMI
	emiUpdate := `
	UPDATE payroll.emi_transaction
	SET
		status = 'paid',
		paid_date = $1,
		paid_amount = $2::numeric,
		penalty_amount = $3::numeric,
		remaining_amount = 0,
		payment_status = CASE WHEN $3::numeric > 0 THEN 'late' ELSE 'on_time' END,
		payroll_run_id = $4
	WHERE emi_id = $5
	`

	_, err := tx.ExecContext(
		ctx,
		emiUpdate,
		paidDate,
		paidAmount,
		penalty,
		nullUUID(payrollRunID),
		emiID,
	)
	if err != nil {
		return fmt.Errorf("failed to update EMI: %w", err)
	}

	// 2️⃣ Insert payment ledger
	paymentID := uuid.New()

	paymentInsert := `
	INSERT INTO payroll.loan_payment (
		payment_id,
		loan_id,
		emi_id,
		amount,
		penalty,
		paid_at,
		source,
		payroll_run_id,
		created_at
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`

	_, err = tx.ExecContext(
		ctx,
		paymentInsert,
		paymentID,
		loanID,
		nullUUID(&emiID),
		paidAmount,
		penalty,
		paidDate,
		source,
		nullUUID(payrollRunID),
		time.Now().UTC(),
	)

	if err != nil {
		return fmt.Errorf("failed to create loan payment: %w", err)
	}

	// 3️⃣ Update loan balance
	loanUpdate := `
	UPDATE payroll.employee_loan
	SET
		outstanding_balance = GREATEST(outstanding_balance - $1::numeric, 0),
		emis_paid = emis_paid + 1
	WHERE loan_id = $2
	`

	_, err = tx.ExecContext(ctx, loanUpdate, paidAmount, loanID)
	if err != nil {
		return fmt.Errorf("failed to apply loan payment: %w", err)
	}

	// 4️⃣ Auto close loan
	autoClose := `
	UPDATE payroll.employee_loan
	SET
		status = 'closed',
		closure_date = NOW()
	WHERE loan_id = $1
	AND outstanding_balance <= 0
	`

	_, err = tx.ExecContext(ctx, autoClose, loanID)
	if err != nil {
		r.logger.Warn("auto close loan failed", zap.Error(err))
	}

	return nil
}

// ---------------------------------------------------------------------
// EMI methods (now include all new fields)
// ---------------------------------------------------------------------

func (r *loanRepository) CreateEMI(ctx context.Context, emi *models.EmiTransaction) error {
	query := `
		INSERT INTO payroll.emi_transaction (
			emi_id,
			loan_id,
			due_date,
			paid_date,
			amount,
			paid_amount,
			penalty_amount,
			remaining_amount,
			payment_status,
			payroll_run_id,
			status
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	if emi.EmiID == uuid.Nil {
		emi.EmiID = uuid.New()
	}
	if emi.Status == "" {
		emi.Status = models.EmiStatusPending
	}
	// payment_status is NOT set – let DB default to 'pending'

	_, err := r.client.Exec(ctx, query,
		emi.EmiID,
		emi.LoanID,
		emi.DueDate,
		nullTime(emi.PaidDate),
		emi.Amount,
		emi.PaidAmount,
		emi.PenaltyAmount,
		emi.OutstandingAmount,
		emi.PaymentStatus, // may be empty, DB will set default 'pending'
		nullUUID(emi.PayrollRunID),
		emi.Status,
	)
	if err != nil {
		r.logger.Error("Failed to create EMI transaction",
			util.String("emi_id", emi.EmiID.String()),
			util.String("loan_id", emi.LoanID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to create EMI: %w", err)
	}
	return nil
}

func (r *loanRepository) GetPendingEMIsForLoan(ctx context.Context, loanID uuid.UUID) ([]models.EmiTransaction, error) {
	query := `
		SELECT
			emi_id, loan_id, due_date, paid_date,
			amount,
			paid_amount, penalty_amount, remaining_amount, payment_status,
			payroll_run_id, status
		FROM payroll.emi_transaction
		WHERE loan_id = $1 AND status = 'pending'
		ORDER BY due_date
	`

	rows, err := r.client.Query(ctx, query, loanID)
	if err != nil {
		r.logger.Error("Failed to get pending EMIs for loan",
			util.String("loan_id", loanID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get pending EMIs: %w", err)
	}
	defer rows.Close()
	return r.scanEMIs(rows)
}

func (r *loanRepository) GetEMIsForPayrollRun(ctx context.Context, payrollRunID uuid.UUID) ([]models.EmiTransaction, error) {
	query := `
		SELECT
			e.emi_id, e.loan_id, e.due_date, e.paid_date,
			e.amount,
			e.paid_amount, e.penalty_amount, e.remaining_amount, e.payment_status,
			e.payroll_run_id, e.status
		FROM payroll.emi_transaction e
		JOIN payroll.employee_loan l ON e.loan_id = l.loan_id
		JOIN payroll.payroll_run r ON r.company_id = l.company_id
		WHERE r.payroll_run_id = $1
		  AND e.status = 'pending'
		  AND e.due_date BETWEEN r.period_start AND r.period_end
	`

	rows, err := r.client.Query(ctx, query, payrollRunID)
	if err != nil {
		r.logger.Error("Failed to get EMIs for payroll run",
			util.String("payroll_run_id", payrollRunID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get EMIs for run: %w", err)
	}
	defer rows.Close()
	return r.scanEMIs(rows)
}

func (r *loanRepository) MarkEMIAsPaid(ctx context.Context, emiID uuid.UUID, paidDate time.Time, paidAmount, penalty float64, payrollRunID *uuid.UUID) error {
	query := `
		UPDATE payroll.emi_transaction
		SET
			status = 'paid',
			paid_date = $1,
			paid_amount = $2,
			penalty_amount = $3,
			remaining_amount = 0,
			payment_status = CASE WHEN $3 > 0 THEN 'late' ELSE 'on_time' END,
			payroll_run_id = $4
		WHERE emi_id = $5
	`

	result, err := r.client.Exec(ctx, query, paidDate, paidAmount, penalty, nullUUID(payrollRunID), emiID)
	if err != nil {
		r.logger.Error("Failed to mark EMI as paid",
			util.String("emi_id", emiID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to update EMI: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("EMI not found")
	}
	return nil
}

// ---------------------------------------------------------------------
// EMI retrieval with loan details (new method, now includes all EMI fields)
// ---------------------------------------------------------------------

// LoanEmiDetail is returned by GetPendingEMIsForEmployeeInPeriodWithDetails.
type LoanEmiDetail struct {
	Emi           models.EmiTransaction
	ComponentCode string
}

func (r *loanRepository) GetPendingEMIsForEmployeeInPeriodWithDetails(
	ctx context.Context,
	companyID, userID uuid.UUID,
	startDate, endDate time.Time,
) ([]LoanEmiDetail, error) {
	query := `
		SELECT
			e.emi_id, e.loan_id, e.due_date, e.paid_date,
			e.amount,
			e.paid_amount, e.penalty_amount, e.remaining_amount, e.payment_status,
			e.payroll_run_id, e.status,
			l.component_code
		FROM payroll.emi_transaction e
		JOIN payroll.employee_loan l ON e.loan_id = l.loan_id
		WHERE l.company_id = $1
		  AND l.user_id = $2
		  AND e.status = 'pending'
		  AND e.due_date BETWEEN $3 AND $4
		ORDER BY e.due_date
	`

	rows, err := r.client.Query(ctx, query, companyID, userID, startDate, endDate)
	if err != nil {
		r.logger.Error("Failed to get pending EMIs with details for employee",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.Time("start_date", startDate),
			util.Time("end_date", endDate),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get pending EMIs with details: %w", err)
	}
	defer rows.Close()

	var details []LoanEmiDetail
	for rows.Next() {
		var e models.EmiTransaction
		var paidDate sql.NullTime
		var payrollRunID uuid.NullUUID
		var compCode string
		var paidAmount sql.NullFloat64
		var penaltyAmount sql.NullFloat64
		var remainingAmount sql.NullFloat64
		var paymentStatus sql.NullString

		err := rows.Scan(
			&e.EmiID,
			&e.LoanID,
			&e.DueDate,
			&paidDate,
			&e.Amount,
			&paidAmount,
			&penaltyAmount,
			&remainingAmount,
			&paymentStatus,
			&payrollRunID,
			&e.Status,
			&compCode,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan EMI with component: %w", err)
		}

		if paidDate.Valid {
			e.PaidDate = &paidDate.Time
		}
		if payrollRunID.Valid {
			e.PayrollRunID = &payrollRunID.UUID
		}
		if paidAmount.Valid {
			e.PaidAmount = paidAmount.Float64
		}
		if penaltyAmount.Valid {
			e.PenaltyAmount = penaltyAmount.Float64
		}
		if remainingAmount.Valid {
			e.OutstandingAmount = remainingAmount.Float64
		}
		if paymentStatus.Valid {
			e.PaymentStatus = paymentStatus.String
		}

		details = append(details, LoanEmiDetail{
			Emi:           e,
			ComponentCode: compCode,
		})
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return details, nil
}

// ---------------------------------------------------------------------
// Legacy method (returns only EMIs, no component code, but now includes new EMI fields)
// ---------------------------------------------------------------------

func (r *loanRepository) GetPendingEMIsForEmployeeInPeriod(
	ctx context.Context,
	companyID, userID uuid.UUID,
	startDate, endDate time.Time,
) ([]models.EmiTransaction, error) {
	// First get all active loans for the user
	loans, err := r.ListLoansByUser(ctx, companyID, userID, false)
	if err != nil {
		return nil, fmt.Errorf("failed to list loans for user: %w", err)
	}
	if len(loans) == 0 {
		return nil, nil
	}

	loanIDs := make([]uuid.UUID, len(loans))
	for i, l := range loans {
		loanIDs[i] = l.LoanID
	}

	query := `
        SELECT
			emi_id, loan_id, due_date, paid_date,
			amount,
			paid_amount, penalty_amount, remaining_amount, payment_status,
			payroll_run_id, status
        FROM payroll.emi_transaction
        WHERE loan_id = ANY($1)
          AND status = 'pending'
          AND due_date BETWEEN $2 AND $3
        ORDER BY due_date
    `
	rows, err := r.client.Query(ctx, query, pq.Array(loanIDs), startDate, endDate)
	if err != nil {
		r.logger.Error("Failed to get pending EMIs for employee in period",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.Time("start_date", startDate),
			util.Time("end_date", endDate),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get pending EMIs: %w", err)
	}
	defer rows.Close()
	return r.scanEMIs(rows)
}

// ---------------------------------------------------------------------
// Basic EMI retrieval by ID and update (UpdateEMI now includes all fields)
// ---------------------------------------------------------------------

func (r *loanRepository) GetEMIByID(ctx context.Context, emiID uuid.UUID) (*models.EmiTransaction, error) {
	query := `
		SELECT
			emi_id, loan_id, due_date, paid_date,
			amount,
			paid_amount, penalty_amount, remaining_amount, payment_status,
			payroll_run_id, status
		FROM payroll.emi_transaction
		WHERE emi_id = $1
	`
	row := r.client.QueryRow(ctx, query, emiID)
	return r.scanEMI(row)
}

func (r *loanRepository) UpdateEMI(ctx context.Context, emi *models.EmiTransaction) error {
	query := `
		UPDATE payroll.emi_transaction
		SET
			paid_date = $1,
			paid_amount = $2,
			penalty_amount = $3,
			remaining_amount = $4,
			payment_status = $5,
			payroll_run_id = $6,
			status = $7
		WHERE emi_id = $8
	`
	_, err := r.client.Exec(ctx, query,
		nullTime(emi.PaidDate),
		emi.PaidAmount,
		emi.PenaltyAmount,
		emi.OutstandingAmount,
		emi.PaymentStatus,
		nullUUID(emi.PayrollRunID),
		emi.Status,
		emi.EmiID,
	)
	return err
}

// ---------------------------------------------------------------------
// Loan Payment ledger methods
// ---------------------------------------------------------------------

func (r *loanRepository) CreateLoanPayment(ctx context.Context, p *models.LoanPayment) error {
	query := `
		INSERT INTO payroll.loan_payment (
			payment_id,
			loan_id,
			emi_id,
			amount,
			penalty,
			paid_at,
			source,
			payroll_run_id,
			created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	if p.PaymentID == uuid.Nil {
		p.PaymentID = uuid.New()
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}

	_, err := r.client.Exec(ctx, query,
		p.PaymentID,
		p.LoanID,
		nullUUID(p.EmiID),
		p.Amount,
		p.Penalty,
		p.PaidAt,
		p.Source,
		nullUUID(p.PayrollRunID),
		p.CreatedAt,
	)
	if err != nil {
		r.logger.Error("Failed to create loan payment",
			util.String("payment_id", p.PaymentID.String()),
			util.String("loan_id", p.LoanID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to create loan payment: %w", err)
	}
	return nil
}

func (r *loanRepository) ListLoanPayments(ctx context.Context, loanID uuid.UUID) ([]models.LoanPayment, error) {
	query := `
		SELECT payment_id, loan_id, emi_id, amount, penalty,
		       paid_at, source, payroll_run_id, created_at
		FROM payroll.loan_payment
		WHERE loan_id = $1
		ORDER BY paid_at DESC
	`

	rows, err := r.client.Query(ctx, query, loanID)
	if err != nil {
		r.logger.Error("Failed to list loan payments",
			util.String("loan_id", loanID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to list loan payments: %w", err)
	}
	defer rows.Close()

	var payments []models.LoanPayment
	for rows.Next() {
		var p models.LoanPayment
		var emiID uuid.NullUUID
		var payrollRunID uuid.NullUUID

		err := rows.Scan(
			&p.PaymentID,
			&p.LoanID,
			&emiID,
			&p.Amount,
			&p.Penalty,
			&p.PaidAt,
			&p.Source,
			&payrollRunID,
			&p.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan loan payment: %w", err)
		}

		if emiID.Valid {
			p.EmiID = &emiID.UUID
		}
		if payrollRunID.Valid {
			p.PayrollRunID = &payrollRunID.UUID
		}
		payments = append(payments, p)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return payments, nil
}

func (r *loanRepository) ListLoanPaymentsByPayrollRun(ctx context.Context, payrollRunID uuid.UUID) ([]models.LoanPayment, error) {
	query := `
		SELECT payment_id, loan_id, emi_id, amount, penalty,
		       paid_at, source, payroll_run_id, created_at
		FROM payroll.loan_payment
		WHERE payroll_run_id = $1
		ORDER BY paid_at DESC
	`

	rows, err := r.client.Query(ctx, query, payrollRunID)
	if err != nil {
		r.logger.Error("Failed to list loan payments by payroll run",
			util.String("payroll_run_id", payrollRunID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to list loan payments by payroll run: %w", err)
	}
	defer rows.Close()

	var payments []models.LoanPayment
	for rows.Next() {
		var p models.LoanPayment
		var emiID uuid.NullUUID
		var prID uuid.NullUUID

		err := rows.Scan(
			&p.PaymentID,
			&p.LoanID,
			&emiID,
			&p.Amount,
			&p.Penalty,
			&p.PaidAt,
			&p.Source,
			&prID,
			&p.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan loan payment: %w", err)
		}

		if emiID.Valid {
			p.EmiID = &emiID.UUID
		}
		if prID.Valid {
			p.PayrollRunID = &prID.UUID
		}
		payments = append(payments, p)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return payments, nil
}

// ---------------------------------------------------------------------
// Scanning helpers (updated)
// ---------------------------------------------------------------------

func (r *loanRepository) scanLoan(row scanner) (*models.EmployeeLoan, error) {
	var l models.EmployeeLoan
	var interestRate sql.NullFloat64
	var interestType sql.NullString
	var outstandingBalance sql.NullFloat64
	var closureDate sql.NullTime
	var createdBy uuid.NullUUID

	err := row.Scan(
		&l.LoanID,
		&l.CompanyID,
		&l.UserID,
		&l.LoanType,
		&l.PrincipalAmount,
		&l.EmiAmount,
		&interestRate,
		&interestType,
		&l.TotalEmis,
		&l.EmisPaid,
		&outstandingBalance,
		&l.DisbursedAt,
		&l.FirstEmiDate,
		&closureDate,
		&l.Status,
		&l.ComponentCode,
		&l.CreatedAt,
		&createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	if interestRate.Valid {
		l.InterestRate = &interestRate.Float64
	}
	if interestType.Valid {
		l.InterestType = &interestType.String
	}
	if outstandingBalance.Valid {
		l.OutstandingBalance = outstandingBalance.Float64
	}
	if closureDate.Valid {
		l.ClosureDate = &closureDate.Time
	}
	if createdBy.Valid {
		l.CreatedBy = &createdBy.UUID
	}
	return &l, nil
}

func (r *loanRepository) scanLoans(rows *sql.Rows) ([]models.EmployeeLoan, error) {
	var loans []models.EmployeeLoan
	for rows.Next() {
		l, err := r.scanLoan(rows)
		if err != nil {
			return nil, err
		}
		if l != nil {
			loans = append(loans, *l)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return loans, nil
}

func (r *loanRepository) scanEMI(row scanner) (*models.EmiTransaction, error) {
	var e models.EmiTransaction
	var paidDate sql.NullTime
	var payrollRunID uuid.NullUUID
	var paidAmount sql.NullFloat64
	var penaltyAmount sql.NullFloat64
	var remainingAmount sql.NullFloat64
	var paymentStatus sql.NullString

	err := row.Scan(
		&e.EmiID,
		&e.LoanID,
		&e.DueDate,
		&paidDate,
		&e.Amount,
		&paidAmount,
		&penaltyAmount,
		&remainingAmount,
		&paymentStatus,
		&payrollRunID,
		&e.Status,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	if paidDate.Valid {
		e.PaidDate = &paidDate.Time
	}
	if payrollRunID.Valid {
		e.PayrollRunID = &payrollRunID.UUID
	}
	if paidAmount.Valid {
		e.PaidAmount = paidAmount.Float64
	}
	if penaltyAmount.Valid {
		e.PenaltyAmount = penaltyAmount.Float64
	}
	if remainingAmount.Valid {
		e.OutstandingAmount = remainingAmount.Float64
	}
	if paymentStatus.Valid {
		e.PaymentStatus = paymentStatus.String
	}
	return &e, nil
}

func (r *loanRepository) scanEMIs(rows *sql.Rows) ([]models.EmiTransaction, error) {
	var emis []models.EmiTransaction
	for rows.Next() {
		e, err := r.scanEMI(rows)
		if err != nil {
			return nil, err
		}
		if e != nil {
			emis = append(emis, *e)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return emis, nil
}

// ---------------------------------------------------------------------
// Helper null converters (unchanged)4
// ---------------------------------------------------------------------

func nullFloat64(f *float64) sql.NullFloat64 {
	if f == nil {
		return sql.NullFloat64{Valid: false}
	}
	return sql.NullFloat64{Float64: *f, Valid: true}
}
func (r *loanRepository) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	return r.client.BeginTx(ctx, opts)
}
