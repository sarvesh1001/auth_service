package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"auth-service/internal/client"
	hrErrors "auth-service/internal/hr/errors"
	"auth-service/internal/hr/payroll/models"
)

type LoanRepository interface {
	GetEMIByID(ctx context.Context, emiID uuid.UUID) (*models.EmiTransaction, error)
	UpdateEMI(ctx context.Context, emi *models.EmiTransaction) error
	CreateEMI(ctx context.Context, emi *models.EmiTransaction) error
	GetPendingEMIsForLoan(ctx context.Context, loanID uuid.UUID) ([]models.EmiTransaction, error)
	GetEMIsForPayrollRun(ctx context.Context, payrollRunID uuid.UUID, locationID *uuid.UUID) ([]models.EmiTransaction, error)
	MarkEMIAsPaid(ctx context.Context, emiID uuid.UUID, paidDate time.Time, paidAmount, penalty float64, payrollRunID *uuid.UUID) error
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)

	GetPendingEMIsForEmployeeInPeriod(ctx context.Context, companyID, userID uuid.UUID, startDate, endDate time.Time) ([]models.EmiTransaction, error)
	GetPendingEMIsForEmployeeInPeriodWithDetails(ctx context.Context, companyID, userID uuid.UUID, startDate, endDate time.Time) ([]LoanEmiDetail, error)

	CreateLoan(ctx context.Context, loan *models.EmployeeLoan) error
	UpdateLoan(ctx context.Context, loan *models.EmployeeLoan) error
	GetLoanByID(ctx context.Context, loanID uuid.UUID) (*models.EmployeeLoan, error)
	ListLoansByUser(ctx context.Context, companyID, userID uuid.UUID, includeClosed bool) ([]models.EmployeeLoan, error)
	ListActiveLoans(ctx context.Context, companyID uuid.UUID, asOf time.Time, locationID *uuid.UUID) ([]models.EmployeeLoan, error)

	CreateLoanPayment(ctx context.Context, payment *models.LoanPayment) error
	ListLoanPayments(ctx context.Context, loanID uuid.UUID) ([]models.LoanPayment, error)
	ListLoanPaymentsByPayrollRun(ctx context.Context, payrollRunID uuid.UUID) ([]models.LoanPayment, error)
	ApplyLoanPayment(ctx context.Context, loanID uuid.UUID, amount float64) error
	ProcessEMIPaymentTx(ctx context.Context, tx *sql.Tx, emiID uuid.UUID, loanID uuid.UUID, paidDate time.Time, paidAmount float64, penalty float64, payrollRunID *uuid.UUID, source string) error
}

type loanRepository struct {
	client *client.PostgresClient
}

func NewLoanRepository(postgresClient *client.PostgresClient) LoanRepository {
	return &loanRepository{
		client: postgresClient,
	}
}

// ---------------------------------------------------------------------
// Loan methods
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
			component_id,
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
		nullUUID(loan.ComponentID),
		loan.CreatedAt,
		nullUUID(loan.CreatedBy),
	)
	if err != nil {
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
			component_id = $13
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
		nullUUID(loan.ComponentID),
		loan.LoanID,
	)
	if err != nil {
		return fmt.Errorf("failed to update loan: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return hrErrors.ErrLoanNotFound
	}
	return nil
}

func (r *loanRepository) GetLoanByID(ctx context.Context, loanID uuid.UUID) (*models.EmployeeLoan, error) {
	query := `
		SELECT
			l.loan_id, l.company_id, l.user_id, l.loan_type,
			l.principal_amount, l.emi_amount, l.interest_rate,
			l.interest_type,
			l.total_emis, l.emis_paid,
			l.outstanding_balance,
			l.disbursed_at,
			l.first_emi_date,
			l.closure_date,
			l.status,
			l.component_id,
			pc.component_code,
			l.created_at,
			l.created_by
		FROM payroll.employee_loan l
		LEFT JOIN payroll.payroll_component pc ON pc.component_id = l.component_id
		WHERE l.loan_id = $1
	`

	row := r.client.QueryRow(ctx, query, loanID)
	loan, err := r.scanLoan(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, hrErrors.ErrLoanNotFound
		}
		return nil, err
	}
	return loan, nil
}

func (r *loanRepository) ListLoansByUser(ctx context.Context, companyID, userID uuid.UUID, includeClosed bool) ([]models.EmployeeLoan, error) {
	query := `
		SELECT
			l.loan_id, l.company_id, l.user_id, l.loan_type,
			l.principal_amount, l.emi_amount, l.interest_rate,
			l.interest_type,
			l.total_emis, l.emis_paid,
			l.outstanding_balance,
			l.disbursed_at,
			l.first_emi_date,
			l.closure_date,
			l.status,
			l.component_id,
			pc.component_code,
			l.created_at,
			l.created_by
		FROM payroll.employee_loan l
		LEFT JOIN payroll.payroll_component pc ON pc.component_id = l.component_id
		WHERE l.company_id = $1 AND l.user_id = $2
	`
	args := []interface{}{companyID, userID}
	if !includeClosed {
		query += " AND l.status = 'active'"
	}
	query += " ORDER BY l.disbursed_at DESC"

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list loans: %w", err)
	}
	defer rows.Close()
	return r.scanLoans(rows)
}

func (r *loanRepository) ListActiveLoans(
	ctx context.Context,
	companyID uuid.UUID,
	asOf time.Time,
	locationID *uuid.UUID,
) ([]models.EmployeeLoan, error) {
	query := `
		SELECT
			l.loan_id, l.company_id, l.user_id, l.loan_type,
			l.principal_amount, l.emi_amount, l.interest_rate,
			l.interest_type,
			l.total_emis, l.emis_paid,
			l.outstanding_balance,
			l.disbursed_at,
			l.first_emi_date,
			l.closure_date,
			l.status,
			l.component_id,
			pc.component_code,
			l.created_at,
			l.created_by
		FROM payroll.employee_loan l
		LEFT JOIN payroll.payroll_component pc ON pc.component_id = l.component_id
		WHERE l.company_id = $1
		  AND l.status = 'active'
		  AND l.disbursed_at <= $2
		  AND (l.closure_date IS NULL OR l.closure_date >= $2)
		  AND ($3::uuid IS NULL OR l.user_id IN (
			  SELECT user_id FROM company_employees
			  WHERE company_id = $1 AND primary_location_id = $3 AND is_active = true
		  ))
		ORDER BY l.user_id, l.disbursed_at
	`

	rows, err := r.client.Query(ctx, query, companyID, asOf, locationID)
	if err != nil {
		return nil, fmt.Errorf("failed to list active loans: %w", err)
	}
	defer rows.Close()
	return r.scanLoans(rows)
}

// ---------------------------------------------------------------------
// Loan Payment application
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
		return fmt.Errorf("failed to apply loan payment: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return hrErrors.ErrLoanNotFound
	}
	return nil
}

// ---------------------------------------------------------------------
// Atomic EMI Payment Processing
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

	autoClose := `
	UPDATE payroll.employee_loan
	SET
		status = 'closed',
		closure_date = NOW()
	WHERE loan_id = $1
	AND outstanding_balance <= 0
	`
	_, _ = tx.ExecContext(ctx, autoClose, loanID)

	return nil
}

// ---------------------------------------------------------------------
// EMI methods
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

	_, err := r.client.Exec(ctx, query,
		emi.EmiID,
		emi.LoanID,
		emi.DueDate,
		nullTime(emi.PaidDate),
		emi.Amount,
		emi.PaidAmount,
		emi.PenaltyAmount,
		emi.OutstandingAmount,
		emi.PaymentStatus,
		nullUUID(emi.PayrollRunID),
		emi.Status,
	)
	if err != nil {
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
		return nil, fmt.Errorf("failed to get pending EMIs: %w", err)
	}
	defer rows.Close()
	return r.scanEMIs(rows)
}

func (r *loanRepository) GetEMIsForPayrollRun(
	ctx context.Context,
	payrollRunID uuid.UUID,
	locationID *uuid.UUID,
) ([]models.EmiTransaction, error) {
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
		  AND ($2::uuid IS NULL OR l.user_id IN (
			  SELECT user_id FROM company_employees
			  WHERE company_id = l.company_id AND primary_location_id = $2 AND is_active = true
		  ))
	`

	rows, err := r.client.Query(ctx, query, payrollRunID, locationID)
	if err != nil {
		return nil, fmt.Errorf("failed to get EMIs for payroll run: %w", err)
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
		return fmt.Errorf("failed to mark EMI as paid: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return hrErrors.ErrEMINotFound
	}
	return nil
}

// ---------------------------------------------------------------------
// EMI retrieval with loan details
// ---------------------------------------------------------------------

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
			pc.component_code
		FROM payroll.emi_transaction e
		JOIN payroll.employee_loan l ON e.loan_id = l.loan_id
		LEFT JOIN payroll.payroll_component pc ON pc.component_id = l.component_id
		WHERE l.company_id = $1
		  AND l.user_id = $2
		  AND e.status = 'pending'
		  AND e.due_date BETWEEN $3 AND $4
		ORDER BY e.due_date
	`

	rows, err := r.client.Query(ctx, query, companyID, userID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending EMIs with details: %w", err)
	}
	defer rows.Close()

	var details []LoanEmiDetail
	for rows.Next() {
		var e models.EmiTransaction
		var paidDate sql.NullTime
		var payrollRunID uuid.NullUUID
		var compCode sql.NullString
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
			ComponentCode: compCode.String,
		})
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return details, nil
}

// ---------------------------------------------------------------------
// Legacy EMI retrieval (no component code)
// ---------------------------------------------------------------------

func (r *loanRepository) GetPendingEMIsForEmployeeInPeriod(
	ctx context.Context,
	companyID, userID uuid.UUID,
	startDate, endDate time.Time,
) ([]models.EmiTransaction, error) {
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
		return nil, fmt.Errorf("failed to get pending EMIs: %w", err)
	}
	defer rows.Close()
	return r.scanEMIs(rows)
}

// ---------------------------------------------------------------------
// Basic EMI retrieval and update
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
	emi, err := r.scanEMI(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, hrErrors.ErrEMINotFound
		}
		return nil, err
	}
	return emi, nil
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
	result, err := r.client.Exec(ctx, query,
		nullTime(emi.PaidDate),
		emi.PaidAmount,
		emi.PenaltyAmount,
		emi.OutstandingAmount,
		emi.PaymentStatus,
		nullUUID(emi.PayrollRunID),
		emi.Status,
		emi.EmiID,
	)
	if err != nil {
		return fmt.Errorf("failed to update EMI: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return hrErrors.ErrEMINotFound
	}
	return nil
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
// Scanning helpers
// ---------------------------------------------------------------------

func (r *loanRepository) scanLoan(row scanner) (*models.EmployeeLoan, error) {
	var l models.EmployeeLoan
	var interestRate sql.NullFloat64
	var interestType sql.NullString
	var outstandingBalance sql.NullFloat64
	var closureDate sql.NullTime
	var componentID uuid.NullUUID
	var componentCode sql.NullString
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
		&componentID,
		&componentCode,
		&l.CreatedAt,
		&createdBy,
	)
	if err != nil {
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
	if componentID.Valid {
		id := componentID.UUID
		l.ComponentID = &id
	}
	if componentCode.Valid {
		l.ComponentCode = componentCode.String
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
// Helper null converters
// ---------------------------------------------------------------------

func nullFloat64(f *float64) sql.NullFloat64 {
	if f == nil {
		return sql.NullFloat64{Valid: false}
	}
	return sql.NullFloat64{Float64: *f, Valid: true}
}

// ---------------------------------------------------------------------
// Transaction support
// ---------------------------------------------------------------------

func (r *loanRepository) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	return r.client.BeginTx(ctx, opts)
}
