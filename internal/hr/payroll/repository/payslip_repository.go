package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/util"
)

type PayslipRepository interface {
	GetPayslipData(ctx context.Context, runID, userID uuid.UUID) (*models.PayslipData, error)
	GetPayslipTemplate(ctx context.Context, companyID uuid.UUID) (*models.PayslipTemplate, error)
	ListPayrollRunsForUser(ctx context.Context, companyID, userID uuid.UUID, from, to time.Time) ([]models.PayrollRunSummary, error)
	GetEmployeeEmail(ctx context.Context, companyID, userID uuid.UUID) (string, error)
}

type payslipRepository struct {
	db     *client.PostgresClient
	logger *zap.Logger
}

func NewPayslipRepository(db *client.PostgresClient, logger *zap.Logger) PayslipRepository {
	return &payslipRepository{
		db:     db,
		logger: logger.Named("payslip_repo"),
	}
}

// GetPayslipData fetches all data required to generate a payslip.
func (r *payslipRepository) GetPayslipData(ctx context.Context, runID, userID uuid.UUID) (*models.PayslipData, error) {
	mainQuery := `
		SELECT
			c.company_id,
			c.company_name,
			u.user_id,
			u.full_name AS employee_name,
			ce.employee_id,
			COALESCE(d.department_name, '') AS department,
			COALESCE(p.title, '') AS position,
			pr.payroll_run_id,
			pr.period_start,
			pr.period_end,
			pi.gross_amount,
			pi.net_amount,
			pt.footer_declaration,
			pt.authorized_signatory
		FROM payroll.payroll_run pr
		JOIN companies c ON c.company_id = pr.company_id
		JOIN payroll.payroll_item pi ON pi.payroll_run_id = pr.payroll_run_id AND pi.user_id = $2
		JOIN users u ON u.user_id = pi.user_id
		JOIN company_employees ce ON ce.company_id = pr.company_id AND ce.user_id = pi.user_id
		LEFT JOIN positions p ON p.position_id = ce.position_id
		LEFT JOIN departments d ON d.department_id = p.department_id
		LEFT JOIN payroll.payslip_template pt ON pt.company_id = c.company_id
		WHERE pr.payroll_run_id = $1
	`
	var data models.PayslipData
	var footerDecl, authSign sql.NullString
	err := r.db.QueryRow(ctx, mainQuery, runID, userID).Scan(
		&data.CompanyID,
		&data.CompanyName,
		&data.UserID,
		&data.EmployeeName,
		&data.EmployeeID,
		&data.Department,
		&data.Position,
		&data.PayrollRunID,
		&data.PeriodStart,
		&data.PeriodEnd,
		&data.GrossAmount,
		&data.NetAmount,
		&footerDecl,
		&authSign,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to fetch payslip data",
			util.String("run_id", runID.String()),
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get payslip data: %w", err)
	}
	if footerDecl.Valid {
		data.FooterDeclaration = footerDecl.String
	}
	if authSign.Valid {
		data.AuthorizedSignatory = authSign.String
	}
	data.GeneratedAt = time.Now().UTC()

	// Updated ledger query using LATERAL join to pick company‑specific or global component definition
	ledgerQuery := `
		SELECT
			pl.component_code,
			COALESCE(pc.description, pl.component_code) AS description,
			pl.amount,
			COALESCE(pc.component_type, 'earning') AS component_type
		FROM payroll.payroll_ledger pl
		JOIN payroll.payroll_item pi ON pi.payroll_item_id = pl.payroll_item_id
		JOIN payroll.payroll_run pr ON pr.payroll_run_id = pi.payroll_run_id
		LEFT JOIN LATERAL (
			SELECT description, component_type
			FROM payroll.payroll_component pc
			WHERE pc.component_code = pl.component_code
			  AND (pc.company_id = pr.company_id OR pc.company_id IS NULL)
			ORDER BY pc.company_id NULLS LAST   -- company‑specific first
			LIMIT 1
		) pc ON true
		WHERE pi.payroll_run_id = $1
		  AND pi.user_id = $2
		  AND pi.is_superseded = false
	`
	rows, err := r.db.Query(ctx, ledgerQuery, runID, userID)
	if err != nil {
		return nil, fmt.Errorf("get ledger entries: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var comp models.PayslipComponent
		var compType string
		if err := rows.Scan(&comp.Code, &comp.Description, &comp.Amount, &compType); err != nil {
			return nil, fmt.Errorf("scan ledger: %w", err)
		}
		if compType == "earning" {
			data.Earnings = append(data.Earnings, comp)
		} else {
			data.Deductions = append(data.Deductions, comp)
		}
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}

	bank, err := r.getActiveBankDetails(ctx, data.CompanyID, userID, data.PeriodEnd)
	if err != nil {
		r.logger.Warn("failed to fetch bank details, continuing without",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
	} else if bank != nil {
		data.BankDetails = &struct {
			AccountHolder string
			AccountNumber string
			IFSCCode      string
			BankName      string
		}{
			AccountHolder: bank.AccountHolder,
			AccountNumber: bank.AccountNumber,
			IFSCCode:      bank.IFSCCode,
			BankName:      bank.BankName,
		}
	}

	return &data, nil
}

// getActiveBankDetails returns the bank details active on the given date.
func (r *payslipRepository) getActiveBankDetails(ctx context.Context, companyID, userID uuid.UUID, asOf time.Time) (*models.EmployeeBankDetails, error) {
	query := `
		SELECT
			bank_detail_id, company_id, user_id,
			account_holder, account_number, ifsc_code,
			bank_name, branch, account_type,
			is_active, effective_from, effective_to,
			created_at, updated_at
		FROM payroll.employee_bank_details
		WHERE company_id = $1
		  AND user_id = $2
		  AND is_active = true
		  AND effective_from <= $3
		  AND (effective_to IS NULL OR effective_to >= $3)
		ORDER BY effective_from DESC
		LIMIT 1
	`
	row := r.db.QueryRow(ctx, query, companyID, userID, asOf)
	return scanBankDetails(row)
}

func scanBankDetails(row interface{ Scan(...interface{}) error }) (*models.EmployeeBankDetails, error) {
	var b models.EmployeeBankDetails
	var effectiveTo sql.NullTime
	var createdAt, updatedAt time.Time

	err := row.Scan(
		&b.BankDetailID,
		&b.CompanyID,
		&b.UserID,
		&b.AccountHolder,
		&b.AccountNumber,
		&b.IFSCCode,
		&b.BankName,
		&b.Branch,
		&b.AccountType,
		&b.IsActive,
		&b.EffectiveFrom,
		&effectiveTo,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if effectiveTo.Valid {
		b.EffectiveTo = &effectiveTo.Time
	}
	b.CreatedAt = createdAt
	b.UpdatedAt = updatedAt
	return &b, nil
}

// GetPayslipTemplate returns the company's payslip template (if any).
func (r *payslipRepository) GetPayslipTemplate(ctx context.Context, companyID uuid.UUID) (*models.PayslipTemplate, error) {
	query := `
		SELECT template_id, company_id, template_name, footer_declaration, authorized_signatory, created_at
		FROM payroll.payslip_template
		WHERE company_id = $1
		ORDER BY created_at DESC
		LIMIT 1
	`
	row := r.db.QueryRow(ctx, query, companyID)
	var t models.PayslipTemplate
	var footer, auth sql.NullString
	err := row.Scan(
		&t.TemplateID,
		&t.CompanyID,
		&t.TemplateName,
		&footer,
		&auth,
		&t.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get payslip template",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get payslip template: %w", err)
	}
	if footer.Valid {
		t.FooterDeclaration = &footer.String
	}
	if auth.Valid {
		t.AuthorizedSignatory = &auth.String
	}
	return &t, nil
}

// ListPayrollRunsForUser returns summary information for payroll runs where the user has an item.
func (r *payslipRepository) ListPayrollRunsForUser(ctx context.Context, companyID, userID uuid.UUID, from, to time.Time) ([]models.PayrollRunSummary, error) {
	conditions := []string{"pr.company_id = $1", "pi.user_id = $2"}
	args := []interface{}{companyID, userID}
	argIdx := 3

	if !from.IsZero() {
		conditions = append(conditions, fmt.Sprintf("pr.period_start >= $%d", argIdx))
		args = append(args, from)
		argIdx++
	}
	if !to.IsZero() {
		conditions = append(conditions, fmt.Sprintf("pr.period_end <= $%d", argIdx))
		args = append(args, to)
		argIdx++
	}
	whereClause := strings.Join(conditions, " AND ")

	query := fmt.Sprintf(`
		SELECT
			pr.payroll_run_id,
			pr.period_start,
			pr.period_end,
			pr.status,
			pr.created_at,
			pi.gross_amount AS total_gross,
			pi.net_amount   AS total_net,
			pi.payable_days,
			pi.unpaid_days
		FROM payroll.payroll_run pr
		JOIN payroll.payroll_item pi ON pi.payroll_run_id = pr.payroll_run_id
		WHERE %s
		ORDER BY pr.period_start DESC
	`, whereClause)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list payroll runs for user",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("list payroll runs: %w", err)
	}
	defer rows.Close()

	var summaries []models.PayrollRunSummary
	for rows.Next() {
		var s models.PayrollRunSummary
		// payable_days and unpaid_days are scanned into placeholders (we ignore them)
		var payableDays, unpaidDays float64
		if err := rows.Scan(
			&s.PayrollRunID,
			&s.PeriodStart,
			&s.PeriodEnd,
			&s.Status,
			&s.CreatedAt,
			&s.TotalGross,
			&s.TotalNet,
			&payableDays,
			&unpaidDays,
		); err != nil {
			return nil, fmt.Errorf("scan run summary: %w", err)
		}
		summaries = append(summaries, s)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return summaries, nil
}
func (r *payslipRepository) GetEmployeeEmail(ctx context.Context, companyID, userID uuid.UUID) (string, error) {
	logger := r.logger.With(
		zap.String("method", "GetEmployeeEmail"),
		zap.String("company_id", companyID.String()),
		zap.String("user_id", userID.String()),
	)
	query := `SELECT email FROM employee_profiles WHERE company_id = $1 AND user_id = $2`
	logger.Debug("executing query", zap.String("query", query))

	var email string
	err := r.db.QueryRow(ctx, query, companyID, userID).Scan(&email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.Warn("employee profile not found")
			return "", fmt.Errorf("employee profile not found for company %s user %s", companyID, userID)
		}
		logger.Error("failed to scan email", zap.Error(err))
		return "", fmt.Errorf("get employee email: %w", err)
	}

	logger.Debug("retrieved email", zap.String("email", email))
	if email == "" {
		logger.Warn("email address is empty")
		return "", fmt.Errorf("email address not set for employee")
	}
	return email, nil
}
