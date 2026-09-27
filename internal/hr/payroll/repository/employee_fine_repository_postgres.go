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

type employeeFineRepository struct {
	client *client.PostgresClient
}

func NewEmployeeFineRepository(
	postgresClient *client.PostgresClient,
) EmployeeFineRepository {
	return &employeeFineRepository{
		client: postgresClient,
	}
}

// ============================================================================
// CREATE & UPDATE
// ============================================================================

func (r *employeeFineRepository) Create(ctx context.Context, fine *models.EmployeeFine) error {
	if fine.FineID == uuid.Nil {
		fine.FineID = uuid.New()
	}
	if fine.CreatedAt.IsZero() {
		fine.CreatedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO payroll.employee_fine (
			fine_id,
			company_id,
			user_id,
			fine_amount,
			reason,
			fine_date,
			is_processed,
			payroll_run_id,
			created_at,
			created_by,
			component_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	_, err := r.client.Exec(ctx, query,
		fine.FineID,
		fine.CompanyID,
		fine.UserID,
		fine.FineAmount,
		fine.Reason,
		fine.FineDate,
		fine.IsProcessed,
		fine.PayrollRunID,
		fine.CreatedAt,
		fine.CreatedBy,
		fine.ComponentID,
	)
	if err != nil {
		return fmt.Errorf("failed to create employee fine: %w", err)
	}
	return nil
}

func (r *employeeFineRepository) Update(ctx context.Context, fine *models.EmployeeFine) error {
	query := `
		UPDATE payroll.employee_fine
		SET
			fine_amount = $1,
			reason = $2,
			fine_date = $3,
			is_processed = $4,
			payroll_run_id = $5,
			component_id = $6
		WHERE fine_id = $7 AND company_id = $8
	`
	result, err := r.client.Exec(ctx, query,
		fine.FineAmount,
		fine.Reason,
		fine.FineDate,
		fine.IsProcessed,
		fine.PayrollRunID,
		fine.ComponentID,
		fine.FineID,
		fine.CompanyID,
	)
	if err != nil {
		return fmt.Errorf("failed to update employee fine: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return hrErrors.ErrEmployeeFineNotFound
	}
	return nil
}

func (r *employeeFineRepository) MarkAsProcessed(
	ctx context.Context,
	fineID uuid.UUID,
	payrollRunID uuid.UUID,
) error {
	query := `
		UPDATE payroll.employee_fine
		SET
			is_processed = true,
			payroll_run_id = $1
		WHERE fine_id = $2 AND is_processed = false
	`
	result, err := r.client.Exec(ctx, query, payrollRunID, fineID)
	if err != nil {
		return fmt.Errorf("failed to mark fine as processed: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return hrErrors.ErrEmployeeFineNotFound
	}
	return nil
}

func (r *employeeFineRepository) BulkMarkAsProcessed(
	ctx context.Context,
	fineIDs []uuid.UUID,
	payrollRunID uuid.UUID,
) error {
	if len(fineIDs) == 0 {
		return nil
	}
	query := `
		UPDATE payroll.employee_fine
		SET
			is_processed = true,
			payroll_run_id = $1
		WHERE fine_id = ANY($2) AND is_processed = false
	`
	_, err := r.client.Exec(ctx, query, payrollRunID, pq.Array(fineIDs))
	if err != nil {
		return fmt.Errorf("failed to bulk mark fines as processed: %w", err)
	}
	return nil
}

// ============================================================================
// RETRIEVAL
// ============================================================================

func (r *employeeFineRepository) GetByID(
	ctx context.Context,
	companyID, fineID uuid.UUID,
) (*models.EmployeeFine, error) {
	query := `
		SELECT
			f.fine_id,
			f.company_id,
			f.user_id,
			f.fine_amount,
			f.reason,
			f.fine_date,
			f.is_processed,
			f.payroll_run_id,
			f.created_at,
			f.created_by,
			f.component_id,
			pc.component_code
		FROM payroll.employee_fine f
		JOIN payroll.payroll_component pc ON pc.component_id = f.component_id
		WHERE f.fine_id = $1 AND f.company_id = $2
	`
	row := r.client.QueryRow(ctx, query, fineID, companyID)
	var fine models.EmployeeFine
	err := row.Scan(
		&fine.FineID,
		&fine.CompanyID,
		&fine.UserID,
		&fine.FineAmount,
		&fine.Reason,
		&fine.FineDate,
		&fine.IsProcessed,
		&fine.PayrollRunID,
		&fine.CreatedAt,
		&fine.CreatedBy,
		&fine.ComponentID,
		&fine.ComponentCode,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, hrErrors.ErrEmployeeFineNotFound
		}
		return nil, fmt.Errorf("failed to get employee fine: %w", err)
	}
	return &fine, nil
}

func (r *employeeFineRepository) GetByFilter(
	ctx context.Context,
	filter models.EmployeeFineFilter,
) ([]models.EmployeeFine, int, error) {
	whereClause := "WHERE f.company_id = $1"
	args := []interface{}{filter.CompanyID}
	paramIdx := 2

	if filter.UserID != nil {
		whereClause += fmt.Sprintf(" AND f.user_id = $%d", paramIdx)
		args = append(args, *filter.UserID)
		paramIdx++
	}
	if filter.IsProcessed != nil {
		whereClause += fmt.Sprintf(" AND f.is_processed = $%d", paramIdx)
		args = append(args, *filter.IsProcessed)
		paramIdx++
	}
	if filter.PayrollRunID != nil {
		whereClause += fmt.Sprintf(" AND f.payroll_run_id = $%d", paramIdx)
		args = append(args, *filter.PayrollRunID)
		paramIdx++
	}
	if filter.FromDate != nil {
		whereClause += fmt.Sprintf(" AND f.fine_date >= $%d", paramIdx)
		args = append(args, *filter.FromDate)
		paramIdx++
	}
	if filter.ToDate != nil {
		whereClause += fmt.Sprintf(" AND f.fine_date <= $%d", paramIdx)
		args = append(args, *filter.ToDate)
		paramIdx++
	}
	// Location filter — via company_employees (current assignment)
	if filter.LocationID != nil {
		whereClause += fmt.Sprintf(
			" AND f.user_id IN (SELECT user_id FROM company_employees WHERE company_id = $1 AND primary_location_id = $%d AND is_active = true)",
			paramIdx)
		args = append(args, *filter.LocationID)
		paramIdx++
	}

	countQuery := `SELECT COUNT(*) FROM payroll.employee_fine f ` + whereClause
	var total int
	err := r.client.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count employee fines: %w", err)
	}
	if total == 0 {
		return []models.EmployeeFine{}, 0, nil
	}

	query := `
		SELECT
			f.fine_id,
			f.company_id,
			f.user_id,
			f.fine_amount,
			f.reason,
			f.fine_date,
			f.is_processed,
			f.payroll_run_id,
			f.created_at,
			f.created_by,
			f.component_id,
			pc.component_code
		FROM payroll.employee_fine f
		JOIN payroll.payroll_component pc ON pc.component_id = f.component_id
	` + whereClause + ` ORDER BY f.fine_date DESC`

	if filter.Page > 0 && filter.PageSize > 0 {
		offset := (filter.Page - 1) * filter.PageSize
		query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", paramIdx, paramIdx+1)
		args = append(args, filter.PageSize, offset)
	} else {
		query += fmt.Sprintf(" LIMIT $%d", paramIdx)
		args = append(args, 100)
	}

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get employee fines: %w", err)
	}
	defer rows.Close()

	var fines []models.EmployeeFine
	for rows.Next() {
		var f models.EmployeeFine
		if err := rows.Scan(
			&f.FineID,
			&f.CompanyID,
			&f.UserID,
			&f.FineAmount,
			&f.Reason,
			&f.FineDate,
			&f.IsProcessed,
			&f.PayrollRunID,
			&f.CreatedAt,
			&f.CreatedBy,
			&f.ComponentID,
			&f.ComponentCode,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan employee fine: %w", err)
		}
		fines = append(fines, f)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration error: %w", err)
	}
	return fines, total, nil
}

func (r *employeeFineRepository) GetUnprocessedByUserAndPeriod(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	periodStart, periodEnd time.Time,
) ([]models.EmployeeFine, error) {
	query := `
		SELECT
			f.fine_id,
			f.company_id,
			f.user_id,
			f.fine_amount,
			f.reason,
			f.fine_date,
			f.is_processed,
			f.payroll_run_id,
			f.created_at,
			f.created_by,
			f.component_id,
			pc.component_code
		FROM payroll.employee_fine f
		JOIN payroll.payroll_component pc ON pc.component_id = f.component_id
		WHERE f.company_id = $1
			AND f.user_id = $2
			AND f.is_processed = false
			AND f.fine_date BETWEEN $3 AND $4
		ORDER BY f.fine_date
	`
	rows, err := r.client.Query(ctx, query, companyID, userID, periodStart, periodEnd)
	if err != nil {
		return nil, fmt.Errorf("failed to get unprocessed fines: %w", err)
	}
	defer rows.Close()

	var fines []models.EmployeeFine
	for rows.Next() {
		var f models.EmployeeFine
		if err := rows.Scan(
			&f.FineID,
			&f.CompanyID,
			&f.UserID,
			&f.FineAmount,
			&f.Reason,
			&f.FineDate,
			&f.IsProcessed,
			&f.PayrollRunID,
			&f.CreatedAt,
			&f.CreatedBy,
			&f.ComponentID,
			&f.ComponentCode,
		); err != nil {
			return nil, fmt.Errorf("failed to scan employee fine: %w", err)
		}
		fines = append(fines, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return fines, nil
}

func (r *employeeFineRepository) GetUnprocessedByCompanyAndPeriod(
	ctx context.Context,
	companyID uuid.UUID,
	periodStart, periodEnd time.Time,
	locationID *uuid.UUID,
) ([]models.EmployeeFine, error) {
	query := `
		SELECT
			f.fine_id,
			f.company_id,
			f.user_id,
			f.fine_amount,
			f.reason,
			f.fine_date,
			f.is_processed,
			f.payroll_run_id,
			f.created_at,
			f.created_by,
			f.component_id,
			pc.component_code
		FROM payroll.employee_fine f
		JOIN payroll.payroll_component pc ON pc.component_id = f.component_id
		WHERE f.company_id = $1
			AND f.is_processed = false
			AND f.fine_date BETWEEN $2 AND $3
			AND ($4::uuid IS NULL OR f.user_id IN (
				SELECT user_id FROM company_employees
				WHERE company_id = $1 AND primary_location_id = $4 AND is_active = true
			))
		ORDER BY f.user_id, f.fine_date
	`
	rows, err := r.client.Query(ctx, query, companyID, periodStart, periodEnd, locationID)
	if err != nil {
		return nil, fmt.Errorf("failed to get unprocessed fines: %w", err)
	}
	defer rows.Close()

	var fines []models.EmployeeFine
	for rows.Next() {
		var f models.EmployeeFine
		if err := rows.Scan(
			&f.FineID,
			&f.CompanyID,
			&f.UserID,
			&f.FineAmount,
			&f.Reason,
			&f.FineDate,
			&f.IsProcessed,
			&f.PayrollRunID,
			&f.CreatedAt,
			&f.CreatedBy,
			&f.ComponentID,
			&f.ComponentCode,
		); err != nil {
			return nil, fmt.Errorf("failed to scan employee fine: %w", err)
		}
		fines = append(fines, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return fines, nil
}

// ============================================================================
// RUN SAFETY
// ============================================================================

func (r *employeeFineRepository) LockUnprocessedForPayrollRun(
	ctx context.Context,
	companyID uuid.UUID,
	periodStart, periodEnd time.Time,
	payrollRunID uuid.UUID,
	locationID *uuid.UUID,
) ([]models.EmployeeFine, error) {
	query := `
		UPDATE payroll.employee_fine
		SET
			is_processed = true,
			payroll_run_id = $1
		WHERE company_id = $2
			AND is_processed = false
			AND fine_date BETWEEN $3 AND $4
			AND ($5::uuid IS NULL OR user_id IN (
				SELECT user_id FROM company_employees
				WHERE company_id = $2 AND primary_location_id = $5 AND is_active = true
			))
		RETURNING
			fine_id,
			company_id,
			user_id,
			fine_amount,
			reason,
			fine_date,
			is_processed,
			payroll_run_id,
			created_at,
			created_by,
			component_id
	`
	rows, err := r.client.Query(ctx, query, payrollRunID, companyID, periodStart, periodEnd, locationID)
	if err != nil {
		return nil, fmt.Errorf("failed to lock and mark fines for payroll run: %w", err)
	}
	defer rows.Close()

	var fines []models.EmployeeFine
	for rows.Next() {
		var f models.EmployeeFine
		if err := rows.Scan(
			&f.FineID,
			&f.CompanyID,
			&f.UserID,
			&f.FineAmount,
			&f.Reason,
			&f.FineDate,
			&f.IsProcessed,
			&f.PayrollRunID,
			&f.CreatedAt,
			&f.CreatedBy,
			&f.ComponentID,
		); err != nil {
			return nil, fmt.Errorf("failed to scan employee fine: %w", err)
		}
		fines = append(fines, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	// Populate component codes via a second lookup (rare write path; one round trip).
	if len(fines) > 0 {
		ids := make([]uuid.UUID, 0, len(fines))
		for _, f := range fines {
			ids = append(ids, f.ComponentID)
		}
		codeByID, err := r.lookupComponentCodes(ctx, ids)
		if err != nil {
			return nil, err
		}
		for i := range fines {
			fines[i].ComponentCode = codeByID[fines[i].ComponentID]
		}
	}
	return fines, nil
}

func (r *employeeFineRepository) lookupComponentCodes(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]string, error) {
	const q = `SELECT component_id, component_code FROM payroll.payroll_component WHERE component_id = ANY($1)`
	rows, err := r.client.Query(ctx, q, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("lookup component codes: %w", err)
	}
	defer rows.Close()
	out := make(map[uuid.UUID]string, len(ids))
	for rows.Next() {
		var id uuid.UUID
		var code string
		if err := rows.Scan(&id, &code); err != nil {
			return nil, err
		}
		out[id] = code
	}
	return out, rows.Err()
}

// ============================================================================
// AUDIT / INTEGRITY
// ============================================================================

func (r *employeeFineRepository) DeleteIfUnprocessed(
	ctx context.Context,
	companyID, fineID uuid.UUID,
) error {
	query := `
		DELETE FROM payroll.employee_fine
		WHERE fine_id = $1 AND company_id = $2 AND is_processed = false
	`
	result, err := r.client.Exec(ctx, query, fineID, companyID)
	if err != nil {
		return fmt.Errorf("failed to delete fine: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return hrErrors.ErrEmployeeFineNotFound
	}
	return nil
}
