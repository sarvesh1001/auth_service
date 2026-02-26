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

type employeeFineRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

// NewEmployeeFineRepository creates a new EmployeeFineRepository instance.
func NewEmployeeFineRepository(
	postgresClient *client.PostgresClient,
	logger *zap.Logger,
) EmployeeFineRepository {
	return &employeeFineRepository{
		client: postgresClient,
		logger: logger,
	}
}

// ---------------------------------------------------------------------
// Create & Update
// ---------------------------------------------------------------------

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
			created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
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
	)
	if err != nil {
		r.logger.Error("Failed to create employee fine",
			util.String("fine_id", fine.FineID.String()),
			util.String("company_id", fine.CompanyID.String()),
			util.String("user_id", fine.UserID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to create employee fine: %w", err)
	}
	return nil
}

func (r *employeeFineRepository) Update(ctx context.Context, fine *models.EmployeeFine) error {
	// Note: we do not update created_at, created_by
	query := `
		UPDATE payroll.employee_fine
		SET
			fine_amount = $1,
			reason = $2,
			fine_date = $3,
			is_processed = $4,
			payroll_run_id = $5
		WHERE fine_id = $6 AND company_id = $7
	`
	result, err := r.client.Exec(ctx, query,
		fine.FineAmount,
		fine.Reason,
		fine.FineDate,
		fine.IsProcessed,
		fine.PayrollRunID,
		fine.FineID,
		fine.CompanyID,
	)
	if err != nil {
		r.logger.Error("Failed to update employee fine",
			util.String("fine_id", fine.FineID.String()),
			util.String("company_id", fine.CompanyID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to update employee fine: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("employee fine not found for company")
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
		r.logger.Error("Failed to mark fine as processed",
			util.String("fine_id", fineID.String()),
			util.String("payroll_run_id", payrollRunID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to mark fine as processed: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("fine not found or already processed")
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
	result, err := r.client.Exec(ctx, query, payrollRunID, pq.Array(fineIDs))
	if err != nil {
		r.logger.Error("Failed to bulk mark fines as processed",
			util.String("payroll_run_id", payrollRunID.String()),
			util.Int("count", len(fineIDs)),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to bulk mark fines as processed: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	r.logger.Info("Bulk marked fines as processed",
		util.Int64("rows_affected", rowsAffected),
	)
	return nil
}

// ---------------------------------------------------------------------
// Retrieval
// ---------------------------------------------------------------------

func (r *employeeFineRepository) GetByID(
	ctx context.Context,
	companyID, fineID uuid.UUID,
) (*models.EmployeeFine, error) {
	query := `
		SELECT
			fine_id,
			company_id,
			user_id,
			fine_amount,
			reason,
			fine_date,
			is_processed,
			payroll_run_id,
			created_at,
			created_by
		FROM payroll.employee_fine
		WHERE fine_id = $1 AND company_id = $2
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
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get employee fine by ID",
			util.String("fine_id", fineID.String()),
			util.String("company_id", companyID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get employee fine: %w", err)
	}
	return &fine, nil
}

func (r *employeeFineRepository) GetByFilter(
	ctx context.Context,
	filter models.EmployeeFineFilter,
) ([]models.EmployeeFine, int, error) {
	whereClause := "WHERE company_id = $1"
	args := []interface{}{filter.CompanyID}
	paramIdx := 2

	if filter.UserID != nil {
		whereClause += fmt.Sprintf(" AND user_id = $%d", paramIdx)
		args = append(args, *filter.UserID)
		paramIdx++
	}
	if filter.IsProcessed != nil {
		whereClause += fmt.Sprintf(" AND is_processed = $%d", paramIdx)
		args = append(args, *filter.IsProcessed)
		paramIdx++
	}
	if filter.PayrollRunID != nil {
		whereClause += fmt.Sprintf(" AND payroll_run_id = $%d", paramIdx)
		args = append(args, *filter.PayrollRunID)
		paramIdx++
	}
	if filter.FromDate != nil {
		whereClause += fmt.Sprintf(" AND fine_date >= $%d", paramIdx)
		args = append(args, *filter.FromDate)
		paramIdx++
	}
	if filter.ToDate != nil {
		whereClause += fmt.Sprintf(" AND fine_date <= $%d", paramIdx)
		args = append(args, *filter.ToDate)
		paramIdx++
	}

	// Count total
	countQuery := `SELECT COUNT(*) FROM payroll.employee_fine ` + whereClause
	var total int
	err := r.client.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		r.logger.Error("Failed to count employee fines by filter",
			util.String("company_id", filter.CompanyID.String()),
			util.ErrorField(err),
		)
		return nil, 0, fmt.Errorf("failed to count employee fines: %w", err)
	}
	if total == 0 {
		return []models.EmployeeFine{}, 0, nil
	}

	// Fetch data
	query := `
		SELECT
			fine_id,
			company_id,
			user_id,
			fine_amount,
			reason,
			fine_date,
			is_processed,
			payroll_run_id,
			created_at,
			created_by
		FROM payroll.employee_fine
	` + whereClause + ` ORDER BY fine_date DESC`

	if filter.Page > 0 && filter.PageSize > 0 {
		offset := (filter.Page - 1) * filter.PageSize
		query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", paramIdx, paramIdx+1)
		args = append(args, filter.PageSize, offset)
	} else {
		// default limit
		query += fmt.Sprintf(" LIMIT $%d", paramIdx)
		args = append(args, 100)
	}

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		r.logger.Error("Failed to get employee fines by filter",
			util.String("company_id", filter.CompanyID.String()),
			util.ErrorField(err),
		)
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
			fine_id,
			company_id,
			user_id,
			fine_amount,
			reason,
			fine_date,
			is_processed,
			payroll_run_id,
			created_at,
			created_by
		FROM payroll.employee_fine
		WHERE company_id = $1
			AND user_id = $2
			AND is_processed = false
			AND fine_date BETWEEN $3 AND $4
		ORDER BY fine_date
	`
	rows, err := r.client.Query(ctx, query, companyID, userID, periodStart, periodEnd)
	if err != nil {
		r.logger.Error("Failed to get unprocessed fines by user and period",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.ErrorField(err),
		)
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
) ([]models.EmployeeFine, error) {
	query := `
		SELECT
			fine_id,
			company_id,
			user_id,
			fine_amount,
			reason,
			fine_date,
			is_processed,
			payroll_run_id,
			created_at,
			created_by
		FROM payroll.employee_fine
		WHERE company_id = $1
			AND is_processed = false
			AND fine_date BETWEEN $2 AND $3
		ORDER BY user_id, fine_date
	`
	rows, err := r.client.Query(ctx, query, companyID, periodStart, periodEnd)
	if err != nil {
		r.logger.Error("Failed to get unprocessed fines by company and period",
			util.String("company_id", companyID.String()),
			util.ErrorField(err),
		)
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

// ---------------------------------------------------------------------
// Run Safety
// ---------------------------------------------------------------------

func (r *employeeFineRepository) LockUnprocessedForPayrollRun(
	ctx context.Context,
	companyID uuid.UUID,
	periodStart, periodEnd time.Time,
	payrollRunID uuid.UUID,
) ([]models.EmployeeFine, error) {
	// Atomically update and return the fines that become processed.
	// This locks the rows and prevents double‑processing.
	query := `
		UPDATE payroll.employee_fine
		SET
			is_processed = true,
			payroll_run_id = $1
		WHERE company_id = $2
			AND is_processed = false
			AND fine_date BETWEEN $3 AND $4
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
			created_by
	`
	rows, err := r.client.Query(ctx, query, payrollRunID, companyID, periodStart, periodEnd)
	if err != nil {
		r.logger.Error("Failed to lock and mark fines for payroll run",
			util.String("company_id", companyID.String()),
			util.String("payroll_run_id", payrollRunID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to lock unprocessed fines: %w", err)
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

// ---------------------------------------------------------------------
// Audit / Integrity
// ---------------------------------------------------------------------

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
		r.logger.Error("Failed to delete unprocessed fine",
			util.String("fine_id", fineID.String()),
			util.String("company_id", companyID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to delete fine: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("fine not found or already processed")
	}
	return nil
}
