package repository

import (
	"auth-service/internal/client"
	hrErrors "auth-service/internal/hr/errors"
	"auth-service/internal/hr/payroll/models"
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type ArrearsRepository interface {
	Create(ctx context.Context, arrears *models.Arrears) error
	GetUnprocessedByUser(ctx context.Context, companyID, userID uuid.UUID) ([]models.Arrears, error)
	GetUnprocessedForPayrollRun(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time) ([]models.Arrears, error)
	MarkAsProcessed(ctx context.Context, arrearsID uuid.UUID, payrollRunID uuid.UUID) error
}

type arrearsRepository struct {
	client *client.PostgresClient
}

func NewArrearsRepository(postgresClient *client.PostgresClient) ArrearsRepository {
	return &arrearsRepository{
		client: postgresClient,
	}
}

// Create inserts a new arrears record with component_id.
func (r *arrearsRepository) Create(ctx context.Context, arrears *models.Arrears) error {
	if arrears.ArrearsID == uuid.Nil {
		arrears.ArrearsID = uuid.New()
	}
	if arrears.CreatedAt.IsZero() {
		arrears.CreatedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO payroll.arrears (
			arrears_id, company_id, user_id, payroll_run_id,
			effective_from, effective_to, amount, reason, processed, created_at,
			component_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	_, err := r.client.Exec(ctx, query,
		arrears.ArrearsID,
		arrears.CompanyID,
		arrears.UserID,
		nullUUID(arrears.PayrollRunID),
		arrears.EffectiveFrom,
		arrears.EffectiveTo,
		arrears.Amount,
		nullString(arrears.Reason),
		arrears.Processed,
		arrears.CreatedAt,
		arrears.ComponentID,
	)
	if err != nil {
		return fmt.Errorf("failed to create arrears: %w", err)
	}
	return nil
}

// GetUnprocessedByUser retrieves all unprocessed arrears for a specific user.
func (r *arrearsRepository) GetUnprocessedByUser(ctx context.Context, companyID, userID uuid.UUID) ([]models.Arrears, error) {
	query := `
		SELECT
			a.arrears_id, a.company_id, a.user_id, a.payroll_run_id,
			a.effective_from, a.effective_to, a.amount, a.reason, a.processed, a.created_at,
			a.component_id, pc.component_code
		FROM payroll.arrears a
		LEFT JOIN payroll.payroll_component pc ON pc.component_id = a.component_id
		WHERE a.company_id = $1 AND a.user_id = $2 AND a.processed = false
		ORDER BY a.effective_from ASC
	`
	rows, err := r.client.Query(ctx, query, companyID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get unprocessed arrears by user: %w", err)
	}
	defer rows.Close()

	var arrearsList []models.Arrears
	for rows.Next() {
		var a models.Arrears
		var payrollRunID uuid.NullUUID
		var reason sql.NullString
		var componentID uuid.NullUUID
		var componentCode sql.NullString

		if err := rows.Scan(
			&a.ArrearsID,
			&a.CompanyID,
			&a.UserID,
			&payrollRunID,
			&a.EffectiveFrom,
			&a.EffectiveTo,
			&a.Amount,
			&reason,
			&a.Processed,
			&a.CreatedAt,
			&componentID,
			&componentCode,
		); err != nil {
			return nil, fmt.Errorf("failed to scan arrears row: %w", err)
		}
		if payrollRunID.Valid {
			a.PayrollRunID = &payrollRunID.UUID
		}
		if reason.Valid {
			a.Reason = &reason.String
		}
		if componentID.Valid {
			id := componentID.UUID
			a.ComponentID = &id
		}
		if componentCode.Valid {
			a.ComponentCode = componentCode.String
		}
		arrearsList = append(arrearsList, a)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return arrearsList, nil
}

// GetUnprocessedForPayrollRun retrieves all unprocessed arrears for a company
// whose effective period overlaps with the given payroll period.
func (r *arrearsRepository) GetUnprocessedForPayrollRun(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time) ([]models.Arrears, error) {
	query := `
		SELECT
			a.arrears_id, a.company_id, a.user_id, a.payroll_run_id,
			a.effective_from, a.effective_to, a.amount, a.reason, a.processed, a.created_at,
			a.component_id, pc.component_code
		FROM payroll.arrears a
		LEFT JOIN payroll.payroll_component pc ON pc.component_id = a.component_id
		WHERE a.company_id = $1
			AND a.processed = false
			AND a.effective_from <= $3
			AND a.effective_to >= $2
		ORDER BY a.user_id, a.effective_from
	`
	rows, err := r.client.Query(ctx, query, companyID, periodStart, periodEnd)
	if err != nil {
		return nil, fmt.Errorf("failed to get unprocessed arrears for payroll run: %w", err)
	}
	defer rows.Close()

	var arrearsList []models.Arrears
	for rows.Next() {
		var a models.Arrears
		var payrollRunID uuid.NullUUID
		var reason sql.NullString
		var componentID uuid.NullUUID
		var componentCode sql.NullString

		if err := rows.Scan(
			&a.ArrearsID,
			&a.CompanyID,
			&a.UserID,
			&payrollRunID,
			&a.EffectiveFrom,
			&a.EffectiveTo,
			&a.Amount,
			&reason,
			&a.Processed,
			&a.CreatedAt,
			&componentID,
			&componentCode,
		); err != nil {
			return nil, fmt.Errorf("failed to scan arrears row: %w", err)
		}
		if payrollRunID.Valid {
			a.PayrollRunID = &payrollRunID.UUID
		}
		if reason.Valid {
			a.Reason = &reason.String
		}
		if componentID.Valid {
			id := componentID.UUID
			a.ComponentID = &id
		}
		if componentCode.Valid {
			a.ComponentCode = componentCode.String
		}
		arrearsList = append(arrearsList, a)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return arrearsList, nil
}

// MarkAsProcessed updates an arrears record to processed and sets the payroll run ID.
func (r *arrearsRepository) MarkAsProcessed(ctx context.Context, arrearsID uuid.UUID, payrollRunID uuid.UUID) error {
	query := `
		UPDATE payroll.arrears
		SET processed = true, payroll_run_id = $2
		WHERE arrears_id = $1 AND processed = false
	`
	result, err := r.client.Exec(ctx, query, arrearsID, payrollRunID)
	if err != nil {
		return fmt.Errorf("failed to mark arrears as processed: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return hrErrors.ErrArrearsNotFound
	}
	return nil
}
