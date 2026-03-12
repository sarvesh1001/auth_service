package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/util"
)

// ArrearsRepository defines operations for payroll arrears.
type ArrearsRepository interface {
	// Create inserts a new arrears record.
	Create(ctx context.Context, arrears *models.Arrears) error
	// GetUnprocessedByUser retrieves all unprocessed arrears for a specific user.
	GetUnprocessedByUser(ctx context.Context, companyID, userID uuid.UUID) ([]models.Arrears, error)
	// GetUnprocessedForPayrollRun retrieves all unprocessed arrears for a company within a period.
	GetUnprocessedForPayrollRun(ctx context.Context, companyID uuid.UUID, periodStart, periodEnd time.Time) ([]models.Arrears, error)
	// MarkAsProcessed updates an arrears record to processed and links it to a payroll run.
	MarkAsProcessed(ctx context.Context, arrearsID uuid.UUID, payrollRunID uuid.UUID) error
}

type arrearsRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

// NewArrearsRepository creates a new arrears repository.
func NewArrearsRepository(postgresClient *client.PostgresClient, logger *zap.Logger) ArrearsRepository {
	return &arrearsRepository{
		client: postgresClient,
		logger: logger.Named("arrears_repo"),
	}
}

// Create inserts a new arrears record with component code.
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
			component_code
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
		arrears.ComponentCode, // new column
	)
	if err != nil {
		r.logger.Error("Failed to create arrears",
			util.String("arrears_id", arrears.ArrearsID.String()),
			util.String("company_id", arrears.CompanyID.String()),
			util.String("user_id", arrears.UserID.String()),
			util.String("component_code", arrears.ComponentCode),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to create arrears: %w", err)
	}
	return nil
}

// GetUnprocessedByUser retrieves all unprocessed arrears for a specific user.
func (r *arrearsRepository) GetUnprocessedByUser(ctx context.Context, companyID, userID uuid.UUID) ([]models.Arrears, error) {
	query := `
		SELECT
			arrears_id, company_id, user_id, payroll_run_id,
			effective_from, effective_to, amount, reason, processed, created_at,
			component_code
		FROM payroll.arrears
		WHERE company_id = $1 AND user_id = $2 AND processed = false
		ORDER BY effective_from ASC
	`
	rows, err := r.client.Query(ctx, query, companyID, userID)
	if err != nil {
		r.logger.Error("Failed to get unprocessed arrears by user",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get unprocessed arrears: %w", err)
	}
	defer rows.Close()

	var arrearsList []models.Arrears
	for rows.Next() {
		var a models.Arrears
		var payrollRunID uuid.NullUUID
		var reason sql.NullString
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
			arrears_id, company_id, user_id, payroll_run_id,
			effective_from, effective_to, amount, reason, processed, created_at,
			component_code
		FROM payroll.arrears
		WHERE company_id = $1
			AND processed = false
			AND effective_from <= $3   -- arrears start on or before period end
			AND effective_to >= $2      -- arrears end on or after period start
		ORDER BY user_id, effective_from
	`
	rows, err := r.client.Query(ctx, query, companyID, periodStart, periodEnd)
	if err != nil {
		r.logger.Error("Failed to get unprocessed arrears for payroll run",
			util.String("company_id", companyID.String()),
			util.Time("period_start", periodStart),
			util.Time("period_end", periodEnd),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get unprocessed arrears: %w", err)
	}
	defer rows.Close()

	var arrearsList []models.Arrears
	for rows.Next() {
		var a models.Arrears
		var payrollRunID uuid.NullUUID
		var reason sql.NullString
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
		r.logger.Error("Failed to mark arrears as processed",
			util.String("arrears_id", arrearsID.String()),
			util.String("payroll_run_id", payrollRunID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to mark arrears as processed: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("arrears not found or already processed")
	}
	return nil
}
