package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/util"
)

// PayslipRepository defines methods for managing payslip records.
type PayslipRepository interface {
	// Create stores a new payslip record.
	Create(ctx context.Context, payslip *models.PayslipRecord) error

	// GetByRunAndUser retrieves a payslip for a specific payroll run and user.
	GetByRunAndUser(ctx context.Context, payrollRunID, userID uuid.UUID) (*models.PayslipRecord, error)

	// ListByRun returns all payslips generated for a given payroll run.
	ListByRun(ctx context.Context, payrollRunID uuid.UUID) ([]models.PayslipRecord, error)

	// ListByUser returns all payslips for a user within a time range (based on generated_at).
	ListByUser(ctx context.Context, companyID, userID uuid.UUID, from, to time.Time) ([]models.PayslipRecord, error)

	// UpdateSentAt marks a payslip as sent by setting the sent_at timestamp.
	UpdateSentAt(ctx context.Context, payslipID uuid.UUID, sentAt time.Time) error
}

// payslipRepository is the Postgres implementation of PayslipRepository.
type payslipRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

// NewPayslipRepository creates a new payslip repository.
func NewPayslipRepository(postgresClient *client.PostgresClient, logger *zap.Logger) PayslipRepository {
	return &payslipRepository{
		client: postgresClient,
		logger: logger,
	}
}

// Create inserts a new payslip record.
func (r *payslipRepository) Create(ctx context.Context, payslip *models.PayslipRecord) error {
	query := `
		INSERT INTO payroll.payslip (
			payslip_id,
			payroll_run_id,
			user_id,
			pdf_object_key,
			generated_at,
			sent_at
		) VALUES ($1, $2, $3, $4, $5, $6)
	`

	// Set defaults if not provided
	if payslip.PayslipID == uuid.Nil {
		payslip.PayslipID = uuid.New()
	}
	if payslip.GeneratedAt.IsZero() {
		payslip.GeneratedAt = time.Now().UTC()
	}

	_, err := r.client.Exec(ctx, query,
		payslip.PayslipID,
		payslip.PayrollRunID,
		payslip.UserID,
		payslip.PDFObjectKey,
		payslip.GeneratedAt,
		nullTime(payslip.SentAt), // helper to convert *time.Time to sql.NullTime
	)
	if err != nil {
		r.logger.Error("Failed to create payslip record",
			util.String("payslip_id", payslip.PayslipID.String()),
			util.String("payroll_run_id", payslip.PayrollRunID.String()),
			util.String("user_id", payslip.UserID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to create payslip: %w", err)
	}
	return nil
}

// GetByRunAndUser retrieves a payslip by payroll run and user.
func (r *payslipRepository) GetByRunAndUser(ctx context.Context, payrollRunID, userID uuid.UUID) (*models.PayslipRecord, error) {
	query := `
		SELECT
			payslip_id,
			payroll_run_id,
			user_id,
			pdf_object_key,
			generated_at,
			sent_at
		FROM payroll.payslip
		WHERE payroll_run_id = $1 AND user_id = $2
	`

	row := r.client.QueryRow(ctx, query, payrollRunID, userID)
	return r.scanPayslip(row)
}

// ListByRun returns all payslips for a payroll run.
func (r *payslipRepository) ListByRun(ctx context.Context, payrollRunID uuid.UUID) ([]models.PayslipRecord, error) {
	query := `
		SELECT
			payslip_id,
			payroll_run_id,
			user_id,
			pdf_object_key,
			generated_at,
			sent_at
		FROM payroll.payslip
		WHERE payroll_run_id = $1
		ORDER BY user_id
	`

	rows, err := r.client.Query(ctx, query, payrollRunID)
	if err != nil {
		r.logger.Error("Failed to list payslips by run",
			util.String("payroll_run_id", payrollRunID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to list payslips by run: %w", err)
	}
	defer rows.Close()

	return r.scanPayslips(rows)
}

// ListByUser returns payslips for a user within a date range (based on generated_at).
func (r *payslipRepository) ListByUser(ctx context.Context, companyID, userID uuid.UUID, from, to time.Time) ([]models.PayslipRecord, error) {
	// We need to join with payroll_run to filter by company_id.
	query := `
		SELECT
			p.payslip_id,
			p.payroll_run_id,
			p.user_id,
			p.pdf_object_key,
			p.generated_at,
			p.sent_at
		FROM payroll.payslip p
		JOIN payroll.payroll_run pr ON p.payroll_run_id = pr.payroll_run_id
		WHERE pr.company_id = $1
		  AND p.user_id = $2
		  AND p.generated_at >= $3
		  AND p.generated_at <= $4
		ORDER BY p.generated_at DESC
	`

	rows, err := r.client.Query(ctx, query, companyID, userID, from, to)
	if err != nil {
		r.logger.Error("Failed to list payslips by user",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.Time("from", from),
			util.Time("to", to),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to list payslips by user: %w", err)
	}
	defer rows.Close()

	return r.scanPayslips(rows)
}

// UpdateSentAt sets the sent_at timestamp for a payslip.
func (r *payslipRepository) UpdateSentAt(ctx context.Context, payslipID uuid.UUID, sentAt time.Time) error {
	query := `
		UPDATE payroll.payslip
		SET sent_at = $1
		WHERE payslip_id = $2
	`

	result, err := r.client.Exec(ctx, query, sentAt, payslipID)
	if err != nil {
		r.logger.Error("Failed to update payslip sent_at",
			util.String("payslip_id", payslipID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to update payslip sent_at: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("payslip not found")
	}
	return nil
}

// scanPayslip scans a single row into a PayslipRecord.
func (r *payslipRepository) scanPayslip(row scanner) (*models.PayslipRecord, error) {
	var p models.PayslipRecord
	var sentAt sql.NullTime

	err := row.Scan(
		&p.PayslipID,
		&p.PayrollRunID,
		&p.UserID,
		&p.PDFObjectKey,
		&p.GeneratedAt,
		&sentAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	if sentAt.Valid {
		p.SentAt = &sentAt.Time
	}
	return &p, nil
}

// scanPayslips scans multiple rows into a slice of PayslipRecord.
func (r *payslipRepository) scanPayslips(rows *sql.Rows) ([]models.PayslipRecord, error) {
	var records []models.PayslipRecord
	for rows.Next() {
		var p models.PayslipRecord
		var sentAt sql.NullTime

		if err := rows.Scan(
			&p.PayslipID,
			&p.PayrollRunID,
			&p.UserID,
			&p.PDFObjectKey,
			&p.GeneratedAt,
			&sentAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan payslip row: %w", err)
		}

		if sentAt.Valid {
			p.SentAt = &sentAt.Time
		}
		records = append(records, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return records, nil
}
