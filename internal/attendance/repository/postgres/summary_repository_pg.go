package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/client"
	"auth-service/internal/util"
)

type summaryRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewSummaryRepository(pg *client.PostgresClient, logger *zap.Logger) repository.SummaryRepository {
	return &summaryRepository{
		client: pg,
		logger: logger.Named("summary_repo"),
	}
}

// UpsertSummary creates or updates a daily summary.
func (r *summaryRepository) UpsertSummary(ctx context.Context, tx *sql.Tx, summary *models.AttendanceDailySummary) error {
	if summary.AttendanceSummaryID == uuid.Nil {
		summary.AttendanceSummaryID = uuid.New()
	}
	if summary.GeneratedAt.IsZero() {
		summary.GeneratedAt = time.Now().UTC()
	}

	metadataJSON, err := json.Marshal(summary.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	query := `
		INSERT INTO attendance.attendance_daily_summary (
			attendance_summary_id,
			company_id,
			subject_type,
			subject_id,
			attendance_date,
			status,
			worked_minutes,
			expected_minutes,
			overtime_minutes,
			late_minutes,
			is_finalized,
			is_payable,
			is_payroll_locked,
			metadata,
			generated_at,
			generated_by
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10,
			$11, $12, $13,
			$14, $15, $16
		)
		ON CONFLICT (company_id, subject_type, subject_id, attendance_date)
		DO UPDATE SET
			status = EXCLUDED.status,
			worked_minutes = EXCLUDED.worked_minutes,
			expected_minutes = EXCLUDED.expected_minutes,
			overtime_minutes = EXCLUDED.overtime_minutes,
			late_minutes = EXCLUDED.late_minutes,
			is_finalized = EXCLUDED.is_finalized,
			is_payable = EXCLUDED.is_payable,
			metadata = EXCLUDED.metadata,
			generated_at = EXCLUDED.generated_at,
			generated_by = EXCLUDED.generated_by
	`

	exec := func(q string, args ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, args...)
		}
		return r.client.Exec(ctx, q, args...)
	}

	_, err = exec(query,
		summary.AttendanceSummaryID,
		summary.CompanyID,
		summary.SubjectType,
		summary.SubjectID,
		summary.AttendanceDate,
		summary.Status,
		summary.WorkedMinutes,
		summary.ExpectedMinutes,
		summary.OvertimeMinutes,
		summary.LateMinutes,
		summary.IsFinalized,
		summary.IsPayable,
		summary.IsPayrollLocked,
		metadataJSON,
		summary.GeneratedAt,
		summary.GeneratedBy,
	)
	if err != nil {
		r.logger.Error("failed to upsert daily summary",
			util.String("summary_id", summary.AttendanceSummaryID.String()),
			util.ErrorField(err))
		return fmt.Errorf("upsert summary: %w", err)
	}
	return nil
}

// GetBySubjectDate retrieves a summary for a specific subject on a given date.
func (r *summaryRepository) GetBySubjectDate(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, date time.Time) (*models.AttendanceDailySummary, error) {
	query := `
		SELECT
			attendance_summary_id,
			company_id,
			subject_type,
			subject_id,
			attendance_date,
			status,
			worked_minutes,
			expected_minutes,
			overtime_minutes,
			late_minutes,
			is_finalized,
			is_payable,
			is_payroll_locked,
			metadata,
			generated_at,
			generated_by
		FROM attendance.attendance_daily_summary
		WHERE company_id = $1
		  AND subject_type = $2
		  AND subject_id = $3
		  AND attendance_date = $4
	`
	row := r.client.QueryRow(ctx, query, companyID, subjectType, subjectID, date)
	return r.scanSummary(row)
}

// GetBySubjectRange retrieves summaries for a subject within a date range.
func (r *summaryRepository) GetBySubjectRange(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, from, to time.Time) ([]*models.AttendanceDailySummary, error) {
	query := `
		SELECT
			attendance_summary_id,
			company_id,
			subject_type,
			subject_id,
			attendance_date,
			status,
			worked_minutes,
			expected_minutes,
			overtime_minutes,
			late_minutes,
			is_finalized,
			is_payable,
			is_payroll_locked,
			metadata,
			generated_at,
			generated_by
		FROM attendance.attendance_daily_summary
		WHERE company_id = $1
		  AND subject_type = $2
		  AND subject_id = $3
		  AND attendance_date BETWEEN $4 AND $5
		ORDER BY attendance_date ASC
	`
	rows, err := r.client.Query(ctx, query, companyID, subjectType, subjectID, from, to)
	if err != nil {
		return nil, fmt.Errorf("query subject range: %w", err)
	}
	defer rows.Close()
	return r.scanSummaries(rows)
}

// GetByCompanyRange retrieves summaries for all subjects in a company within a date range.
func (r *summaryRepository) GetByCompanyRange(ctx context.Context, companyID uuid.UUID, from, to time.Time, limit, offset int) ([]*models.AttendanceDailySummary, int64, error) {
	// Count total
	countQuery := `
		SELECT COUNT(*)
		FROM attendance.attendance_daily_summary
		WHERE company_id = $1
		  AND attendance_date BETWEEN $2 AND $3
	`
	var total int64
	err := r.client.QueryRow(ctx, countQuery, companyID, from, to).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count summaries: %w", err)
	}

	// Fetch paginated
	query := `
		SELECT
			attendance_summary_id,
			company_id,
			subject_type,
			subject_id,
			attendance_date,
			status,
			worked_minutes,
			expected_minutes,
			overtime_minutes,
			late_minutes,
			is_finalized,
			is_payable,
			is_payroll_locked,
			metadata,
			generated_at,
			generated_by
		FROM attendance.attendance_daily_summary
		WHERE company_id = $1
		  AND attendance_date BETWEEN $2 AND $3
		ORDER BY attendance_date DESC
		LIMIT $4 OFFSET $5
	`
	rows, err := r.client.Query(ctx, query, companyID, from, to, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("query company range: %w", err)
	}
	defer rows.Close()
	summaries, err := r.scanSummaries(rows)
	if err != nil {
		return nil, 0, err
	}
	return summaries, total, nil
}

// LockForPayroll sets is_payroll_locked = true for a specific summary.
func (r *summaryRepository) LockForPayroll(ctx context.Context, tx *sql.Tx, summaryID uuid.UUID) error {
	query := `
		UPDATE attendance.attendance_daily_summary
		SET is_payroll_locked = true
		WHERE attendance_summary_id = $1
		  AND is_payroll_locked = false
	`
	exec := func(q string, args ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, args...)
		}
		return r.client.Exec(ctx, q, args...)
	}
	result, err := exec(query, summaryID)
	if err != nil {
		return fmt.Errorf("lock for payroll: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("summary already locked or not found")
	}
	return nil
}

// LockBySubjectDateRange locks all summaries for a subject in a date range (for payroll).
func (r *summaryRepository) LockBySubjectDateRange(ctx context.Context, tx *sql.Tx, companyID, subjectID uuid.UUID, subjectType string, from, to time.Time) error {
	query := `
		UPDATE attendance.attendance_daily_summary
		SET is_payroll_locked = true
		WHERE company_id = $1
		  AND subject_type = $2
		  AND subject_id = $3
		  AND attendance_date BETWEEN $4 AND $5
		  AND is_payroll_locked = false
	`
	exec := func(q string, args ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, args...)
		}
		return r.client.Exec(ctx, q, args...)
	}
	result, err := exec(query, companyID, subjectType, subjectID, from, to)
	if err != nil {
		return fmt.Errorf("lock range: %w", err)
	}
	rows, _ := result.RowsAffected()
	r.logger.Info("locked summaries for payroll",
		util.String("company_id", companyID.String()),
		util.String("subject_id", subjectID.String()),
		util.Int64("rows_affected", rows))
	return nil
}

// MarkFinalized sets is_finalized = true for a summary.
func (r *summaryRepository) MarkFinalized(ctx context.Context, summaryID uuid.UUID) error {
	query := `
		UPDATE attendance.attendance_daily_summary
		SET is_finalized = true
		WHERE attendance_summary_id = $1
	`
	_, err := r.client.Exec(ctx, query, summaryID)
	if err != nil {
		return fmt.Errorf("mark finalized: %w", err)
	}
	return nil
}

// DeleteByID deletes a summary permanently.
func (r *summaryRepository) DeleteByID(ctx context.Context, summaryID uuid.UUID) error {
	query := `DELETE FROM attendance.attendance_daily_summary WHERE attendance_summary_id = $1`
	result, err := r.client.Exec(ctx, query, summaryID)
	if err != nil {
		return fmt.Errorf("delete summary: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("summary not found")
	}
	return nil
}

// HealthCheck checks database connectivity.
func (r *summaryRepository) HealthCheck(ctx context.Context) error {
	query := `SELECT 1 FROM attendance.attendance_daily_summary LIMIT 1`
	_, err := r.client.Exec(ctx, query)
	if err != nil {
		r.logger.Error("summary health check failed", util.ErrorField(err))
		return fmt.Errorf("health check: %w", err)
	}
	return nil
}

// scanSummary scans a single row.
func (r *summaryRepository) scanSummary(row *sql.Row) (*models.AttendanceDailySummary, error) {
	var summary models.AttendanceDailySummary
	var metadataJSON []byte
	err := row.Scan(
		&summary.AttendanceSummaryID,
		&summary.CompanyID,
		&summary.SubjectType,
		&summary.SubjectID,
		&summary.AttendanceDate,
		&summary.Status,
		&summary.WorkedMinutes,
		&summary.ExpectedMinutes,
		&summary.OvertimeMinutes,
		&summary.LateMinutes,
		&summary.IsFinalized,
		&summary.IsPayable,
		&summary.IsPayrollLocked,
		&metadataJSON,
		&summary.GeneratedAt,
		&summary.GeneratedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan summary: %w", err)
	}
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &summary.Metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}
	return &summary, nil
}

// scanSummaries scans multiple rows.
func (r *summaryRepository) scanSummaries(rows *sql.Rows) ([]*models.AttendanceDailySummary, error) {
	var summaries []*models.AttendanceDailySummary
	for rows.Next() {
		var summary models.AttendanceDailySummary
		var metadataJSON []byte
		err := rows.Scan(
			&summary.AttendanceSummaryID,
			&summary.CompanyID,
			&summary.SubjectType,
			&summary.SubjectID,
			&summary.AttendanceDate,
			&summary.Status,
			&summary.WorkedMinutes,
			&summary.ExpectedMinutes,
			&summary.OvertimeMinutes,
			&summary.LateMinutes,
			&summary.IsFinalized,
			&summary.IsPayable,
			&summary.IsPayrollLocked,
			&metadataJSON,
			&summary.GeneratedAt,
			&summary.GeneratedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("scan summary row: %w", err)
		}
		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &summary.Metadata); err != nil {
				return nil, fmt.Errorf("unmarshal metadata: %w", err)
			}
		}
		summaries = append(summaries, &summary)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return summaries, nil
}

// attendance/repository/postgres/summary_repository_pg.go

func (r *summaryRepository) MarkFinalizedForPeriod(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, from, to time.Time) error {
	query := `
        UPDATE attendance.attendance_daily_summary
        SET is_finalized = true
        WHERE company_id = $1
          AND subject_type = $2
          AND subject_id = $3
          AND attendance_date BETWEEN $4 AND $5
          AND is_finalized = false
    `
	result, err := r.client.Exec(ctx, query, companyID, subjectType, subjectID, from, to)
	if err != nil {
		return fmt.Errorf("mark finalized for period: %w", err)
	}
	rows, _ := result.RowsAffected()
	r.logger.Info("finalized attendance summaries for period",
		util.String("company_id", companyID.String()),
		util.String("subject_id", subjectID.String()),
		util.String("from", from.Format("2006-01-02")),
		util.String("to", to.Format("2006-01-02")),
		util.Int64("rows_affected", rows),
	)
	return nil
}
