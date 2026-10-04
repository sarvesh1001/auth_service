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
)

type sessionSummaryRepo struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewAttendanceSessionSummaryRepository(pg *client.PostgresClient, logger *zap.Logger) repository.AttendanceSessionSummaryRepository {
	return &sessionSummaryRepo{
		client: pg,
		logger: logger.Named("session_summary_repo"),
	}
}

// ── CHANGED: added timezone
const sessionSummaryColumns = `
	summary_id, company_id, subject_type, subject_id,
	employment_location_id,
	session_id, session_date, timezone, status, marked_at, marked_by,
	source_type, device_id, is_auto, remarks,
	metadata, created_at, updated_at
`

func (r *sessionSummaryRepo) Upsert(ctx context.Context, tx *sql.Tx, summary *models.AttendanceSessionSummary) error {
	if summary.SummaryID == uuid.Nil {
		summary.SummaryID = uuid.New()
	}
	now := time.Now().UTC()
	summary.CreatedAt = now
	summary.UpdatedAt = now

	// ── Guard: writer must supply tz.
	if summary.Timezone == "" {
		r.logger.Error("SessionSummary.Upsert: timezone empty; defaulting to UTC",
			zap.String("summary_id", summary.SummaryID.String()),
			zap.String("company_id", summary.CompanyID.String()),
			zap.String("subject_id", summary.SubjectID.String()),
		)
		summary.Timezone = "UTC"
	}

	metadataJSON, _ := json.Marshal(summary.Metadata)

	query := `
		INSERT INTO attendance.attendance_session_summary (
			summary_id, company_id, subject_type, subject_id,
			employment_location_id,
			session_id, session_date, timezone, status, marked_at, marked_by,
			source_type, device_id, is_auto, remarks,
			metadata, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10, $11,
			$12, $13, $14, $15,
			$16, $17, $18
		)
		ON CONFLICT (company_id, subject_type, subject_id, session_id) DO UPDATE SET
			employment_location_id = EXCLUDED.employment_location_id,
			session_date = EXCLUDED.session_date,
			timezone = EXCLUDED.timezone,
			status = EXCLUDED.status,
			marked_at = EXCLUDED.marked_at,
			marked_by = EXCLUDED.marked_by,
			source_type = EXCLUDED.source_type,
			device_id = EXCLUDED.device_id,
			is_auto = EXCLUDED.is_auto,
			remarks = EXCLUDED.remarks,
			metadata = EXCLUDED.metadata,
			updated_at = EXCLUDED.updated_at`
	exec := func(q string, a ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, a...)
		}
		return r.client.Exec(ctx, q, a...)
	}
	_, err := exec(query,
		summary.SummaryID,
		summary.CompanyID,
		summary.SubjectType,
		summary.SubjectID,
		summary.EmploymentLocationID,
		summary.SessionID,
		summary.SessionDate,
		summary.Timezone,
		summary.Status,
		summary.MarkedAt,
		summary.MarkedBy,
		summary.SourceType,
		summary.DeviceID,
		summary.IsAuto,
		summary.Remarks,
		metadataJSON,
		summary.CreatedAt,
		summary.UpdatedAt,
	)
	if err != nil {
		r.logger.Error("failed to upsert session summary",
			zap.String("summary_id", summary.SummaryID.String()),
			zap.String("timezone", summary.Timezone),
			zap.Error(err))
	}
	return err
}

func (r *sessionSummaryRepo) GetBySessionAndSubject(ctx context.Context, tx *sql.Tx, sessionID, subjectID uuid.UUID, subjectType string) (*models.AttendanceSessionSummary, error) {
	query := `SELECT ` + sessionSummaryColumns + `
		FROM attendance.attendance_session_summary
		WHERE session_id = $1 AND subject_type = $2 AND subject_id = $3`
	row := r.getRow(ctx, tx, query, sessionID, subjectType, subjectID)
	return r.scanSummary(row)
}

func (r *sessionSummaryRepo) GetBySession(ctx context.Context, tx *sql.Tx, sessionID uuid.UUID) ([]*models.AttendanceSessionSummary, error) {
	query := `SELECT ` + sessionSummaryColumns + `
		FROM attendance.attendance_session_summary
		WHERE session_id = $1
		ORDER BY subject_type, subject_id`
	rows, err := r.getRows(ctx, tx, query, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return r.scanSummaries(rows)
}

func (r *sessionSummaryRepo) GetBySubject(ctx context.Context, tx *sql.Tx, companyID, subjectID uuid.UUID, subjectType string, fromDate, toDate time.Time) ([]*models.AttendanceSessionSummary, error) {
	query := `SELECT ` + sessionSummaryColumns + `
		FROM attendance.attendance_session_summary
		WHERE company_id = $1 AND subject_type = $2 AND subject_id = $3
		  AND session_date BETWEEN $4 AND $5
		ORDER BY session_date, session_id`
	rows, err := r.getRows(ctx, tx, query, companyID, subjectType, subjectID, fromDate, toDate)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return r.scanSummaries(rows)
}

func (r *sessionSummaryRepo) List(ctx context.Context, tx *sql.Tx, filter repository.SessionSummaryFilter, pag repository.Pagination) ([]*models.AttendanceSessionSummary, error) {
	query := `SELECT ` + sessionSummaryColumns + `
		FROM attendance.attendance_session_summary
		WHERE 1=1`
	args := []interface{}{}
	argPos := 1
	if filter.CompanyID != nil {
		query += fmt.Sprintf(" AND company_id = $%d", argPos)
		args = append(args, *filter.CompanyID)
		argPos++
	}
	if filter.SubjectType != nil {
		query += fmt.Sprintf(" AND subject_type = $%d", argPos)
		args = append(args, *filter.SubjectType)
		argPos++
	}
	if filter.SubjectID != nil {
		query += fmt.Sprintf(" AND subject_id = $%d", argPos)
		args = append(args, *filter.SubjectID)
		argPos++
	}
	if filter.SessionID != nil {
		query += fmt.Sprintf(" AND session_id = $%d", argPos)
		args = append(args, *filter.SessionID)
		argPos++
	}
	if filter.SessionDate != nil {
		query += fmt.Sprintf(" AND session_date = $%d", argPos)
		args = append(args, *filter.SessionDate)
		argPos++
	}
	if filter.Status != nil {
		query += fmt.Sprintf(" AND status = $%d", argPos)
		args = append(args, *filter.Status)
		argPos++
	}
	if filter.LocationID != nil {
		query += fmt.Sprintf(" AND employment_location_id = $%d", argPos)
		args = append(args, *filter.LocationID)
		argPos++
	}
	query += " ORDER BY session_date DESC, subject_type, subject_id"
	if pag.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argPos, argPos+1)
		args = append(args, pag.Limit, pag.Offset)
	}
	rows, err := r.getRows(ctx, tx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return r.scanSummaries(rows)
}

func (r *sessionSummaryRepo) Count(ctx context.Context, tx *sql.Tx, filter repository.SessionSummaryFilter) (int64, error) {
	query := `SELECT COUNT(*) FROM attendance.attendance_session_summary WHERE 1=1`
	args := []interface{}{}
	argPos := 1
	if filter.CompanyID != nil {
		query += fmt.Sprintf(" AND company_id = $%d", argPos)
		args = append(args, *filter.CompanyID)
		argPos++
	}
	if filter.SubjectType != nil {
		query += fmt.Sprintf(" AND subject_type = $%d", argPos)
		args = append(args, *filter.SubjectType)
		argPos++
	}
	if filter.SubjectID != nil {
		query += fmt.Sprintf(" AND subject_id = $%d", argPos)
		args = append(args, *filter.SubjectID)
		argPos++
	}
	if filter.SessionID != nil {
		query += fmt.Sprintf(" AND session_id = $%d", argPos)
		args = append(args, *filter.SessionID)
		argPos++
	}
	if filter.SessionDate != nil {
		query += fmt.Sprintf(" AND session_date = $%d", argPos)
		args = append(args, *filter.SessionDate)
		argPos++
	}
	if filter.Status != nil {
		query += fmt.Sprintf(" AND status = $%d", argPos)
		args = append(args, *filter.Status)
		argPos++
	}
	if filter.LocationID != nil {
		query += fmt.Sprintf(" AND employment_location_id = $%d", argPos)
		args = append(args, *filter.LocationID)
		argPos++
	}
	var count int64
	err := r.getRow(ctx, tx, query, args...).Scan(&count)
	return count, err
}

func (r *sessionSummaryRepo) getRow(ctx context.Context, tx *sql.Tx, query string, args ...interface{}) *sql.Row {
	if tx != nil {
		return tx.QueryRowContext(ctx, query, args...)
	}
	return r.client.QueryRow(ctx, query, args...)
}

func (r *sessionSummaryRepo) getRows(ctx context.Context, tx *sql.Tx, query string, args ...interface{}) (*sql.Rows, error) {
	if tx != nil {
		return tx.QueryContext(ctx, query, args...)
	}
	return r.client.Query(ctx, query, args...)
}

func (r *sessionSummaryRepo) scanSummary(row *sql.Row) (*models.AttendanceSessionSummary, error) {
	var s models.AttendanceSessionSummary
	var markedByUUID uuid.NullUUID
	var deviceIDStr, remarks sql.NullString
	var metadataJSON []byte
	var employmentLocID sql.NullString
	err := row.Scan(
		&s.SummaryID,
		&s.CompanyID,
		&s.SubjectType,
		&s.SubjectID,
		&employmentLocID,
		&s.SessionID,
		&s.SessionDate,
		&s.Timezone,
		&s.Status,
		&s.MarkedAt,
		&markedByUUID,
		&s.SourceType,
		&deviceIDStr,
		&s.IsAuto,
		&remarks,
		&metadataJSON,
		&s.CreatedAt,
		&s.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	r.assignSessionSummaryNulls(&s, employmentLocID, markedByUUID, deviceIDStr, remarks, metadataJSON)
	return &s, nil
}

func (r *sessionSummaryRepo) scanSummaries(rows *sql.Rows) ([]*models.AttendanceSessionSummary, error) {
	var summaries []*models.AttendanceSessionSummary
	for rows.Next() {
		var s models.AttendanceSessionSummary
		var markedByUUID uuid.NullUUID
		var deviceIDStr, remarks sql.NullString
		var metadataJSON []byte
		var employmentLocID sql.NullString
		err := rows.Scan(
			&s.SummaryID,
			&s.CompanyID,
			&s.SubjectType,
			&s.SubjectID,
			&employmentLocID,
			&s.SessionID,
			&s.SessionDate,
			&s.Timezone,
			&s.Status,
			&s.MarkedAt,
			&markedByUUID,
			&s.SourceType,
			&deviceIDStr,
			&s.IsAuto,
			&remarks,
			&metadataJSON,
			&s.CreatedAt,
			&s.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		r.assignSessionSummaryNulls(&s, employmentLocID, markedByUUID, deviceIDStr, remarks, metadataJSON)
		summaries = append(summaries, &s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return summaries, nil
}

func (r *sessionSummaryRepo) assignSessionSummaryNulls(
	s *models.AttendanceSessionSummary,
	employmentLoc sql.NullString,
	markedBy uuid.NullUUID,
	deviceID, remarks sql.NullString,
	metadataJSON []byte,
) {
	if employmentLoc.Valid && employmentLoc.String != "" {
		if id, err := uuid.Parse(employmentLoc.String); err == nil {
			s.EmploymentLocationID = &id
		}
	}
	if markedBy.Valid {
		s.MarkedBy = &markedBy.UUID
	}
	if deviceID.Valid {
		s.DeviceID = &deviceID.String
	}
	if remarks.Valid {
		s.Remarks = &remarks.String
	}
	if len(metadataJSON) > 0 {
		_ = json.Unmarshal(metadataJSON, &s.Metadata)
	}
}
