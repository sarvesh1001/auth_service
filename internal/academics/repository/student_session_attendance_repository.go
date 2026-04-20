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

	"auth-service/internal/academics/models"
	"auth-service/internal/util"
)

// StudentSessionAttendanceRepository defines operations for period-wise attendance.
type StudentSessionAttendanceRepository interface {
	Create(ctx context.Context, db DBTX, a *models.StudentSessionAttendance) error
	Upsert(ctx context.Context, db DBTX, a *models.StudentSessionAttendance) error
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.StudentSessionAttendance, error)
	GetBySessionAndEnrollment(ctx context.Context, db DBTX, sessionID, enrollmentID uuid.UUID) (*models.StudentSessionAttendance, error)
	List(ctx context.Context, db DBTX, filter StudentSessionAttendanceFilter, p Pagination, s Sort) ([]*models.StudentSessionAttendance, error)
	Count(ctx context.Context, db DBTX, filter StudentSessionAttendanceFilter) (int64, error)
	Update(ctx context.Context, db DBTX, a *models.StudentSessionAttendance) error
	Delete(ctx context.Context, db DBTX, id uuid.UUID) error
	DeleteBySession(ctx context.Context, db DBTX, sessionID uuid.UUID) error // for session reset
}

// StudentSessionAttendanceFilter for querying period attendance.
type StudentSessionAttendanceFilter struct {
	SessionID    *uuid.UUID
	EnrollmentID *uuid.UUID
	StudentID    *uuid.UUID // joins with enrollments
	SectionID    *uuid.UUID // joins with enrollments and sections
	Status       *models.SessionAttendanceStatus
	SourceType   *models.AttendanceSourceType
	MarkedFrom   *time.Time
	MarkedTo     *time.Time
	IsAuto       *bool
}

type studentSessionAttendanceRepository struct {
	logger *zap.Logger
}

// NewStudentSessionAttendanceRepository creates a new repository.
func NewStudentSessionAttendanceRepository(logger *zap.Logger) StudentSessionAttendanceRepository {
	return &studentSessionAttendanceRepository{
		logger: logger.Named("student_session_attendance_repo"),
	}
}

var allowedSSASortFields = map[string]bool{
	"marked_at":     true,
	"status":        true,
	"created_at":    true,
	"updated_at":    true,
	"session_id":    true,
	"enrollment_id": true,
}

func (r *studentSessionAttendanceRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "marked_at"
	}
	if !allowedSSASortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY ssa.%s %s", field, dir), nil
}

func (r *studentSessionAttendanceRepository) validatePagination(p Pagination) (int, int) {
	limit := p.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := p.Offset
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func (r *studentSessionAttendanceRepository) buildFilter(filter StudentSessionAttendanceFilter) (string, []interface{}, string, error) {
	var conditions []string
	var args []interface{}
	idx := 1
	fromClause := "FROM academics.student_session_attendance ssa"

	// Simple direct filters
	if filter.SessionID != nil {
		conditions = append(conditions, fmt.Sprintf("ssa.session_id = $%d", idx))
		args = append(args, *filter.SessionID)
		idx++
	}
	if filter.EnrollmentID != nil {
		conditions = append(conditions, fmt.Sprintf("ssa.enrollment_id = $%d", idx))
		args = append(args, *filter.EnrollmentID)
		idx++
	}
	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("ssa.status = $%d", idx))
		args = append(args, *filter.Status)
		idx++
	}
	if filter.SourceType != nil {
		conditions = append(conditions, fmt.Sprintf("ssa.source_type = $%d", idx))
		args = append(args, *filter.SourceType)
		idx++
	}
	if filter.MarkedFrom != nil {
		conditions = append(conditions, fmt.Sprintf("ssa.marked_at >= $%d", idx))
		args = append(args, *filter.MarkedFrom)
		idx++
	}
	if filter.MarkedTo != nil {
		conditions = append(conditions, fmt.Sprintf("ssa.marked_at <= $%d", idx))
		args = append(args, *filter.MarkedTo)
		idx++
	}
	if filter.IsAuto != nil {
		conditions = append(conditions, fmt.Sprintf("ssa.is_auto = $%d", idx))
		args = append(args, *filter.IsAuto)
		idx++
	}

	// Joins for student/section filters
	if filter.StudentID != nil || filter.SectionID != nil {
		fromClause += " JOIN academics.enrollments e ON ssa.enrollment_id = e.enrollment_id"
		if filter.StudentID != nil {
			conditions = append(conditions, fmt.Sprintf("e.student_id = $%d", idx))
			args = append(args, *filter.StudentID)
			idx++
		}
		if filter.SectionID != nil {
			fromClause += " JOIN academics.section sec ON e.section_id = sec.section_id AND sec.deleted_at IS NULL"
			conditions = append(conditions, fmt.Sprintf("sec.section_id = $%d", idx))
			args = append(args, *filter.SectionID)
			idx++
		}
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}
	return whereClause, args, fromClause, nil
}

// Create inserts a new period attendance record.
func (r *studentSessionAttendanceRepository) Create(ctx context.Context, db DBTX, a *models.StudentSessionAttendance) error {
	query := `
		INSERT INTO academics.student_session_attendance (
			session_id, enrollment_id, status, marked_at, marked_by,
			source_type, device_id, is_auto, remarks, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
		RETURNING attendance_id, created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		a.SessionID, a.EnrollmentID, a.Status, a.MarkedAt, a.MarkedBy,
		a.SourceType, a.DeviceID, a.IsAuto, a.Remarks,
	).Scan(&a.AttendanceID, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create student session attendance",
			util.String("session_id", a.SessionID.String()),
			util.String("enrollment_id", a.EnrollmentID.String()),
			util.ErrorField(err))
		return fmt.Errorf("create student session attendance: %w", err)
	}
	return nil
}

// Upsert inserts or updates on conflict (session_id, enrollment_id).
func (r *studentSessionAttendanceRepository) Upsert(ctx context.Context, db DBTX, a *models.StudentSessionAttendance) error {
	query := `
		INSERT INTO academics.student_session_attendance (
			session_id, enrollment_id, status, marked_at, marked_by,
			source_type, device_id, is_auto, remarks, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
		ON CONFLICT (session_id, enrollment_id) DO UPDATE SET
			status = EXCLUDED.status,
			marked_at = EXCLUDED.marked_at,
			marked_by = EXCLUDED.marked_by,
			source_type = EXCLUDED.source_type,
			device_id = EXCLUDED.device_id,
			is_auto = EXCLUDED.is_auto,
			remarks = EXCLUDED.remarks,
			updated_at = NOW()
		RETURNING attendance_id, created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		a.SessionID, a.EnrollmentID, a.Status, a.MarkedAt, a.MarkedBy,
		a.SourceType, a.DeviceID, a.IsAuto, a.Remarks,
	).Scan(&a.AttendanceID, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to upsert student session attendance",
			util.String("session_id", a.SessionID.String()),
			util.String("enrollment_id", a.EnrollmentID.String()),
			util.ErrorField(err))
		return fmt.Errorf("upsert student session attendance: %w", err)
	}
	return nil
}

// GetByID retrieves a period attendance record by its primary key.
func (r *studentSessionAttendanceRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.StudentSessionAttendance, error) {
	query := `
		SELECT attendance_id, session_id, enrollment_id, status, marked_at, marked_by,
		       source_type, device_id, is_auto, remarks, created_at, updated_at
		FROM academics.student_session_attendance
		WHERE attendance_id = $1
	`
	row := db.QueryRowContext(ctx, query, id)
	return r.scanAttendance(row)
}

// GetBySessionAndEnrollment retrieves attendance for a specific session and enrollment.
func (r *studentSessionAttendanceRepository) GetBySessionAndEnrollment(ctx context.Context, db DBTX, sessionID, enrollmentID uuid.UUID) (*models.StudentSessionAttendance, error) {
	query := `
		SELECT attendance_id, session_id, enrollment_id, status, marked_at, marked_by,
		       source_type, device_id, is_auto, remarks, created_at, updated_at
		FROM academics.student_session_attendance
		WHERE session_id = $1 AND enrollment_id = $2
	`
	row := db.QueryRowContext(ctx, query, sessionID, enrollmentID)
	return r.scanAttendance(row)
}

// List returns period attendance records matching the filter.
func (r *studentSessionAttendanceRepository) List(ctx context.Context, db DBTX, filter StudentSessionAttendanceFilter, p Pagination, s Sort) ([]*models.StudentSessionAttendance, error) {
	where, args, fromClause, err := r.buildFilter(filter)
	if err != nil {
		return nil, err
	}
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT ssa.attendance_id, ssa.session_id, ssa.enrollment_id, ssa.status, ssa.marked_at, ssa.marked_by,
		       ssa.source_type, ssa.device_id, ssa.is_auto, ssa.remarks, ssa.created_at, ssa.updated_at
		%s
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, fromClause, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list student session attendances",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list student session attendances: %w", err)
	}
	defer rows.Close()

	var result []*models.StudentSessionAttendance
	for rows.Next() {
		a, err := r.scanAttendance(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, a)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// Count returns the number of records matching the filter.
func (r *studentSessionAttendanceRepository) Count(ctx context.Context, db DBTX, filter StudentSessionAttendanceFilter) (int64, error) {
	where, args, fromClause, err := r.buildFilter(filter)
	if err != nil {
		return 0, err
	}
	query := fmt.Sprintf("SELECT COUNT(*) %s %s", fromClause, where)
	var count int64
	err = db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count student session attendances",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count student session attendances: %w", err)
	}
	return count, nil
}

// Update modifies an existing period attendance record (full object update).
func (r *studentSessionAttendanceRepository) Update(ctx context.Context, db DBTX, a *models.StudentSessionAttendance) error {
	query := `
		UPDATE academics.student_session_attendance
		SET status = $2, marked_at = $3, marked_by = $4,
		    source_type = $5, device_id = $6, is_auto = $7, remarks = $8,
		    updated_at = NOW()
		WHERE attendance_id = $1
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		a.AttendanceID, a.Status, a.MarkedAt, a.MarkedBy,
		a.SourceType, a.DeviceID, a.IsAuto, a.Remarks,
	).Scan(&a.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: student session attendance %s", ErrNotFound, a.AttendanceID)
		}
		r.logger.Error("failed to update student session attendance",
			util.String("attendance_id", a.AttendanceID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update student session attendance: %w", err)
	}
	return nil
}

// Delete removes a period attendance record by ID.
func (r *studentSessionAttendanceRepository) Delete(ctx context.Context, db DBTX, id uuid.UUID) error {
	query := `DELETE FROM academics.student_session_attendance WHERE attendance_id = $1`
	result, err := db.ExecContext(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete student session attendance",
			util.String("attendance_id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete student session attendance: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("student session attendance %s not found", id)
	}
	return nil
}

// DeleteBySession removes all attendance records for a given session (e.g., for reset).
func (r *studentSessionAttendanceRepository) DeleteBySession(ctx context.Context, db DBTX, sessionID uuid.UUID) error {
	query := `DELETE FROM academics.student_session_attendance WHERE session_id = $1`
	result, err := db.ExecContext(ctx, query, sessionID)
	if err != nil {
		r.logger.Error("failed to delete attendances by session",
			util.String("session_id", sessionID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete attendances by session: %w", err)
	}
	_, _ = result.RowsAffected() // we don't need the count
	return nil
}

// scanAttendance scans a row into a StudentSessionAttendance object.
func (r *studentSessionAttendanceRepository) scanAttendance(row scanner) (*models.StudentSessionAttendance, error) {
	var a models.StudentSessionAttendance
	var markedBy uuid.NullUUID
	var deviceID sql.NullString

	err := row.Scan(
		&a.AttendanceID,
		&a.SessionID,
		&a.EnrollmentID,
		&a.Status,
		&a.MarkedAt,
		&markedBy,
		&a.SourceType,
		&deviceID,
		&a.IsAuto,
		&a.Remarks,
		&a.CreatedAt,
		&a.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan student session attendance: %w", err)
	}
	if markedBy.Valid {
		a.MarkedBy = &markedBy.UUID
	}
	if deviceID.Valid {
		a.DeviceID = &deviceID.String
	}
	return &a, nil
}
