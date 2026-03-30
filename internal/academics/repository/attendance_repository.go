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

// AttendanceRepository defines operations for attendance records, summaries, and exemptions.
type AttendanceRepository interface {
	// Attendance records
	Upsert(ctx context.Context, db DBTX, a *models.StudentAttendance) error
	BulkUpsert(ctx context.Context, db DBTX, attendances []*models.StudentAttendance) error
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.StudentAttendance, error)
	GetByEnrollmentAndDate(ctx context.Context, db DBTX, enrollmentID uuid.UUID, date time.Time) (*models.StudentAttendance, error)
	List(ctx context.Context, db DBTX, filter AttendanceFilter, p Pagination, s Sort) ([]*models.StudentAttendance, error)
	Count(ctx context.Context, db DBTX, filter AttendanceFilter) (int64, error)
	Delete(ctx context.Context, db DBTX, id uuid.UUID) error

	// Summary methods
	GetSummary(ctx context.Context, db DBTX, studentID, academicYearID uuid.UUID, termID *uuid.UUID) (*models.StudentAttendanceSummary, error)
	RecalculateSummary(ctx context.Context, db DBTX, studentID, academicYearID uuid.UUID, termID *uuid.UUID) error
	BulkRecalcSummaries(ctx context.Context, db DBTX, studentIDs []uuid.UUID, academicYearID uuid.UUID, termID *uuid.UUID) error

	// Exemptions
	CreateExemption(ctx context.Context, db DBTX, e *models.StudentAttendanceExemption) error
	GetExemptionByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.StudentAttendanceExemption, error)
	ListExemptions(ctx context.Context, db DBTX, studentID *uuid.UUID, fromDate, toDate *time.Time, p Pagination) ([]*models.StudentAttendanceExemption, error)
	DeleteExemption(ctx context.Context, db DBTX, id uuid.UUID) error
	UpdateExemption(ctx context.Context, db DBTX, e *models.StudentAttendanceExemption) error
}

type attendanceRepository struct {
	logger *zap.Logger
}

func NewAttendanceRepository(logger *zap.Logger) AttendanceRepository {
	return &attendanceRepository{
		logger: logger.Named("attendance_repo"),
	}
}

var allowedAttendanceSortFields = map[string]bool{
	"attendance_date": true,
	"status":          true,
	"created_at":      true,
	"updated_at":      true,
}

func (r *attendanceRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "attendance_date"
	}
	if !allowedAttendanceSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY a.%s %s", field, dir), nil
}

func (r *attendanceRepository) validatePagination(p Pagination) (int, int) {
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

// buildAttendanceFilter builds WHERE clause and args for attendance queries.
// It may join with enrollments and sections if needed.
func (r *attendanceRepository) buildAttendanceFilter(filter AttendanceFilter) (string, []interface{}, string, error) {
	var conditions []string
	var args []interface{}
	idx := 1
	fromClause := "FROM academics.student_attendance a"

	if filter.EnrollmentID != nil {
		conditions = append(conditions, fmt.Sprintf("a.enrollment_id = $%d", idx))
		args = append(args, *filter.EnrollmentID)
		idx++
	}

	if filter.StudentID != nil || filter.SectionID != nil || filter.TermID != nil || filter.AcademicYearID != nil {
		// Need to join enrollments
		fromClause += " JOIN academics.enrollments e ON a.enrollment_id = e.enrollment_id AND e.deleted_at IS NULL"
		if filter.StudentID != nil {
			conditions = append(conditions, fmt.Sprintf("e.student_id = $%d", idx))
			args = append(args, *filter.StudentID)
			idx++
		}
		if filter.SectionID != nil {
			conditions = append(conditions, fmt.Sprintf("e.section_id = $%d", idx))
			args = append(args, *filter.SectionID)
			idx++
		}
		if filter.TermID != nil {
			// Need section table to filter by term
			fromClause += " JOIN academics.section sec ON e.section_id = sec.section_id AND sec.deleted_at IS NULL"
			conditions = append(conditions, fmt.Sprintf("sec.term_id = $%d", idx))
			args = append(args, *filter.TermID)
			idx++
		}
		if filter.AcademicYearID != nil {
			conditions = append(conditions, fmt.Sprintf("e.academic_year_id = $%d", idx))
			args = append(args, *filter.AcademicYearID)
			idx++
		}
	}

	if filter.FromDate != nil {
		conditions = append(conditions, fmt.Sprintf("a.attendance_date >= $%d", idx))
		args = append(args, *filter.FromDate)
		idx++
	}
	if filter.ToDate != nil {
		conditions = append(conditions, fmt.Sprintf("a.attendance_date <= $%d", idx))
		args = append(args, *filter.ToDate)
		idx++
	}
	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("a.status = $%d", idx))
		args = append(args, *filter.Status)
		idx++
	}
	if filter.MarkedBy != nil {
		conditions = append(conditions, fmt.Sprintf("a.marked_by = $%d", idx))
		args = append(args, *filter.MarkedBy)
		idx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}
	return whereClause, args, fromClause, nil
}

// --- Attendance Record Methods ------------------------------------------

// Upsert creates or updates an attendance record using ON CONFLICT.
func (r *attendanceRepository) Upsert(ctx context.Context, db DBTX, a *models.StudentAttendance) error {
	query := `
        INSERT INTO academics.student_attendance (
            enrollment_id, attendance_date, status, marked_by, remarks, created_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
        ON CONFLICT (enrollment_id, attendance_date) DO UPDATE SET
            status = EXCLUDED.status,
            marked_by = EXCLUDED.marked_by,
            remarks = EXCLUDED.remarks,
            updated_at = NOW()
        RETURNING attendance_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		a.EnrollmentID, a.AttendanceDate, a.Status, a.MarkedBy, a.Remarks, a.CreatedBy,
	).Scan(&a.AttendanceID, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to upsert attendance",
			util.String("enrollment_id", a.EnrollmentID.String()),
			util.Time("date", a.AttendanceDate),
			util.ErrorField(err))
		return fmt.Errorf("upsert attendance: %w", err)
	}
	return nil
}

func (r *attendanceRepository) BulkUpsert(ctx context.Context, db DBTX, attendances []*models.StudentAttendance) error {
	if len(attendances) == 0 {
		return nil
	}
	tx, isOwner, err := beginTxIfNotTx(ctx, db)
	if err != nil {
		return err
	}
	needRollback := isOwner
	defer func() {
		if needRollback {
			_ = tx.Rollback()
		}
	}()

	stmt, err := tx.PrepareContext(ctx, `
        INSERT INTO academics.student_attendance (
            enrollment_id, attendance_date, status, marked_by, remarks, created_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
        ON CONFLICT (enrollment_id, attendance_date) DO UPDATE SET
            status = EXCLUDED.status,
            marked_by = EXCLUDED.marked_by,
            remarks = EXCLUDED.remarks,
            updated_at = NOW()
        RETURNING attendance_id, created_at, updated_at
    `)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, a := range attendances {
		err := stmt.QueryRowContext(ctx,
			a.EnrollmentID, a.AttendanceDate, a.Status, a.MarkedBy, a.Remarks, a.CreatedBy,
		).Scan(&a.AttendanceID, &a.CreatedAt, &a.UpdatedAt)
		if err != nil {
			r.logger.Error("bulk upsert attendance failed",
				util.String("enrollment_id", a.EnrollmentID.String()),
				util.Time("date", a.AttendanceDate),
				util.ErrorField(err))
			return fmt.Errorf("bulk upsert attendance row: %w", err)
		}
	}

	if isOwner {
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit tx: %w", err)
		}
		needRollback = false
	}
	return nil
}

func (r *attendanceRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.StudentAttendance, error) {
	query := `
        SELECT attendance_id, enrollment_id, attendance_date, status, marked_by, remarks, created_at, updated_at, created_by
        FROM academics.student_attendance
        WHERE attendance_id = $1
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanAttendance(row)
}

func (r *attendanceRepository) GetByEnrollmentAndDate(ctx context.Context, db DBTX, enrollmentID uuid.UUID, date time.Time) (*models.StudentAttendance, error) {
	query := `
        SELECT attendance_id, enrollment_id, attendance_date, status, marked_by, remarks, created_at, updated_at, created_by
        FROM academics.student_attendance
        WHERE enrollment_id = $1 AND attendance_date = $2
    `
	row := db.QueryRowContext(ctx, query, enrollmentID, date)
	return r.scanAttendance(row)
}

func (r *attendanceRepository) List(ctx context.Context, db DBTX, filter AttendanceFilter, p Pagination, s Sort) ([]*models.StudentAttendance, error) {
	where, args, fromClause, err := r.buildAttendanceFilter(filter)
	if err != nil {
		return nil, err
	}
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
        SELECT a.attendance_id, a.enrollment_id, a.attendance_date, a.status, a.marked_by, a.remarks, a.created_at, a.updated_at, a.created_by
        %s
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, fromClause, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list attendances",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list attendances: %w", err)
	}
	defer rows.Close()

	var result []*models.StudentAttendance
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

func (r *attendanceRepository) Count(ctx context.Context, db DBTX, filter AttendanceFilter) (int64, error) {
	where, args, fromClause, err := r.buildAttendanceFilter(filter)
	if err != nil {
		return 0, err
	}
	query := fmt.Sprintf("SELECT COUNT(*) %s %s", fromClause, where)
	var count int64
	err = db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count attendances",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count attendances: %w", err)
	}
	return count, nil
}

func (r *attendanceRepository) Delete(ctx context.Context, db DBTX, id uuid.UUID) error {
	query := `DELETE FROM academics.student_attendance WHERE attendance_id = $1`
	result, err := db.ExecContext(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete attendance",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete attendance: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("attendance %s not found", id)
	}
	return nil
}

// --- Summary Methods ---------------------------------------------------

func (r *attendanceRepository) GetSummary(ctx context.Context, db DBTX, studentID, academicYearID uuid.UUID, termID *uuid.UUID) (*models.StudentAttendanceSummary, error) {
	var query string
	var args []interface{}
	if termID != nil {
		query = `
            SELECT summary_id, student_id, academic_year_id, term_id,
                   total_present, total_absent, total_late, total_half_day, total_working_days,
                   attendance_percentage, created_at, updated_at
            FROM academics.student_attendance_summary
            WHERE student_id = $1 AND academic_year_id = $2 AND term_id = $3
        `
		args = []interface{}{studentID, academicYearID, *termID}
	} else {
		query = `
            SELECT summary_id, student_id, academic_year_id, term_id,
                   total_present, total_absent, total_late, total_half_day, total_working_days,
                   attendance_percentage, created_at, updated_at
            FROM academics.student_attendance_summary
            WHERE student_id = $1 AND academic_year_id = $2 AND term_id IS NULL
        `
		args = []interface{}{studentID, academicYearID}
	}

	row := db.QueryRowContext(ctx, query, args...)
	return r.scanSummary(row)
}

func (r *attendanceRepository) RecalculateSummary(ctx context.Context, db DBTX, studentID, academicYearID uuid.UUID, termID *uuid.UUID) error {
	tx, isOwner, err := beginTxIfNotTx(ctx, db)
	if err != nil {
		return err
	}
	needRollback := isOwner
	defer func() {
		if needRollback {
			_ = tx.Rollback()
		}
	}()

	var query string
	var args []interface{}

	if termID != nil {
		query = `
            WITH enrollment_ids AS (
                SELECT e.enrollment_id
                FROM academics.enrollments e
                JOIN academics.section sec ON e.section_id = sec.section_id
                WHERE e.student_id = $1
                  AND e.academic_year_id = $2
                  AND sec.term_id = $3
                  AND e.deleted_at IS NULL
            ),
            attendance_stats AS (
                SELECT
                    COUNT(*) FILTER (WHERE a.status = 'present') as total_present,
                    COUNT(*) FILTER (WHERE a.status = 'absent') as total_absent,
                    COUNT(*) FILTER (WHERE a.status = 'late') as total_late,
                    COUNT(*) FILTER (WHERE a.status = 'half-day') as total_half_day,
                    COUNT(*) FILTER (WHERE a.status IN ('present','absent','late','half-day')) as total_working_days
                FROM academics.student_attendance a
                WHERE a.enrollment_id IN (SELECT enrollment_id FROM enrollment_ids)
            )
            INSERT INTO academics.student_attendance_summary (
                student_id, academic_year_id, term_id,
                total_present, total_absent, total_late, total_half_day, total_working_days,
                created_at, updated_at
            )
            SELECT $1, $2, $3,
                   total_present, total_absent, total_late, total_half_day, total_working_days,
                   NOW(), NOW()
            FROM attendance_stats
            ON CONFLICT (student_id, academic_year_id, term_id) DO UPDATE SET
                total_present = EXCLUDED.total_present,
                total_absent = EXCLUDED.total_absent,
                total_late = EXCLUDED.total_late,
                total_half_day = EXCLUDED.total_half_day,
                total_working_days = EXCLUDED.total_working_days,
                updated_at = NOW()
        `
		args = []interface{}{studentID, academicYearID, *termID}
	} else {
		query = `
            WITH enrollment_ids AS (
                SELECT e.enrollment_id
                FROM academics.enrollments e
                WHERE e.student_id = $1
                  AND e.academic_year_id = $2
                  AND e.deleted_at IS NULL
            ),
            attendance_stats AS (
                SELECT
                    COUNT(*) FILTER (WHERE a.status = 'present') as total_present,
                    COUNT(*) FILTER (WHERE a.status = 'absent') as total_absent,
                    COUNT(*) FILTER (WHERE a.status = 'late') as total_late,
                    COUNT(*) FILTER (WHERE a.status = 'half-day') as total_half_day,
                    COUNT(*) FILTER (WHERE a.status IN ('present','absent','late','half-day')) as total_working_days
                FROM academics.student_attendance a
                WHERE a.enrollment_id IN (SELECT enrollment_id FROM enrollment_ids)
            )
            INSERT INTO academics.student_attendance_summary (
                student_id, academic_year_id, term_id,
                total_present, total_absent, total_late, total_half_day, total_working_days,
                created_at, updated_at
            )
            SELECT $1, $2, NULL,
                   total_present, total_absent, total_late, total_half_day, total_working_days,
                   NOW(), NOW()
            FROM attendance_stats
            ON CONFLICT (student_id, academic_year_id) WHERE term_id IS NULL DO UPDATE SET
                total_present = EXCLUDED.total_present,
                total_absent = EXCLUDED.total_absent,
                total_late = EXCLUDED.total_late,
                total_half_day = EXCLUDED.total_half_day,
                total_working_days = EXCLUDED.total_working_days,
                updated_at = NOW()
        `
		args = []interface{}{studentID, academicYearID}
	}

	_, err = tx.ExecContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to recalculate attendance summary",
			util.String("student_id", studentID.String()),
			util.String("academic_year_id", academicYearID.String()),
			util.ErrorField(err))
		return fmt.Errorf("recalculate summary: %w", err)
	}

	if isOwner {
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit tx: %w", err)
		}
		needRollback = false
	}
	return nil
}

func (r *attendanceRepository) BulkRecalcSummaries(ctx context.Context, db DBTX, studentIDs []uuid.UUID, academicYearID uuid.UUID, termID *uuid.UUID) error {
	if len(studentIDs) == 0 {
		return nil
	}
	tx, isOwner, err := beginTxIfNotTx(ctx, db)
	if err != nil {
		return err
	}
	needRollback := isOwner
	defer func() {
		if needRollback {
			_ = tx.Rollback()
		}
	}()

	for _, sid := range studentIDs {
		if err := r.RecalculateSummary(ctx, tx, sid, academicYearID, termID); err != nil {
			return err
		}
	}

	if isOwner {
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit tx: %w", err)
		}
		needRollback = false
	}
	return nil
}

// --- Exemption Methods -------------------------------------------------

func (r *attendanceRepository) CreateExemption(ctx context.Context, db DBTX, e *models.StudentAttendanceExemption) error {
	query := `
        INSERT INTO academics.student_attendance_exemptions (
            student_id, from_date, to_date, reason, approved_by, created_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
        RETURNING exemption_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		e.StudentID, e.FromDate, e.ToDate, e.Reason, e.ApprovedBy, e.CreatedBy,
	).Scan(&e.ExemptionID, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create attendance exemption",
			util.String("student_id", e.StudentID.String()),
			util.ErrorField(err))
		return fmt.Errorf("create exemption: %w", err)
	}
	return nil
}

func (r *attendanceRepository) GetExemptionByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.StudentAttendanceExemption, error) {
	query := `
        SELECT exemption_id, student_id, from_date, to_date, reason, approved_by, created_at, updated_at, created_by
        FROM academics.student_attendance_exemptions
        WHERE exemption_id = $1
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanExemption(row)
}

func (r *attendanceRepository) ListExemptions(ctx context.Context, db DBTX, studentID *uuid.UUID, fromDate, toDate *time.Time, p Pagination) ([]*models.StudentAttendanceExemption, error) {
	var conditions []string
	var args []interface{}
	idx := 1

	if studentID != nil {
		conditions = append(conditions, fmt.Sprintf("student_id = $%d", idx))
		args = append(args, *studentID)
		idx++
	}
	if fromDate != nil {
		conditions = append(conditions, fmt.Sprintf("from_date >= $%d", idx))
		args = append(args, *fromDate)
		idx++
	}
	if toDate != nil {
		conditions = append(conditions, fmt.Sprintf("to_date <= $%d", idx))
		args = append(args, *toDate)
		idx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	limit, offset := r.validatePagination(p)
	query := fmt.Sprintf(`
        SELECT exemption_id, student_id, from_date, to_date, reason, approved_by, created_at, updated_at, created_by
        FROM academics.student_attendance_exemptions
        %s
        ORDER BY from_date DESC
        LIMIT $%d OFFSET $%d
    `, whereClause, len(args)+1, len(args)+2)

	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list attendance exemptions",
			util.Any("studentID", studentID),
			util.ErrorField(err))
		return nil, fmt.Errorf("list exemptions: %w", err)
	}
	defer rows.Close()

	var result []*models.StudentAttendanceExemption
	for rows.Next() {
		e, err := r.scanExemption(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, e)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *attendanceRepository) UpdateExemption(ctx context.Context, db DBTX, e *models.StudentAttendanceExemption) error {
	query := `
        UPDATE academics.student_attendance_exemptions
        SET from_date = $2, to_date = $3, reason = $4, approved_by = $5, updated_at = NOW()
        WHERE exemption_id = $1
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		e.ExemptionID, e.FromDate, e.ToDate, e.Reason, e.ApprovedBy,
	).Scan(&e.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: exemption %s", ErrNotFound, e.ExemptionID)
		}
		r.logger.Error("failed to update attendance exemption",
			util.String("id", e.ExemptionID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update exemption: %w", err)
	}
	return nil
}

func (r *attendanceRepository) DeleteExemption(ctx context.Context, db DBTX, id uuid.UUID) error {
	query := `DELETE FROM academics.student_attendance_exemptions WHERE exemption_id = $1`
	result, err := db.ExecContext(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete attendance exemption",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete exemption: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("exemption %s not found", id)
	}
	return nil
}

// --- Scanning Helpers --------------------------------------------------

func (r *attendanceRepository) scanAttendance(row scanner) (*models.StudentAttendance, error) {
	var a models.StudentAttendance
	var markedBy, createdBy uuid.NullUUID

	err := row.Scan(
		&a.AttendanceID,
		&a.EnrollmentID,
		&a.AttendanceDate,
		&a.Status,
		&markedBy,
		&a.Remarks,
		&a.CreatedAt,
		&a.UpdatedAt,
		&createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan attendance: %w", err)
	}
	if markedBy.Valid {
		a.MarkedBy = &markedBy.UUID
	}
	if createdBy.Valid {
		a.CreatedBy = &createdBy.UUID
	}
	return &a, nil
}

func (r *attendanceRepository) scanSummary(row scanner) (*models.StudentAttendanceSummary, error) {
	var s models.StudentAttendanceSummary
	var termID uuid.NullUUID

	err := row.Scan(
		&s.SummaryID,
		&s.StudentID,
		&s.AcademicYearID,
		&termID,
		&s.TotalPresent,
		&s.TotalAbsent,
		&s.TotalLate,
		&s.TotalHalfDay,
		&s.TotalWorkingDays,
		&s.AttendancePercentage,
		&s.CreatedAt,
		&s.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan summary: %w", err)
	}
	if termID.Valid {
		s.TermID = &termID.UUID
	}
	return &s, nil
}

func (r *attendanceRepository) scanExemption(row scanner) (*models.StudentAttendanceExemption, error) {
	var e models.StudentAttendanceExemption
	var approvedBy, createdBy uuid.NullUUID

	err := row.Scan(
		&e.ExemptionID,
		&e.StudentID,
		&e.FromDate,
		&e.ToDate,
		&e.Reason,
		&approvedBy,
		&e.CreatedAt,
		&e.UpdatedAt,
		&createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan exemption: %w", err)
	}
	if approvedBy.Valid {
		e.ApprovedBy = &approvedBy.UUID
	}
	if createdBy.Valid {
		e.CreatedBy = &createdBy.UUID
	}
	return &e, nil
}
