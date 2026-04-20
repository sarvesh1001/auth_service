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

type AcademicSessionRepository interface {
	Create(ctx context.Context, db DBTX, session *models.AcademicSession) error
	BulkCreate(ctx context.Context, db DBTX, sessions []*models.AcademicSession) error
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.AcademicSession, error)
	GetByTimetableEntryAndDate(ctx context.Context, db DBTX, entryID uuid.UUID, date time.Time) (*models.AcademicSession, error)
	// GetActiveSessionForStudentAtTime finds a session that matches the student's section,
	// session_date = date, and current_time between start_time and end_time.
	GetActiveSessionForStudentAtTime(ctx context.Context, db DBTX, studentID, companyID uuid.UUID, date, currentTime time.Time) (*models.AcademicSession, error)
	List(ctx context.Context, db DBTX, filter AcademicSessionFilter, p Pagination, s Sort) ([]*models.AcademicSession, error)
	Count(ctx context.Context, db DBTX, filter AcademicSessionFilter) (int64, error)
	Update(ctx context.Context, db DBTX, session *models.AcademicSession) error
	UpdateStatus(ctx context.Context, db DBTX, id uuid.UUID, status models.AcademicSessionStatus, updatedBy *uuid.UUID) error
	Delete(ctx context.Context, db DBTX, id uuid.UUID) error
	// For session generation: check if session already exists for a given entry and date
	Exists(ctx context.Context, db DBTX, timetableEntryID uuid.UUID, date time.Time) (bool, error)
}

type AcademicSessionFilter struct {
	SectionID   *uuid.UUID
	TeacherID   *uuid.UUID
	SubjectID   *uuid.UUID
	SessionDate *time.Time
	FromDate    *time.Time
	ToDate      *time.Time
	Status      *models.AcademicSessionStatus
}

type academicSessionRepository struct {
	logger *zap.Logger
}

func NewAcademicSessionRepository(logger *zap.Logger) AcademicSessionRepository {
	return &academicSessionRepository{
		logger: logger.Named("academic_session_repo"),
	}
}

var allowedAcademicSessionSortFields = map[string]bool{
	"session_date": true,
	"start_time":   true,
	"end_time":     true,
	"status":       true,
	"created_at":   true,
	"updated_at":   true,
}

func (r *academicSessionRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "session_date"
	}
	if !allowedAcademicSessionSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY a.%s %s", field, dir), nil
}

func (r *academicSessionRepository) validatePagination(p Pagination) (int, int) {
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

func (r *academicSessionRepository) buildFilter(filter AcademicSessionFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.SectionID != nil {
		conditions = append(conditions, fmt.Sprintf("a.section_id = $%d", idx))
		args = append(args, *filter.SectionID)
		idx++
	}
	if filter.TeacherID != nil {
		conditions = append(conditions, fmt.Sprintf("a.teacher_id = $%d", idx))
		args = append(args, *filter.TeacherID)
		idx++
	}
	if filter.SubjectID != nil {
		conditions = append(conditions, fmt.Sprintf("a.subject_id = $%d", idx))
		args = append(args, *filter.SubjectID)
		idx++
	}
	if filter.SessionDate != nil {
		conditions = append(conditions, fmt.Sprintf("a.session_date = $%d", idx))
		args = append(args, *filter.SessionDate)
		idx++
	}
	if filter.FromDate != nil {
		conditions = append(conditions, fmt.Sprintf("a.session_date >= $%d", idx))
		args = append(args, *filter.FromDate)
		idx++
	}
	if filter.ToDate != nil {
		conditions = append(conditions, fmt.Sprintf("a.session_date <= $%d", idx))
		args = append(args, *filter.ToDate)
		idx++
	}
	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("a.status = $%d", idx))
		args = append(args, *filter.Status)
		idx++
	}

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *academicSessionRepository) scanSession(row scanner) (*models.AcademicSession, error) {
	var s models.AcademicSession
	var teacherID, roomID, createdBy, updatedBy uuid.NullUUID

	err := row.Scan(
		&s.SessionID,
		&s.TimetableEntryID,
		&s.SessionDate,
		&s.StartTime,
		&s.EndTime,
		&teacherID,
		&roomID,
		&s.Status,
		&s.SectionID,
		&s.SubjectID,
		&s.SlotID,
		&s.CreatedAt,
		&s.UpdatedAt,
		&createdBy,
		&updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan academic session: %w", err)
	}

	if teacherID.Valid {
		s.TeacherID = &teacherID.UUID
	}
	if roomID.Valid {
		s.RoomID = &roomID.UUID
	}
	if createdBy.Valid {
		s.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		s.UpdatedBy = &updatedBy.UUID
	}
	return &s, nil
}

// Create inserts a new academic session.
func (r *academicSessionRepository) Create(ctx context.Context, db DBTX, session *models.AcademicSession) error {
	query := `
		INSERT INTO academics.academic_session (
			timetable_entry_id, session_date, start_time, end_time,
			teacher_id, room_id, status, section_id, subject_id, slot_id,
			created_by, updated_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), NOW())
		RETURNING session_id, created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		session.TimetableEntryID, session.SessionDate, session.StartTime, session.EndTime,
		session.TeacherID, session.RoomID, session.Status,
		session.SectionID, session.SubjectID, session.SlotID,
		session.CreatedBy, session.UpdatedBy,
	).Scan(&session.SessionID, &session.CreatedAt, &session.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create academic session",
			util.String("timetable_entry_id", session.TimetableEntryID.String()),
			util.Time("date", session.SessionDate),
			util.ErrorField(err))
		return fmt.Errorf("create academic session: %w", err)
	}
	return nil
}

// BulkCreate inserts many sessions efficiently.
func (r *academicSessionRepository) BulkCreate(ctx context.Context, db DBTX, sessions []*models.AcademicSession) error {
	if len(sessions) == 0 {
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
		INSERT INTO academics.academic_session (
			timetable_entry_id, session_date, start_time, end_time,
			teacher_id, room_id, status, section_id, subject_id, slot_id,
			created_by, updated_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), NOW())
		RETURNING session_id, created_at, updated_at
	`)
	if err != nil {
		return fmt.Errorf("prepare bulk insert: %w", err)
	}
	defer stmt.Close()

	for _, s := range sessions {
		err := stmt.QueryRowContext(ctx,
			s.TimetableEntryID, s.SessionDate, s.StartTime, s.EndTime,
			s.TeacherID, s.RoomID, s.Status,
			s.SectionID, s.SubjectID, s.SlotID,
			s.CreatedBy, s.UpdatedBy,
		).Scan(&s.SessionID, &s.CreatedAt, &s.UpdatedAt)
		if err != nil {
			r.logger.Error("bulk create academic session failed",
				util.String("timetable_entry_id", s.TimetableEntryID.String()),
				util.Time("date", s.SessionDate),
				util.ErrorField(err))
			return fmt.Errorf("bulk create academic session row: %w", err)
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

// GetByID retrieves a session by its ID.
func (r *academicSessionRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.AcademicSession, error) {
	query := `
		SELECT session_id, timetable_entry_id, session_date, start_time, end_time,
		       teacher_id, room_id, status, section_id, subject_id, slot_id,
		       created_at, updated_at, created_by, updated_by
		FROM academics.academic_session
		WHERE session_id = $1
	`
	row := db.QueryRowContext(ctx, query, id)
	return r.scanSession(row)
}

// GetByTimetableEntryAndDate returns a session for a specific timetable entry on a given date.
func (r *academicSessionRepository) GetByTimetableEntryAndDate(ctx context.Context, db DBTX, entryID uuid.UUID, date time.Time) (*models.AcademicSession, error) {
	query := `
		SELECT session_id, timetable_entry_id, session_date, start_time, end_time,
		       teacher_id, room_id, status, section_id, subject_id, slot_id,
		       created_at, updated_at, created_by, updated_by
		FROM academics.academic_session
		WHERE timetable_entry_id = $1 AND session_date = $2
	`
	row := db.QueryRowContext(ctx, query, entryID, date)
	return r.scanSession(row)
}

// GetActiveSessionForStudentAtTime finds the session that the student should be attending at a given date and time.
// It uses the student's active enrollment on that date to get the section, then finds a session
// for that section where session_date = date and the current time falls between start_time and end_time.
func (r *academicSessionRepository) GetActiveSessionForStudentAtTime(ctx context.Context, db DBTX, studentID, companyID uuid.UUID, date, currentTime time.Time) (*models.AcademicSession, error) {
	// First get the student's active enrollment on the given date
	// We join with enrollment_repository's logic: use academic_year dates
	query := `
		SELECT a.session_id, a.timetable_entry_id, a.session_date, a.start_time, a.end_time,
		       a.teacher_id, a.room_id, a.status, a.section_id, a.subject_id, a.slot_id,
		       a.created_at, a.updated_at, a.created_by, a.updated_by
		FROM academics.academic_session a
		INNER JOIN academics.enrollments e ON a.section_id = e.section_id
		INNER JOIN academics.academic_year ay ON e.academic_year_id = ay.academic_year_id
		INNER JOIN academics.students s ON e.student_id = s.student_id
		WHERE s.company_id = $1
		  AND e.student_id = $2
		  AND e.status = 'active'
		  AND ay.start_date <= $3
		  AND ay.end_date >= $3
		  AND a.session_date = $3
		  AND a.start_time <= $4
		  AND a.end_time >= $4
		LIMIT 1
	`
	row := db.QueryRowContext(ctx, query, companyID, studentID, date, currentTime)
	return r.scanSession(row)
}

// List returns filtered and paginated sessions.
func (r *academicSessionRepository) List(ctx context.Context, db DBTX, filter AcademicSessionFilter, p Pagination, s Sort) ([]*models.AcademicSession, error) {
	where, args := r.buildFilter(filter)
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT session_id, timetable_entry_id, session_date, start_time, end_time,
		       teacher_id, room_id, status, section_id, subject_id, slot_id,
		       created_at, updated_at, created_by, updated_by
		FROM academics.academic_session a
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list academic sessions",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list academic sessions: %w", err)
	}
	defer rows.Close()

	var result []*models.AcademicSession
	for rows.Next() {
		session, err := r.scanSession(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, session)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// Count returns the number of sessions matching the filter.
func (r *academicSessionRepository) Count(ctx context.Context, db DBTX, filter AcademicSessionFilter) (int64, error) {
	where, args := r.buildFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.academic_session a %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count academic sessions",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count academic sessions: %w", err)
	}
	return count, nil
}

// Update modifies an existing session (full update). Uses optimistic locking via version if needed.
func (r *academicSessionRepository) Update(ctx context.Context, db DBTX, session *models.AcademicSession) error {
	query := `
		UPDATE academics.academic_session
		SET timetable_entry_id = $2,
		    session_date = $3,
		    start_time = $4,
		    end_time = $5,
		    teacher_id = $6,
		    room_id = $7,
		    status = $8,
		    section_id = $9,
		    subject_id = $10,
		    slot_id = $11,
		    updated_by = $12,
		    updated_at = NOW()
		WHERE session_id = $1
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		session.SessionID,
		session.TimetableEntryID,
		session.SessionDate,
		session.StartTime,
		session.EndTime,
		session.TeacherID,
		session.RoomID,
		session.Status,
		session.SectionID,
		session.SubjectID,
		session.SlotID,
		session.UpdatedBy,
	).Scan(&session.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: academic session %s", ErrNotFound, session.SessionID)
		}
		r.logger.Error("failed to update academic session",
			util.String("session_id", session.SessionID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update academic session: %w", err)
	}
	return nil
}

// UpdateStatus changes only the status of a session.
func (r *academicSessionRepository) UpdateStatus(ctx context.Context, db DBTX, id uuid.UUID, status models.AcademicSessionStatus, updatedBy *uuid.UUID) error {
	query := `
		UPDATE academics.academic_session
		SET status = $2, updated_by = $3, updated_at = NOW()
		WHERE session_id = $1
	`
	result, err := db.ExecContext(ctx, query, id, status, updatedBy)
	if err != nil {
		r.logger.Error("failed to update academic session status",
			util.String("session_id", id.String()),
			util.String("status", string(status)),
			util.ErrorField(err))
		return fmt.Errorf("update session status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("academic session %s not found", id)
	}
	return nil
}

// Delete soft-deletes a session (sets deleted_at? But our table has no deleted_at; we can hard delete or add a flag.
// According to your schema, there is no deleted_at. We'll hard delete as per existing pattern for similar tables.
func (r *academicSessionRepository) Delete(ctx context.Context, db DBTX, id uuid.UUID) error {
	query := `DELETE FROM academics.academic_session WHERE session_id = $1`
	result, err := db.ExecContext(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete academic session",
			util.String("session_id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete academic session: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("academic session %s not found", id)
	}
	return nil
}

// Exists checks whether a session already exists for a given timetable entry and date.
func (r *academicSessionRepository) Exists(ctx context.Context, db DBTX, timetableEntryID uuid.UUID, date time.Time) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM academics.academic_session WHERE timetable_entry_id = $1 AND session_date = $2)`
	var exists bool
	err := db.QueryRowContext(ctx, query, timetableEntryID, date).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check existence of academic session",
			util.String("timetable_entry_id", timetableEntryID.String()),
			util.Time("date", date),
			util.ErrorField(err))
		return false, fmt.Errorf("exists academic session: %w", err)
	}
	return exists, nil
}
