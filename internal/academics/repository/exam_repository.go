package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/util"
)

// ==================== Common Types ====================

// ==================== Combined Exam Repository ====================

type ExamRepository interface {
	// Exam methods
	CreateExam(ctx context.Context, db DBTX, e *models.Exam) error
	GetExamByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Exam, error)
	ListExams(ctx context.Context, db DBTX, filter ExamFilter, p Pagination, s Sort) ([]*models.Exam, error)
	CountExams(ctx context.Context, db DBTX, filter ExamFilter) (int64, error)
	UpdateExam(ctx context.Context, db DBTX, e *models.Exam) error
	DeleteExam(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error
	GetExamsByTerm(ctx context.Context, db DBTX, termID uuid.UUID) ([]*models.Exam, error)

	// ExamSchedule methods
	CreateExamSchedule(ctx context.Context, db DBTX, s *models.ExamSchedule) error
	GetExamScheduleByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.ExamSchedule, error)
	ListExamSchedules(ctx context.Context, db DBTX, filter ExamScheduleFilter, p Pagination, s Sort) ([]*models.ExamSchedule, error)
	UpdateExamSchedule(ctx context.Context, db DBTX, s *models.ExamSchedule) error
	DeleteExamSchedule(ctx context.Context, db DBTX, id uuid.UUID) error
	GetExamSchedulesByExam(ctx context.Context, db DBTX, examID uuid.UUID) ([]*models.ExamSchedule, error)

	// ExamResult methods
	CreateExamResult(ctx context.Context, db DBTX, r *models.ExamResult) error
	BulkCreateExamResults(ctx context.Context, db DBTX, results []*models.ExamResult) error
	GetExamResultByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.ExamResult, error)
	ListExamResults(ctx context.Context, db DBTX, filter ExamResultFilter, p Pagination, s Sort) ([]*models.ExamResult, error)
	UpdateExamResult(ctx context.Context, db DBTX, r *models.ExamResult) error
	DeleteExamResult(ctx context.Context, db DBTX, id uuid.UUID) error
	GetExamResultsByExamAndEnrollment(ctx context.Context, db DBTX, examID, enrollmentID uuid.UUID) ([]*models.ExamResult, error)

	// ExamGrade methods
	CreateExamGrade(ctx context.Context, db DBTX, g *models.ExamGrade) error
	GetExamGradeByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.ExamGrade, error)
	ListExamGrades(ctx context.Context, db DBTX, filter ExamGradeFilter, p Pagination, s Sort) ([]*models.ExamGrade, error)
	UpdateExamGrade(ctx context.Context, db DBTX, g *models.ExamGrade) error
	DeleteExamGrade(ctx context.Context, db DBTX, id uuid.UUID) error
	GetExamGradesByExam(ctx context.Context, db DBTX, examID uuid.UUID) ([]*models.ExamGrade, error)
}

type examRepository struct {
	logger *zap.Logger
}

func NewExamRepository(logger *zap.Logger) ExamRepository {
	return &examRepository{logger: logger.Named("exam_repo")}
}

// ==================== Exam Filter and Helpers ====================

var allowedExamSortFields = map[string]bool{
	"created_at": true,
	"updated_at": true,
	"exam_name":  true,
	"start_date": true,
	"end_date":   true,
	"is_active":  true,
}

func (r *examRepository) validateExamSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "created_at"
	}
	if !allowedExamSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY e.%s %s", field, dir), nil
}

func (r *examRepository) buildExamFilter(filter ExamFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.AcademicYearID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("e.academic_year_id = $%d", idx))
		args = append(args, filter.AcademicYearID)
		idx++
	}
	if filter.TermID != nil {
		conditions = append(conditions, fmt.Sprintf("e.term_id = $%d", idx))
		args = append(args, *filter.TermID)
		idx++
	}
	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("e.is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("e.exam_name ILIKE $%d", idx))
		args = append(args, "%"+filter.Search+"%")
		idx++
	}
	if filter.StartDateFrom != nil {
		conditions = append(conditions, fmt.Sprintf("e.start_date >= $%d", idx))
		args = append(args, *filter.StartDateFrom)
		idx++
	}
	if filter.StartDateTo != nil {
		conditions = append(conditions, fmt.Sprintf("e.start_date <= $%d", idx))
		args = append(args, *filter.StartDateTo)
		idx++
	}
	if filter.EndDateFrom != nil {
		conditions = append(conditions, fmt.Sprintf("e.end_date >= $%d", idx))
		args = append(args, *filter.EndDateFrom)
		idx++
	}
	if filter.EndDateTo != nil {
		conditions = append(conditions, fmt.Sprintf("e.end_date <= $%d", idx))
		args = append(args, *filter.EndDateTo)
		idx++
	}
	conditions = append(conditions, "e.deleted_at IS NULL")

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *examRepository) scanExam(row scanner) (*models.Exam, error) {
	var e models.Exam
	var createdBy, updatedBy uuid.NullUUID

	err := row.Scan(
		&e.ExamID,
		&e.AcademicYearID,
		&e.TermID,
		&e.ExamName,
		&e.StartDate,
		&e.EndDate,
		&e.Description,
		&e.IsActive,
		&e.CreatedAt,
		&e.UpdatedAt,
		&createdBy,
		&updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan exam: %w", err)
	}

	if createdBy.Valid {
		e.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		e.UpdatedBy = &updatedBy.UUID
	}
	return &e, nil
}

// ==================== ExamSchedule Filter and Helpers ====================

var allowedExamScheduleSortFields = map[string]bool{
	"created_at": true,
	"updated_at": true,
	"date":       true,
	"start_time": true,
}

func (r *examRepository) validateExamScheduleSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "date"
	}
	if !allowedExamScheduleSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "ASC"
	}
	return fmt.Sprintf("ORDER BY es.%s %s", field, dir), nil
}

func (r *examRepository) buildExamScheduleFilter(filter ExamScheduleFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.ExamID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("es.exam_id = $%d", idx))
		args = append(args, filter.ExamID)
		idx++
	}
	if filter.SubjectID != nil {
		conditions = append(conditions, fmt.Sprintf("es.subject_id = $%d", idx))
		args = append(args, *filter.SubjectID)
		idx++
	}
	if filter.RoomID != nil {
		conditions = append(conditions, fmt.Sprintf("es.room_id = $%d", idx))
		args = append(args, *filter.RoomID)
		idx++
	}
	if filter.DateFrom != nil {
		conditions = append(conditions, fmt.Sprintf("es.date >= $%d", idx))
		args = append(args, *filter.DateFrom)
		idx++
	}
	if filter.DateTo != nil {
		conditions = append(conditions, fmt.Sprintf("es.date <= $%d", idx))
		args = append(args, *filter.DateTo)
		idx++
	}

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *examRepository) scanExamSchedule(row scanner) (*models.ExamSchedule, error) {
	var s models.ExamSchedule
	var startTime, endTime sql.NullTime
	var roomID uuid.NullUUID
	var createdBy, updatedBy uuid.NullUUID

	err := row.Scan(
		&s.ScheduleID,
		&s.ExamID,
		&s.SubjectID,
		&s.Date,
		&startTime,
		&endTime,
		&roomID,
		&s.MaxMarks,
		&s.PassingMarks,
		&s.CreatedAt,
		&s.UpdatedAt,
		&createdBy,
		&updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan exam schedule: %w", err)
	}

	if startTime.Valid {
		s.StartTime = &startTime.Time
	}
	if endTime.Valid {
		s.EndTime = &endTime.Time
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

// ==================== ExamResult Filter and Helpers ====================

var allowedExamResultSortFields = map[string]bool{
	"created_at":     true,
	"updated_at":     true,
	"marks_obtained": true,
	"grade":          true,
}

func (r *examRepository) validateExamResultSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "created_at"
	}
	if !allowedExamResultSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY er.%s %s", field, dir), nil
}

func (r *examRepository) buildExamResultFilter(filter ExamResultFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.ExamID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("er.exam_id = $%d", idx))
		args = append(args, filter.ExamID)
		idx++
	}
	if filter.EnrollmentID != nil {
		conditions = append(conditions, fmt.Sprintf("er.enrollment_id = $%d", idx))
		args = append(args, *filter.EnrollmentID)
		idx++
	}
	if filter.SubjectID != nil {
		conditions = append(conditions, fmt.Sprintf("er.subject_id = $%d", idx))
		args = append(args, *filter.SubjectID)
		idx++
	}
	if filter.Grade != nil {
		conditions = append(conditions, fmt.Sprintf("er.grade = $%d", idx))
		args = append(args, *filter.Grade)
		idx++
	}
	if filter.MarksMin != nil {
		conditions = append(conditions, fmt.Sprintf("er.marks_obtained >= $%d", idx))
		args = append(args, *filter.MarksMin)
		idx++
	}
	if filter.MarksMax != nil {
		conditions = append(conditions, fmt.Sprintf("er.marks_obtained <= $%d", idx))
		args = append(args, *filter.MarksMax)
		idx++
	}

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *examRepository) scanExamResult(row scanner) (*models.ExamResult, error) {
	var res models.ExamResult
	var marksObtained sql.NullFloat64
	var grade, remarks sql.NullString
	var enteredBy, createdBy uuid.NullUUID

	err := row.Scan(
		&res.ResultID,
		&res.ExamID,
		&res.EnrollmentID,
		&res.SubjectID,
		&marksObtained,
		&grade,
		&remarks,
		&enteredBy,
		&res.EnteredAt,
		&res.CreatedAt,
		&res.UpdatedAt,
		&createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan exam result: %w", err)
	}

	if marksObtained.Valid {
		res.MarksObtained = &marksObtained.Float64
	}
	if grade.Valid {
		res.Grade = grade.String
	}
	if remarks.Valid {
		res.Remarks = remarks.String
	}
	if enteredBy.Valid {
		res.EnteredBy = &enteredBy.UUID
	}
	if createdBy.Valid {
		res.CreatedBy = &createdBy.UUID
	}
	return &res, nil
}

// ==================== ExamGrade Filter and Helpers ====================

var allowedExamGradeSortFields = map[string]bool{
	"created_at": true,
	"grade_name": true,
	"min_marks":  true,
	"max_marks":  true,
}

func (r *examRepository) validateExamGradeSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "min_marks"
	}
	if !allowedExamGradeSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "ASC"
	}
	return fmt.Sprintf("ORDER BY eg.%s %s", field, dir), nil
}

func (r *examRepository) buildExamGradeFilter(filter ExamGradeFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.ExamID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("eg.exam_id = $%d", idx))
		args = append(args, filter.ExamID)
		idx++
	}

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *examRepository) scanExamGrade(row scanner) (*models.ExamGrade, error) {
	var g models.ExamGrade
	err := row.Scan(
		&g.GradeID,
		&g.ExamID,
		&g.GradeName,
		&g.MinMarks,
		&g.MaxMarks,
		&g.GradePoint,
		&g.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan exam grade: %w", err)
	}
	return &g, nil
}

// ==================== Exam Implementation ====================

func (r *examRepository) CreateExam(ctx context.Context, db DBTX, e *models.Exam) error {
	query := `
        INSERT INTO academics.exams (
            academic_year_id, term_id, exam_name, start_date, end_date,
            description, is_active, created_by, updated_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
        RETURNING exam_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		e.AcademicYearID, e.TermID, e.ExamName, e.StartDate, e.EndDate,
		e.Description, e.IsActive, e.CreatedBy, e.UpdatedBy,
	).Scan(&e.ExamID, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create exam",
			util.String("exam_name", e.ExamName),
			util.ErrorField(err))
		return fmt.Errorf("create exam: %w", err)
	}
	return nil
}

func (r *examRepository) GetExamByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Exam, error) {
	query := `
        SELECT
            exam_id, academic_year_id, term_id, exam_name, start_date, end_date,
            description, is_active, created_at, updated_at, created_by, updated_by
        FROM academics.exams
        WHERE exam_id = $1 AND deleted_at IS NULL
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanExam(row)
}

func (r *examRepository) ListExams(ctx context.Context, db DBTX, filter ExamFilter, p Pagination, s Sort) ([]*models.Exam, error) {
	where, args := r.buildExamFilter(filter)
	orderBy, err := r.validateExamSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
        SELECT
            exam_id, academic_year_id, term_id, exam_name, start_date, end_date,
            description, is_active, created_at, updated_at, created_by, updated_by
        FROM academics.exams e
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list exams",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list exams: %w", err)
	}
	defer rows.Close()

	var result []*models.Exam
	for rows.Next() {
		e, err := r.scanExam(rows)
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

func (r *examRepository) CountExams(ctx context.Context, db DBTX, filter ExamFilter) (int64, error) {
	where, args := r.buildExamFilter(filter)

	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.exams e %s", where)

	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count exams",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count exams: %w", err)
	}
	return count, nil
}

func (r *examRepository) UpdateExam(ctx context.Context, db DBTX, e *models.Exam) error {
	query := `
        UPDATE academics.exams
        SET
            term_id = $2,
            exam_name = $3,
            start_date = $4,
            end_date = $5,
            description = $6,
            is_active = $7,
            updated_by = $8,
            updated_at = NOW()
        WHERE exam_id = $1 AND deleted_at IS NULL
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		e.ExamID, e.TermID, e.ExamName, e.StartDate, e.EndDate,
		e.Description, e.IsActive, e.UpdatedBy,
	).Scan(&e.UpdatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: exam %s", ErrNotFound, e.ExamID)
		}
		r.logger.Error("failed to update exam",
			util.String("id", e.ExamID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update exam: %w", err)
	}
	return nil
}

func (r *examRepository) DeleteExam(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error {
	query := `UPDATE academics.exams SET deleted_at = NOW(), updated_by = $2, updated_at = NOW() WHERE exam_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, deletedBy)
	if err != nil {
		r.logger.Error("failed to delete exam",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete exam: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("exam %s not found or already deleted", id)
	}
	return nil
}

func (r *examRepository) GetExamsByTerm(ctx context.Context, db DBTX, termID uuid.UUID) ([]*models.Exam, error) {
	filter := ExamFilter{TermID: &termID}
	return r.ListExams(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "start_date", Direction: "ASC"})
}

// ==================== ExamSchedule Implementation ====================

func (r *examRepository) CreateExamSchedule(ctx context.Context, db DBTX, s *models.ExamSchedule) error {
	query := `
        INSERT INTO academics.exam_schedules (
            exam_id, subject_id, date, start_time, end_time, room_id,
            max_marks, passing_marks, created_by, updated_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW())
        RETURNING schedule_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		s.ExamID, s.SubjectID, s.Date, s.StartTime, s.EndTime, s.RoomID,
		s.MaxMarks, s.PassingMarks, s.CreatedBy, s.UpdatedBy,
	).Scan(&s.ScheduleID, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create exam schedule",
			util.String("exam_id", s.ExamID.String()),
			util.String("subject_id", s.SubjectID.String()),
			util.ErrorField(err))
		return fmt.Errorf("create exam schedule: %w", err)
	}
	return nil
}

func (r *examRepository) GetExamScheduleByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.ExamSchedule, error) {
	query := `
        SELECT
            schedule_id, exam_id, subject_id, date, start_time, end_time, room_id,
            max_marks, passing_marks, created_at, updated_at, created_by, updated_by
        FROM academics.exam_schedules
        WHERE schedule_id = $1
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanExamSchedule(row)
}

func (r *examRepository) ListExamSchedules(ctx context.Context, db DBTX, filter ExamScheduleFilter, p Pagination, s Sort) ([]*models.ExamSchedule, error) {
	where, args := r.buildExamScheduleFilter(filter)
	orderBy, err := r.validateExamScheduleSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
        SELECT
            schedule_id, exam_id, subject_id, date, start_time, end_time, room_id,
            max_marks, passing_marks, created_at, updated_at, created_by, updated_by
        FROM academics.exam_schedules es
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list exam schedules",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list exam schedules: %w", err)
	}
	defer rows.Close()

	var result []*models.ExamSchedule
	for rows.Next() {
		s, err := r.scanExamSchedule(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *examRepository) UpdateExamSchedule(ctx context.Context, db DBTX, s *models.ExamSchedule) error {
	query := `
        UPDATE academics.exam_schedules
        SET
            subject_id = $2,
            date = $3,
            start_time = $4,
            end_time = $5,
            room_id = $6,
            max_marks = $7,
            passing_marks = $8,
            updated_by = $9,
            updated_at = NOW()
        WHERE schedule_id = $1
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		s.ScheduleID, s.SubjectID, s.Date, s.StartTime, s.EndTime, s.RoomID,
		s.MaxMarks, s.PassingMarks, s.UpdatedBy,
	).Scan(&s.UpdatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: exam schedule %s", ErrNotFound, s.ScheduleID)
		}
		r.logger.Error("failed to update exam schedule",
			util.String("id", s.ScheduleID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update exam schedule: %w", err)
	}
	return nil
}

func (r *examRepository) DeleteExamSchedule(ctx context.Context, db DBTX, id uuid.UUID) error {
	query := `DELETE FROM academics.exam_schedules WHERE schedule_id = $1`
	result, err := db.ExecContext(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete exam schedule",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete exam schedule: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("exam schedule %s not found", id)
	}
	return nil
}

func (r *examRepository) GetExamSchedulesByExam(ctx context.Context, db DBTX, examID uuid.UUID) ([]*models.ExamSchedule, error) {
	filter := ExamScheduleFilter{ExamID: examID}
	return r.ListExamSchedules(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "date", Direction: "ASC"})
}

// ==================== ExamResult Implementation ====================

func (r *examRepository) CreateExamResult(ctx context.Context, db DBTX, res *models.ExamResult) error {
	query := `
        INSERT INTO academics.exam_results (
            exam_id, enrollment_id, subject_id, marks_obtained, grade, remarks,
            entered_by, entered_at, created_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8, NOW(), NOW())
        RETURNING result_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		res.ExamID, res.EnrollmentID, res.SubjectID, res.MarksObtained, res.Grade, res.Remarks,
		res.EnteredBy, res.CreatedBy,
	).Scan(&res.ResultID, &res.CreatedAt, &res.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create exam result",
			util.String("exam_id", res.ExamID.String()),
			util.String("enrollment_id", res.EnrollmentID.String()),
			util.ErrorField(err))
		return fmt.Errorf("create exam result: %w", err)
	}
	return nil
}

func (r *examRepository) BulkCreateExamResults(ctx context.Context, db DBTX, results []*models.ExamResult) error {
	if len(results) == 0 {
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
        INSERT INTO academics.exam_results (
            exam_id, enrollment_id, subject_id, marks_obtained, grade, remarks,
            entered_by, entered_at, created_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8, NOW(), NOW())
        RETURNING result_id, created_at, updated_at
    `)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, res := range results {
		err := stmt.QueryRowContext(ctx,
			res.ExamID, res.EnrollmentID, res.SubjectID, res.MarksObtained, res.Grade, res.Remarks,
			res.EnteredBy, res.CreatedBy,
		).Scan(&res.ResultID, &res.CreatedAt, &res.UpdatedAt)
		if err != nil {
			r.logger.Error("bulk create exam result failed",
				util.String("exam_id", res.ExamID.String()),
				util.String("enrollment_id", res.EnrollmentID.String()),
				util.ErrorField(err))
			return fmt.Errorf("bulk create exam result row: %w", err)
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

func (r *examRepository) GetExamResultByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.ExamResult, error) {
	query := `
        SELECT
            result_id, exam_id, enrollment_id, subject_id, marks_obtained, grade, remarks,
            entered_by, entered_at, created_at, updated_at, created_by
        FROM academics.exam_results
        WHERE result_id = $1
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanExamResult(row)
}

func (r *examRepository) ListExamResults(ctx context.Context, db DBTX, filter ExamResultFilter, p Pagination, s Sort) ([]*models.ExamResult, error) {
	where, args := r.buildExamResultFilter(filter)
	orderBy, err := r.validateExamResultSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
        SELECT
            result_id, exam_id, enrollment_id, subject_id, marks_obtained, grade, remarks,
            entered_by, entered_at, created_at, updated_at, created_by
        FROM academics.exam_results er
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list exam results",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list exam results: %w", err)
	}
	defer rows.Close()

	var result []*models.ExamResult
	for rows.Next() {
		res, err := r.scanExamResult(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *examRepository) UpdateExamResult(ctx context.Context, db DBTX, res *models.ExamResult) error {
	query := `
        UPDATE academics.exam_results
        SET
            marks_obtained = $2,
            grade = $3,
            remarks = $4,
            entered_by = $5,
            entered_at = NOW(),
            updated_at = NOW()
        WHERE result_id = $1
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		res.ResultID, res.MarksObtained, res.Grade, res.Remarks, res.EnteredBy,
	).Scan(&res.UpdatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: exam result %s", ErrNotFound, res.ResultID)
		}
		r.logger.Error("failed to update exam result",
			util.String("id", res.ResultID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update exam result: %w", err)
	}
	return nil
}

func (r *examRepository) DeleteExamResult(ctx context.Context, db DBTX, id uuid.UUID) error {
	query := `DELETE FROM academics.exam_results WHERE result_id = $1`
	result, err := db.ExecContext(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete exam result",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete exam result: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("exam result %s not found", id)
	}
	return nil
}

func (r *examRepository) GetExamResultsByExamAndEnrollment(ctx context.Context, db DBTX, examID, enrollmentID uuid.UUID) ([]*models.ExamResult, error) {
	filter := ExamResultFilter{
		ExamID:       examID,
		EnrollmentID: &enrollmentID,
	}
	return r.ListExamResults(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "subject_id", Direction: "ASC"})
}

// ==================== ExamGrade Implementation ====================

func (r *examRepository) CreateExamGrade(ctx context.Context, db DBTX, g *models.ExamGrade) error {
	query := `
        INSERT INTO academics.exam_grades (
            exam_id, grade_name, min_marks, max_marks, grade_point, created_at
        ) VALUES ($1, $2, $3, $4, $5, NOW())
        RETURNING grade_id, created_at
    `
	err := db.QueryRowContext(ctx, query,
		g.ExamID, g.GradeName, g.MinMarks, g.MaxMarks, g.GradePoint,
	).Scan(&g.GradeID, &g.CreatedAt)
	if err != nil {
		r.logger.Error("failed to create exam grade",
			util.String("exam_id", g.ExamID.String()),
			util.String("grade_name", g.GradeName),
			util.ErrorField(err))
		return fmt.Errorf("create exam grade: %w", err)
	}
	return nil
}

func (r *examRepository) GetExamGradeByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.ExamGrade, error) {
	query := `
        SELECT
            grade_id, exam_id, grade_name, min_marks, max_marks, grade_point, created_at
        FROM academics.exam_grades
        WHERE grade_id = $1
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanExamGrade(row)
}

func (r *examRepository) ListExamGrades(ctx context.Context, db DBTX, filter ExamGradeFilter, p Pagination, s Sort) ([]*models.ExamGrade, error) {
	where, args := r.buildExamGradeFilter(filter)
	orderBy, err := r.validateExamGradeSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
        SELECT
            grade_id, exam_id, grade_name, min_marks, max_marks, grade_point, created_at
        FROM academics.exam_grades eg
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list exam grades",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list exam grades: %w", err)
	}
	defer rows.Close()

	var result []*models.ExamGrade
	for rows.Next() {
		g, err := r.scanExamGrade(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, g)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *examRepository) UpdateExamGrade(ctx context.Context, db DBTX, g *models.ExamGrade) error {
	query := `
        UPDATE academics.exam_grades
        SET
            grade_name = $2,
            min_marks = $3,
            max_marks = $4,
            grade_point = $5
        WHERE grade_id = $1
        RETURNING created_at
    `
	err := db.QueryRowContext(ctx, query,
		g.GradeID, g.GradeName, g.MinMarks, g.MaxMarks, g.GradePoint,
	).Scan(&g.CreatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: exam grade %s", ErrNotFound, g.GradeID)
		}
		r.logger.Error("failed to update exam grade",
			util.String("id", g.GradeID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update exam grade: %w", err)
	}
	return nil
}

func (r *examRepository) DeleteExamGrade(ctx context.Context, db DBTX, id uuid.UUID) error {
	query := `DELETE FROM academics.exam_grades WHERE grade_id = $1`
	result, err := db.ExecContext(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete exam grade",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete exam grade: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("exam grade %s not found", id)
	}
	return nil
}

func (r *examRepository) GetExamGradesByExam(ctx context.Context, db DBTX, examID uuid.UUID) ([]*models.ExamGrade, error) {
	filter := ExamGradeFilter{ExamID: examID}
	return r.ListExamGrades(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "min_marks", Direction: "ASC"})
}

// ==================== Common Helpers ====================

func (r *examRepository) validatePagination(p Pagination) (int, int) {
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
