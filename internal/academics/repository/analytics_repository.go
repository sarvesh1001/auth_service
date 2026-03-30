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

// AnalyticsRepository defines all analytics data operations.
type AnalyticsRepository interface {
	// Student performance summaries
	GetStudentPerformanceSummary(ctx context.Context, db DBTX, id uuid.UUID) (*models.StudentPerformanceSummary, error)
	ListStudentPerformanceSummaries(ctx context.Context, db DBTX, filter StudentPerformanceSummaryFilter, p Pagination, s Sort) ([]*models.StudentPerformanceSummary, error)
	CountStudentPerformanceSummaries(ctx context.Context, db DBTX, filter StudentPerformanceSummaryFilter) (int64, error)
	CreateStudentPerformanceSummary(ctx context.Context, db DBTX, summary *models.StudentPerformanceSummary) error
	UpdateStudentPerformanceSummary(ctx context.Context, db DBTX, summary *models.StudentPerformanceSummary) error
	DeleteStudentPerformanceSummary(ctx context.Context, db DBTX, id uuid.UUID) error

	// Class performance summaries
	GetClassPerformanceSummary(ctx context.Context, db DBTX, id uuid.UUID) (*models.ClassPerformanceSummary, error)
	ListClassPerformanceSummaries(ctx context.Context, db DBTX, filter ClassPerformanceSummaryFilter, p Pagination, s Sort) ([]*models.ClassPerformanceSummary, error)
	CountClassPerformanceSummaries(ctx context.Context, db DBTX, filter ClassPerformanceSummaryFilter) (int64, error)
	CreateClassPerformanceSummary(ctx context.Context, db DBTX, summary *models.ClassPerformanceSummary) error
	UpdateClassPerformanceSummary(ctx context.Context, db DBTX, summary *models.ClassPerformanceSummary) error
	DeleteClassPerformanceSummary(ctx context.Context, db DBTX, id uuid.UUID) error

	// Student rankings
	GetStudentRanking(ctx context.Context, db DBTX, id uuid.UUID) (*models.StudentRanking, error)
	ListStudentRankings(ctx context.Context, db DBTX, filter StudentRankingFilter, p Pagination, s Sort) ([]*models.StudentRanking, error)
	CountStudentRankings(ctx context.Context, db DBTX, filter StudentRankingFilter) (int64, error)
	CreateStudentRanking(ctx context.Context, db DBTX, ranking *models.StudentRanking) error
	UpdateStudentRanking(ctx context.Context, db DBTX, ranking *models.StudentRanking) error
	DeleteStudentRanking(ctx context.Context, db DBTX, id uuid.UUID) error

	// Academic year metrics (aggregated)
	GetAcademicYearMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.AcademicYearMetrics, error)
	ListAcademicYearMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.AcademicYearMetrics, error)
	UpdateAcademicYearMetrics(ctx context.Context, db DBTX, update *models.AcademicYearMetricsUpdate) error
	RefreshAcademicYearMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error
	DeleteAcademicYearMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error

	// Exam metrics
	GetExamMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.ExamMetrics, error)
	ListExamMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.ExamMetrics, error)
	UpdateExamMetrics(ctx context.Context, db DBTX, update *models.ExamMetricsUpdate) error
	RefreshExamMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error
	DeleteExamMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error

	// Fee metrics
	GetFeeMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.FeeMetrics, error)
	ListFeeMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.FeeMetrics, error)
	UpdateFeeMetrics(ctx context.Context, db DBTX, update *models.FeeMetricsUpdate) error
	RefreshFeeMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error
	DeleteFeeMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error

	// Grading metrics
	GetGradingMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.GradingMetrics, error)
	ListGradingMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.GradingMetrics, error)
	UpdateGradingMetrics(ctx context.Context, db DBTX, update *models.GradingMetricsUpdate) error
	RefreshGradingMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error
	DeleteGradingMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error

	// Guardian metrics
	GetGuardianMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.GuardianMetrics, error)
	ListGuardianMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.GuardianMetrics, error)
	UpdateGuardianMetrics(ctx context.Context, db DBTX, update *models.GuardianMetricsUpdate) error
	RefreshGuardianMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error
	DeleteGuardianMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error

	// Library metrics
	GetLibraryMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.LibraryMetrics, error)
	ListLibraryMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.LibraryMetrics, error)
	UpdateLibraryMetrics(ctx context.Context, db DBTX, update *models.LibraryMetricsUpdate) error
	RefreshLibraryMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error
	DeleteLibraryMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error

	// ===================== New metrics for the 9 services =====================

	// Room metrics
	GetRoomMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.RoomMetrics, error)
	ListRoomMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.RoomMetrics, error)
	UpdateRoomMetrics(ctx context.Context, db DBTX, update *models.RoomMetricsUpdate) error
	RefreshRoomMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error
	DeleteRoomMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error

	// Section metrics
	GetSectionMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.SectionMetrics, error)
	ListSectionMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.SectionMetrics, error)
	UpdateSectionMetrics(ctx context.Context, db DBTX, update *models.SectionMetricsUpdate) error
	RefreshSectionMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error
	DeleteSectionMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error

	// Student metrics (additional to academic_year_metrics)
	GetStudentMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.StudentMetrics, error)
	ListStudentMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.StudentMetrics, error)
	UpdateStudentMetrics(ctx context.Context, db DBTX, update *models.StudentMetricsUpdate) error
	RefreshStudentMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error
	DeleteStudentMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error

	// Subject metrics
	GetSubjectMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.SubjectMetrics, error)
	ListSubjectMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.SubjectMetrics, error)
	UpdateSubjectMetrics(ctx context.Context, db DBTX, update *models.SubjectMetricsUpdate) error
	RefreshSubjectMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error
	DeleteSubjectMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error

	// Submission metrics
	GetSubmissionMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.SubmissionMetrics, error)
	ListSubmissionMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.SubmissionMetrics, error)
	UpdateSubmissionMetrics(ctx context.Context, db DBTX, update *models.SubmissionMetricsUpdate) error
	RefreshSubmissionMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error
	DeleteSubmissionMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error

	// Teacher metrics
	GetTeacherMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.TeacherMetrics, error)
	ListTeacherMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.TeacherMetrics, error)
	UpdateTeacherMetrics(ctx context.Context, db DBTX, update *models.TeacherMetricsUpdate) error
	RefreshTeacherMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error
	DeleteTeacherMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error

	// Timetable metrics
	GetTimetableMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.TimetableMetrics, error)
	ListTimetableMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.TimetableMetrics, error)
	UpdateTimetableMetrics(ctx context.Context, db DBTX, update *models.TimetableMetricsUpdate) error
	RefreshTimetableMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error
	DeleteTimetableMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error

	// Transport metrics
	GetTransportMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.TransportMetrics, error)
	ListTransportMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.TransportMetrics, error)
	UpdateTransportMetrics(ctx context.Context, db DBTX, update *models.TransportMetricsUpdate) error
	RefreshTransportMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error
	DeleteTransportMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error
}

// analyticsRepository implements AnalyticsRepository.
type analyticsRepository struct {
	logger *zap.Logger
}

// NewAnalyticsRepository creates a new instance.
func NewAnalyticsRepository(logger *zap.Logger) AnalyticsRepository {
	return &analyticsRepository{
		logger: logger.Named("analytics_repo"),
	}
}

// ================================ Helper functions ================================

// validateSort validates and builds the ORDER BY clause.
func (r *analyticsRepository) validateSort(s Sort, allowedFields map[string]bool) (string, error) {
	field := s.Field
	if field == "" {
		field = "created_at"
	}
	if !allowedFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY %s %s", field, dir), nil
}

// validatePagination returns limit and offset with defaults.
func (r *analyticsRepository) validatePagination(p Pagination) (int, int) {
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

// ================================ Student Performance ================================

var allowedStudentPerformanceSortFields = map[string]bool{
	"created_at":         true,
	"updated_at":         true,
	"overall_percentage": true,
	"grade":              true,
	"rank":               true,
	"student_id":         true,
	"academic_year_id":   true,
	"term_id":            true,
}

func (r *analyticsRepository) buildStudentPerformanceFilter(filter StudentPerformanceSummaryFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1
	if filter.StudentID != nil {
		conditions = append(conditions, fmt.Sprintf("student_id = $%d", idx))
		args = append(args, *filter.StudentID)
		idx++
	}
	if filter.AcademicYearID != nil {
		conditions = append(conditions, fmt.Sprintf("academic_year_id = $%d", idx))
		args = append(args, *filter.AcademicYearID)
		idx++
	}
	if filter.TermID != nil {
		conditions = append(conditions, fmt.Sprintf("term_id = $%d", idx))
		args = append(args, *filter.TermID)
		idx++
	}
	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *analyticsRepository) GetStudentPerformanceSummary(ctx context.Context, db DBTX, id uuid.UUID) (*models.StudentPerformanceSummary, error) {
	query := `SELECT summary_id, student_id, academic_year_id, term_id, overall_percentage, grade, rank, created_at, updated_at
              FROM academics.student_performance_summary
              WHERE summary_id = $1`
	row := db.QueryRowContext(ctx, query, id)
	return r.scanStudentPerformanceSummary(row)
}

func (r *analyticsRepository) ListStudentPerformanceSummaries(ctx context.Context, db DBTX, filter StudentPerformanceSummaryFilter, p Pagination, s Sort) ([]*models.StudentPerformanceSummary, error) {
	where, args := r.buildStudentPerformanceFilter(filter)
	orderBy, err := r.validateSort(s, allowedStudentPerformanceSortFields)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)
	query := fmt.Sprintf(`
        SELECT summary_id, student_id, academic_year_id, term_id, overall_percentage, grade, rank, created_at, updated_at
        FROM academics.student_performance_summary
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list student performance summaries",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list student performance summaries: %w", err)
	}
	defer rows.Close()
	var result []*models.StudentPerformanceSummary
	for rows.Next() {
		s, err := r.scanStudentPerformanceSummary(rows)
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

func (r *analyticsRepository) CountStudentPerformanceSummaries(ctx context.Context, db DBTX, filter StudentPerformanceSummaryFilter) (int64, error) {
	where, args := r.buildStudentPerformanceFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.student_performance_summary %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count student performance summaries",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count student performance summaries: %w", err)
	}
	return count, nil
}

func (r *analyticsRepository) CreateStudentPerformanceSummary(ctx context.Context, db DBTX, summary *models.StudentPerformanceSummary) error {
	query := `
        INSERT INTO academics.student_performance_summary (
            student_id, academic_year_id, term_id, overall_percentage, grade, rank, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
        RETURNING summary_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		summary.StudentID, summary.AcademicYearID, summary.TermID,
		summary.OverallPercentage, summary.Grade, summary.Rank,
	).Scan(&summary.SummaryID, &summary.CreatedAt, &summary.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create student performance summary",
			util.String("student_id", summary.StudentID.String()),
			util.ErrorField(err))
		return fmt.Errorf("create student performance summary: %w", err)
	}
	return nil
}

func (r *analyticsRepository) UpdateStudentPerformanceSummary(ctx context.Context, db DBTX, summary *models.StudentPerformanceSummary) error {
	query := `
        UPDATE academics.student_performance_summary
        SET student_id = $2, academic_year_id = $3, term_id = $4,
            overall_percentage = $5, grade = $6, rank = $7,
            updated_at = NOW()
        WHERE summary_id = $1
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		summary.SummaryID,
		summary.StudentID,
		summary.AcademicYearID,
		summary.TermID,
		summary.OverallPercentage,
		summary.Grade,
		summary.Rank,
	).Scan(&summary.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: student performance summary %s", ErrNotFound, summary.SummaryID)
		}
		r.logger.Error("failed to update student performance summary",
			util.String("id", summary.SummaryID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update student performance summary: %w", err)
	}
	return nil
}

func (r *analyticsRepository) DeleteStudentPerformanceSummary(ctx context.Context, db DBTX, id uuid.UUID) error {
	query := `DELETE FROM academics.student_performance_summary WHERE summary_id = $1`
	result, err := db.ExecContext(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete student performance summary",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete student performance summary: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: student performance summary %s", ErrNotFound, id)
	}
	return nil
}

func (r *analyticsRepository) scanStudentPerformanceSummary(row scanner) (*models.StudentPerformanceSummary, error) {
	var s models.StudentPerformanceSummary
	var overallPercentage sql.NullFloat64
	var grade sql.NullString
	var rank sql.NullInt32
	err := row.Scan(
		&s.SummaryID,
		&s.StudentID,
		&s.AcademicYearID,
		&s.TermID,
		&overallPercentage,
		&grade,
		&rank,
		&s.CreatedAt,
		&s.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan student performance summary: %w", err)
	}
	if overallPercentage.Valid {
		s.OverallPercentage = &overallPercentage.Float64
	}
	if grade.Valid {
		s.Grade = grade.String
	}
	if rank.Valid {
		s.Rank = int(rank.Int32)
	}
	return &s, nil
}

// ================================ Class Performance ================================

var allowedClassPerformanceSortFields = map[string]bool{
	"created_at":         true,
	"updated_at":         true,
	"average_percentage": true,
	"pass_percentage":    true,
	"total_students":     true,
	"section_id":         true,
	"academic_year_id":   true,
	"term_id":            true,
}

func (r *analyticsRepository) buildClassPerformanceFilter(filter ClassPerformanceSummaryFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1
	if filter.SectionID != nil {
		conditions = append(conditions, fmt.Sprintf("section_id = $%d", idx))
		args = append(args, *filter.SectionID)
		idx++
	}
	if filter.AcademicYearID != nil {
		conditions = append(conditions, fmt.Sprintf("academic_year_id = $%d", idx))
		args = append(args, *filter.AcademicYearID)
		idx++
	}
	if filter.TermID != nil {
		conditions = append(conditions, fmt.Sprintf("term_id = $%d", idx))
		args = append(args, *filter.TermID)
		idx++
	}
	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *analyticsRepository) GetClassPerformanceSummary(ctx context.Context, db DBTX, id uuid.UUID) (*models.ClassPerformanceSummary, error) {
	query := `SELECT class_summary_id, section_id, academic_year_id, term_id, average_percentage, pass_percentage, total_students, created_at, updated_at
              FROM academics.class_performance_summary
              WHERE class_summary_id = $1`
	row := db.QueryRowContext(ctx, query, id)
	return r.scanClassPerformanceSummary(row)
}

func (r *analyticsRepository) ListClassPerformanceSummaries(ctx context.Context, db DBTX, filter ClassPerformanceSummaryFilter, p Pagination, s Sort) ([]*models.ClassPerformanceSummary, error) {
	where, args := r.buildClassPerformanceFilter(filter)
	orderBy, err := r.validateSort(s, allowedClassPerformanceSortFields)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)
	query := fmt.Sprintf(`
        SELECT class_summary_id, section_id, academic_year_id, term_id, average_percentage, pass_percentage, total_students, created_at, updated_at
        FROM academics.class_performance_summary
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list class performance summaries",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list class performance summaries: %w", err)
	}
	defer rows.Close()
	var result []*models.ClassPerformanceSummary
	for rows.Next() {
		c, err := r.scanClassPerformanceSummary(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *analyticsRepository) CountClassPerformanceSummaries(ctx context.Context, db DBTX, filter ClassPerformanceSummaryFilter) (int64, error) {
	where, args := r.buildClassPerformanceFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.class_performance_summary %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count class performance summaries",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count class performance summaries: %w", err)
	}
	return count, nil
}

func (r *analyticsRepository) CreateClassPerformanceSummary(ctx context.Context, db DBTX, summary *models.ClassPerformanceSummary) error {
	query := `
        INSERT INTO academics.class_performance_summary (
            section_id, academic_year_id, term_id, average_percentage, pass_percentage, total_students, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
        RETURNING class_summary_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		summary.SectionID, summary.AcademicYearID, summary.TermID,
		summary.AveragePercentage, summary.PassPercentage, summary.TotalStudents,
	).Scan(&summary.ClassSummaryID, &summary.CreatedAt, &summary.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create class performance summary",
			util.String("section_id", summary.SectionID.String()),
			util.ErrorField(err))
		return fmt.Errorf("create class performance summary: %w", err)
	}
	return nil
}

func (r *analyticsRepository) UpdateClassPerformanceSummary(ctx context.Context, db DBTX, summary *models.ClassPerformanceSummary) error {
	query := `
        UPDATE academics.class_performance_summary
        SET section_id = $2, academic_year_id = $3, term_id = $4,
            average_percentage = $5, pass_percentage = $6, total_students = $7,
            updated_at = NOW()
        WHERE class_summary_id = $1
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		summary.ClassSummaryID,
		summary.SectionID,
		summary.AcademicYearID,
		summary.TermID,
		summary.AveragePercentage,
		summary.PassPercentage,
		summary.TotalStudents,
	).Scan(&summary.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: class performance summary %s", ErrNotFound, summary.ClassSummaryID)
		}
		r.logger.Error("failed to update class performance summary",
			util.String("id", summary.ClassSummaryID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update class performance summary: %w", err)
	}
	return nil
}

func (r *analyticsRepository) DeleteClassPerformanceSummary(ctx context.Context, db DBTX, id uuid.UUID) error {
	query := `DELETE FROM academics.class_performance_summary WHERE class_summary_id = $1`
	result, err := db.ExecContext(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete class performance summary",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete class performance summary: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: class performance summary %s", ErrNotFound, id)
	}
	return nil
}

func (r *analyticsRepository) scanClassPerformanceSummary(row scanner) (*models.ClassPerformanceSummary, error) {
	var c models.ClassPerformanceSummary
	err := row.Scan(
		&c.ClassSummaryID,
		&c.SectionID,
		&c.AcademicYearID,
		&c.TermID,
		&c.AveragePercentage,
		&c.PassPercentage,
		&c.TotalStudents,
		&c.CreatedAt,
		&c.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan class performance summary: %w", err)
	}
	return &c, nil
}

// ================================ Student Rankings ================================

var allowedStudentRankingSortFields = map[string]bool{
	"created_at":       true,
	"rank":             true,
	"student_id":       true,
	"academic_year_id": true,
	"term_id":          true,
}

func (r *analyticsRepository) buildStudentRankingFilter(filter StudentRankingFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1
	if filter.StudentID != nil {
		conditions = append(conditions, fmt.Sprintf("student_id = $%d", idx))
		args = append(args, *filter.StudentID)
		idx++
	}
	if filter.AcademicYearID != nil {
		conditions = append(conditions, fmt.Sprintf("academic_year_id = $%d", idx))
		args = append(args, *filter.AcademicYearID)
		idx++
	}
	if filter.TermID != nil {
		conditions = append(conditions, fmt.Sprintf("term_id = $%d", idx))
		args = append(args, *filter.TermID)
		idx++
	}
	if filter.RankFrom != nil {
		conditions = append(conditions, fmt.Sprintf("rank >= $%d", idx))
		args = append(args, *filter.RankFrom)
		idx++
	}
	if filter.RankTo != nil {
		conditions = append(conditions, fmt.Sprintf("rank <= $%d", idx))
		args = append(args, *filter.RankTo)
		idx++
	}
	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *analyticsRepository) GetStudentRanking(ctx context.Context, db DBTX, id uuid.UUID) (*models.StudentRanking, error) {
	query := `SELECT ranking_id, student_id, academic_year_id, term_id, rank, created_at
              FROM academics.student_rankings
              WHERE ranking_id = $1`
	row := db.QueryRowContext(ctx, query, id)
	return r.scanStudentRanking(row)
}

func (r *analyticsRepository) ListStudentRankings(ctx context.Context, db DBTX, filter StudentRankingFilter, p Pagination, s Sort) ([]*models.StudentRanking, error) {
	where, args := r.buildStudentRankingFilter(filter)
	orderBy, err := r.validateSort(s, allowedStudentRankingSortFields)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)
	query := fmt.Sprintf(`
        SELECT ranking_id, student_id, academic_year_id, term_id, rank, created_at
        FROM academics.student_rankings
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list student rankings",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list student rankings: %w", err)
	}
	defer rows.Close()
	var result []*models.StudentRanking
	for rows.Next() {
		rnk, err := r.scanStudentRanking(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, rnk)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *analyticsRepository) CountStudentRankings(ctx context.Context, db DBTX, filter StudentRankingFilter) (int64, error) {
	where, args := r.buildStudentRankingFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.student_rankings %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count student rankings",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count student rankings: %w", err)
	}
	return count, nil
}

func (r *analyticsRepository) CreateStudentRanking(ctx context.Context, db DBTX, ranking *models.StudentRanking) error {
	query := `
        INSERT INTO academics.student_rankings (
            student_id, academic_year_id, term_id, rank, created_at
        ) VALUES ($1, $2, $3, $4, NOW())
        RETURNING ranking_id, created_at
    `
	err := db.QueryRowContext(ctx, query,
		ranking.StudentID, ranking.AcademicYearID, ranking.TermID, ranking.Rank,
	).Scan(&ranking.RankingID, &ranking.CreatedAt)
	if err != nil {
		r.logger.Error("failed to create student ranking",
			util.String("student_id", ranking.StudentID.String()),
			util.ErrorField(err))
		return fmt.Errorf("create student ranking: %w", err)
	}
	return nil
}

func (r *analyticsRepository) UpdateStudentRanking(ctx context.Context, db DBTX, ranking *models.StudentRanking) error {
	query := `
        UPDATE academics.student_rankings
        SET student_id = $2, academic_year_id = $3, term_id = $4, rank = $5
        WHERE ranking_id = $1
    `
	result, err := db.ExecContext(ctx, query,
		ranking.RankingID,
		ranking.StudentID,
		ranking.AcademicYearID,
		ranking.TermID,
		ranking.Rank,
	)
	if err != nil {
		r.logger.Error("failed to update student ranking",
			util.String("id", ranking.RankingID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update student ranking: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: student ranking %s", ErrNotFound, ranking.RankingID)
	}
	return nil
}

func (r *analyticsRepository) DeleteStudentRanking(ctx context.Context, db DBTX, id uuid.UUID) error {
	query := `DELETE FROM academics.student_rankings WHERE ranking_id = $1`
	result, err := db.ExecContext(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete student ranking",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete student ranking: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: student ranking %s", ErrNotFound, id)
	}
	return nil
}

func (r *analyticsRepository) scanStudentRanking(row scanner) (*models.StudentRanking, error) {
	var rnk models.StudentRanking
	err := row.Scan(
		&rnk.RankingID,
		&rnk.StudentID,
		&rnk.AcademicYearID,
		&rnk.TermID,
		&rnk.Rank,
		&rnk.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan student ranking: %w", err)
	}
	return &rnk, nil
}

// ================================ Academic Year Metrics ================================

func (r *analyticsRepository) GetAcademicYearMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.AcademicYearMetrics, error) {
	query := `
        SELECT academic_year_id, total_students, active_students, total_terms,
               total_sections, total_courses, total_subjects,
               total_admissions, approved_admissions, pending_admissions, rejected_admissions,
               total_assignments, published_assignments,
               total_attendance_records, total_absent_records, total_late_records, total_half_day_records,
               total_exemptions, total_subject_mappings, courses_with_curriculum,
               total_enrollments, active_enrollments, completed_enrollments, withdrawn_enrollments,
               last_updated
        FROM analytics.academic_year_metrics
        WHERE academic_year_id = $1
    `
	var m models.AcademicYearMetrics
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(
		&m.AcademicYearID, &m.TotalStudents, &m.ActiveStudents, &m.TotalTerms,
		&m.TotalSections, &m.TotalCourses, &m.TotalSubjects,
		&m.TotalAdmissions, &m.ApprovedAdmissions, &m.PendingAdmissions, &m.RejectedAdmissions,
		&m.TotalAssignments, &m.PublishedAssignments,
		&m.TotalAttendanceRecords, &m.TotalAbsentRecords, &m.TotalLateRecords, &m.TotalHalfDayRecords,
		&m.TotalExemptions, &m.TotalSubjectMappings, &m.CoursesWithCurriculum,
		&m.TotalEnrollments, &m.ActiveEnrollments, &m.CompletedEnrollments, &m.WithdrawnEnrollments,
		&m.LastUpdated,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get academic year metrics: %w", err)
	}
	return &m, nil
}

func (r *analyticsRepository) ListAcademicYearMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.AcademicYearMetrics, error) {
	query := `
        SELECT academic_year_id, total_students, active_students, total_terms,
               total_sections, total_courses, total_subjects,
               total_admissions, approved_admissions, pending_admissions, rejected_admissions,
               total_assignments, published_assignments,
               total_attendance_records, total_absent_records, total_late_records, total_half_day_records,
               total_exemptions, total_subject_mappings, courses_with_curriculum,
               total_enrollments, active_enrollments, completed_enrollments, withdrawn_enrollments,
               last_updated
        FROM analytics.academic_year_metrics
        ORDER BY last_updated DESC
        LIMIT $1 OFFSET $2
    `
	rows, err := db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list academic year metrics: %w", err)
	}
	defer rows.Close()
	var results []*models.AcademicYearMetrics
	for rows.Next() {
		var m models.AcademicYearMetrics
		if err := rows.Scan(
			&m.AcademicYearID, &m.TotalStudents, &m.ActiveStudents, &m.TotalTerms,
			&m.TotalSections, &m.TotalCourses, &m.TotalSubjects,
			&m.TotalAdmissions, &m.ApprovedAdmissions, &m.PendingAdmissions, &m.RejectedAdmissions,
			&m.TotalAssignments, &m.PublishedAssignments,
			&m.TotalAttendanceRecords, &m.TotalAbsentRecords, &m.TotalLateRecords, &m.TotalHalfDayRecords,
			&m.TotalExemptions, &m.TotalSubjectMappings, &m.CoursesWithCurriculum,
			&m.TotalEnrollments, &m.ActiveEnrollments, &m.CompletedEnrollments, &m.WithdrawnEnrollments,
			&m.LastUpdated,
		); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		results = append(results, &m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return results, nil
}

func (r *analyticsRepository) UpdateAcademicYearMetrics(ctx context.Context, db DBTX, update *models.AcademicYearMetricsUpdate) error {
	query := `
        INSERT INTO analytics.academic_year_metrics (
            academic_year_id, total_students, active_students, total_terms,
            total_sections, total_courses, total_subjects,
            total_admissions, approved_admissions, pending_admissions, rejected_admissions,
            total_assignments, published_assignments,
            total_attendance_records, total_absent_records, total_late_records, total_half_day_records,
            total_exemptions, total_subject_mappings, courses_with_curriculum,
            total_enrollments, active_enrollments, completed_enrollments, withdrawn_enrollments,
            last_updated
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_students   = analytics.academic_year_metrics.total_students + EXCLUDED.total_students,
            active_students  = analytics.academic_year_metrics.active_students + EXCLUDED.active_students,
            total_terms      = analytics.academic_year_metrics.total_terms + EXCLUDED.total_terms,
            total_sections   = analytics.academic_year_metrics.total_sections + EXCLUDED.total_sections,
            total_courses    = analytics.academic_year_metrics.total_courses + EXCLUDED.total_courses,
            total_subjects   = analytics.academic_year_metrics.total_subjects + EXCLUDED.total_subjects,
            total_admissions = analytics.academic_year_metrics.total_admissions + EXCLUDED.total_admissions,
            approved_admissions = analytics.academic_year_metrics.approved_admissions + EXCLUDED.approved_admissions,
            pending_admissions = analytics.academic_year_metrics.pending_admissions + EXCLUDED.pending_admissions,
            rejected_admissions = analytics.academic_year_metrics.rejected_admissions + EXCLUDED.rejected_admissions,
            total_assignments = analytics.academic_year_metrics.total_assignments + EXCLUDED.total_assignments,
            published_assignments = analytics.academic_year_metrics.published_assignments + EXCLUDED.published_assignments,
            total_attendance_records = analytics.academic_year_metrics.total_attendance_records + EXCLUDED.total_attendance_records,
            total_absent_records = analytics.academic_year_metrics.total_absent_records + EXCLUDED.total_absent_records,
            total_late_records = analytics.academic_year_metrics.total_late_records + EXCLUDED.total_late_records,
            total_half_day_records = analytics.academic_year_metrics.total_half_day_records + EXCLUDED.total_half_day_records,
            total_exemptions = analytics.academic_year_metrics.total_exemptions + EXCLUDED.total_exemptions,
            total_subject_mappings = analytics.academic_year_metrics.total_subject_mappings + EXCLUDED.total_subject_mappings,
            courses_with_curriculum = analytics.academic_year_metrics.courses_with_curriculum + EXCLUDED.courses_with_curriculum,
            total_enrollments = analytics.academic_year_metrics.total_enrollments + EXCLUDED.total_enrollments,
            active_enrollments = analytics.academic_year_metrics.active_enrollments + EXCLUDED.active_enrollments,
            completed_enrollments = analytics.academic_year_metrics.completed_enrollments + EXCLUDED.completed_enrollments,
            withdrawn_enrollments = analytics.academic_year_metrics.withdrawn_enrollments + EXCLUDED.withdrawn_enrollments,
            last_updated = NOW()
    `
	_, err := db.ExecContext(ctx, query,
		update.AcademicYearID,
		update.DeltaStudents,
		update.DeltaActive,
		update.DeltaTerms,
		update.DeltaSections,
		update.DeltaCourses,
		update.DeltaSubjects,
		update.DeltaTotalAdm,
		update.DeltaApprovedAdm,
		update.DeltaPendingAdm,
		update.DeltaRejectedAdm,
		update.DeltaTotalAssignments,
		update.DeltaPublishedAssignments,
		update.DeltaAttendanceRecords,
		update.DeltaAbsentRecords,
		update.DeltaLateRecords,
		update.DeltaHalfDayRecords,
		update.DeltaExemptions,
		update.DeltaTotalSubjectMappings,
		update.DeltaCoursesWithCurriculum,
		update.DeltaTotalEnrollments,
		update.DeltaActiveEnrollments,
		update.DeltaCompletedEnrollments,
		update.DeltaWithdrawnEnrollments,
	)
	if err != nil {
		r.logger.Error("failed to update academic year metrics",
			zap.String("academic_year_id", update.AcademicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("update academic year metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) RefreshAcademicYearMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	query := `
        WITH student_counts AS (
            SELECT e.academic_year_id, COUNT(DISTINCT e.student_id) AS total_students,
                   COUNT(DISTINCT e.student_id) FILTER (WHERE s.status = 'active') AS active_students
            FROM academics.enrollments e
            JOIN academics.students s ON s.student_id = e.student_id
            WHERE e.academic_year_id = $1
              AND e.deleted_at IS NULL AND s.deleted_at IS NULL
            GROUP BY e.academic_year_id
        ),
        term_counts AS (
            SELECT academic_year_id, COUNT(*) AS total_terms
            FROM academics.term
            WHERE academic_year_id = $1 AND deleted_at IS NULL
            GROUP BY academic_year_id
        ),
        section_counts AS (
            SELECT t.academic_year_id, COUNT(DISTINCT s.section_id) AS total_sections
            FROM academics.section s
            JOIN academics.term t ON t.term_id = s.term_id
            WHERE t.academic_year_id = $1 AND s.deleted_at IS NULL AND t.deleted_at IS NULL
            GROUP BY t.academic_year_id
        ),
        course_counts AS (
            SELECT t.academic_year_id, COUNT(DISTINCT s.course_id) AS total_courses
            FROM academics.section s
            JOIN academics.term t ON t.term_id = s.term_id
            WHERE t.academic_year_id = $1 AND s.deleted_at IS NULL AND t.deleted_at IS NULL
            GROUP BY t.academic_year_id
        ),
        subject_counts AS (
            SELECT t.academic_year_id, COUNT(DISTINCT sub.subject_id) AS total_subjects
            FROM academics.section s
            JOIN academics.term t ON t.term_id = s.term_id
            JOIN academics.subject_course_mapping scm ON scm.course_id = s.course_id
            JOIN academics.subject sub ON sub.subject_id = scm.subject_id
            WHERE t.academic_year_id = $1 AND s.deleted_at IS NULL AND t.deleted_at IS NULL
              AND sub.deleted_at IS NULL
            GROUP BY t.academic_year_id
        ),
        admission_counts AS (
            SELECT academic_year_id,
                   COUNT(*) AS total_admissions,
                   COUNT(*) FILTER (WHERE admission_status = 'approved') AS approved_admissions,
                   COUNT(*) FILTER (WHERE admission_status = 'pending') AS pending_admissions,
                   COUNT(*) FILTER (WHERE admission_status = 'rejected') AS rejected_admissions
            FROM academics.admissions
            WHERE academic_year_id = $1
            GROUP BY academic_year_id
        ),
        assignment_counts AS (
            SELECT t.academic_year_id,
                   COUNT(a.assignment_id) AS total_assignments,
                   COUNT(a.assignment_id) FILTER (WHERE a.is_published = true) AS published_assignments
            FROM academics.assignments a
            JOIN academics.section s ON s.section_id = a.section_id
            JOIN academics.term t ON t.term_id = s.term_id
            WHERE t.academic_year_id = $1
              AND a.deleted_at IS NULL
            GROUP BY t.academic_year_id
        ),
        attendance_counts AS (
            SELECT e.academic_year_id,
                   COUNT(a.attendance_id) AS total_attendance_records,
                   COUNT(a.attendance_id) FILTER (WHERE a.status = 'absent') AS total_absent_records,
                   COUNT(a.attendance_id) FILTER (WHERE a.status = 'late') AS total_late_records,
                   COUNT(a.attendance_id) FILTER (WHERE a.status = 'half-day') AS total_half_day_records
            FROM academics.student_attendance a
            JOIN academics.enrollments e ON e.enrollment_id = a.enrollment_id
            WHERE e.academic_year_id = $1
            GROUP BY e.academic_year_id
        ),
        exemption_counts AS (
            SELECT e.academic_year_id,
                   COUNT(ex.exemption_id) AS total_exemptions
            FROM academics.student_attendance_exemptions ex
            JOIN academics.enrollments e ON e.student_id = ex.student_id
            WHERE e.academic_year_id = $1
              AND ex.from_date <= (SELECT end_date FROM academics.academic_year WHERE academic_year_id = $1)
            GROUP BY e.academic_year_id
        ),
        curriculum_counts AS (
            SELECT t.academic_year_id,
                   COUNT(scm.mapping_id) AS total_subject_mappings,
                   COUNT(DISTINCT s.course_id) FILTER (WHERE scm.mapping_id IS NOT NULL) AS courses_with_curriculum
            FROM academics.section s
            JOIN academics.term t ON t.term_id = s.term_id
            LEFT JOIN academics.subject_course_mapping scm ON scm.course_id = s.course_id
            WHERE t.academic_year_id = $1 AND s.deleted_at IS NULL AND t.deleted_at IS NULL
            GROUP BY t.academic_year_id
        ),
        enrollment_counts AS (
            SELECT academic_year_id,
                   COUNT(*) AS total_enrollments,
                   COUNT(*) FILTER (WHERE status = 'active') AS active_enrollments,
                   COUNT(*) FILTER (WHERE status = 'completed') AS completed_enrollments,
                   COUNT(*) FILTER (WHERE status = 'withdrawn') AS withdrawn_enrollments
            FROM academics.enrollments
            WHERE academic_year_id = $1 AND deleted_at IS NULL
            GROUP BY academic_year_id
        )
        SELECT
            COALESCE(sc.total_students, 0),
            COALESCE(sc.active_students, 0),
            COALESCE(tc.total_terms, 0),
            COALESCE(scc.total_sections, 0),
            COALESCE(cc.total_courses, 0),
            COALESCE(suc.total_subjects, 0),
            COALESCE(ac.total_admissions, 0),
            COALESCE(ac.approved_admissions, 0),
            COALESCE(ac.pending_admissions, 0),
            COALESCE(ac.rejected_admissions, 0),
            COALESCE(asc.total_assignments, 0),
            COALESCE(asc.published_assignments, 0),
            COALESCE(att.total_attendance_records, 0),
            COALESCE(att.total_absent_records, 0),
            COALESCE(att.total_late_records, 0),
            COALESCE(att.total_half_day_records, 0),
            COALESCE(exc.total_exemptions, 0),
            COALESCE(cur.total_subject_mappings, 0),
            COALESCE(cur.courses_with_curriculum, 0),
            COALESCE(enc.total_enrollments, 0),
            COALESCE(enc.active_enrollments, 0),
            COALESCE(enc.completed_enrollments, 0),
            COALESCE(enc.withdrawn_enrollments, 0)
        FROM (SELECT $1 AS academic_year_id) ay
        LEFT JOIN student_counts sc ON sc.academic_year_id = ay.academic_year_id
        LEFT JOIN term_counts tc ON tc.academic_year_id = ay.academic_year_id
        LEFT JOIN section_counts scc ON scc.academic_year_id = ay.academic_year_id
        LEFT JOIN course_counts cc ON cc.academic_year_id = ay.academic_year_id
        LEFT JOIN subject_counts suc ON suc.academic_year_id = ay.academic_year_id
        LEFT JOIN admission_counts ac ON ac.academic_year_id = ay.academic_year_id
        LEFT JOIN assignment_counts asc ON asc.academic_year_id = ay.academic_year_id
        LEFT JOIN attendance_counts att ON att.academic_year_id = ay.academic_year_id
        LEFT JOIN exemption_counts exc ON exc.academic_year_id = ay.academic_year_id
        LEFT JOIN curriculum_counts cur ON cur.academic_year_id = ay.academic_year_id
        LEFT JOIN enrollment_counts enc ON enc.academic_year_id = ay.academic_year_id
    `
	var totalStudents, activeStudents, totalTerms, totalSections, totalCourses, totalSubjects int
	var totalAdmissions, approvedAdmissions, pendingAdmissions, rejectedAdmissions int
	var totalAssignments, publishedAssignments int
	var totalAttendanceRecords, totalAbsentRecords, totalLateRecords, totalHalfDayRecords int
	var totalExemptions, totalSubjectMappings, coursesWithCurriculum int
	var totalEnrollments, activeEnrollments, completedEnrollments, withdrawnEnrollments int
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(
		&totalStudents, &activeStudents, &totalTerms, &totalSections, &totalCourses, &totalSubjects,
		&totalAdmissions, &approvedAdmissions, &pendingAdmissions, &rejectedAdmissions,
		&totalAssignments, &publishedAssignments,
		&totalAttendanceRecords, &totalAbsentRecords, &totalLateRecords, &totalHalfDayRecords,
		&totalExemptions, &totalSubjectMappings, &coursesWithCurriculum,
		&totalEnrollments, &activeEnrollments, &completedEnrollments, &withdrawnEnrollments,
	)
	if err != nil {
		return fmt.Errorf("recompute metrics: %w", err)
	}
	upsertQuery := `
        INSERT INTO analytics.academic_year_metrics (
            academic_year_id, total_students, active_students, total_terms,
            total_sections, total_courses, total_subjects,
            total_admissions, approved_admissions, pending_admissions, rejected_admissions,
            total_assignments, published_assignments,
            total_attendance_records, total_absent_records, total_late_records, total_half_day_records,
            total_exemptions, total_subject_mappings, courses_with_curriculum,
            total_enrollments, active_enrollments, completed_enrollments, withdrawn_enrollments,
            last_updated
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_students   = EXCLUDED.total_students,
            active_students  = EXCLUDED.active_students,
            total_terms      = EXCLUDED.total_terms,
            total_sections   = EXCLUDED.total_sections,
            total_courses    = EXCLUDED.total_courses,
            total_subjects   = EXCLUDED.total_subjects,
            total_admissions = EXCLUDED.total_admissions,
            approved_admissions = EXCLUDED.approved_admissions,
            pending_admissions = EXCLUDED.pending_admissions,
            rejected_admissions = EXCLUDED.rejected_admissions,
            total_assignments = EXCLUDED.total_assignments,
            published_assignments = EXCLUDED.published_assignments,
            total_attendance_records = EXCLUDED.total_attendance_records,
            total_absent_records = EXCLUDED.total_absent_records,
            total_late_records = EXCLUDED.total_late_records,
            total_half_day_records = EXCLUDED.total_half_day_records,
            total_exemptions = EXCLUDED.total_exemptions,
            total_subject_mappings = EXCLUDED.total_subject_mappings,
            courses_with_curriculum = EXCLUDED.courses_with_curriculum,
            total_enrollments = EXCLUDED.total_enrollments,
            active_enrollments = EXCLUDED.active_enrollments,
            completed_enrollments = EXCLUDED.completed_enrollments,
            withdrawn_enrollments = EXCLUDED.withdrawn_enrollments,
            last_updated = NOW()
    `
	_, err = db.ExecContext(ctx, upsertQuery,
		academicYearID,
		totalStudents, activeStudents, totalTerms, totalSections, totalCourses, totalSubjects,
		totalAdmissions, approvedAdmissions, pendingAdmissions, rejectedAdmissions,
		totalAssignments, publishedAssignments,
		totalAttendanceRecords, totalAbsentRecords, totalLateRecords, totalHalfDayRecords,
		totalExemptions, totalSubjectMappings, coursesWithCurriculum,
		totalEnrollments, activeEnrollments, completedEnrollments, withdrawnEnrollments,
	)
	if err != nil {
		return fmt.Errorf("upsert metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) DeleteAcademicYearMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	query := `DELETE FROM analytics.academic_year_metrics WHERE academic_year_id = $1`
	result, err := db.ExecContext(ctx, query, academicYearID)
	if err != nil {
		r.logger.Error("failed to delete academic year metrics",
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("delete academic year metrics: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: academic year metrics %s", ErrNotFound, academicYearID)
	}
	return nil
}

// ================================ Exam Metrics ================================

func (r *analyticsRepository) GetExamMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.ExamMetrics, error) {
	query := `SELECT academic_year_id, total_exams, total_schedules, total_results, total_grades, last_updated
	          FROM analytics.exam_metrics WHERE academic_year_id = $1`
	var m models.ExamMetrics
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(
		&m.AcademicYearID, &m.TotalExams, &m.TotalSchedules,
		&m.TotalResults, &m.TotalGrades, &m.LastUpdated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get exam metrics: %w", err)
	}
	return &m, nil
}

func (r *analyticsRepository) ListExamMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.ExamMetrics, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	query := `SELECT academic_year_id, total_exams, total_schedules, total_results, total_grades, last_updated
	          FROM analytics.exam_metrics ORDER BY last_updated DESC LIMIT $1 OFFSET $2`
	rows, err := db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list exam metrics: %w", err)
	}
	defer rows.Close()
	var results []*models.ExamMetrics
	for rows.Next() {
		var m models.ExamMetrics
		if err := rows.Scan(&m.AcademicYearID, &m.TotalExams, &m.TotalSchedules,
			&m.TotalResults, &m.TotalGrades, &m.LastUpdated); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		results = append(results, &m)
	}
	return results, rows.Err()
}

func (r *analyticsRepository) UpdateExamMetrics(ctx context.Context, db DBTX, update *models.ExamMetricsUpdate) error {
	query := `
        INSERT INTO analytics.exam_metrics (academic_year_id, total_exams, total_schedules, total_results, total_grades, last_updated)
        VALUES ($1, $2, $3, $4, $5, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_exams = analytics.exam_metrics.total_exams + EXCLUDED.total_exams,
            total_schedules = analytics.exam_metrics.total_schedules + EXCLUDED.total_schedules,
            total_results = analytics.exam_metrics.total_results + EXCLUDED.total_results,
            total_grades = analytics.exam_metrics.total_grades + EXCLUDED.total_grades,
            last_updated = NOW()
    `
	_, err := db.ExecContext(ctx, query,
		update.AcademicYearID,
		update.DeltaExams,
		update.DeltaSchedules,
		update.DeltaResults,
		update.DeltaGrades,
	)
	if err != nil {
		r.logger.Error("failed to update exam metrics",
			zap.String("academic_year_id", update.AcademicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("update exam metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) RefreshExamMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	query := `
		WITH exam_counts AS (
			SELECT academic_year_id, COUNT(*) AS total_exams
			FROM academics.exams
			WHERE academic_year_id = $1 AND deleted_at IS NULL
			GROUP BY academic_year_id
		),
		schedule_counts AS (
			SELECT e.academic_year_id, COUNT(s.schedule_id) AS total_schedules
			FROM academics.exam_schedules s
			JOIN academics.exams e ON e.exam_id = s.exam_id
			WHERE e.academic_year_id = $1
			GROUP BY e.academic_year_id
		),
		result_counts AS (
			SELECT e.academic_year_id, COUNT(r.result_id) AS total_results
			FROM academics.exam_results r
			JOIN academics.exams e ON e.exam_id = r.exam_id
			WHERE e.academic_year_id = $1
			GROUP BY e.academic_year_id
		),
		grade_counts AS (
			SELECT e.academic_year_id, COUNT(g.grade_id) AS total_grades
			FROM academics.exam_grades g
			JOIN academics.exams e ON e.exam_id = g.exam_id
			WHERE e.academic_year_id = $1
			GROUP BY e.academic_year_id
		)
		SELECT
			COALESCE(ec.total_exams, 0),
			COALESCE(sc.total_schedules, 0),
			COALESCE(rc.total_results, 0),
			COALESCE(gc.total_grades, 0)
		FROM (SELECT $1 AS academic_year_id) ay
		LEFT JOIN exam_counts ec ON ec.academic_year_id = ay.academic_year_id
		LEFT JOIN schedule_counts sc ON sc.academic_year_id = ay.academic_year_id
		LEFT JOIN result_counts rc ON rc.academic_year_id = ay.academic_year_id
		LEFT JOIN grade_counts gc ON gc.academic_year_id = ay.academic_year_id
	`
	var totalExams, totalSchedules, totalResults, totalGrades int
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(&totalExams, &totalSchedules, &totalResults, &totalGrades)
	if err != nil {
		return fmt.Errorf("refresh exam metrics: %w", err)
	}
	upsertQuery := `
        INSERT INTO analytics.exam_metrics (academic_year_id, total_exams, total_schedules, total_results, total_grades, last_updated)
        VALUES ($1, $2, $3, $4, $5, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_exams = EXCLUDED.total_exams,
            total_schedules = EXCLUDED.total_schedules,
            total_results = EXCLUDED.total_results,
            total_grades = EXCLUDED.total_grades,
            last_updated = NOW()
    `
	_, err = db.ExecContext(ctx, upsertQuery, academicYearID, totalExams, totalSchedules, totalResults, totalGrades)
	if err != nil {
		return fmt.Errorf("upsert exam metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) DeleteExamMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	query := `DELETE FROM analytics.exam_metrics WHERE academic_year_id = $1`
	result, err := db.ExecContext(ctx, query, academicYearID)
	if err != nil {
		r.logger.Error("failed to delete exam metrics",
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("delete exam metrics: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: exam metrics %s", ErrNotFound, academicYearID)
	}
	return nil
}

// ================================ Fee Metrics ================================

func (r *analyticsRepository) GetFeeMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.FeeMetrics, error) {
	query := `SELECT academic_year_id, total_fee_structures, total_invoices, total_payments,
	          total_discounts, total_penalties, total_receipts,
	          total_invoice_amount, total_paid_amount, total_discount_amount, total_penalty_amount,
	          last_updated
	          FROM analytics.fee_metrics WHERE academic_year_id = $1`
	var m models.FeeMetrics
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(
		&m.AcademicYearID, &m.TotalFeeStructures, &m.TotalInvoices,
		&m.TotalPayments, &m.TotalDiscounts, &m.TotalPenalties,
		&m.TotalReceipts, &m.TotalInvoiceAmount, &m.TotalPaidAmount,
		&m.TotalDiscountAmount, &m.TotalPenaltyAmount, &m.LastUpdated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get fee metrics: %w", err)
	}
	return &m, nil
}

func (r *analyticsRepository) ListFeeMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.FeeMetrics, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	query := `SELECT academic_year_id, total_fee_structures, total_invoices, total_payments,
	          total_discounts, total_penalties, total_receipts,
	          total_invoice_amount, total_paid_amount, total_discount_amount, total_penalty_amount,
	          last_updated
	          FROM analytics.fee_metrics ORDER BY last_updated DESC LIMIT $1 OFFSET $2`
	rows, err := db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list fee metrics: %w", err)
	}
	defer rows.Close()
	var results []*models.FeeMetrics
	for rows.Next() {
		var m models.FeeMetrics
		if err := rows.Scan(&m.AcademicYearID, &m.TotalFeeStructures, &m.TotalInvoices,
			&m.TotalPayments, &m.TotalDiscounts, &m.TotalPenalties, &m.TotalReceipts,
			&m.TotalInvoiceAmount, &m.TotalPaidAmount, &m.TotalDiscountAmount,
			&m.TotalPenaltyAmount, &m.LastUpdated); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		results = append(results, &m)
	}
	return results, rows.Err()
}

func (r *analyticsRepository) UpdateFeeMetrics(ctx context.Context, db DBTX, update *models.FeeMetricsUpdate) error {
	query := `
        INSERT INTO analytics.fee_metrics (
            academic_year_id, total_fee_structures, total_invoices, total_payments,
            total_discounts, total_penalties, total_receipts,
            total_invoice_amount, total_paid_amount, total_discount_amount, total_penalty_amount,
            last_updated
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_fee_structures = analytics.fee_metrics.total_fee_structures + EXCLUDED.total_fee_structures,
            total_invoices = analytics.fee_metrics.total_invoices + EXCLUDED.total_invoices,
            total_payments = analytics.fee_metrics.total_payments + EXCLUDED.total_payments,
            total_discounts = analytics.fee_metrics.total_discounts + EXCLUDED.total_discounts,
            total_penalties = analytics.fee_metrics.total_penalties + EXCLUDED.total_penalties,
            total_receipts = analytics.fee_metrics.total_receipts + EXCLUDED.total_receipts,
            total_invoice_amount = analytics.fee_metrics.total_invoice_amount + EXCLUDED.total_invoice_amount,
            total_paid_amount = analytics.fee_metrics.total_paid_amount + EXCLUDED.total_paid_amount,
            total_discount_amount = analytics.fee_metrics.total_discount_amount + EXCLUDED.total_discount_amount,
            total_penalty_amount = analytics.fee_metrics.total_penalty_amount + EXCLUDED.total_penalty_amount,
            last_updated = NOW()
    `
	_, err := db.ExecContext(ctx, query,
		update.AcademicYearID,
		update.DeltaFeeStructures,
		update.DeltaInvoices,
		update.DeltaPayments,
		update.DeltaDiscounts,
		update.DeltaPenalties,
		update.DeltaReceipts,
		update.DeltaInvoiceAmount,
		update.DeltaPaidAmount,
		update.DeltaDiscountAmount,
		update.DeltaPenaltyAmount,
	)
	if err != nil {
		r.logger.Error("failed to update fee metrics",
			zap.String("academic_year_id", update.AcademicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("update fee metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) RefreshFeeMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	query := `
		WITH fee_structure_counts AS (
			SELECT academic_year_id, COUNT(*) AS total_fee_structures
			FROM academics.fee_structures
			WHERE academic_year_id = $1 AND deleted_at IS NULL
			GROUP BY academic_year_id
		),
		invoice_counts AS (
			SELECT e.academic_year_id, COUNT(i.invoice_id) AS total_invoices,
			       COALESCE(SUM(i.total_amount), 0) AS total_invoice_amount
			FROM academics.student_fee_invoices i
			JOIN academics.enrollments e ON e.student_id = i.student_id
			WHERE e.academic_year_id = $1
			GROUP BY e.academic_year_id
		),
		payment_counts AS (
			SELECT e.academic_year_id, COUNT(p.payment_id) AS total_payments,
			       COALESCE(SUM(p.amount), 0) AS total_paid_amount
			FROM academics.student_fee_payments p
			JOIN academics.student_fee_invoices i ON i.invoice_id = p.invoice_id
			JOIN academics.enrollments e ON e.student_id = i.student_id
			WHERE e.academic_year_id = $1
			GROUP BY e.academic_year_id
		),
		discount_counts AS (
			SELECT e.academic_year_id, COUNT(d.discount_id) AS total_discounts,
			       COALESCE(SUM(d.discount_value), 0) AS total_discount_amount
			FROM academics.fee_discounts d
			JOIN academics.enrollments e ON e.student_id = d.student_id
			WHERE e.academic_year_id = $1
			GROUP BY e.academic_year_id
		),
		penalty_counts AS (
			SELECT e.academic_year_id, COUNT(p.penalty_id) AS total_penalties,
			       COALESCE(SUM(p.amount), 0) AS total_penalty_amount
			FROM academics.fee_penalties p
			JOIN academics.student_fee_invoices i ON i.invoice_id = p.invoice_id
			JOIN academics.enrollments e ON e.student_id = i.student_id
			WHERE e.academic_year_id = $1
			GROUP BY e.academic_year_id
		),
		receipt_counts AS (
			SELECT e.academic_year_id, COUNT(r.receipt_id) AS total_receipts
			FROM academics.fee_receipts r
			JOIN academics.student_fee_payments p ON p.payment_id = r.payment_id
			JOIN academics.student_fee_invoices i ON i.invoice_id = p.invoice_id
			JOIN academics.enrollments e ON e.student_id = i.student_id
			WHERE e.academic_year_id = $1
			GROUP BY e.academic_year_id
		)
		SELECT
			COALESCE(fsc.total_fee_structures, 0),
			COALESCE(ic.total_invoices, 0),
			COALESCE(pc.total_payments, 0),
			COALESCE(dc.total_discounts, 0),
			COALESCE(pnc.total_penalties, 0),
			COALESCE(rc.total_receipts, 0),
			COALESCE(ic.total_invoice_amount, 0),
			COALESCE(pc.total_paid_amount, 0),
			COALESCE(dc.total_discount_amount, 0),
			COALESCE(pnc.total_penalty_amount, 0)
		FROM (SELECT $1 AS academic_year_id) ay
		LEFT JOIN fee_structure_counts fsc ON fsc.academic_year_id = ay.academic_year_id
		LEFT JOIN invoice_counts ic ON ic.academic_year_id = ay.academic_year_id
		LEFT JOIN payment_counts pc ON pc.academic_year_id = ay.academic_year_id
		LEFT JOIN discount_counts dc ON dc.academic_year_id = ay.academic_year_id
		LEFT JOIN penalty_counts pnc ON pnc.academic_year_id = ay.academic_year_id
		LEFT JOIN receipt_counts rc ON rc.academic_year_id = ay.academic_year_id
	`
	var totalFeeStructures, totalInvoices, totalPayments, totalDiscounts, totalPenalties, totalReceipts int
	var totalInvoiceAmount, totalPaidAmount, totalDiscountAmount, totalPenaltyAmount float64
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(
		&totalFeeStructures, &totalInvoices, &totalPayments,
		&totalDiscounts, &totalPenalties, &totalReceipts,
		&totalInvoiceAmount, &totalPaidAmount, &totalDiscountAmount, &totalPenaltyAmount,
	)
	if err != nil {
		return fmt.Errorf("refresh fee metrics: %w", err)
	}
	upsertQuery := `
        INSERT INTO analytics.fee_metrics (
            academic_year_id, total_fee_structures, total_invoices, total_payments,
            total_discounts, total_penalties, total_receipts,
            total_invoice_amount, total_paid_amount, total_discount_amount, total_penalty_amount,
            last_updated
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_fee_structures = EXCLUDED.total_fee_structures,
            total_invoices = EXCLUDED.total_invoices,
            total_payments = EXCLUDED.total_payments,
            total_discounts = EXCLUDED.total_discounts,
            total_penalties = EXCLUDED.total_penalties,
            total_receipts = EXCLUDED.total_receipts,
            total_invoice_amount = EXCLUDED.total_invoice_amount,
            total_paid_amount = EXCLUDED.total_paid_amount,
            total_discount_amount = EXCLUDED.total_discount_amount,
            total_penalty_amount = EXCLUDED.total_penalty_amount,
            last_updated = NOW()
    `
	_, err = db.ExecContext(ctx, upsertQuery,
		academicYearID,
		totalFeeStructures, totalInvoices, totalPayments,
		totalDiscounts, totalPenalties, totalReceipts,
		totalInvoiceAmount, totalPaidAmount, totalDiscountAmount, totalPenaltyAmount,
	)
	if err != nil {
		return fmt.Errorf("upsert fee metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) DeleteFeeMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	query := `DELETE FROM analytics.fee_metrics WHERE academic_year_id = $1`
	result, err := db.ExecContext(ctx, query, academicYearID)
	if err != nil {
		r.logger.Error("failed to delete fee metrics",
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("delete fee metrics: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: fee metrics %s", ErrNotFound, academicYearID)
	}
	return nil
}

// ================================ Grading Metrics ================================

func (r *analyticsRepository) GetGradingMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.GradingMetrics, error) {
	query := `SELECT academic_year_id, total_policies, total_boundaries, last_updated
	          FROM analytics.grading_metrics WHERE academic_year_id = $1`
	var m models.GradingMetrics
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(
		&m.AcademicYearID, &m.TotalPolicies, &m.TotalBoundaries, &m.LastUpdated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get grading metrics: %w", err)
	}
	return &m, nil
}

func (r *analyticsRepository) ListGradingMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.GradingMetrics, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	query := `SELECT academic_year_id, total_policies, total_boundaries, last_updated
	          FROM analytics.grading_metrics ORDER BY last_updated DESC LIMIT $1 OFFSET $2`
	rows, err := db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list grading metrics: %w", err)
	}
	defer rows.Close()
	var results []*models.GradingMetrics
	for rows.Next() {
		var m models.GradingMetrics
		if err := rows.Scan(&m.AcademicYearID, &m.TotalPolicies, &m.TotalBoundaries, &m.LastUpdated); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		results = append(results, &m)
	}
	return results, rows.Err()
}

func (r *analyticsRepository) UpdateGradingMetrics(ctx context.Context, db DBTX, update *models.GradingMetricsUpdate) error {
	query := `
        INSERT INTO analytics.grading_metrics (academic_year_id, total_policies, total_boundaries, last_updated)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_policies = analytics.grading_metrics.total_policies + EXCLUDED.total_policies,
            total_boundaries = analytics.grading_metrics.total_boundaries + EXCLUDED.total_boundaries,
            last_updated = NOW()
    `
	_, err := db.ExecContext(ctx, query,
		update.AcademicYearID,
		update.DeltaPolicies,
		update.DeltaBoundaries,
	)
	if err != nil {
		r.logger.Error("failed to update grading metrics",
			zap.String("academic_year_id", update.AcademicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("update grading metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) RefreshGradingMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	query := `
		WITH policy_counts AS (
			SELECT company_id, COUNT(*) AS total_policies
			FROM academics.grading_policies
			WHERE deleted_at IS NULL
			GROUP BY company_id
		),
		boundary_counts AS (
			SELECT p.company_id, COUNT(b.boundary_id) AS total_boundaries
			FROM academics.grade_boundaries b
			JOIN academics.grading_policies p ON p.policy_id = b.policy_id
			WHERE b.deleted_at IS NULL AND p.deleted_at IS NULL
			GROUP BY p.company_id
		),
		company_academic_year AS (
			SELECT ay.academic_year_id, ay.company_id
			FROM academics.academic_year ay
			WHERE ay.academic_year_id = $1
		)
		SELECT
			COALESCE(pc.total_policies, 0),
			COALESCE(bc.total_boundaries, 0)
		FROM company_academic_year cay
		LEFT JOIN policy_counts pc ON pc.company_id = cay.company_id
		LEFT JOIN boundary_counts bc ON bc.company_id = cay.company_id
	`
	var totalPolicies, totalBoundaries int
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(&totalPolicies, &totalBoundaries)
	if err != nil {
		return fmt.Errorf("refresh grading metrics: %w", err)
	}
	upsertQuery := `
        INSERT INTO analytics.grading_metrics (academic_year_id, total_policies, total_boundaries, last_updated)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_policies = EXCLUDED.total_policies,
            total_boundaries = EXCLUDED.total_boundaries,
            last_updated = NOW()
    `
	_, err = db.ExecContext(ctx, upsertQuery, academicYearID, totalPolicies, totalBoundaries)
	if err != nil {
		return fmt.Errorf("upsert grading metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) DeleteGradingMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	query := `DELETE FROM analytics.grading_metrics WHERE academic_year_id = $1`
	result, err := db.ExecContext(ctx, query, academicYearID)
	if err != nil {
		r.logger.Error("failed to delete grading metrics",
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("delete grading metrics: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: grading metrics %s", ErrNotFound, academicYearID)
	}
	return nil
}

// ================================ Guardian Metrics ================================

func (r *analyticsRepository) GetGuardianMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.GuardianMetrics, error) {
	query := `SELECT academic_year_id, total_guardians, total_primary_guardians, last_updated
	          FROM analytics.guardian_metrics WHERE academic_year_id = $1`
	var m models.GuardianMetrics
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(
		&m.AcademicYearID, &m.TotalGuardians, &m.TotalPrimaryGuardians, &m.LastUpdated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get guardian metrics: %w", err)
	}
	return &m, nil
}

func (r *analyticsRepository) ListGuardianMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.GuardianMetrics, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	query := `SELECT academic_year_id, total_guardians, total_primary_guardians, last_updated
	          FROM analytics.guardian_metrics ORDER BY last_updated DESC LIMIT $1 OFFSET $2`
	rows, err := db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list guardian metrics: %w", err)
	}
	defer rows.Close()
	var results []*models.GuardianMetrics
	for rows.Next() {
		var m models.GuardianMetrics
		if err := rows.Scan(&m.AcademicYearID, &m.TotalGuardians, &m.TotalPrimaryGuardians, &m.LastUpdated); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		results = append(results, &m)
	}
	return results, rows.Err()
}

func (r *analyticsRepository) UpdateGuardianMetrics(ctx context.Context, db DBTX, update *models.GuardianMetricsUpdate) error {
	query := `
        INSERT INTO analytics.guardian_metrics (academic_year_id, total_guardians, total_primary_guardians, last_updated)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_guardians = analytics.guardian_metrics.total_guardians + EXCLUDED.total_guardians,
            total_primary_guardians = analytics.guardian_metrics.total_primary_guardians + EXCLUDED.total_primary_guardians,
            last_updated = NOW()
    `
	_, err := db.ExecContext(ctx, query,
		update.AcademicYearID,
		update.DeltaGuardians,
		update.DeltaPrimaryGuardians,
	)
	if err != nil {
		r.logger.Error("failed to update guardian metrics",
			zap.String("academic_year_id", update.AcademicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("update guardian metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) RefreshGuardianMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	query := `
		SELECT
			COUNT(DISTINCT sg.guardian_id) AS total_guardians,
			COUNT(DISTINCT sg.guardian_id) FILTER (WHERE sg.is_primary = true) AS total_primary_guardians
		FROM academics.student_guardians sg
		JOIN academics.enrollments e ON e.student_id = sg.student_id
		WHERE e.academic_year_id = $1 AND e.status = 'active'
	`
	var totalGuardians, totalPrimaryGuardians int
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(&totalGuardians, &totalPrimaryGuardians)
	if err != nil {
		return fmt.Errorf("refresh guardian metrics: %w", err)
	}
	upsertQuery := `
        INSERT INTO analytics.guardian_metrics (academic_year_id, total_guardians, total_primary_guardians, last_updated)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_guardians = EXCLUDED.total_guardians,
            total_primary_guardians = EXCLUDED.total_primary_guardians,
            last_updated = NOW()
    `
	_, err = db.ExecContext(ctx, upsertQuery, academicYearID, totalGuardians, totalPrimaryGuardians)
	if err != nil {
		return fmt.Errorf("upsert guardian metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) DeleteGuardianMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	query := `DELETE FROM analytics.guardian_metrics WHERE academic_year_id = $1`
	result, err := db.ExecContext(ctx, query, academicYearID)
	if err != nil {
		r.logger.Error("failed to delete guardian metrics",
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("delete guardian metrics: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: guardian metrics %s", ErrNotFound, academicYearID)
	}
	return nil
}

// ================================ Library Metrics ================================

func (r *analyticsRepository) GetLibraryMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.LibraryMetrics, error) {
	query := `SELECT academic_year_id, total_categories, total_books, total_copies,
	          total_issues, total_returns, total_fines, total_fine_amount, last_updated
	          FROM analytics.library_metrics WHERE academic_year_id = $1`
	var m models.LibraryMetrics
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(
		&m.AcademicYearID, &m.TotalCategories, &m.TotalBooks, &m.TotalCopies,
		&m.TotalIssues, &m.TotalReturns, &m.TotalFines, &m.TotalFineAmount,
		&m.LastUpdated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get library metrics: %w", err)
	}
	return &m, nil
}

func (r *analyticsRepository) ListLibraryMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.LibraryMetrics, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	query := `SELECT academic_year_id, total_categories, total_books, total_copies,
	          total_issues, total_returns, total_fines, total_fine_amount, last_updated
	          FROM analytics.library_metrics ORDER BY last_updated DESC LIMIT $1 OFFSET $2`
	rows, err := db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list library metrics: %w", err)
	}
	defer rows.Close()
	var results []*models.LibraryMetrics
	for rows.Next() {
		var m models.LibraryMetrics
		if err := rows.Scan(&m.AcademicYearID, &m.TotalCategories, &m.TotalBooks, &m.TotalCopies,
			&m.TotalIssues, &m.TotalReturns, &m.TotalFines, &m.TotalFineAmount, &m.LastUpdated); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		results = append(results, &m)
	}
	return results, rows.Err()
}

func (r *analyticsRepository) UpdateLibraryMetrics(ctx context.Context, db DBTX, update *models.LibraryMetricsUpdate) error {
	query := `
        INSERT INTO analytics.library_metrics (
            academic_year_id, total_categories, total_books, total_copies,
            total_issues, total_returns, total_fines, total_fine_amount, last_updated
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_categories = analytics.library_metrics.total_categories + EXCLUDED.total_categories,
            total_books = analytics.library_metrics.total_books + EXCLUDED.total_books,
            total_copies = analytics.library_metrics.total_copies + EXCLUDED.total_copies,
            total_issues = analytics.library_metrics.total_issues + EXCLUDED.total_issues,
            total_returns = analytics.library_metrics.total_returns + EXCLUDED.total_returns,
            total_fines = analytics.library_metrics.total_fines + EXCLUDED.total_fines,
            total_fine_amount = analytics.library_metrics.total_fine_amount + EXCLUDED.total_fine_amount,
            last_updated = NOW()
    `
	_, err := db.ExecContext(ctx, query,
		update.AcademicYearID,
		update.DeltaCategories,
		update.DeltaBooks,
		update.DeltaCopies,
		update.DeltaIssues,
		update.DeltaReturns,
		update.DeltaFines,
		update.DeltaFineAmount,
	)
	if err != nil {
		r.logger.Error("failed to update library metrics",
			zap.String("academic_year_id", update.AcademicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("update library metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) RefreshLibraryMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	query := `
		WITH category_counts AS (
			SELECT COUNT(*) AS total_categories
			FROM academics.library_categories
			WHERE deleted_at IS NULL
		),
		book_counts AS (
			SELECT COUNT(*) AS total_books
			FROM academics.library_books
			WHERE deleted_at IS NULL
		),
		copy_counts AS (
			SELECT COUNT(*) AS total_copies
			FROM academics.library_book_copies
			WHERE deleted_at IS NULL
		),
		issue_counts AS (
			SELECT COUNT(*) AS total_issues
			FROM academics.library_issues
			WHERE returned_at IS NULL
		),
		return_counts AS (
			SELECT COUNT(*) AS total_returns
			FROM academics.library_returns
		),
		fine_counts AS (
			SELECT COUNT(*) AS total_fines,
			       COALESCE(SUM(fine_amount), 0) AS total_fine_amount
			FROM academics.library_fines
		)
		SELECT
			COALESCE(cc.total_categories, 0),
			COALESCE(bc.total_books, 0),
			COALESCE(cpc.total_copies, 0),
			COALESCE(ic.total_issues, 0),
			COALESCE(rc.total_returns, 0),
			COALESCE(fc.total_fines, 0),
			COALESCE(fc.total_fine_amount, 0)
		FROM (SELECT 1) dummy
		LEFT JOIN category_counts cc ON true
		LEFT JOIN book_counts bc ON true
		LEFT JOIN copy_counts cpc ON true
		LEFT JOIN issue_counts ic ON true
		LEFT JOIN return_counts rc ON true
		LEFT JOIN fine_counts fc ON true
	`
	var totalCategories, totalBooks, totalCopies, totalIssues, totalReturns, totalFines int
	var totalFineAmount float64
	err := db.QueryRowContext(ctx, query).Scan(
		&totalCategories, &totalBooks, &totalCopies,
		&totalIssues, &totalReturns, &totalFines, &totalFineAmount,
	)
	if err != nil {
		return fmt.Errorf("refresh library metrics: %w", err)
	}
	upsertQuery := `
        INSERT INTO analytics.library_metrics (
            academic_year_id, total_categories, total_books, total_copies,
            total_issues, total_returns, total_fines, total_fine_amount, last_updated
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_categories = EXCLUDED.total_categories,
            total_books = EXCLUDED.total_books,
            total_copies = EXCLUDED.total_copies,
            total_issues = EXCLUDED.total_issues,
            total_returns = EXCLUDED.total_returns,
            total_fines = EXCLUDED.total_fines,
            total_fine_amount = EXCLUDED.total_fine_amount,
            last_updated = NOW()
    `
	_, err = db.ExecContext(ctx, upsertQuery,
		academicYearID,
		totalCategories, totalBooks, totalCopies,
		totalIssues, totalReturns, totalFines, totalFineAmount,
	)
	if err != nil {
		return fmt.Errorf("upsert library metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) DeleteLibraryMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	query := `DELETE FROM analytics.library_metrics WHERE academic_year_id = $1`
	result, err := db.ExecContext(ctx, query, academicYearID)
	if err != nil {
		r.logger.Error("failed to delete library metrics",
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("delete library metrics: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: library metrics %s", ErrNotFound, academicYearID)
	}
	return nil
}

// ================================ Room Metrics ================================

func (r *analyticsRepository) GetRoomMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.RoomMetrics, error) {
	query := `SELECT academic_year_id, total_rooms, active_rooms, last_updated
	          FROM analytics.room_metrics WHERE academic_year_id = $1`
	var m models.RoomMetrics
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(&m.AcademicYearID, &m.TotalRooms, &m.ActiveRooms, &m.LastUpdated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get room metrics: %w", err)
	}
	return &m, nil
}

func (r *analyticsRepository) ListRoomMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.RoomMetrics, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	query := `SELECT academic_year_id, total_rooms, active_rooms, last_updated
	          FROM analytics.room_metrics ORDER BY last_updated DESC LIMIT $1 OFFSET $2`
	rows, err := db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list room metrics: %w", err)
	}
	defer rows.Close()
	var results []*models.RoomMetrics
	for rows.Next() {
		var m models.RoomMetrics
		if err := rows.Scan(&m.AcademicYearID, &m.TotalRooms, &m.ActiveRooms, &m.LastUpdated); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		results = append(results, &m)
	}
	return results, rows.Err()
}

func (r *analyticsRepository) UpdateRoomMetrics(ctx context.Context, db DBTX, update *models.RoomMetricsUpdate) error {
	query := `
        INSERT INTO analytics.room_metrics (academic_year_id, total_rooms, active_rooms, last_updated)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_rooms = analytics.room_metrics.total_rooms + EXCLUDED.total_rooms,
            active_rooms = analytics.room_metrics.active_rooms + EXCLUDED.active_rooms,
            last_updated = NOW()
    `
	_, err := db.ExecContext(ctx, query,
		update.AcademicYearID,
		update.DeltaRooms,
		update.DeltaActive,
	)
	if err != nil {
		r.logger.Error("failed to update room metrics",
			zap.String("academic_year_id", update.AcademicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("update room metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) RefreshRoomMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	// Rooms are company-level, but we link them to academic year via the company.
	// We'll count rooms from all active rooms in the company of the academic year.
	query := `
		WITH company AS (
			SELECT company_id FROM academics.academic_year WHERE academic_year_id = $1
		)
		SELECT
			COUNT(r.room_id) AS total_rooms,
			COUNT(r.room_id) FILTER (WHERE r.is_active = true) AS active_rooms
		FROM academics.rooms r
		WHERE r.company_id = (SELECT company_id FROM company)
		  AND r.deleted_at IS NULL
	`
	var totalRooms, activeRooms int
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(&totalRooms, &activeRooms)
	if err != nil {
		return fmt.Errorf("refresh room metrics: %w", err)
	}
	upsertQuery := `
        INSERT INTO analytics.room_metrics (academic_year_id, total_rooms, active_rooms, last_updated)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_rooms = EXCLUDED.total_rooms,
            active_rooms = EXCLUDED.active_rooms,
            last_updated = NOW()
    `
	_, err = db.ExecContext(ctx, upsertQuery, academicYearID, totalRooms, activeRooms)
	if err != nil {
		return fmt.Errorf("upsert room metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) DeleteRoomMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	query := `DELETE FROM analytics.room_metrics WHERE academic_year_id = $1`
	result, err := db.ExecContext(ctx, query, academicYearID)
	if err != nil {
		r.logger.Error("failed to delete room metrics",
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("delete room metrics: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: room metrics %s", ErrNotFound, academicYearID)
	}
	return nil
}

// ================================ Section Metrics ================================

func (r *analyticsRepository) GetSectionMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.SectionMetrics, error) {
	query := `SELECT academic_year_id, total_sections, active_sections, total_capacity, used_capacity, last_updated
	          FROM analytics.section_metrics WHERE academic_year_id = $1`
	var m models.SectionMetrics
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(
		&m.AcademicYearID, &m.TotalSections, &m.ActiveSections, &m.TotalCapacity, &m.UsedCapacity, &m.LastUpdated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get section metrics: %w", err)
	}
	return &m, nil
}

func (r *analyticsRepository) ListSectionMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.SectionMetrics, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	query := `SELECT academic_year_id, total_sections, active_sections, total_capacity, used_capacity, last_updated
	          FROM analytics.section_metrics ORDER BY last_updated DESC LIMIT $1 OFFSET $2`
	rows, err := db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list section metrics: %w", err)
	}
	defer rows.Close()
	var results []*models.SectionMetrics
	for rows.Next() {
		var m models.SectionMetrics
		if err := rows.Scan(&m.AcademicYearID, &m.TotalSections, &m.ActiveSections, &m.TotalCapacity, &m.UsedCapacity, &m.LastUpdated); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		results = append(results, &m)
	}
	return results, rows.Err()
}

func (r *analyticsRepository) UpdateSectionMetrics(ctx context.Context, db DBTX, update *models.SectionMetricsUpdate) error {
	query := `
        INSERT INTO analytics.section_metrics (academic_year_id, total_sections, active_sections, total_capacity, used_capacity, last_updated)
        VALUES ($1, $2, $3, $4, $5, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_sections = analytics.section_metrics.total_sections + EXCLUDED.total_sections,
            active_sections = analytics.section_metrics.active_sections + EXCLUDED.active_sections,
            total_capacity = analytics.section_metrics.total_capacity + EXCLUDED.total_capacity,
            used_capacity = analytics.section_metrics.used_capacity + EXCLUDED.used_capacity,
            last_updated = NOW()
    `
	_, err := db.ExecContext(ctx, query,
		update.AcademicYearID,
		update.DeltaSections,
		update.DeltaActive,
		update.DeltaTotalCap,
		update.DeltaUsedCap,
	)
	if err != nil {
		r.logger.Error("failed to update section metrics",
			zap.String("academic_year_id", update.AcademicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("update section metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) RefreshSectionMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	// Sections are linked to terms, which belong to academic years.
	// We also need total capacity (sum of section capacities) and used capacity (sum of enrollments per section)
	query := `
		WITH sections_in_year AS (
			SELECT s.section_id, s.capacity, s.is_active
			FROM academics.section s
			JOIN academics.term t ON t.term_id = s.term_id
			WHERE t.academic_year_id = $1
			  AND s.deleted_at IS NULL
		),
		enrollment_counts AS (
			SELECT e.section_id, COUNT(*) AS enrolled
			FROM academics.enrollments e
			WHERE e.academic_year_id = $1 AND e.status = 'active' AND e.deleted_at IS NULL
			GROUP BY e.section_id
		)
		SELECT
			COUNT(s.section_id) AS total_sections,
			COUNT(s.section_id) FILTER (WHERE s.is_active = true) AS active_sections,
			COALESCE(SUM(s.capacity), 0) AS total_capacity,
			COALESCE(SUM(ec.enrolled), 0) AS used_capacity
		FROM sections_in_year s
		LEFT JOIN enrollment_counts ec ON ec.section_id = s.section_id
	`
	var totalSections, activeSections, totalCapacity, usedCapacity int
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(&totalSections, &activeSections, &totalCapacity, &usedCapacity)
	if err != nil {
		return fmt.Errorf("refresh section metrics: %w", err)
	}
	upsertQuery := `
        INSERT INTO analytics.section_metrics (academic_year_id, total_sections, active_sections, total_capacity, used_capacity, last_updated)
        VALUES ($1, $2, $3, $4, $5, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_sections = EXCLUDED.total_sections,
            active_sections = EXCLUDED.active_sections,
            total_capacity = EXCLUDED.total_capacity,
            used_capacity = EXCLUDED.used_capacity,
            last_updated = NOW()
    `
	_, err = db.ExecContext(ctx, upsertQuery, academicYearID, totalSections, activeSections, totalCapacity, usedCapacity)
	if err != nil {
		return fmt.Errorf("upsert section metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) DeleteSectionMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	query := `DELETE FROM analytics.section_metrics WHERE academic_year_id = $1`
	result, err := db.ExecContext(ctx, query, academicYearID)
	if err != nil {
		r.logger.Error("failed to delete section metrics",
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("delete section metrics: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: section metrics %s", ErrNotFound, academicYearID)
	}
	return nil
}

// ================================ Student Metrics ================================

func (r *analyticsRepository) GetStudentMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.StudentMetrics, error) {
	query := `SELECT academic_year_id, total_students, active_students, male_students, female_students, last_updated
	          FROM analytics.student_metrics WHERE academic_year_id = $1`
	var m models.StudentMetrics
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(
		&m.AcademicYearID, &m.TotalStudents, &m.ActiveStudents, &m.MaleStudents, &m.FemaleStudents, &m.LastUpdated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get student metrics: %w", err)
	}
	return &m, nil
}

func (r *analyticsRepository) ListStudentMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.StudentMetrics, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	query := `SELECT academic_year_id, total_students, active_students, male_students, female_students, last_updated
	          FROM analytics.student_metrics ORDER BY last_updated DESC LIMIT $1 OFFSET $2`
	rows, err := db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list student metrics: %w", err)
	}
	defer rows.Close()
	var results []*models.StudentMetrics
	for rows.Next() {
		var m models.StudentMetrics
		if err := rows.Scan(&m.AcademicYearID, &m.TotalStudents, &m.ActiveStudents, &m.MaleStudents, &m.FemaleStudents, &m.LastUpdated); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		results = append(results, &m)
	}
	return results, rows.Err()
}

func (r *analyticsRepository) UpdateStudentMetrics(ctx context.Context, db DBTX, update *models.StudentMetricsUpdate) error {
	query := `
        INSERT INTO analytics.student_metrics (academic_year_id, total_students, active_students, male_students, female_students, last_updated)
        VALUES ($1, $2, $3, $4, $5, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_students = analytics.student_metrics.total_students + EXCLUDED.total_students,
            active_students = analytics.student_metrics.active_students + EXCLUDED.active_students,
            male_students = analytics.student_metrics.male_students + EXCLUDED.male_students,
            female_students = analytics.student_metrics.female_students + EXCLUDED.female_students,
            last_updated = NOW()
    `
	_, err := db.ExecContext(ctx, query,
		update.AcademicYearID,
		update.DeltaTotal,
		update.DeltaActive,
		update.DeltaMale,
		update.DeltaFemale,
	)
	if err != nil {
		r.logger.Error("failed to update student metrics",
			zap.String("academic_year_id", update.AcademicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("update student metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) RefreshStudentMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	query := `
		SELECT
			COUNT(DISTINCT s.student_id) AS total_students,
			COUNT(DISTINCT s.student_id) FILTER (WHERE s.status = 'active') AS active_students,
			COUNT(DISTINCT s.student_id) FILTER (WHERE s.gender = 'male') AS male_students,
			COUNT(DISTINCT s.student_id) FILTER (WHERE s.gender = 'female') AS female_students
		FROM academics.students s
		JOIN academics.enrollments e ON e.student_id = s.student_id
		WHERE e.academic_year_id = $1 AND e.deleted_at IS NULL AND s.deleted_at IS NULL
	`
	var totalStudents, activeStudents, maleStudents, femaleStudents int
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(&totalStudents, &activeStudents, &maleStudents, &femaleStudents)
	if err != nil {
		return fmt.Errorf("refresh student metrics: %w", err)
	}
	upsertQuery := `
        INSERT INTO analytics.student_metrics (academic_year_id, total_students, active_students, male_students, female_students, last_updated)
        VALUES ($1, $2, $3, $4, $5, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_students = EXCLUDED.total_students,
            active_students = EXCLUDED.active_students,
            male_students = EXCLUDED.male_students,
            female_students = EXCLUDED.female_students,
            last_updated = NOW()
    `
	_, err = db.ExecContext(ctx, upsertQuery, academicYearID, totalStudents, activeStudents, maleStudents, femaleStudents)
	if err != nil {
		return fmt.Errorf("upsert student metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) DeleteStudentMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	query := `DELETE FROM analytics.student_metrics WHERE academic_year_id = $1`
	result, err := db.ExecContext(ctx, query, academicYearID)
	if err != nil {
		r.logger.Error("failed to delete student metrics",
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("delete student metrics: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: student metrics %s", ErrNotFound, academicYearID)
	}
	return nil
}

// ================================ Subject Metrics ================================

func (r *analyticsRepository) GetSubjectMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.SubjectMetrics, error) {
	query := `SELECT academic_year_id, total_subjects, active_subjects, total_credits, last_updated
	          FROM analytics.subject_metrics WHERE academic_year_id = $1`
	var m models.SubjectMetrics
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(
		&m.AcademicYearID, &m.TotalSubjects, &m.ActiveSubjects, &m.TotalCredits, &m.LastUpdated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get subject metrics: %w", err)
	}
	return &m, nil
}

func (r *analyticsRepository) ListSubjectMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.SubjectMetrics, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	query := `SELECT academic_year_id, total_subjects, active_subjects, total_credits, last_updated
	          FROM analytics.subject_metrics ORDER BY last_updated DESC LIMIT $1 OFFSET $2`
	rows, err := db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list subject metrics: %w", err)
	}
	defer rows.Close()
	var results []*models.SubjectMetrics
	for rows.Next() {
		var m models.SubjectMetrics
		if err := rows.Scan(&m.AcademicYearID, &m.TotalSubjects, &m.ActiveSubjects, &m.TotalCredits, &m.LastUpdated); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		results = append(results, &m)
	}
	return results, rows.Err()
}

func (r *analyticsRepository) UpdateSubjectMetrics(ctx context.Context, db DBTX, update *models.SubjectMetricsUpdate) error {
	query := `
        INSERT INTO analytics.subject_metrics (academic_year_id, total_subjects, active_subjects, total_credits, last_updated)
        VALUES ($1, $2, $3, $4, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_subjects = analytics.subject_metrics.total_subjects + EXCLUDED.total_subjects,
            active_subjects = analytics.subject_metrics.active_subjects + EXCLUDED.active_subjects,
            total_credits = analytics.subject_metrics.total_credits + EXCLUDED.total_credits,
            last_updated = NOW()
    `
	_, err := db.ExecContext(ctx, query,
		update.AcademicYearID,
		update.DeltaTotal,
		update.DeltaActive,
		update.DeltaCredits,
	)
	if err != nil {
		r.logger.Error("failed to update subject metrics",
			zap.String("academic_year_id", update.AcademicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("update subject metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) RefreshSubjectMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	// Subjects are linked to courses via mappings, and courses are linked to academic years via sections/terms.
	// We'll count subjects used in sections belonging to the academic year.
	query := `
		WITH subjects_in_year AS (
			SELECT DISTINCT sub.subject_id, sub.is_active, sub.credits
			FROM academics.subject sub
			JOIN academics.subject_course_mapping scm ON scm.subject_id = sub.subject_id
			JOIN academics.section s ON s.course_id = scm.course_id
			JOIN academics.term t ON t.term_id = s.term_id
			WHERE t.academic_year_id = $1
			  AND sub.deleted_at IS NULL
		)
		SELECT
			COUNT(subject_id) AS total_subjects,
			COUNT(subject_id) FILTER (WHERE is_active = true) AS active_subjects,
			COALESCE(SUM(credits), 0) AS total_credits
		FROM subjects_in_year
	`
	var totalSubjects, activeSubjects, totalCredits int
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(&totalSubjects, &activeSubjects, &totalCredits)
	if err != nil {
		return fmt.Errorf("refresh subject metrics: %w", err)
	}
	upsertQuery := `
        INSERT INTO analytics.subject_metrics (academic_year_id, total_subjects, active_subjects, total_credits, last_updated)
        VALUES ($1, $2, $3, $4, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_subjects = EXCLUDED.total_subjects,
            active_subjects = EXCLUDED.active_subjects,
            total_credits = EXCLUDED.total_credits,
            last_updated = NOW()
    `
	_, err = db.ExecContext(ctx, upsertQuery, academicYearID, totalSubjects, activeSubjects, totalCredits)
	if err != nil {
		return fmt.Errorf("upsert subject metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) DeleteSubjectMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	query := `DELETE FROM analytics.subject_metrics WHERE academic_year_id = $1`
	result, err := db.ExecContext(ctx, query, academicYearID)
	if err != nil {
		r.logger.Error("failed to delete subject metrics",
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("delete subject metrics: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: subject metrics %s", ErrNotFound, academicYearID)
	}
	return nil
}

// ================================ Submission Metrics ================================

func (r *analyticsRepository) GetSubmissionMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.SubmissionMetrics, error) {
	query := `SELECT academic_year_id, total_submissions, late_submissions, graded_submissions, last_updated
	          FROM analytics.submission_metrics WHERE academic_year_id = $1`
	var m models.SubmissionMetrics
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(
		&m.AcademicYearID, &m.TotalSubmissions, &m.LateSubmissions, &m.GradedSubmissions, &m.LastUpdated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get submission metrics: %w", err)
	}
	return &m, nil
}

func (r *analyticsRepository) ListSubmissionMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.SubmissionMetrics, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	query := `SELECT academic_year_id, total_submissions, late_submissions, graded_submissions, last_updated
	          FROM analytics.submission_metrics ORDER BY last_updated DESC LIMIT $1 OFFSET $2`
	rows, err := db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list submission metrics: %w", err)
	}
	defer rows.Close()
	var results []*models.SubmissionMetrics
	for rows.Next() {
		var m models.SubmissionMetrics
		if err := rows.Scan(&m.AcademicYearID, &m.TotalSubmissions, &m.LateSubmissions, &m.GradedSubmissions, &m.LastUpdated); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		results = append(results, &m)
	}
	return results, rows.Err()
}

func (r *analyticsRepository) UpdateSubmissionMetrics(ctx context.Context, db DBTX, update *models.SubmissionMetricsUpdate) error {
	query := `
        INSERT INTO analytics.submission_metrics (academic_year_id, total_submissions, late_submissions, graded_submissions, last_updated)
        VALUES ($1, $2, $3, $4, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_submissions = analytics.submission_metrics.total_submissions + EXCLUDED.total_submissions,
            late_submissions = analytics.submission_metrics.late_submissions + EXCLUDED.late_submissions,
            graded_submissions = analytics.submission_metrics.graded_submissions + EXCLUDED.graded_submissions,
            last_updated = NOW()
    `
	_, err := db.ExecContext(ctx, query,
		update.AcademicYearID,
		update.DeltaTotal,
		update.DeltaLate,
		update.DeltaGraded,
	)
	if err != nil {
		r.logger.Error("failed to update submission metrics",
			zap.String("academic_year_id", update.AcademicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("update submission metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) RefreshSubmissionMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	query := `
		WITH submissions_in_year AS (
			SELECT sub.submission_id, sub.status, sub.submission_date
			FROM academics.assignment_submissions sub
			JOIN academics.assignments a ON a.assignment_id = sub.assignment_id
			JOIN academics.section s ON s.section_id = a.section_id
			JOIN academics.term t ON t.term_id = s.term_id
			WHERE t.academic_year_id = $1
			  AND sub.deleted_at IS NULL
		)
		SELECT
			COUNT(*) AS total_submissions,
			COUNT(*) FILTER (WHERE status = 'late') AS late_submissions,
			COUNT(*) FILTER (WHERE status = 'graded') AS graded_submissions
		FROM submissions_in_year
	`
	var total, late, graded int
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(&total, &late, &graded)
	if err != nil {
		return fmt.Errorf("refresh submission metrics: %w", err)
	}
	upsertQuery := `
        INSERT INTO analytics.submission_metrics (academic_year_id, total_submissions, late_submissions, graded_submissions, last_updated)
        VALUES ($1, $2, $3, $4, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_submissions = EXCLUDED.total_submissions,
            late_submissions = EXCLUDED.late_submissions,
            graded_submissions = EXCLUDED.graded_submissions,
            last_updated = NOW()
    `
	_, err = db.ExecContext(ctx, upsertQuery, academicYearID, total, late, graded)
	if err != nil {
		return fmt.Errorf("upsert submission metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) DeleteSubmissionMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	query := `DELETE FROM analytics.submission_metrics WHERE academic_year_id = $1`
	result, err := db.ExecContext(ctx, query, academicYearID)
	if err != nil {
		r.logger.Error("failed to delete submission metrics",
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("delete submission metrics: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: submission metrics %s", ErrNotFound, academicYearID)
	}
	return nil
}

// ================================ Teacher Metrics ================================

func (r *analyticsRepository) GetTeacherMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.TeacherMetrics, error) {
	query := `SELECT academic_year_id, total_teachers, active_teachers, last_updated
	          FROM analytics.teacher_metrics WHERE academic_year_id = $1`
	var m models.TeacherMetrics
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(&m.AcademicYearID, &m.TotalTeachers, &m.ActiveTeachers, &m.LastUpdated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get teacher metrics: %w", err)
	}
	return &m, nil
}

func (r *analyticsRepository) ListTeacherMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.TeacherMetrics, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	query := `SELECT academic_year_id, total_teachers, active_teachers, last_updated
	          FROM analytics.teacher_metrics ORDER BY last_updated DESC LIMIT $1 OFFSET $2`
	rows, err := db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list teacher metrics: %w", err)
	}
	defer rows.Close()
	var results []*models.TeacherMetrics
	for rows.Next() {
		var m models.TeacherMetrics
		if err := rows.Scan(&m.AcademicYearID, &m.TotalTeachers, &m.ActiveTeachers, &m.LastUpdated); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		results = append(results, &m)
	}
	return results, rows.Err()
}

func (r *analyticsRepository) UpdateTeacherMetrics(ctx context.Context, db DBTX, update *models.TeacherMetricsUpdate) error {
	query := `
        INSERT INTO analytics.teacher_metrics (academic_year_id, total_teachers, active_teachers, last_updated)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_teachers = analytics.teacher_metrics.total_teachers + EXCLUDED.total_teachers,
            active_teachers = analytics.teacher_metrics.active_teachers + EXCLUDED.active_teachers,
            last_updated = NOW()
    `
	_, err := db.ExecContext(ctx, query,
		update.AcademicYearID,
		update.DeltaTotal,
		update.DeltaActive,
	)
	if err != nil {
		r.logger.Error("failed to update teacher metrics",
			zap.String("academic_year_id", update.AcademicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("update teacher metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) RefreshTeacherMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	// Teachers are assigned to sections in terms. We'll count distinct teachers assigned to sections in this academic year.
	query := `
		WITH company AS (
			SELECT company_id FROM academics.academic_year WHERE academic_year_id = $1
		),
		teachers_in_year AS (
			SELECT DISTINCT t.teacher_id, t.status
			FROM academics.teacher t
			JOIN academics.teacher_section ts ON ts.teacher_id = t.teacher_id
			JOIN academics.section s ON s.section_id = ts.section_id
			JOIN academics.term term ON term.term_id = s.term_id
			WHERE term.academic_year_id = $1
			  AND t.deleted_at IS NULL
		)
		SELECT
			COUNT(teacher_id) AS total_teachers,
			COUNT(teacher_id) FILTER (WHERE status = 'active') AS active_teachers
		FROM teachers_in_year
	`
	var totalTeachers, activeTeachers int
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(&totalTeachers, &activeTeachers)
	if err != nil {
		return fmt.Errorf("refresh teacher metrics: %w", err)
	}
	upsertQuery := `
        INSERT INTO analytics.teacher_metrics (academic_year_id, total_teachers, active_teachers, last_updated)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_teachers = EXCLUDED.total_teachers,
            active_teachers = EXCLUDED.active_teachers,
            last_updated = NOW()
    `
	_, err = db.ExecContext(ctx, upsertQuery, academicYearID, totalTeachers, activeTeachers)
	if err != nil {
		return fmt.Errorf("upsert teacher metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) DeleteTeacherMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	query := `DELETE FROM analytics.teacher_metrics WHERE academic_year_id = $1`
	result, err := db.ExecContext(ctx, query, academicYearID)
	if err != nil {
		r.logger.Error("failed to delete teacher metrics",
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("delete teacher metrics: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: teacher metrics %s", ErrNotFound, academicYearID)
	}
	return nil
}

// ================================ Timetable Metrics ================================

func (r *analyticsRepository) GetTimetableMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.TimetableMetrics, error) {
	query := `SELECT academic_year_id, total_timetables, active_timetables, total_slots, total_entries, total_changes, last_updated
	          FROM analytics.timetable_metrics WHERE academic_year_id = $1`
	var m models.TimetableMetrics
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(
		&m.AcademicYearID, &m.TotalTimetables, &m.ActiveTimetables, &m.TotalSlots, &m.TotalEntries, &m.TotalChanges, &m.LastUpdated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get timetable metrics: %w", err)
	}
	return &m, nil
}

func (r *analyticsRepository) ListTimetableMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.TimetableMetrics, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	query := `SELECT academic_year_id, total_timetables, active_timetables, total_slots, total_entries, total_changes, last_updated
	          FROM analytics.timetable_metrics ORDER BY last_updated DESC LIMIT $1 OFFSET $2`
	rows, err := db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list timetable metrics: %w", err)
	}
	defer rows.Close()
	var results []*models.TimetableMetrics
	for rows.Next() {
		var m models.TimetableMetrics
		if err := rows.Scan(&m.AcademicYearID, &m.TotalTimetables, &m.ActiveTimetables, &m.TotalSlots, &m.TotalEntries, &m.TotalChanges, &m.LastUpdated); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		results = append(results, &m)
	}
	return results, rows.Err()
}

func (r *analyticsRepository) UpdateTimetableMetrics(ctx context.Context, db DBTX, update *models.TimetableMetricsUpdate) error {
	query := `
        INSERT INTO analytics.timetable_metrics (academic_year_id, total_timetables, active_timetables, total_slots, total_entries, total_changes, last_updated)
        VALUES ($1, $2, $3, $4, $5, $6, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_timetables = analytics.timetable_metrics.total_timetables + EXCLUDED.total_timetables,
            active_timetables = analytics.timetable_metrics.active_timetables + EXCLUDED.active_timetables,
            total_slots = analytics.timetable_metrics.total_slots + EXCLUDED.total_slots,
            total_entries = analytics.timetable_metrics.total_entries + EXCLUDED.total_entries,
            total_changes = analytics.timetable_metrics.total_changes + EXCLUDED.total_changes,
            last_updated = NOW()
    `
	_, err := db.ExecContext(ctx, query,
		update.AcademicYearID,
		update.DeltaTimetables,
		update.DeltaActive,
		update.DeltaSlots,
		update.DeltaEntries,
		update.DeltaChanges,
	)
	if err != nil {
		r.logger.Error("failed to update timetable metrics",
			zap.String("academic_year_id", update.AcademicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("update timetable metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) RefreshTimetableMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	query := `
		WITH timetables_in_year AS (
			SELECT tt.timetable_id, tt.is_active
			FROM academics.timetables tt
			WHERE tt.academic_year_id = $1 AND tt.deleted_at IS NULL
		),
		slot_counts AS (
			SELECT tt.timetable_id, COUNT(slot_id) AS total_slots
			FROM academics.timetable_slots s
			JOIN timetables_in_year tt ON tt.timetable_id = s.timetable_id
			GROUP BY tt.timetable_id
		),
		entry_counts AS (
			SELECT s.timetable_id, COUNT(e.entry_id) AS total_entries
			FROM academics.timetable_entries e
			 JOIN academics.timetable_slots s ON s.slot_id = e.slot_id
			 JOIN timetables_in_year tt ON tt.timetable_id = s.timetable_id
			GROUP BY s.timetable_id
		),
		change_counts AS (
			SELECT s.timetable_id, COUNT(c.change_id) AS total_changes
			FROM academics.timetable_changes c
			 JOIN academics.timetable_entries e ON e.entry_id = c.entry_id
			 JOIN academics.timetable_slots s ON s.slot_id = e.slot_id
			 JOIN timetables_in_year tt ON tt.timetable_id = s.timetable_id
			GROUP BY s.timetable_id
		)
		SELECT
			COUNT(tt.timetable_id) AS total_timetables,
			COUNT(tt.timetable_id) FILTER (WHERE tt.is_active = true) AS active_timetables,
			COALESCE(SUM(sc.total_slots), 0) AS total_slots,
			COALESCE(SUM(ec.total_entries), 0) AS total_entries,
			COALESCE(SUM(cc.total_changes), 0) AS total_changes
		FROM timetables_in_year tt
		LEFT JOIN slot_counts sc ON sc.timetable_id = tt.timetable_id
		LEFT JOIN entry_counts ec ON ec.timetable_id = tt.timetable_id
		LEFT JOIN change_counts cc ON cc.timetable_id = tt.timetable_id
	`
	var totalTimetables, activeTimetables, totalSlots, totalEntries, totalChanges int
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(&totalTimetables, &activeTimetables, &totalSlots, &totalEntries, &totalChanges)
	if err != nil {
		return fmt.Errorf("refresh timetable metrics: %w", err)
	}
	upsertQuery := `
        INSERT INTO analytics.timetable_metrics (academic_year_id, total_timetables, active_timetables, total_slots, total_entries, total_changes, last_updated)
        VALUES ($1, $2, $3, $4, $5, $6, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_timetables = EXCLUDED.total_timetables,
            active_timetables = EXCLUDED.active_timetables,
            total_slots = EXCLUDED.total_slots,
            total_entries = EXCLUDED.total_entries,
            total_changes = EXCLUDED.total_changes,
            last_updated = NOW()
    `
	_, err = db.ExecContext(ctx, upsertQuery, academicYearID, totalTimetables, activeTimetables, totalSlots, totalEntries, totalChanges)
	if err != nil {
		return fmt.Errorf("upsert timetable metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) DeleteTimetableMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	query := `DELETE FROM analytics.timetable_metrics WHERE academic_year_id = $1`
	result, err := db.ExecContext(ctx, query, academicYearID)
	if err != nil {
		r.logger.Error("failed to delete timetable metrics",
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("delete timetable metrics: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: timetable metrics %s", ErrNotFound, academicYearID)
	}
	return nil
}

// ================================ Transport Metrics ================================

func (r *analyticsRepository) GetTransportMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.TransportMetrics, error) {
	query := `SELECT academic_year_id, total_routes, total_stops, total_vehicles, active_vehicles,
	          total_driver_assignments, total_student_assignments, last_updated
	          FROM analytics.transport_metrics WHERE academic_year_id = $1`
	var m models.TransportMetrics
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(
		&m.AcademicYearID, &m.TotalRoutes, &m.TotalStops, &m.TotalVehicles, &m.ActiveVehicles,
		&m.TotalDriverAssignments, &m.TotalStudentAssignments, &m.LastUpdated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get transport metrics: %w", err)
	}
	return &m, nil
}

func (r *analyticsRepository) ListTransportMetrics(ctx context.Context, db DBTX, limit, offset int) ([]*models.TransportMetrics, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	query := `SELECT academic_year_id, total_routes, total_stops, total_vehicles, active_vehicles,
	          total_driver_assignments, total_student_assignments, last_updated
	          FROM analytics.transport_metrics ORDER BY last_updated DESC LIMIT $1 OFFSET $2`
	rows, err := db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list transport metrics: %w", err)
	}
	defer rows.Close()
	var results []*models.TransportMetrics
	for rows.Next() {
		var m models.TransportMetrics
		if err := rows.Scan(&m.AcademicYearID, &m.TotalRoutes, &m.TotalStops, &m.TotalVehicles, &m.ActiveVehicles,
			&m.TotalDriverAssignments, &m.TotalStudentAssignments, &m.LastUpdated); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		results = append(results, &m)
	}
	return results, rows.Err()
}

func (r *analyticsRepository) UpdateTransportMetrics(ctx context.Context, db DBTX, update *models.TransportMetricsUpdate) error {
	query := `
        INSERT INTO analytics.transport_metrics (
            academic_year_id, total_routes, total_stops, total_vehicles, active_vehicles,
            total_driver_assignments, total_student_assignments, last_updated
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_routes = analytics.transport_metrics.total_routes + EXCLUDED.total_routes,
            total_stops = analytics.transport_metrics.total_stops + EXCLUDED.total_stops,
            total_vehicles = analytics.transport_metrics.total_vehicles + EXCLUDED.total_vehicles,
            active_vehicles = analytics.transport_metrics.active_vehicles + EXCLUDED.active_vehicles,
            total_driver_assignments = analytics.transport_metrics.total_driver_assignments + EXCLUDED.total_driver_assignments,
            total_student_assignments = analytics.transport_metrics.total_student_assignments + EXCLUDED.total_student_assignments,
            last_updated = NOW()
    `
	_, err := db.ExecContext(ctx, query,
		update.AcademicYearID,
		update.DeltaRoutes,
		update.DeltaStops,
		update.DeltaVehicles,
		update.DeltaActiveVehicles,
		update.DeltaDriverAssignments,
		update.DeltaStudentAssignments,
	)
	if err != nil {
		r.logger.Error("failed to update transport metrics",
			zap.String("academic_year_id", update.AcademicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("update transport metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) RefreshTransportMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	// Transport is company-level. We'll get the company from the academic year.
	query := `
		WITH company AS (
			SELECT company_id FROM academics.academic_year WHERE academic_year_id = $1
		)
		SELECT
			(SELECT COUNT(*) FROM academics.transport_routes WHERE company_id = (SELECT company_id FROM company) AND deleted_at IS NULL) AS total_routes,
			(SELECT COUNT(*) FROM academics.transport_stops WHERE route_id IN (SELECT route_id FROM academics.transport_routes WHERE company_id = (SELECT company_id FROM company)) AND deleted_at IS NULL) AS total_stops,
			(SELECT COUNT(*) FROM academics.transport_vehicles WHERE company_id = (SELECT company_id FROM company) AND deleted_at IS NULL) AS total_vehicles,
			(SELECT COUNT(*) FROM academics.transport_vehicles WHERE company_id = (SELECT company_id FROM company) AND is_active = true AND deleted_at IS NULL) AS active_vehicles,
			(SELECT COUNT(*) FROM academics.transport_driver_assignments WHERE vehicle_id IN (SELECT vehicle_id FROM academics.transport_vehicles WHERE company_id = (SELECT company_id FROM company)) AND deleted_at IS NULL) AS total_driver_assignments,
			(SELECT COUNT(*) FROM academics.student_transport_assignments WHERE route_id IN (SELECT route_id FROM academics.transport_routes WHERE company_id = (SELECT company_id FROM company)) AND deleted_at IS NULL) AS total_student_assignments
	`
	var totalRoutes, totalStops, totalVehicles, activeVehicles, totalDriverAssignments, totalStudentAssignments int
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(
		&totalRoutes, &totalStops, &totalVehicles, &activeVehicles,
		&totalDriverAssignments, &totalStudentAssignments,
	)
	if err != nil {
		return fmt.Errorf("refresh transport metrics: %w", err)
	}
	upsertQuery := `
        INSERT INTO analytics.transport_metrics (
            academic_year_id, total_routes, total_stops, total_vehicles, active_vehicles,
            total_driver_assignments, total_student_assignments, last_updated
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
        ON CONFLICT (academic_year_id) DO UPDATE SET
            total_routes = EXCLUDED.total_routes,
            total_stops = EXCLUDED.total_stops,
            total_vehicles = EXCLUDED.total_vehicles,
            active_vehicles = EXCLUDED.active_vehicles,
            total_driver_assignments = EXCLUDED.total_driver_assignments,
            total_student_assignments = EXCLUDED.total_student_assignments,
            last_updated = NOW()
    `
	_, err = db.ExecContext(ctx, upsertQuery,
		academicYearID, totalRoutes, totalStops, totalVehicles, activeVehicles,
		totalDriverAssignments, totalStudentAssignments,
	)
	if err != nil {
		return fmt.Errorf("upsert transport metrics: %w", err)
	}
	return nil
}

func (r *analyticsRepository) DeleteTransportMetrics(ctx context.Context, db DBTX, academicYearID uuid.UUID) error {
	query := `DELETE FROM analytics.transport_metrics WHERE academic_year_id = $1`
	result, err := db.ExecContext(ctx, query, academicYearID)
	if err != nil {
		r.logger.Error("failed to delete transport metrics",
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("delete transport metrics: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: transport metrics %s", ErrNotFound, academicYearID)
	}
	return nil
}
