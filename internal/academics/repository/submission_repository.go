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

// SubmissionRepository defines database operations for submissions, grades, and comments.
type SubmissionRepository interface {
	// Submissions
	CreateSubmission(ctx context.Context, db DBTX, s *models.AssignmentSubmission) error
	GetSubmissionByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.AssignmentSubmission, error)
	GetSubmissionByAssignmentAndStudent(ctx context.Context, db DBTX, assignmentID, studentID uuid.UUID) (*models.AssignmentSubmission, error)
	ListSubmissions(ctx context.Context, db DBTX, filter SubmissionFilter, p Pagination, s Sort) ([]*models.AssignmentSubmission, error)
	CountSubmissions(ctx context.Context, db DBTX, filter SubmissionFilter) (int64, error)
	UpdateSubmission(ctx context.Context, db DBTX, s *models.AssignmentSubmission) error
	DeleteSubmission(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error

	// Grading
	GradeSubmission(ctx context.Context, db DBTX, submissionID uuid.UUID, marks float64, feedback string, gradedBy uuid.UUID) error
	CreateGrade(ctx context.Context, db DBTX, g *models.AssignmentGrade) error
	GetGradesBySubmission(ctx context.Context, db DBTX, submissionID uuid.UUID) ([]*models.AssignmentGrade, error)

	// Comments
	AddComment(ctx context.Context, db DBTX, c *models.AssignmentComment) error
	GetCommentsBySubmission(ctx context.Context, db DBTX, submissionID uuid.UUID) ([]*models.AssignmentComment, error)
}

type submissionRepository struct {
	logger *zap.Logger
}

// NewSubmissionRepository creates a new submission repository.
func NewSubmissionRepository(logger *zap.Logger) SubmissionRepository {
	return &submissionRepository{
		logger: logger.Named("submission_repo"),
	}
}

var allowedSubmissionSortFields = map[string]bool{
	"submission_date": true,
	"created_at":      true,
	"updated_at":      true,
	"status":          true,
}

func (r *submissionRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "submission_date"
	}
	if !allowedSubmissionSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY s.%s %s", field, dir), nil
}

func (r *submissionRepository) validatePagination(p Pagination) (int, int) {
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

func (r *submissionRepository) buildSubmissionFilter(filter SubmissionFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.AssignmentID != nil {
		conditions = append(conditions, fmt.Sprintf("s.assignment_id = $%d", idx))
		args = append(args, *filter.AssignmentID)
		idx++
	}
	if filter.StudentID != nil {
		conditions = append(conditions, fmt.Sprintf("s.student_id = $%d", idx))
		args = append(args, *filter.StudentID)
		idx++
	}
	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("s.status = $%d", idx))
		args = append(args, *filter.Status)
		idx++
	}
	if filter.Graded != nil {
		if *filter.Graded {
			conditions = append(conditions, "s.status = 'graded'")
		} else {
			conditions = append(conditions, "s.status IN ('submitted', 'late')")
		}
	}
	if filter.SubmittedFrom != nil {
		conditions = append(conditions, fmt.Sprintf("s.submission_date >= $%d", idx))
		args = append(args, *filter.SubmittedFrom)
		idx++
	}
	if filter.SubmittedTo != nil {
		conditions = append(conditions, fmt.Sprintf("s.submission_date <= $%d", idx))
		args = append(args, *filter.SubmittedTo)
		idx++
	}

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

// --- Submissions ---------------------------------------------------------

func (r *submissionRepository) CreateSubmission(ctx context.Context, db DBTX, s *models.AssignmentSubmission) error {
	query := `
        INSERT INTO academics.assignment_submissions (
            assignment_id, student_id, submission_date, file_url, remarks,
            status, marks_obtained, feedback, graded_by, graded_at,
            created_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
        RETURNING submission_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		s.AssignmentID, s.StudentID, s.SubmissionDate, s.FileURL, s.Remarks,
		s.Status, s.MarksObtained, s.Feedback, s.GradedBy, s.GradedAt,
		s.CreatedBy,
	).Scan(&s.SubmissionID, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create submission",
			util.String("assignment_id", s.AssignmentID.String()),
			util.String("student_id", s.StudentID.String()),
			util.ErrorField(err))
		return fmt.Errorf("create submission: %w", err)
	}
	return nil
}

func (r *submissionRepository) GetSubmissionByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.AssignmentSubmission, error) {
	query := `
        SELECT
            submission_id, assignment_id, student_id, submission_date, file_url, remarks,
            status, marks_obtained, feedback, graded_by, graded_at,
            created_at, updated_at, created_by
        FROM academics.assignment_submissions
        WHERE submission_id = $1
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanSubmission(row)
}

func (r *submissionRepository) GetSubmissionByAssignmentAndStudent(ctx context.Context, db DBTX, assignmentID, studentID uuid.UUID) (*models.AssignmentSubmission, error) {
	query := `
        SELECT
            submission_id, assignment_id, student_id, submission_date, file_url, remarks,
            status, marks_obtained, feedback, graded_by, graded_at,
            created_at, updated_at, created_by
        FROM academics.assignment_submissions
        WHERE assignment_id = $1 AND student_id = $2
    `
	row := db.QueryRowContext(ctx, query, assignmentID, studentID)
	return r.scanSubmission(row)
}

func (r *submissionRepository) ListSubmissions(ctx context.Context, db DBTX, filter SubmissionFilter, p Pagination, s Sort) ([]*models.AssignmentSubmission, error) {
	where, args := r.buildSubmissionFilter(filter)
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
        SELECT
            submission_id, assignment_id, student_id, submission_date, file_url, remarks,
            status, marks_obtained, feedback, graded_by, graded_at,
            created_at, updated_at, created_by
        FROM academics.assignment_submissions s
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list submissions",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list submissions: %w", err)
	}
	defer rows.Close()

	var result []*models.AssignmentSubmission
	for rows.Next() {
		sub, err := r.scanSubmission(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, sub)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *submissionRepository) CountSubmissions(ctx context.Context, db DBTX, filter SubmissionFilter) (int64, error) {
	where, args := r.buildSubmissionFilter(filter)

	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.assignment_submissions s %s", where)

	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count submissions",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count submissions: %w", err)
	}
	return count, nil
}

func (r *submissionRepository) UpdateSubmission(ctx context.Context, db DBTX, s *models.AssignmentSubmission) error {
	query := `
        UPDATE academics.assignment_submissions
        SET
            submission_date = $2,
            file_url = $3,
            remarks = $4,
            status = $5,
            marks_obtained = $6,
            feedback = $7,
            graded_by = $8,
            graded_at = $9,
            updated_at = NOW()
        WHERE submission_id = $1
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		s.SubmissionID,
		s.SubmissionDate,
		s.FileURL,
		s.Remarks,
		s.Status,
		s.MarksObtained,
		s.Feedback,
		s.GradedBy,
		s.GradedAt,
	).Scan(&s.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: submission %s", ErrNotFound, s.SubmissionID)
		}
		r.logger.Error("failed to update submission",
			util.String("id", s.SubmissionID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update submission: %w", err)
	}
	return nil
}

func (r *submissionRepository) DeleteSubmission(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error {
	// Hard delete as per schema (no deleted_at column)
	query := `DELETE FROM academics.assignment_submissions WHERE submission_id = $1`
	result, err := db.ExecContext(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete submission",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete submission: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("submission %s not found", id)
	}
	return nil
}

// --- Grading ------------------------------------------------------------

func (r *submissionRepository) GradeSubmission(ctx context.Context, db DBTX, submissionID uuid.UUID, marks float64, feedback string, gradedBy uuid.UUID) error {
	query := `
        UPDATE academics.assignment_submissions
        SET
            marks_obtained = $2,
            feedback = $3,
            status = 'graded',
            graded_by = $4,
            graded_at = NOW(),
            updated_at = NOW()
        WHERE submission_id = $1
    `
	_, err := db.ExecContext(ctx, query, submissionID, marks, feedback, gradedBy)
	if err != nil {
		r.logger.Error("failed to grade submission",
			util.String("submission_id", submissionID.String()),
			util.ErrorField(err))
		return fmt.Errorf("grade submission: %w", err)
	}
	return nil
}

func (r *submissionRepository) CreateGrade(ctx context.Context, db DBTX, g *models.AssignmentGrade) error {
	query := `
        INSERT INTO academics.assignment_grades (
            submission_id, marks, graded_by, graded_at, remarks, created_by, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, NOW())
        RETURNING grade_id, created_at
    `
	err := db.QueryRowContext(ctx, query,
		g.SubmissionID, g.Marks, g.GradedBy, g.GradedAt, g.Remarks, g.CreatedBy,
	).Scan(&g.GradeID, &g.CreatedAt)
	if err != nil {
		r.logger.Error("failed to create grade",
			util.String("submission_id", g.SubmissionID.String()),
			util.ErrorField(err))
		return fmt.Errorf("create grade: %w", err)
	}
	return nil
}

func (r *submissionRepository) GetGradesBySubmission(ctx context.Context, db DBTX, submissionID uuid.UUID) ([]*models.AssignmentGrade, error) {
	query := `
        SELECT
            grade_id, submission_id, marks, graded_by, graded_at, remarks, created_at, created_by
        FROM academics.assignment_grades
        WHERE submission_id = $1
        ORDER BY graded_at DESC
    `
	rows, err := db.QueryContext(ctx, query, submissionID)
	if err != nil {
		r.logger.Error("failed to get grades by submission",
			util.String("submission_id", submissionID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get grades by submission: %w", err)
	}
	defer rows.Close()

	var grades []*models.AssignmentGrade
	for rows.Next() {
		var g models.AssignmentGrade
		var createdBy uuid.NullUUID
		if err := rows.Scan(
			&g.GradeID,
			&g.SubmissionID,
			&g.Marks,
			&g.GradedBy,
			&g.GradedAt,
			&g.Remarks,
			&g.CreatedAt,
			&createdBy,
		); err != nil {
			return nil, fmt.Errorf("scan grade: %w", err)
		}
		if createdBy.Valid {
			g.CreatedBy = &createdBy.UUID
		}
		grades = append(grades, &g)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return grades, nil
}

// --- Comments -----------------------------------------------------------

func (r *submissionRepository) AddComment(ctx context.Context, db DBTX, c *models.AssignmentComment) error {
	query := `
        INSERT INTO academics.assignment_comments (
            submission_id, comment_by, comment, created_by, created_at
        ) VALUES ($1, $2, $3, $4, NOW())
        RETURNING comment_id, created_at
    `
	err := db.QueryRowContext(ctx, query,
		c.SubmissionID, c.CommentBy, c.Comment, c.CreatedBy,
	).Scan(&c.CommentID, &c.CreatedAt)
	if err != nil {
		r.logger.Error("failed to add comment",
			util.String("submission_id", c.SubmissionID.String()),
			util.ErrorField(err))
		return fmt.Errorf("add comment: %w", err)
	}
	return nil
}

func (r *submissionRepository) GetCommentsBySubmission(ctx context.Context, db DBTX, submissionID uuid.UUID) ([]*models.AssignmentComment, error) {
	query := `
        SELECT
            comment_id, submission_id, comment_by, comment, created_at, created_by
        FROM academics.assignment_comments
        WHERE submission_id = $1
        ORDER BY created_at ASC
    `
	rows, err := db.QueryContext(ctx, query, submissionID)
	if err != nil {
		r.logger.Error("failed to get comments by submission",
			util.String("submission_id", submissionID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get comments by submission: %w", err)
	}
	defer rows.Close()

	var comments []*models.AssignmentComment
	for rows.Next() {
		var c models.AssignmentComment
		var createdBy uuid.NullUUID
		if err := rows.Scan(
			&c.CommentID,
			&c.SubmissionID,
			&c.CommentBy,
			&c.Comment,
			&c.CreatedAt,
			&createdBy,
		); err != nil {
			return nil, fmt.Errorf("scan comment: %w", err)
		}
		if createdBy.Valid {
			c.CreatedBy = &createdBy.UUID
		}
		comments = append(comments, &c)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return comments, nil
}

// scanSubmission scans a row into an AssignmentSubmission model.
func (r *submissionRepository) scanSubmission(row scanner) (*models.AssignmentSubmission, error) {
	var s models.AssignmentSubmission
	var marksObtained sql.NullFloat64
	var gradedBy, createdBy uuid.NullUUID
	var gradedAt sql.NullTime

	err := row.Scan(
		&s.SubmissionID,
		&s.AssignmentID,
		&s.StudentID,
		&s.SubmissionDate,
		&s.FileURL,
		&s.Remarks,
		&s.Status,
		&marksObtained,
		&s.Feedback,
		&gradedBy,
		&gradedAt,
		&s.CreatedAt,
		&s.UpdatedAt,
		&createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan submission: %w", err)
	}
	if marksObtained.Valid {
		s.MarksObtained = &marksObtained.Float64
	}
	if gradedBy.Valid {
		s.GradedBy = &gradedBy.UUID
	}
	if gradedAt.Valid {
		s.GradedAt = &gradedAt.Time
	}
	if createdBy.Valid {
		s.CreatedBy = &createdBy.UUID
	}
	return &s, nil
}
