package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/client"
	"auth-service/internal/util"
)

// SubjectCourseMappingRepository defines methods for subject_course_mapping table.
type SubjectCourseMappingRepository interface {
	Create(ctx context.Context, e *models.SubjectCourseMapping) error
	BulkCreate(ctx context.Context, e []*models.SubjectCourseMapping) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.SubjectCourseMapping, error)
	ListByCourse(ctx context.Context, courseID uuid.UUID) ([]*models.SubjectCourseMapping, error)
	ListBySubject(ctx context.Context, subjectID uuid.UUID) ([]*models.SubjectCourseMapping, error)
	ListByCourseAndTerm(ctx context.Context, courseID uuid.UUID, termNumber int) ([]*models.SubjectCourseMapping, error)
	Exists(ctx context.Context, courseID, subjectID uuid.UUID, termNumber int) (bool, error)
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteByCourse(ctx context.Context, courseID uuid.UUID) error
}

type subjectCourseMappingRepository struct {
	db     *client.PostgresClient
	logger *zap.Logger
}

// NewSubjectCourseMappingRepository creates a new mapping repository.
func NewSubjectCourseMappingRepository(db *client.PostgresClient, logger *zap.Logger) SubjectCourseMappingRepository {
	return &subjectCourseMappingRepository{
		db:     db,
		logger: logger.Named("subject_course_mapping_repo"),
	}
}

// Create inserts a new mapping.
func (r *subjectCourseMappingRepository) Create(ctx context.Context, e *models.SubjectCourseMapping) error {
	query := `
		INSERT INTO academics.subject_course_mapping (
			course_id, subject_id, term_number, is_compulsory, created_at, updated_at
		) VALUES ($1, $2, $3, $4, NOW(), NOW())
		RETURNING mapping_id, created_at, updated_at
	`
	err := r.db.QueryRow(ctx, query,
		e.CourseID, e.SubjectID, e.TermNumber, e.IsCompulsory,
	).Scan(&e.MappingID, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create subject course mapping",
			util.String("course_id", e.CourseID.String()),
			util.String("subject_id", e.SubjectID.String()),
			util.ErrorField(err))
		return fmt.Errorf("create mapping: %w", err)
	}
	return nil
}

// BulkCreate inserts multiple mappings.
func (r *subjectCourseMappingRepository) BulkCreate(ctx context.Context, e []*models.SubjectCourseMapping) error {
	if len(e) == 0 {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO academics.subject_course_mapping (
			course_id, subject_id, term_number, is_compulsory, created_at, updated_at
		) VALUES ($1, $2, $3, $4, NOW(), NOW())
		RETURNING mapping_id, created_at, updated_at
	`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, m := range e {
		err = stmt.QueryRowContext(ctx,
			m.CourseID, m.SubjectID, m.TermNumber, m.IsCompulsory,
		).Scan(&m.MappingID, &m.CreatedAt, &m.UpdatedAt)
		if err != nil {
			r.logger.Error("bulk create mapping failed",
				util.String("course_id", m.CourseID.String()),
				util.String("subject_id", m.SubjectID.String()),
				util.ErrorField(err))
			return fmt.Errorf("bulk create mapping row: %w", err)
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// GetByID retrieves a mapping by its ID.
func (r *subjectCourseMappingRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.SubjectCourseMapping, error) {
	query := `
		SELECT mapping_id, course_id, subject_id, term_number, is_compulsory, created_at, updated_at
		FROM academics.subject_course_mapping
		WHERE mapping_id = $1
	`
	var m models.SubjectCourseMapping
	var termNumber sql.NullInt64
	err := r.db.QueryRow(ctx, query, id).Scan(
		&m.MappingID, &m.CourseID, &m.SubjectID, &termNumber,
		&m.IsCompulsory, &m.CreatedAt, &m.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get mapping by ID",
			util.String("id", id.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get mapping by ID: %w", err)
	}
	if termNumber.Valid {
		m.TermNumber = int(termNumber.Int64)
	}
	return &m, nil
}

// ListByCourse returns all mappings for a given course.
func (r *subjectCourseMappingRepository) ListByCourse(ctx context.Context, courseID uuid.UUID) ([]*models.SubjectCourseMapping, error) {
	query := `
		SELECT mapping_id, course_id, subject_id, term_number, is_compulsory, created_at, updated_at
		FROM academics.subject_course_mapping
		WHERE course_id = $1
		ORDER BY term_number NULLS LAST, created_at
	`
	rows, err := r.db.Query(ctx, query, courseID)
	if err != nil {
		r.logger.Error("failed to list mappings by course",
			util.String("course_id", courseID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("list by course: %w", err)
	}
	defer rows.Close()
	return r.scanMappings(rows)
}

// ListBySubject returns all mappings for a given subject.
func (r *subjectCourseMappingRepository) ListBySubject(ctx context.Context, subjectID uuid.UUID) ([]*models.SubjectCourseMapping, error) {
	query := `
		SELECT mapping_id, course_id, subject_id, term_number, is_compulsory, created_at, updated_at
		FROM academics.subject_course_mapping
		WHERE subject_id = $1
		ORDER BY term_number NULLS LAST, created_at
	`
	rows, err := r.db.Query(ctx, query, subjectID)
	if err != nil {
		r.logger.Error("failed to list mappings by subject",
			util.String("subject_id", subjectID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("list by subject: %w", err)
	}
	defer rows.Close()
	return r.scanMappings(rows)
}

// ListByCourseAndTerm returns mappings for a course and specific term.
func (r *subjectCourseMappingRepository) ListByCourseAndTerm(ctx context.Context, courseID uuid.UUID, termNumber int) ([]*models.SubjectCourseMapping, error) {
	query := `
		SELECT mapping_id, course_id, subject_id, term_number, is_compulsory, created_at, updated_at
		FROM academics.subject_course_mapping
		WHERE course_id = $1 AND term_number = $2
		ORDER BY created_at
	`
	rows, err := r.db.Query(ctx, query, courseID, termNumber)
	if err != nil {
		r.logger.Error("failed to list mappings by course and term",
			util.String("course_id", courseID.String()),
			util.Int("term", termNumber),
			util.ErrorField(err))
		return nil, fmt.Errorf("list by course and term: %w", err)
	}
	defer rows.Close()
	return r.scanMappings(rows)
}

// Exists checks if a mapping exists.
func (r *subjectCourseMappingRepository) Exists(ctx context.Context, courseID, subjectID uuid.UUID, termNumber int) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM academics.subject_course_mapping WHERE course_id = $1 AND subject_id = $2 AND term_number = $3)`
	var exists bool
	err := r.db.QueryRow(ctx, query, courseID, subjectID, termNumber).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check mapping existence",
			util.String("course_id", courseID.String()),
			util.String("subject_id", subjectID.String()),
			util.Int("term", termNumber),
			util.ErrorField(err))
		return false, fmt.Errorf("exists mapping: %w", err)
	}
	return exists, nil
}

// Delete removes a mapping.
func (r *subjectCourseMappingRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM academics.subject_course_mapping WHERE mapping_id = $1`
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete mapping",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete mapping: %w", err)
	}
	return nil
}

// DeleteByCourse removes all mappings for a course.
func (r *subjectCourseMappingRepository) DeleteByCourse(ctx context.Context, courseID uuid.UUID) error {
	query := `DELETE FROM academics.subject_course_mapping WHERE course_id = $1`
	_, err := r.db.Exec(ctx, query, courseID)
	if err != nil {
		r.logger.Error("failed to delete mappings by course",
			util.String("course_id", courseID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete by course: %w", err)
	}
	return nil
}

// scanMappings helper to scan rows into mapping slice.
func (r *subjectCourseMappingRepository) scanMappings(rows *sql.Rows) ([]*models.SubjectCourseMapping, error) {
	var result []*models.SubjectCourseMapping
	for rows.Next() {
		var m models.SubjectCourseMapping
		var termNumber sql.NullInt64
		if err := rows.Scan(
			&m.MappingID, &m.CourseID, &m.SubjectID, &termNumber,
			&m.IsCompulsory, &m.CreatedAt, &m.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan mapping: %w", err)
		}
		if termNumber.Valid {
			m.TermNumber = int(termNumber.Int64)
		}
		result = append(result, &m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}
