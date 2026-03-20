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

// SubjectCourseMappingRepository defines methods for subject_course_mapping table.
// This table does not have audit or soft delete columns, so no changes for those.
type SubjectCourseMappingRepository interface {
	Create(ctx context.Context, db DBTX, e *models.SubjectCourseMapping) error
	BulkCreate(ctx context.Context, db DBTX, e []*models.SubjectCourseMapping) error
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.SubjectCourseMapping, error)
	ListByCourse(ctx context.Context, db DBTX, courseID uuid.UUID) ([]*models.SubjectCourseMapping, error)
	ListBySubject(ctx context.Context, db DBTX, subjectID uuid.UUID) ([]*models.SubjectCourseMapping, error)
	ListByCourseAndTerm(ctx context.Context, db DBTX, courseID uuid.UUID, termNumber int) ([]*models.SubjectCourseMapping, error)
	Exists(ctx context.Context, db DBTX, courseID, subjectID uuid.UUID, termNumber int) (bool, error)
	Delete(ctx context.Context, db DBTX, id uuid.UUID) error
	DeleteByCourse(ctx context.Context, db DBTX, courseID uuid.UUID) error
	ListByCourseIDsAndTermNumbers(ctx context.Context, db DBTX, courseIDs []uuid.UUID, termNumbers []int) ([]*models.SubjectCourseMapping, error)
}

type subjectCourseMappingRepository struct {
	logger *zap.Logger
}

// NewSubjectCourseMappingRepository creates a new mapping repository.
func NewSubjectCourseMappingRepository(logger *zap.Logger) SubjectCourseMappingRepository {
	return &subjectCourseMappingRepository{
		logger: logger.Named("subject_course_mapping_repo"),
	}
}

// Create inserts a new mapping.
func (r *subjectCourseMappingRepository) Create(ctx context.Context, db DBTX, e *models.SubjectCourseMapping) error {
	query := `
		INSERT INTO academics.subject_course_mapping (
			course_id, subject_id, term_number, is_compulsory, created_at, updated_at
		) VALUES ($1, $2, $3, $4, NOW(), NOW())
		RETURNING mapping_id, created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
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

// BulkCreate inserts multiple mappings with proper transaction handling.
func (r *subjectCourseMappingRepository) BulkCreate(ctx context.Context, db DBTX, e []*models.SubjectCourseMapping) error {
	if len(e) == 0 {
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

	if isOwner {
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit tx: %w", err)
		}
		needRollback = false
	}
	return nil
}

// GetByID retrieves a mapping by its ID.
func (r *subjectCourseMappingRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.SubjectCourseMapping, error) {
	query := `
		SELECT mapping_id, course_id, subject_id, term_number, is_compulsory, created_at, updated_at
		FROM academics.subject_course_mapping
		WHERE mapping_id = $1
	`
	var m models.SubjectCourseMapping
	var termNumber sql.NullInt64
	err := db.QueryRowContext(ctx, query, id).Scan(
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
func (r *subjectCourseMappingRepository) ListByCourse(ctx context.Context, db DBTX, courseID uuid.UUID) ([]*models.SubjectCourseMapping, error) {
	query := `
		SELECT mapping_id, course_id, subject_id, term_number, is_compulsory, created_at, updated_at
		FROM academics.subject_course_mapping
		WHERE course_id = $1
		ORDER BY term_number NULLS LAST, created_at
	`
	rows, err := db.QueryContext(ctx, query, courseID)
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
func (r *subjectCourseMappingRepository) ListBySubject(ctx context.Context, db DBTX, subjectID uuid.UUID) ([]*models.SubjectCourseMapping, error) {
	query := `
		SELECT mapping_id, course_id, subject_id, term_number, is_compulsory, created_at, updated_at
		FROM academics.subject_course_mapping
		WHERE subject_id = $1
		ORDER BY term_number NULLS LAST, created_at
	`
	rows, err := db.QueryContext(ctx, query, subjectID)
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
func (r *subjectCourseMappingRepository) ListByCourseAndTerm(ctx context.Context, db DBTX, courseID uuid.UUID, termNumber int) ([]*models.SubjectCourseMapping, error) {
	query := `
		SELECT mapping_id, course_id, subject_id, term_number, is_compulsory, created_at, updated_at
		FROM academics.subject_course_mapping
		WHERE course_id = $1 AND term_number = $2
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, courseID, termNumber)
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
func (r *subjectCourseMappingRepository) Exists(ctx context.Context, db DBTX, courseID, subjectID uuid.UUID, termNumber int) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM academics.subject_course_mapping WHERE course_id = $1 AND subject_id = $2 AND term_number = $3)`
	var exists bool
	err := db.QueryRowContext(ctx, query, courseID, subjectID, termNumber).Scan(&exists)
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
func (r *subjectCourseMappingRepository) Delete(ctx context.Context, db DBTX, id uuid.UUID) error {
	query := `DELETE FROM academics.subject_course_mapping WHERE mapping_id = $1`
	result, err := db.ExecContext(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete mapping",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete mapping: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("mapping %s not found", id)
	}
	return nil
}

// DeleteByCourse removes all mappings for a course.
func (r *subjectCourseMappingRepository) DeleteByCourse(ctx context.Context, db DBTX, courseID uuid.UUID) error {
	query := `DELETE FROM academics.subject_course_mapping WHERE course_id = $1`
	_, err := db.ExecContext(ctx, query, courseID)
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

// ListByCourseIDsAndTermNumbers retrieves all mappings for the given course IDs and term numbers.
func (r *subjectCourseMappingRepository) ListByCourseIDsAndTermNumbers(ctx context.Context, db DBTX, courseIDs []uuid.UUID, termNumbers []int) ([]*models.SubjectCourseMapping, error) {
	if len(courseIDs) == 0 || len(termNumbers) == 0 {
		return []*models.SubjectCourseMapping{}, nil
	}
	// Build placeholders for course IDs and term numbers
	coursePlaceholders := make([]string, len(courseIDs))
	courseArgs := make([]interface{}, len(courseIDs))
	for i, id := range courseIDs {
		coursePlaceholders[i] = fmt.Sprintf("$%d", i+1)
		courseArgs[i] = id
	}
	termPlaceholders := make([]string, len(termNumbers))
	termArgs := make([]interface{}, len(termNumbers))
	for i, tn := range termNumbers {
		termPlaceholders[i] = fmt.Sprintf("$%d", i+len(courseIDs)+1)
		termArgs[i] = tn
	}
	allArgs := append(courseArgs, termArgs...)

	query := fmt.Sprintf(`
        SELECT mapping_id, course_id, subject_id, term_number, is_compulsory, created_at, updated_at
        FROM academics.subject_course_mapping
        WHERE course_id IN (%s) AND term_number IN (%s)
    `, strings.Join(coursePlaceholders, ","), strings.Join(termPlaceholders, ","))

	rows, err := db.QueryContext(ctx, query, allArgs...)
	if err != nil {
		r.logger.Error("failed to list mappings by course IDs and term numbers",
			zap.Any("course_ids", courseIDs),
			zap.Any("term_numbers", termNumbers),
			zap.Error(err))
		return nil, fmt.Errorf("list by course IDs and term numbers: %w", err)
	}
	defer rows.Close()
	return r.scanMappings(rows)
}
