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

// AssignmentRepository defines database operations for assignments.
type AssignmentRepository interface {
	Create(ctx context.Context, db DBTX, a *models.Assignment) error
	BulkCreate(ctx context.Context, db DBTX, assignments []*models.Assignment) error
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Assignment, error)
	GetByIDs(ctx context.Context, db DBTX, ids []uuid.UUID) ([]*models.Assignment, error)
	List(ctx context.Context, db DBTX, filter AssignmentFilter, p Pagination, s Sort) ([]*models.Assignment, error)
	Count(ctx context.Context, db DBTX, filter AssignmentFilter) (int64, error)
	Update(ctx context.Context, db DBTX, a *models.Assignment) error
	Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error
	Publish(ctx context.Context, db DBTX, id uuid.UUID, published bool, updatedBy *uuid.UUID) error
}

type assignmentRepository struct {
	logger *zap.Logger
}

// NewAssignmentRepository creates a new assignment repository.
func NewAssignmentRepository(logger *zap.Logger) AssignmentRepository {
	return &assignmentRepository{
		logger: logger.Named("assignment_repo"),
	}
}

var allowedAssignmentSortFields = map[string]bool{
	"created_at": true,
	"updated_at": true,
	"due_date":   true,
	"title":      true,
}

func (r *assignmentRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "created_at"
	}
	if !allowedAssignmentSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY a.%s %s", field, dir), nil
}

func (r *assignmentRepository) validatePagination(p Pagination) (int, int) {
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

func (r *assignmentRepository) buildAssignmentFilter(filter AssignmentFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.SectionID != nil {
		conditions = append(conditions, fmt.Sprintf("a.section_id = $%d", idx))
		args = append(args, *filter.SectionID)
		idx++
	}
	if filter.SubjectID != nil {
		conditions = append(conditions, fmt.Sprintf("a.subject_id = $%d", idx))
		args = append(args, *filter.SubjectID)
		idx++
	}
	if filter.TeacherID != nil {
		conditions = append(conditions, fmt.Sprintf("a.teacher_id = $%d", idx))
		args = append(args, *filter.TeacherID)
		idx++
	}
	if filter.IsPublished != nil {
		conditions = append(conditions, fmt.Sprintf("a.is_published = $%d", idx))
		args = append(args, *filter.IsPublished)
		idx++
	}
	if filter.DueDateFrom != nil {
		conditions = append(conditions, fmt.Sprintf("a.due_date >= $%d", idx))
		args = append(args, *filter.DueDateFrom)
		idx++
	}
	if filter.DueDateTo != nil {
		conditions = append(conditions, fmt.Sprintf("a.due_date <= $%d", idx))
		args = append(args, *filter.DueDateTo)
		idx++
	}
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(a.title ILIKE $%d OR a.description ILIKE $%d)", idx, idx))
		args = append(args, "%"+filter.Search+"%")
		idx++
	}

	conditions = append(conditions, "a.deleted_at IS NULL")

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

// Create inserts a new assignment.
func (r *assignmentRepository) Create(ctx context.Context, db DBTX, a *models.Assignment) error {
	query := `
        INSERT INTO academics.assignments (
            section_id, subject_id, teacher_id, title, description, due_date,
            max_marks, attachment_url, is_published,
            created_by, updated_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
        RETURNING assignment_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		a.SectionID, a.SubjectID, a.TeacherID, a.Title, a.Description, a.DueDate,
		a.MaxMarks, a.AttachmentURL, a.IsPublished,
		a.CreatedBy, a.UpdatedBy,
	).Scan(&a.AssignmentID, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create assignment",
			util.String("title", a.Title),
			util.ErrorField(err))
		return fmt.Errorf("create assignment: %w", err)
	}
	return nil
}

// GetByID retrieves an assignment by ID.
func (r *assignmentRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Assignment, error) {
	query := `
        SELECT
            assignment_id, section_id, subject_id, teacher_id, title, description,
            due_date, max_marks, attachment_url, is_published,
            created_at, updated_at, created_by, updated_by
        FROM academics.assignments
        WHERE assignment_id = $1 AND deleted_at IS NULL
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanAssignment(row)
}

// GetByIDs retrieves multiple assignments by their IDs.
func (r *assignmentRepository) GetByIDs(ctx context.Context, db DBTX, ids []uuid.UUID) ([]*models.Assignment, error) {
	if len(ids) == 0 {
		return []*models.Assignment{}, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	query := fmt.Sprintf(`
        SELECT
            assignment_id, section_id, subject_id, teacher_id, title, description,
            due_date, max_marks, attachment_url, is_published,
            created_at, updated_at, created_by, updated_by
        FROM academics.assignments
        WHERE assignment_id IN (%s) AND deleted_at IS NULL
    `, strings.Join(placeholders, ","))

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to get assignments by IDs", zap.Error(err))
		return nil, fmt.Errorf("get assignments by IDs: %w", err)
	}
	defer rows.Close()

	var result []*models.Assignment
	for rows.Next() {
		a, err := r.scanAssignment(rows)
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

// List returns assignments matching the filter with pagination and sorting.
func (r *assignmentRepository) List(ctx context.Context, db DBTX, filter AssignmentFilter, p Pagination, s Sort) ([]*models.Assignment, error) {
	where, args := r.buildAssignmentFilter(filter)
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
        SELECT
            assignment_id, section_id, subject_id, teacher_id, title, description,
            due_date, max_marks, attachment_url, is_published,
            created_at, updated_at, created_by, updated_by
        FROM academics.assignments a
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list assignments",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list assignments: %w", err)
	}
	defer rows.Close()

	var result []*models.Assignment
	for rows.Next() {
		a, err := r.scanAssignment(rows)
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

// Count returns the number of assignments matching the filter.
func (r *assignmentRepository) Count(ctx context.Context, db DBTX, filter AssignmentFilter) (int64, error) {
	where, args := r.buildAssignmentFilter(filter)

	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.assignments a %s", where)

	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count assignments",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count assignments: %w", err)
	}
	return count, nil
}

// Update modifies an existing assignment.
func (r *assignmentRepository) Update(ctx context.Context, db DBTX, a *models.Assignment) error {
	query := `
        UPDATE academics.assignments
        SET
            section_id = $2,
            subject_id = $3,
            teacher_id = $4,
            title = $5,
            description = $6,
            due_date = $7,
            max_marks = $8,
            attachment_url = $9,
            is_published = $10,
            updated_by = $11,
            updated_at = NOW()
        WHERE assignment_id = $1 AND deleted_at IS NULL
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		a.AssignmentID,
		a.SectionID, a.SubjectID, a.TeacherID, a.Title, a.Description, a.DueDate,
		a.MaxMarks, a.AttachmentURL, a.IsPublished,
		a.UpdatedBy,
	).Scan(&a.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: assignment %s", ErrNotFound, a.AssignmentID)
		}
		r.logger.Error("failed to update assignment",
			util.String("id", a.AssignmentID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update assignment: %w", err)
	}
	return nil
}

// Delete soft‑deletes an assignment.
func (r *assignmentRepository) Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error {
	query := `UPDATE academics.assignments SET deleted_at = NOW(), updated_by = $2, updated_at = NOW() WHERE assignment_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, deletedBy)
	if err != nil {
		r.logger.Error("failed to delete assignment",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete assignment: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("assignment %s not found or already deleted", id)
	}
	return nil
}

// Publish toggles the published status of an assignment.
func (r *assignmentRepository) Publish(ctx context.Context, db DBTX, id uuid.UUID, published bool, updatedBy *uuid.UUID) error {
	query := `UPDATE academics.assignments SET is_published = $2, updated_by = $3, updated_at = NOW() WHERE assignment_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, published, updatedBy)
	if err != nil {
		r.logger.Error("failed to publish assignment",
			util.String("id", id.String()),
			util.Bool("published", published),
			util.ErrorField(err))
		return fmt.Errorf("publish assignment: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("assignment %s not found or deleted", id)
	}
	return nil
}

// scanAssignment scans a row into an Assignment model.
func (r *assignmentRepository) scanAssignment(row scanner) (*models.Assignment, error) {
	var a models.Assignment
	var maxMarks sql.NullFloat64
	var createdBy, updatedBy uuid.NullUUID

	err := row.Scan(
		&a.AssignmentID,
		&a.SectionID,
		&a.SubjectID,
		&a.TeacherID,
		&a.Title,
		&a.Description,
		&a.DueDate,
		&maxMarks,
		&a.AttachmentURL,
		&a.IsPublished,
		&a.CreatedAt,
		&a.UpdatedAt,
		&createdBy,
		&updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan assignment: %w", err)
	}
	if maxMarks.Valid {
		a.MaxMarks = &maxMarks.Float64
	}
	if createdBy.Valid {
		a.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		a.UpdatedBy = &updatedBy.UUID
	}
	return &a, nil
}
func (r *assignmentRepository) BulkCreate(ctx context.Context, db DBTX, assignments []*models.Assignment) error {
	if len(assignments) == 0 {
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

	// Prepare the statement
	stmt, err := tx.PrepareContext(ctx, `
        INSERT INTO academics.assignments (
            section_id, subject_id, teacher_id, title, description, due_date,
            max_marks, attachment_url, is_published,
            created_by, updated_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
        RETURNING assignment_id, created_at, updated_at
    `)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, a := range assignments {
		err = stmt.QueryRowContext(ctx,
			a.SectionID, a.SubjectID, a.TeacherID, a.Title, a.Description, a.DueDate,
			a.MaxMarks, a.AttachmentURL, a.IsPublished,
			a.CreatedBy, a.UpdatedBy,
		).Scan(&a.AssignmentID, &a.CreatedAt, &a.UpdatedAt)
		if err != nil {
			r.logger.Error("failed to insert assignment in bulk",
				util.String("title", a.Title),
				util.ErrorField(err))
			return fmt.Errorf("bulk insert assignment: %w", err)
		}
	}

	if isOwner {
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit tx: %w", err)
		}
		needRollback = false
	}

	r.logger.Info("bulk inserted assignments", zap.Int("count", len(assignments)))
	return nil
}
