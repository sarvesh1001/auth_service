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

// SectionRepository defines methods for section table.
type SectionRepository interface {
	Create(ctx context.Context, db DBTX, e *models.Section) error
	BulkCreate(ctx context.Context, db DBTX, e []*models.Section) error
	Upsert(ctx context.Context, db DBTX, e *models.Section) error
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Section, error)
	List(ctx context.Context, db DBTX, filter SectionFilter, p Pagination, s Sort) ([]*models.Section, error)
	ListByCourse(ctx context.Context, db DBTX, courseID uuid.UUID) ([]*models.Section, error)
	ListByTerm(ctx context.Context, db DBTX, termID uuid.UUID) ([]*models.Section, error)
	Count(ctx context.Context, db DBTX, filter SectionFilter) (int64, error)
	Exists(ctx context.Context, db DBTX, courseID, termID uuid.UUID, name string) (bool, error)
	Update(ctx context.Context, db DBTX, e *models.Section) error
	UpdateCapacity(ctx context.Context, db DBTX, sectionID uuid.UUID, capacity int, updatedBy *uuid.UUID) error
	Activate(ctx context.Context, db DBTX, id uuid.UUID, updatedBy *uuid.UUID) error
	Deactivate(ctx context.Context, db DBTX, id uuid.UUID, updatedBy *uuid.UUID) error
	GetByIDForUpdate(ctx context.Context, db DBTX, id uuid.UUID) (*models.Section, error)
	Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error
}

type sectionRepository struct {
	logger *zap.Logger
}

// NewSectionRepository creates a new section repository.
func NewSectionRepository(logger *zap.Logger) SectionRepository {
	return &sectionRepository{
		logger: logger.Named("section_repo"),
	}
}

// Allowed sort fields for sections
var allowedSectionSortFields = map[string]bool{
	"created_at": true,
	"name":       true,
	"capacity":   true,
	"is_active":  true,
}

func (r *sectionRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "created_at"
	}
	if !allowedSectionSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}

	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}

	return fmt.Sprintf("ORDER BY %s %s", field, dir), nil
}

func (r *sectionRepository) validatePagination(p Pagination) (int, int) {
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

// Create inserts a new section.
func (r *sectionRepository) Create(ctx context.Context, db DBTX, e *models.Section) error {
	query := `
		INSERT INTO academics.section (
			course_id, term_id, name, capacity, is_active,
			created_by, updated_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
		RETURNING section_id, created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		e.CourseID, e.TermID, e.Name, e.Capacity, e.IsActive,
		e.CreatedBy, e.UpdatedBy,
	).Scan(&e.SectionID, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create section",
			util.String("course_id", e.CourseID.String()),
			util.String("term_id", e.TermID.String()),
			util.String("name", e.Name),
			util.ErrorField(err))
		return fmt.Errorf("create section: %w", err)
	}
	return nil
}

// BulkCreate inserts multiple sections with proper transaction handling.
func (r *sectionRepository) BulkCreate(ctx context.Context, db DBTX, e []*models.Section) error {
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
		INSERT INTO academics.section (
			course_id, term_id, name, capacity, is_active,
			created_by, updated_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
		RETURNING section_id, created_at, updated_at
	`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, s := range e {
		err = stmt.QueryRowContext(ctx,
			s.CourseID, s.TermID, s.Name, s.Capacity, s.IsActive,
			s.CreatedBy, s.UpdatedBy,
		).Scan(&s.SectionID, &s.CreatedAt, &s.UpdatedAt)
		if err != nil {
			r.logger.Error("bulk create section failed",
				util.String("course_id", s.CourseID.String()),
				util.String("term_id", s.TermID.String()),
				util.String("name", s.Name),
				util.ErrorField(err))
			return fmt.Errorf("bulk create section row: %w", err)
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

// Upsert inserts or updates using the unique constraint (enterprise pattern).
func (r *sectionRepository) Upsert(ctx context.Context, db DBTX, e *models.Section) error {
	query := `
        INSERT INTO academics.section (
            course_id, term_id, name, capacity, is_active,
            created_by, updated_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
        ON CONFLICT (course_id, term_id, name) WHERE deleted_at IS NULL
        DO UPDATE SET
            capacity = EXCLUDED.capacity,
            is_active = EXCLUDED.is_active,
            updated_by = EXCLUDED.updated_by,
            updated_at = NOW()
        RETURNING section_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		e.CourseID, e.TermID, e.Name, e.Capacity, e.IsActive,
		e.CreatedBy, e.UpdatedBy,
	).Scan(&e.SectionID, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to upsert section",
			zap.String("course_id", e.CourseID.String()),
			zap.String("term_id", e.TermID.String()),
			zap.String("name", e.Name),
			zap.Error(err))
		return fmt.Errorf("upsert section: %w", err)
	}
	return nil
}

// GetByID retrieves a section by its ID (only if not deleted).
func (r *sectionRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Section, error) {
	query := `
		SELECT section_id, course_id, term_id, name, capacity,
		       is_active, created_at, updated_at, created_by, updated_by
		FROM academics.section
		WHERE section_id = $1 AND deleted_at IS NULL
	`
	var s models.Section
	var capacity sql.NullInt64
	var createdBy, updatedBy uuid.NullUUID
	err := db.QueryRowContext(ctx, query, id).Scan(
		&s.SectionID, &s.CourseID, &s.TermID, &s.Name, &capacity,
		&s.IsActive, &s.CreatedAt, &s.UpdatedAt, &createdBy, &updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get section by ID",
			util.String("id", id.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get section by ID: %w", err)
	}
	if capacity.Valid {
		s.Capacity = int(capacity.Int64)
	}
	if createdBy.Valid {
		s.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		s.UpdatedBy = &updatedBy.UUID
	}
	return &s, nil
}

// List returns sections matching the filter with pagination and sorting (only non-deleted).
func (r *sectionRepository) List(ctx context.Context, db DBTX, filter SectionFilter, p Pagination, s Sort) ([]*models.Section, error) {
	where, args := r.buildSectionFilter(filter)
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	// Fix WHERE clause: ensure deleted_at IS NULL is always present
	if where == "" {
		where = "WHERE deleted_at IS NULL"
	} else {
		where += " AND deleted_at IS NULL"
	}

	query := fmt.Sprintf(`
		SELECT section_id, course_id, term_id, name, capacity,
		       is_active, created_at, updated_at, created_by, updated_by
		FROM academics.section
		%s %s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list sections",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list sections: %w", err)
	}
	defer rows.Close()

	var result []*models.Section
	for rows.Next() {
		var s models.Section
		var capacity sql.NullInt64
		var createdBy, updatedBy uuid.NullUUID
		if err := rows.Scan(
			&s.SectionID, &s.CourseID, &s.TermID, &s.Name, &capacity,
			&s.IsActive, &s.CreatedAt, &s.UpdatedAt, &createdBy, &updatedBy,
		); err != nil {
			return nil, fmt.Errorf("scan section: %w", err)
		}
		if capacity.Valid {
			s.Capacity = int(capacity.Int64)
		}
		if createdBy.Valid {
			s.CreatedBy = &createdBy.UUID
		}
		if updatedBy.Valid {
			s.UpdatedBy = &updatedBy.UUID
		}
		result = append(result, &s)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// ListByCourse returns all sections for a given course.
func (r *sectionRepository) ListByCourse(ctx context.Context, db DBTX, courseID uuid.UUID) ([]*models.Section, error) {
	return r.List(ctx, db, SectionFilter{
		CourseIDs: []uuid.UUID{courseID}, // updated to slice
	}, Pagination{Limit: 1000}, Sort{Field: "name", Direction: "ASC"})
}

// ListByTerm returns all sections for a given term.
func (r *sectionRepository) ListByTerm(ctx context.Context, db DBTX, termID uuid.UUID) ([]*models.Section, error) {
	return r.List(ctx, db, SectionFilter{
		TermIDs: []uuid.UUID{termID}, // updated to slice
	}, Pagination{Limit: 1000}, Sort{Field: "name", Direction: "ASC"})
}

// Count returns the number of sections matching the filter (only non-deleted).
func (r *sectionRepository) Count(ctx context.Context, db DBTX, filter SectionFilter) (int64, error) {
	where, args := r.buildSectionFilter(filter)

	// Fix WHERE clause: ensure deleted_at IS NULL is always present
	if where == "" {
		where = "WHERE deleted_at IS NULL"
	} else {
		where += " AND deleted_at IS NULL"
	}

	query := fmt.Sprintf(`SELECT COUNT(*) FROM academics.section %s`, where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count sections",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count sections: %w", err)
	}
	return count, nil
}

// Exists checks if an active (non-deleted) section with given course, term, and name exists.
func (r *sectionRepository) Exists(ctx context.Context, db DBTX, courseID, termID uuid.UUID, name string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM academics.section WHERE course_id = $1 AND term_id = $2 AND name = $3 AND deleted_at IS NULL)`
	var exists bool
	err := db.QueryRowContext(ctx, query, courseID, termID, name).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check section existence",
			util.String("course_id", courseID.String()),
			util.String("term_id", termID.String()),
			util.String("name", name),
			util.ErrorField(err))
		return false, fmt.Errorf("exists section: %w", err)
	}
	return exists, nil
}

// Update modifies an existing section (only if not deleted).
func (r *sectionRepository) Update(ctx context.Context, db DBTX, e *models.Section) error {
	query := `
		UPDATE academics.section
		SET name = $2, capacity = $3, is_active = $4, updated_by = $5, updated_at = NOW()
		WHERE section_id = $1 AND deleted_at IS NULL
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		e.SectionID, e.Name, e.Capacity, e.IsActive, e.UpdatedBy,
	).Scan(&e.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("section %s not found or deleted", e.SectionID)
		}
		r.logger.Error("failed to update section",
			util.String("id", e.SectionID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update section: %w", err)
	}
	return nil
}

// UpdateCapacity updates only the capacity of a section (only if not deleted).
func (r *sectionRepository) UpdateCapacity(ctx context.Context, db DBTX, sectionID uuid.UUID, capacity int, updatedBy *uuid.UUID) error {
	query := `UPDATE academics.section SET capacity = $2, updated_by = $3, updated_at = NOW() WHERE section_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, sectionID, capacity, updatedBy)
	if err != nil {
		r.logger.Error("failed to update section capacity",
			util.String("section_id", sectionID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update capacity: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("section %s not found or deleted", sectionID)
	}
	return nil
}

// Activate sets is_active to true (only if not deleted).
func (r *sectionRepository) Activate(ctx context.Context, db DBTX, id uuid.UUID, updatedBy *uuid.UUID) error {
	query := `UPDATE academics.section SET is_active = true, updated_by = $2, updated_at = NOW() WHERE section_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, updatedBy)
	if err != nil {
		r.logger.Error("failed to activate section",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("activate section: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("section %s not found or deleted", id)
	}
	return nil
}

// Deactivate sets is_active to false (only if not deleted).
func (r *sectionRepository) Deactivate(ctx context.Context, db DBTX, id uuid.UUID, updatedBy *uuid.UUID) error {
	query := `UPDATE academics.section SET is_active = false, updated_by = $2, updated_at = NOW() WHERE section_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, updatedBy)
	if err != nil {
		r.logger.Error("failed to deactivate section",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("deactivate section: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("section %s not found or deleted", id)
	}
	return nil
}

// GetByIDForUpdate retrieves a section with row lock (only if not deleted).
func (r *sectionRepository) GetByIDForUpdate(ctx context.Context, db DBTX, id uuid.UUID) (*models.Section, error) {
	query := `
		SELECT section_id, course_id, term_id, name, capacity,
		       is_active, created_at, updated_at, created_by, updated_by
		FROM academics.section
		WHERE section_id = $1 AND deleted_at IS NULL
		FOR UPDATE
	`
	var s models.Section
	var capacity sql.NullInt64
	var createdBy, updatedBy uuid.NullUUID
	err := db.QueryRowContext(ctx, query, id).Scan(
		&s.SectionID, &s.CourseID, &s.TermID, &s.Name, &capacity,
		&s.IsActive, &s.CreatedAt, &s.UpdatedAt, &createdBy, &updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get section for update",
			util.String("id", id.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get section for update: %w", err)
	}
	if capacity.Valid {
		s.Capacity = int(capacity.Int64)
	}
	if createdBy.Valid {
		s.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		s.UpdatedBy = &updatedBy.UUID
	}
	return &s, nil
}

// Delete soft-deletes a section.
func (r *sectionRepository) Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error {
	query := `UPDATE academics.section SET deleted_at = NOW(), updated_by = $2, updated_at = NOW() WHERE section_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, deletedBy)
	if err != nil {
		r.logger.Error("failed to delete section",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete section: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("section %s not found or already deleted", id)
	}
	return nil
}

// buildSectionFilter constructs WHERE clause and arguments for SectionFilter.
// Note: Does NOT include deleted_at; caller must add that.
func (r *sectionRepository) buildSectionFilter(filter SectionFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	// Handle multiple course IDs
	if len(filter.CourseIDs) > 0 {
		placeholders := make([]string, len(filter.CourseIDs))
		for i, id := range filter.CourseIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conditions = append(conditions, fmt.Sprintf("course_id IN (%s)", strings.Join(placeholders, ",")))
	}

	// Handle multiple term IDs
	if len(filter.TermIDs) > 0 {
		placeholders := make([]string, len(filter.TermIDs))
		for i, id := range filter.TermIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conditions = append(conditions, fmt.Sprintf("term_id IN (%s)", strings.Join(placeholders, ",")))
	}

	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("name ILIKE $%d", idx))
		args = append(args, "%"+filter.Search+"%")
		idx++
	}
	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}
