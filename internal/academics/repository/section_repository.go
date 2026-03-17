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
	"auth-service/internal/client"
	"auth-service/internal/util"
)

// SectionRepository defines methods for section table.
type SectionRepository interface {
	Create(ctx context.Context, e *models.Section) error
	BulkCreate(ctx context.Context, e []*models.Section) error
	Upsert(ctx context.Context, e *models.Section) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Section, error)
	List(ctx context.Context, filter SectionFilter, p Pagination, s Sort) ([]*models.Section, error)
	ListByCourse(ctx context.Context, courseID uuid.UUID) ([]*models.Section, error)
	ListByTerm(ctx context.Context, termID uuid.UUID) ([]*models.Section, error)
	Count(ctx context.Context, filter SectionFilter) (int64, error)
	Exists(ctx context.Context, courseID, termID uuid.UUID, name string) (bool, error)
	Update(ctx context.Context, e *models.Section) error
	UpdateCapacity(ctx context.Context, sectionID uuid.UUID, capacity int) error
	Activate(ctx context.Context, id uuid.UUID) error
	Deactivate(ctx context.Context, id uuid.UUID) error
	GetByIDForUpdate(ctx context.Context, id uuid.UUID) (*models.Section, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

type sectionRepository struct {
	db     *client.PostgresClient
	logger *zap.Logger
}

// NewSectionRepository creates a new section repository.
func NewSectionRepository(db *client.PostgresClient, logger *zap.Logger) SectionRepository {
	return &sectionRepository{
		db:     db,
		logger: logger.Named("section_repo"),
	}
}

// Create inserts a new section.
func (r *sectionRepository) Create(ctx context.Context, e *models.Section) error {
	query := `
		INSERT INTO academics.section (
			course_id, term_id, name, capacity, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
		RETURNING section_id, created_at, updated_at
	`
	err := r.db.QueryRow(ctx, query,
		e.CourseID, e.TermID, e.Name, e.Capacity, e.IsActive,
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

// BulkCreate inserts multiple sections.
func (r *sectionRepository) BulkCreate(ctx context.Context, e []*models.Section) error {
	if len(e) == 0 {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO academics.section (
			course_id, term_id, name, capacity, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
		RETURNING section_id, created_at, updated_at
	`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, s := range e {
		err = stmt.QueryRowContext(ctx,
			s.CourseID, s.TermID, s.Name, s.Capacity, s.IsActive,
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
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// Upsert inserts or updates on conflict (course_id, term_id, name).
func (r *sectionRepository) Upsert(ctx context.Context, e *models.Section) error {
	query := `
		INSERT INTO academics.section (
			course_id, term_id, name, capacity, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
		ON CONFLICT (course_id, term_id, name) DO UPDATE SET
			capacity = EXCLUDED.capacity,
			is_active = EXCLUDED.is_active,
			updated_at = NOW()
		RETURNING section_id, created_at, updated_at
	`
	err := r.db.QueryRow(ctx, query,
		e.CourseID, e.TermID, e.Name, e.Capacity, e.IsActive,
	).Scan(&e.SectionID, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to upsert section",
			util.String("course_id", e.CourseID.String()),
			util.String("term_id", e.TermID.String()),
			util.String("name", e.Name),
			util.ErrorField(err))
		return fmt.Errorf("upsert section: %w", err)
	}
	return nil
}

// GetByID retrieves a section by its ID.
func (r *sectionRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Section, error) {
	query := `
		SELECT section_id, course_id, term_id, name, capacity, is_active, created_at, updated_at
		FROM academics.section
		WHERE section_id = $1
	`
	var s models.Section
	var capacity sql.NullInt64
	err := r.db.QueryRow(ctx, query, id).Scan(
		&s.SectionID, &s.CourseID, &s.TermID, &s.Name, &capacity,
		&s.IsActive, &s.CreatedAt, &s.UpdatedAt,
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
	return &s, nil
}

// List returns sections matching the filter with pagination and sorting.
func (r *sectionRepository) List(ctx context.Context, filter SectionFilter, p Pagination, s Sort) ([]*models.Section, error) {
	where, args := r.buildSectionFilter(filter)
	orderBy := "ORDER BY " + s.Field + " " + s.Direction
	if s.Field == "" {
		orderBy = "ORDER BY created_at DESC"
	}
	query := fmt.Sprintf(`
		SELECT section_id, course_id, term_id, name, capacity, is_active, created_at, updated_at
		FROM academics.section
		%s %s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, p.Limit, p.Offset)
	rows, err := r.db.Query(ctx, query, args...)
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
		if err := rows.Scan(
			&s.SectionID, &s.CourseID, &s.TermID, &s.Name, &capacity,
			&s.IsActive, &s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan section: %w", err)
		}
		if capacity.Valid {
			s.Capacity = int(capacity.Int64)
		}
		result = append(result, &s)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// ListByCourse returns all sections for a given course.
func (r *sectionRepository) ListByCourse(ctx context.Context, courseID uuid.UUID) ([]*models.Section, error) {
	return r.List(ctx, SectionFilter{CourseID: courseID}, Pagination{Limit: 1000}, Sort{Field: "name", Direction: "ASC"})
}

// ListByTerm returns all sections for a given term.
func (r *sectionRepository) ListByTerm(ctx context.Context, termID uuid.UUID) ([]*models.Section, error) {
	return r.List(ctx, SectionFilter{TermID: termID}, Pagination{Limit: 1000}, Sort{Field: "name", Direction: "ASC"})
}

// Count returns the number of sections matching the filter.
func (r *sectionRepository) Count(ctx context.Context, filter SectionFilter) (int64, error) {
	where, args := r.buildSectionFilter(filter)
	query := fmt.Sprintf(`SELECT COUNT(*) FROM academics.section %s`, where)
	var count int64
	err := r.db.QueryRow(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count sections",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count sections: %w", err)
	}
	return count, nil
}

// Exists checks if a section with given course, term, and name exists.
func (r *sectionRepository) Exists(ctx context.Context, courseID, termID uuid.UUID, name string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM academics.section WHERE course_id = $1 AND term_id = $2 AND name = $3)`
	var exists bool
	err := r.db.QueryRow(ctx, query, courseID, termID, name).Scan(&exists)
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

// Update modifies an existing section.
func (r *sectionRepository) Update(ctx context.Context, e *models.Section) error {
	query := `
		UPDATE academics.section
		SET name = $2, capacity = $3, is_active = $4, updated_at = NOW()
		WHERE section_id = $1
		RETURNING updated_at
	`
	err := r.db.QueryRow(ctx, query,
		e.SectionID, e.Name, e.Capacity, e.IsActive,
	).Scan(&e.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to update section",
			util.String("id", e.SectionID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update section: %w", err)
	}
	return nil
}

// UpdateCapacity updates only the capacity of a section.
func (r *sectionRepository) UpdateCapacity(ctx context.Context, sectionID uuid.UUID, capacity int) error {
	query := `UPDATE academics.section SET capacity = $2, updated_at = NOW() WHERE section_id = $1`
	_, err := r.db.Exec(ctx, query, sectionID, capacity)
	if err != nil {
		r.logger.Error("failed to update section capacity",
			util.String("section_id", sectionID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update capacity: %w", err)
	}
	return nil
}

// Activate sets is_active to true.
func (r *sectionRepository) Activate(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE academics.section SET is_active = true, updated_at = NOW() WHERE section_id = $1`
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to activate section",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("activate section: %w", err)
	}
	return nil
}

// Deactivate sets is_active to false.
func (r *sectionRepository) Deactivate(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE academics.section SET is_active = false, updated_at = NOW() WHERE section_id = $1`
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to deactivate section",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("deactivate section: %w", err)
	}
	return nil
}

// GetByIDForUpdate retrieves a section with row lock.
func (r *sectionRepository) GetByIDForUpdate(ctx context.Context, id uuid.UUID) (*models.Section, error) {
	query := `
		SELECT section_id, course_id, term_id, name, capacity, is_active, created_at, updated_at
		FROM academics.section
		WHERE section_id = $1
		FOR UPDATE
	`
	var s models.Section
	var capacity sql.NullInt64
	err := r.db.QueryRow(ctx, query, id).Scan(
		&s.SectionID, &s.CourseID, &s.TermID, &s.Name, &capacity,
		&s.IsActive, &s.CreatedAt, &s.UpdatedAt,
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
	return &s, nil
}

// Delete removes a section.
func (r *sectionRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM academics.section WHERE section_id = $1`
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete section",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete section: %w", err)
	}
	return nil
}

// buildSectionFilter constructs WHERE clause and arguments for SectionFilter.
func (r *sectionRepository) buildSectionFilter(filter SectionFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CourseID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("course_id = $%d", idx))
		args = append(args, filter.CourseID)
		idx++
	}
	if filter.TermID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("term_id = $%d", idx))
		args = append(args, filter.TermID)
		idx++
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
