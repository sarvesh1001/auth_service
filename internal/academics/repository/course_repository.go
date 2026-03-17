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

// CourseRepository defines methods for course table.
type CourseRepository interface {
	Create(ctx context.Context, e *models.Course) error
	BulkCreate(ctx context.Context, e []*models.Course) error
	Upsert(ctx context.Context, e *models.Course) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Course, error)
	GetByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.Course, error)
	List(ctx context.Context, filter CourseFilter, p Pagination, s Sort) ([]*models.Course, error)
	ListActive(ctx context.Context, companyID uuid.UUID) ([]*models.Course, error)
	Count(ctx context.Context, filter CourseFilter) (int64, error)
	Exists(ctx context.Context, companyID uuid.UUID, code string) (bool, error)
	Update(ctx context.Context, e *models.Course) error
	Activate(ctx context.Context, id uuid.UUID) error
	Deactivate(ctx context.Context, id uuid.UUID) error
	GetByIDForUpdate(ctx context.Context, id uuid.UUID) (*models.Course, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

type courseRepository struct {
	db     *client.PostgresClient
	logger *zap.Logger
}

// NewCourseRepository creates a new course repository.
func NewCourseRepository(db *client.PostgresClient, logger *zap.Logger) CourseRepository {
	return &courseRepository{
		db:     db,
		logger: logger.Named("course_repo"),
	}
}

// Create inserts a new course.
func (r *courseRepository) Create(ctx context.Context, e *models.Course) error {
	query := `
		INSERT INTO academics.course (
			company_id, code, name, description, credits, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
		RETURNING course_id, created_at, updated_at
	`
	err := r.db.QueryRow(ctx, query,
		e.CompanyID, e.Code, e.Name, e.Description, e.Credits, e.IsActive,
	).Scan(&e.CourseID, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create course",
			util.String("company_id", e.CompanyID.String()),
			util.String("code", e.Code),
			util.ErrorField(err))
		return fmt.Errorf("create course: %w", err)
	}
	return nil
}

// BulkCreate inserts multiple courses.
func (r *courseRepository) BulkCreate(ctx context.Context, e []*models.Course) error {
	if len(e) == 0 {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO academics.course (
			company_id, code, name, description, credits, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
		RETURNING course_id, created_at, updated_at
	`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, c := range e {
		err = stmt.QueryRowContext(ctx,
			c.CompanyID, c.Code, c.Name, c.Description, c.Credits, c.IsActive,
		).Scan(&c.CourseID, &c.CreatedAt, &c.UpdatedAt)
		if err != nil {
			r.logger.Error("bulk create course failed",
				util.String("company_id", c.CompanyID.String()),
				util.String("code", c.Code),
				util.ErrorField(err))
			return fmt.Errorf("bulk create course row: %w", err)
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// Upsert inserts or updates on conflict (company_id, code).
func (r *courseRepository) Upsert(ctx context.Context, e *models.Course) error {
	query := `
		INSERT INTO academics.course (
			company_id, code, name, description, credits, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
		ON CONFLICT (company_id, code) DO UPDATE SET
			name = EXCLUDED.name,
			description = EXCLUDED.description,
			credits = EXCLUDED.credits,
			is_active = EXCLUDED.is_active,
			updated_at = NOW()
		RETURNING course_id, created_at, updated_at
	`
	err := r.db.QueryRow(ctx, query,
		e.CompanyID, e.Code, e.Name, e.Description, e.Credits, e.IsActive,
	).Scan(&e.CourseID, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to upsert course",
			util.String("company_id", e.CompanyID.String()),
			util.String("code", e.Code),
			util.ErrorField(err))
		return fmt.Errorf("upsert course: %w", err)
	}
	return nil
}

// GetByID retrieves a course by its ID.
func (r *courseRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Course, error) {
	query := `
		SELECT course_id, company_id, code, name, description, credits, is_active, created_at, updated_at
		FROM academics.course
		WHERE course_id = $1
	`
	var c models.Course
	var description sql.NullString
	var credits sql.NullInt64
	err := r.db.QueryRow(ctx, query, id).Scan(
		&c.CourseID, &c.CompanyID, &c.Code, &c.Name, &description, &credits,
		&c.IsActive, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get course by ID",
			util.String("id", id.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get course by ID: %w", err)
	}
	if description.Valid {
		c.Description = description.String
	}
	if credits.Valid {
		c.Credits = int(credits.Int64)
	}
	return &c, nil
}

// GetByCode retrieves a course by company and code.
func (r *courseRepository) GetByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.Course, error) {
	query := `
		SELECT course_id, company_id, code, name, description, credits, is_active, created_at, updated_at
		FROM academics.course
		WHERE company_id = $1 AND code = $2
	`
	var c models.Course
	var description sql.NullString
	var credits sql.NullInt64
	err := r.db.QueryRow(ctx, query, companyID, code).Scan(
		&c.CourseID, &c.CompanyID, &c.Code, &c.Name, &description, &credits,
		&c.IsActive, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get course by code",
			util.String("company_id", companyID.String()),
			util.String("code", code),
			util.ErrorField(err))
		return nil, fmt.Errorf("get course by code: %w", err)
	}
	if description.Valid {
		c.Description = description.String
	}
	if credits.Valid {
		c.Credits = int(credits.Int64)
	}
	return &c, nil
}

// List returns courses matching the filter with pagination and sorting.
func (r *courseRepository) List(ctx context.Context, filter CourseFilter, p Pagination, s Sort) ([]*models.Course, error) {
	where, args := r.buildCourseFilter(filter)
	orderBy := "ORDER BY " + s.Field + " " + s.Direction
	if s.Field == "" {
		orderBy = "ORDER BY created_at DESC"
	}
	query := fmt.Sprintf(`
		SELECT course_id, company_id, code, name, description, credits, is_active, created_at, updated_at
		FROM academics.course
		%s %s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, p.Limit, p.Offset)
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list courses",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list courses: %w", err)
	}
	defer rows.Close()

	var result []*models.Course
	for rows.Next() {
		var c models.Course
		var description sql.NullString
		var credits sql.NullInt64
		if err := rows.Scan(
			&c.CourseID, &c.CompanyID, &c.Code, &c.Name, &description, &credits,
			&c.IsActive, &c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan course: %w", err)
		}
		if description.Valid {
			c.Description = description.String
		}
		if credits.Valid {
			c.Credits = int(credits.Int64)
		}
		result = append(result, &c)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// ListActive returns all active courses for a company.
func (r *courseRepository) ListActive(ctx context.Context, companyID uuid.UUID) ([]*models.Course, error) {
	active := true
	return r.List(ctx, CourseFilter{CompanyID: companyID, IsActive: &active}, Pagination{Limit: 1000}, Sort{Field: "name", Direction: "ASC"})
}

// Count returns the number of courses matching the filter.
func (r *courseRepository) Count(ctx context.Context, filter CourseFilter) (int64, error) {
	where, args := r.buildCourseFilter(filter)
	query := fmt.Sprintf(`SELECT COUNT(*) FROM academics.course %s`, where)
	var count int64
	err := r.db.QueryRow(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count courses",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count courses: %w", err)
	}
	return count, nil
}

// Exists checks if a course with given company and code exists.
func (r *courseRepository) Exists(ctx context.Context, companyID uuid.UUID, code string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM academics.course WHERE company_id = $1 AND code = $2)`
	var exists bool
	err := r.db.QueryRow(ctx, query, companyID, code).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check course existence",
			util.String("company_id", companyID.String()),
			util.String("code", code),
			util.ErrorField(err))
		return false, fmt.Errorf("exists course: %w", err)
	}
	return exists, nil
}

// Update modifies an existing course.
func (r *courseRepository) Update(ctx context.Context, e *models.Course) error {
	query := `
		UPDATE academics.course
		SET code = $2, name = $3, description = $4, credits = $5, is_active = $6, updated_at = NOW()
		WHERE course_id = $1
		RETURNING updated_at
	`
	err := r.db.QueryRow(ctx, query,
		e.CourseID, e.Code, e.Name, e.Description, e.Credits, e.IsActive,
	).Scan(&e.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to update course",
			util.String("id", e.CourseID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update course: %w", err)
	}
	return nil
}

// Activate sets is_active to true.
func (r *courseRepository) Activate(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE academics.course SET is_active = true, updated_at = NOW() WHERE course_id = $1`
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to activate course",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("activate course: %w", err)
	}
	return nil
}

// Deactivate sets is_active to false.
func (r *courseRepository) Deactivate(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE academics.course SET is_active = false, updated_at = NOW() WHERE course_id = $1`
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to deactivate course",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("deactivate course: %w", err)
	}
	return nil
}

// GetByIDForUpdate retrieves a course with row lock.
func (r *courseRepository) GetByIDForUpdate(ctx context.Context, id uuid.UUID) (*models.Course, error) {
	query := `
		SELECT course_id, company_id, code, name, description, credits, is_active, created_at, updated_at
		FROM academics.course
		WHERE course_id = $1
		FOR UPDATE
	`
	var c models.Course
	var description sql.NullString
	var credits sql.NullInt64
	err := r.db.QueryRow(ctx, query, id).Scan(
		&c.CourseID, &c.CompanyID, &c.Code, &c.Name, &description, &credits,
		&c.IsActive, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get course for update",
			util.String("id", id.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get course for update: %w", err)
	}
	if description.Valid {
		c.Description = description.String
	}
	if credits.Valid {
		c.Credits = int(credits.Int64)
	}
	return &c, nil
}

// Delete removes a course.
func (r *courseRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM academics.course WHERE course_id = $1`
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete course",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete course: %w", err)
	}
	return nil
}

// buildCourseFilter constructs WHERE clause and arguments for CourseFilter.
func (r *courseRepository) buildCourseFilter(filter CourseFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}
	if filter.Code != "" {
		conditions = append(conditions, fmt.Sprintf("code = $%d", idx))
		args = append(args, filter.Code)
		idx++
	}
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR code ILIKE $%d)", idx, idx))
		args = append(args, "%"+filter.Search+"%")
		idx++
	}
	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}
