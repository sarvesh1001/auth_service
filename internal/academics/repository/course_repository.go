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

// DBTX is the interface that both *sql.DB and *sql.Tx satisfy.
// It is assumed to be defined elsewhere (e.g., in a common internal package).
type DBTX interface {
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
}

// CourseRepository defines methods for course table.
type CourseRepository interface {
	GetByIDs(ctx context.Context, db DBTX, ids []uuid.UUID) (map[uuid.UUID]*models.Course, error)
	Create(ctx context.Context, db DBTX, e *models.Course) error
	BulkCreate(ctx context.Context, db DBTX, e []*models.Course) error
	Upsert(ctx context.Context, db DBTX, e *models.Course) error
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Course, error)
	GetByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (*models.Course, error)
	List(ctx context.Context, db DBTX, filter CourseFilter, p Pagination, s Sort) ([]*models.Course, error)
	ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Course, error)
	Count(ctx context.Context, db DBTX, filter CourseFilter) (int64, error)
	Exists(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (bool, error)
	Update(ctx context.Context, db DBTX, e *models.Course) error
	Activate(ctx context.Context, db DBTX, id uuid.UUID, updatedBy *uuid.UUID) error
	Deactivate(ctx context.Context, db DBTX, id uuid.UUID, updatedBy *uuid.UUID) error
	GetByIDForUpdate(ctx context.Context, db DBTX, id uuid.UUID) (*models.Course, error)
	Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error
	ListByCompanyAndCodes(ctx context.Context, db DBTX, keys []struct {
		CompanyID uuid.UUID
		Code      string
	}) ([]*models.Course, error)
}

type courseRepository struct {
	logger *zap.Logger
}

// NewCourseRepository creates a new course repository.
func NewCourseRepository(logger *zap.Logger) CourseRepository {
	return &courseRepository{
		logger: logger.Named("course_repo"),
	}
}

// --- helper methods for sorting and pagination ---

var allowedCourseSortFields = map[string]bool{
	"created_at": true,
	"name":       true,
	"code":       true,
	"credits":    true,
	"is_active":  true,
	"company_id": true,
}

func (r *courseRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "created_at"
	}
	if !allowedCourseSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}

	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}

	return fmt.Sprintf("ORDER BY %s %s", field, dir), nil
}

func (r *courseRepository) validatePagination(p Pagination) (int, int) {
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

// --- filter builder (without deleted_at) ---

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

// --- repository methods ---

// Create inserts a new course.
func (r *courseRepository) Create(ctx context.Context, db DBTX, e *models.Course) error {
	query := `
		INSERT INTO academics.course (
			company_id, code, name, description, credits, is_active,
			created_by, updated_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
		RETURNING course_id, created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		e.CompanyID, e.Code, e.Name, e.Description, e.Credits, e.IsActive,
		e.CreatedBy, e.UpdatedBy,
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
// db must be a transaction (service manages it).
func (r *courseRepository) BulkCreate(ctx context.Context, db DBTX, e []*models.Course) error {
	if len(e) == 0 {
		return nil
	}

	stmt, err := db.PrepareContext(ctx, `
		INSERT INTO academics.course (
			company_id, code, name, description, credits, is_active,
			created_by, updated_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
		RETURNING course_id, created_at, updated_at
	`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, c := range e {
		err = stmt.QueryRowContext(ctx,
			c.CompanyID, c.Code, c.Name, c.Description, c.Credits, c.IsActive,
			c.CreatedBy, c.UpdatedBy,
		).Scan(&c.CourseID, &c.CreatedAt, &c.UpdatedAt)
		if err != nil {
			r.logger.Error("bulk create course failed",
				util.String("company_id", c.CompanyID.String()),
				util.String("code", c.Code),
				util.ErrorField(err))
			return fmt.Errorf("bulk create course row: %w", err)
		}
	}
	return nil
}

// Upsert inserts or updates on conflict (company_id, code) where deleted_at IS NULL.
// Assumes a partial unique index exists: UNIQUE (company_id, code) WHERE deleted_at IS NULL.
func (r *courseRepository) Upsert(ctx context.Context, db DBTX, e *models.Course) error {
	query := `
        INSERT INTO academics.course (
            company_id, code, name, description, credits, is_active,
            created_by, updated_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
        ON CONFLICT (company_id, code) WHERE deleted_at IS NULL
        DO UPDATE SET
            name = EXCLUDED.name,
            description = EXCLUDED.description,
            credits = EXCLUDED.credits,
            is_active = EXCLUDED.is_active,
            updated_by = EXCLUDED.updated_by,
            updated_at = NOW()
        RETURNING course_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		e.CompanyID, e.Code, e.Name, e.Description, e.Credits, e.IsActive,
		e.CreatedBy, e.UpdatedBy,
	).Scan(&e.CourseID, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to upsert course",
			zap.String("company_id", e.CompanyID.String()),
			zap.String("code", e.Code),
			zap.Error(err))
		return fmt.Errorf("upsert course: %w", err)
	}
	return nil
}

// GetByID retrieves a course by its ID (only if not deleted).
func (r *courseRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Course, error) {
	query := `
		SELECT course_id, company_id, code, name, description, credits,
		       is_active, created_at, updated_at, created_by, updated_by
		FROM academics.course
		WHERE course_id = $1 AND deleted_at IS NULL
	`
	var c models.Course
	var description sql.NullString
	var credits sql.NullInt64
	var createdBy, updatedBy uuid.NullUUID
	err := db.QueryRowContext(ctx, query, id).Scan(
		&c.CourseID, &c.CompanyID, &c.Code, &c.Name, &description, &credits,
		&c.IsActive, &c.CreatedAt, &c.UpdatedAt, &createdBy, &updatedBy,
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
	if createdBy.Valid {
		c.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		c.UpdatedBy = &updatedBy.UUID
	}
	return &c, nil
}

// GetByCode retrieves a course by company and code (only if not deleted).
func (r *courseRepository) GetByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (*models.Course, error) {
	query := `
		SELECT course_id, company_id, code, name, description, credits,
		       is_active, created_at, updated_at, created_by, updated_by
		FROM academics.course
		WHERE company_id = $1 AND code = $2 AND deleted_at IS NULL
	`
	var c models.Course
	var description sql.NullString
	var credits sql.NullInt64
	var createdBy, updatedBy uuid.NullUUID
	err := db.QueryRowContext(ctx, query, companyID, code).Scan(
		&c.CourseID, &c.CompanyID, &c.Code, &c.Name, &description, &credits,
		&c.IsActive, &c.CreatedAt, &c.UpdatedAt, &createdBy, &updatedBy,
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
	if createdBy.Valid {
		c.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		c.UpdatedBy = &updatedBy.UUID
	}
	return &c, nil
}

// List returns courses matching the filter with pagination and sorting (only non-deleted).
func (r *courseRepository) List(ctx context.Context, db DBTX, filter CourseFilter, p Pagination, s Sort) ([]*models.Course, error) {
	where, args := r.buildCourseFilter(filter)
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	// Handle WHERE clause for deleted_at properly
	if where == "" {
		where = "WHERE deleted_at IS NULL"
	} else {
		where += " AND deleted_at IS NULL"
	}

	query := fmt.Sprintf(`
		SELECT course_id, company_id, code, name, description, credits,
		       is_active, created_at, updated_at, created_by, updated_by
		FROM academics.course
		%s %s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
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
		var createdBy, updatedBy uuid.NullUUID
		if err := rows.Scan(
			&c.CourseID, &c.CompanyID, &c.Code, &c.Name, &description, &credits,
			&c.IsActive, &c.CreatedAt, &c.UpdatedAt, &createdBy, &updatedBy,
		); err != nil {
			return nil, fmt.Errorf("scan course: %w", err)
		}
		if description.Valid {
			c.Description = description.String
		}
		if credits.Valid {
			c.Credits = int(credits.Int64)
		}
		if createdBy.Valid {
			c.CreatedBy = &createdBy.UUID
		}
		if updatedBy.Valid {
			c.UpdatedBy = &updatedBy.UUID
		}
		result = append(result, &c)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// ListActive returns all active courses for a company.
func (r *courseRepository) ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Course, error) {
	active := true
	return r.List(ctx, db, CourseFilter{CompanyID: companyID, IsActive: &active}, Pagination{Limit: 1000}, Sort{Field: "name", Direction: "ASC"})
}

// Count returns the number of courses matching the filter (only non-deleted).
func (r *courseRepository) Count(ctx context.Context, db DBTX, filter CourseFilter) (int64, error) {
	where, args := r.buildCourseFilter(filter)
	// Add deleted_at condition
	if where == "" {
		where = "WHERE deleted_at IS NULL"
	} else {
		where += " AND deleted_at IS NULL"
	}
	query := fmt.Sprintf(`SELECT COUNT(*) FROM academics.course %s`, where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count courses",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count courses: %w", err)
	}
	return count, nil
}

// Exists checks if an active (non-deleted) course with given company and code exists.
func (r *courseRepository) Exists(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM academics.course WHERE company_id = $1 AND code = $2 AND deleted_at IS NULL)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, code).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check course existence",
			util.String("company_id", companyID.String()),
			util.String("code", code),
			util.ErrorField(err))
		return false, fmt.Errorf("exists course: %w", err)
	}
	return exists, nil
}

// Update modifies an existing course (only if not deleted).
func (r *courseRepository) Update(ctx context.Context, db DBTX, e *models.Course) error {
	query := `
		UPDATE academics.course
		SET code = $2, name = $3, description = $4, credits = $5,
		    is_active = $6, updated_by = $7, updated_at = NOW()
		WHERE course_id = $1 AND deleted_at IS NULL
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		e.CourseID, e.Code, e.Name, e.Description, e.Credits, e.IsActive, e.UpdatedBy,
	).Scan(&e.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("course %s not found or deleted", e.CourseID)
		}
		r.logger.Error("failed to update course",
			util.String("id", e.CourseID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update course: %w", err)
	}
	return nil
}

// Activate sets is_active to true (only if not deleted).
func (r *courseRepository) Activate(ctx context.Context, db DBTX, id uuid.UUID, updatedBy *uuid.UUID) error {
	query := `UPDATE academics.course SET is_active = true, updated_by = $2, updated_at = NOW() WHERE course_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, updatedBy)
	if err != nil {
		r.logger.Error("failed to activate course",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("activate course: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("course %s not found or deleted", id)
	}
	return nil
}

// Deactivate sets is_active to false (only if not deleted).
func (r *courseRepository) Deactivate(ctx context.Context, db DBTX, id uuid.UUID, updatedBy *uuid.UUID) error {
	query := `UPDATE academics.course SET is_active = false, updated_by = $2, updated_at = NOW() WHERE course_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, updatedBy)
	if err != nil {
		r.logger.Error("failed to deactivate course",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("deactivate course: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("course %s not found or deleted", id)
	}
	return nil
}

// GetByIDForUpdate retrieves a course with row lock (only if not deleted).
func (r *courseRepository) GetByIDForUpdate(ctx context.Context, db DBTX, id uuid.UUID) (*models.Course, error) {
	query := `
		SELECT course_id, company_id, code, name, description, credits,
		       is_active, created_at, updated_at, created_by, updated_by
		FROM academics.course
		WHERE course_id = $1 AND deleted_at IS NULL
		FOR UPDATE
	`
	var c models.Course
	var description sql.NullString
	var credits sql.NullInt64
	var createdBy, updatedBy uuid.NullUUID
	err := db.QueryRowContext(ctx, query, id).Scan(
		&c.CourseID, &c.CompanyID, &c.Code, &c.Name, &description, &credits,
		&c.IsActive, &c.CreatedAt, &c.UpdatedAt, &createdBy, &updatedBy,
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
	if createdBy.Valid {
		c.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		c.UpdatedBy = &updatedBy.UUID
	}
	return &c, nil
}

// Delete soft-deletes a course.
func (r *courseRepository) Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error {
	query := `UPDATE academics.course SET deleted_at = NOW(), updated_by = $2, updated_at = NOW() WHERE course_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, deletedBy)
	if err != nil {
		r.logger.Error("failed to delete course",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete course: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("course %s not found or already deleted", id)
	}
	return nil
}

func (r *courseRepository) ListByCompanyAndCodes(ctx context.Context, db DBTX, keys []struct {
	CompanyID uuid.UUID
	Code      string
}) ([]*models.Course, error) {
	if len(keys) == 0 {
		return []*models.Course{}, nil
	}

	// Build the SQL with a dynamic number of placeholders.
	// We'll use a query like:
	//   SELECT ... FROM academics.course
	//   WHERE (company_id, code) IN (($1,$2), ($3,$4), ...)
	//     AND deleted_at IS NULL
	var placeholders []string
	var args []interface{}
	for i, key := range keys {
		// Each pair contributes two placeholders: ($%d,$%d)
		base := i*2 + 1
		placeholders = append(placeholders, fmt.Sprintf("($%d,$%d)", base, base+1))
		args = append(args, key.CompanyID, key.Code)
	}

	query := fmt.Sprintf(`
        SELECT course_id, company_id, code, name, description, credits,
               is_active, created_at, updated_at, created_by, updated_by
        FROM academics.course
        WHERE (company_id, code) IN (%s)
          AND deleted_at IS NULL
    `, strings.Join(placeholders, ","))

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list courses by company and codes",
			zap.Int("key_count", len(keys)),
			zap.Error(err))
		return nil, fmt.Errorf("list by company and codes: %w", err)
	}
	defer rows.Close()

	var result []*models.Course
	for rows.Next() {
		var c models.Course
		var description sql.NullString
		var credits sql.NullInt64
		var createdBy, updatedBy uuid.NullUUID

		if err := rows.Scan(
			&c.CourseID, &c.CompanyID, &c.Code, &c.Name, &description, &credits,
			&c.IsActive, &c.CreatedAt, &c.UpdatedAt, &createdBy, &updatedBy,
		); err != nil {
			return nil, fmt.Errorf("scan course: %w", err)
		}

		if description.Valid {
			c.Description = description.String
		}
		if credits.Valid {
			c.Credits = int(credits.Int64)
		}
		if createdBy.Valid {
			c.CreatedBy = &createdBy.UUID
		}
		if updatedBy.Valid {
			c.UpdatedBy = &updatedBy.UUID
		}

		result = append(result, &c)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}

	return result, nil
}

// GetByIDs returns a map of courses keyed by ID for the given IDs.
func (r *courseRepository) GetByIDs(ctx context.Context, db DBTX, ids []uuid.UUID) (map[uuid.UUID]*models.Course, error) {
	if len(ids) == 0 {
		return map[uuid.UUID]*models.Course{}, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	query := fmt.Sprintf(`
        SELECT course_id, company_id, code, name, description, credits,
               is_active, created_at, updated_at, created_by, updated_by
        FROM academics.course
        WHERE course_id IN (%s) AND deleted_at IS NULL
    `, strings.Join(placeholders, ","))
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get courses by IDs: %w", err)
	}
	defer rows.Close()
	result := make(map[uuid.UUID]*models.Course)
	for rows.Next() {
		var c models.Course
		var description sql.NullString
		var credits sql.NullInt64
		var createdBy, updatedBy uuid.NullUUID
		if err := rows.Scan(
			&c.CourseID, &c.CompanyID, &c.Code, &c.Name, &description, &credits,
			&c.IsActive, &c.CreatedAt, &c.UpdatedAt, &createdBy, &updatedBy,
		); err != nil {
			return nil, fmt.Errorf("scan course: %w", err)
		}
		if description.Valid {
			c.Description = description.String
		}
		if credits.Valid {
			c.Credits = int(credits.Int64)
		}
		if createdBy.Valid {
			c.CreatedBy = &createdBy.UUID
		}
		if updatedBy.Valid {
			c.UpdatedBy = &updatedBy.UUID
		}
		result[c.CourseID] = &c
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}
