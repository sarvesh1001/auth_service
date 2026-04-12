package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/util"
)

// SubjectRepository defines all database operations for subjects.
type SubjectRepository interface {
	Create(ctx context.Context, db DBTX, e *models.Subject) error
	BulkCreate(ctx context.Context, db DBTX, e []*models.Subject) error
	Upsert(ctx context.Context, db DBTX, e *models.Subject) (inserted bool, err error) // now returns inserted flag
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Subject, error)
	GetByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (*models.Subject, error)
	List(ctx context.Context, db DBTX, filter SubjectFilter, p Pagination, s Sort) ([]*models.Subject, error)
	ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Subject, error)
	Count(ctx context.Context, db DBTX, filter SubjectFilter) (int64, error)
	Exists(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (bool, error)
	Update(ctx context.Context, db DBTX, e *models.Subject) error
	Activate(ctx context.Context, db DBTX, id uuid.UUID, updatedBy *uuid.UUID) error
	Deactivate(ctx context.Context, db DBTX, id uuid.UUID, updatedBy *uuid.UUID) error
	GetByIDForUpdate(ctx context.Context, db DBTX, id uuid.UUID) (*models.Subject, error)
	Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error
	GetByIDs(ctx context.Context, db DBTX, ids []uuid.UUID) (map[uuid.UUID]*models.Subject, error)
	FindByCompanyAndCodes(ctx context.Context, db DBTX, companyID uuid.UUID, codes []string) ([]*models.Subject, error)
	IsAssignedToAnyCourse(ctx context.Context, db DBTX, subjectID uuid.UUID) (bool, error)
}

type subjectRepository struct {
	logger *zap.Logger
}

func NewSubjectRepository(logger *zap.Logger) SubjectRepository {
	return &subjectRepository{
		logger: logger.Named("subject_repo"),
	}
}

// allowedSubjectSortFields defines which columns can be used in ORDER BY.
var allowedSubjectSortFields = map[string]bool{
	"created_at": true,
	"name":       true,
	"code":       true,
	"credits":    true,
	"is_active":  true,
	"company_id": true,
}

// ---------------------------------------------------------------------
// Helpers (pagination, sorting, filter)
// ---------------------------------------------------------------------
func (r *subjectRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "created_at"
	}
	if !allowedSubjectSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY %s %s", field, dir), nil
}

func (r *subjectRepository) validatePagination(p Pagination) (int, int) {
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

func (r *subjectRepository) buildSubjectFilter(filter SubjectFilter) (string, []interface{}) {
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

// ---------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------
func (r *subjectRepository) Create(ctx context.Context, db DBTX, e *models.Subject) error {
	query := `
		INSERT INTO academics.subject (
			company_id, code, name, description, credits, is_active,
			created_by, updated_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
		RETURNING subject_id, created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		e.CompanyID, e.Code, e.Name, e.Description, e.Credits, e.IsActive,
		e.CreatedBy, e.UpdatedBy,
	).Scan(&e.SubjectID, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create subject",
			util.String("company_id", e.CompanyID.String()),
			util.String("code", e.Code),
			util.ErrorField(err))
		return fmt.Errorf("create subject: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// BulkCreate (no transaction handling – service provides tx)
// ---------------------------------------------------------------------
func (r *subjectRepository) BulkCreate(ctx context.Context, db DBTX, e []*models.Subject) error {
	if len(e) == 0 {
		return nil
	}

	// Use a prepared statement for performance
	stmt, err := db.PrepareContext(ctx, `
		INSERT INTO academics.subject (
			company_id, code, name, description, credits, is_active,
			created_by, updated_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
		RETURNING subject_id, created_at, updated_at
	`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, s := range e {
		err = stmt.QueryRowContext(ctx,
			s.CompanyID, s.Code, s.Name, s.Description, s.Credits, s.IsActive,
			s.CreatedBy, s.UpdatedBy,
		).Scan(&s.SubjectID, &s.CreatedAt, &s.UpdatedAt)
		if err != nil {
			r.logger.Error("bulk create subject failed",
				util.String("company_id", s.CompanyID.String()),
				util.String("code", s.Code),
				util.ErrorField(err))
			return fmt.Errorf("bulk create subject row: %w", err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------
// Upsert (returns inserted flag)
// ---------------------------------------------------------------------
func (r *subjectRepository) Upsert(ctx context.Context, db DBTX, e *models.Subject) (bool, error) {
	// Use a CTE to detect whether an insert or update happened.
	// The CTE returns a flag 'inserted' along with the subject fields.
	query := `
		WITH upsert AS (
			INSERT INTO academics.subject (
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
			RETURNING subject_id, created_at, updated_at, (xmax = 0) AS inserted
		)
		SELECT subject_id, created_at, updated_at, inserted FROM upsert
	`
	var inserted bool
	err := db.QueryRowContext(ctx, query,
		e.CompanyID, e.Code, e.Name, e.Description, e.Credits, e.IsActive,
		e.CreatedBy, e.UpdatedBy,
	).Scan(&e.SubjectID, &e.CreatedAt, &e.UpdatedAt, &inserted)
	if err != nil {
		r.logger.Error("failed to upsert subject",
			zap.String("company_id", e.CompanyID.String()),
			zap.String("code", e.Code),
			zap.Error(err))
		return false, fmt.Errorf("upsert subject: %w", err)
	}
	return inserted, nil
}

// ---------------------------------------------------------------------
// GetByID
// ---------------------------------------------------------------------
func (r *subjectRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Subject, error) {
	query := `
		SELECT subject_id, company_id, code, name, description, credits,
		       is_active, created_at, updated_at, created_by, updated_by
		FROM academics.subject
		WHERE subject_id = $1 AND deleted_at IS NULL
	`
	var s models.Subject
	var description sql.NullString
	var credits sql.NullInt64
	var createdBy, updatedBy uuid.NullUUID
	err := db.QueryRowContext(ctx, query, id).Scan(
		&s.SubjectID, &s.CompanyID, &s.Code, &s.Name, &description, &credits,
		&s.IsActive, &s.CreatedAt, &s.UpdatedAt, &createdBy, &updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get subject by ID",
			util.String("id", id.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get subject by ID: %w", err)
	}
	if description.Valid {
		s.Description = description.String
	}
	if credits.Valid {
		s.Credits = int(credits.Int64)
	}
	if createdBy.Valid {
		s.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		s.UpdatedBy = &updatedBy.UUID
	}
	return &s, nil
}

// ---------------------------------------------------------------------
// GetByCode
// ---------------------------------------------------------------------
func (r *subjectRepository) GetByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (*models.Subject, error) {
	query := `
		SELECT subject_id, company_id, code, name, description, credits,
		       is_active, created_at, updated_at, created_by, updated_by
		FROM academics.subject
		WHERE company_id = $1 AND code = $2 AND deleted_at IS NULL
	`
	var s models.Subject
	var description sql.NullString
	var credits sql.NullInt64
	var createdBy, updatedBy uuid.NullUUID
	err := db.QueryRowContext(ctx, query, companyID, code).Scan(
		&s.SubjectID, &s.CompanyID, &s.Code, &s.Name, &description, &credits,
		&s.IsActive, &s.CreatedAt, &s.UpdatedAt, &createdBy, &updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get subject by code",
			util.String("company_id", companyID.String()),
			util.String("code", code),
			util.ErrorField(err))
		return nil, fmt.Errorf("get subject by code: %w", err)
	}
	if description.Valid {
		s.Description = description.String
	}
	if credits.Valid {
		s.Credits = int(credits.Int64)
	}
	if createdBy.Valid {
		s.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		s.UpdatedBy = &updatedBy.UUID
	}
	return &s, nil
}

// ---------------------------------------------------------------------
// List
// ---------------------------------------------------------------------
func (r *subjectRepository) List(ctx context.Context, db DBTX, filter SubjectFilter, p Pagination, s Sort) ([]*models.Subject, error) {
	where, args := r.buildSubjectFilter(filter)
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)
	if where == "" {
		where = "WHERE deleted_at IS NULL"
	} else {
		where += " AND deleted_at IS NULL"
	}
	query := fmt.Sprintf(`
		SELECT subject_id, company_id, code, name, description, credits,
		       is_active, created_at, updated_at, created_by, updated_by
		FROM academics.subject
		%s %s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list subjects",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list subjects: %w", err)
	}
	defer rows.Close()

	var result []*models.Subject
	for rows.Next() {
		var s models.Subject
		var description sql.NullString
		var credits sql.NullInt64
		var createdBy, updatedBy uuid.NullUUID
		if err := rows.Scan(
			&s.SubjectID, &s.CompanyID, &s.Code, &s.Name, &description, &credits,
			&s.IsActive, &s.CreatedAt, &s.UpdatedAt, &createdBy, &updatedBy,
		); err != nil {
			return nil, fmt.Errorf("scan subject: %w", err)
		}
		if description.Valid {
			s.Description = description.String
		}
		if credits.Valid {
			s.Credits = int(credits.Int64)
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

// ---------------------------------------------------------------------
// ListActive
// ---------------------------------------------------------------------
func (r *subjectRepository) ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Subject, error) {
	active := true
	return r.List(ctx, db, SubjectFilter{CompanyID: companyID, IsActive: &active}, Pagination{Limit: 1000}, Sort{Field: "name", Direction: "ASC"})
}

// ---------------------------------------------------------------------
// Count
// ---------------------------------------------------------------------
func (r *subjectRepository) Count(ctx context.Context, db DBTX, filter SubjectFilter) (int64, error) {
	where, args := r.buildSubjectFilter(filter)
	if where == "" {
		where = "WHERE deleted_at IS NULL"
	} else {
		where += " AND deleted_at IS NULL"
	}
	query := fmt.Sprintf(`SELECT COUNT(*) FROM academics.subject %s`, where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count subjects",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count subjects: %w", err)
	}
	return count, nil
}

// ---------------------------------------------------------------------
// Exists
// ---------------------------------------------------------------------
func (r *subjectRepository) Exists(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM academics.subject WHERE company_id = $1 AND code = $2 AND deleted_at IS NULL)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, code).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check subject existence",
			util.String("company_id", companyID.String()),
			util.String("code", code),
			util.ErrorField(err))
		return false, fmt.Errorf("exists subject: %w", err)
	}
	return exists, nil
}

// ---------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------
func (r *subjectRepository) Update(ctx context.Context, db DBTX, e *models.Subject) error {
	query := `
		UPDATE academics.subject
		SET code = $2, name = $3, description = $4, credits = $5,
		    is_active = $6, updated_by = $7, updated_at = NOW()
		WHERE subject_id = $1 AND deleted_at IS NULL
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		e.SubjectID, e.Code, e.Name, e.Description, e.Credits, e.IsActive, e.UpdatedBy,
	).Scan(&e.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("subject %s not found or deleted", e.SubjectID)
		}
		r.logger.Error("failed to update subject",
			util.String("id", e.SubjectID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update subject: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// Activate / Deactivate
// ---------------------------------------------------------------------
func (r *subjectRepository) Activate(ctx context.Context, db DBTX, id uuid.UUID, updatedBy *uuid.UUID) error {
	query := `UPDATE academics.subject SET is_active = true, updated_by = $2, updated_at = NOW() WHERE subject_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, updatedBy)
	if err != nil {
		r.logger.Error("failed to activate subject",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("activate subject: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("subject %s not found or deleted", id)
	}
	return nil
}

func (r *subjectRepository) Deactivate(ctx context.Context, db DBTX, id uuid.UUID, updatedBy *uuid.UUID) error {
	query := `UPDATE academics.subject SET is_active = false, updated_by = $2, updated_at = NOW() WHERE subject_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, updatedBy)
	if err != nil {
		r.logger.Error("failed to deactivate subject",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("deactivate subject: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("subject %s not found or deleted", id)
	}
	return nil
}

// ---------------------------------------------------------------------
// GetByIDForUpdate (with row lock)
// ---------------------------------------------------------------------
func (r *subjectRepository) GetByIDForUpdate(ctx context.Context, db DBTX, id uuid.UUID) (*models.Subject, error) {
	query := `
		SELECT subject_id, company_id, code, name, description, credits,
		       is_active, created_at, updated_at, created_by, updated_by
		FROM academics.subject
		WHERE subject_id = $1 AND deleted_at IS NULL
		FOR UPDATE
	`
	var s models.Subject
	var description sql.NullString
	var credits sql.NullInt64
	var createdBy, updatedBy uuid.NullUUID
	err := db.QueryRowContext(ctx, query, id).Scan(
		&s.SubjectID, &s.CompanyID, &s.Code, &s.Name, &description, &credits,
		&s.IsActive, &s.CreatedAt, &s.UpdatedAt, &createdBy, &updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get subject for update",
			util.String("id", id.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get subject for update: %w", err)
	}
	if description.Valid {
		s.Description = description.String
	}
	if credits.Valid {
		s.Credits = int(credits.Int64)
	}
	if createdBy.Valid {
		s.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		s.UpdatedBy = &updatedBy.UUID
	}
	return &s, nil
}

// ---------------------------------------------------------------------
// Delete (soft delete)
// ---------------------------------------------------------------------
func (r *subjectRepository) Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error {
	query := `UPDATE academics.subject SET deleted_at = NOW(), updated_by = $2, updated_at = NOW() WHERE subject_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, deletedBy)
	if err != nil {
		r.logger.Error("failed to delete subject",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete subject: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("subject %s not found or already deleted", id)
	}
	return nil
}

// ---------------------------------------------------------------------
// GetByIDs
// ---------------------------------------------------------------------
func (r *subjectRepository) GetByIDs(ctx context.Context, db DBTX, ids []uuid.UUID) (map[uuid.UUID]*models.Subject, error) {
	if len(ids) == 0 {
		return map[uuid.UUID]*models.Subject{}, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	query := fmt.Sprintf(`
        SELECT subject_id, company_id, code, name, description, credits,
               is_active, created_at, updated_at, created_by, updated_by
        FROM academics.subject
        WHERE subject_id IN (%s) AND deleted_at IS NULL
    `, strings.Join(placeholders, ","))
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get subjects by IDs: %w", err)
	}
	defer rows.Close()
	result := make(map[uuid.UUID]*models.Subject)
	for rows.Next() {
		var s models.Subject
		var description sql.NullString
		var credits sql.NullInt64
		var createdBy, updatedBy uuid.NullUUID
		if err := rows.Scan(
			&s.SubjectID, &s.CompanyID, &s.Code, &s.Name, &description, &credits,
			&s.IsActive, &s.CreatedAt, &s.UpdatedAt, &createdBy, &updatedBy,
		); err != nil {
			return nil, fmt.Errorf("scan subject: %w", err)
		}
		if description.Valid {
			s.Description = description.String
		}
		if credits.Valid {
			s.Credits = int(credits.Int64)
		}
		if createdBy.Valid {
			s.CreatedBy = &createdBy.UUID
		}
		if updatedBy.Valid {
			s.UpdatedBy = &updatedBy.UUID
		}
		result[s.SubjectID] = &s
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// ---------------------------------------------------------------------
// FindByCompanyAndCodes
// ---------------------------------------------------------------------
func (r *subjectRepository) FindByCompanyAndCodes(ctx context.Context, db DBTX, companyID uuid.UUID, codes []string) ([]*models.Subject, error) {
	if len(codes) == 0 {
		return []*models.Subject{}, nil
	}
	query := `
		SELECT subject_id, company_id, code, name, description, credits,
		       is_active, created_at, updated_at, created_by, updated_by
		FROM academics.subject
		WHERE company_id = $1 AND code = ANY($2) AND deleted_at IS NULL
	`
	rows, err := db.QueryContext(ctx, query, companyID, pq.Array(codes))
	if err != nil {
		r.logger.Error("failed to find subjects by codes",
			util.String("company_id", companyID.String()),
			util.Any("codes", codes),
			util.ErrorField(err))
		return nil, fmt.Errorf("find subjects by codes: %w", err)
	}
	defer rows.Close()

	var result []*models.Subject
	for rows.Next() {
		var s models.Subject
		var description sql.NullString
		var credits sql.NullInt64
		var createdBy, updatedBy uuid.NullUUID
		if err := rows.Scan(
			&s.SubjectID, &s.CompanyID, &s.Code, &s.Name, &description, &credits,
			&s.IsActive, &s.CreatedAt, &s.UpdatedAt, &createdBy, &updatedBy,
		); err != nil {
			return nil, fmt.Errorf("scan subject: %w", err)
		}
		if description.Valid {
			s.Description = description.String
		}
		if credits.Valid {
			s.Credits = int(credits.Int64)
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

// ---------------------------------------------------------------------
// IsAssignedToAnyCourse
// ---------------------------------------------------------------------
// ✅ FIXED: removed the non‑existent `deleted_at` column from the query.
// The error `column scm.deleted_at does not exist` came from a different file
// (e.g., curriculum_repository.go) that joins subject_course_mapping with section/term.
// This method is correct.
func (r *subjectRepository) IsAssignedToAnyCourse(ctx context.Context, db DBTX, subjectID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM academics.subject_course_mapping WHERE subject_id = $1)`
	var exists bool
	err := db.QueryRowContext(ctx, query, subjectID).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check subject course assignments",
			util.String("subject_id", subjectID.String()),
			util.ErrorField(err))
		return false, fmt.Errorf("check subject assignments: %w", err)
	}
	return exists, nil
}
