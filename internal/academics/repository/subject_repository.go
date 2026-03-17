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

// SubjectRepository defines methods for subject table.
type SubjectRepository interface {
	Create(ctx context.Context, e *models.Subject) error
	BulkCreate(ctx context.Context, e []*models.Subject) error
	Upsert(ctx context.Context, e *models.Subject) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Subject, error)
	GetByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.Subject, error)
	List(ctx context.Context, filter SubjectFilter, p Pagination, s Sort) ([]*models.Subject, error)
	ListActive(ctx context.Context, companyID uuid.UUID) ([]*models.Subject, error)
	Count(ctx context.Context, filter SubjectFilter) (int64, error)
	Exists(ctx context.Context, companyID uuid.UUID, code string) (bool, error)
	Update(ctx context.Context, e *models.Subject) error
	Activate(ctx context.Context, id uuid.UUID) error
	Deactivate(ctx context.Context, id uuid.UUID) error
	GetByIDForUpdate(ctx context.Context, id uuid.UUID) (*models.Subject, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

type subjectRepository struct {
	db     *client.PostgresClient
	logger *zap.Logger
}

// NewSubjectRepository creates a new subject repository.
func NewSubjectRepository(db *client.PostgresClient, logger *zap.Logger) SubjectRepository {
	return &subjectRepository{
		db:     db,
		logger: logger.Named("subject_repo"),
	}
}

// Create inserts a new subject.
func (r *subjectRepository) Create(ctx context.Context, e *models.Subject) error {
	query := `
		INSERT INTO academics.subject (
			company_id, code, name, description, credits, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
		RETURNING subject_id, created_at, updated_at
	`
	err := r.db.QueryRow(ctx, query,
		e.CompanyID, e.Code, e.Name, e.Description, e.Credits, e.IsActive,
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

// BulkCreate inserts multiple subjects.
func (r *subjectRepository) BulkCreate(ctx context.Context, e []*models.Subject) error {
	if len(e) == 0 {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO academics.subject (
			company_id, code, name, description, credits, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
		RETURNING subject_id, created_at, updated_at
	`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, s := range e {
		err = stmt.QueryRowContext(ctx,
			s.CompanyID, s.Code, s.Name, s.Description, s.Credits, s.IsActive,
		).Scan(&s.SubjectID, &s.CreatedAt, &s.UpdatedAt)
		if err != nil {
			r.logger.Error("bulk create subject failed",
				util.String("company_id", s.CompanyID.String()),
				util.String("code", s.Code),
				util.ErrorField(err))
			return fmt.Errorf("bulk create subject row: %w", err)
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// Upsert inserts or updates on conflict (company_id, code).
func (r *subjectRepository) Upsert(ctx context.Context, e *models.Subject) error {
	query := `
		INSERT INTO academics.subject (
			company_id, code, name, description, credits, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
		ON CONFLICT (company_id, code) DO UPDATE SET
			name = EXCLUDED.name,
			description = EXCLUDED.description,
			credits = EXCLUDED.credits,
			is_active = EXCLUDED.is_active,
			updated_at = NOW()
		RETURNING subject_id, created_at, updated_at
	`
	err := r.db.QueryRow(ctx, query,
		e.CompanyID, e.Code, e.Name, e.Description, e.Credits, e.IsActive,
	).Scan(&e.SubjectID, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to upsert subject",
			util.String("company_id", e.CompanyID.String()),
			util.String("code", e.Code),
			util.ErrorField(err))
		return fmt.Errorf("upsert subject: %w", err)
	}
	return nil
}

// GetByID retrieves a subject by its ID.
func (r *subjectRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Subject, error) {
	query := `
		SELECT subject_id, company_id, code, name, description, credits, is_active, created_at, updated_at
		FROM academics.subject
		WHERE subject_id = $1
	`
	var s models.Subject
	var description sql.NullString
	var credits sql.NullInt64
	err := r.db.QueryRow(ctx, query, id).Scan(
		&s.SubjectID, &s.CompanyID, &s.Code, &s.Name, &description, &credits,
		&s.IsActive, &s.CreatedAt, &s.UpdatedAt,
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
	return &s, nil
}

// GetByCode retrieves a subject by company and code.
func (r *subjectRepository) GetByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.Subject, error) {
	query := `
		SELECT subject_id, company_id, code, name, description, credits, is_active, created_at, updated_at
		FROM academics.subject
		WHERE company_id = $1 AND code = $2
	`
	var s models.Subject
	var description sql.NullString
	var credits sql.NullInt64
	err := r.db.QueryRow(ctx, query, companyID, code).Scan(
		&s.SubjectID, &s.CompanyID, &s.Code, &s.Name, &description, &credits,
		&s.IsActive, &s.CreatedAt, &s.UpdatedAt,
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
	return &s, nil
}

// List returns subjects matching the filter with pagination and sorting.
func (r *subjectRepository) List(ctx context.Context, filter SubjectFilter, p Pagination, s Sort) ([]*models.Subject, error) {
	where, args := r.buildSubjectFilter(filter)
	orderBy := "ORDER BY " + s.Field + " " + s.Direction
	if s.Field == "" {
		orderBy = "ORDER BY created_at DESC"
	}
	query := fmt.Sprintf(`
		SELECT subject_id, company_id, code, name, description, credits, is_active, created_at, updated_at
		FROM academics.subject
		%s %s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, p.Limit, p.Offset)
	rows, err := r.db.Query(ctx, query, args...)
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
		if err := rows.Scan(
			&s.SubjectID, &s.CompanyID, &s.Code, &s.Name, &description, &credits,
			&s.IsActive, &s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan subject: %w", err)
		}
		if description.Valid {
			s.Description = description.String
		}
		if credits.Valid {
			s.Credits = int(credits.Int64)
		}
		result = append(result, &s)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// ListActive returns all active subjects for a company.
func (r *subjectRepository) ListActive(ctx context.Context, companyID uuid.UUID) ([]*models.Subject, error) {
	active := true
	return r.List(ctx, SubjectFilter{CompanyID: companyID, IsActive: &active}, Pagination{Limit: 1000}, Sort{Field: "name", Direction: "ASC"})
}

// Count returns the number of subjects matching the filter.
func (r *subjectRepository) Count(ctx context.Context, filter SubjectFilter) (int64, error) {
	where, args := r.buildSubjectFilter(filter)
	query := fmt.Sprintf(`SELECT COUNT(*) FROM academics.subject %s`, where)
	var count int64
	err := r.db.QueryRow(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count subjects",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count subjects: %w", err)
	}
	return count, nil
}

// Exists checks if a subject with given company and code exists.
func (r *subjectRepository) Exists(ctx context.Context, companyID uuid.UUID, code string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM academics.subject WHERE company_id = $1 AND code = $2)`
	var exists bool
	err := r.db.QueryRow(ctx, query, companyID, code).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check subject existence",
			util.String("company_id", companyID.String()),
			util.String("code", code),
			util.ErrorField(err))
		return false, fmt.Errorf("exists subject: %w", err)
	}
	return exists, nil
}

// Update modifies an existing subject.
func (r *subjectRepository) Update(ctx context.Context, e *models.Subject) error {
	query := `
		UPDATE academics.subject
		SET code = $2, name = $3, description = $4, credits = $5, is_active = $6, updated_at = NOW()
		WHERE subject_id = $1
		RETURNING updated_at
	`
	err := r.db.QueryRow(ctx, query,
		e.SubjectID, e.Code, e.Name, e.Description, e.Credits, e.IsActive,
	).Scan(&e.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to update subject",
			util.String("id", e.SubjectID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update subject: %w", err)
	}
	return nil
}

// Activate sets is_active to true.
func (r *subjectRepository) Activate(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE academics.subject SET is_active = true, updated_at = NOW() WHERE subject_id = $1`
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to activate subject",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("activate subject: %w", err)
	}
	return nil
}

// Deactivate sets is_active to false.
func (r *subjectRepository) Deactivate(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE academics.subject SET is_active = false, updated_at = NOW() WHERE subject_id = $1`
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to deactivate subject",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("deactivate subject: %w", err)
	}
	return nil
}

// GetByIDForUpdate retrieves a subject with row lock.
func (r *subjectRepository) GetByIDForUpdate(ctx context.Context, id uuid.UUID) (*models.Subject, error) {
	query := `
		SELECT subject_id, company_id, code, name, description, credits, is_active, created_at, updated_at
		FROM academics.subject
		WHERE subject_id = $1
		FOR UPDATE
	`
	var s models.Subject
	var description sql.NullString
	var credits sql.NullInt64
	err := r.db.QueryRow(ctx, query, id).Scan(
		&s.SubjectID, &s.CompanyID, &s.Code, &s.Name, &description, &credits,
		&s.IsActive, &s.CreatedAt, &s.UpdatedAt,
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
	return &s, nil
}

// Delete removes a subject.
func (r *subjectRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM academics.subject WHERE subject_id = $1`
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete subject",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete subject: %w", err)
	}
	return nil
}

// buildSubjectFilter constructs WHERE clause and arguments for SubjectFilter.
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
