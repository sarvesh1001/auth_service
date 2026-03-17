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

// TermRepository defines methods for term table.
type TermRepository interface {
	Create(ctx context.Context, e *models.Term) error
	BulkCreate(ctx context.Context, e []*models.Term) error
	Upsert(ctx context.Context, e *models.Term) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Term, error)
	GetCurrent(ctx context.Context, academicYearID uuid.UUID) (*models.Term, error)
	List(ctx context.Context, filter TermFilter, p Pagination, s Sort) ([]*models.Term, error)
	ListByAcademicYear(ctx context.Context, academicYearID uuid.UUID) ([]*models.Term, error)
	Count(ctx context.Context, filter TermFilter) (int64, error)
	Exists(ctx context.Context, academicYearID uuid.UUID, name string) (bool, error)
	Update(ctx context.Context, e *models.Term) error
	SetCurrent(ctx context.Context, academicYearID, termID uuid.UUID) error
	GetByIDForUpdate(ctx context.Context, id uuid.UUID) (*models.Term, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

type termRepository struct {
	db     *client.PostgresClient
	logger *zap.Logger
}

// NewTermRepository creates a new term repository.
func NewTermRepository(db *client.PostgresClient, logger *zap.Logger) TermRepository {
	return &termRepository{
		db:     db,
		logger: logger.Named("term_repo"),
	}
}

// Create inserts a new term.
func (r *termRepository) Create(ctx context.Context, e *models.Term) error {
	query := `
		INSERT INTO academics.term (
			academic_year_id, name, start_date, end_date, is_current, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
		RETURNING term_id, created_at, updated_at
	`
	err := r.db.QueryRow(ctx, query,
		e.AcademicYearID, e.Name, e.StartDate, e.EndDate, e.IsCurrent,
	).Scan(&e.TermID, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create term",
			util.String("academic_year_id", e.AcademicYearID.String()),
			util.String("name", e.Name),
			util.ErrorField(err))
		return fmt.Errorf("create term: %w", err)
	}
	return nil
}

// BulkCreate inserts multiple terms.
func (r *termRepository) BulkCreate(ctx context.Context, e []*models.Term) error {
	if len(e) == 0 {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO academics.term (
			academic_year_id, name, start_date, end_date, is_current, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
		RETURNING term_id, created_at, updated_at
	`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, t := range e {
		err = stmt.QueryRowContext(ctx,
			t.AcademicYearID, t.Name, t.StartDate, t.EndDate, t.IsCurrent,
		).Scan(&t.TermID, &t.CreatedAt, &t.UpdatedAt)
		if err != nil {
			r.logger.Error("bulk create term failed",
				util.String("academic_year_id", t.AcademicYearID.String()),
				util.String("name", t.Name),
				util.ErrorField(err))
			return fmt.Errorf("bulk create term row: %w", err)
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// Upsert inserts or updates on conflict (academic_year_id, name).
func (r *termRepository) Upsert(ctx context.Context, e *models.Term) error {
	query := `
		INSERT INTO academics.term (
			academic_year_id, name, start_date, end_date, is_current, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
		ON CONFLICT (academic_year_id, name) DO UPDATE SET
			start_date = EXCLUDED.start_date,
			end_date = EXCLUDED.end_date,
			is_current = EXCLUDED.is_current,
			updated_at = NOW()
		RETURNING term_id, created_at, updated_at
	`
	err := r.db.QueryRow(ctx, query,
		e.AcademicYearID, e.Name, e.StartDate, e.EndDate, e.IsCurrent,
	).Scan(&e.TermID, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to upsert term",
			util.String("academic_year_id", e.AcademicYearID.String()),
			util.String("name", e.Name),
			util.ErrorField(err))
		return fmt.Errorf("upsert term: %w", err)
	}
	return nil
}

// GetByID retrieves a term by its ID.
func (r *termRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Term, error) {
	query := `
		SELECT term_id, academic_year_id, name, start_date, end_date, is_current, created_at, updated_at
		FROM academics.term
		WHERE term_id = $1
	`
	var t models.Term
	err := r.db.QueryRow(ctx, query, id).Scan(
		&t.TermID, &t.AcademicYearID, &t.Name, &t.StartDate, &t.EndDate,
		&t.IsCurrent, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get term by ID",
			util.String("id", id.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get term by ID: %w", err)
	}
	return &t, nil
}

// GetCurrent returns the current term for an academic year.
func (r *termRepository) GetCurrent(ctx context.Context, academicYearID uuid.UUID) (*models.Term, error) {
	query := `
		SELECT term_id, academic_year_id, name, start_date, end_date, is_current, created_at, updated_at
		FROM academics.term
		WHERE academic_year_id = $1 AND is_current = true
		LIMIT 1
	`
	var t models.Term
	err := r.db.QueryRow(ctx, query, academicYearID).Scan(
		&t.TermID, &t.AcademicYearID, &t.Name, &t.StartDate, &t.EndDate,
		&t.IsCurrent, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get current term",
			util.String("academic_year_id", academicYearID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get current term: %w", err)
	}
	return &t, nil
}

// List returns terms matching the filter with pagination and sorting.
func (r *termRepository) List(ctx context.Context, filter TermFilter, p Pagination, s Sort) ([]*models.Term, error) {
	where, args := r.buildTermFilter(filter)
	orderBy := "ORDER BY " + s.Field + " " + s.Direction
	if s.Field == "" {
		orderBy = "ORDER BY created_at DESC"
	}
	query := fmt.Sprintf(`
		SELECT term_id, academic_year_id, name, start_date, end_date, is_current, created_at, updated_at
		FROM academics.term
		%s %s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, p.Limit, p.Offset)
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list terms",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list terms: %w", err)
	}
	defer rows.Close()

	var result []*models.Term
	for rows.Next() {
		var t models.Term
		if err := rows.Scan(
			&t.TermID, &t.AcademicYearID, &t.Name, &t.StartDate, &t.EndDate,
			&t.IsCurrent, &t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan term: %w", err)
		}
		result = append(result, &t)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// ListByAcademicYear returns all terms for a given academic year.
func (r *termRepository) ListByAcademicYear(ctx context.Context, academicYearID uuid.UUID) ([]*models.Term, error) {
	return r.List(ctx, TermFilter{AcademicYearID: academicYearID}, Pagination{Limit: 1000}, Sort{Field: "start_date", Direction: "ASC"})
}

// Count returns the number of terms matching the filter.
func (r *termRepository) Count(ctx context.Context, filter TermFilter) (int64, error) {
	where, args := r.buildTermFilter(filter)
	query := fmt.Sprintf(`SELECT COUNT(*) FROM academics.term %s`, where)
	var count int64
	err := r.db.QueryRow(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count terms",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count terms: %w", err)
	}
	return count, nil
}

// Exists checks if a term with given academic year and name exists.
func (r *termRepository) Exists(ctx context.Context, academicYearID uuid.UUID, name string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM academics.term WHERE academic_year_id = $1 AND name = $2)`
	var exists bool
	err := r.db.QueryRow(ctx, query, academicYearID, name).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check term existence",
			util.String("academic_year_id", academicYearID.String()),
			util.String("name", name),
			util.ErrorField(err))
		return false, fmt.Errorf("exists term: %w", err)
	}
	return exists, nil
}

// Update modifies an existing term.
func (r *termRepository) Update(ctx context.Context, e *models.Term) error {
	query := `
		UPDATE academics.term
		SET name = $2, start_date = $3, end_date = $4, is_current = $5, updated_at = NOW()
		WHERE term_id = $1
		RETURNING updated_at
	`
	err := r.db.QueryRow(ctx, query,
		e.TermID, e.Name, e.StartDate, e.EndDate, e.IsCurrent,
	).Scan(&e.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to update term",
			util.String("id", e.TermID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update term: %w", err)
	}
	return nil
}

// SetCurrent marks the given term as current and unsets others for the academic year.
func (r *termRepository) SetCurrent(ctx context.Context, academicYearID, termID uuid.UUID) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Unset all current for academic year
	_, err = tx.ExecContext(ctx, `UPDATE academics.term SET is_current = false, updated_at = NOW() WHERE academic_year_id = $1`, academicYearID)
	if err != nil {
		r.logger.Error("failed to unset current terms",
			util.String("academic_year_id", academicYearID.String()),
			util.ErrorField(err))
		return fmt.Errorf("unset current: %w", err)
	}

	// Set the new current
	res, err := tx.ExecContext(ctx, `UPDATE academics.term SET is_current = true, updated_at = NOW() WHERE term_id = $1`, termID)
	if err != nil {
		r.logger.Error("failed to set current term",
			util.String("id", termID.String()),
			util.ErrorField(err))
		return fmt.Errorf("set current: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("term %s not found", termID)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// GetByIDForUpdate retrieves a term with a row lock (FOR UPDATE).
func (r *termRepository) GetByIDForUpdate(ctx context.Context, id uuid.UUID) (*models.Term, error) {
	query := `
		SELECT term_id, academic_year_id, name, start_date, end_date, is_current, created_at, updated_at
		FROM academics.term
		WHERE term_id = $1
		FOR UPDATE
	`
	var t models.Term
	err := r.db.QueryRow(ctx, query, id).Scan(
		&t.TermID, &t.AcademicYearID, &t.Name, &t.StartDate, &t.EndDate,
		&t.IsCurrent, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get term for update",
			util.String("id", id.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get term for update: %w", err)
	}
	return &t, nil
}

// Delete removes a term.
func (r *termRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM academics.term WHERE term_id = $1`
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete term",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete term: %w", err)
	}
	return nil
}

// buildTermFilter constructs WHERE clause and arguments for TermFilter.
func (r *termRepository) buildTermFilter(filter TermFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.AcademicYearID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("academic_year_id = $%d", idx))
		args = append(args, filter.AcademicYearID)
		idx++
	}
	if filter.IsCurrent != nil {
		conditions = append(conditions, fmt.Sprintf("is_current = $%d", idx))
		args = append(args, *filter.IsCurrent)
		idx++
	}
	if !filter.StartFrom.IsZero() {
		conditions = append(conditions, fmt.Sprintf("start_date >= $%d", idx))
		args = append(args, filter.StartFrom)
		idx++
	}
	if !filter.EndTo.IsZero() {
		conditions = append(conditions, fmt.Sprintf("end_date <= $%d", idx))
		args = append(args, filter.EndTo)
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
