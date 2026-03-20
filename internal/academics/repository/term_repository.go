package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/util"
)

// TermRepository defines methods for term table.
type TermRepository interface {
	Create(ctx context.Context, db DBTX, e *models.Term) error
	BulkCreate(ctx context.Context, db DBTX, e []*models.Term) error
	Upsert(ctx context.Context, db DBTX, e *models.Term) error
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Term, error)
	GetCurrent(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.Term, error)
	List(ctx context.Context, db DBTX, filter TermFilter, p Pagination, s Sort) ([]*models.Term, error)
	ListByAcademicYear(ctx context.Context, db DBTX, academicYearID uuid.UUID) ([]*models.Term, error)
	Count(ctx context.Context, db DBTX, filter TermFilter) (int64, error)
	Exists(ctx context.Context, db DBTX, academicYearID uuid.UUID, name string) (bool, error)
	Update(ctx context.Context, db DBTX, e *models.Term) error
	SetCurrent(ctx context.Context, db DBTX, academicYearID, termID uuid.UUID, updatedBy *uuid.UUID) error
	GetByIDForUpdate(ctx context.Context, db DBTX, id uuid.UUID) (*models.Term, error)
	Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error
	CheckOverlap(ctx context.Context, db DBTX, academicYearID uuid.UUID, start, end time.Time, excludeID uuid.UUID) (bool, error)
	GetAcademicYearByTerm(ctx context.Context, db DBTX, termID uuid.UUID) (*models.AcademicYear, error)
	GetByIDs(ctx context.Context, db DBTX, ids []uuid.UUID) (map[uuid.UUID]*models.Term, error)
	GetAcademicYearsByTermIDs(ctx context.Context, db DBTX, termIDs []uuid.UUID) (map[uuid.UUID]*models.AcademicYear, error)
}

type termRepository struct {
	logger *zap.Logger
}

// NewTermRepository creates a new term repository.
func NewTermRepository(logger *zap.Logger) TermRepository {
	return &termRepository{
		logger: logger.Named("term_repo"),
	}
}

// Allowed sort fields for terms
var allowedTermSortFields = map[string]bool{
	"created_at": true,
	"name":       true,
	"start_date": true,
	"end_date":   true,
	"is_current": true,
}

func (r *termRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "created_at"
	}
	if !allowedTermSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY %s %s", field, dir), nil
}

func (r *termRepository) validatePagination(p Pagination) (int, int) {
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

// Create inserts a new term.
func (r *termRepository) Create(ctx context.Context, db DBTX, e *models.Term) error {
	query := `
		INSERT INTO academics.term (
			academic_year_id, name, start_date, end_date, is_current,
			created_by, updated_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
		RETURNING term_id, created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		e.AcademicYearID, e.Name, e.StartDate, e.EndDate, e.IsCurrent,
		e.CreatedBy, e.UpdatedBy,
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

// BulkCreate inserts multiple terms with proper transaction handling.
func (r *termRepository) BulkCreate(ctx context.Context, db DBTX, e []*models.Term) error {
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
		INSERT INTO academics.term (
			academic_year_id, name, start_date, end_date, is_current,
			created_by, updated_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
		RETURNING term_id, created_at, updated_at
	`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, t := range e {
		err = stmt.QueryRowContext(ctx,
			t.AcademicYearID, t.Name, t.StartDate, t.EndDate, t.IsCurrent,
			t.CreatedBy, t.UpdatedBy,
		).Scan(&t.TermID, &t.CreatedAt, &t.UpdatedAt)
		if err != nil {
			r.logger.Error("bulk create term failed",
				util.String("academic_year_id", t.AcademicYearID.String()),
				util.String("name", t.Name),
				util.ErrorField(err))
			return fmt.Errorf("bulk create term row: %w", err)
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
// Upsert inserts or updates using the unique constraint (enterprise pattern).
func (r *termRepository) Upsert(ctx context.Context, db DBTX, e *models.Term) error {
	query := `
        INSERT INTO academics.term (
            academic_year_id, name, start_date, end_date, is_current,
            created_by, updated_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
        ON CONFLICT (academic_year_id, name) WHERE deleted_at IS NULL
        DO UPDATE SET
            start_date = EXCLUDED.start_date,
            end_date = EXCLUDED.end_date,
            is_current = EXCLUDED.is_current,
            updated_by = EXCLUDED.updated_by,
            updated_at = NOW()
        RETURNING term_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		e.AcademicYearID, e.Name, e.StartDate, e.EndDate, e.IsCurrent,
		e.CreatedBy, e.UpdatedBy,
	).Scan(&e.TermID, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to upsert term",
			zap.String("academic_year_id", e.AcademicYearID.String()),
			zap.String("name", e.Name),
			zap.Error(err))
		return fmt.Errorf("upsert term: %w", err)
	}
	return nil
}

// GetByID retrieves a term by its ID (only if not deleted).
func (r *termRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Term, error) {
	query := `
		SELECT term_id, academic_year_id, name, start_date, end_date,
		       is_current, created_at, updated_at, created_by, updated_by
		FROM academics.term
		WHERE term_id = $1 AND deleted_at IS NULL
	`
	var t models.Term
	var createdBy, updatedBy uuid.NullUUID
	err := db.QueryRowContext(ctx, query, id).Scan(
		&t.TermID, &t.AcademicYearID, &t.Name, &t.StartDate, &t.EndDate,
		&t.IsCurrent, &t.CreatedAt, &t.UpdatedAt, &createdBy, &updatedBy,
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
	if createdBy.Valid {
		t.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		t.UpdatedBy = &updatedBy.UUID
	}
	return &t, nil
}

// GetCurrent returns the current term for an academic year (only if not deleted).
func (r *termRepository) GetCurrent(ctx context.Context, db DBTX, academicYearID uuid.UUID) (*models.Term, error) {
	query := `
		SELECT term_id, academic_year_id, name, start_date, end_date,
		       is_current, created_at, updated_at, created_by, updated_by
		FROM academics.term
		WHERE academic_year_id = $1 AND is_current = true AND deleted_at IS NULL
		LIMIT 1
	`
	var t models.Term
	var createdBy, updatedBy uuid.NullUUID
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(
		&t.TermID, &t.AcademicYearID, &t.Name, &t.StartDate, &t.EndDate,
		&t.IsCurrent, &t.CreatedAt, &t.UpdatedAt, &createdBy, &updatedBy,
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
	if createdBy.Valid {
		t.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		t.UpdatedBy = &updatedBy.UUID
	}
	return &t, nil
}

// List returns terms matching the filter with pagination and sorting (only non-deleted).
func (r *termRepository) List(ctx context.Context, db DBTX, filter TermFilter, p Pagination, s Sort) ([]*models.Term, error) {
	where, args := r.buildTermFilter(filter)
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
		SELECT term_id, academic_year_id, name, start_date, end_date,
		       is_current, created_at, updated_at, created_by, updated_by
		FROM academics.term
		%s %s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
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
		var createdBy, updatedBy uuid.NullUUID
		if err := rows.Scan(
			&t.TermID, &t.AcademicYearID, &t.Name, &t.StartDate, &t.EndDate,
			&t.IsCurrent, &t.CreatedAt, &t.UpdatedAt, &createdBy, &updatedBy,
		); err != nil {
			return nil, fmt.Errorf("scan term: %w", err)
		}
		if createdBy.Valid {
			t.CreatedBy = &createdBy.UUID
		}
		if updatedBy.Valid {
			t.UpdatedBy = &updatedBy.UUID
		}
		result = append(result, &t)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// ListByAcademicYear returns all terms for a given academic year.
func (r *termRepository) ListByAcademicYear(ctx context.Context, db DBTX, academicYearID uuid.UUID) ([]*models.Term, error) {
	return r.List(ctx, db, TermFilter{AcademicYearID: academicYearID}, Pagination{Limit: 1000}, Sort{Field: "start_date", Direction: "ASC"})
}

// Count returns the number of terms matching the filter (only non-deleted).
func (r *termRepository) Count(ctx context.Context, db DBTX, filter TermFilter) (int64, error) {
	where, args := r.buildTermFilter(filter)

	// Fix WHERE clause: ensure deleted_at IS NULL is always present
	if where == "" {
		where = "WHERE deleted_at IS NULL"
	} else {
		where += " AND deleted_at IS NULL"
	}

	query := fmt.Sprintf(`SELECT COUNT(*) FROM academics.term %s`, where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count terms",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count terms: %w", err)
	}
	return count, nil
}

// Exists checks if an active (non-deleted) term with given academic year and name exists.
func (r *termRepository) Exists(ctx context.Context, db DBTX, academicYearID uuid.UUID, name string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM academics.term WHERE academic_year_id = $1 AND name = $2 AND deleted_at IS NULL)`
	var exists bool
	err := db.QueryRowContext(ctx, query, academicYearID, name).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check term existence",
			util.String("academic_year_id", academicYearID.String()),
			util.String("name", name),
			util.ErrorField(err))
		return false, fmt.Errorf("exists term: %w", err)
	}
	return exists, nil
}

// Update modifies an existing term (only if not deleted).
func (r *termRepository) Update(ctx context.Context, db DBTX, e *models.Term) error {
	query := `
		UPDATE academics.term
		SET name = $2, start_date = $3, end_date = $4, is_current = $5,
		    updated_by = $6, updated_at = NOW()
		WHERE term_id = $1 AND deleted_at IS NULL
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		e.TermID, e.Name, e.StartDate, e.EndDate, e.IsCurrent, e.UpdatedBy,
	).Scan(&e.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("term %s not found or deleted", e.TermID)
		}
		r.logger.Error("failed to update term",
			util.String("id", e.TermID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update term: %w", err)
	}
	return nil
}

// SetCurrent marks the given term as current and unsets others for the academic year.
// Uses SELECT FOR UPDATE to prevent race conditions. Assumes caller manages transaction.
// SetCurrent marks the given term as current and unsets others for the academic year.
// Uses SELECT FOR UPDATE to prevent race conditions. Must be called within a transaction.
func (r *termRepository) SetCurrent(ctx context.Context, db DBTX, academicYearID, termID uuid.UUID, updatedBy *uuid.UUID) error {
	// Ensure we are in a transaction
	if _, ok := db.(*sql.Tx); !ok {
		return fmt.Errorf("SetCurrent must be called within a transaction")
	}

	// Lock all rows for this academic year (only non-deleted)
	_, err := db.ExecContext(ctx, `SELECT 1 FROM academics.term WHERE academic_year_id = $1 AND deleted_at IS NULL FOR UPDATE`, academicYearID)
	if err != nil {
		r.logger.Error("failed to lock terms",
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("lock terms: %w", err)
	}

	// Unset all current for academic year (only non-deleted)
	_, err = db.ExecContext(ctx, `UPDATE academics.term SET is_current = false, updated_by = $2, updated_at = NOW() WHERE academic_year_id = $1 AND deleted_at IS NULL`, academicYearID, updatedBy)
	if err != nil {
		r.logger.Error("failed to unset current terms",
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("unset current: %w", err)
	}

	// Set the new current (only if not deleted)
	res, err := db.ExecContext(ctx, `UPDATE academics.term SET is_current = true, updated_by = $2, updated_at = NOW() WHERE term_id = $1 AND deleted_at IS NULL`, termID, updatedBy)
	if err != nil {
		r.logger.Error("failed to set current term",
			zap.String("id", termID.String()),
			zap.Error(err))
		return fmt.Errorf("set current: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("term %s not found or deleted", termID)
	}
	return nil
}

// GetByIDForUpdate retrieves a term with a row lock (only if not deleted).
func (r *termRepository) GetByIDForUpdate(ctx context.Context, db DBTX, id uuid.UUID) (*models.Term, error) {
	query := `
		SELECT term_id, academic_year_id, name, start_date, end_date,
		       is_current, created_at, updated_at, created_by, updated_by
		FROM academics.term
		WHERE term_id = $1 AND deleted_at IS NULL
		FOR UPDATE
	`
	var t models.Term
	var createdBy, updatedBy uuid.NullUUID
	err := db.QueryRowContext(ctx, query, id).Scan(
		&t.TermID, &t.AcademicYearID, &t.Name, &t.StartDate, &t.EndDate,
		&t.IsCurrent, &t.CreatedAt, &t.UpdatedAt, &createdBy, &updatedBy,
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
	if createdBy.Valid {
		t.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		t.UpdatedBy = &updatedBy.UUID
	}
	return &t, nil
}

// Delete soft-deletes a term.
func (r *termRepository) Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error {
	query := `UPDATE academics.term SET deleted_at = NOW(), updated_by = $2, updated_at = NOW() WHERE term_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, deletedBy)
	if err != nil {
		r.logger.Error("failed to delete term",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete term: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("term %s not found or already deleted", id)
	}
	return nil
}

// buildTermFilter constructs WHERE clause and arguments for TermFilter.
// Note: Does NOT include deleted_at; caller must add that.
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
	if filter.StartFrom != nil {
		conditions = append(conditions, fmt.Sprintf("start_date >= $%d", idx))
		args = append(args, *filter.StartFrom)
		idx++
	}
	if filter.EndTo != nil {
		conditions = append(conditions, fmt.Sprintf("end_date <= $%d", idx))
		args = append(args, *filter.EndTo)
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
func (r *termRepository) CheckOverlap(ctx context.Context, db DBTX, academicYearID uuid.UUID, start, end time.Time, excludeID uuid.UUID) (bool, error) {
	query := `
        SELECT EXISTS(
            SELECT 1 FROM academics.term
            WHERE academic_year_id = $1
              AND deleted_at IS NULL
              AND ($2::uuid IS NULL OR term_id != $2)
              AND NOT ($3 > end_date OR $4 < start_date)
        )
    `
	var exists bool
	err := db.QueryRowContext(ctx, query,
		academicYearID,
		excludeID,
		start,
		end,
	).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check term overlap",
			zap.String("academic_year_id", academicYearID.String()),
			zap.Time("start", start),
			zap.Time("end", end),
			zap.String("exclude_id", excludeID.String()),
			zap.Error(err))
		return false, fmt.Errorf("check term overlap: %w", err)
	}
	return exists, nil
}

// GetAcademicYearByTerm returns the academic year associated with a term.
func (r *termRepository) GetAcademicYearByTerm(ctx context.Context, db DBTX, termID uuid.UUID) (*models.AcademicYear, error) {
	query := `
		SELECT ay.academic_year_id, ay.company_id, ay.name, ay.start_date, ay.end_date,
		       ay.is_current, ay.created_at, ay.updated_at, ay.created_by, ay.updated_by
		FROM academics.term t
		JOIN academics.academic_year ay ON t.academic_year_id = ay.academic_year_id
		WHERE t.term_id = $1 AND t.deleted_at IS NULL AND ay.deleted_at IS NULL
	`
	var ay models.AcademicYear
	var createdBy, updatedBy uuid.NullUUID
	err := db.QueryRowContext(ctx, query, termID).Scan(
		&ay.AcademicYearID, &ay.CompanyID, &ay.Name, &ay.StartDate, &ay.EndDate,
		&ay.IsCurrent, &ay.CreatedAt, &ay.UpdatedAt, &createdBy, &updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get academic year by term",
			zap.String("term_id", termID.String()),
			zap.Error(err))
		return nil, fmt.Errorf("get academic year by term: %w", err)
	}
	if createdBy.Valid {
		ay.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		ay.UpdatedBy = &updatedBy.UUID
	}
	return &ay, nil
}

// GetByIDs returns a map of terms keyed by ID for the given IDs.
func (r *termRepository) GetByIDs(ctx context.Context, db DBTX, ids []uuid.UUID) (map[uuid.UUID]*models.Term, error) {
	if len(ids) == 0 {
		return map[uuid.UUID]*models.Term{}, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	query := fmt.Sprintf(`
        SELECT term_id, academic_year_id, name, start_date, end_date,
               is_current, created_at, updated_at, created_by, updated_by
        FROM academics.term
        WHERE term_id IN (%s) AND deleted_at IS NULL
    `, strings.Join(placeholders, ","))
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get terms by IDs: %w", err)
	}
	defer rows.Close()
	result := make(map[uuid.UUID]*models.Term)
	for rows.Next() {
		var t models.Term
		var createdBy, updatedBy uuid.NullUUID
		if err := rows.Scan(
			&t.TermID, &t.AcademicYearID, &t.Name, &t.StartDate, &t.EndDate,
			&t.IsCurrent, &t.CreatedAt, &t.UpdatedAt, &createdBy, &updatedBy,
		); err != nil {
			return nil, fmt.Errorf("scan term: %w", err)
		}
		if createdBy.Valid {
			t.CreatedBy = &createdBy.UUID
		}
		if updatedBy.Valid {
			t.UpdatedBy = &updatedBy.UUID
		}
		result[t.TermID] = &t
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// GetAcademicYearsByTermIDs returns a map of academic years keyed by term ID for the given term IDs.
func (r *termRepository) GetAcademicYearsByTermIDs(ctx context.Context, db DBTX, termIDs []uuid.UUID) (map[uuid.UUID]*models.AcademicYear, error) {
	if len(termIDs) == 0 {
		return map[uuid.UUID]*models.AcademicYear{}, nil
	}
	placeholders := make([]string, len(termIDs))
	args := make([]interface{}, len(termIDs))
	for i, id := range termIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	query := fmt.Sprintf(`
        SELECT t.term_id, ay.academic_year_id, ay.company_id, ay.name,
               ay.start_date, ay.end_date, ay.is_current,
               ay.created_at, ay.updated_at, ay.created_by, ay.updated_by
        FROM academics.term t
        JOIN academics.academic_year ay ON t.academic_year_id = ay.academic_year_id
        WHERE t.term_id IN (%s) AND t.deleted_at IS NULL AND ay.deleted_at IS NULL
    `, strings.Join(placeholders, ","))
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get academic years by term IDs: %w", err)
	}
	defer rows.Close()
	result := make(map[uuid.UUID]*models.AcademicYear)
	for rows.Next() {
		var termID uuid.UUID
		var ay models.AcademicYear
		var createdBy, updatedBy uuid.NullUUID
		if err := rows.Scan(
			&termID,
			&ay.AcademicYearID, &ay.CompanyID, &ay.Name,
			&ay.StartDate, &ay.EndDate, &ay.IsCurrent,
			&ay.CreatedAt, &ay.UpdatedAt, &createdBy, &updatedBy,
		); err != nil {
			return nil, fmt.Errorf("scan academic year: %w", err)
		}
		if createdBy.Valid {
			ay.CreatedBy = &createdBy.UUID
		}
		if updatedBy.Valid {
			ay.UpdatedBy = &updatedBy.UUID
		}
		result[termID] = &ay
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}
