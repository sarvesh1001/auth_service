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
	"auth-service/internal/client"
	"auth-service/internal/util"
)

// AcademicYearRepository defines methods for academic_year table.
type AcademicYearRepository interface {
	Create(ctx context.Context, e *models.AcademicYear) error
	BulkCreate(ctx context.Context, e []*models.AcademicYear) error
	Upsert(ctx context.Context, e *models.AcademicYear) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.AcademicYear, error)
	GetCurrent(ctx context.Context, companyID uuid.UUID) (*models.AcademicYear, error)
	GetByName(ctx context.Context, companyID uuid.UUID, name string) (*models.AcademicYear, error)
	List(ctx context.Context, filter AcademicYearFilter, p Pagination, s Sort) ([]*models.AcademicYear, error)
	ListByCompany(ctx context.Context, companyID uuid.UUID) ([]*models.AcademicYear, error)
	Count(ctx context.Context, filter AcademicYearFilter) (int64, error)
	Exists(ctx context.Context, companyID uuid.UUID, name string) (bool, error)
	Update(ctx context.Context, e *models.AcademicYear) error
	UpdateDates(ctx context.Context, id uuid.UUID, start, end time.Time) error
	SetCurrent(ctx context.Context, companyID, academicYearID uuid.UUID) error
	GetByIDForUpdate(ctx context.Context, id uuid.UUID) (*models.AcademicYear, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

type academicYearRepository struct {
	db     *client.PostgresClient
	logger *zap.Logger
}

// NewAcademicYearRepository creates a new academic year repository.
func NewAcademicYearRepository(db *client.PostgresClient, logger *zap.Logger) AcademicYearRepository {
	return &academicYearRepository{
		db:     db,
		logger: logger.Named("academic_year_repo"),
	}
}

// Create inserts a new academic year.
func (r *academicYearRepository) Create(ctx context.Context, e *models.AcademicYear) error {
	query := `
		INSERT INTO academics.academic_year (
			company_id, name, start_date, end_date, is_current, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
		RETURNING academic_year_id, created_at, updated_at
	`
	err := r.db.QueryRow(ctx, query,
		e.CompanyID, e.Name, e.StartDate, e.EndDate, e.IsCurrent,
	).Scan(&e.AcademicYearID, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create academic year",
			util.String("company_id", e.CompanyID.String()),
			util.String("name", e.Name),
			util.ErrorField(err))
		return fmt.Errorf("create academic year: %w", err)
	}
	return nil
}

// BulkCreate inserts multiple academic years in a single transaction.
func (r *academicYearRepository) BulkCreate(ctx context.Context, e []*models.AcademicYear) error {
	if len(e) == 0 {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO academics.academic_year (
			company_id, name, start_date, end_date, is_current, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
		RETURNING academic_year_id, created_at, updated_at
	`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, ay := range e {
		err = stmt.QueryRowContext(ctx,
			ay.CompanyID, ay.Name, ay.StartDate, ay.EndDate, ay.IsCurrent,
		).Scan(&ay.AcademicYearID, &ay.CreatedAt, &ay.UpdatedAt)
		if err != nil {
			r.logger.Error("bulk create failed",
				util.String("company_id", ay.CompanyID.String()),
				util.String("name", ay.Name),
				util.ErrorField(err))
			return fmt.Errorf("bulk create row: %w", err)
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// Upsert inserts or updates on conflict (company_id, name).
func (r *academicYearRepository) Upsert(ctx context.Context, e *models.AcademicYear) error {
	query := `
		INSERT INTO academics.academic_year (
			company_id, name, start_date, end_date, is_current, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
		ON CONFLICT (company_id, name) DO UPDATE SET
			start_date = EXCLUDED.start_date,
			end_date = EXCLUDED.end_date,
			is_current = EXCLUDED.is_current,
			updated_at = NOW()
		RETURNING academic_year_id, created_at, updated_at
	`
	err := r.db.QueryRow(ctx, query,
		e.CompanyID, e.Name, e.StartDate, e.EndDate, e.IsCurrent,
	).Scan(&e.AcademicYearID, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to upsert academic year",
			util.String("company_id", e.CompanyID.String()),
			util.String("name", e.Name),
			util.ErrorField(err))
		return fmt.Errorf("upsert academic year: %w", err)
	}
	return nil
}

// GetByID retrieves an academic year by its ID.
func (r *academicYearRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.AcademicYear, error) {
	query := `
		SELECT academic_year_id, company_id, name, start_date, end_date, is_current, created_at, updated_at
		FROM academics.academic_year
		WHERE academic_year_id = $1
	`
	var ay models.AcademicYear
	err := r.db.QueryRow(ctx, query, id).Scan(
		&ay.AcademicYearID, &ay.CompanyID, &ay.Name, &ay.StartDate, &ay.EndDate,
		&ay.IsCurrent, &ay.CreatedAt, &ay.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get academic year by ID",
			util.String("id", id.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get academic year by ID: %w", err)
	}
	return &ay, nil
}

// GetCurrent returns the current academic year for a company.
func (r *academicYearRepository) GetCurrent(ctx context.Context, companyID uuid.UUID) (*models.AcademicYear, error) {
	query := `
		SELECT academic_year_id, company_id, name, start_date, end_date, is_current, created_at, updated_at
		FROM academics.academic_year
		WHERE company_id = $1 AND is_current = true
		LIMIT 1
	`
	var ay models.AcademicYear
	err := r.db.QueryRow(ctx, query, companyID).Scan(
		&ay.AcademicYearID, &ay.CompanyID, &ay.Name, &ay.StartDate, &ay.EndDate,
		&ay.IsCurrent, &ay.CreatedAt, &ay.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get current academic year",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get current academic year: %w", err)
	}
	return &ay, nil
}

// GetByName retrieves an academic year by company and name.
func (r *academicYearRepository) GetByName(ctx context.Context, companyID uuid.UUID, name string) (*models.AcademicYear, error) {
	query := `
		SELECT academic_year_id, company_id, name, start_date, end_date, is_current, created_at, updated_at
		FROM academics.academic_year
		WHERE company_id = $1 AND name = $2
	`
	var ay models.AcademicYear
	err := r.db.QueryRow(ctx, query, companyID, name).Scan(
		&ay.AcademicYearID, &ay.CompanyID, &ay.Name, &ay.StartDate, &ay.EndDate,
		&ay.IsCurrent, &ay.CreatedAt, &ay.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get academic year by name",
			util.String("company_id", companyID.String()),
			util.String("name", name),
			util.ErrorField(err))
		return nil, fmt.Errorf("get academic year by name: %w", err)
	}
	return &ay, nil
}

// List returns academic years matching the filter with pagination and sorting.
func (r *academicYearRepository) List(ctx context.Context, filter AcademicYearFilter, p Pagination, s Sort) ([]*models.AcademicYear, error) {
	where, args := r.buildAcademicYearFilter(filter)
	orderBy := "ORDER BY " + s.Field + " " + s.Direction
	if s.Field == "" {
		orderBy = "ORDER BY created_at DESC"
	}
	query := fmt.Sprintf(`
		SELECT academic_year_id, company_id, name, start_date, end_date, is_current, created_at, updated_at
		FROM academics.academic_year
		%s %s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, p.Limit, p.Offset)
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list academic years",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list academic years: %w", err)
	}
	defer rows.Close()

	var result []*models.AcademicYear
	for rows.Next() {
		var ay models.AcademicYear
		if err := rows.Scan(
			&ay.AcademicYearID, &ay.CompanyID, &ay.Name, &ay.StartDate, &ay.EndDate,
			&ay.IsCurrent, &ay.CreatedAt, &ay.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan academic year: %w", err)
		}
		result = append(result, &ay)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// ListByCompany returns all academic years for a company.
func (r *academicYearRepository) ListByCompany(ctx context.Context, companyID uuid.UUID) ([]*models.AcademicYear, error) {
	return r.List(ctx, AcademicYearFilter{CompanyID: companyID}, Pagination{Limit: 1000}, Sort{Field: "start_date", Direction: "DESC"})
}

// Count returns the number of academic years matching the filter.
func (r *academicYearRepository) Count(ctx context.Context, filter AcademicYearFilter) (int64, error) {
	where, args := r.buildAcademicYearFilter(filter)
	query := fmt.Sprintf(`SELECT COUNT(*) FROM academics.academic_year %s`, where)
	var count int64
	err := r.db.QueryRow(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count academic years",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count academic years: %w", err)
	}
	return count, nil
}

// Exists checks if an academic year with given company and name exists.
func (r *academicYearRepository) Exists(ctx context.Context, companyID uuid.UUID, name string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM academics.academic_year WHERE company_id = $1 AND name = $2)`
	var exists bool
	err := r.db.QueryRow(ctx, query, companyID, name).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check existence of academic year",
			util.String("company_id", companyID.String()),
			util.String("name", name),
			util.ErrorField(err))
		return false, fmt.Errorf("exists academic year: %w", err)
	}
	return exists, nil
}

// Update modifies an existing academic year.
func (r *academicYearRepository) Update(ctx context.Context, e *models.AcademicYear) error {
	query := `
		UPDATE academics.academic_year
		SET name = $2, start_date = $3, end_date = $4, is_current = $5, updated_at = NOW()
		WHERE academic_year_id = $1
		RETURNING updated_at
	`
	err := r.db.QueryRow(ctx, query,
		e.AcademicYearID, e.Name, e.StartDate, e.EndDate, e.IsCurrent,
	).Scan(&e.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to update academic year",
			util.String("id", e.AcademicYearID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update academic year: %w", err)
	}
	return nil
}

// UpdateDates updates only start and end dates.
func (r *academicYearRepository) UpdateDates(ctx context.Context, id uuid.UUID, start, end time.Time) error {
	query := `
		UPDATE academics.academic_year
		SET start_date = $2, end_date = $3, updated_at = NOW()
		WHERE academic_year_id = $1
	`
	_, err := r.db.Exec(ctx, query, id, start, end)
	if err != nil {
		r.logger.Error("failed to update academic year dates",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("update academic year dates: %w", err)
	}
	return nil
}

// SetCurrent marks the given academic year as current and unsets others for the company.
func (r *academicYearRepository) SetCurrent(ctx context.Context, companyID, academicYearID uuid.UUID) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Unset all current for company
	_, err = tx.ExecContext(ctx, `UPDATE academics.academic_year SET is_current = false, updated_at = NOW() WHERE company_id = $1`, companyID)
	if err != nil {
		r.logger.Error("failed to unset current academic years",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("unset current: %w", err)
	}

	// Set the new current
	res, err := tx.ExecContext(ctx, `UPDATE academics.academic_year SET is_current = true, updated_at = NOW() WHERE academic_year_id = $1`, academicYearID)
	if err != nil {
		r.logger.Error("failed to set current academic year",
			util.String("id", academicYearID.String()),
			util.ErrorField(err))
		return fmt.Errorf("set current: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("academic year %s not found", academicYearID)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// GetByIDForUpdate retrieves an academic year with a row lock (FOR UPDATE).
// Caller must be inside a transaction.
func (r *academicYearRepository) GetByIDForUpdate(ctx context.Context, id uuid.UUID) (*models.AcademicYear, error) {
	query := `
		SELECT academic_year_id, company_id, name, start_date, end_date, is_current, created_at, updated_at
		FROM academics.academic_year
		WHERE academic_year_id = $1
		FOR UPDATE
	`
	var ay models.AcademicYear
	err := r.db.QueryRow(ctx, query, id).Scan(
		&ay.AcademicYearID, &ay.CompanyID, &ay.Name, &ay.StartDate, &ay.EndDate,
		&ay.IsCurrent, &ay.CreatedAt, &ay.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get academic year for update",
			util.String("id", id.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get academic year for update: %w", err)
	}
	return &ay, nil
}

// Delete removes an academic year.
func (r *academicYearRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM academics.academic_year WHERE academic_year_id = $1`
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete academic year",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete academic year: %w", err)
	}
	return nil
}

// buildAcademicYearFilter constructs the WHERE clause and arguments for AcademicYearFilter.
func (r *academicYearRepository) buildAcademicYearFilter(filter AcademicYearFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
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
