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

type AcademicYearRepository interface {
	Create(ctx context.Context, db DBTX, e *models.AcademicYear) error
	BulkCreate(ctx context.Context, db DBTX, e []*models.AcademicYear) error
	Upsert(ctx context.Context, db DBTX, e *models.AcademicYear) error
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.AcademicYear, error)
	GetCurrent(ctx context.Context, db DBTX, companyID uuid.UUID) (*models.AcademicYear, error)
	GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.AcademicYear, error)
	List(ctx context.Context, db DBTX, filter AcademicYearFilter, p Pagination, s Sort) ([]*models.AcademicYear, error)
	ListByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.AcademicYear, error)
	Count(ctx context.Context, db DBTX, filter AcademicYearFilter) (int64, error)
	Exists(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error)
	Update(ctx context.Context, db DBTX, e *models.AcademicYear) error
	UpdateDates(ctx context.Context, db DBTX, id uuid.UUID, start, end time.Time, updatedBy *uuid.UUID) error
	SetCurrent(ctx context.Context, db DBTX, companyID, academicYearID uuid.UUID, updatedBy *uuid.UUID) error
	UnsetCurrent(ctx context.Context, db DBTX, companyID uuid.UUID, updatedBy *uuid.UUID) error
	GetByIDForUpdate(ctx context.Context, db DBTX, id uuid.UUID) (*models.AcademicYear, error)
	Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error
	CheckOverlap(ctx context.Context, db DBTX, companyID uuid.UUID, start, end time.Time, excludeID uuid.UUID) (bool, error)
}

type academicYearRepository struct {
	logger *zap.Logger
}

func NewAcademicYearRepository(logger *zap.Logger) AcademicYearRepository {
	return &academicYearRepository{
		logger: logger.Named("academic_year_repo"),
	}
}

var allowedAcademicYearSortFields = map[string]bool{
	"created_at": true,
	"name":       true,
	"start_date": true,
	"end_date":   true,
	"is_current": true,
}

func (r *academicYearRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "created_at"
	}
	if !allowedAcademicYearSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY %s %s", field, dir), nil
}

func (r *academicYearRepository) validatePagination(p Pagination) (int, int) {
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

func (r *academicYearRepository) Create(ctx context.Context, db DBTX, e *models.AcademicYear) error {
	query := `
		INSERT INTO academics.academic_year (
			company_id, name, start_date, end_date, is_current,
			created_by, updated_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
		RETURNING academic_year_id, created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		e.CompanyID, e.Name, e.StartDate, e.EndDate, e.IsCurrent,
		e.CreatedBy, e.UpdatedBy,
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

func (r *academicYearRepository) BulkCreate(ctx context.Context, db DBTX, e []*models.AcademicYear) error {
	if len(e) == 0 {
		return nil
	}

	// db must be a transaction when called from service
	stmt, err := db.PrepareContext(ctx, `
		INSERT INTO academics.academic_year (
			company_id, name, start_date, end_date, is_current,
			created_by, updated_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
		RETURNING academic_year_id, created_at, updated_at
	`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, ay := range e {
		err = stmt.QueryRowContext(ctx,
			ay.CompanyID, ay.Name, ay.StartDate, ay.EndDate, ay.IsCurrent,
			ay.CreatedBy, ay.UpdatedBy,
		).Scan(&ay.AcademicYearID, &ay.CreatedAt, &ay.UpdatedAt)
		if err != nil {
			r.logger.Error("bulk create failed",
				util.String("company_id", ay.CompanyID.String()),
				util.String("name", ay.Name),
				util.ErrorField(err))
			return fmt.Errorf("bulk create row: %w", err)
		}
	}
	return nil
}

func (r *academicYearRepository) Upsert(ctx context.Context, db DBTX, e *models.AcademicYear) error {
	query := `
        INSERT INTO academics.academic_year (
            company_id, name, start_date, end_date, is_current,
            created_by, updated_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
        ON CONFLICT (company_id, name) WHERE deleted_at IS NULL
        DO UPDATE SET
            start_date = EXCLUDED.start_date,
            end_date = EXCLUDED.end_date,
            is_current = EXCLUDED.is_current,
            updated_by = EXCLUDED.updated_by,
            updated_at = NOW()
        RETURNING academic_year_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		e.CompanyID, e.Name, e.StartDate, e.EndDate, e.IsCurrent,
		e.CreatedBy, e.UpdatedBy,
	).Scan(&e.AcademicYearID, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to upsert academic year",
			zap.String("company_id", e.CompanyID.String()),
			zap.String("name", e.Name),
			zap.Error(err))
		return fmt.Errorf("upsert academic year: %w", err)
	}
	return nil
}

func (r *academicYearRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.AcademicYear, error) {
	query := `
		SELECT academic_year_id, company_id, name, start_date, end_date,
		       is_current, created_at, updated_at, created_by, updated_by
		FROM academics.academic_year
		WHERE academic_year_id = $1 AND deleted_at IS NULL
	`
	var ay models.AcademicYear
	var createdBy, updatedBy uuid.NullUUID
	err := db.QueryRowContext(ctx, query, id).Scan(
		&ay.AcademicYearID, &ay.CompanyID, &ay.Name, &ay.StartDate, &ay.EndDate,
		&ay.IsCurrent, &ay.CreatedAt, &ay.UpdatedAt, &createdBy, &updatedBy,
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
	if createdBy.Valid {
		ay.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		ay.UpdatedBy = &updatedBy.UUID
	}
	return &ay, nil
}

func (r *academicYearRepository) GetCurrent(ctx context.Context, db DBTX, companyID uuid.UUID) (*models.AcademicYear, error) {
	query := `
		SELECT academic_year_id, company_id, name, start_date, end_date,
		       is_current, created_at, updated_at, created_by, updated_by
		FROM academics.academic_year
		WHERE company_id = $1 AND is_current = true AND deleted_at IS NULL
		LIMIT 1
	`
	var ay models.AcademicYear
	var createdBy, updatedBy uuid.NullUUID
	err := db.QueryRowContext(ctx, query, companyID).Scan(
		&ay.AcademicYearID, &ay.CompanyID, &ay.Name, &ay.StartDate, &ay.EndDate,
		&ay.IsCurrent, &ay.CreatedAt, &ay.UpdatedAt, &createdBy, &updatedBy,
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
	if createdBy.Valid {
		ay.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		ay.UpdatedBy = &updatedBy.UUID
	}
	return &ay, nil
}

func (r *academicYearRepository) GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.AcademicYear, error) {
	query := `
		SELECT academic_year_id, company_id, name, start_date, end_date,
		       is_current, created_at, updated_at, created_by, updated_by
		FROM academics.academic_year
		WHERE company_id = $1 AND name ILIKE $2 AND deleted_at IS NULL
	`
	var ay models.AcademicYear
	var createdBy, updatedBy uuid.NullUUID
	err := db.QueryRowContext(ctx, query, companyID, name).Scan(
		&ay.AcademicYearID, &ay.CompanyID, &ay.Name, &ay.StartDate, &ay.EndDate,
		&ay.IsCurrent, &ay.CreatedAt, &ay.UpdatedAt, &createdBy, &updatedBy,
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
	if createdBy.Valid {
		ay.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		ay.UpdatedBy = &updatedBy.UUID
	}
	return &ay, nil
}
func (r *academicYearRepository) List(ctx context.Context, db DBTX, filter AcademicYearFilter, p Pagination, s Sort) ([]*models.AcademicYear, error) {
	where, args := r.buildAcademicYearFilter(filter)
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
		SELECT academic_year_id, company_id, name, start_date, end_date,
		       is_current, created_at, updated_at, created_by, updated_by
		FROM academics.academic_year
		%s %s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
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
		var createdBy, updatedBy uuid.NullUUID
		if err := rows.Scan(
			&ay.AcademicYearID, &ay.CompanyID, &ay.Name, &ay.StartDate, &ay.EndDate,
			&ay.IsCurrent, &ay.CreatedAt, &ay.UpdatedAt, &createdBy, &updatedBy,
		); err != nil {
			return nil, fmt.Errorf("scan academic year: %w", err)
		}
		if createdBy.Valid {
			ay.CreatedBy = &createdBy.UUID
		}
		if updatedBy.Valid {
			ay.UpdatedBy = &updatedBy.UUID
		}
		result = append(result, &ay)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *academicYearRepository) ListByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.AcademicYear, error) {
	return r.List(ctx, db, AcademicYearFilter{CompanyID: companyID}, Pagination{Limit: 1000}, Sort{Field: "start_date", Direction: "DESC"})
}

func (r *academicYearRepository) Count(ctx context.Context, db DBTX, filter AcademicYearFilter) (int64, error) {
	where, args := r.buildAcademicYearFilter(filter)
	if where == "" {
		where = "WHERE deleted_at IS NULL"
	} else {
		where += " AND deleted_at IS NULL"
	}
	query := fmt.Sprintf(`SELECT COUNT(*) FROM academics.academic_year %s`, where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count academic years",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count academic years: %w", err)
	}
	return count, nil
}

func (r *academicYearRepository) Exists(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM academics.academic_year WHERE company_id = $1 AND name = $2 AND deleted_at IS NULL)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, name).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check existence of academic year",
			util.String("company_id", companyID.String()),
			util.String("name", name),
			util.ErrorField(err))
		return false, fmt.Errorf("exists academic year: %w", err)
	}
	return exists, nil
}

func (r *academicYearRepository) Update(ctx context.Context, db DBTX, e *models.AcademicYear) error {
	query := `
		UPDATE academics.academic_year
		SET name = $2, start_date = $3, end_date = $4, is_current = $5,
		    updated_by = $6, updated_at = NOW()
		WHERE academic_year_id = $1 AND deleted_at IS NULL
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		e.AcademicYearID, e.Name, e.StartDate, e.EndDate, e.IsCurrent, e.UpdatedBy,
	).Scan(&e.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("academic year %s not found or deleted", e.AcademicYearID)
		}
		r.logger.Error("failed to update academic year",
			util.String("id", e.AcademicYearID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update academic year: %w", err)
	}
	return nil
}

func (r *academicYearRepository) UpdateDates(ctx context.Context, db DBTX, id uuid.UUID, start, end time.Time, updatedBy *uuid.UUID) error {
	query := `
		UPDATE academics.academic_year
		SET start_date = $2, end_date = $3, updated_by = $4, updated_at = NOW()
		WHERE academic_year_id = $1 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, id, start, end, updatedBy)
	if err != nil {
		r.logger.Error("failed to update academic year dates",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("update academic year dates: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("academic year %s not found or deleted", id)
	}
	return nil
}

func (r *academicYearRepository) SetCurrent(ctx context.Context, db DBTX, companyID, academicYearID uuid.UUID, updatedBy *uuid.UUID) error {
	// lock the company's rows
	_, err := db.ExecContext(ctx, `SELECT 1 FROM academics.academic_year WHERE company_id = $1 FOR UPDATE`, companyID)
	if err != nil {
		r.logger.Error("failed to lock academic years",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		return fmt.Errorf("lock academic years: %w", err)
	}
	// unset any current
	_, err = db.ExecContext(ctx, `UPDATE academics.academic_year SET is_current = false, updated_by = $2, updated_at = NOW() WHERE company_id = $1 AND deleted_at IS NULL`, companyID, updatedBy)
	if err != nil {
		r.logger.Error("failed to unset current academic years",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		return fmt.Errorf("unset current: %w", err)
	}
	// set the new current
	res, err := db.ExecContext(ctx, `UPDATE academics.academic_year SET is_current = true, updated_by = $2, updated_at = NOW() WHERE academic_year_id = $1 AND deleted_at IS NULL`, academicYearID, updatedBy)
	if err != nil {
		r.logger.Error("failed to set current academic year",
			zap.String("id", academicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("set current: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("academic year %s not found or deleted", academicYearID)
	}
	return nil
}

func (r *academicYearRepository) UnsetCurrent(ctx context.Context, db DBTX, companyID uuid.UUID, updatedBy *uuid.UUID) error {
	_, err := db.ExecContext(ctx, `
		UPDATE academics.academic_year
		SET is_current = false, updated_by = $2, updated_at = NOW()
		WHERE company_id = $1 AND deleted_at IS NULL
	`, companyID, updatedBy)
	if err != nil {
		r.logger.Error("failed to unset current academic years",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		return fmt.Errorf("unset current: %w", err)
	}
	return nil
}

func (r *academicYearRepository) GetByIDForUpdate(ctx context.Context, db DBTX, id uuid.UUID) (*models.AcademicYear, error) {
	query := `
		SELECT academic_year_id, company_id, name, start_date, end_date,
		       is_current, created_at, updated_at, created_by, updated_by
		FROM academics.academic_year
		WHERE academic_year_id = $1 AND deleted_at IS NULL
		FOR UPDATE
	`
	var ay models.AcademicYear
	var createdBy, updatedBy uuid.NullUUID
	err := db.QueryRowContext(ctx, query, id).Scan(
		&ay.AcademicYearID, &ay.CompanyID, &ay.Name, &ay.StartDate, &ay.EndDate,
		&ay.IsCurrent, &ay.CreatedAt, &ay.UpdatedAt, &createdBy, &updatedBy,
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
	if createdBy.Valid {
		ay.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		ay.UpdatedBy = &updatedBy.UUID
	}
	return &ay, nil
}

func (r *academicYearRepository) Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error {
	query := `UPDATE academics.academic_year SET deleted_at = NOW(), updated_by = $2, updated_at = NOW() WHERE academic_year_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, deletedBy)
	if err != nil {
		r.logger.Error("failed to delete academic year",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete academic year: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("academic year %s not found or already deleted", id)
	}
	return nil
}

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

func (r *academicYearRepository) CheckOverlap(ctx context.Context, db DBTX, companyID uuid.UUID, start, end time.Time, excludeID uuid.UUID) (bool, error) {
	if start.After(end) {
		return false, fmt.Errorf("start date must be before or equal to end date")
	}
	query := `
		SELECT EXISTS(
			SELECT 1
			FROM academics.academic_year
			WHERE company_id = $1
			  AND deleted_at IS NULL
			  AND start_date <= $3
			  AND end_date >= $2
	`
	args := []interface{}{companyID, start, end}
	argPos := 4
	if excludeID != uuid.Nil {
		query += fmt.Sprintf(" AND academic_year_id != $%d", argPos)
		args = append(args, excludeID)
		argPos++
	}
	query += ")"
	var exists bool
	err := db.QueryRowContext(ctx, query, args...).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check overlap",
			zap.String("company_id", companyID.String()),
			zap.Time("start", start),
			zap.Time("end", end),
			zap.String("exclude_id", excludeID.String()),
			zap.Error(err))
		return false, fmt.Errorf("check overlap: %w", err)
	}
	return exists, nil
}
