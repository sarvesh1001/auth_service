package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/client"
	"auth-service/internal/util"
)

type workCenterRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewWorkCenterRepository(pg *client.PostgresClient, logger *zap.Logger) repository.WorkCenterRepository {
	return &workCenterRepository{
		client: pg,
		logger: logger.Named("work_center_repo"),
	}
}

const workCenterColumns = `
	work_center_code, company_id, location_id, name, description,
	timezone, is_active, created_at, updated_at
`

func (r *workCenterRepository) Create(ctx context.Context, tx *sql.Tx, wc *models.WorkCenter) error {
	now := time.Now().UTC()
	if wc.CreatedAt.IsZero() {
		wc.CreatedAt = now
	}
	if wc.UpdatedAt.IsZero() {
		wc.UpdatedAt = now
	}

	query := `
		INSERT INTO attendance.work_centers (
			work_center_code, company_id, location_id, name, description,
			timezone, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	exec := func(q string, a ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, a...)
		}
		return r.client.Exec(ctx, q, a...)
	}

	_, err := exec(query,
		wc.WorkCenterCode,
		wc.CompanyID,
		wc.LocationID,
		wc.Name,
		wc.Description,
		wc.Timezone,
		wc.IsActive,
		wc.CreatedAt,
		wc.UpdatedAt,
	)
	if err != nil {
		r.logger.Error("failed to create work center",
			util.String("work_center_code", wc.WorkCenterCode),
			util.ErrorField(err))
		return fmt.Errorf("create work center: %w", err)
	}
	return nil
}

func (r *workCenterRepository) GetByCode(ctx context.Context, companyID uuid.UUID, workCenterCode string) (*models.WorkCenter, error) {
	query := `SELECT ` + workCenterColumns + `
		FROM attendance.work_centers
		WHERE company_id = $1 AND work_center_code = $2`
	row := r.client.QueryRow(ctx, query, companyID, workCenterCode)
	return r.scanWorkCenter(row)
}

func (r *workCenterRepository) Update(ctx context.Context, tx *sql.Tx, wc *models.WorkCenter) error {
	wc.UpdatedAt = time.Now().UTC()
	query := `
		UPDATE attendance.work_centers SET
			location_id = $1,
			name = $2,
			description = $3,
			timezone = $4,
			is_active = $5,
			updated_at = $6
		WHERE work_center_code = $7 AND company_id = $8`
	exec := func(q string, a ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, a...)
		}
		return r.client.Exec(ctx, q, a...)
	}
	result, err := exec(query,
		wc.LocationID,
		wc.Name,
		wc.Description,
		wc.Timezone,
		wc.IsActive,
		wc.UpdatedAt,
		wc.WorkCenterCode,
		wc.CompanyID,
	)
	if err != nil {
		return fmt.Errorf("update work center: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return errors.New("work center not found")
	}
	return nil
}

func (r *workCenterRepository) Delete(ctx context.Context, companyID uuid.UUID, workCenterCode string) error {
	result, err := r.client.Exec(ctx,
		`DELETE FROM attendance.work_centers WHERE company_id = $1 AND work_center_code = $2`,
		companyID, workCenterCode)
	if err != nil {
		return fmt.Errorf("delete work center: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return errors.New("work center not found")
	}
	return nil
}

// List — locationID == nil means no filter.
func (r *workCenterRepository) List(ctx context.Context, companyID uuid.UUID, locationID *uuid.UUID, limit, offset int) ([]*models.WorkCenter, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	var locArg interface{}
	if locationID != nil {
		locArg = *locationID
	}

	var total int
	if err := r.client.QueryRow(ctx, `
		SELECT COUNT(*) FROM attendance.work_centers
		WHERE company_id = $1
		  AND ($2::uuid IS NULL OR location_id = $2)`,
		companyID, locArg).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count work centers: %w", err)
	}

	query := `SELECT ` + workCenterColumns + `
		FROM attendance.work_centers
		WHERE company_id = $1
		  AND ($2::uuid IS NULL OR location_id = $2)
		ORDER BY created_at DESC
		LIMIT $3 OFFSET $4`
	rows, err := r.client.Query(ctx, query, companyID, locArg, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list work centers: %w", err)
	}
	defer rows.Close()

	wcs, err := r.scanWorkCenters(rows)
	if err != nil {
		return nil, 0, err
	}
	return wcs, total, nil
}

// Search — locationID == nil means no filter.
func (r *workCenterRepository) Search(ctx context.Context, companyID uuid.UUID, locationID *uuid.UUID, filters map[string]interface{}, limit, offset int) ([]*models.WorkCenter, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	conditions := []string{"company_id = $1"}
	args := []interface{}{companyID}
	argIdx := 2

	if locationID != nil {
		conditions = append(conditions, fmt.Sprintf("($%d::uuid IS NULL OR location_id = $%d)", argIdx, argIdx))
		args = append(args, *locationID)
		argIdx++
	} else {
		conditions = append(conditions, fmt.Sprintf("($%d::uuid IS NULL OR location_id IS NOT NULL OR location_id IS NULL)", argIdx))
		args = append(args, nil)
		argIdx++
	}

	for field, value := range filters {
		switch field {
		case "name":
			conditions = append(conditions, fmt.Sprintf("name ILIKE $%d", argIdx))
			args = append(args, "%"+value.(string)+"%")
			argIdx++
		case "is_active":
			conditions = append(conditions, fmt.Sprintf("is_active = $%d", argIdx))
			args = append(args, value)
			argIdx++
		case "work_center_code":
			conditions = append(conditions, fmt.Sprintf("work_center_code ILIKE $%d", argIdx))
			args = append(args, "%"+value.(string)+"%")
			argIdx++
		}
	}

	where := "WHERE " + strings.Join(conditions, " AND ")

	var total int
	if err := r.client.QueryRow(ctx, "SELECT COUNT(*) FROM attendance.work_centers "+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count search: %w", err)
	}

	query := fmt.Sprintf(`SELECT %s FROM attendance.work_centers %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, workCenterColumns, where, argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search work centers: %w", err)
	}
	defer rows.Close()

	wcs, err := r.scanWorkCenters(rows)
	if err != nil {
		return nil, 0, err
	}
	return wcs, total, nil
}

// GetActive — locationID == nil means no filter.
func (r *workCenterRepository) GetActive(ctx context.Context, companyID uuid.UUID, locationID *uuid.UUID) ([]*models.WorkCenter, error) {
	var locArg interface{}
	if locationID != nil {
		locArg = *locationID
	}
	query := `SELECT ` + workCenterColumns + `
		FROM attendance.work_centers
		WHERE company_id = $1
		  AND is_active = true
		  AND ($2::uuid IS NULL OR location_id = $2)
		ORDER BY name ASC`
	rows, err := r.client.Query(ctx, query, companyID, locArg)
	if err != nil {
		return nil, fmt.Errorf("get active work centers: %w", err)
	}
	defer rows.Close()
	return r.scanWorkCenters(rows)
}

func (r *workCenterRepository) Exists(ctx context.Context, companyID uuid.UUID, workCenterCode string) (bool, error) {
	var exists bool
	err := r.client.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM attendance.work_centers WHERE company_id = $1 AND work_center_code = $2)`,
		companyID, workCenterCode).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check existence: %w", err)
	}
	return exists, nil
}

func (r *workCenterRepository) ExistsByName(ctx context.Context, companyID uuid.UUID, name string) (bool, error) {
	var exists bool
	err := r.client.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM attendance.work_centers WHERE company_id = $1 AND name = $2)`,
		companyID, name).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check name existence: %w", err)
	}
	return exists, nil
}

func (r *workCenterRepository) HealthCheck(ctx context.Context) error {
	_, err := r.client.Exec(ctx, `SELECT 1 FROM attendance.work_centers LIMIT 1`)
	if err != nil {
		return fmt.Errorf("health check: %w", err)
	}
	return nil
}

func (r *workCenterRepository) scanWorkCenter(row *sql.Row) (*models.WorkCenter, error) {
	var wc models.WorkCenter
	var desc sql.NullString
	var locationID sql.NullString
	err := row.Scan(
		&wc.WorkCenterCode,
		&wc.CompanyID,
		&locationID,
		&wc.Name,
		&desc,
		&wc.Timezone,
		&wc.IsActive,
		&wc.CreatedAt,
		&wc.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan work center: %w", err)
	}
	if desc.Valid {
		wc.Description = &desc.String
	}
	if locationID.Valid && locationID.String != "" {
		if id, err := uuid.Parse(locationID.String); err == nil {
			wc.LocationID = &id
		}
	}
	return &wc, nil
}

func (r *workCenterRepository) scanWorkCenters(rows *sql.Rows) ([]*models.WorkCenter, error) {
	var wcs []*models.WorkCenter
	for rows.Next() {
		var wc models.WorkCenter
		var desc sql.NullString
		var locationID sql.NullString
		err := rows.Scan(
			&wc.WorkCenterCode,
			&wc.CompanyID,
			&locationID,
			&wc.Name,
			&desc,
			&wc.Timezone,
			&wc.IsActive,
			&wc.CreatedAt,
			&wc.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan work center rows: %w", err)
		}
		if desc.Valid {
			wc.Description = &desc.String
		}
		if locationID.Valid && locationID.String != "" {
			if id, err := uuid.Parse(locationID.String); err == nil {
				wc.LocationID = &id
			}
		}
		wcs = append(wcs, &wc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return wcs, nil
}
