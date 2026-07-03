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

// Create inserts a new work center.
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
			work_center_code, company_id, name, description,
			timezone, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	exec := func(q string, args ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, args...)
		}
		return r.client.Exec(ctx, q, args...)
	}

	_, err := exec(query,
		wc.WorkCenterCode,
		wc.CompanyID,
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
			util.String("company_id", wc.CompanyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("create work center: %w", err)
	}
	return nil
}

// GetByCode retrieves a work center by company and code.
func (r *workCenterRepository) GetByCode(ctx context.Context, companyID uuid.UUID, workCenterCode string) (*models.WorkCenter, error) {
	query := `
		SELECT work_center_code, company_id, name, description,
		       timezone, is_active, created_at, updated_at
		FROM attendance.work_centers
		WHERE company_id = $1 AND work_center_code = $2
	`

	row := r.client.QueryRow(ctx, query, companyID, workCenterCode)
	return r.scanWorkCenter(row)
}

// Update updates an existing work center.
func (r *workCenterRepository) Update(ctx context.Context, tx *sql.Tx, wc *models.WorkCenter) error {
	wc.UpdatedAt = time.Now().UTC()

	query := `
		UPDATE attendance.work_centers SET
			name = $1,
			description = $2,
			timezone = $3,
			is_active = $4,
			updated_at = $5
		WHERE work_center_code = $6 AND company_id = $7
	`

	exec := func(q string, args ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, args...)
		}
		return r.client.Exec(ctx, q, args...)
	}

	result, err := exec(query,
		wc.Name,
		wc.Description,
		wc.Timezone,
		wc.IsActive,
		wc.UpdatedAt,
		wc.WorkCenterCode,
		wc.CompanyID,
	)
	if err != nil {
		r.logger.Error("failed to update work center",
			util.String("work_center_code", wc.WorkCenterCode),
			util.String("company_id", wc.CompanyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update work center: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("work center not found")
	}
	return nil
}

// Delete permanently removes a work center.
func (r *workCenterRepository) Delete(ctx context.Context, companyID uuid.UUID, workCenterCode string) error {
	query := `DELETE FROM attendance.work_centers WHERE company_id = $1 AND work_center_code = $2`
	result, err := r.client.Exec(ctx, query, companyID, workCenterCode)
	if err != nil {
		r.logger.Error("failed to delete work center",
			util.String("work_center_code", workCenterCode),
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete work center: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("work center not found")
	}
	return nil
}

// List retrieves work centers for a company with pagination.
func (r *workCenterRepository) List(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.WorkCenter, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	// Count total
	countQuery := `SELECT COUNT(*) FROM attendance.work_centers WHERE company_id = $1`
	var total int
	err := r.client.QueryRow(ctx, countQuery, companyID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count work centers: %w", err)
	}

	query := `
		SELECT work_center_code, company_id, name, description,
		       timezone, is_active, created_at, updated_at
		FROM attendance.work_centers
		WHERE company_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.client.Query(ctx, query, companyID, limit, offset)
	if err != nil {
		r.logger.Error("failed to list work centers",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, 0, fmt.Errorf("list work centers: %w", err)
	}
	defer rows.Close()

	var workCenters []*models.WorkCenter
	for rows.Next() {
		wc, err := r.scanWorkCenterFromRows(rows)
		if err != nil {
			return nil, 0, err
		}
		workCenters = append(workCenters, wc)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", err)
	}
	return workCenters, total, nil
}

// Search searches work centers with filters.
func (r *workCenterRepository) Search(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}, limit, offset int) ([]*models.WorkCenter, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	conditions := []string{"company_id = $1"}
	args := []interface{}{companyID}
	argIdx := 2

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

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM attendance.work_centers %s", whereClause)
	var total int
	err := r.client.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count search: %w", err)
	}

	// Query
	query := fmt.Sprintf(`
		SELECT work_center_code, company_id, name, description,
		       timezone, is_active, created_at, updated_at
		FROM attendance.work_centers %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)

	args = append(args, limit, offset)
	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to search work centers",
			util.String("company_id", companyID.String()),
			util.Any("filters", filters),
			util.ErrorField(err))
		return nil, 0, fmt.Errorf("search work centers: %w", err)
	}
	defer rows.Close()

	var workCenters []*models.WorkCenter
	for rows.Next() {
		wc, err := r.scanWorkCenterFromRows(rows)
		if err != nil {
			return nil, 0, err
		}
		workCenters = append(workCenters, wc)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", err)
	}
	return workCenters, total, nil
}

// GetActive retrieves all active work centers for a company.
func (r *workCenterRepository) GetActive(ctx context.Context, companyID uuid.UUID) ([]*models.WorkCenter, error) {
	query := `
		SELECT work_center_code, company_id, name, description,
		       timezone, is_active, created_at, updated_at
		FROM attendance.work_centers
		WHERE company_id = $1 AND is_active = true
		ORDER BY name ASC
	`

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		r.logger.Error("failed to get active work centers",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get active work centers: %w", err)
	}
	defer rows.Close()

	var workCenters []*models.WorkCenter
	for rows.Next() {
		wc, err := r.scanWorkCenterFromRows(rows)
		if err != nil {
			return nil, err
		}
		workCenters = append(workCenters, wc)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return workCenters, nil
}

// Exists checks if a work center exists by code.
func (r *workCenterRepository) Exists(ctx context.Context, companyID uuid.UUID, workCenterCode string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM attendance.work_centers WHERE company_id = $1 AND work_center_code = $2)`
	err := r.client.QueryRow(ctx, query, companyID, workCenterCode).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check existence: %w", err)
	}
	return exists, nil
}

// ExistsByName checks if a work center exists by name (within a company).
func (r *workCenterRepository) ExistsByName(ctx context.Context, companyID uuid.UUID, name string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM attendance.work_centers WHERE company_id = $1 AND name = $2)`
	err := r.client.QueryRow(ctx, query, companyID, name).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check name existence: %w", err)
	}
	return exists, nil
}

// HealthCheck verifies database connectivity.
func (r *workCenterRepository) HealthCheck(ctx context.Context) error {
	query := `SELECT 1 FROM attendance.work_centers LIMIT 1`
	_, err := r.client.Exec(ctx, query)
	if err != nil {
		r.logger.Error("health check failed", util.ErrorField(err))
		return fmt.Errorf("health check: %w", err)
	}
	return nil
}

// scanWorkCenter scans a single row from *sql.Row.
func (r *workCenterRepository) scanWorkCenter(row *sql.Row) (*models.WorkCenter, error) {
	var wc models.WorkCenter
	var description sql.NullString
	err := row.Scan(
		&wc.WorkCenterCode,
		&wc.CompanyID,
		&wc.Name,
		&description,
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
	if description.Valid {
		wc.Description = &description.String
	}
	return &wc, nil
}

// scanWorkCenterFromRows scans a row from *sql.Rows.
func (r *workCenterRepository) scanWorkCenterFromRows(rows *sql.Rows) (*models.WorkCenter, error) {
	var wc models.WorkCenter
	var description sql.NullString
	err := rows.Scan(
		&wc.WorkCenterCode,
		&wc.CompanyID,
		&wc.Name,
		&description,
		&wc.Timezone,
		&wc.IsActive,
		&wc.CreatedAt,
		&wc.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scan work center rows: %w", err)
	}
	if description.Valid {
		wc.Description = &description.String
	}
	return &wc, nil
}
