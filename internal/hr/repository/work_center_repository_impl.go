// auth-service/internal/hr/repository/work_center_repository_impl.go
package repository

import (
	"auth-service/internal/client"
	"auth-service/internal/hr/models/workcenter"
	"auth-service/internal/util"
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type WorkCenterRepositoryImpl struct {
	client    *client.PostgresClient
	logger    *zap.Logger
	stmtCache map[string]*sql.Stmt
	stmtMutex sync.RWMutex
}

func NewWorkCenterRepository(postgresClient *client.PostgresClient, logger *zap.Logger) WorkCenterRepository {
	repo := &WorkCenterRepositoryImpl{
		client:    postgresClient,
		logger:    logger,
		stmtCache: make(map[string]*sql.Stmt),
	}
	go repo.initializePreparedStatements(context.Background())
	return repo
}

func (r *WorkCenterRepositoryImpl) CreateWorkCenter(ctx context.Context, workCenter *workcenter.WorkCenter) error {
	startTime := time.Now()

	query := `
		INSERT INTO work_centers (
			work_center_code, company_id, name, description, 
			timezone, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err := r.client.Exec(ctx, query,
		workCenter.WorkCenterCode,
		workCenter.CompanyID,
		workCenter.Name,
		workCenter.Description,
		workCenter.Timezone,
		workCenter.IsActive,
		workCenter.CreatedAt,
		workCenter.UpdatedAt,
	)
	if err != nil {
		r.logger.Error("Failed to create work center",
			util.String("work_center_code", workCenter.WorkCenterCode),
			util.String("company_id", workCenter.CompanyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create work center: %w", err)
	}

	r.logger.Debug("Work center created",
		util.String("work_center_code", workCenter.WorkCenterCode),
		util.String("company_id", workCenter.CompanyID.String()),
		util.Duration("duration", time.Since(startTime)))
	return nil
}

func (r *WorkCenterRepositoryImpl) GetWorkCenterByCode(ctx context.Context, companyID uuid.UUID, workCenterCode string) (*workcenter.WorkCenter, error) {
	stmt, ok := r.getStmt("get_work_center_by_code")
	if !ok {
		return nil, fmt.Errorf("prepared statement not found: get_work_center_by_code")
	}

	rows, err := stmt.QueryContext(ctx, companyID, workCenterCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get work center: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanWorkCenter(rows)
	}
	return nil, fmt.Errorf("work center not found: %s", workCenterCode)
}

func (r *WorkCenterRepositoryImpl) GetWorkCenterByID(ctx context.Context, companyID uuid.UUID, workCenterCode string) (*workcenter.WorkCenter, error) {
	return r.GetWorkCenterByCode(ctx, companyID, workCenterCode)
}

func (r *WorkCenterRepositoryImpl) UpdateWorkCenter(ctx context.Context, workCenter *workcenter.WorkCenter) error {
	now := time.Now().UTC()
	workCenter.UpdatedAt = now

	query := `
		UPDATE work_centers SET
			name = $1, description = $2, timezone = $3,
			is_active = $4, updated_at = $5
		WHERE work_center_code = $6 AND company_id = $7`

	result, err := r.client.Exec(ctx, query,
		workCenter.Name,
		workCenter.Description,
		workCenter.Timezone,
		workCenter.IsActive,
		workCenter.UpdatedAt,
		workCenter.WorkCenterCode,
		workCenter.CompanyID,
	)
	if err != nil {
		return fmt.Errorf("failed to update work center: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("work center not found: %s", workCenter.WorkCenterCode)
	}
	return nil
}

func (r *WorkCenterRepositoryImpl) DeleteWorkCenter(ctx context.Context, companyID uuid.UUID, workCenterCode string) error {
	query := `DELETE FROM work_centers WHERE work_center_code = $1 AND company_id = $2`

	result, err := r.client.Exec(ctx, query, workCenterCode, companyID)
	if err != nil {
		return fmt.Errorf("failed to delete work center: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("work center not found: %s", workCenterCode)
	}
	return nil
}

func (r *WorkCenterRepositoryImpl) ListWorkCenters(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*workcenter.WorkCenter, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	var totalCount int
	countQuery := `SELECT COUNT(*) FROM work_centers WHERE company_id = $1`
	err := r.client.QueryRow(ctx, countQuery, companyID).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count work centers: %w", err)
	}

	query := `
		SELECT work_center_code, company_id, name, description,
		       timezone, is_active, created_at, updated_at
		FROM work_centers
		WHERE company_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`

	rows, err := r.client.Query(ctx, query, companyID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list work centers: %w", err)
	}
	defer rows.Close()

	workCenters := make([]*workcenter.WorkCenter, 0, limit)
	for rows.Next() {
		workCenter, err := r.scanWorkCenter(rows)
		if err != nil {
			r.logger.Warn("Failed to scan work center", util.ErrorField(err))
			continue
		}
		workCenters = append(workCenters, workCenter)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating work centers: %w", err)
	}

	return workCenters, totalCount, nil
}

func (r *WorkCenterRepositoryImpl) SearchWorkCenters(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}, limit, offset int) ([]*workcenter.WorkCenter, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	conditions := []string{"company_id = $1"}
	params := []interface{}{companyID}
	paramCount := 2

	for field, value := range filters {
		switch field {
		case "name":
			conditions = append(conditions, fmt.Sprintf("name ILIKE $%d", paramCount))
			params = append(params, "%"+value.(string)+"%")
			paramCount++
		case "is_active":
			conditions = append(conditions, fmt.Sprintf("is_active = $%d", paramCount))
			params = append(params, value)
			paramCount++
		case "work_center_code":
			conditions = append(conditions, fmt.Sprintf("work_center_code ILIKE $%d", paramCount))
			params = append(params, "%"+value.(string)+"%")
			paramCount++
		}
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM work_centers %s", whereClause)
	var totalCount int
	err := r.client.QueryRow(ctx, countQuery, params...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count search results: %w", err)
	}

	searchQuery := fmt.Sprintf(`
		SELECT work_center_code, company_id, name, description,
		       timezone, is_active, created_at, updated_at
		FROM work_centers %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, whereClause, paramCount, paramCount+1)

	params = append(params, limit, offset)
	rows, err := r.client.Query(ctx, searchQuery, params...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search work centers: %w", err)
	}
	defer rows.Close()

	workCenters := make([]*workcenter.WorkCenter, 0, limit)
	for rows.Next() {
		workCenter, err := r.scanWorkCenter(rows)
		if err != nil {
			r.logger.Warn("Failed to scan work center", util.ErrorField(err))
			continue
		}
		workCenters = append(workCenters, workCenter)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating search results: %w", err)
	}

	return workCenters, totalCount, nil
}

func (r *WorkCenterRepositoryImpl) CheckWorkCenterExists(ctx context.Context, companyID uuid.UUID, workCenterCode string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM work_centers WHERE company_id = $1 AND work_center_code = $2)`

	err := r.client.QueryRow(ctx, query, companyID, workCenterCode).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check work center existence: %w", err)
	}
	return exists, nil
}

func (r *WorkCenterRepositoryImpl) CheckWorkCenterNameExists(ctx context.Context, companyID uuid.UUID, name string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM work_centers WHERE company_id = $1 AND name = $2)`

	err := r.client.QueryRow(ctx, query, companyID, name).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check work center name existence: %w", err)
	}
	return exists, nil
}

func (r *WorkCenterRepositoryImpl) GetActiveWorkCenters(ctx context.Context, companyID uuid.UUID) ([]*workcenter.WorkCenter, error) {
	query := `
		SELECT work_center_code, company_id, name, description,
		       timezone, is_active, created_at, updated_at
		FROM work_centers
		WHERE company_id = $1 AND is_active = true
		ORDER BY name ASC`

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active work centers: %w", err)
	}
	defer rows.Close()

	workCenters := make([]*workcenter.WorkCenter, 0)
	for rows.Next() {
		workCenter, err := r.scanWorkCenter(rows)
		if err != nil {
			r.logger.Warn("Failed to scan work center", util.ErrorField(err))
			continue
		}
		workCenters = append(workCenters, workCenter)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating active work centers: %w", err)
	}

	return workCenters, nil
}

func (r *WorkCenterRepositoryImpl) scanWorkCenter(rows *sql.Rows) (*workcenter.WorkCenter, error) {
	var workCenter workcenter.WorkCenter
	var description sql.NullString

	err := rows.Scan(
		&workCenter.WorkCenterCode,
		&workCenter.CompanyID,
		&workCenter.Name,
		&description,
		&workCenter.Timezone,
		&workCenter.IsActive,
		&workCenter.CreatedAt,
		&workCenter.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	if description.Valid {
		workCenter.Description = &description.String
	}

	return &workCenter, nil
}

func (r *WorkCenterRepositoryImpl) initializePreparedStatements(ctx context.Context) {
	statements := map[string]string{
		"get_work_center_by_code": `
			SELECT work_center_code, company_id, name, description,
			       timezone, is_active, created_at, updated_at
			FROM work_centers WHERE company_id = $1 AND work_center_code = $2`,
	}

	for name, query := range statements {
		stmt, err := r.client.DB.PrepareContext(ctx, query)
		if err != nil {
			r.logger.Warn("Failed to prepare statement",
				util.String("statement", name),
				util.ErrorField(err))
			continue
		}

		r.stmtMutex.Lock()
		r.stmtCache[name] = stmt
		r.stmtMutex.Unlock()
	}

	r.logger.Info("Work center prepared statements initialized",
		util.Int("statements", len(r.stmtCache)))
}

func (r *WorkCenterRepositoryImpl) getStmt(name string) (*sql.Stmt, bool) {
	r.stmtMutex.RLock()
	defer r.stmtMutex.RUnlock()
	stmt, exists := r.stmtCache[name]
	return stmt, exists
}

func (r *WorkCenterRepositoryImpl) HealthCheck(ctx context.Context) error {
	query := `SELECT 1 FROM work_centers LIMIT 1`
	_, err := r.client.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("work center repository health check failed: %w", err)
	}
	return nil
}
