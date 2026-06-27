// repository/workflow_repository.go
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/models"
)

// ---------------------------------------------------------------------
// Interface
// ---------------------------------------------------------------------

type WorkflowRepository interface {
	Create(ctx context.Context, db DBTX, workflow *models.Workflow) error
	Update(ctx context.Context, db DBTX, workflow *models.Workflow) error
	Delete(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) error

	GetByID(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) (*models.Workflow, error)
	GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.Workflow, error)
	GetWithSteps(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) (*models.Workflow, error)

	List(ctx context.Context, db DBTX, filter WorkflowFilter, p Pagination, s Sort) ([]*models.Workflow, int64, error)
	ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Workflow, error)

	SetActive(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) error
	SetInactive(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) error

	Exists(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) (bool, error)
	ExistsByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error)

	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.Workflow, int64, error)

	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) (*models.Workflow, error)
}

// ---------------------------------------------------------------------
// Filter
// ---------------------------------------------------------------------

type WorkflowFilter struct {
	CompanyID    uuid.UUID
	WorkflowIDs  []uuid.UUID
	Name         *string
	TriggerEvent *string
	IsActive     *bool
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------

type workflowRepository struct {
	logger *zap.Logger
}

func NewWorkflowRepository(logger *zap.Logger) WorkflowRepository {
	return &workflowRepository{
		logger: logger.Named("subscription_workflow_repo"),
	}
}

const workflowTable = "subscription.workflows"

func (r *workflowRepository) scanWorkflow(s scanner) (*models.Workflow, error) {
	var w models.Workflow
	err := s.Scan(
		&w.WorkflowID,
		&w.CompanyID,
		&w.WorkflowName,
		&w.TriggerEvent,
		&w.IsActive,
		&w.CreatedAt,
		&w.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan workflow: %w", err)
	}
	return &w, nil
}

func (r *workflowRepository) buildWorkflowFilter(filter WorkflowFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if len(filter.WorkflowIDs) > 0 {
		placeholders := make([]string, len(filter.WorkflowIDs))
		for i, id := range filter.WorkflowIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("workflow_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.Name != nil {
		conds = append(conds, fmt.Sprintf("workflow_name = $%d", idx))
		args = append(args, *filter.Name)
		idx++
	}
	if filter.TriggerEvent != nil {
		conds = append(conds, fmt.Sprintf("trigger_event = $%d", idx))
		args = append(args, *filter.TriggerEvent)
		idx++
	}
	if filter.IsActive != nil {
		conds = append(conds, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

var workflowAllowedSort = map[string]bool{
	"workflow_id":   true,
	"workflow_name": true,
	"trigger_event": true,
	"is_active":     true,
	"created_at":    true,
	"updated_at":    true,
}

// ---------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------

func (r *workflowRepository) Create(ctx context.Context, db DBTX, workflow *models.Workflow) error {
	query := `
		INSERT INTO subscription.workflows (
			workflow_id, company_id, workflow_name, trigger_event,
			is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		workflow.WorkflowID,
		workflow.CompanyID,
		workflow.WorkflowName,
		workflow.TriggerEvent,
		workflow.IsActive,
	).Scan(&workflow.CreatedAt, &workflow.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create workflow: %w", err)
	}
	return nil
}

func (r *workflowRepository) Update(ctx context.Context, db DBTX, workflow *models.Workflow) error {
	query := `
		UPDATE subscription.workflows SET
			workflow_name = $3,
			trigger_event = $4,
			is_active = $5,
			updated_at = NOW()
		WHERE workflow_id = $1 AND company_id = $2
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		workflow.WorkflowID,
		workflow.CompanyID,
		workflow.WorkflowName,
		workflow.TriggerEvent,
		workflow.IsActive,
	).Scan(&workflow.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return fmt.Errorf("update workflow: %w", err)
	}
	return nil
}

func (r *workflowRepository) Delete(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) error {
	// First delete all steps
	stepRepo := NewWorkflowStepRepository(r.logger)
	if _, err := stepRepo.DeleteByWorkflow(ctx, db, companyID, workflowID); err != nil {
		return fmt.Errorf("delete workflow steps: %w", err)
	}

	query := `DELETE FROM subscription.workflows WHERE workflow_id = $1 AND company_id = $2`
	result, err := db.ExecContext(ctx, query, workflowID, companyID)
	if err != nil {
		return fmt.Errorf("delete workflow: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------
// Single Fetch
// ---------------------------------------------------------------------

func (r *workflowRepository) GetByID(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) (*models.Workflow, error) {
	query := `
		SELECT workflow_id, company_id, workflow_name, trigger_event,
			is_active, created_at, updated_at
		FROM subscription.workflows
		WHERE workflow_id = $1 AND company_id = $2
	`
	row := db.QueryRowContext(ctx, query, workflowID, companyID)
	return r.scanWorkflow(row)
}

func (r *workflowRepository) GetByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (*models.Workflow, error) {
	query := `
		SELECT workflow_id, company_id, workflow_name, trigger_event,
			is_active, created_at, updated_at
		FROM subscription.workflows
		WHERE company_id = $1 AND workflow_name = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, name)
	return r.scanWorkflow(row)
}

// ---------------------------------------------------------------------
// Aggregate Loading
// ---------------------------------------------------------------------

// GetWithSteps loads a workflow with its steps (converts pointers to values)
func (r *workflowRepository) GetWithSteps(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) (*models.Workflow, error) {
	workflow, err := r.GetByID(ctx, db, companyID, workflowID)
	if err != nil {
		return nil, err
	}

	stepRepo := NewWorkflowStepRepository(r.logger)
	stepPtrs, err := stepRepo.ListByWorkflow(ctx, db, companyID, workflowID)
	if err != nil {
		return nil, fmt.Errorf("load workflow steps: %w", err)
	}

	// Convert []*models.WorkflowStep to []models.WorkflowStep
	steps := make([]models.WorkflowStep, len(stepPtrs))
	for i, s := range stepPtrs {
		if s != nil {
			steps[i] = *s
		}
	}
	workflow.Steps = steps
	return workflow, nil
}

// ---------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------

func (r *workflowRepository) List(ctx context.Context, db DBTX, filter WorkflowFilter, p Pagination, s Sort) ([]*models.Workflow, int64, error) {
	where, args := r.buildWorkflowFilter(filter)
	if where == "" {
		return nil, 0, fmt.Errorf("company_id is required in filter")
	}

	orderBy, err := validateSort(s, workflowAllowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY workflow_name"
	}

	limit, offset := validatePagination(p)

	// Count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", workflowTable, where)
	var total int64
	if err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count workflows: %w", err)
	}
	if total == 0 {
		return []*models.Workflow{}, 0, nil
	}

	// Data
	query := fmt.Sprintf(`
		SELECT workflow_id, company_id, workflow_name, trigger_event,
			is_active, created_at, updated_at
		FROM %s
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, workflowTable, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list workflows: %w", err)
	}
	defer rows.Close()

	var result []*models.Workflow
	for rows.Next() {
		w, err := r.scanWorkflow(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, w)
	}
	return result, total, rows.Err()
}

func (r *workflowRepository) ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Workflow, error) {
	filter := WorkflowFilter{
		CompanyID: companyID,
		IsActive:  ptrBool(true),
	}
	workflows, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{})
	return workflows, err
}

// ---------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------

func (r *workflowRepository) SetActive(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) error {
	query := `
		UPDATE subscription.workflows
		SET is_active = true, updated_at = NOW()
		WHERE workflow_id = $1 AND company_id = $2
	`
	result, err := db.ExecContext(ctx, query, workflowID, companyID)
	if err != nil {
		return fmt.Errorf("set active: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *workflowRepository) SetInactive(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) error {
	query := `
		UPDATE subscription.workflows
		SET is_active = false, updated_at = NOW()
		WHERE workflow_id = $1 AND company_id = $2
	`
	result, err := db.ExecContext(ctx, query, workflowID, companyID)
	if err != nil {
		return fmt.Errorf("set inactive: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

func (r *workflowRepository) Exists(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.workflows WHERE workflow_id = $1 AND company_id = $2)`
	err := db.QueryRowContext(ctx, query, workflowID, companyID).Scan(&exists)
	return exists, err
}

func (r *workflowRepository) ExistsByName(ctx context.Context, db DBTX, companyID uuid.UUID, name string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.workflows WHERE company_id = $1 AND workflow_name = $2)`
	err := db.QueryRowContext(ctx, query, companyID, name).Scan(&exists)
	return exists, err
}

// ---------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------

func (r *workflowRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.Workflow, int64, error) {
	pattern := "%" + query + "%"
	where := "WHERE company_id = $1 AND (workflow_name ILIKE $2 OR trigger_event ILIKE $2)"
	args := []interface{}{companyID, pattern}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", workflowTable, where)
	var total int64
	if err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("search workflows count: %w", err)
	}
	if total == 0 {
		return []*models.Workflow{}, 0, nil
	}

	baseQuery := `
		SELECT workflow_id, company_id, workflow_name, trigger_event,
			is_active, created_at, updated_at
		FROM subscription.workflows
	`
	querySQL := fmt.Sprintf(`%s %s ORDER BY workflow_name LIMIT $%d OFFSET $%d`, baseQuery, where, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search workflows: %w", err)
	}
	defer rows.Close()

	var result []*models.Workflow
	for rows.Next() {
		w, err := r.scanWorkflow(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, w)
	}
	return result, total, rows.Err()
}

// ---------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------

func (r *workflowRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) (*models.Workflow, error) {
	query := `
		SELECT workflow_id, company_id, workflow_name, trigger_event,
			is_active, created_at, updated_at
		FROM subscription.workflows
		WHERE workflow_id = $1 AND company_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, workflowID, companyID)
	return r.scanWorkflow(row)
}
