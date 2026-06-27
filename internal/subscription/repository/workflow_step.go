// repository/workflow_step_repository.go
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

type WorkflowStepRepository interface {
	Create(ctx context.Context, db DBTX, step *models.WorkflowStep) error
	Update(ctx context.Context, db DBTX, step *models.WorkflowStep) error
	Delete(ctx context.Context, db DBTX, companyID, workflowStepID uuid.UUID) error
	DeleteByWorkflow(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) (int64, error)

	GetByID(ctx context.Context, db DBTX, companyID, workflowStepID uuid.UUID) (*models.WorkflowStep, error)
	GetByWorkflow(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) ([]*models.WorkflowStep, error)
	GetByStepOrder(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID, stepOrder int) (*models.WorkflowStep, error)
	GetFirstStep(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) (*models.WorkflowStep, error)
	GetLastStep(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) (*models.WorkflowStep, error)

	List(ctx context.Context, db DBTX, filter WorkflowStepFilter, p Pagination, s Sort) ([]*models.WorkflowStep, int64, error)
	ListByWorkflow(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) ([]*models.WorkflowStep, error)
	ListActive(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) ([]*models.WorkflowStep, error)

	UpdateStepOrder(ctx context.Context, db DBTX, companyID, workflowStepID uuid.UUID, newOrder int) error
	MoveUp(ctx context.Context, db DBTX, companyID, workflowStepID uuid.UUID) error
	MoveDown(ctx context.Context, db DBTX, companyID, workflowStepID uuid.UUID) error
	SetActive(ctx context.Context, db DBTX, companyID, workflowStepID uuid.UUID) error
	SetInactive(ctx context.Context, db DBTX, companyID, workflowStepID uuid.UUID) error

	Exists(ctx context.Context, db DBTX, companyID, workflowStepID uuid.UUID) (bool, error)
	ExistsStepOrder(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID, stepOrder int) (bool, error)

	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.WorkflowStep, int64, error)

	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, workflowStepID uuid.UUID) (*models.WorkflowStep, error)
}

// ---------------------------------------------------------------------
// Filter
// ---------------------------------------------------------------------

type WorkflowStepFilter struct {
	CompanyID       uuid.UUID
	WorkflowStepIDs []uuid.UUID
	WorkflowID      *uuid.UUID
	StepOrder       *int
	StepType        *string
	IsActive        *bool
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------

type workflowStepRepository struct {
	logger *zap.Logger
}

func NewWorkflowStepRepository(logger *zap.Logger) WorkflowStepRepository {
	return &workflowStepRepository{
		logger: logger.Named("subscription_workflow_step_repo"),
	}
}

const workflowStepTable = "subscription.workflow_steps"

func (r *workflowStepRepository) scanWorkflowStep(s scanner) (*models.WorkflowStep, error) {
	var step models.WorkflowStep
	var dependsOnStep sql.NullString
	var config string

	err := s.Scan(
		&step.StepID,
		&step.WorkflowID,
		&step.StepOrder,
		&step.StepType,
		&config,
		&dependsOnStep,
		&step.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan workflow step: %w", err)
	}
	if dependsOnStep.Valid {
		if uid, err := uuid.Parse(dependsOnStep.String); err == nil {
			step.DependsOnStep = &uid
		}
	}
	step.Config = []byte(config)
	return &step, nil
}

func (r *workflowStepRepository) buildWorkflowStepFilter(filter WorkflowStepFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		// will join later
	}
	if len(filter.WorkflowStepIDs) > 0 {
		placeholders := make([]string, len(filter.WorkflowStepIDs))
		for i, id := range filter.WorkflowStepIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("ws.step_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.WorkflowID != nil {
		conds = append(conds, fmt.Sprintf("ws.workflow_id = $%d", idx))
		args = append(args, *filter.WorkflowID)
		idx++
	}
	if filter.StepOrder != nil {
		conds = append(conds, fmt.Sprintf("ws.step_order = $%d", idx))
		args = append(args, *filter.StepOrder)
		idx++
	}
	if filter.StepType != nil {
		conds = append(conds, fmt.Sprintf("ws.step_type = $%d", idx))
		args = append(args, *filter.StepType)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

var workflowStepAllowedSort = map[string]bool{
	"step_id":    true,
	"step_order": true,
	"step_type":  true,
	"created_at": true,
}

// ---------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------

func (r *workflowStepRepository) Create(ctx context.Context, db DBTX, step *models.WorkflowStep) error {
	query := `
		INSERT INTO subscription.workflow_steps (
			step_id, workflow_id, step_order, step_type,
			config, depends_on_step, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, NOW())
	`
	_, err := db.ExecContext(ctx, query,
		step.StepID,
		step.WorkflowID,
		step.StepOrder,
		step.StepType,
		step.Config,
		step.DependsOnStep,
	)
	if err != nil {
		return fmt.Errorf("create workflow step: %w", err)
	}
	return nil
}

func (r *workflowStepRepository) Update(ctx context.Context, db DBTX, step *models.WorkflowStep) error {
	query := `
		UPDATE subscription.workflow_steps SET
			workflow_id = $2,
			step_order = $3,
			step_type = $4,
			config = $5,
			depends_on_step = $6
		WHERE step_id = $1
	`
	result, err := db.ExecContext(ctx, query,
		step.StepID,
		step.WorkflowID,
		step.StepOrder,
		step.StepType,
		step.Config,
		step.DependsOnStep,
	)
	if err != nil {
		return fmt.Errorf("update workflow step: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *workflowStepRepository) Delete(ctx context.Context, db DBTX, companyID, workflowStepID uuid.UUID) error {
	query := `
		DELETE FROM subscription.workflow_steps ws
		USING subscription.workflows w
		WHERE ws.workflow_id = w.workflow_id
		AND w.company_id = $1
		AND ws.step_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, workflowStepID)
	if err != nil {
		return fmt.Errorf("delete workflow step: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *workflowStepRepository) DeleteByWorkflow(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) (int64, error) {
	query := `
		DELETE FROM subscription.workflow_steps ws
		USING subscription.workflows w
		WHERE ws.workflow_id = w.workflow_id
		AND w.company_id = $1
		AND w.workflow_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, workflowID)
	if err != nil {
		return 0, fmt.Errorf("delete workflow steps: %w", err)
	}
	rows, _ := result.RowsAffected()
	return rows, nil
}

// ---------------------------------------------------------------------
// Single Fetch
// ---------------------------------------------------------------------

func (r *workflowStepRepository) GetByID(ctx context.Context, db DBTX, companyID, workflowStepID uuid.UUID) (*models.WorkflowStep, error) {
	query := `
		SELECT ws.step_id, ws.workflow_id, ws.step_order, ws.step_type,
			ws.config, ws.depends_on_step, ws.created_at
		FROM subscription.workflow_steps ws
		JOIN subscription.workflows w ON ws.workflow_id = w.workflow_id
		WHERE ws.step_id = $1 AND w.company_id = $2
	`
	row := db.QueryRowContext(ctx, query, workflowStepID, companyID)
	return r.scanWorkflowStep(row)
}

func (r *workflowStepRepository) GetByWorkflow(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) ([]*models.WorkflowStep, error) {
	filter := WorkflowStepFilter{
		CompanyID:  companyID,
		WorkflowID: &workflowID,
	}
	steps, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "step_order", Direction: "ASC"})
	return steps, err
}

func (r *workflowStepRepository) GetByStepOrder(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID, stepOrder int) (*models.WorkflowStep, error) {
	query := `
		SELECT ws.step_id, ws.workflow_id, ws.step_order, ws.step_type,
			ws.config, ws.depends_on_step, ws.created_at
		FROM subscription.workflow_steps ws
		JOIN subscription.workflows w ON ws.workflow_id = w.workflow_id
		WHERE w.company_id = $1 AND w.workflow_id = $2 AND ws.step_order = $3
	`
	row := db.QueryRowContext(ctx, query, companyID, workflowID, stepOrder)
	return r.scanWorkflowStep(row)
}

func (r *workflowStepRepository) GetFirstStep(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) (*models.WorkflowStep, error) {
	query := `
		SELECT ws.step_id, ws.workflow_id, ws.step_order, ws.step_type,
			ws.config, ws.depends_on_step, ws.created_at
		FROM subscription.workflow_steps ws
		JOIN subscription.workflows w ON ws.workflow_id = w.workflow_id
		WHERE w.company_id = $1 AND w.workflow_id = $2
		ORDER BY ws.step_order ASC
		LIMIT 1
	`
	row := db.QueryRowContext(ctx, query, companyID, workflowID)
	return r.scanWorkflowStep(row)
}

func (r *workflowStepRepository) GetLastStep(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) (*models.WorkflowStep, error) {
	query := `
		SELECT ws.step_id, ws.workflow_id, ws.step_order, ws.step_type,
			ws.config, ws.depends_on_step, ws.created_at
		FROM subscription.workflow_steps ws
		JOIN subscription.workflows w ON ws.workflow_id = w.workflow_id
		WHERE w.company_id = $1 AND w.workflow_id = $2
		ORDER BY ws.step_order DESC
		LIMIT 1
	`
	row := db.QueryRowContext(ctx, query, companyID, workflowID)
	return r.scanWorkflowStep(row)
}

// ---------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------

func (r *workflowStepRepository) List(ctx context.Context, db DBTX, filter WorkflowStepFilter, p Pagination, s Sort) ([]*models.WorkflowStep, int64, error) {
	from := "subscription.workflow_steps ws"
	joins := []string{"JOIN subscription.workflows w ON ws.workflow_id = w.workflow_id"}
	whereCond := "w.company_id = $1"
	args := []interface{}{filter.CompanyID}
	idx := 2

	if len(filter.WorkflowStepIDs) > 0 {
		placeholders := make([]string, len(filter.WorkflowStepIDs))
		for i, id := range filter.WorkflowStepIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		whereCond += fmt.Sprintf(" AND ws.step_id IN (%s)", strings.Join(placeholders, ","))
	}
	if filter.WorkflowID != nil {
		whereCond += fmt.Sprintf(" AND ws.workflow_id = $%d", idx)
		args = append(args, *filter.WorkflowID)
		idx++
	}
	if filter.StepOrder != nil {
		whereCond += fmt.Sprintf(" AND ws.step_order = $%d", idx)
		args = append(args, *filter.StepOrder)
		idx++
	}
	if filter.StepType != nil {
		whereCond += fmt.Sprintf(" AND ws.step_type = $%d", idx)
		args = append(args, *filter.StepType)
		idx++
	}

	fullFrom := from + " " + strings.Join(joins, " ")
	whereClause := "WHERE " + whereCond

	orderBy, err := validateSort(s, workflowStepAllowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY ws.step_order ASC"
	}

	limit, offset := validatePagination(p)

	// Count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", fullFrom, whereClause)
	var total int64
	if err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count workflow steps: %w", err)
	}
	if total == 0 {
		return []*models.WorkflowStep{}, 0, nil
	}

	// Data
	query := fmt.Sprintf(`
		SELECT ws.step_id, ws.workflow_id, ws.step_order, ws.step_type,
			ws.config, ws.depends_on_step, ws.created_at
		FROM %s
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, fullFrom, whereClause, orderBy, idx, idx+1)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list workflow steps: %w", err)
	}
	defer rows.Close()

	var result []*models.WorkflowStep
	for rows.Next() {
		step, err := r.scanWorkflowStep(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, step)
	}
	return result, total, rows.Err()
}

func (r *workflowStepRepository) ListByWorkflow(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) ([]*models.WorkflowStep, error) {
	filter := WorkflowStepFilter{
		CompanyID:  companyID,
		WorkflowID: &workflowID,
	}
	steps, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "step_order", Direction: "ASC"})
	return steps, err
}

func (r *workflowStepRepository) ListActive(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) ([]*models.WorkflowStep, error) {
	// There's no IsActive column on workflow_steps; they're considered active if the workflow is active.
	// We'll return all steps for the workflow.
	return r.ListByWorkflow(ctx, db, companyID, workflowID)
}

// ---------------------------------------------------------------------
// Step Operations
// ---------------------------------------------------------------------

func (r *workflowStepRepository) UpdateStepOrder(ctx context.Context, db DBTX, companyID, workflowStepID uuid.UUID, newOrder int) error {
	// First, get the step to know its workflow
	step, err := r.GetByID(ctx, db, companyID, workflowStepID)
	if err != nil {
		return err
	}

	// Get all steps for this workflow
	_, err = r.ListByWorkflow(ctx, db, companyID, step.WorkflowID)
	if err != nil {
		return fmt.Errorf("get steps for reorder: %w", err)
	}

	// Find the current order
	currentOrder := step.StepOrder
	if currentOrder == newOrder {
		return nil
	}

	// Determine if moving up or down
	if newOrder < currentOrder {
		// Moving up: shift steps between newOrder and currentOrder-1 down by 1
		query := `
			UPDATE subscription.workflow_steps
			SET step_order = step_order + 1
			WHERE workflow_id = $1 AND step_order >= $2 AND step_order < $3
		`
		if _, err := db.ExecContext(ctx, query, step.WorkflowID, newOrder, currentOrder); err != nil {
			return fmt.Errorf("shift steps up: %w", err)
		}
	} else {
		// Moving down: shift steps between currentOrder+1 and newOrder up by 1
		query := `
			UPDATE subscription.workflow_steps
			SET step_order = step_order - 1
			WHERE workflow_id = $1 AND step_order > $2 AND step_order <= $3
		`
		if _, err := db.ExecContext(ctx, query, step.WorkflowID, currentOrder, newOrder); err != nil {
			return fmt.Errorf("shift steps down: %w", err)
		}
	}

	// Set the new order
	query := `
		UPDATE subscription.workflow_steps
		SET step_order = $1
		WHERE step_id = $2
	`
	if _, err := db.ExecContext(ctx, query, newOrder, workflowStepID); err != nil {
		return fmt.Errorf("update step order: %w", err)
	}

	return nil
}

func (r *workflowStepRepository) MoveUp(ctx context.Context, db DBTX, companyID, workflowStepID uuid.UUID) error {
	step, err := r.GetByID(ctx, db, companyID, workflowStepID)
	if err != nil {
		return err
	}
	if step.StepOrder <= 1 {
		return nil // already at top
	}
	return r.UpdateStepOrder(ctx, db, companyID, workflowStepID, step.StepOrder-1)
}

func (r *workflowStepRepository) MoveDown(ctx context.Context, db DBTX, companyID, workflowStepID uuid.UUID) error {
	step, err := r.GetByID(ctx, db, companyID, workflowStepID)
	if err != nil {
		return err
	}
	// Get max order
	maxOrder, err := r.getMaxOrder(ctx, db, companyID, step.WorkflowID)
	if err != nil {
		return err
	}
	if step.StepOrder >= maxOrder {
		return nil // already at bottom
	}
	return r.UpdateStepOrder(ctx, db, companyID, workflowStepID, step.StepOrder+1)
}

func (r *workflowStepRepository) getMaxOrder(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID) (int, error) {
	var max sql.NullInt32
	query := `
		SELECT MAX(ws.step_order)
		FROM subscription.workflow_steps ws
		JOIN subscription.workflows w ON ws.workflow_id = w.workflow_id
		WHERE w.company_id = $1 AND w.workflow_id = $2
	`
	err := db.QueryRowContext(ctx, query, companyID, workflowID).Scan(&max)
	if err != nil {
		return 0, fmt.Errorf("get max order: %w", err)
	}
	if !max.Valid {
		return 0, nil
	}
	return int(max.Int32), nil
}

func (r *workflowStepRepository) SetActive(ctx context.Context, db DBTX, companyID, workflowStepID uuid.UUID) error {
	// No is_active on workflow_steps; this is a no-op for steps
	// Steps are active if their workflow is active
	return nil
}

func (r *workflowStepRepository) SetInactive(ctx context.Context, db DBTX, companyID, workflowStepID uuid.UUID) error {
	// No is_active on workflow_steps; this is a no-op for steps
	return nil
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

func (r *workflowStepRepository) Exists(ctx context.Context, db DBTX, companyID, workflowStepID uuid.UUID) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(
			SELECT 1 FROM subscription.workflow_steps ws
			JOIN subscription.workflows w ON ws.workflow_id = w.workflow_id
			WHERE ws.step_id = $1 AND w.company_id = $2
		)
	`
	err := db.QueryRowContext(ctx, query, workflowStepID, companyID).Scan(&exists)
	return exists, err
}

func (r *workflowStepRepository) ExistsStepOrder(ctx context.Context, db DBTX, companyID, workflowID uuid.UUID, stepOrder int) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(
			SELECT 1 FROM subscription.workflow_steps ws
			JOIN subscription.workflows w ON ws.workflow_id = w.workflow_id
			WHERE w.company_id = $1 AND w.workflow_id = $2 AND ws.step_order = $3
		)
	`
	err := db.QueryRowContext(ctx, query, companyID, workflowID, stepOrder).Scan(&exists)
	return exists, err
}

// ---------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------

func (r *workflowStepRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.WorkflowStep, int64, error) {
	pattern := "%" + query + "%"
	where := `
		JOIN subscription.workflows w ON ws.workflow_id = w.workflow_id
		WHERE w.company_id = $1
		AND (ws.step_type ILIKE $2 OR ws.config::text ILIKE $2)
	`
	args := []interface{}{companyID, pattern}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM subscription.workflow_steps ws %s", where)
	var total int64
	if err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("search workflow steps count: %w", err)
	}
	if total == 0 {
		return []*models.WorkflowStep{}, 0, nil
	}

	baseQuery := `
		SELECT ws.step_id, ws.workflow_id, ws.step_order, ws.step_type,
			ws.config, ws.depends_on_step, ws.created_at
		FROM subscription.workflow_steps ws
	`
	querySQL := fmt.Sprintf(`%s %s ORDER BY ws.created_at DESC LIMIT $%d OFFSET $%d`, baseQuery, where, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search workflow steps: %w", err)
	}
	defer rows.Close()

	var result []*models.WorkflowStep
	for rows.Next() {
		step, err := r.scanWorkflowStep(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, step)
	}
	return result, total, rows.Err()
}

// ---------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------

func (r *workflowStepRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, workflowStepID uuid.UUID) (*models.WorkflowStep, error) {
	query := `
		SELECT ws.step_id, ws.workflow_id, ws.step_order, ws.step_type,
			ws.config, ws.depends_on_step, ws.created_at
		FROM subscription.workflow_steps ws
		JOIN subscription.workflows w ON ws.workflow_id = w.workflow_id
		WHERE ws.step_id = $1 AND w.company_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, workflowStepID, companyID)
	return r.scanWorkflowStep(row)
}
