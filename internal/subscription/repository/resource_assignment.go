// repository/resource_assignment_repository.go
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/models"
)

// ---------------------------------------------------------------------
// ResourceAssignmentRepository Interface (as given)
// ---------------------------------------------------------------------

type ResourceAssignmentRepository interface {
	Create(ctx context.Context, db DBTX, resource *models.ResourceAssignment) error
	Update(ctx context.Context, db DBTX, resource *models.ResourceAssignment) error
	Delete(ctx context.Context, db DBTX, companyID, resourceAssignmentID uuid.UUID) error

	GetByID(ctx context.Context, db DBTX, companyID, resourceAssignmentID uuid.UUID) (*models.ResourceAssignment, error)
	GetByResource(ctx context.Context, db DBTX, companyID uuid.UUID, resourceType string, resourceID uuid.UUID) (*models.ResourceAssignment, error)
	GetBySubscription(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) ([]*models.ResourceAssignment, error)

	List(ctx context.Context, db DBTX, filter ResourceAssignmentFilter, p Pagination, s Sort) ([]*models.ResourceAssignment, int64, error)
	ListByResourceType(ctx context.Context, db DBTX, companyID uuid.UUID, resourceType string) ([]*models.ResourceAssignment, error)
	ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.ResourceAssignment, error)

	AssignResource(ctx context.Context, db DBTX, resource *models.ResourceAssignment) error
	UnassignResource(ctx context.Context, db DBTX, companyID, resourceAssignmentID uuid.UUID) error
	TransferResource(ctx context.Context, db DBTX, companyID, resourceAssignmentID uuid.UUID, newSubscriptionID uuid.UUID) error

	Exists(ctx context.Context, db DBTX, companyID, resourceAssignmentID uuid.UUID) (bool, error)
	IsAssigned(ctx context.Context, db DBTX, companyID uuid.UUID, resourceType string, resourceID uuid.UUID) (bool, error)

	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.ResourceAssignment, int64, error)

	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, resourceAssignmentID uuid.UUID) (*models.ResourceAssignment, error)
}

type ResourceAssignmentFilter struct {
	CompanyID             uuid.UUID
	ResourceAssignmentIDs []uuid.UUID
	SubscriptionID        *uuid.UUID
	ResourceType          *string
	ResourceID            *uuid.UUID
	IsActive              *bool
	AssignedFrom          *time.Time
	AssignedTo            *time.Time
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------

type resourceAssignmentRepository struct {
	logger *zap.Logger
}

func NewResourceAssignmentRepository(logger *zap.Logger) ResourceAssignmentRepository {
	return &resourceAssignmentRepository{
		logger: logger.Named("subscription_resource_assignment_repo"),
	}
}

const resourceAssignmentTable = "subscription.resource_assignments"

// scanResourceAssignment expects columns: assignment_id, subscription_id, resource_type,
// resource_id, allocation_strategy, assigned_at, assigned_until, status_id, created_at, updated_at
func (r *resourceAssignmentRepository) scanResourceAssignment(s scanner) (*models.ResourceAssignment, error) {
	var ra models.ResourceAssignment
	var assignedUntil sql.NullTime
	var statusID int16

	err := s.Scan(
		&ra.AssignmentID,
		&ra.SubscriptionID,
		&ra.ResourceType,
		&ra.ResourceID,
		&ra.AllocationStrategy,
		&ra.AssignedAt,
		&assignedUntil,
		&statusID,
		&ra.CreatedAt,
		&ra.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan resource assignment: %w", err)
	}
	if assignedUntil.Valid {
		ra.AssignedUntil = &assignedUntil.Time
	}
	ra.StatusID = statusID
	return &ra, nil
}

// buildResourceAssignmentFilter builds WHERE clause and args for ResourceAssignmentFilter.
// CompanyID is handled by joining with subscriptions.
func (r *resourceAssignmentRepository) buildResourceAssignmentFilter(filter ResourceAssignmentFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		// handled via join in List method
	}
	if len(filter.ResourceAssignmentIDs) > 0 {
		placeholders := make([]string, len(filter.ResourceAssignmentIDs))
		for i, id := range filter.ResourceAssignmentIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("ra.assignment_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.SubscriptionID != nil {
		conds = append(conds, fmt.Sprintf("ra.subscription_id = $%d", idx))
		args = append(args, *filter.SubscriptionID)
		idx++
	}
	if filter.ResourceType != nil {
		conds = append(conds, fmt.Sprintf("ra.resource_type = $%d", idx))
		args = append(args, *filter.ResourceType)
		idx++
	}
	if filter.ResourceID != nil {
		conds = append(conds, fmt.Sprintf("ra.resource_id = $%d", idx))
		args = append(args, *filter.ResourceID)
		idx++
	}
	if filter.IsActive != nil {
		if *filter.IsActive {
			conds = append(conds, "ra.status_id = 1")
		} else {
			conds = append(conds, "ra.status_id != 1")
		}
	}
	if filter.AssignedFrom != nil {
		conds = append(conds, fmt.Sprintf("ra.assigned_at >= $%d", idx))
		args = append(args, *filter.AssignedFrom)
		idx++
	}
	if filter.AssignedTo != nil {
		conds = append(conds, fmt.Sprintf("ra.assigned_at <= $%d", idx))
		args = append(args, *filter.AssignedTo)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

var resourceAssignmentAllowedSort = map[string]bool{
	"assignment_id":  true,
	"resource_type":  true,
	"resource_id":    true,
	"assigned_at":    true,
	"assigned_until": true,
	"status_id":      true,
	"created_at":     true,
	"updated_at":     true,
}

// ---------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------

func (r *resourceAssignmentRepository) Create(ctx context.Context, db DBTX, resource *models.ResourceAssignment) error {
	query := `
		INSERT INTO subscription.resource_assignments (
			assignment_id, subscription_id, resource_type,
			resource_id, allocation_strategy, assigned_at, assigned_until,
			status_id, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		resource.AssignmentID,
		resource.SubscriptionID,
		resource.ResourceType,
		resource.ResourceID,
		resource.AllocationStrategy,
		resource.AssignedAt,
		resource.AssignedUntil,
		resource.StatusID,
	).Scan(&resource.CreatedAt, &resource.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create resource assignment: %w", err)
	}
	return nil
}

func (r *resourceAssignmentRepository) Update(ctx context.Context, db DBTX, resource *models.ResourceAssignment) error {
	query := `
		UPDATE subscription.resource_assignments
		SET subscription_id = $2,
			resource_type = $3,
			resource_id = $4,
			allocation_strategy = $5,
			assigned_at = $6,
			assigned_until = $7,
			status_id = $8,
			updated_at = NOW()
		WHERE assignment_id = $1
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		resource.AssignmentID,
		resource.SubscriptionID,
		resource.ResourceType,
		resource.ResourceID,
		resource.AllocationStrategy,
		resource.AssignedAt,
		resource.AssignedUntil,
		resource.StatusID,
	).Scan(&resource.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return fmt.Errorf("update resource assignment: %w", err)
	}
	return nil
}

func (r *resourceAssignmentRepository) Delete(ctx context.Context, db DBTX, companyID, resourceAssignmentID uuid.UUID) error {
	// Verify company via join
	query := `
		DELETE FROM subscription.resource_assignments ra
		USING subscription.subscriptions s
		WHERE ra.subscription_id = s.subscription_id
		AND s.company_id = $1
		AND ra.assignment_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, resourceAssignmentID)
	if err != nil {
		return fmt.Errorf("delete resource assignment: %w", err)
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

func (r *resourceAssignmentRepository) GetByID(ctx context.Context, db DBTX, companyID, resourceAssignmentID uuid.UUID) (*models.ResourceAssignment, error) {
	query := `
		SELECT ra.assignment_id, ra.subscription_id, ra.resource_type,
			ra.resource_id, ra.allocation_strategy, ra.assigned_at, ra.assigned_until,
			ra.status_id, ra.created_at, ra.updated_at
		FROM subscription.resource_assignments ra
		JOIN subscription.subscriptions s ON ra.subscription_id = s.subscription_id
		WHERE ra.assignment_id = $1 AND s.company_id = $2
	`
	row := db.QueryRowContext(ctx, query, resourceAssignmentID, companyID)
	return r.scanResourceAssignment(row)
}

func (r *resourceAssignmentRepository) GetByResource(ctx context.Context, db DBTX, companyID uuid.UUID, resourceType string, resourceID uuid.UUID) (*models.ResourceAssignment, error) {
	query := `
		SELECT ra.assignment_id, ra.subscription_id, ra.resource_type,
			ra.resource_id, ra.allocation_strategy, ra.assigned_at, ra.assigned_until,
			ra.status_id, ra.created_at, ra.updated_at
		FROM subscription.resource_assignments ra
		JOIN subscription.subscriptions s ON ra.subscription_id = s.subscription_id
		WHERE s.company_id = $1 AND ra.resource_type = $2 AND ra.resource_id = $3
		ORDER BY ra.assigned_at DESC
		LIMIT 1
	`
	row := db.QueryRowContext(ctx, query, companyID, resourceType, resourceID)
	return r.scanResourceAssignment(row)
}

func (r *resourceAssignmentRepository) GetBySubscription(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) ([]*models.ResourceAssignment, error) {
	query := `
		SELECT ra.assignment_id, ra.subscription_id, ra.resource_type,
			ra.resource_id, ra.allocation_strategy, ra.assigned_at, ra.assigned_until,
			ra.status_id, ra.created_at, ra.updated_at
		FROM subscription.resource_assignments ra
		JOIN subscription.subscriptions s ON ra.subscription_id = s.subscription_id
		WHERE s.company_id = $1 AND ra.subscription_id = $2
		ORDER BY ra.assigned_at DESC
	`
	rows, err := db.QueryContext(ctx, query, companyID, subscriptionID)
	if err != nil {
		return nil, fmt.Errorf("get assignments by subscription: %w", err)
	}
	defer rows.Close()
	var result []*models.ResourceAssignment
	for rows.Next() {
		ra, err := r.scanResourceAssignment(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, ra)
	}
	return result, rows.Err()
}

// ---------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------

func (r *resourceAssignmentRepository) List(ctx context.Context, db DBTX, filter ResourceAssignmentFilter, p Pagination, s Sort) ([]*models.ResourceAssignment, int64, error) {
	// Build from with join to subscriptions for company filter
	from := "subscription.resource_assignments ra"
	joins := []string{"JOIN subscription.subscriptions s ON ra.subscription_id = s.subscription_id"}
	whereCond := "s.company_id = $1"
	args := []interface{}{filter.CompanyID}
	idx := 2

	if filter.SubscriptionID != nil {
		whereCond += fmt.Sprintf(" AND ra.subscription_id = $%d", idx)
		args = append(args, *filter.SubscriptionID)
		idx++
	}
	if len(filter.ResourceAssignmentIDs) > 0 {
		placeholders := make([]string, len(filter.ResourceAssignmentIDs))
		for i, id := range filter.ResourceAssignmentIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		whereCond += fmt.Sprintf(" AND ra.assignment_id IN (%s)", strings.Join(placeholders, ","))
	}
	if filter.ResourceType != nil {
		whereCond += fmt.Sprintf(" AND ra.resource_type = $%d", idx)
		args = append(args, *filter.ResourceType)
		idx++
	}
	if filter.ResourceID != nil {
		whereCond += fmt.Sprintf(" AND ra.resource_id = $%d", idx)
		args = append(args, *filter.ResourceID)
		idx++
	}
	if filter.IsActive != nil {
		if *filter.IsActive {
			whereCond += " AND ra.status_id = 1"
		} else {
			whereCond += " AND ra.status_id != 1"
		}
	}
	if filter.AssignedFrom != nil {
		whereCond += fmt.Sprintf(" AND ra.assigned_at >= $%d", idx)
		args = append(args, *filter.AssignedFrom)
		idx++
	}
	if filter.AssignedTo != nil {
		whereCond += fmt.Sprintf(" AND ra.assigned_at <= $%d", idx)
		args = append(args, *filter.AssignedTo)
		idx++
	}

	fullFrom := from + " " + strings.Join(joins, " ")
	whereClause := "WHERE " + whereCond

	orderBy, err := validateSort(s, resourceAssignmentAllowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY ra.assigned_at DESC"
	}
	limit, offset := validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", fullFrom, whereClause)
	var total int64
	if err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count resource assignments: %w", err)
	}
	if total == 0 {
		return []*models.ResourceAssignment{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT ra.assignment_id, ra.subscription_id, ra.resource_type,
			ra.resource_id, ra.allocation_strategy, ra.assigned_at, ra.assigned_until,
			ra.status_id, ra.created_at, ra.updated_at
		FROM %s
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, fullFrom, whereClause, orderBy, idx, idx+1)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list resource assignments: %w", err)
	}
	defer rows.Close()
	var result []*models.ResourceAssignment
	for rows.Next() {
		ra, err := r.scanResourceAssignment(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, ra)
	}
	return result, total, rows.Err()
}

func (r *resourceAssignmentRepository) ListByResourceType(ctx context.Context, db DBTX, companyID uuid.UUID, resourceType string) ([]*models.ResourceAssignment, error) {
	filter := ResourceAssignmentFilter{
		CompanyID:    companyID,
		ResourceType: &resourceType,
	}
	assignments, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "assigned_at", Direction: "DESC"})
	return assignments, err
}

func (r *resourceAssignmentRepository) ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.ResourceAssignment, error) {
	filter := ResourceAssignmentFilter{
		CompanyID: companyID,
		IsActive:  ptrBool(true),
	}
	assignments, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "assigned_at", Direction: "DESC"})
	return assignments, err
}

// ---------------------------------------------------------------------
// Assignment Operations
// ---------------------------------------------------------------------

func (r *resourceAssignmentRepository) AssignResource(ctx context.Context, db DBTX, resource *models.ResourceAssignment) error {
	return r.Create(ctx, db, resource)
}

func (r *resourceAssignmentRepository) UnassignResource(ctx context.Context, db DBTX, companyID, resourceAssignmentID uuid.UUID) error {
	query := `
		UPDATE subscription.resource_assignments ra
		SET status_id = 8, assigned_until = NOW(), updated_at = NOW()
		FROM subscription.subscriptions s
		WHERE ra.subscription_id = s.subscription_id
		AND s.company_id = $1
		AND ra.assignment_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, resourceAssignmentID)
	if err != nil {
		return fmt.Errorf("unassign resource: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *resourceAssignmentRepository) TransferResource(ctx context.Context, db DBTX, companyID, resourceAssignmentID uuid.UUID, newSubscriptionID uuid.UUID) error {
	// Verify company and update subscription
	query := `
		UPDATE subscription.resource_assignments ra
		SET subscription_id = $3, updated_at = NOW()
		FROM subscription.subscriptions s
		WHERE ra.subscription_id = s.subscription_id
		AND s.company_id = $1
		AND ra.assignment_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, resourceAssignmentID, newSubscriptionID)
	if err != nil {
		return fmt.Errorf("transfer resource: %w", err)
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

func (r *resourceAssignmentRepository) Exists(ctx context.Context, db DBTX, companyID, resourceAssignmentID uuid.UUID) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(
			SELECT 1 FROM subscription.resource_assignments ra
			JOIN subscription.subscriptions s ON ra.subscription_id = s.subscription_id
			WHERE ra.assignment_id = $1 AND s.company_id = $2
		)
	`
	err := db.QueryRowContext(ctx, query, resourceAssignmentID, companyID).Scan(&exists)
	return exists, err
}

func (r *resourceAssignmentRepository) IsAssigned(ctx context.Context, db DBTX, companyID uuid.UUID, resourceType string, resourceID uuid.UUID) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(
			SELECT 1 FROM subscription.resource_assignments ra
			JOIN subscription.subscriptions s ON ra.subscription_id = s.subscription_id
			WHERE s.company_id = $1
			AND ra.resource_type = $2
			AND ra.resource_id = $3
			AND ra.status_id = 1
		)
	`
	err := db.QueryRowContext(ctx, query, companyID, resourceType, resourceID).Scan(&exists)
	return exists, err
}

// ---------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------

func (r *resourceAssignmentRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.ResourceAssignment, int64, error) {
	pattern := "%" + query + "%"
	where := `
		JOIN subscription.subscriptions s ON ra.subscription_id = s.subscription_id
		WHERE s.company_id = $1
		AND (ra.resource_type ILIKE $2 OR ra.resource_id::text ILIKE $2 OR ra.allocation_strategy ILIKE $2)
	`
	args := []interface{}{companyID, pattern}
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM subscription.resource_assignments ra %s", where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search resource assignments count: %w", err)
	}
	if total == 0 {
		return []*models.ResourceAssignment{}, 0, nil
	}
	baseQuery := `
		SELECT ra.assignment_id, ra.subscription_id, ra.resource_type,
			ra.resource_id, ra.allocation_strategy, ra.assigned_at, ra.assigned_until,
			ra.status_id, ra.created_at, ra.updated_at
		FROM subscription.resource_assignments ra
	`
	querySQL := fmt.Sprintf(`%s %s ORDER BY ra.assigned_at DESC LIMIT $%d OFFSET $%d`, baseQuery, where, len(args)+1, len(args)+2)
	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search resource assignments: %w", err)
	}
	defer rows.Close()
	var result []*models.ResourceAssignment
	for rows.Next() {
		ra, err := r.scanResourceAssignment(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, ra)
	}
	return result, total, rows.Err()
}

// ---------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------

func (r *resourceAssignmentRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, resourceAssignmentID uuid.UUID) (*models.ResourceAssignment, error) {
	query := `
		SELECT ra.assignment_id, ra.subscription_id, ra.resource_type,
			ra.resource_id, ra.allocation_strategy, ra.assigned_at, ra.assigned_until,
			ra.status_id, ra.created_at, ra.updated_at
		FROM subscription.resource_assignments ra
		JOIN subscription.subscriptions s ON ra.subscription_id = s.subscription_id
		WHERE ra.assignment_id = $1 AND s.company_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, resourceAssignmentID, companyID)
	return r.scanResourceAssignment(row)
}
