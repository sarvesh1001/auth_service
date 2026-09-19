package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"

	"auth-service/internal/accounting/models"
	"auth-service/internal/util"
)

// CostCenterFilter defines filter criteria for listing cost centers.
type CostCenterFilter struct {
	CompanyID uuid.UUID
	IsActive  *bool
	ParentID  *uuid.UUID
	Search    string
}

// CostCenterTreeNode represents a cost center in a hierarchical tree.
type CostCenterTreeNode struct {
	CostCenter *models.CostCenter
	Children   []*CostCenterTreeNode
}

// CostCenterRepository defines the interface for cost center data access.
type CostCenterRepository interface {
	// Write operations
	Create(ctx context.Context, db DBTX, cc *models.CostCenter) error
	BulkCreate(ctx context.Context, db DBTX, costCenters []*models.CostCenter) error
	Update(ctx context.Context, db DBTX, cc *models.CostCenter) error
	UpdateStatus(ctx context.Context, db DBTX, costCenterID uuid.UUID, isActive bool, updatedBy *uuid.UUID) error
	UpdateParent(ctx context.Context, db DBTX, costCenterID uuid.UUID, parentID *uuid.UUID, updatedBy *uuid.UUID) error
	Delete(ctx context.Context, db DBTX, costCenterID uuid.UUID, deletedBy *uuid.UUID) error

	// Read operations
	GetByID(ctx context.Context, db DBTX, costCenterID uuid.UUID) (*models.CostCenter, error)
	GetByIDForUpdate(ctx context.Context, db DBTX, costCenterID uuid.UUID) (*models.CostCenter, error)
	GetByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (*models.CostCenter, error)
	ExistsByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (bool, error)
	ExistsByID(ctx context.Context, db DBTX, costCenterID uuid.UUID) (bool, error)
	List(ctx context.Context, db DBTX, filter CostCenterFilter, p Pagination, s Sort) ([]*models.CostCenter, error)
	ListByCompany(ctx context.Context, db DBTX, companyID uuid.UUID, includeInactive bool) ([]*models.CostCenter, error)
	Count(ctx context.Context, db DBTX, filter CostCenterFilter) (int64, error)

	// Hierarchy operations
	GetChildren(ctx context.Context, db DBTX, parentID uuid.UUID) ([]*models.CostCenter, error)
	GetTree(ctx context.Context, db DBTX, companyID uuid.UUID, includeInactive bool) ([]*CostCenterTreeNode, error)
	HasChildren(ctx context.Context, db DBTX, costCenterID uuid.UUID) (bool, error)
	CountChildren(ctx context.Context, db DBTX, costCenterID uuid.UUID) (int, error)
	IsLeaf(ctx context.Context, db DBTX, costCenterID uuid.UUID) (bool, error)

	// Validation / safety
	CheckCircularReference(ctx context.Context, db DBTX, costCenterID uuid.UUID, parentID *uuid.UUID) (bool, error)
	CheckUsageInLedger(ctx context.Context, db DBTX, costCenterID uuid.UUID) (bool, error)
	CheckUsageInEmployees(ctx context.Context, db DBTX, costCenterID uuid.UUID) (bool, error)

	// Bulk reads
	GetByIDs(ctx context.Context, db DBTX, companyID uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]*models.CostCenter, error)
	GetActiveByIDs(ctx context.Context, db DBTX, companyID uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]*models.CostCenter, error)
	ValidateCostCenterIDs(ctx context.Context, db DBTX, companyID uuid.UUID, ids []uuid.UUID) error

	// Locking
	LockCostCenter(ctx context.Context, db DBTX, costCenterID uuid.UUID) error
}

// costCenterRepository implements CostCenterRepository.
type costCenterRepository struct {
	logger *zap.Logger
}

// NewCostCenterRepository creates a new cost center repository.
func NewCostCenterRepository(logger *zap.Logger) CostCenterRepository {
	return &costCenterRepository{
		logger: logger.Named("cost_center_repo"),
	}
}

// allowed sort fields
var allowedCostCenterSortFields = map[string]bool{
	"cost_center_code": true,
	"cost_center_name": true,
	"created_at":       true,
	"updated_at":       true,
}

func (r *costCenterRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "cost_center_code"
	}
	if !allowedCostCenterSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "ASC"
	}
	return fmt.Sprintf("ORDER BY %s %s", field, dir), nil
}

func (r *costCenterRepository) validatePagination(p Pagination) (int, int) {
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

func (r *costCenterRepository) buildFilter(filter CostCenterFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}
	if filter.ParentID != nil {
		if *filter.ParentID == uuid.Nil {
			conditions = append(conditions, "parent_id IS NULL")
		} else {
			conditions = append(conditions, fmt.Sprintf("parent_id = $%d", idx))
			args = append(args, *filter.ParentID)
			idx++
		}
	}
	if filter.Search != "" {
		pattern := "%" + filter.Search + "%"
		conditions = append(conditions, fmt.Sprintf("(cost_center_code ILIKE $%d OR cost_center_name ILIKE $%d)", idx, idx+1))
		args = append(args, pattern, pattern)
		idx += 2
	}

	conditions = append(conditions, "deleted_at IS NULL")

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *costCenterRepository) scanCostCenter(scanner interface {
	Scan(dest ...interface{}) error
}) (*models.CostCenter, error) {
	var cc models.CostCenter
	var parentID, accountID, createdBy, updatedBy uuid.NullUUID
	var deletedAt sql.NullTime

	err := scanner.Scan(
		&cc.CostCenterID,
		&cc.CompanyID,
		&cc.CostCenterCode,
		&cc.CostCenterName,
		&cc.Description,
		&parentID,
		&accountID,
		&cc.IsActive,
		&cc.CreatedAt,
		&cc.UpdatedAt,
		&createdBy,
		&updatedBy,
		&deletedAt,
	)
	if err != nil {
		return nil, err
	}

	if parentID.Valid {
		cc.ParentID = &parentID.UUID
	}
	if accountID.Valid {
		cc.AccountID = &accountID.UUID
	}
	if createdBy.Valid {
		cc.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		cc.UpdatedBy = &updatedBy.UUID
	}
	if deletedAt.Valid {
		cc.DeletedAt = &deletedAt.Time
	}
	return &cc, nil
}

// ============================================================
// WRITE OPERATIONS
// ============================================================

// Create inserts a new cost center.
func (r *costCenterRepository) Create(ctx context.Context, db DBTX, cc *models.CostCenter) error {
	query := `
		INSERT INTO accounting.cost_centers (
			cost_center_id, company_id, cost_center_code, cost_center_name,
			description, parent_id, account_id, is_active,
			created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW(), $9, $10)
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		cc.CostCenterID, cc.CompanyID, cc.CostCenterCode, cc.CostCenterName,
		cc.Description, cc.ParentID, cc.AccountID, cc.IsActive,
		cc.CreatedBy, cc.UpdatedBy,
	).Scan(&cc.CreatedAt, &cc.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create cost center",
			util.String("company_id", cc.CompanyID.String()),
			util.String("code", cc.CostCenterCode),
			util.ErrorField(err))
		return fmt.Errorf("create cost center: %w", err)
	}
	return nil
}

// BulkCreate inserts multiple cost centers using a prepared statement.
func (r *costCenterRepository) BulkCreate(ctx context.Context, db DBTX, costCenters []*models.CostCenter) error {
	if len(costCenters) == 0 {
		return nil
	}
	stmt, err := db.PrepareContext(ctx, `
		INSERT INTO accounting.cost_centers (
			cost_center_id, company_id, cost_center_code, cost_center_name,
			description, parent_id, account_id, is_active,
			created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW(), $9, $10)
		RETURNING created_at, updated_at
	`)
	if err != nil {
		return fmt.Errorf("prepare bulk insert: %w", err)
	}
	defer stmt.Close()

	for _, cc := range costCenters {
		err = stmt.QueryRowContext(ctx,
			cc.CostCenterID, cc.CompanyID, cc.CostCenterCode, cc.CostCenterName,
			cc.Description, cc.ParentID, cc.AccountID, cc.IsActive,
			cc.CreatedBy, cc.UpdatedBy,
		).Scan(&cc.CreatedAt, &cc.UpdatedAt)
		if err != nil {
			r.logger.Error("bulk create failed",
				util.String("company_id", cc.CompanyID.String()),
				util.String("code", cc.CostCenterCode),
				util.ErrorField(err))
			return fmt.Errorf("bulk create cost center: %w", err)
		}
	}
	return nil
}

// Update modifies an existing cost center.
func (r *costCenterRepository) Update(ctx context.Context, db DBTX, cc *models.CostCenter) error {
	query := `
		UPDATE accounting.cost_centers
		SET cost_center_code = $2,
		    cost_center_name = $3,
		    description      = $4,
		    parent_id        = $5,
		    account_id       = $6,
		    is_active        = $7,
		    updated_by       = $8,
		    updated_at       = NOW()
		WHERE cost_center_id = $1 AND deleted_at IS NULL
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		cc.CostCenterID, cc.CostCenterCode, cc.CostCenterName,
		cc.Description, cc.ParentID, cc.AccountID, cc.IsActive,
		cc.UpdatedBy,
	).Scan(&cc.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		r.logger.Error("failed to update cost center",
			util.String("id", cc.CostCenterID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update cost center: %w", err)
	}
	return nil
}

// UpdateStatus toggles is_active. Always allowed, even if referenced.
func (r *costCenterRepository) UpdateStatus(ctx context.Context, db DBTX, costCenterID uuid.UUID, isActive bool, updatedBy *uuid.UUID) error {
	query := `
		UPDATE accounting.cost_centers
		SET is_active = $2, updated_by = $3, updated_at = NOW()
		WHERE cost_center_id = $1 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, costCenterID, isActive, updatedBy)
	if err != nil {
		r.logger.Error("failed to update cost center status",
			util.String("id", costCenterID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update cost center status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateParent changes the parent cost center.
func (r *costCenterRepository) UpdateParent(ctx context.Context, db DBTX, costCenterID uuid.UUID, parentID *uuid.UUID, updatedBy *uuid.UUID) error {
	query := `
		UPDATE accounting.cost_centers
		SET parent_id = $2, updated_by = $3, updated_at = NOW()
		WHERE cost_center_id = $1 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, costCenterID, parentID, updatedBy)
	if err != nil {
		r.logger.Error("failed to update cost center parent",
			util.String("id", costCenterID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update cost center parent: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete soft-deletes. Blocked if children exist or if referenced by ledger
// entries or by employee_profiles. Employees should be moved off the cost
// center first (HR action); ledger references mean the cost center must be
// deactivated, not deleted.
func (r *costCenterRepository) Delete(ctx context.Context, db DBTX, costCenterID uuid.UUID, deletedBy *uuid.UUID) error {
	hasChildren, err := r.HasChildren(ctx, db, costCenterID)
	if err != nil {
		return fmt.Errorf("check children before delete: %w", err)
	}
	if hasChildren {
		return fmt.Errorf("cannot delete cost center %s: has child cost centers", costCenterID)
	}

	usedInLedger, err := r.CheckUsageInLedger(ctx, db, costCenterID)
	if err != nil {
		return fmt.Errorf("check ledger usage before delete: %w", err)
	}
	if usedInLedger {
		return fmt.Errorf("cannot delete cost center %s: referenced by ledger entries", costCenterID)
	}

	usedByEmployees, err := r.CheckUsageInEmployees(ctx, db, costCenterID)
	if err != nil {
		return fmt.Errorf("check employee usage before delete: %w", err)
	}
	if usedByEmployees {
		return fmt.Errorf("cannot delete cost center %s: assigned to one or more employees", costCenterID)
	}

	query := `
		UPDATE accounting.cost_centers
		SET deleted_at = NOW(), updated_by = $2, updated_at = NOW()
		WHERE cost_center_id = $1 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, costCenterID, deletedBy)
	if err != nil {
		r.logger.Error("failed to delete cost center",
			util.String("id", costCenterID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete cost center: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// ============================================================
// READ OPERATIONS
// ============================================================

const costCenterSelectCols = `
	cost_center_id, company_id, cost_center_code, cost_center_name,
	description, parent_id, account_id, is_active,
	created_at, updated_at, created_by, updated_by, deleted_at
`

func (r *costCenterRepository) GetByID(ctx context.Context, db DBTX, costCenterID uuid.UUID) (*models.CostCenter, error) {
	query := `SELECT ` + costCenterSelectCols + `
		FROM accounting.cost_centers
		WHERE cost_center_id = $1 AND deleted_at IS NULL`

	cc, err := r.scanCostCenter(db.QueryRowContext(ctx, query, costCenterID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get cost center by ID",
			util.String("id", costCenterID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get cost center by ID: %w", err)
	}
	return cc, nil
}

func (r *costCenterRepository) GetByIDForUpdate(ctx context.Context, db DBTX, costCenterID uuid.UUID) (*models.CostCenter, error) {
	query := `SELECT ` + costCenterSelectCols + `
		FROM accounting.cost_centers
		WHERE cost_center_id = $1 AND deleted_at IS NULL
		FOR UPDATE`

	cc, err := r.scanCostCenter(db.QueryRowContext(ctx, query, costCenterID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get cost center for update: %w", err)
	}
	return cc, nil
}

func (r *costCenterRepository) GetByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (*models.CostCenter, error) {
	query := `SELECT ` + costCenterSelectCols + `
		FROM accounting.cost_centers
		WHERE company_id = $1 AND cost_center_code = $2 AND deleted_at IS NULL`

	cc, err := r.scanCostCenter(db.QueryRowContext(ctx, query, companyID, code))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get cost center by code: %w", err)
	}
	return cc, nil
}

func (r *costCenterRepository) ExistsByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (bool, error) {
	query := `SELECT EXISTS(
		SELECT 1 FROM accounting.cost_centers
		WHERE company_id = $1 AND cost_center_code = $2 AND deleted_at IS NULL
	)`
	var exists bool
	if err := db.QueryRowContext(ctx, query, companyID, code).Scan(&exists); err != nil {
		return false, fmt.Errorf("exists by code: %w", err)
	}
	return exists, nil
}

func (r *costCenterRepository) ExistsByID(ctx context.Context, db DBTX, costCenterID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(
		SELECT 1 FROM accounting.cost_centers
		WHERE cost_center_id = $1 AND deleted_at IS NULL
	)`
	var exists bool
	if err := db.QueryRowContext(ctx, query, costCenterID).Scan(&exists); err != nil {
		return false, fmt.Errorf("exists by ID: %w", err)
	}
	return exists, nil
}

func (r *costCenterRepository) List(ctx context.Context, db DBTX, filter CostCenterFilter, p Pagination, s Sort) ([]*models.CostCenter, error) {
	where, args := r.buildFilter(filter)
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT %s
		FROM accounting.cost_centers
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, costCenterSelectCols, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list cost centers",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list cost centers: %w", err)
	}
	defer rows.Close()

	var result []*models.CostCenter
	for rows.Next() {
		cc, err := r.scanCostCenter(rows)
		if err != nil {
			return nil, fmt.Errorf("scan cost center: %w", err)
		}
		result = append(result, cc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *costCenterRepository) ListByCompany(ctx context.Context, db DBTX, companyID uuid.UUID, includeInactive bool) ([]*models.CostCenter, error) {
	filter := CostCenterFilter{CompanyID: companyID}
	if !includeInactive {
		active := true
		filter.IsActive = &active
	}
	return r.List(ctx, db, filter,
		Pagination{Limit: 1000},
		Sort{Field: "cost_center_code", Direction: "ASC"},
	)
}

func (r *costCenterRepository) Count(ctx context.Context, db DBTX, filter CostCenterFilter) (int64, error) {
	where, args := r.buildFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM accounting.cost_centers %s", where)
	var count int64
	if err := db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count cost centers: %w", err)
	}
	return count, nil
}

// ============================================================
// HIERARCHY
// ============================================================

func (r *costCenterRepository) GetChildren(ctx context.Context, db DBTX, parentID uuid.UUID) ([]*models.CostCenter, error) {
	query := `SELECT ` + costCenterSelectCols + `
		FROM accounting.cost_centers
		WHERE parent_id = $1 AND deleted_at IS NULL
		ORDER BY cost_center_code`
	rows, err := db.QueryContext(ctx, query, parentID)
	if err != nil {
		return nil, fmt.Errorf("get cost center children: %w", err)
	}
	defer rows.Close()

	var result []*models.CostCenter
	for rows.Next() {
		cc, err := r.scanCostCenter(rows)
		if err != nil {
			return nil, fmt.Errorf("scan child cost center: %w", err)
		}
		result = append(result, cc)
	}
	return result, nil
}

func (r *costCenterRepository) GetTree(ctx context.Context, db DBTX, companyID uuid.UUID, includeInactive bool) ([]*CostCenterTreeNode, error) {
	all, err := r.ListByCompany(ctx, db, companyID, includeInactive)
	if err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return []*CostCenterTreeNode{}, nil
	}

	childrenMap := make(map[uuid.UUID][]*models.CostCenter)
	var roots []*models.CostCenter

	for _, cc := range all {
		if cc.ParentID == nil {
			roots = append(roots, cc)
		} else {
			childrenMap[*cc.ParentID] = append(childrenMap[*cc.ParentID], cc)
		}
	}

	var build func(parent *models.CostCenter) *CostCenterTreeNode
	build = func(parent *models.CostCenter) *CostCenterTreeNode {
		node := &CostCenterTreeNode{
			CostCenter: parent,
			Children:   []*CostCenterTreeNode{},
		}
		for _, child := range childrenMap[parent.CostCenterID] {
			node.Children = append(node.Children, build(child))
		}
		return node
	}

	trees := make([]*CostCenterTreeNode, len(roots))
	for i, root := range roots {
		trees[i] = build(root)
	}
	return trees, nil
}

func (r *costCenterRepository) HasChildren(ctx context.Context, db DBTX, costCenterID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(
		SELECT 1 FROM accounting.cost_centers
		WHERE parent_id = $1 AND deleted_at IS NULL
	)`
	var exists bool
	if err := db.QueryRowContext(ctx, query, costCenterID).Scan(&exists); err != nil {
		return false, fmt.Errorf("has children: %w", err)
	}
	return exists, nil
}

func (r *costCenterRepository) CountChildren(ctx context.Context, db DBTX, costCenterID uuid.UUID) (int, error) {
	query := `SELECT COUNT(*) FROM accounting.cost_centers
		WHERE parent_id = $1 AND deleted_at IS NULL`
	var count int
	if err := db.QueryRowContext(ctx, query, costCenterID).Scan(&count); err != nil {
		return 0, fmt.Errorf("count children: %w", err)
	}
	return count, nil
}

func (r *costCenterRepository) IsLeaf(ctx context.Context, db DBTX, costCenterID uuid.UUID) (bool, error) {
	hasChildren, err := r.HasChildren(ctx, db, costCenterID)
	if err != nil {
		return false, err
	}
	return !hasChildren, nil
}

// ============================================================
// VALIDATION / SAFETY
// ============================================================

func (r *costCenterRepository) CheckCircularReference(ctx context.Context, db DBTX, costCenterID uuid.UUID, parentID *uuid.UUID) (bool, error) {
	if parentID == nil {
		return false, nil
	}
	current := *parentID
	seen := make(map[uuid.UUID]struct{}) // hard stop against pre-existing cycles

	for current != uuid.Nil {
		if current == costCenterID {
			return true, nil
		}
		if _, dup := seen[current]; dup {
			// Already in a cycle before we got here — bail out safely.
			return true, nil
		}
		seen[current] = struct{}{}

		query := `SELECT parent_id FROM accounting.cost_centers
			WHERE cost_center_id = $1 AND deleted_at IS NULL`
		var next uuid.NullUUID
		err := db.QueryRowContext(ctx, query, current).Scan(&next)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				break
			}
			return false, fmt.Errorf("check circular reference: %w", err)
		}
		if !next.Valid {
			break
		}
		current = next.UUID
	}
	return false, nil
}

func (r *costCenterRepository) CheckUsageInLedger(ctx context.Context, db DBTX, costCenterID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(
		SELECT 1 FROM accounting.ledger_entries
		WHERE cost_center_id = $1
		LIMIT 1
	)`
	var exists bool
	if err := db.QueryRowContext(ctx, query, costCenterID).Scan(&exists); err != nil {
		return false, fmt.Errorf("check usage in ledger: %w", err)
	}
	return exists, nil
}

func (r *costCenterRepository) CheckUsageInEmployees(ctx context.Context, db DBTX, costCenterID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(
		SELECT 1 FROM employee_profiles
		WHERE cost_center_id = $1
		LIMIT 1
	)`
	var exists bool
	if err := db.QueryRowContext(ctx, query, costCenterID).Scan(&exists); err != nil {
		return false, fmt.Errorf("check usage in employees: %w", err)
	}
	return exists, nil
}

// ============================================================
// BULK READS
// ============================================================

func (r *costCenterRepository) GetByIDs(ctx context.Context, db DBTX, companyID uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]*models.CostCenter, error) {
	if len(ids) == 0 {
		return map[uuid.UUID]*models.CostCenter{}, nil
	}
	deduped := dedupeUUIDs(ids)

	query := `SELECT ` + costCenterSelectCols + `
		FROM accounting.cost_centers
		WHERE company_id = $1 AND cost_center_id = ANY($2) AND deleted_at IS NULL`

	rows, err := db.QueryContext(ctx, query, companyID, pq.Array(deduped))
	if err != nil {
		return nil, fmt.Errorf("get cost centers by IDs: %w", err)
	}
	defer rows.Close()

	result := make(map[uuid.UUID]*models.CostCenter, len(deduped))
	for rows.Next() {
		cc, err := r.scanCostCenter(rows)
		if err != nil {
			return nil, fmt.Errorf("scan cost center in GetByIDs: %w", err)
		}
		result[cc.CostCenterID] = cc
	}
	return result, nil
}

func (r *costCenterRepository) GetActiveByIDs(ctx context.Context, db DBTX, companyID uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]*models.CostCenter, error) {
	if len(ids) == 0 {
		return map[uuid.UUID]*models.CostCenter{}, nil
	}
	deduped := dedupeUUIDs(ids)

	query := `SELECT ` + costCenterSelectCols + `
		FROM accounting.cost_centers
		WHERE company_id = $1
		  AND cost_center_id = ANY($2)
		  AND deleted_at IS NULL
		  AND is_active = true`

	rows, err := db.QueryContext(ctx, query, companyID, pq.Array(deduped))
	if err != nil {
		return nil, fmt.Errorf("get active cost centers by IDs: %w", err)
	}
	defer rows.Close()

	result := make(map[uuid.UUID]*models.CostCenter)
	for rows.Next() {
		cc, err := r.scanCostCenter(rows)
		if err != nil {
			return nil, fmt.Errorf("scan cost center in GetActiveByIDs: %w", err)
		}
		result[cc.CostCenterID] = cc
	}
	return result, nil
}

func (r *costCenterRepository) ValidateCostCenterIDs(ctx context.Context, db DBTX, companyID uuid.UUID, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}
	deduped := dedupeUUIDs(ids)

	query := `
		SELECT COUNT(*) = $2
		FROM (
			SELECT DISTINCT cost_center_id
			FROM accounting.cost_centers
			WHERE company_id = $1
			  AND cost_center_id = ANY($3)
			  AND deleted_at IS NULL
		) t
	`
	var valid bool
	if err := db.QueryRowContext(ctx, query, companyID, len(deduped), pq.Array(deduped)).Scan(&valid); err != nil {
		return fmt.Errorf("validate cost center IDs: %w", err)
	}
	if !valid {
		return fmt.Errorf("one or more cost center IDs are invalid, deleted, or belong to a different company")
	}
	return nil
}

// ============================================================
// LOCKING
// ============================================================

func (r *costCenterRepository) LockCostCenter(ctx context.Context, db DBTX, costCenterID uuid.UUID) error {
	query := `SELECT cost_center_id FROM accounting.cost_centers
		WHERE cost_center_id = $1 AND deleted_at IS NULL
		FOR UPDATE`
	var id uuid.UUID
	if err := db.QueryRowContext(ctx, query, costCenterID).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("lock cost center: %w", err)
	}
	return nil
}

// ============================================================
// HELPERS
// ============================================================

// dedupeUUIDs returns unique UUIDs preserving nothing about order.
// If account_repository.go already defines this, delete this copy and
// rely on the shared one.
func dedupeUUIDs(ids []uuid.UUID) []uuid.UUID {
	seen := make(map[uuid.UUID]struct{}, len(ids))
	out := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}
