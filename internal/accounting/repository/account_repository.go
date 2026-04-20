package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/accounting/models"
	"auth-service/internal/util"
)

// DBTX is the database interface that can be satisfied by *sql.DB or *sql.Tx
type DBTX interface {
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
}

// AccountFilter defines filter criteria for listing accounts
type AccountFilter struct {
	CompanyID       uuid.UUID
	AccountType     *string
	IsActive        *bool
	ParentAccountID *uuid.UUID
	Search          string // searches account_code and account_name
}

// Pagination holds limit and offset for paginated queries
type Pagination struct {
	Limit  int
	Offset int
}

// Sort holds field and direction for sorting
type Sort struct {
	Field     string
	Direction string
}

// AccountTreeNode represents an account in a hierarchical tree structure
type AccountTreeNode struct {
	Account  *models.Account
	Children []*AccountTreeNode
}

// AccountRepository defines the interface for account data access
type AccountRepository interface {
	// Write operations
	Create(ctx context.Context, db DBTX, a *models.Account) error
	BulkCreate(ctx context.Context, db DBTX, accounts []*models.Account) error
	Upsert(ctx context.Context, db DBTX, a *models.Account) error
	Update(ctx context.Context, db DBTX, a *models.Account) error
	UpdateStatus(ctx context.Context, db DBTX, accountID uuid.UUID, isActive bool, updatedBy *uuid.UUID) error
	UpdateParent(ctx context.Context, db DBTX, accountID uuid.UUID, parentID *uuid.UUID, updatedBy *uuid.UUID) error
	Delete(ctx context.Context, db DBTX, accountID uuid.UUID, deletedBy *uuid.UUID) error

	// Read operations
	GetByID(ctx context.Context, db DBTX, accountID uuid.UUID) (*models.Account, error)
	GetByIDForUpdate(ctx context.Context, db DBTX, accountID uuid.UUID) (*models.Account, error)
	GetByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (*models.Account, error)
	ExistsByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (bool, error)
	List(ctx context.Context, db DBTX, filter AccountFilter, p Pagination, s Sort) ([]*models.Account, error)
	ListByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Account, error)
	Count(ctx context.Context, db DBTX, filter AccountFilter) (int64, error)

	// Hierarchy operations
	GetChildren(ctx context.Context, db DBTX, parentID uuid.UUID) ([]*models.Account, error)
	GetTree(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*AccountTreeNode, error)
	HasChildren(ctx context.Context, db DBTX, accountID uuid.UUID) (bool, error)

	// Validation / safety
	CheckCircularReference(ctx context.Context, db DBTX, accountID uuid.UUID, parentID *uuid.UUID) (bool, error)
	CheckUsageInJournal(ctx context.Context, db DBTX, accountID uuid.UUID) (bool, error)

	// Locking
	LockAccount(ctx context.Context, db DBTX, accountID uuid.UUID) error
}

// accountRepository implements AccountRepository
type accountRepository struct {
	logger *zap.Logger
}

// NewAccountRepository creates a new account repository instance
func NewAccountRepository(logger *zap.Logger) AccountRepository {
	return &accountRepository{
		logger: logger.Named("account_repo"),
	}
}

// allowed sort fields for accounts
var allowedAccountSortFields = map[string]bool{
	"account_code": true,
	"account_name": true,
	"account_type": true,
	"created_at":   true,
	"updated_at":   true,
}

// validateSort returns a safe ORDER BY clause
func (r *accountRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "account_code"
	}
	if !allowedAccountSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "ASC"
	}
	return fmt.Sprintf("ORDER BY %s %s", field, dir), nil
}

// validatePagination returns sanitized limit and offset
func (r *accountRepository) validatePagination(p Pagination) (int, int) {
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

// buildAccountFilter constructs WHERE clause and arguments
func (r *accountRepository) buildAccountFilter(filter AccountFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.AccountType != nil {
		conditions = append(conditions, fmt.Sprintf("account_type = $%d", idx))
		args = append(args, *filter.AccountType)
		idx++
	}
	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}
	if filter.ParentAccountID != nil {
		if *filter.ParentAccountID == uuid.Nil {
			conditions = append(conditions, fmt.Sprintf("parent_account_id IS NULL"))
		} else {
			conditions = append(conditions, fmt.Sprintf("parent_account_id = $%d", idx))
			args = append(args, *filter.ParentAccountID)
			idx++
		}
	}
	if filter.Search != "" {
		searchPattern := "%" + filter.Search + "%"
		conditions = append(conditions, fmt.Sprintf("(account_code ILIKE $%d OR account_name ILIKE $%d)", idx, idx+1))
		args = append(args, searchPattern, searchPattern)
		idx += 2
	}

	// Soft delete condition
	conditions = append(conditions, "deleted_at IS NULL")

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

// scanAccount scans a row into an Account model, handling nullable fields
func (r *accountRepository) scanAccount(scanner interface {
	Scan(dest ...interface{}) error
}) (*models.Account, error) {
	var a models.Account
	var parentID uuid.NullUUID
	var createdBy, updatedBy uuid.NullUUID
	var deletedAt sql.NullTime

	err := scanner.Scan(
		&a.AccountID, &a.CompanyID, &a.AccountCode, &a.AccountName,
		&a.AccountType, &parentID, &a.IsActive, &a.Description,
		&a.CreatedAt, &a.UpdatedAt, &createdBy, &updatedBy, &deletedAt,
	)
	if err != nil {
		return nil, err
	}

	if parentID.Valid {
		a.ParentAccountID = &parentID.UUID
	}
	if createdBy.Valid {
		a.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		a.UpdatedBy = &updatedBy.UUID
	}
	if deletedAt.Valid {
		a.DeletedAt = &deletedAt.Time
	}
	return &a, nil
}

// Create inserts a new account
func (r *accountRepository) Create(ctx context.Context, db DBTX, a *models.Account) error {
	query := `
		INSERT INTO accounting.accounts (
			account_id, company_id, account_code, account_name, account_type,
			parent_account_id, is_active, description,
			created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW(), $9, $10)
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		a.AccountID, a.CompanyID, a.AccountCode, a.AccountName, a.AccountType,
		a.ParentAccountID, a.IsActive, a.Description,
		a.CreatedBy, a.UpdatedBy,
	).Scan(&a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create account",
			util.String("company_id", a.CompanyID.String()),
			util.String("code", a.AccountCode),
			util.ErrorField(err))
		return fmt.Errorf("create account: %w", err)
	}
	return nil
}

// BulkCreate inserts multiple accounts in a single transaction using a prepared statement
func (r *accountRepository) BulkCreate(ctx context.Context, db DBTX, accounts []*models.Account) error {
	if len(accounts) == 0 {
		return nil
	}
	stmt, err := db.PrepareContext(ctx, `
		INSERT INTO accounting.accounts (
			account_id, company_id, account_code, account_name, account_type,
			parent_account_id, is_active, description,
			created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW(), $9, $10)
		RETURNING created_at, updated_at
	`)
	if err != nil {
		return fmt.Errorf("prepare bulk insert: %w", err)
	}
	defer stmt.Close()

	for _, a := range accounts {
		err = stmt.QueryRowContext(ctx,
			a.AccountID, a.CompanyID, a.AccountCode, a.AccountName, a.AccountType,
			a.ParentAccountID, a.IsActive, a.Description,
			a.CreatedBy, a.UpdatedBy,
		).Scan(&a.CreatedAt, &a.UpdatedAt)
		if err != nil {
			r.logger.Error("bulk create failed",
				util.String("company_id", a.CompanyID.String()),
				util.String("code", a.AccountCode),
				util.ErrorField(err))
			return fmt.Errorf("bulk create account: %w", err)
		}
	}
	return nil
}

// Upsert inserts or updates an account based on unique constraint (company_id, account_code)
func (r *accountRepository) Upsert(ctx context.Context, db DBTX, a *models.Account) error {
	query := `
		INSERT INTO accounting.accounts (
			account_id, company_id, account_code, account_name, account_type,
			parent_account_id, is_active, description,
			created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW(), $9, $10)
		ON CONFLICT (company_id, account_code) WHERE deleted_at IS NULL
		DO UPDATE SET
			account_name = EXCLUDED.account_name,
			account_type = EXCLUDED.account_type,
			parent_account_id = EXCLUDED.parent_account_id,
			is_active = EXCLUDED.is_active,
			description = EXCLUDED.description,
			updated_by = EXCLUDED.updated_by,
			updated_at = NOW()
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		a.AccountID, a.CompanyID, a.AccountCode, a.AccountName, a.AccountType,
		a.ParentAccountID, a.IsActive, a.Description,
		a.CreatedBy, a.UpdatedBy,
	).Scan(&a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to upsert account",
			util.String("company_id", a.CompanyID.String()),
			util.String("code", a.AccountCode),
			util.ErrorField(err))
		return fmt.Errorf("upsert account: %w", err)
	}
	return nil
}

// Update updates an existing account (full update except ID and timestamps)
func (r *accountRepository) Update(ctx context.Context, db DBTX, a *models.Account) error {
	query := `
		UPDATE accounting.accounts
		SET account_name = $2,
		    account_type = $3,
		    parent_account_id = $4,
		    is_active = $5,
		    description = $6,
		    updated_by = $7,
		    updated_at = NOW()
		WHERE account_id = $1 AND deleted_at IS NULL
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		a.AccountID, a.AccountName, a.AccountType,
		a.ParentAccountID, a.IsActive, a.Description,
		a.UpdatedBy,
	).Scan(&a.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("account %s not found or already deleted", a.AccountID)
		}
		r.logger.Error("failed to update account",
			util.String("id", a.AccountID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update account: %w", err)
	}
	return nil
}

// UpdateStatus toggles the active status of an account
func (r *accountRepository) UpdateStatus(ctx context.Context, db DBTX, accountID uuid.UUID, isActive bool, updatedBy *uuid.UUID) error {
	query := `
		UPDATE accounting.accounts
		SET is_active = $2, updated_by = $3, updated_at = NOW()
		WHERE account_id = $1 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, accountID, isActive, updatedBy)
	if err != nil {
		r.logger.Error("failed to update account status",
			util.String("id", accountID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update account status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("account %s not found or already deleted", accountID)
	}
	return nil
}

// UpdateParent changes the parent account of an account
func (r *accountRepository) UpdateParent(ctx context.Context, db DBTX, accountID uuid.UUID, parentID *uuid.UUID, updatedBy *uuid.UUID) error {
	query := `
		UPDATE accounting.accounts
		SET parent_account_id = $2, updated_by = $3, updated_at = NOW()
		WHERE account_id = $1 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, accountID, parentID, updatedBy)
	if err != nil {
		r.logger.Error("failed to update account parent",
			util.String("id", accountID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update account parent: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("account %s not found or already deleted", accountID)
	}
	return nil
}

// Delete soft-deletes an account by setting deleted_at
func (r *accountRepository) Delete(ctx context.Context, db DBTX, accountID uuid.UUID, deletedBy *uuid.UUID) error {
	query := `
		UPDATE accounting.accounts
		SET deleted_at = NOW(), updated_by = $2, updated_at = NOW()
		WHERE account_id = $1 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, accountID, deletedBy)
	if err != nil {
		r.logger.Error("failed to delete account",
			util.String("id", accountID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete account: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("account %s not found or already deleted", accountID)
	}
	return nil
}

// GetByID retrieves an account by its ID
func (r *accountRepository) GetByID(ctx context.Context, db DBTX, accountID uuid.UUID) (*models.Account, error) {
	query := `
		SELECT account_id, company_id, account_code, account_name, account_type,
		       parent_account_id, is_active, description,
		       created_at, updated_at, created_by, updated_by, deleted_at
		FROM accounting.accounts
		WHERE account_id = $1 AND deleted_at IS NULL
	`
	var a models.Account
	var parentID uuid.NullUUID
	var createdBy, updatedBy uuid.NullUUID
	var deletedAt sql.NullTime

	err := db.QueryRowContext(ctx, query, accountID).Scan(
		&a.AccountID, &a.CompanyID, &a.AccountCode, &a.AccountName, &a.AccountType,
		&parentID, &a.IsActive, &a.Description,
		&a.CreatedAt, &a.UpdatedAt, &createdBy, &updatedBy, &deletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get account by ID",
			util.String("id", accountID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get account by ID: %w", err)
	}
	if parentID.Valid {
		a.ParentAccountID = &parentID.UUID
	}
	if createdBy.Valid {
		a.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		a.UpdatedBy = &updatedBy.UUID
	}
	if deletedAt.Valid {
		a.DeletedAt = &deletedAt.Time
	}
	return &a, nil
}

// GetByIDForUpdate retrieves an account with row-level locking for update
func (r *accountRepository) GetByIDForUpdate(ctx context.Context, db DBTX, accountID uuid.UUID) (*models.Account, error) {
	query := `
		SELECT account_id, company_id, account_code, account_name, account_type,
		       parent_account_id, is_active, description,
		       created_at, updated_at, created_by, updated_by, deleted_at
		FROM accounting.accounts
		WHERE account_id = $1 AND deleted_at IS NULL
		FOR UPDATE
	`
	var a models.Account
	var parentID uuid.NullUUID
	var createdBy, updatedBy uuid.NullUUID
	var deletedAt sql.NullTime

	err := db.QueryRowContext(ctx, query, accountID).Scan(
		&a.AccountID, &a.CompanyID, &a.AccountCode, &a.AccountName, &a.AccountType,
		&parentID, &a.IsActive, &a.Description,
		&a.CreatedAt, &a.UpdatedAt, &createdBy, &updatedBy, &deletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get account for update",
			util.String("id", accountID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get account for update: %w", err)
	}
	if parentID.Valid {
		a.ParentAccountID = &parentID.UUID
	}
	if createdBy.Valid {
		a.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		a.UpdatedBy = &updatedBy.UUID
	}
	if deletedAt.Valid {
		a.DeletedAt = &deletedAt.Time
	}
	return &a, nil
}

// GetByCode retrieves an account by company and account code
func (r *accountRepository) GetByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (*models.Account, error) {
	query := `
		SELECT account_id, company_id, account_code, account_name, account_type,
		       parent_account_id, is_active, description,
		       created_at, updated_at, created_by, updated_by, deleted_at
		FROM accounting.accounts
		WHERE company_id = $1 AND account_code = $2 AND deleted_at IS NULL
	`
	var a models.Account
	var parentID uuid.NullUUID
	var createdBy, updatedBy uuid.NullUUID
	var deletedAt sql.NullTime

	err := db.QueryRowContext(ctx, query, companyID, code).Scan(
		&a.AccountID, &a.CompanyID, &a.AccountCode, &a.AccountName, &a.AccountType,
		&parentID, &a.IsActive, &a.Description,
		&a.CreatedAt, &a.UpdatedAt, &createdBy, &updatedBy, &deletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get account by code",
			util.String("company_id", companyID.String()),
			util.String("code", code),
			util.ErrorField(err))
		return nil, fmt.Errorf("get account by code: %w", err)
	}
	if parentID.Valid {
		a.ParentAccountID = &parentID.UUID
	}
	if createdBy.Valid {
		a.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		a.UpdatedBy = &updatedBy.UUID
	}
	if deletedAt.Valid {
		a.DeletedAt = &deletedAt.Time
	}
	return &a, nil
}

// ExistsByCode checks if an account code exists for a company
func (r *accountRepository) ExistsByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM accounting.accounts WHERE company_id = $1 AND account_code = $2 AND deleted_at IS NULL)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, code).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check existence by code",
			util.String("company_id", companyID.String()),
			util.String("code", code),
			util.ErrorField(err))
		return false, fmt.Errorf("exists by code: %w", err)
	}
	return exists, nil
}

// List returns a paginated list of accounts matching the filter
func (r *accountRepository) List(ctx context.Context, db DBTX, filter AccountFilter, p Pagination, s Sort) ([]*models.Account, error) {
	where, args := r.buildAccountFilter(filter)
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT account_id, company_id, account_code, account_name, account_type,
		       parent_account_id, is_active, description,
		       created_at, updated_at, created_by, updated_by, deleted_at
		FROM accounting.accounts
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list accounts",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list accounts: %w", err)
	}
	defer rows.Close()

	var result []*models.Account
	for rows.Next() {
		a, err := r.scanAccount(rows)
		if err != nil {
			return nil, fmt.Errorf("scan account: %w", err)
		}
		result = append(result, a)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// ListByCompany returns all accounts for a company (convenience wrapper)
func (r *accountRepository) ListByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Account, error) {
	return r.List(ctx, db, AccountFilter{CompanyID: companyID}, Pagination{Limit: 1000}, Sort{Field: "account_code", Direction: "ASC"})
}

// Count returns the number of accounts matching the filter
func (r *accountRepository) Count(ctx context.Context, db DBTX, filter AccountFilter) (int64, error) {
	where, args := r.buildAccountFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM accounting.accounts %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count accounts",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count accounts: %w", err)
	}
	return count, nil
}

// GetChildren returns direct children of a parent account
func (r *accountRepository) GetChildren(ctx context.Context, db DBTX, parentID uuid.UUID) ([]*models.Account, error) {
	query := `
		SELECT account_id, company_id, account_code, account_name, account_type,
		       parent_account_id, is_active, description,
		       created_at, updated_at, created_by, updated_by, deleted_at
		FROM accounting.accounts
		WHERE parent_account_id = $1 AND deleted_at IS NULL
		ORDER BY account_code
	`
	rows, err := db.QueryContext(ctx, query, parentID)
	if err != nil {
		r.logger.Error("failed to get children",
			util.String("parent_id", parentID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get children: %w", err)
	}
	defer rows.Close()

	var children []*models.Account
	for rows.Next() {
		a, err := r.scanAccount(rows)
		if err != nil {
			return nil, fmt.Errorf("scan child account: %w", err)
		}
		children = append(children, a)
	}
	return children, nil
}

// GetTree returns the full account hierarchy tree for a company
func (r *accountRepository) GetTree(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*AccountTreeNode, error) {
	// Fetch all accounts for the company
	all, err := r.ListByCompany(ctx, db, companyID)
	if err != nil {
		return nil, err
	}

	// Build map of account pointers
	accountMap := make(map[uuid.UUID]*models.Account)
	for _, acc := range all {
		accountMap[acc.AccountID] = acc
	}

	// Build map of children
	childrenMap := make(map[uuid.UUID][]*models.Account)
	for _, acc := range all {
		if acc.ParentAccountID != nil {
			parentID := *acc.ParentAccountID
			childrenMap[parentID] = append(childrenMap[parentID], acc)
		}
	}

	// Recursive function to build tree nodes
	var buildTree func(parentID *uuid.UUID) []*AccountTreeNode
	buildTree = func(parentID *uuid.UUID) []*AccountTreeNode {
		var nodes []*AccountTreeNode
		for _, acc := range all {
			if (parentID == nil && acc.ParentAccountID == nil) ||
				(parentID != nil && acc.ParentAccountID != nil && *acc.ParentAccountID == *parentID) {
				node := &AccountTreeNode{
					Account:  acc,
					Children: buildTree(&acc.AccountID),
				}
				nodes = append(nodes, node)
			}
		}
		return nodes
	}

	return buildTree(nil), nil
}

// HasChildren checks if an account has any child accounts
func (r *accountRepository) HasChildren(ctx context.Context, db DBTX, accountID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM accounting.accounts WHERE parent_account_id = $1 AND deleted_at IS NULL)`
	var exists bool
	err := db.QueryRowContext(ctx, query, accountID).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check children",
			util.String("account_id", accountID.String()),
			util.ErrorField(err))
		return false, fmt.Errorf("has children: %w", err)
	}
	return exists, nil
}

// CheckCircularReference detects if setting parent_id would create a cycle in the hierarchy
func (r *accountRepository) CheckCircularReference(ctx context.Context, db DBTX, accountID uuid.UUID, parentID *uuid.UUID) (bool, error) {
	if parentID == nil {
		return false, nil
	}
	// Traverse up from parentID, if we ever reach accountID, it's a cycle
	current := *parentID
	for current != uuid.Nil {
		if current == accountID {
			return true, nil
		}
		// Get parent of current
		query := `SELECT parent_account_id FROM accounting.accounts WHERE account_id = $1 AND deleted_at IS NULL`
		var nextParent uuid.NullUUID
		err := db.QueryRowContext(ctx, query, current).Scan(&nextParent)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				break
			}
			r.logger.Error("failed to traverse hierarchy",
				util.String("account_id", accountID.String()),
				util.ErrorField(err))
			return false, fmt.Errorf("check circular reference: %w", err)
		}
		if !nextParent.Valid {
			break
		}
		current = nextParent.UUID
	}
	return false, nil
}

// CheckUsageInJournal checks if the account is referenced in any journal line (posted entries)
func (r *accountRepository) CheckUsageInJournal(ctx context.Context, db DBTX, accountID uuid.UUID) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM accounting.journal_lines jl
			INNER JOIN accounting.journal_entries je ON jl.journal_entry_id = je.journal_entry_id
			WHERE jl.account_id = $1 AND je.status = 'posted' AND je.deleted_at IS NULL
		)
	`
	var exists bool
	err := db.QueryRowContext(ctx, query, accountID).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check journal usage",
			util.String("account_id", accountID.String()),
			util.ErrorField(err))
		return false, fmt.Errorf("check usage in journal: %w", err)
	}
	return exists, nil
}

// LockAccount acquires a row-level lock on an account (for use within a transaction)
func (r *accountRepository) LockAccount(ctx context.Context, db DBTX, accountID uuid.UUID) error {
	query := `SELECT account_id FROM accounting.accounts WHERE account_id = $1 FOR UPDATE`
	var id uuid.UUID
	err := db.QueryRowContext(ctx, query, accountID).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("account %s not found", accountID)
		}
		r.logger.Error("failed to lock account",
			util.String("account_id", accountID.String()),
			util.ErrorField(err))
		return fmt.Errorf("lock account: %w", err)
	}
	return nil
}
