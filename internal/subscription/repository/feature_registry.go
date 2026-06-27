// repository/feature_registry_repository.go
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/models"
)

// ---------------------------------------------------------------------
// FeatureRegistryRepository Interface
// ---------------------------------------------------------------------

type FeatureRegistryRepository interface {
	// CRUD
	Create(ctx context.Context, db DBTX, feature *models.FeatureRegistry) error
	Update(ctx context.Context, db DBTX, feature *models.FeatureRegistry) error
	Delete(ctx context.Context, db DBTX, featureKey string) error

	// Single Fetch
	GetByKey(ctx context.Context, db DBTX, featureKey string) (*models.FeatureRegistry, error)

	// Listing
	List(ctx context.Context, db DBTX, filter FeatureRegistryFilter, p Pagination, s Sort) ([]*models.FeatureRegistry, int64, error)
	ListByModule(ctx context.Context, db DBTX, module string) ([]*models.FeatureRegistry, error)
	ListByPermissionScope(ctx context.Context, db DBTX, scope string) ([]*models.FeatureRegistry, error)
	ListActive(ctx context.Context, db DBTX) ([]*models.FeatureRegistry, error)

	// Validation
	Exists(ctx context.Context, db DBTX, featureKey string) (bool, error)

	// Search
	Search(ctx context.Context, db DBTX, query string, limit int, offset int) ([]*models.FeatureRegistry, int64, error)

	// Concurrency / Locking
	GetByKeyForUpdate(ctx context.Context, db DBTX, featureKey string) (*models.FeatureRegistry, error)
}

// ---------------------------------------------------------------------
// Filter
// ---------------------------------------------------------------------

type FeatureRegistryFilter struct {
	FeatureKeys     []string
	Module          *string
	FeatureGroup    *string
	PermissionScope *string
	IsActive        *bool
	Version         *int
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------

type featureRegistryRepository struct {
	logger *zap.Logger
}

func NewFeatureRegistryRepository(logger *zap.Logger) FeatureRegistryRepository {
	return &featureRegistryRepository{
		logger: logger.Named("subscription_feature_registry_repo"),
	}
}

const featureRegistryTable = "subscription.feature_registry"

// buildFeatureFilter builds WHERE clause for FeatureRegistry.
func buildFeatureFilter(filter FeatureRegistryFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if len(filter.FeatureKeys) > 0 {
		placeholders := make([]string, len(filter.FeatureKeys))
		for i, key := range filter.FeatureKeys {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, key)
			idx++
		}
		conds = append(conds, fmt.Sprintf("feature_key IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.Module != nil {
		conds = append(conds, fmt.Sprintf("module = $%d", idx))
		args = append(args, *filter.Module)
		idx++
	}
	if filter.FeatureGroup != nil {
		conds = append(conds, fmt.Sprintf("feature_group = $%d", idx))
		args = append(args, *filter.FeatureGroup)
		idx++
	}
	if filter.PermissionScope != nil {
		conds = append(conds, fmt.Sprintf("permission_scope = $%d", idx))
		args = append(args, *filter.PermissionScope)
		idx++
	}
	if filter.IsActive != nil {
		conds = append(conds, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}
	if filter.Version != nil {
		conds = append(conds, fmt.Sprintf("version = $%d", idx))
		args = append(args, *filter.Version)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// allowed sort fields for FeatureRegistry
var featureAllowedSort = map[string]bool{
	"feature_key":      true,
	"module":           true,
	"feature_group":    true,
	"permission_scope": true,
	"version":          true,
	"is_active":        true,
	"created_at":       true,
	"updated_at":       true,
}

func (r *featureRegistryRepository) scanFeatureRegistry(s scanner) (*models.FeatureRegistry, error) {
	var f models.FeatureRegistry
	var _ []string // GORM uses []string with pg array, but we scan as string and split.
	var dependsOnStr string

	err := s.Scan(
		&f.FeatureKey,
		&f.Module,
		&f.FeatureGroup,
		&f.PermissionScope,
		&f.Description,
		&f.DefaultLimit,
		&dependsOnStr, // scan as string
		&f.Version,
		&f.IsActive,
		&f.CreatedAt,
		&f.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan feature registry: %w", err)
	}

	// Parse depends_on if needed; dependsOnStr is like "{key1,key2}" from PostgreSQL
	// We can convert to slice using split.
	if len(dependsOnStr) > 2 {
		// remove braces
		trimmed := dependsOnStr[1 : len(dependsOnStr)-1]
		if trimmed != "" {
			f.DependsOn = strings.Split(trimmed, ",")
		} else {
			f.DependsOn = []string{}
		}
	} else {
		f.DependsOn = []string{}
	}
	return &f, nil
}

// ---------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------

func (r *featureRegistryRepository) Create(ctx context.Context, db DBTX, feature *models.FeatureRegistry) error {
	query := `
		INSERT INTO subscription.feature_registry (
			feature_key, module, feature_group, permission_scope,
			description, default_limit, depends_on, version, is_active,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
	`
	_, err := db.ExecContext(ctx, query,
		feature.FeatureKey,
		feature.Module,
		feature.FeatureGroup,
		feature.PermissionScope,
		feature.Description,
		feature.DefaultLimit,
		feature.DependsOn, // GORM maps to pg array; Exec accepts slice
		feature.Version,
		feature.IsActive,
	)
	if err != nil {
		return fmt.Errorf("create feature registry: %w", err)
	}
	return nil
}

func (r *featureRegistryRepository) Update(ctx context.Context, db DBTX, feature *models.FeatureRegistry) error {
	query := `
		UPDATE subscription.feature_registry SET
			module = $2,
			feature_group = $3,
			permission_scope = $4,
			description = $5,
			default_limit = $6,
			depends_on = $7,
			version = $8,
			is_active = $9,
			updated_at = NOW()
		WHERE feature_key = $1
	`
	result, err := db.ExecContext(ctx, query,
		feature.FeatureKey,
		feature.Module,
		feature.FeatureGroup,
		feature.PermissionScope,
		feature.Description,
		feature.DefaultLimit,
		feature.DependsOn,
		feature.Version,
		feature.IsActive,
	)
	if err != nil {
		return fmt.Errorf("update feature registry: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *featureRegistryRepository) Delete(ctx context.Context, db DBTX, featureKey string) error {
	query := `DELETE FROM subscription.feature_registry WHERE feature_key = $1`
	result, err := db.ExecContext(ctx, query, featureKey)
	if err != nil {
		return fmt.Errorf("delete feature registry: %w", err)
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

func (r *featureRegistryRepository) GetByKey(ctx context.Context, db DBTX, featureKey string) (*models.FeatureRegistry, error) {
	query := `
		SELECT feature_key, module, feature_group, permission_scope,
			description, default_limit, depends_on, version, is_active,
			created_at, updated_at
		FROM subscription.feature_registry
		WHERE feature_key = $1
	`
	row := db.QueryRowContext(ctx, query, featureKey)
	return r.scanFeatureRegistry(row)
}

// ---------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------

func (r *featureRegistryRepository) List(ctx context.Context, db DBTX, filter FeatureRegistryFilter, p Pagination, s Sort) ([]*models.FeatureRegistry, int64, error) {
	where, args := buildFeatureFilter(filter)

	orderBy, err := validateSort(s, featureAllowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY feature_key"
	}

	limit, offset := validatePagination(p)

	// Count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", featureRegistryTable, where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count features: %w", err)
	}
	if total == 0 {
		return []*models.FeatureRegistry{}, 0, nil
	}

	// Data
	query := fmt.Sprintf(`
		SELECT feature_key, module, feature_group, permission_scope,
			description, default_limit, depends_on, version, is_active,
			created_at, updated_at
		FROM %s
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, featureRegistryTable, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list features: %w", err)
	}
	defer rows.Close()

	var result []*models.FeatureRegistry
	for rows.Next() {
		f, err := r.scanFeatureRegistry(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, f)
	}
	return result, total, rows.Err()
}

func (r *featureRegistryRepository) ListByModule(ctx context.Context, db DBTX, module string) ([]*models.FeatureRegistry, error) {
	filter := FeatureRegistryFilter{Module: &module}
	features, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{})
	return features, err
}

func (r *featureRegistryRepository) ListByPermissionScope(ctx context.Context, db DBTX, scope string) ([]*models.FeatureRegistry, error) {
	filter := FeatureRegistryFilter{PermissionScope: &scope}
	features, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{})
	return features, err
}

func (r *featureRegistryRepository) ListActive(ctx context.Context, db DBTX) ([]*models.FeatureRegistry, error) {
	active := true
	filter := FeatureRegistryFilter{IsActive: &active}
	features, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{})
	return features, err
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

func (r *featureRegistryRepository) Exists(ctx context.Context, db DBTX, featureKey string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.feature_registry WHERE feature_key = $1)`
	err := db.QueryRowContext(ctx, query, featureKey).Scan(&exists)
	return exists, err
}

// ---------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------

func (r *featureRegistryRepository) Search(ctx context.Context, db DBTX, query string, limit int, offset int) ([]*models.FeatureRegistry, int64, error) {
	pattern := "%" + query + "%"
	baseQuery := `
		SELECT feature_key, module, feature_group, permission_scope,
			description, default_limit, depends_on, version, is_active,
			created_at, updated_at
		FROM subscription.feature_registry
	`
	where := "WHERE feature_key ILIKE $1 OR module ILIKE $1 OR description ILIKE $1"
	args := []interface{}{pattern}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM subscription.feature_registry %s", where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search feature count: %w", err)
	}
	if total == 0 {
		return []*models.FeatureRegistry{}, 0, nil
	}

	querySQL := fmt.Sprintf(`%s %s ORDER BY feature_key LIMIT $%d OFFSET $%d`, baseQuery, where, len(args)+1, len(args)+2)
	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search features: %w", err)
	}
	defer rows.Close()

	var result []*models.FeatureRegistry
	for rows.Next() {
		f, err := r.scanFeatureRegistry(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, f)
	}
	return result, total, rows.Err()
}

// ---------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------

func (r *featureRegistryRepository) GetByKeyForUpdate(ctx context.Context, db DBTX, featureKey string) (*models.FeatureRegistry, error) {
	query := `
		SELECT feature_key, module, feature_group, permission_scope,
			description, default_limit, depends_on, version, is_active,
			created_at, updated_at
		FROM subscription.feature_registry
		WHERE feature_key = $1
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, featureKey)
	return r.scanFeatureRegistry(row)
}
