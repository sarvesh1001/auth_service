// FILE: repository/feature_repository.go

package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"auth-service/internal/subscription/models"

	"go.uber.org/zap"
)

// -------------------------------------------------------------------------
// FeatureRepository Interface
// -------------------------------------------------------------------------

type FeatureRepository interface {
	// -------------------------------------------------------------------------
	// CRUD
	// -------------------------------------------------------------------------

	Create(ctx context.Context, db DBTX, feature *models.FeatureRegistry) error
	GetByKey(ctx context.Context, db DBTX, featureKey string) (*models.FeatureRegistry, error)
	Update(ctx context.Context, db DBTX, feature *models.FeatureRegistry) error
	Delete(ctx context.Context, db DBTX, featureKey string) error

	// -------------------------------------------------------------------------
	// Status / Lifecycle
	// -------------------------------------------------------------------------

	Activate(ctx context.Context, db DBTX, featureKey string) error
	Deactivate(ctx context.Context, db DBTX, featureKey string) error

	// -------------------------------------------------------------------------
	// Validation
	// -------------------------------------------------------------------------

	Exists(ctx context.Context, db DBTX, featureKey string) (bool, error)
	IsActive(ctx context.Context, db DBTX, featureKey string) (bool, error)

	HasDependencies(ctx context.Context, db DBTX, featureKey string) (bool, error)
	GetDependencies(ctx context.Context, db DBTX, featureKey string) ([]string, error)

	// -------------------------------------------------------------------------
	// Querying
	// -------------------------------------------------------------------------

	List(ctx context.Context, db DBTX, filter FeatureFilter, p Pagination, s Sort) ([]*models.FeatureRegistry, int64, error)

	Search(ctx context.Context, db DBTX, query string, limit, offset int) ([]*models.FeatureRegistry, int64, error)

	GetActive(ctx context.Context, db DBTX) ([]*models.FeatureRegistry, error)

	GetByModule(ctx context.Context, db DBTX, module string) ([]*models.FeatureRegistry, error)

	GetByFeatureGroup(ctx context.Context, db DBTX, featureGroup string) ([]*models.FeatureRegistry, error)

	GetByPermissionScope(ctx context.Context, db DBTX, permissionScope string) ([]*models.FeatureRegistry, error)

	// -------------------------------------------------------------------------
	// Locking
	// -------------------------------------------------------------------------

	GetByKeyForUpdate(ctx context.Context, db DBTX, featureKey string) (*models.FeatureRegistry, error)
}

// -------------------------------------------------------------------------
// Filter, Pagination, Sort
// -------------------------------------------------------------------------

type FeatureFilter struct {
	FeatureKeys     []string
	Module          *string
	FeatureGroup    *string
	PermissionScope *string
	IsActive        *bool
	VersionMin      *int
	VersionMax      *int
	CreatedFrom     *time.Time
	CreatedTo       *time.Time
	UpdatedFrom     *time.Time
	UpdatedTo       *time.Time
}

// Pagination and Sort are defined in the same package or shared.
// If you have a shared package, you can remove these.

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type featureRepository struct {
	logger *zap.Logger
}

// NewFeatureRepository creates a new FeatureRepository.
func NewFeatureRepository(logger *zap.Logger) FeatureRepository {
	return &featureRepository{
		logger: logger.Named("subscription_feature_repo"),
	}
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (r *featureRepository) Create(ctx context.Context, db DBTX, feature *models.FeatureRegistry) error {
	query := `
		INSERT INTO subscription.feature_registry (
			feature_key, module, feature_group, permission_scope, description,
			default_limit, depends_on, version, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	_, err := db.ExecContext(ctx, query,
		feature.FeatureKey,
		feature.Module,
		feature.FeatureGroup,
		feature.PermissionScope,
		feature.Description,
		feature.DefaultLimit,
		pq.Array(feature.DependsOn),
		feature.Version,
		feature.IsActive,
		feature.CreatedAt,
		feature.UpdatedAt,
	)
	if err != nil {
		r.logger.Error("failed to create feature", zap.String("feature_key", feature.FeatureKey), zap.Error(err))
		return fmt.Errorf("create feature: %w", err)
	}
	return nil
}

func (r *featureRepository) GetByKey(ctx context.Context, db DBTX, featureKey string) (*models.FeatureRegistry, error) {
	query := `
		SELECT feature_key, module, feature_group, permission_scope, description,
		       default_limit, depends_on, version, is_active, created_at, updated_at
		FROM subscription.feature_registry
		WHERE feature_key = $1
	`
	var feature models.FeatureRegistry
	var dependsOn pq.StringArray
	err := db.QueryRowContext(ctx, query, featureKey).Scan(
		&feature.FeatureKey,
		&feature.Module,
		&feature.FeatureGroup,
		&feature.PermissionScope,
		&feature.Description,
		&feature.DefaultLimit,
		&dependsOn,
		&feature.Version,
		&feature.IsActive,
		&feature.CreatedAt,
		&feature.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get feature by key", zap.String("feature_key", featureKey), zap.Error(err))
		return nil, fmt.Errorf("get feature by key: %w", err)
	}
	feature.DependsOn = []string(dependsOn)
	return &feature, nil
}

func (r *featureRepository) Update(ctx context.Context, db DBTX, feature *models.FeatureRegistry) error {
	query := `
		UPDATE subscription.feature_registry
		SET module = $1,
		    feature_group = $2,
		    permission_scope = $3,
		    description = $4,
		    default_limit = $5,
		    depends_on = $6,
		    version = $7,
		    is_active = $8,
		    updated_at = $9
		WHERE feature_key = $10
	`
	_, err := db.ExecContext(ctx, query,
		feature.Module,
		feature.FeatureGroup,
		feature.PermissionScope,
		feature.Description,
		feature.DefaultLimit,
		pq.Array(feature.DependsOn),
		feature.Version,
		feature.IsActive,
		feature.UpdatedAt,
		feature.FeatureKey,
	)
	if err != nil {
		r.logger.Error("failed to update feature", zap.String("feature_key", feature.FeatureKey), zap.Error(err))
		return fmt.Errorf("update feature: %w", err)
	}
	return nil
}

func (r *featureRepository) Delete(ctx context.Context, db DBTX, featureKey string) error {
	query := `DELETE FROM subscription.feature_registry WHERE feature_key = $1`
	result, err := db.ExecContext(ctx, query, featureKey)
	if err != nil {
		r.logger.Error("failed to delete feature", zap.String("feature_key", featureKey), zap.Error(err))
		return fmt.Errorf("delete feature: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// -------------------------------------------------------------------------
// Status / Lifecycle
// -------------------------------------------------------------------------

func (r *featureRepository) Activate(ctx context.Context, db DBTX, featureKey string) error {
	query := `UPDATE subscription.feature_registry SET is_active = true, updated_at = NOW() WHERE feature_key = $1`
	_, err := db.ExecContext(ctx, query, featureKey)
	if err != nil {
		r.logger.Error("failed to activate feature", zap.String("feature_key", featureKey), zap.Error(err))
		return fmt.Errorf("activate feature: %w", err)
	}
	return nil
}

func (r *featureRepository) Deactivate(ctx context.Context, db DBTX, featureKey string) error {
	query := `UPDATE subscription.feature_registry SET is_active = false, updated_at = NOW() WHERE feature_key = $1`
	_, err := db.ExecContext(ctx, query, featureKey)
	if err != nil {
		r.logger.Error("failed to deactivate feature", zap.String("feature_key", featureKey), zap.Error(err))
		return fmt.Errorf("deactivate feature: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Validation
// -------------------------------------------------------------------------

func (r *featureRepository) Exists(ctx context.Context, db DBTX, featureKey string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.feature_registry WHERE feature_key = $1)`
	var exists bool
	err := db.QueryRowContext(ctx, query, featureKey).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check exist: %w", err)
	}
	return exists, nil
}

func (r *featureRepository) IsActive(ctx context.Context, db DBTX, featureKey string) (bool, error) {
	query := `SELECT is_active FROM subscription.feature_registry WHERE feature_key = $1`
	var active bool
	err := db.QueryRowContext(ctx, query, featureKey).Scan(&active)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("check is active: %w", err)
	}
	return active, nil
}

func (r *featureRepository) HasDependencies(ctx context.Context, db DBTX, featureKey string) (bool, error) {
	query := `SELECT array_length(depends_on, 1) > 0 FROM subscription.feature_registry WHERE feature_key = $1`
	var has bool
	err := db.QueryRowContext(ctx, query, featureKey).Scan(&has)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("check dependencies: %w", err)
	}
	return has, nil
}

func (r *featureRepository) GetDependencies(ctx context.Context, db DBTX, featureKey string) ([]string, error) {
	query := `SELECT depends_on FROM subscription.feature_registry WHERE feature_key = $1`
	var dependsOn pq.StringArray
	err := db.QueryRowContext(ctx, query, featureKey).Scan(&dependsOn)
	if err != nil {
		if err == sql.ErrNoRows {
			return []string{}, nil
		}
		return nil, fmt.Errorf("get dependencies: %w", err)
	}
	return []string(dependsOn), nil
}

// -------------------------------------------------------------------------
// Querying
// -------------------------------------------------------------------------

func (r *featureRepository) List(ctx context.Context, db DBTX, filter FeatureFilter, p Pagination, s Sort) ([]*models.FeatureRegistry, int64, error) {
	where, args := r.buildFilterConditions(filter)
	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	// Count total
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.feature_registry %s`, whereClause)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count features: %w", err)
	}
	if total == 0 {
		return []*models.FeatureRegistry{}, 0, nil
	}

	// Build sort
	sortClause := ""
	if s.Field != "" {
		direction := "ASC"
		if strings.ToUpper(s.Direction) == "DESC" {
			direction = "DESC"
		}
		sortClause = fmt.Sprintf("ORDER BY %s %s", s.Field, direction)
	} else {
		sortClause = "ORDER BY created_at DESC"
	}

	query := fmt.Sprintf(`
		SELECT feature_key, module, feature_group, permission_scope, description,
		       default_limit, depends_on, version, is_active, created_at, updated_at
		FROM subscription.feature_registry
		%s %s
		LIMIT $%d OFFSET $%d
	`, whereClause, sortClause, len(args)+1, len(args)+2)

	limitArgs := append(args, p.Limit, p.Offset)
	rows, err := db.QueryContext(ctx, query, limitArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list features: %w", err)
	}
	defer rows.Close()

	var features []*models.FeatureRegistry
	for rows.Next() {
		var feature models.FeatureRegistry
		var dependsOn pq.StringArray
		err := rows.Scan(
			&feature.FeatureKey,
			&feature.Module,
			&feature.FeatureGroup,
			&feature.PermissionScope,
			&feature.Description,
			&feature.DefaultLimit,
			&dependsOn,
			&feature.Version,
			&feature.IsActive,
			&feature.CreatedAt,
			&feature.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan feature: %w", err)
		}
		feature.DependsOn = []string(dependsOn)
		features = append(features, &feature)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", err)
	}
	return features, total, nil
}

func (r *featureRepository) Search(ctx context.Context, db DBTX, query string, limit, offset int) ([]*models.FeatureRegistry, int64, error) {
	searchPattern := "%" + query + "%"
	where := "feature_key ILIKE $1 OR module ILIKE $1 OR feature_group ILIKE $1 OR description ILIKE $1"
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.feature_registry WHERE %s`, where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, searchPattern).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count search features: %w", err)
	}
	if total == 0 {
		return []*models.FeatureRegistry{}, 0, nil
	}

	dataQuery := fmt.Sprintf(`
		SELECT feature_key, module, feature_group, permission_scope, description,
		       default_limit, depends_on, version, is_active, created_at, updated_at
		FROM subscription.feature_registry
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, 2, 3)

	rows, err := db.QueryContext(ctx, dataQuery, searchPattern, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("search features: %w", err)
	}
	defer rows.Close()

	var features []*models.FeatureRegistry
	for rows.Next() {
		var feature models.FeatureRegistry
		var dependsOn pq.StringArray
		err := rows.Scan(
			&feature.FeatureKey,
			&feature.Module,
			&feature.FeatureGroup,
			&feature.PermissionScope,
			&feature.Description,
			&feature.DefaultLimit,
			&dependsOn,
			&feature.Version,
			&feature.IsActive,
			&feature.CreatedAt,
			&feature.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan feature: %w", err)
		}
		feature.DependsOn = []string(dependsOn)
		features = append(features, &feature)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", err)
	}
	return features, total, nil
}

func (r *featureRepository) GetActive(ctx context.Context, db DBTX) ([]*models.FeatureRegistry, error) {
	query := `
		SELECT feature_key, module, feature_group, permission_scope, description,
		       default_limit, depends_on, version, is_active, created_at, updated_at
		FROM subscription.feature_registry
		WHERE is_active = true
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("get active features: %w", err)
	}
	defer rows.Close()

	var features []*models.FeatureRegistry
	for rows.Next() {
		var feature models.FeatureRegistry
		var dependsOn pq.StringArray
		err := rows.Scan(
			&feature.FeatureKey,
			&feature.Module,
			&feature.FeatureGroup,
			&feature.PermissionScope,
			&feature.Description,
			&feature.DefaultLimit,
			&dependsOn,
			&feature.Version,
			&feature.IsActive,
			&feature.CreatedAt,
			&feature.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan feature: %w", err)
		}
		feature.DependsOn = []string(dependsOn)
		features = append(features, &feature)
	}
	return features, rows.Err()
}

func (r *featureRepository) GetByModule(ctx context.Context, db DBTX, module string) ([]*models.FeatureRegistry, error) {
	query := `
		SELECT feature_key, module, feature_group, permission_scope, description,
		       default_limit, depends_on, version, is_active, created_at, updated_at
		FROM subscription.feature_registry
		WHERE module = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, module)
	if err != nil {
		return nil, fmt.Errorf("get by module: %w", err)
	}
	defer rows.Close()

	var features []*models.FeatureRegistry
	for rows.Next() {
		var feature models.FeatureRegistry
		var dependsOn pq.StringArray
		err := rows.Scan(
			&feature.FeatureKey,
			&feature.Module,
			&feature.FeatureGroup,
			&feature.PermissionScope,
			&feature.Description,
			&feature.DefaultLimit,
			&dependsOn,
			&feature.Version,
			&feature.IsActive,
			&feature.CreatedAt,
			&feature.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan feature: %w", err)
		}
		feature.DependsOn = []string(dependsOn)
		features = append(features, &feature)
	}
	return features, rows.Err()
}

func (r *featureRepository) GetByFeatureGroup(ctx context.Context, db DBTX, featureGroup string) ([]*models.FeatureRegistry, error) {
	query := `
		SELECT feature_key, module, feature_group, permission_scope, description,
		       default_limit, depends_on, version, is_active, created_at, updated_at
		FROM subscription.feature_registry
		WHERE feature_group = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, featureGroup)
	if err != nil {
		return nil, fmt.Errorf("get by feature group: %w", err)
	}
	defer rows.Close()

	var features []*models.FeatureRegistry
	for rows.Next() {
		var feature models.FeatureRegistry
		var dependsOn pq.StringArray
		err := rows.Scan(
			&feature.FeatureKey,
			&feature.Module,
			&feature.FeatureGroup,
			&feature.PermissionScope,
			&feature.Description,
			&feature.DefaultLimit,
			&dependsOn,
			&feature.Version,
			&feature.IsActive,
			&feature.CreatedAt,
			&feature.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan feature: %w", err)
		}
		feature.DependsOn = []string(dependsOn)
		features = append(features, &feature)
	}
	return features, rows.Err()
}

func (r *featureRepository) GetByPermissionScope(ctx context.Context, db DBTX, permissionScope string) ([]*models.FeatureRegistry, error) {
	query := `
		SELECT feature_key, module, feature_group, permission_scope, description,
		       default_limit, depends_on, version, is_active, created_at, updated_at
		FROM subscription.feature_registry
		WHERE permission_scope = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, permissionScope)
	if err != nil {
		return nil, fmt.Errorf("get by permission scope: %w", err)
	}
	defer rows.Close()

	var features []*models.FeatureRegistry
	for rows.Next() {
		var feature models.FeatureRegistry
		var dependsOn pq.StringArray
		err := rows.Scan(
			&feature.FeatureKey,
			&feature.Module,
			&feature.FeatureGroup,
			&feature.PermissionScope,
			&feature.Description,
			&feature.DefaultLimit,
			&dependsOn,
			&feature.Version,
			&feature.IsActive,
			&feature.CreatedAt,
			&feature.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan feature: %w", err)
		}
		feature.DependsOn = []string(dependsOn)
		features = append(features, &feature)
	}
	return features, rows.Err()
}

// -------------------------------------------------------------------------
// Locking
// -------------------------------------------------------------------------

func (r *featureRepository) GetByKeyForUpdate(ctx context.Context, db DBTX, featureKey string) (*models.FeatureRegistry, error) {
	query := `
		SELECT feature_key, module, feature_group, permission_scope, description,
		       default_limit, depends_on, version, is_active, created_at, updated_at
		FROM subscription.feature_registry
		WHERE feature_key = $1
		FOR UPDATE
	`
	var feature models.FeatureRegistry
	var dependsOn pq.StringArray
	err := db.QueryRowContext(ctx, query, featureKey).Scan(
		&feature.FeatureKey,
		&feature.Module,
		&feature.FeatureGroup,
		&feature.PermissionScope,
		&feature.Description,
		&feature.DefaultLimit,
		&dependsOn,
		&feature.Version,
		&feature.IsActive,
		&feature.CreatedAt,
		&feature.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get feature for update", zap.String("feature_key", featureKey), zap.Error(err))
		return nil, fmt.Errorf("get feature for update: %w", err)
	}
	feature.DependsOn = []string(dependsOn)
	return &feature, nil
}

// -------------------------------------------------------------------------
// Helper: build filter conditions
// -------------------------------------------------------------------------

func (r *featureRepository) buildFilterConditions(filter FeatureFilter) ([]string, []interface{}) {
	var conditions []string
	var args []interface{}
	argPos := 1

	if len(filter.FeatureKeys) > 0 {
		placeholders := make([]string, len(filter.FeatureKeys))
		for i, key := range filter.FeatureKeys {
			placeholders[i] = fmt.Sprintf("$%d", argPos+i)
			args = append(args, key)
		}
		conditions = append(conditions, fmt.Sprintf("feature_key IN (%s)", strings.Join(placeholders, ",")))
		argPos += len(filter.FeatureKeys)
	}

	if filter.Module != nil {
		conditions = append(conditions, fmt.Sprintf("module = $%d", argPos))
		args = append(args, *filter.Module)
		argPos++
	}

	if filter.FeatureGroup != nil {
		conditions = append(conditions, fmt.Sprintf("feature_group = $%d", argPos))
		args = append(args, *filter.FeatureGroup)
		argPos++
	}

	if filter.PermissionScope != nil {
		conditions = append(conditions, fmt.Sprintf("permission_scope = $%d", argPos))
		args = append(args, *filter.PermissionScope)
		argPos++
	}

	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argPos))
		args = append(args, *filter.IsActive)
		argPos++
	}

	if filter.VersionMin != nil {
		conditions = append(conditions, fmt.Sprintf("version >= $%d", argPos))
		args = append(args, *filter.VersionMin)
		argPos++
	}
	if filter.VersionMax != nil {
		conditions = append(conditions, fmt.Sprintf("version <= $%d", argPos))
		args = append(args, *filter.VersionMax)
		argPos++
	}

	if filter.CreatedFrom != nil {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", argPos))
		args = append(args, *filter.CreatedFrom)
		argPos++
	}
	if filter.CreatedTo != nil {
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", argPos))
		args = append(args, *filter.CreatedTo)
		argPos++
	}

	if filter.UpdatedFrom != nil {
		conditions = append(conditions, fmt.Sprintf("updated_at >= $%d", argPos))
		args = append(args, *filter.UpdatedFrom)
		argPos++
	}
	if filter.UpdatedTo != nil {
		conditions = append(conditions, fmt.Sprintf("updated_at <= $%d", argPos))
		args = append(args, *filter.UpdatedTo)
		argPos++
	}

	return conditions, args
}
