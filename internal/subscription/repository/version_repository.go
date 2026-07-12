// FILE: repository/version_repository.go

package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/subscription/models"

	"go.uber.org/zap"
)

// -------------------------------------------------------------------------
// VersionRepository Interface
// -------------------------------------------------------------------------

type VersionRepository interface {
	// -------------------------------------------------------------------------
	// CRUD
	// -------------------------------------------------------------------------

	Create(ctx context.Context, db DBTX, version *models.PlanVersion) error
	GetByID(ctx context.Context, db DBTX, companyID, versionID uuid.UUID) (*models.PlanVersion, error)
	GetByPlanAndVersion(ctx context.Context, db DBTX, companyID, planID uuid.UUID, version int) (*models.PlanVersion, error)
	Update(ctx context.Context, db DBTX, version *models.PlanVersion) error
	Delete(ctx context.Context, db DBTX, companyID, versionID uuid.UUID) error

	// -------------------------------------------------------------------------
	// Publishing
	// -------------------------------------------------------------------------

	Publish(ctx context.Context, db DBTX, companyID, versionID uuid.UUID, publishedBy uuid.UUID) error
	Unpublish(ctx context.Context, db DBTX, companyID, versionID uuid.UUID) error
	Restore(ctx context.Context, db DBTX, companyID, versionID uuid.UUID) error

	// -------------------------------------------------------------------------
	// Validation
	// -------------------------------------------------------------------------

	Exists(ctx context.Context, db DBTX, companyID, versionID uuid.UUID) (bool, error)
	ExistsVersion(ctx context.Context, db DBTX, companyID, planID uuid.UUID, version int) (bool, error)
	IsPublished(ctx context.Context, db DBTX, companyID, versionID uuid.UUID) (bool, error)

	// -------------------------------------------------------------------------
	// Querying
	// -------------------------------------------------------------------------

	List(ctx context.Context, db DBTX, filter VersionFilter, p Pagination, s Sort) ([]*models.PlanVersion, int64, error)
	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.PlanVersion, int64, error)
	GetByPlan(ctx context.Context, db DBTX, companyID, planID uuid.UUID) ([]*models.PlanVersion, error)
	GetPublished(ctx context.Context, db DBTX, companyID, planID uuid.UUID) ([]*models.PlanVersion, error)
	GetLatest(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (*models.PlanVersion, error)

	// -------------------------------------------------------------------------
	// Locking
	// -------------------------------------------------------------------------

	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, versionID uuid.UUID) (*models.PlanVersion, error)

	// -------------------------------------------------------------------------
	// NEW: Retrieve including soft-deleted
	// -------------------------------------------------------------------------

	GetByIDIncludingDeleted(ctx context.Context, db DBTX, companyID, versionID uuid.UUID) (*models.PlanVersion, error)
}

// -------------------------------------------------------------------------
// Filter, Pagination, Sort
// -------------------------------------------------------------------------

type VersionFilter struct {
	CompanyID uuid.UUID

	VersionIDs []uuid.UUID

	PlanID *uuid.UUID

	VersionMin *int
	VersionMax *int

	IsPublished *bool

	PublishedFrom *time.Time
	PublishedTo   *time.Time

	CreatedFrom *time.Time
	CreatedTo   *time.Time

	UpdatedFrom *time.Time
	UpdatedTo   *time.Time
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type versionRepository struct {
	logger *zap.Logger
}

// NewVersionRepository creates a new VersionRepository.
func NewVersionRepository(logger *zap.Logger) VersionRepository {
	return &versionRepository{
		logger: logger.Named("subscription_version_repo"),
	}
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (r *versionRepository) Create(ctx context.Context, db DBTX, version *models.PlanVersion) error {
	query := `
		INSERT INTO subscription.plan_versions (
			version_id, company_id, plan_id, version_number, snapshot,
			is_published, published_at, published_by, created_at, updated_at, deleted_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	_, err := db.ExecContext(ctx, query,
		version.VersionID,
		version.CompanyID,
		version.PlanID,
		version.VersionNumber,
		version.Snapshot,
		version.IsPublished,
		version.PublishedAt,
		version.PublishedBy,
		version.CreatedAt,
		version.UpdatedAt,
		version.DeletedAt,
	)
	if err != nil {
		r.logger.Error("failed to create plan version", zap.Error(err))
		return fmt.Errorf("create plan version: %w", err)
	}
	return nil
}

func (r *versionRepository) GetByID(ctx context.Context, db DBTX, companyID, versionID uuid.UUID) (*models.PlanVersion, error) {
	query := r.buildSelectQuery() + ` WHERE company_id = $1 AND version_id = $2 AND deleted_at IS NULL`
	var v models.PlanVersion
	err := r.scanVersion(ctx, db, query, &v, companyID, versionID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &v, nil
}

// GetByIDIncludingDeleted returns a version even if it has been soft-deleted.
func (r *versionRepository) GetByIDIncludingDeleted(ctx context.Context, db DBTX, companyID, versionID uuid.UUID) (*models.PlanVersion, error) {
	query := r.buildSelectQuery() + ` WHERE company_id = $1 AND version_id = $2` // no deleted_at filter
	var v models.PlanVersion
	err := r.scanVersion(ctx, db, query, &v, companyID, versionID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &v, nil
}

func (r *versionRepository) GetByPlanAndVersion(ctx context.Context, db DBTX, companyID, planID uuid.UUID, version int) (*models.PlanVersion, error) {
	query := r.buildSelectQuery() + ` WHERE company_id = $1 AND plan_id = $2 AND version_number = $3 AND deleted_at IS NULL`
	var v models.PlanVersion
	err := r.scanVersion(ctx, db, query, &v, companyID, planID, version)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &v, nil
}

func (r *versionRepository) Update(ctx context.Context, db DBTX, version *models.PlanVersion) error {
	query := `
		UPDATE subscription.plan_versions
		SET snapshot = $1,
		    is_published = $2,
		    published_at = $3,
		    published_by = $4,
		    updated_at = NOW(),
		    deleted_at = $5
		WHERE company_id = $6 AND version_id = $7
	`
	_, err := db.ExecContext(ctx, query,
		version.Snapshot,
		version.IsPublished,
		version.PublishedAt,
		version.PublishedBy,
		version.DeletedAt,
		version.CompanyID,
		version.VersionID,
	)
	if err != nil {
		r.logger.Error("failed to update plan version", zap.Error(err))
		return fmt.Errorf("update plan version: %w", err)
	}
	return nil
}

func (r *versionRepository) Delete(ctx context.Context, db DBTX, companyID, versionID uuid.UUID) error {
	query := `DELETE FROM subscription.plan_versions WHERE company_id = $1 AND version_id = $2`
	result, err := db.ExecContext(ctx, query, companyID, versionID)
	if err != nil {
		r.logger.Error("failed to delete plan version", zap.Error(err))
		return fmt.Errorf("delete plan version: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// -------------------------------------------------------------------------
// Publishing
// -------------------------------------------------------------------------

func (r *versionRepository) Publish(ctx context.Context, db DBTX, companyID, versionID uuid.UUID, publishedBy uuid.UUID) error {
	query := `
		UPDATE subscription.plan_versions
		SET is_published = true, published_at = NOW(), published_by = $1, updated_at = NOW()
		WHERE company_id = $2 AND version_id = $3
	`
	_, err := db.ExecContext(ctx, query, publishedBy, companyID, versionID)
	if err != nil {
		r.logger.Error("failed to publish plan version", zap.Error(err))
		return fmt.Errorf("publish plan version: %w", err)
	}
	return nil
}

func (r *versionRepository) Unpublish(ctx context.Context, db DBTX, companyID, versionID uuid.UUID) error {
	query := `
		UPDATE subscription.plan_versions
		SET is_published = false, published_at = NULL, published_by = NULL, updated_at = NOW()
		WHERE company_id = $1 AND version_id = $2
	`
	_, err := db.ExecContext(ctx, query, companyID, versionID)
	if err != nil {
		r.logger.Error("failed to unpublish plan version", zap.Error(err))
		return fmt.Errorf("unpublish plan version: %w", err)
	}
	return nil
}

func (r *versionRepository) Restore(ctx context.Context, db DBTX, companyID, versionID uuid.UUID) error {
	query := `
		UPDATE subscription.plan_versions
		SET deleted_at = NULL, updated_at = NOW()
		WHERE company_id = $1 AND version_id = $2
	`
	_, err := db.ExecContext(ctx, query, companyID, versionID)
	if err != nil {
		r.logger.Error("failed to restore plan version", zap.Error(err))
		return fmt.Errorf("restore plan version: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Validation
// -------------------------------------------------------------------------

func (r *versionRepository) Exists(ctx context.Context, db DBTX, companyID, versionID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.plan_versions WHERE company_id = $1 AND version_id = $2 AND deleted_at IS NULL)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, versionID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check exists: %w", err)
	}
	return exists, nil
}

func (r *versionRepository) ExistsVersion(ctx context.Context, db DBTX, companyID, planID uuid.UUID, version int) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.plan_versions WHERE company_id = $1 AND plan_id = $2 AND version_number = $3 AND deleted_at IS NULL)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, planID, version).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check version exists: %w", err)
	}
	return exists, nil
}

func (r *versionRepository) IsPublished(ctx context.Context, db DBTX, companyID, versionID uuid.UUID) (bool, error) {
	query := `SELECT is_published FROM subscription.plan_versions WHERE company_id = $1 AND version_id = $2 AND deleted_at IS NULL`
	var published bool
	err := db.QueryRowContext(ctx, query, companyID, versionID).Scan(&published)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("check is published: %w", err)
	}
	return published, nil
}

// -------------------------------------------------------------------------
// Querying
// -------------------------------------------------------------------------

func (r *versionRepository) List(ctx context.Context, db DBTX, filter VersionFilter, p Pagination, s Sort) ([]*models.PlanVersion, int64, error) {
	where, args := r.buildFilterConditions(filter)
	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	// Count total
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.plan_versions %s`, whereClause)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count plan versions: %w", err)
	}
	if total == 0 {
		return []*models.PlanVersion{}, 0, nil
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
		%s %s %s
		LIMIT $%d OFFSET $%d
	`, r.buildSelectQuery(), whereClause, sortClause, len(args)+1, len(args)+2)

	limitArgs := append(args, p.Limit, p.Offset)
	rows, err := db.QueryContext(ctx, query, limitArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list plan versions: %w", err)
	}
	defer rows.Close()

	var versions []*models.PlanVersion
	for rows.Next() {
		var v models.PlanVersion
		if err := r.scanVersionRows(rows, &v); err != nil {
			return nil, 0, fmt.Errorf("scan plan version: %w", err)
		}
		versions = append(versions, &v)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", err)
	}
	return versions, total, nil
}

func (r *versionRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.PlanVersion, int64, error) {
	searchPattern := "%" + query + "%"
	where := "company_id = $1 AND deleted_at IS NULL AND (version_number::text ILIKE $2 OR plan_id::text ILIKE $2)"
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.plan_versions WHERE %s`, where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, companyID, searchPattern).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count search: %w", err)
	}
	if total == 0 {
		return []*models.PlanVersion{}, 0, nil
	}

	dataQuery := fmt.Sprintf(`
		%s WHERE %s
		ORDER BY plan_id, version_number DESC
		LIMIT $%d OFFSET $%d
	`, r.buildSelectQuery(), where, 3, 4)

	rows, err := db.QueryContext(ctx, dataQuery, companyID, searchPattern, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("search plan versions: %w", err)
	}
	defer rows.Close()

	var versions []*models.PlanVersion
	for rows.Next() {
		var v models.PlanVersion
		if err := r.scanVersionRows(rows, &v); err != nil {
			return nil, 0, fmt.Errorf("scan plan version: %w", err)
		}
		versions = append(versions, &v)
	}
	return versions, total, rows.Err()
}

func (r *versionRepository) GetByPlan(ctx context.Context, db DBTX, companyID, planID uuid.UUID) ([]*models.PlanVersion, error) {
	query := r.buildSelectQuery() + ` WHERE company_id = $1 AND plan_id = $2 AND deleted_at IS NULL ORDER BY version_number DESC`
	rows, err := db.QueryContext(ctx, query, companyID, planID)
	if err != nil {
		return nil, fmt.Errorf("get by plan: %w", err)
	}
	defer rows.Close()
	return r.collectVersions(rows)
}

func (r *versionRepository) GetPublished(ctx context.Context, db DBTX, companyID, planID uuid.UUID) ([]*models.PlanVersion, error) {
	query := r.buildSelectQuery() + ` WHERE company_id = $1 AND plan_id = $2 AND is_published = true AND deleted_at IS NULL ORDER BY published_at DESC`
	rows, err := db.QueryContext(ctx, query, companyID, planID)
	if err != nil {
		return nil, fmt.Errorf("get published: %w", err)
	}
	defer rows.Close()
	return r.collectVersions(rows)
}

func (r *versionRepository) GetLatest(ctx context.Context, db DBTX, companyID, planID uuid.UUID) (*models.PlanVersion, error) {
	query := r.buildSelectQuery() + ` WHERE company_id = $1 AND plan_id = $2 AND deleted_at IS NULL ORDER BY version_number DESC LIMIT 1`
	var v models.PlanVersion
	err := r.scanVersion(ctx, db, query, &v, companyID, planID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &v, nil
}

// -------------------------------------------------------------------------
// Locking
// -------------------------------------------------------------------------

func (r *versionRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, versionID uuid.UUID) (*models.PlanVersion, error) {
	query := r.buildSelectQuery() + ` WHERE company_id = $1 AND version_id = $2 FOR UPDATE`
	var v models.PlanVersion
	err := r.scanVersion(ctx, db, query, &v, companyID, versionID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &v, nil
}

// -------------------------------------------------------------------------
// Helper functions
// -------------------------------------------------------------------------

// buildSelectQuery returns the SELECT columns for the plan_versions table.
func (r *versionRepository) buildSelectQuery() string {
	return `
		SELECT version_id, company_id, plan_id, version_number, snapshot,
		       is_published, published_at, published_by,
		       created_at, updated_at, deleted_at
		FROM subscription.plan_versions
	`
}

// scanVersion scans a single row into a models.PlanVersion.
func (r *versionRepository) scanVersion(ctx context.Context, db DBTX, query string, v *models.PlanVersion, args ...interface{}) error {
	return db.QueryRowContext(ctx, query, args...).Scan(
		&v.VersionID,
		&v.CompanyID,
		&v.PlanID,
		&v.VersionNumber,
		&v.Snapshot,
		&v.IsPublished,
		&v.PublishedAt,
		&v.PublishedBy,
		&v.CreatedAt,
		&v.UpdatedAt,
		&v.DeletedAt,
	)
}

// scanVersionRows scans the current row into a models.PlanVersion.
func (r *versionRepository) scanVersionRows(rows *sql.Rows, v *models.PlanVersion) error {
	return rows.Scan(
		&v.VersionID,
		&v.CompanyID,
		&v.PlanID,
		&v.VersionNumber,
		&v.Snapshot,
		&v.IsPublished,
		&v.PublishedAt,
		&v.PublishedBy,
		&v.CreatedAt,
		&v.UpdatedAt,
		&v.DeletedAt,
	)
}

// collectVersions reads all rows into a slice.
func (r *versionRepository) collectVersions(rows *sql.Rows) ([]*models.PlanVersion, error) {
	var versions []*models.PlanVersion
	for rows.Next() {
		var v models.PlanVersion
		if err := r.scanVersionRows(rows, &v); err != nil {
			return nil, fmt.Errorf("scan version: %w", err)
		}
		versions = append(versions, &v)
	}
	return versions, rows.Err()
}

// buildFilterConditions builds the WHERE clause and arguments from the filter.
func (r *versionRepository) buildFilterConditions(filter VersionFilter) ([]string, []interface{}) {
	var conditions []string
	var args []interface{}
	argPos := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", argPos))
		args = append(args, filter.CompanyID)
		argPos++
	}

	if len(filter.VersionIDs) > 0 {
		placeholders := make([]string, len(filter.VersionIDs))
		for i, id := range filter.VersionIDs {
			placeholders[i] = fmt.Sprintf("$%d", argPos+i)
			args = append(args, id)
		}
		conditions = append(conditions, fmt.Sprintf("version_id IN (%s)", strings.Join(placeholders, ",")))
		argPos += len(filter.VersionIDs)
	}

	if filter.PlanID != nil {
		conditions = append(conditions, fmt.Sprintf("plan_id = $%d", argPos))
		args = append(args, *filter.PlanID)
		argPos++
	}

	if filter.VersionMin != nil {
		conditions = append(conditions, fmt.Sprintf("version_number >= $%d", argPos))
		args = append(args, *filter.VersionMin)
		argPos++
	}
	if filter.VersionMax != nil {
		conditions = append(conditions, fmt.Sprintf("version_number <= $%d", argPos))
		args = append(args, *filter.VersionMax)
		argPos++
	}

	if filter.IsPublished != nil {
		conditions = append(conditions, fmt.Sprintf("is_published = $%d", argPos))
		args = append(args, *filter.IsPublished)
		argPos++
	}

	addDateRange(&conditions, &args, &argPos, "published_at", filter.PublishedFrom, filter.PublishedTo)
	addDateRange(&conditions, &args, &argPos, "created_at", filter.CreatedFrom, filter.CreatedTo)
	addDateRange(&conditions, &args, &argPos, "updated_at", filter.UpdatedFrom, filter.UpdatedTo)

	// Always exclude soft-deleted by default (no flag to include them in this filter)
	conditions = append(conditions, "deleted_at IS NULL")

	return conditions, args
}
