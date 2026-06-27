// repository/subscription_version.go
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/datatypes"

	"auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/models"
)

// ---------------------------------------------------------------------
// SubscriptionVersionRepository Interface
// ---------------------------------------------------------------------

type SubscriptionVersionRepository interface {
	Create(ctx context.Context, db DBTX, version *models.SubscriptionVersion) error
	GetByID(ctx context.Context, db DBTX, versionID uuid.UUID) (*models.SubscriptionVersion, error)
	GetLatest(ctx context.Context, db DBTX, subscriptionID uuid.UUID) (*models.SubscriptionVersion, error)
	GetByVersion(ctx context.Context, db DBTX, subscriptionID uuid.UUID, versionNumber int) (*models.SubscriptionVersion, error)
	List(ctx context.Context, db DBTX, filter SubscriptionVersionFilter, p Pagination, s Sort) ([]*models.SubscriptionVersion, int64, error)
	ListBySubscription(ctx context.Context, db DBTX, subscriptionID uuid.UUID, p Pagination, s Sort) ([]*models.SubscriptionVersion, int64, error)
	Exists(ctx context.Context, db DBTX, versionID uuid.UUID) (bool, error)
	GetByIDForUpdate(ctx context.Context, db DBTX, versionID uuid.UUID) (*models.SubscriptionVersion, error)
}

// ---------------------------------------------------------------------
// Filter
// ---------------------------------------------------------------------

type SubscriptionVersionFilter struct {
	SubscriptionID uuid.UUID
	VersionIDs     []uuid.UUID
	VersionNumber  *int
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------

type subscriptionVersionRepository struct {
	logger *zap.Logger
}

func NewSubscriptionVersionRepository(logger *zap.Logger) SubscriptionVersionRepository {
	return &subscriptionVersionRepository{
		logger: logger.Named("subscription_version_repo"),
	}
}

const versionTable = "subscription.subscription_versions"

func (r *subscriptionVersionRepository) scanVersion(s scanner) (*models.SubscriptionVersion, error) {
	var v models.SubscriptionVersion
	var reason sql.NullString
	var snapshot string

	err := s.Scan(
		&v.VersionID,
		&v.SubscriptionID,
		&v.VersionNumber,
		&snapshot,
		&reason,
		&v.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan version: %w", err)
	}

	if reason.Valid {
		v.Reason = &reason.String
	}
	v.Snapshot = datatypes.JSON(snapshot)
	return &v, nil
}

func (r *subscriptionVersionRepository) buildVersionFilter(filter SubscriptionVersionFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.SubscriptionID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("subscription_id = $%d", idx))
		args = append(args, filter.SubscriptionID)
		idx++
	}

	if len(filter.VersionIDs) > 0 {
		placeholders := make([]string, len(filter.VersionIDs))
		for i, id := range filter.VersionIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("version_id IN (%s)", strings.Join(placeholders, ",")))
	}

	if filter.VersionNumber != nil {
		conds = append(conds, fmt.Sprintf("version_number = $%d", idx))
		args = append(args, *filter.VersionNumber)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

var versionAllowedSort = map[string]bool{
	"version_id":     true,
	"version_number": true,
	"created_at":     true,
}

// ---------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------

func (r *subscriptionVersionRepository) Create(ctx context.Context, db DBTX, version *models.SubscriptionVersion) error {
	query := `
		INSERT INTO subscription.subscription_versions (
			version_id, subscription_id, version_number, snapshot, reason, created_at
		) VALUES ($1, $2, $3, $4, $5, NOW())
	`
	_, err := db.ExecContext(ctx, query,
		version.VersionID,
		version.SubscriptionID,
		version.VersionNumber,
		version.Snapshot,
		version.Reason,
	)
	if err != nil {
		return fmt.Errorf("create subscription version: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// Single Fetch
// ---------------------------------------------------------------------

func (r *subscriptionVersionRepository) GetByID(ctx context.Context, db DBTX, versionID uuid.UUID) (*models.SubscriptionVersion, error) {
	query := `
		SELECT version_id, subscription_id, version_number, snapshot, reason, created_at
		FROM subscription.subscription_versions
		WHERE version_id = $1
	`
	row := db.QueryRowContext(ctx, query, versionID)
	return r.scanVersion(row)
}

func (r *subscriptionVersionRepository) GetLatest(ctx context.Context, db DBTX, subscriptionID uuid.UUID) (*models.SubscriptionVersion, error) {
	query := `
		SELECT version_id, subscription_id, version_number, snapshot, reason, created_at
		FROM subscription.subscription_versions
		WHERE subscription_id = $1
		ORDER BY version_number DESC
		LIMIT 1
	`
	row := db.QueryRowContext(ctx, query, subscriptionID)
	return r.scanVersion(row)
}

func (r *subscriptionVersionRepository) GetByVersion(ctx context.Context, db DBTX, subscriptionID uuid.UUID, versionNumber int) (*models.SubscriptionVersion, error) {
	query := `
		SELECT version_id, subscription_id, version_number, snapshot, reason, created_at
		FROM subscription.subscription_versions
		WHERE subscription_id = $1 AND version_number = $2
	`
	row := db.QueryRowContext(ctx, query, subscriptionID, versionNumber)
	return r.scanVersion(row)
}

// ---------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------

func (r *subscriptionVersionRepository) List(ctx context.Context, db DBTX, filter SubscriptionVersionFilter, p Pagination, s Sort) ([]*models.SubscriptionVersion, int64, error) {
	where, args := r.buildVersionFilter(filter)
	if where == "" {
		return nil, 0, fmt.Errorf("subscription_id is required in filter")
	}

	orderBy, err := validateSort(s, versionAllowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY version_number DESC"
	}

	limit, offset := validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", versionTable, where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count versions: %w", err)
	}
	if total == 0 {
		return []*models.SubscriptionVersion{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT version_id, subscription_id, version_number, snapshot, reason, created_at
		FROM %s
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, versionTable, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list versions: %w", err)
	}
	defer rows.Close()

	var result []*models.SubscriptionVersion
	for rows.Next() {
		v, err := r.scanVersion(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, v)
	}
	return result, total, rows.Err()
}

func (r *subscriptionVersionRepository) ListBySubscription(ctx context.Context, db DBTX, subscriptionID uuid.UUID, p Pagination, s Sort) ([]*models.SubscriptionVersion, int64, error) {
	filter := SubscriptionVersionFilter{
		SubscriptionID: subscriptionID,
	}
	return r.List(ctx, db, filter, p, s)
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

func (r *subscriptionVersionRepository) Exists(ctx context.Context, db DBTX, versionID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.subscription_versions WHERE version_id = $1)`
	err := db.QueryRowContext(ctx, query, versionID).Scan(&exists)
	return exists, err
}

// ---------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------

func (r *subscriptionVersionRepository) GetByIDForUpdate(ctx context.Context, db DBTX, versionID uuid.UUID) (*models.SubscriptionVersion, error) {
	query := `
		SELECT version_id, subscription_id, version_number, snapshot, reason, created_at
		FROM subscription.subscription_versions
		WHERE version_id = $1
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, versionID)
	return r.scanVersion(row)
}
