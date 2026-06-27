// repository/status.go
package repository

import (
	"context"
	"database/sql"
	"fmt"

	"go.uber.org/zap"

	"auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/models"
)

// ---------------------------------------------------------------------
// StatusRepository Interface
// ---------------------------------------------------------------------

type StatusRepository interface {
	Create(ctx context.Context, db DBTX, status *models.Status) error
	Update(ctx context.Context, db DBTX, status *models.Status) error
	Delete(ctx context.Context, db DBTX, statusID int16) error

	GetByID(ctx context.Context, db DBTX, statusID int16) (*models.Status, error)
	GetByCode(ctx context.Context, db DBTX, category string, code string) (*models.Status, error)
	GetByName(ctx context.Context, db DBTX, category string, name string) (*models.Status, error)

	List(ctx context.Context, db DBTX, filter StatusFilter, p Pagination, s Sort) ([]*models.Status, int64, error)
	ListByCategory(ctx context.Context, db DBTX, category string) ([]*models.Status, error)
	ListActiveSubscriptionStatuses(ctx context.Context, db DBTX) ([]*models.Status, error)

	Exists(ctx context.Context, db DBTX, statusID int16) (bool, error)
	ExistsByCode(ctx context.Context, db DBTX, category string, code string) (bool, error)

	Search(ctx context.Context, db DBTX, query string, limit int, offset int) ([]*models.Status, int64, error)

	GetByIDForUpdate(ctx context.Context, db DBTX, statusID int16) (*models.Status, error)
}

// ---------------------------------------------------------------------
// Filter
// ---------------------------------------------------------------------

type StatusFilter struct {
	StatusIDs []int16
	Category  *string
	Code      *string
	Name      *string
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------

type statusRepository struct {
	logger *zap.Logger
}

func NewStatusRepository(logger *zap.Logger) StatusRepository {
	return &statusRepository{
		logger: logger.Named("subscription_status_repo"),
	}
}

const statusTable = "subscription.statuses"

func (r *statusRepository) toLookupFilter(filter StatusFilter) LookupFilter {
	return LookupFilter{
		IDs:      filter.StatusIDs,
		Code:     filter.Code,
		Name:     filter.Name,
		Category: filter.Category,
	}
}

// scanStatus scans a row into models.Status
func (r *statusRepository) scanStatus(s scanner) (*models.Status, error) {
	var st models.Status
	err := s.Scan(
		&st.StatusID,
		&st.Code,
		&st.Category,
		&st.Name,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan status: %w", err)
	}
	return &st, nil
}

// ---------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------

func (r *statusRepository) Create(ctx context.Context, db DBTX, status *models.Status) error {
	query := `
		INSERT INTO subscription.statuses (status_id, code, category, name)
		VALUES ($1, $2, $3, $4)
	`
	_, err := db.ExecContext(ctx, query, status.StatusID, status.Code, status.Category, status.Name)
	if err != nil {
		return fmt.Errorf("create status: %w", err)
	}
	return nil
}

func (r *statusRepository) Update(ctx context.Context, db DBTX, status *models.Status) error {
	query := `
		UPDATE subscription.statuses
		SET code = $2, category = $3, name = $4
		WHERE status_id = $1
	`
	result, err := db.ExecContext(ctx, query, status.StatusID, status.Code, status.Category, status.Name)
	if err != nil {
		return fmt.Errorf("update status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *statusRepository) Delete(ctx context.Context, db DBTX, statusID int16) error {
	query := `DELETE FROM subscription.statuses WHERE status_id = $1`
	result, err := db.ExecContext(ctx, query, statusID)
	if err != nil {
		return fmt.Errorf("delete status: %w", err)
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

func (r *statusRepository) GetByID(ctx context.Context, db DBTX, statusID int16) (*models.Status, error) {
	query := `SELECT status_id, code, category, name FROM subscription.statuses WHERE status_id = $1`
	row := db.QueryRowContext(ctx, query, statusID)
	return r.scanStatus(row)
}

func (r *statusRepository) GetByCode(ctx context.Context, db DBTX, category string, code string) (*models.Status, error) {
	query := `SELECT status_id, code, category, name FROM subscription.statuses WHERE category = $1 AND code = $2`
	row := db.QueryRowContext(ctx, query, category, code)
	return r.scanStatus(row)
}

func (r *statusRepository) GetByName(ctx context.Context, db DBTX, category string, name string) (*models.Status, error) {
	query := `SELECT status_id, code, category, name FROM subscription.statuses WHERE category = $1 AND name = $2`
	row := db.QueryRowContext(ctx, query, category, name)
	return r.scanStatus(row)
}

// ---------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------

func (r *statusRepository) List(ctx context.Context, db DBTX, filter StatusFilter, p Pagination, s Sort) ([]*models.Status, int64, error) {
	return listLookup(
		ctx, db, r.logger,
		statusTable,
		r.toLookupFilter(filter),
		p, s,
		"status_id", "code", "name", "category",
		r.scanStatus,
	)
}

func (r *statusRepository) ListByCategory(ctx context.Context, db DBTX, category string) ([]*models.Status, error) {
	query := `SELECT status_id, code, category, name FROM subscription.statuses WHERE category = $1 ORDER BY status_id`
	rows, err := db.QueryContext(ctx, query, category)
	if err != nil {
		return nil, fmt.Errorf("list by category: %w", err)
	}
	defer rows.Close()
	var result []*models.Status
	for rows.Next() {
		st, err := r.scanStatus(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, st)
	}
	return result, rows.Err()
}

func (r *statusRepository) ListActiveSubscriptionStatuses(ctx context.Context, db DBTX) ([]*models.Status, error) {
	// "active" for subscriptions = status_id=1, category='subscription', code='active'
	// We'll just call ListByCategory and filter in code if needed, but we can return all
	return r.ListByCategory(ctx, db, "subscription")
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

func (r *statusRepository) Exists(ctx context.Context, db DBTX, statusID int16) (bool, error) {
	return existsLookup(ctx, db, statusTable, "status_id", statusID)
}

func (r *statusRepository) ExistsByCode(ctx context.Context, db DBTX, category string, code string) (bool, error) {
	return existsLookupByCode(ctx, db, statusTable, "code", code, "category", category)
}

// ---------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------

func (r *statusRepository) Search(ctx context.Context, db DBTX, query string, limit int, offset int) ([]*models.Status, int64, error) {
	return searchLookup(
		ctx, db, r.logger,
		statusTable,
		nil, // no company_id
		query, limit, offset,
		"code", "name",
		r.scanStatus,
	)
}

// ---------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------

func (r *statusRepository) GetByIDForUpdate(ctx context.Context, db DBTX, statusID int16) (*models.Status, error) {
	query := `SELECT status_id, code, category, name FROM subscription.statuses WHERE status_id = $1 FOR UPDATE`
	row := db.QueryRowContext(ctx, query, statusID)
	return r.scanStatus(row)
}
