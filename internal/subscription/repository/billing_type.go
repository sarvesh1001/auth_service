// repository/billing_type_repository.go
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
// BillingTypeRepository Interface
// ---------------------------------------------------------------------

type BillingTypeRepository interface {
	// CRUD
	Create(ctx context.Context, db DBTX, billingType *models.BillingType) error
	Update(ctx context.Context, db DBTX, billingType *models.BillingType) error
	Delete(ctx context.Context, db DBTX, billingTypeID int16) error

	// Single Fetch
	GetByID(ctx context.Context, db DBTX, billingTypeID int16) (*models.BillingType, error)
	GetByCode(ctx context.Context, db DBTX, code string) (*models.BillingType, error)
	GetByName(ctx context.Context, db DBTX, name string) (*models.BillingType, error)

	// Listing
	List(ctx context.Context, db DBTX, filter BillingTypeFilter, p Pagination, s Sort) ([]*models.BillingType, int64, error)

	// Validation
	Exists(ctx context.Context, db DBTX, billingTypeID int16) (bool, error)
	ExistsByCode(ctx context.Context, db DBTX, code string) (bool, error)

	// Search
	Search(ctx context.Context, db DBTX, query string, limit int, offset int) ([]*models.BillingType, int64, error)

	// Concurrency / Locking
	GetByIDForUpdate(ctx context.Context, db DBTX, billingTypeID int16) (*models.BillingType, error)
}

// ---------------------------------------------------------------------
// Filter
// ---------------------------------------------------------------------

type BillingTypeFilter struct {
	BillingTypeIDs []int16
	Code           *string
	Name           *string
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------

type billingTypeRepository struct {
	logger *zap.Logger
}

func NewBillingTypeRepository(logger *zap.Logger) BillingTypeRepository {
	return &billingTypeRepository{
		logger: logger.Named("subscription_billing_type_repo"),
	}
}

const billingTypeTable = "subscription.billing_types"

func (r *billingTypeRepository) toLookupFilter(filter BillingTypeFilter) LookupFilter {
	return LookupFilter{
		IDs:  filter.BillingTypeIDs,
		Code: filter.Code,
		Name: filter.Name,
		// No Category field for billing_types
	}
}

func (r *billingTypeRepository) scanBillingType(s scanner) (*models.BillingType, error) {
	var bt models.BillingType
	err := s.Scan(
		&bt.BillingTypeID,
		&bt.Code,
		&bt.Name,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan billing type: %w", err)
	}
	return &bt, nil
}

// ---------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------

func (r *billingTypeRepository) Create(ctx context.Context, db DBTX, billingType *models.BillingType) error {
	query := `
		INSERT INTO subscription.billing_types (billing_type_id, code, name)
		VALUES ($1, $2, $3)
	`
	_, err := db.ExecContext(ctx, query, billingType.BillingTypeID, billingType.Code, billingType.Name)
	if err != nil {
		return fmt.Errorf("create billing type: %w", err)
	}
	return nil
}

func (r *billingTypeRepository) Update(ctx context.Context, db DBTX, billingType *models.BillingType) error {
	query := `
		UPDATE subscription.billing_types
		SET code = $2, name = $3
		WHERE billing_type_id = $1
	`
	result, err := db.ExecContext(ctx, query, billingType.BillingTypeID, billingType.Code, billingType.Name)
	if err != nil {
		return fmt.Errorf("update billing type: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *billingTypeRepository) Delete(ctx context.Context, db DBTX, billingTypeID int16) error {
	query := `DELETE FROM subscription.billing_types WHERE billing_type_id = $1`
	result, err := db.ExecContext(ctx, query, billingTypeID)
	if err != nil {
		return fmt.Errorf("delete billing type: %w", err)
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

func (r *billingTypeRepository) GetByID(ctx context.Context, db DBTX, billingTypeID int16) (*models.BillingType, error) {
	query := `SELECT billing_type_id, code, name FROM subscription.billing_types WHERE billing_type_id = $1`
	row := db.QueryRowContext(ctx, query, billingTypeID)
	return r.scanBillingType(row)
}

func (r *billingTypeRepository) GetByCode(ctx context.Context, db DBTX, code string) (*models.BillingType, error) {
	query := `SELECT billing_type_id, code, name FROM subscription.billing_types WHERE code = $1`
	row := db.QueryRowContext(ctx, query, code)
	return r.scanBillingType(row)
}

func (r *billingTypeRepository) GetByName(ctx context.Context, db DBTX, name string) (*models.BillingType, error) {
	query := `SELECT billing_type_id, code, name FROM subscription.billing_types WHERE name = $1`
	row := db.QueryRowContext(ctx, query, name)
	return r.scanBillingType(row)
}

// ---------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------

func (r *billingTypeRepository) List(ctx context.Context, db DBTX, filter BillingTypeFilter, p Pagination, s Sort) ([]*models.BillingType, int64, error) {
	return listLookup(
		ctx, db, r.logger,
		billingTypeTable,
		r.toLookupFilter(filter),
		p, s,
		"billing_type_id", "code", "name", "", // no category column
		r.scanBillingType,
	)
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

func (r *billingTypeRepository) Exists(ctx context.Context, db DBTX, billingTypeID int16) (bool, error) {
	return existsLookup(ctx, db, billingTypeTable, "billing_type_id", billingTypeID)
}

func (r *billingTypeRepository) ExistsByCode(ctx context.Context, db DBTX, code string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.billing_types WHERE code = $1)`
	err := db.QueryRowContext(ctx, query, code).Scan(&exists)
	return exists, err
}

// ---------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------

func (r *billingTypeRepository) Search(ctx context.Context, db DBTX, query string, limit int, offset int) ([]*models.BillingType, int64, error) {
	return searchLookup(
		ctx, db, r.logger,
		billingTypeTable,
		nil, // no company_id
		query, limit, offset,
		"code", "name",
		r.scanBillingType,
	)
}

// ---------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------

func (r *billingTypeRepository) GetByIDForUpdate(ctx context.Context, db DBTX, billingTypeID int16) (*models.BillingType, error) {
	query := `SELECT billing_type_id, code, name FROM subscription.billing_types WHERE billing_type_id = $1 FOR UPDATE`
	row := db.QueryRowContext(ctx, query, billingTypeID)
	return r.scanBillingType(row)
}
