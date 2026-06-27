// repository/business_model_repository.go
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
// BusinessModelRepository Interface
// ---------------------------------------------------------------------

type BusinessModelRepository interface {
	// CRUD
	Create(ctx context.Context, db DBTX, businessModel *models.BusinessModel) error
	Update(ctx context.Context, db DBTX, businessModel *models.BusinessModel) error
	Delete(ctx context.Context, db DBTX, businessModelID int16) error

	// Single Fetch
	GetByID(ctx context.Context, db DBTX, businessModelID int16) (*models.BusinessModel, error)
	GetByCode(ctx context.Context, db DBTX, code string) (*models.BusinessModel, error)
	GetByName(ctx context.Context, db DBTX, name string) (*models.BusinessModel, error)

	// Listing
	List(ctx context.Context, db DBTX, filter BusinessModelFilter, p Pagination, s Sort) ([]*models.BusinessModel, int64, error)

	// Validation
	Exists(ctx context.Context, db DBTX, businessModelID int16) (bool, error)
	ExistsByCode(ctx context.Context, db DBTX, code string) (bool, error)

	// Search
	Search(ctx context.Context, db DBTX, query string, limit int, offset int) ([]*models.BusinessModel, int64, error)

	// Concurrency / Locking
	GetByIDForUpdate(ctx context.Context, db DBTX, businessModelID int16) (*models.BusinessModel, error)
}

// ---------------------------------------------------------------------
// Filter
// ---------------------------------------------------------------------

type BusinessModelFilter struct {
	BusinessModelIDs []int16
	Code             *string
	Name             *string
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------

type businessModelRepository struct {
	logger *zap.Logger
}

func NewBusinessModelRepository(logger *zap.Logger) BusinessModelRepository {
	return &businessModelRepository{
		logger: logger.Named("subscription_business_model_repo"),
	}
}

const businessModelTable = "subscription.business_models"

func (r *businessModelRepository) toLookupFilter(filter BusinessModelFilter) LookupFilter {
	return LookupFilter{
		IDs:  filter.BusinessModelIDs,
		Code: filter.Code,
		Name: filter.Name,
		// No Category field for business_models
	}
}

func (r *businessModelRepository) scanBusinessModel(s scanner) (*models.BusinessModel, error) {
	var bm models.BusinessModel
	err := s.Scan(
		&bm.BusinessModelID,
		&bm.Code,
		&bm.Name,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan business model: %w", err)
	}
	return &bm, nil
}

// ---------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------

func (r *businessModelRepository) Create(ctx context.Context, db DBTX, businessModel *models.BusinessModel) error {
	query := `
		INSERT INTO subscription.business_models (business_model_id, code, name)
		VALUES ($1, $2, $3)
	`
	_, err := db.ExecContext(ctx, query, businessModel.BusinessModelID, businessModel.Code, businessModel.Name)
	if err != nil {
		return fmt.Errorf("create business model: %w", err)
	}
	return nil
}

func (r *businessModelRepository) Update(ctx context.Context, db DBTX, businessModel *models.BusinessModel) error {
	query := `
		UPDATE subscription.business_models
		SET code = $2, name = $3
		WHERE business_model_id = $1
	`
	result, err := db.ExecContext(ctx, query, businessModel.BusinessModelID, businessModel.Code, businessModel.Name)
	if err != nil {
		return fmt.Errorf("update business model: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *businessModelRepository) Delete(ctx context.Context, db DBTX, businessModelID int16) error {
	query := `DELETE FROM subscription.business_models WHERE business_model_id = $1`
	result, err := db.ExecContext(ctx, query, businessModelID)
	if err != nil {
		return fmt.Errorf("delete business model: %w", err)
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

func (r *businessModelRepository) GetByID(ctx context.Context, db DBTX, businessModelID int16) (*models.BusinessModel, error) {
	query := `SELECT business_model_id, code, name FROM subscription.business_models WHERE business_model_id = $1`
	row := db.QueryRowContext(ctx, query, businessModelID)
	return r.scanBusinessModel(row)
}

func (r *businessModelRepository) GetByCode(ctx context.Context, db DBTX, code string) (*models.BusinessModel, error) {
	query := `SELECT business_model_id, code, name FROM subscription.business_models WHERE code = $1`
	row := db.QueryRowContext(ctx, query, code)
	return r.scanBusinessModel(row)
}

func (r *businessModelRepository) GetByName(ctx context.Context, db DBTX, name string) (*models.BusinessModel, error) {
	query := `SELECT business_model_id, code, name FROM subscription.business_models WHERE name = $1`
	row := db.QueryRowContext(ctx, query, name)
	return r.scanBusinessModel(row)
}

// ---------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------

func (r *businessModelRepository) List(ctx context.Context, db DBTX, filter BusinessModelFilter, p Pagination, s Sort) ([]*models.BusinessModel, int64, error) {
	return listLookup(
		ctx, db, r.logger,
		businessModelTable,
		r.toLookupFilter(filter),
		p, s,
		"business_model_id", "code", "name", "", // no category column
		r.scanBusinessModel,
	)
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

func (r *businessModelRepository) Exists(ctx context.Context, db DBTX, businessModelID int16) (bool, error) {
	return existsLookup(ctx, db, businessModelTable, "business_model_id", businessModelID)
}

func (r *businessModelRepository) ExistsByCode(ctx context.Context, db DBTX, code string) (bool, error) {
	// Simple existence check – no category needed
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.business_models WHERE code = $1)`
	err := db.QueryRowContext(ctx, query, code).Scan(&exists)
	return exists, err
}

// ---------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------

func (r *businessModelRepository) Search(ctx context.Context, db DBTX, query string, limit int, offset int) ([]*models.BusinessModel, int64, error) {
	return searchLookup(
		ctx, db, r.logger,
		businessModelTable,
		nil, // no company_id
		query, limit, offset,
		"code", "name",
		r.scanBusinessModel,
	)
}

// ---------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------

func (r *businessModelRepository) GetByIDForUpdate(ctx context.Context, db DBTX, businessModelID int16) (*models.BusinessModel, error) {
	query := `SELECT business_model_id, code, name FROM subscription.business_models WHERE business_model_id = $1 FOR UPDATE`
	row := db.QueryRowContext(ctx, query, businessModelID)
	return r.scanBusinessModel(row)
}
