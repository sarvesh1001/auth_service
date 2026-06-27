// repository/provider_repository.go
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
// ProviderRepository Interface
// ---------------------------------------------------------------------

type ProviderRepository interface {
	Create(ctx context.Context, db DBTX, provider *models.Provider) error
	Update(ctx context.Context, db DBTX, provider *models.Provider) error
	Delete(ctx context.Context, db DBTX, providerID int16) error

	GetByID(ctx context.Context, db DBTX, providerID int16) (*models.Provider, error)
	GetByCode(ctx context.Context, db DBTX, code string) (*models.Provider, error)
	GetByName(ctx context.Context, db DBTX, name string) (*models.Provider, error)

	List(ctx context.Context, db DBTX, filter ProviderFilter, p Pagination, s Sort) ([]*models.Provider, int64, error)

	Exists(ctx context.Context, db DBTX, providerID int16) (bool, error)
	ExistsByCode(ctx context.Context, db DBTX, code string) (bool, error)

	Search(ctx context.Context, db DBTX, query string, limit int, offset int) ([]*models.Provider, int64, error)

	GetByIDForUpdate(ctx context.Context, db DBTX, providerID int16) (*models.Provider, error)
}

type ProviderFilter struct {
	ProviderIDs []int16
	Code        *string
	Name        *string
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------

type providerRepository struct {
	logger *zap.Logger
}

func NewProviderRepository(logger *zap.Logger) ProviderRepository {
	return &providerRepository{
		logger: logger.Named("subscription_provider_repo"),
	}
}

const providerTable = "subscription.providers"

func (r *providerRepository) toLookupFilter(filter ProviderFilter) LookupFilter {
	return LookupFilter{
		IDs:  filter.ProviderIDs,
		Code: filter.Code,
		Name: filter.Name,
	}
}

func (r *providerRepository) scanProvider(s scanner) (*models.Provider, error) {
	var p models.Provider
	err := s.Scan(&p.ProviderID, &p.Code, &p.Name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan provider: %w", err)
	}
	return &p, nil
}

// ---------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------

func (r *providerRepository) Create(ctx context.Context, db DBTX, provider *models.Provider) error {
	query := `INSERT INTO subscription.providers (provider_id, code, name) VALUES ($1, $2, $3)`
	_, err := db.ExecContext(ctx, query, provider.ProviderID, provider.Code, provider.Name)
	if err != nil {
		return fmt.Errorf("create provider: %w", err)
	}
	return nil
}

func (r *providerRepository) Update(ctx context.Context, db DBTX, provider *models.Provider) error {
	query := `UPDATE subscription.providers SET code = $2, name = $3 WHERE provider_id = $1`
	result, err := db.ExecContext(ctx, query, provider.ProviderID, provider.Code, provider.Name)
	if err != nil {
		return fmt.Errorf("update provider: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *providerRepository) Delete(ctx context.Context, db DBTX, providerID int16) error {
	query := `DELETE FROM subscription.providers WHERE provider_id = $1`
	result, err := db.ExecContext(ctx, query, providerID)
	if err != nil {
		return fmt.Errorf("delete provider: %w", err)
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

func (r *providerRepository) GetByID(ctx context.Context, db DBTX, providerID int16) (*models.Provider, error) {
	query := `SELECT provider_id, code, name FROM subscription.providers WHERE provider_id = $1`
	row := db.QueryRowContext(ctx, query, providerID)
	return r.scanProvider(row)
}

func (r *providerRepository) GetByCode(ctx context.Context, db DBTX, code string) (*models.Provider, error) {
	query := `SELECT provider_id, code, name FROM subscription.providers WHERE code = $1`
	row := db.QueryRowContext(ctx, query, code)
	return r.scanProvider(row)
}

func (r *providerRepository) GetByName(ctx context.Context, db DBTX, name string) (*models.Provider, error) {
	query := `SELECT provider_id, code, name FROM subscription.providers WHERE name = $1`
	row := db.QueryRowContext(ctx, query, name)
	return r.scanProvider(row)
}

// ---------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------

func (r *providerRepository) List(ctx context.Context, db DBTX, filter ProviderFilter, p Pagination, s Sort) ([]*models.Provider, int64, error) {
	return listLookup(
		ctx, db, r.logger,
		providerTable,
		r.toLookupFilter(filter),
		p, s,
		"provider_id", "code", "name", "",
		r.scanProvider,
	)
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

func (r *providerRepository) Exists(ctx context.Context, db DBTX, providerID int16) (bool, error) {
	return existsLookup(ctx, db, providerTable, "provider_id", providerID)
}

func (r *providerRepository) ExistsByCode(ctx context.Context, db DBTX, code string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.providers WHERE code = $1)`
	err := db.QueryRowContext(ctx, query, code).Scan(&exists)
	return exists, err
}

// ---------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------

func (r *providerRepository) Search(ctx context.Context, db DBTX, query string, limit int, offset int) ([]*models.Provider, int64, error) {
	return searchLookup(
		ctx, db, r.logger,
		providerTable,
		nil,
		query, limit, offset,
		"code", "name",
		r.scanProvider,
	)
}

// ---------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------

func (r *providerRepository) GetByIDForUpdate(ctx context.Context, db DBTX, providerID int16) (*models.Provider, error) {
	query := `SELECT provider_id, code, name FROM subscription.providers WHERE provider_id = $1 FOR UPDATE`
	row := db.QueryRowContext(ctx, query, providerID)
	return r.scanProvider(row)
}
