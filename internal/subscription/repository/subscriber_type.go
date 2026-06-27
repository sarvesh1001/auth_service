// repository/subscriber_type_repository.go
package repository

import (
	"context"
	"database/sql"
	"fmt"

	"go.uber.org/zap"

	"auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/models"
)

type SubscriberTypeRepository interface {
	Create(ctx context.Context, db DBTX, subscriberType *models.SubscriberType) error
	Update(ctx context.Context, db DBTX, subscriberType *models.SubscriberType) error
	Delete(ctx context.Context, db DBTX, subscriberTypeID int16) error

	GetByID(ctx context.Context, db DBTX, subscriberTypeID int16) (*models.SubscriberType, error)
	GetByCode(ctx context.Context, db DBTX, code string) (*models.SubscriberType, error)
	GetByName(ctx context.Context, db DBTX, name string) (*models.SubscriberType, error)

	List(ctx context.Context, db DBTX, filter SubscriberTypeFilter, p Pagination, s Sort) ([]*models.SubscriberType, int64, error)

	Exists(ctx context.Context, db DBTX, subscriberTypeID int16) (bool, error)
	ExistsByCode(ctx context.Context, db DBTX, code string) (bool, error)

	Search(ctx context.Context, db DBTX, query string, limit int, offset int) ([]*models.SubscriberType, int64, error)

	GetByIDForUpdate(ctx context.Context, db DBTX, subscriberTypeID int16) (*models.SubscriberType, error)
}

type SubscriberTypeFilter struct {
	SubscriberTypeIDs []int16
	Code              *string
	Name              *string
}

type subscriberTypeRepository struct {
	logger *zap.Logger
}

func NewSubscriberTypeRepository(logger *zap.Logger) SubscriberTypeRepository {
	return &subscriberTypeRepository{
		logger: logger.Named("subscription_subscriber_type_repo"),
	}
}

const subscriberTypeTable = "subscription.subscriber_types"

func (r *subscriberTypeRepository) toLookupFilter(filter SubscriberTypeFilter) LookupFilter {
	return LookupFilter{
		IDs:  filter.SubscriberTypeIDs,
		Code: filter.Code,
		Name: filter.Name,
	}
}

func (r *subscriberTypeRepository) scanSubscriberType(s scanner) (*models.SubscriberType, error) {
	var st models.SubscriberType
	err := s.Scan(&st.SubscriberTypeID, &st.Code, &st.Name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan subscriber type: %w", err)
	}
	return &st, nil
}

// ---------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------

func (r *subscriberTypeRepository) Create(ctx context.Context, db DBTX, subscriberType *models.SubscriberType) error {
	query := `INSERT INTO subscription.subscriber_types (subscriber_type_id, code, name) VALUES ($1, $2, $3)`
	_, err := db.ExecContext(ctx, query, subscriberType.SubscriberTypeID, subscriberType.Code, subscriberType.Name)
	if err != nil {
		return fmt.Errorf("create subscriber type: %w", err)
	}
	return nil
}

func (r *subscriberTypeRepository) Update(ctx context.Context, db DBTX, subscriberType *models.SubscriberType) error {
	query := `UPDATE subscription.subscriber_types SET code = $2, name = $3 WHERE subscriber_type_id = $1`
	result, err := db.ExecContext(ctx, query, subscriberType.SubscriberTypeID, subscriberType.Code, subscriberType.Name)
	if err != nil {
		return fmt.Errorf("update subscriber type: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *subscriberTypeRepository) Delete(ctx context.Context, db DBTX, subscriberTypeID int16) error {
	query := `DELETE FROM subscription.subscriber_types WHERE subscriber_type_id = $1`
	result, err := db.ExecContext(ctx, query, subscriberTypeID)
	if err != nil {
		return fmt.Errorf("delete subscriber type: %w", err)
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

func (r *subscriberTypeRepository) GetByID(ctx context.Context, db DBTX, subscriberTypeID int16) (*models.SubscriberType, error) {
	query := `SELECT subscriber_type_id, code, name FROM subscription.subscriber_types WHERE subscriber_type_id = $1`
	row := db.QueryRowContext(ctx, query, subscriberTypeID)
	return r.scanSubscriberType(row)
}

func (r *subscriberTypeRepository) GetByCode(ctx context.Context, db DBTX, code string) (*models.SubscriberType, error) {
	query := `SELECT subscriber_type_id, code, name FROM subscription.subscriber_types WHERE code = $1`
	row := db.QueryRowContext(ctx, query, code)
	return r.scanSubscriberType(row)
}

func (r *subscriberTypeRepository) GetByName(ctx context.Context, db DBTX, name string) (*models.SubscriberType, error) {
	query := `SELECT subscriber_type_id, code, name FROM subscription.subscriber_types WHERE name = $1`
	row := db.QueryRowContext(ctx, query, name)
	return r.scanSubscriberType(row)
}

// ---------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------

func (r *subscriberTypeRepository) List(ctx context.Context, db DBTX, filter SubscriberTypeFilter, p Pagination, s Sort) ([]*models.SubscriberType, int64, error) {
	return listLookup(
		ctx, db, r.logger,
		subscriberTypeTable,
		r.toLookupFilter(filter),
		p, s,
		"subscriber_type_id", "code", "name", "",
		r.scanSubscriberType,
	)
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

func (r *subscriberTypeRepository) Exists(ctx context.Context, db DBTX, subscriberTypeID int16) (bool, error) {
	return existsLookup(ctx, db, subscriberTypeTable, "subscriber_type_id", subscriberTypeID)
}

func (r *subscriberTypeRepository) ExistsByCode(ctx context.Context, db DBTX, code string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.subscriber_types WHERE code = $1)`
	err := db.QueryRowContext(ctx, query, code).Scan(&exists)
	return exists, err
}

// ---------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------

func (r *subscriberTypeRepository) Search(ctx context.Context, db DBTX, query string, limit int, offset int) ([]*models.SubscriberType, int64, error) {
	return searchLookup(
		ctx, db, r.logger,
		subscriberTypeTable,
		nil,
		query, limit, offset,
		"code", "name",
		r.scanSubscriberType,
	)
}

// ---------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------

func (r *subscriberTypeRepository) GetByIDForUpdate(ctx context.Context, db DBTX, subscriberTypeID int16) (*models.SubscriberType, error) {
	query := `SELECT subscriber_type_id, code, name FROM subscription.subscriber_types WHERE subscriber_type_id = $1 FOR UPDATE`
	row := db.QueryRowContext(ctx, query, subscriberTypeID)
	return r.scanSubscriberType(row)
}
