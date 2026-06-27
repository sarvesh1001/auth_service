// repository/schedule_type_repository.go
package repository

import (
	"context"
	"database/sql"
	"fmt"

	"go.uber.org/zap"

	"auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/models"
)

type ScheduleTypeRepository interface {
	Create(ctx context.Context, db DBTX, scheduleType *models.ScheduleType) error
	Update(ctx context.Context, db DBTX, scheduleType *models.ScheduleType) error
	Delete(ctx context.Context, db DBTX, scheduleTypeID int16) error

	GetByID(ctx context.Context, db DBTX, scheduleTypeID int16) (*models.ScheduleType, error)
	GetByCode(ctx context.Context, db DBTX, code string) (*models.ScheduleType, error)
	GetByName(ctx context.Context, db DBTX, name string) (*models.ScheduleType, error)

	List(ctx context.Context, db DBTX, filter ScheduleTypeFilter, p Pagination, s Sort) ([]*models.ScheduleType, int64, error)

	Exists(ctx context.Context, db DBTX, scheduleTypeID int16) (bool, error)
	ExistsByCode(ctx context.Context, db DBTX, code string) (bool, error)

	Search(ctx context.Context, db DBTX, query string, limit int, offset int) ([]*models.ScheduleType, int64, error)

	GetByIDForUpdate(ctx context.Context, db DBTX, scheduleTypeID int16) (*models.ScheduleType, error)
}

type ScheduleTypeFilter struct {
	ScheduleTypeIDs []int16
	Code            *string
	Name            *string
}

type scheduleTypeRepository struct {
	logger *zap.Logger
}

func NewScheduleTypeRepository(logger *zap.Logger) ScheduleTypeRepository {
	return &scheduleTypeRepository{
		logger: logger.Named("subscription_schedule_type_repo"),
	}
}

const scheduleTypeTable = "subscription.schedule_types"

func (r *scheduleTypeRepository) toLookupFilter(filter ScheduleTypeFilter) LookupFilter {
	return LookupFilter{
		IDs:  filter.ScheduleTypeIDs,
		Code: filter.Code,
		Name: filter.Name,
	}
}

func (r *scheduleTypeRepository) scanScheduleType(s scanner) (*models.ScheduleType, error) {
	var st models.ScheduleType
	err := s.Scan(&st.ScheduleTypeID, &st.Code, &st.Name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan schedule type: %w", err)
	}
	return &st, nil
}

// ---------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------

func (r *scheduleTypeRepository) Create(ctx context.Context, db DBTX, scheduleType *models.ScheduleType) error {
	query := `INSERT INTO subscription.schedule_types (schedule_type_id, code, name) VALUES ($1, $2, $3)`
	_, err := db.ExecContext(ctx, query, scheduleType.ScheduleTypeID, scheduleType.Code, scheduleType.Name)
	if err != nil {
		return fmt.Errorf("create schedule type: %w", err)
	}
	return nil
}

func (r *scheduleTypeRepository) Update(ctx context.Context, db DBTX, scheduleType *models.ScheduleType) error {
	query := `UPDATE subscription.schedule_types SET code = $2, name = $3 WHERE schedule_type_id = $1`
	result, err := db.ExecContext(ctx, query, scheduleType.ScheduleTypeID, scheduleType.Code, scheduleType.Name)
	if err != nil {
		return fmt.Errorf("update schedule type: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *scheduleTypeRepository) Delete(ctx context.Context, db DBTX, scheduleTypeID int16) error {
	query := `DELETE FROM subscription.schedule_types WHERE schedule_type_id = $1`
	result, err := db.ExecContext(ctx, query, scheduleTypeID)
	if err != nil {
		return fmt.Errorf("delete schedule type: %w", err)
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

func (r *scheduleTypeRepository) GetByID(ctx context.Context, db DBTX, scheduleTypeID int16) (*models.ScheduleType, error) {
	query := `SELECT schedule_type_id, code, name FROM subscription.schedule_types WHERE schedule_type_id = $1`
	row := db.QueryRowContext(ctx, query, scheduleTypeID)
	return r.scanScheduleType(row)
}

func (r *scheduleTypeRepository) GetByCode(ctx context.Context, db DBTX, code string) (*models.ScheduleType, error) {
	query := `SELECT schedule_type_id, code, name FROM subscription.schedule_types WHERE code = $1`
	row := db.QueryRowContext(ctx, query, code)
	return r.scanScheduleType(row)
}

func (r *scheduleTypeRepository) GetByName(ctx context.Context, db DBTX, name string) (*models.ScheduleType, error) {
	query := `SELECT schedule_type_id, code, name FROM subscription.schedule_types WHERE name = $1`
	row := db.QueryRowContext(ctx, query, name)
	return r.scanScheduleType(row)
}

// ---------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------

func (r *scheduleTypeRepository) List(ctx context.Context, db DBTX, filter ScheduleTypeFilter, p Pagination, s Sort) ([]*models.ScheduleType, int64, error) {
	return listLookup(
		ctx, db, r.logger,
		scheduleTypeTable,
		r.toLookupFilter(filter),
		p, s,
		"schedule_type_id", "code", "name", "",
		r.scanScheduleType,
	)
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

func (r *scheduleTypeRepository) Exists(ctx context.Context, db DBTX, scheduleTypeID int16) (bool, error) {
	return existsLookup(ctx, db, scheduleTypeTable, "schedule_type_id", scheduleTypeID)
}

func (r *scheduleTypeRepository) ExistsByCode(ctx context.Context, db DBTX, code string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.schedule_types WHERE code = $1)`
	err := db.QueryRowContext(ctx, query, code).Scan(&exists)
	return exists, err
}

// ---------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------

func (r *scheduleTypeRepository) Search(ctx context.Context, db DBTX, query string, limit int, offset int) ([]*models.ScheduleType, int64, error) {
	return searchLookup(
		ctx, db, r.logger,
		scheduleTypeTable,
		nil,
		query, limit, offset,
		"code", "name",
		r.scanScheduleType,
	)
}

// ---------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------

func (r *scheduleTypeRepository) GetByIDForUpdate(ctx context.Context, db DBTX, scheduleTypeID int16) (*models.ScheduleType, error) {
	query := `SELECT schedule_type_id, code, name FROM subscription.schedule_types WHERE schedule_type_id = $1 FOR UPDATE`
	row := db.QueryRowContext(ctx, query, scheduleTypeID)
	return r.scanScheduleType(row)
}
