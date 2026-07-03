package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/client"
	"auth-service/internal/util"
)

type locationRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewLocationRepository(pg *client.PostgresClient, logger *zap.Logger) repository.LocationRepository {
	return &locationRepository{
		client: pg,
		logger: logger.Named("location_repo"),
	}
}

// Create inserts a new location.
func (r *locationRepository) Create(ctx context.Context, tx *sql.Tx, location *models.AttendanceLocation) error {
	if location.LocationID == uuid.Nil {
		location.LocationID = uuid.New()
	}
	now := time.Now().UTC()
	if location.CreatedAt.IsZero() {
		location.CreatedAt = now
	}
	if location.UpdatedAt.IsZero() {
		location.UpdatedAt = now
	}

	query := `
		INSERT INTO attendance.attendance_locations (
			location_id, company_id, name, location_type,
			geo_lat, geo_lng, location_code, zone, is_active,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	exec := func(q string, args ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, args...)
		}
		return r.client.Exec(ctx, q, args...)
	}

	_, err := exec(query,
		location.LocationID,
		location.CompanyID,
		location.Name,
		location.LocationType,
		location.GeoLat,
		location.GeoLng,
		location.LocationCode,
		location.Zone,
		location.IsActive,
		location.CreatedAt,
		location.UpdatedAt,
	)
	if err != nil {
		r.logger.Error("failed to create attendance location",
			util.String("location_id", location.LocationID.String()),
			util.ErrorField(err))
		return fmt.Errorf("create location: %w", err)
	}
	return nil
}

// GetByID retrieves a location by ID.
func (r *locationRepository) GetByID(ctx context.Context, locationID uuid.UUID) (*models.AttendanceLocation, error) {
	query := `
		SELECT location_id, company_id, name, location_type,
		       geo_lat, geo_lng, location_code, zone, is_active,
		       created_at, updated_at
		FROM attendance.attendance_locations
		WHERE location_id = $1
	`
	row := r.client.QueryRow(ctx, query, locationID)
	return r.scanLocation(row)
}

// GetByCompany retrieves all locations for a company.
func (r *locationRepository) GetByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.AttendanceLocation, error) {
	query := `
		SELECT location_id, company_id, name, location_type,
		       geo_lat, geo_lng, location_code, zone, is_active,
		       created_at, updated_at
		FROM attendance.attendance_locations
		WHERE company_id = $1
	`
	if activeOnly {
		query += " AND is_active = true"
	}
	query += " ORDER BY name"

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		r.logger.Error("failed to list locations by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("list locations: %w", err)
	}
	defer rows.Close()

	var locations []*models.AttendanceLocation
	for rows.Next() {
		loc, err := r.scanLocationFromRows(rows)
		if err != nil {
			return nil, err
		}
		locations = append(locations, loc)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return locations, nil
}

// GetByCode retrieves a location by company and location_code.
func (r *locationRepository) GetByCode(ctx context.Context, companyID uuid.UUID, locationCode string) (*models.AttendanceLocation, error) {
	query := `
		SELECT location_id, company_id, name, location_type,
		       geo_lat, geo_lng, location_code, zone, is_active,
		       created_at, updated_at
		FROM attendance.attendance_locations
		WHERE company_id = $1 AND location_code = $2
	`
	row := r.client.QueryRow(ctx, query, companyID, locationCode)
	return r.scanLocation(row)
}

// Update updates an existing location.
func (r *locationRepository) Update(ctx context.Context, tx *sql.Tx, location *models.AttendanceLocation) error {
	location.UpdatedAt = time.Now().UTC()

	query := `
		UPDATE attendance.attendance_locations SET
			name = $1,
			location_type = $2,
			geo_lat = $3,
			geo_lng = $4,
			location_code = $5,
			zone = $6,
			is_active = $7,
			updated_at = $8
		WHERE location_id = $9
	`

	exec := func(q string, args ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, args...)
		}
		return r.client.Exec(ctx, q, args...)
	}

	result, err := exec(query,
		location.Name,
		location.LocationType,
		location.GeoLat,
		location.GeoLng,
		location.LocationCode,
		location.Zone,
		location.IsActive,
		location.UpdatedAt,
		location.LocationID,
	)
	if err != nil {
		r.logger.Error("failed to update location",
			util.String("location_id", location.LocationID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update location: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("location not found")
	}
	return nil
}

// Delete removes a location permanently.
func (r *locationRepository) Delete(ctx context.Context, locationID uuid.UUID) error {
	query := `DELETE FROM attendance.attendance_locations WHERE location_id = $1`
	result, err := r.client.Exec(ctx, query, locationID)
	if err != nil {
		r.logger.Error("failed to delete location",
			util.String("location_id", locationID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete location: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("location not found")
	}
	return nil
}

// HealthCheck verifies database connectivity.
func (r *locationRepository) HealthCheck(ctx context.Context) error {
	query := `SELECT 1 FROM attendance.attendance_locations LIMIT 1`
	_, err := r.client.Exec(ctx, query)
	if err != nil {
		r.logger.Error("health check failed", util.ErrorField(err))
		return fmt.Errorf("health check: %w", err)
	}
	return nil
}

// scanLocation scans a single row into an AttendanceLocation.
func (r *locationRepository) scanLocation(row *sql.Row) (*models.AttendanceLocation, error) {
	var loc models.AttendanceLocation
	err := row.Scan(
		&loc.LocationID,
		&loc.CompanyID,
		&loc.Name,
		&loc.LocationType,
		&loc.GeoLat,
		&loc.GeoLng,
		&loc.LocationCode,
		&loc.Zone,
		&loc.IsActive,
		&loc.CreatedAt,
		&loc.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan location: %w", err)
	}
	return &loc, nil
}

// scanLocationFromRows scans a row from *sql.Rows.
func (r *locationRepository) scanLocationFromRows(rows *sql.Rows) (*models.AttendanceLocation, error) {
	var loc models.AttendanceLocation
	err := rows.Scan(
		&loc.LocationID,
		&loc.CompanyID,
		&loc.Name,
		&loc.LocationType,
		&loc.GeoLat,
		&loc.GeoLng,
		&loc.LocationCode,
		&loc.Zone,
		&loc.IsActive,
		&loc.CreatedAt,
		&loc.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scan location rows: %w", err)
	}
	return &loc, nil
}
