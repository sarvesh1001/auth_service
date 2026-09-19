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

type geofenceRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

// NewGeofenceRepository creates a new geofence repository.
func NewGeofenceRepository(pg *client.PostgresClient, logger *zap.Logger) repository.GeofenceRepository {
	return &geofenceRepository{
		client: pg,
		logger: logger.Named("geofence_repo"),
	}
}

// Create inserts a new geofence.
func (r *geofenceRepository) Create(
	ctx context.Context,
	tx *sql.Tx,
	geofence *models.Geofence,
) error {
	if geofence.GeofenceID == uuid.Nil {
		geofence.GeofenceID = uuid.New()
	}
	now := time.Now().UTC()
	if geofence.CreatedAt.IsZero() {
		geofence.CreatedAt = now
	}
	if geofence.UpdatedAt.IsZero() {
		geofence.UpdatedAt = now
	}

	query := `
		INSERT INTO attendance.geofences (
			geofence_id, company_id, employment_location_id,
			name, location_type, geo_lat, geo_lng, location_code, zone,
			is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	exec := func(q string, args ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, args...)
		}
		return r.client.Exec(ctx, q, args...)
	}

	_, err := exec(query,
		geofence.GeofenceID,
		geofence.CompanyID,
		geofence.EmploymentLocationID,
		geofence.Name,
		geofence.LocationType,
		geofence.GeoLat,
		geofence.GeoLng,
		geofence.LocationCode,
		geofence.Zone,
		geofence.IsActive,
		geofence.CreatedAt,
		geofence.UpdatedAt,
	)
	if err != nil {
		r.logger.Error("failed to create geofence",
			util.String("geofence_id", geofence.GeofenceID.String()),
			util.ErrorField(err))
		return fmt.Errorf("create geofence: %w", err)
	}
	return nil
}

// GetByID retrieves a geofence by ID.
func (r *geofenceRepository) GetByID(
	ctx context.Context,
	geofenceID uuid.UUID,
) (*models.Geofence, error) {
	query := `
		SELECT geofence_id, company_id, employment_location_id,
		       name, location_type, geo_lat, geo_lng, location_code, zone,
		       is_active, created_at, updated_at
		FROM attendance.geofences
		WHERE geofence_id = $1
	`
	row := r.client.QueryRow(ctx, query, geofenceID)
	return r.scanGeofence(row)
}

// GetByCompany retrieves all geofences for a company.
func (r *geofenceRepository) GetByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	activeOnly bool,
) ([]*models.Geofence, error) {
	query := `
		SELECT geofence_id, company_id, employment_location_id,
		       name, location_type, geo_lat, geo_lng, location_code, zone,
		       is_active, created_at, updated_at
		FROM attendance.geofences
		WHERE company_id = $1
	`
	if activeOnly {
		query += " AND is_active = true"
	}
	query += " ORDER BY name"

	return r.queryGeofences(ctx, query, companyID)
}

// GetByEmploymentLocation retrieves all geofences belonging to a
// specific employment location.
func (r *geofenceRepository) GetByEmploymentLocation(
	ctx context.Context,
	companyID uuid.UUID,
	employmentLocationID uuid.UUID,
	activeOnly bool,
) ([]*models.Geofence, error) {
	query := `
		SELECT geofence_id, company_id, employment_location_id,
		       name, location_type, geo_lat, geo_lng, location_code, zone,
		       is_active, created_at, updated_at
		FROM attendance.geofences
		WHERE company_id = $1 AND employment_location_id = $2
	`
	if activeOnly {
		query += " AND is_active = true"
	}
	query += " ORDER BY name"

	return r.queryGeofences(ctx, query, companyID, employmentLocationID)
}

// GetByCode retrieves a geofence by company and location_code.
func (r *geofenceRepository) GetByCode(
	ctx context.Context,
	companyID uuid.UUID,
	locationCode string,
) (*models.Geofence, error) {
	query := `
		SELECT geofence_id, company_id, employment_location_id,
		       name, location_type, geo_lat, geo_lng, location_code, zone,
		       is_active, created_at, updated_at
		FROM attendance.geofences
		WHERE company_id = $1 AND location_code = $2
	`
	row := r.client.QueryRow(ctx, query, companyID, locationCode)
	return r.scanGeofence(row)
}

// Update updates an existing geofence.
func (r *geofenceRepository) Update(
	ctx context.Context,
	tx *sql.Tx,
	geofence *models.Geofence,
) error {
	geofence.UpdatedAt = time.Now().UTC()

	query := `
		UPDATE attendance.geofences SET
			employment_location_id = $1,
			name                   = $2,
			location_type          = $3,
			geo_lat                = $4,
			geo_lng                = $5,
			location_code          = $6,
			zone                   = $7,
			is_active              = $8,
			updated_at             = $9
		WHERE geofence_id = $10
	`

	exec := func(q string, args ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, args...)
		}
		return r.client.Exec(ctx, q, args...)
	}

	result, err := exec(query,
		geofence.EmploymentLocationID,
		geofence.Name,
		geofence.LocationType,
		geofence.GeoLat,
		geofence.GeoLng,
		geofence.LocationCode,
		geofence.Zone,
		geofence.IsActive,
		geofence.UpdatedAt,
		geofence.GeofenceID,
	)
	if err != nil {
		r.logger.Error("failed to update geofence",
			util.String("geofence_id", geofence.GeofenceID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update geofence: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("geofence not found")
	}
	return nil
}

// Delete removes a geofence permanently.
func (r *geofenceRepository) Delete(ctx context.Context, geofenceID uuid.UUID) error {
	query := `DELETE FROM attendance.geofences WHERE geofence_id = $1`
	result, err := r.client.Exec(ctx, query, geofenceID)
	if err != nil {
		r.logger.Error("failed to delete geofence",
			util.String("geofence_id", geofenceID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete geofence: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("geofence not found")
	}
	return nil
}

// HealthCheck verifies database connectivity.
func (r *geofenceRepository) HealthCheck(ctx context.Context) error {
	query := `SELECT 1 FROM attendance.geofences LIMIT 1`
	_, err := r.client.Exec(ctx, query)
	if err != nil {
		r.logger.Error("health check failed", util.ErrorField(err))
		return fmt.Errorf("health check: %w", err)
	}
	return nil
}

// ----- helpers -----

// queryGeofences executes a query and scans the result set.
// Returns an empty slice (not nil) when no rows match.
func (r *geofenceRepository) queryGeofences(
	ctx context.Context,
	query string,
	args ...interface{},
) ([]*models.Geofence, error) {
	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to query geofences", util.ErrorField(err))
		return nil, fmt.Errorf("query geofences: %w", err)
	}
	defer rows.Close()

	geofences := make([]*models.Geofence, 0)
	for rows.Next() {
		g, err := r.scanGeofenceFromRows(rows)
		if err != nil {
			return nil, err
		}
		geofences = append(geofences, g)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return geofences, nil
}

func (r *geofenceRepository) scanGeofence(row *sql.Row) (*models.Geofence, error) {
	var g models.Geofence
	err := row.Scan(
		&g.GeofenceID,
		&g.CompanyID,
		&g.EmploymentLocationID,
		&g.Name,
		&g.LocationType,
		&g.GeoLat,
		&g.GeoLng,
		&g.LocationCode,
		&g.Zone,
		&g.IsActive,
		&g.CreatedAt,
		&g.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan geofence: %w", err)
	}
	return &g, nil
}

func (r *geofenceRepository) scanGeofenceFromRows(rows *sql.Rows) (*models.Geofence, error) {
	var g models.Geofence
	err := rows.Scan(
		&g.GeofenceID,
		&g.CompanyID,
		&g.EmploymentLocationID,
		&g.Name,
		&g.LocationType,
		&g.GeoLat,
		&g.GeoLng,
		&g.LocationCode,
		&g.Zone,
		&g.IsActive,
		&g.CreatedAt,
		&g.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scan geofence rows: %w", err)
	}
	return &g, nil
}
