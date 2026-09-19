package repository

import (
	"context"
	"database/sql"

	"github.com/google/uuid"

	"auth-service/internal/attendance/models"
)

// GeofenceRepository defines operations for attendance geofences.
//
// A geofence is a physical zone belonging to exactly one employment
// location (public.locations). Devices and attendance events reference
// geofences by ID.
type GeofenceRepository interface {
	// Create inserts a new geofence.
	Create(ctx context.Context, tx *sql.Tx, geofence *models.Geofence) error

	// GetByID retrieves a geofence by its ID.
	GetByID(ctx context.Context, geofenceID uuid.UUID) (*models.Geofence, error)

	// GetByCompany retrieves all geofences for a company, optionally
	// filtering by active status.
	GetByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.Geofence, error)

	// GetByEmploymentLocation retrieves all geofences belonging to a
	// specific employment location.
	GetByEmploymentLocation(
		ctx context.Context,
		companyID uuid.UUID,
		employmentLocationID uuid.UUID,
		activeOnly bool,
	) ([]*models.Geofence, error)

	// GetByCode retrieves a geofence by company and location_code.
	GetByCode(ctx context.Context, companyID uuid.UUID, locationCode string) (*models.Geofence, error)

	// Update updates an existing geofence.
	Update(ctx context.Context, tx *sql.Tx, geofence *models.Geofence) error

	// Delete removes a geofence permanently.
	Delete(ctx context.Context, geofenceID uuid.UUID) error

	// HealthCheck verifies database connectivity.
	HealthCheck(ctx context.Context) error
}
