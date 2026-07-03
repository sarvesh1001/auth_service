package repository

import (
	"context"
	"database/sql"

	"github.com/google/uuid"

	"auth-service/internal/attendance/models"
)

// LocationRepository defines operations for attendance locations.
type LocationRepository interface {
	// Create inserts a new location.
	Create(ctx context.Context, tx *sql.Tx, location *models.AttendanceLocation) error

	// GetByID retrieves a location by its ID.
	GetByID(ctx context.Context, locationID uuid.UUID) (*models.AttendanceLocation, error)

	// GetByCompany retrieves all locations for a company, optionally filtering by active status.
	GetByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.AttendanceLocation, error)

	// GetByCode retrieves a location by company and location_code.
	GetByCode(ctx context.Context, companyID uuid.UUID, locationCode string) (*models.AttendanceLocation, error)

	// Update updates an existing location.
	Update(ctx context.Context, tx *sql.Tx, location *models.AttendanceLocation) error

	// Delete soft‑deletes (or hard‑deletes) a location. We'll use a soft delete by setting is_active = false,
	// but we can also physically delete if required. This implementation does a hard delete.
	Delete(ctx context.Context, locationID uuid.UUID) error

	// HealthCheck verifies database connectivity.
	HealthCheck(ctx context.Context) error
}
