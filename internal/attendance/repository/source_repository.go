package repository

import (
	"context"
	"database/sql"

	"github.com/google/uuid"

	"auth-service/internal/attendance/models"
)

// SourceRepository defines operations for attendance sources and source types.
type SourceRepository interface {
	// ── Source Types ──
	// GetSourceTypes retrieves all source types (optionally active only).
	GetSourceTypes(ctx context.Context, activeOnly bool) ([]*models.AttendanceSourceType, error)

	// GetSourceTypeByType retrieves a specific source type by its type string.
	GetSourceTypeByType(ctx context.Context, sourceType string) (*models.AttendanceSourceType, error)

	// ── Sources ──
	// Create inserts a new attendance source.
	Create(ctx context.Context, tx *sql.Tx, source *models.AttendanceSource) error

	// GetByID retrieves a source by its ID.
	GetByID(ctx context.Context, sourceID uuid.UUID) (*models.AttendanceSource, error)
	GetEventTypes(ctx context.Context, activeOnly bool) ([]*models.AttendanceEventType, error)

	// GetByCompany retrieves all sources for a company, optionally filtering by active status.
	GetByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.AttendanceSource, error)

	// GetByType retrieves a source by company and source_type (should be unique per company+type).
	GetByType(ctx context.Context, companyID uuid.UUID, sourceType string) (*models.AttendanceSource, error)

	// Update updates an existing source.
	Update(ctx context.Context, tx *sql.Tx, source *models.AttendanceSource) error

	// Delete soft-deletes or hard-deletes a source. We'll use hard delete for simplicity.
	Delete(ctx context.Context, sourceID uuid.UUID) error

	// HealthCheck verifies database connectivity.
	HealthCheck(ctx context.Context) error
}
