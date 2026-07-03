package repository

import (
	"context"
	"database/sql"

	"github.com/google/uuid"

	"auth-service/internal/attendance/models"
)

// WorkCenterRepository defines operations for work centers.
type WorkCenterRepository interface {
	// Create inserts a new work center.
	Create(ctx context.Context, tx *sql.Tx, wc *models.WorkCenter) error

	// GetByCode retrieves a work center by company and code.
	GetByCode(ctx context.Context, companyID uuid.UUID, workCenterCode string) (*models.WorkCenter, error)

	// Update updates an existing work center.
	Update(ctx context.Context, tx *sql.Tx, wc *models.WorkCenter) error

	// Delete permanently removes a work center.
	Delete(ctx context.Context, companyID uuid.UUID, workCenterCode string) error

	// List retrieves work centers for a company with pagination.
	List(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.WorkCenter, int, error)

	// Search searches work centers with filters.
	Search(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}, limit, offset int) ([]*models.WorkCenter, int, error)

	// GetActive retrieves all active work centers for a company.
	GetActive(ctx context.Context, companyID uuid.UUID) ([]*models.WorkCenter, error)

	// Exists checks if a work center exists by code.
	Exists(ctx context.Context, companyID uuid.UUID, workCenterCode string) (bool, error)

	// ExistsByName checks if a work center exists by name (within a company).
	ExistsByName(ctx context.Context, companyID uuid.UUID, name string) (bool, error)

	// HealthCheck verifies database connectivity.
	HealthCheck(ctx context.Context) error
}
