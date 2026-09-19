package repository

import (
	"context"
	"database/sql"

	"github.com/google/uuid"

	"auth-service/internal/attendance/models"
)

type WorkCenterRepository interface {
	Create(ctx context.Context, tx *sql.Tx, wc *models.WorkCenter) error
	GetByCode(ctx context.Context, companyID uuid.UUID, workCenterCode string) (*models.WorkCenter, error)
	Update(ctx context.Context, tx *sql.Tx, wc *models.WorkCenter) error
	Delete(ctx context.Context, companyID uuid.UUID, workCenterCode string) error

	// List returns work centers for a company, optionally scoped to a location.
	// locationID == nil → no filter (ALL scope).
	List(ctx context.Context, companyID uuid.UUID, locationID *uuid.UUID, limit, offset int) ([]*models.WorkCenter, int, error)

	// Search applies arbitrary filters plus an optional location filter.
	Search(ctx context.Context, companyID uuid.UUID, locationID *uuid.UUID, filters map[string]interface{}, limit, offset int) ([]*models.WorkCenter, int, error)

	// GetActive returns active work centers, optionally scoped to a location.
	GetActive(ctx context.Context, companyID uuid.UUID, locationID *uuid.UUID) ([]*models.WorkCenter, error)

	Exists(ctx context.Context, companyID uuid.UUID, workCenterCode string) (bool, error)
	ExistsByName(ctx context.Context, companyID uuid.UUID, name string) (bool, error)
	HealthCheck(ctx context.Context) error
}
