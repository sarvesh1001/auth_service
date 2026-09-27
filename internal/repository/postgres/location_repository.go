package postgres

import (
	"auth-service/internal/client"
	"auth-service/internal/models"
	"context"
	"time"

	"github.com/google/uuid"
)

// LocationRepository defines location-related database operations.
//
// Every method takes a client.DBTX as its second argument. Callers pass:
//   - r.client.Pool()             → run against the pool (auto-commit)
//   - tx (an active *sql.Tx)      → participate in the caller's transaction
//
// This lets the same method run inside or outside a transaction without
// needing two variants.
type LocationRepository interface {
	// Location CRUD
	CreateLocation(ctx context.Context, db client.DBTX, loc *models.Location) error
	GetLocation(ctx context.Context, db client.DBTX, locationID uuid.UUID) (*models.Location, error)
	UpdateLocation(ctx context.Context, db client.DBTX, loc *models.Location) error
	DeleteLocation(ctx context.Context, db client.DBTX, locationID uuid.UUID) error // soft delete (set is_active=false)
	ListLocations(ctx context.Context, db client.DBTX, companyID uuid.UUID, limit, offset int) ([]*models.Location, int, error)
	CountActiveLocations(ctx context.Context, db client.DBTX, companyID uuid.UUID) (int, error)

	// Employee location access
	AddLocationAccess(ctx context.Context, db client.DBTX, access *models.EmployeeLocationAccess) error
	RemoveLocationAccess(ctx context.Context, db client.DBTX, companyID, userID, locationID uuid.UUID) error
	GetLocationAccessForEmployee(ctx context.Context, db client.DBTX, companyID, userID uuid.UUID) ([]*models.EmployeeLocationAccess, error)
	GetEmployeeLocationsWithAccess(ctx context.Context, db client.DBTX, companyID, userID uuid.UUID) ([]*models.LocationWithAccess, error)

	// Employee location fields on company_employees
	SetEmployeePrimaryLocation(ctx context.Context, db client.DBTX, companyID, userID, locationID uuid.UUID) error
	UpdateEmployeeLocationScope(ctx context.Context, db client.DBTX, companyID, userID uuid.UUID, scope string) error
	GetEmployeeLocationDetails(ctx context.Context, db client.DBTX, companyID, userID uuid.UUID) (*models.EmployeeLocationDetails, error)
	IsLocationAccessible(ctx context.Context, db client.DBTX, companyID, userID, locationID uuid.UUID) (bool, error)
	GetLocationAccessLevel(ctx context.Context, db client.DBTX, companyID, userID, locationID uuid.UUID) (string, error)
	DeleteAllLocationAccessForUser(ctx context.Context, db client.DBTX, companyID, userID uuid.UUID) error
	// Location history
	AddLocationHistory(ctx context.Context, db client.DBTX, history *models.EmployeeLocationHistory) error
	CloseActiveLocationHistory(ctx context.Context, db client.DBTX, companyID, userID uuid.UUID, endDate time.Time) error
	GetLocationHistory(ctx context.Context, db client.DBTX, companyID, userID uuid.UUID) ([]*models.EmployeeLocationHistory, error)
}
