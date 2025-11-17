// internal/repository/postgres/user_repository_interface.go
package postgres

import (
	"context"
	"time"

	"auth-service/internal/models"

	"github.com/google/uuid"
)

type UserRepository interface {
	// Core user operations
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error)
	GetUserByPhoneHash(ctx context.Context, phoneHash string) (*models.User, error)
	UpdateUser(ctx context.Context, user *models.User) error
	UpdateUserStatus(ctx context.Context, userID uuid.UUID, isVerified, isActive bool) error
	UpdateLastLogin(ctx context.Context, userID uuid.UUID, timestamp time.Time) error

	// Batch operations
	CreateUsersBatch(ctx context.Context, users []*models.User) error
	GetUsersByIDBatch(ctx context.Context, userIDs []uuid.UUID) ([]*models.User, error)
	UpdateUserStatusBatch(ctx context.Context, updates []models.UserStatusUpdate) error

	// KYC operations
	UpdateKYCStatus(ctx context.Context, userID uuid.UUID, status, level string) error
	GetUsersByKYCStatus(ctx context.Context, status string, limit, offset int) ([]*models.User, int, error)

	// Company user operations
	GetUsersByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.User, int, error)

	// Search and analytics
	GetUsersByRegion(ctx context.Context, region string, limit, offset int) ([]*models.User, int, error)
	GetUsersCreatedAfter(ctx context.Context, after time.Time, limit, offset int) ([]*models.User, int, error)

	// Maintenance operations
	HealthCheck(ctx context.Context) error
	GetRepositoryStats(ctx context.Context) (map[string]interface{}, error)

	// New methods for partitioned table
	GetUserByIDWithPartition(ctx context.Context, userID uuid.UUID) (*models.User, error)
	GetUsersByCreationDateRange(ctx context.Context, start, end time.Time, limit int) ([]*models.User, error)
	// ----------------------------------------------------------------------
	// Core Operations
	// ----------------------------------------------------------------------

	DeleteUser(ctx context.Context, userID uuid.UUID) error
	SoftDeleteUser(ctx context.Context, userID uuid.UUID) error
	ReactivateUser(ctx context.Context, userID uuid.UUID) error
	ArchiveInactiveUsers(ctx context.Context, before time.Time) (int, error)
	UpdateUserFields(ctx context.Context, userID uuid.UUID, fields map[string]interface{}) error

	// ----------------------------------------------------------------------
	// Search & Filter Operations
	// ----------------------------------------------------------------------

	GetRecentlyActiveUsers(ctx context.Context, since time.Time, limit int) ([]*models.User, error)
	GetInactiveUsersSince(ctx context.Context, since time.Time, limit int) ([]*models.User, error)
	SearchUsersByPhoneOrDevice(ctx context.Context, query string, limit, offset int) ([]*models.User, int, error)
	SearchUsers(ctx context.Context, filters map[string]interface{}, limit, offset int) ([]*models.User, int, error)

	// ----------------------------------------------------------------------
	// Device Management
	// ----------------------------------------------------------------------

	GetUserByDeviceFingerprint(ctx context.Context, fingerprint string) (*models.User, error)
	AddUserDevice(ctx context.Context, device *models.UserDevice) error
	GetUserDevices(ctx context.Context, userID uuid.UUID) ([]models.UserDevice, error)
	RemoveUserDevice(ctx context.Context, userID uuid.UUID, deviceID string) error

	// ----------------------------------------------------------------------
	// Login Attempts & Security
	// ----------------------------------------------------------------------

	RecordLoginAttempt(ctx context.Context, userID uuid.UUID, success bool, ip, userAgent string) error
	GetRecentLoginAttempts(ctx context.Context, userID uuid.UUID, limit int) ([]models.LoginAttempt, error)

	// ----------------------------------------------------------------------
	// Analytics & Aggregation
	// ----------------------------------------------------------------------

	CountUsersByRegion(ctx context.Context) (map[string]int, error)
	CountUsersByKYCStatus(ctx context.Context) (map[string]int, error)
	CountActiveUsers(ctx context.Context) (int, error)
	CountNewUsersSince(ctx context.Context, since time.Time) (int, error)
	GetUserActivityStats(ctx context.Context, since time.Time) (map[string]interface{}, error)
	GetKYCDistribution(ctx context.Context) (map[string]int, error)
	GetActiveUserCountsByRegion(ctx context.Context) (map[string]int, error)
	GetUserGrowthMetrics(ctx context.Context, since time.Time) (map[string]interface{}, error)

	// ----------------------------------------------------------------------
	// Maintenance & Optimization
	// ----------------------------------------------------------------------

	RebuildUserIndexes(ctx context.Context) error
	VacuumUserTable(ctx context.Context) error

	// Close method for cleanup
	Close() error
}

type UserStatusUpdate struct {
	UserID     uuid.UUID `db:"user_id"`
	IsVerified bool      `db:"is_verified"`
	IsActive   bool      `db:"is_active"`
	UpdatedAt  time.Time `db:"updated_at"`
}
