package postgres

import (
	"context"
	"time"

	"auth-service/internal/client"
	"auth-service/internal/models"

	"github.com/google/uuid"
)

// UserRepository defines user-related database operations.
//
// Every method takes a client.DBTX as its second argument. Callers pass:
//   - r.client.Pool()         → run against the pool (auto-commit)
//   - tx (an active *sql.Tx)  → participate in the caller's transaction
//
// This lets the same method run inside or outside a transaction without
// needing two variants. In particular, UserService.CreateUser must be called
// with an active tx so the user row and any dependent rows (e.g. employee)
// commit atomically.
type UserRepository interface {
	// ----------------------------------------------------------------------
	// Core Operations
	// ----------------------------------------------------------------------
	FindCompanyEmployeeSummaryByUsername(ctx context.Context, db client.DBTX, companyID uuid.UUID, username string) (*models.EmployeeSummary, error)
	CreateUser(ctx context.Context, db client.DBTX, user *models.User) error
	GetUserByID(ctx context.Context, db client.DBTX, userID uuid.UUID) (*models.User, error)
	GetUserByPhoneHash(ctx context.Context, db client.DBTX, phoneHash string) (*models.User, error)
	GetUserByUsername(ctx context.Context, db client.DBTX, username string) (*models.User, error)
	GetUserByUsernameExact(ctx context.Context, db client.DBTX, username string) (*models.UserByUsername, error)
	UpdateUser(ctx context.Context, db client.DBTX, user *models.User) error
	UpdateUserStatus(ctx context.Context, db client.DBTX, userID uuid.UUID, isVerified, isActive bool) error
	UpdateLastLogin(ctx context.Context, db client.DBTX, userID uuid.UUID, timestamp time.Time) error
	DeleteUser(ctx context.Context, db client.DBTX, userID uuid.UUID) error
	SoftDeleteUser(ctx context.Context, db client.DBTX, userID uuid.UUID) error
	ReactivateUser(ctx context.Context, db client.DBTX, userID uuid.UUID) error
	IsUserEmployeeOfCompany(ctx context.Context, db client.DBTX, userID, companyID uuid.UUID) (bool, error)

	// ----------------------------------------------------------------------
	// Search & Filter Operations
	// ----------------------------------------------------------------------

	SearchUsers(ctx context.Context, db client.DBTX, req *models.UserSearchRequest) ([]*models.UserSearchResult, int, error)
	SearchUsersByUsername(ctx context.Context, db client.DBTX, username string, limit int) ([]*models.User, error)
	SearchUsersByFullName(ctx context.Context, db client.DBTX, fullName string, limit int) ([]*models.User, error)
	SearchUsersByPhoneOrDevice(ctx context.Context, db client.DBTX, query string, limit, offset int) ([]*models.User, int, error)
	GetUserSuggestions(ctx context.Context, db client.DBTX, prefix string, limit int) ([]*models.UserSuggestion, error)
	FindUserByUsername(ctx context.Context, db client.DBTX, username string) (*models.UserByUsername, error)
	SearchUsersAdvanced(ctx context.Context, db client.DBTX, filters map[string]interface{}, limit, offset int) ([]*models.User, int, error)

	// ----------------------------------------------------------------------
	// Batch Operations
	//
	// For atomicity, callers must pass a *sql.Tx. Passing the pool means each
	// statement auto-commits independently.
	// ----------------------------------------------------------------------

	CreateUsersBatch(ctx context.Context, db client.DBTX, users []*models.User) error
	GetUsersByIDBatch(ctx context.Context, db client.DBTX, userIDs []uuid.UUID) ([]*models.User, error)
	UpdateUserStatusBatch(ctx context.Context, db client.DBTX, updates []UserStatusUpdate) error

	// ----------------------------------------------------------------------
	// KYC Operations
	// ----------------------------------------------------------------------

	UpdateKYCStatus(ctx context.Context, db client.DBTX, userID uuid.UUID, status, level string) error
	GetUsersByKYCStatus(ctx context.Context, db client.DBTX, status string, limit, offset int) ([]*models.User, int, error)

	// ----------------------------------------------------------------------
	// Company User Operations
	// ----------------------------------------------------------------------

	GetUsersByCompany(ctx context.Context, db client.DBTX, companyID uuid.UUID, limit, offset int) ([]*models.User, int, error)

	// ----------------------------------------------------------------------
	// Device Management
	// ----------------------------------------------------------------------

	GetUserByDeviceFingerprint(ctx context.Context, db client.DBTX, fingerprint string) (*models.User, error)
	AddUserDevice(ctx context.Context, db client.DBTX, device *models.UserDevice) error
	GetUserDevices(ctx context.Context, db client.DBTX, userID uuid.UUID) ([]models.UserDevice, error)
	RemoveUserDevice(ctx context.Context, db client.DBTX, userID uuid.UUID, deviceID string) error

	// ----------------------------------------------------------------------
	// Login Attempts & Security
	// ----------------------------------------------------------------------

	RecordLoginAttempt(ctx context.Context, db client.DBTX, userID uuid.UUID, success bool, ip, userAgent string) error
	GetRecentLoginAttempts(ctx context.Context, db client.DBTX, userID uuid.UUID, limit int) ([]models.LoginAttempt, error)

	// ----------------------------------------------------------------------
	// Search and Analytics
	// ----------------------------------------------------------------------

	GetUsersByRegion(ctx context.Context, db client.DBTX, region string, limit, offset int) ([]*models.User, int, error)
	GetUsersCreatedAfter(ctx context.Context, db client.DBTX, after time.Time, limit, offset int) ([]*models.User, int, error)
	GetUsersByCreationDateRange(ctx context.Context, db client.DBTX, start, end time.Time, limit int) ([]*models.User, error)
	CountUsersByRegion(ctx context.Context, db client.DBTX) (map[string]int, error)
	CountUsersByKYCStatus(ctx context.Context, db client.DBTX) (map[string]int, error)
	CountActiveUsers(ctx context.Context, db client.DBTX) (int, error)
	CountNewUsersSince(ctx context.Context, db client.DBTX, since time.Time) (int, error)
	GetUserActivityStats(ctx context.Context, db client.DBTX, since time.Time) (map[string]interface{}, error)
	GetKYCDistribution(ctx context.Context, db client.DBTX) (map[string]int, error)
	GetActiveUserCountsByRegion(ctx context.Context, db client.DBTX) (map[string]int, error)
	GetUserGrowthMetrics(ctx context.Context, db client.DBTX, since time.Time) (map[string]interface{}, error)
	GetUserSearchStats(ctx context.Context, db client.DBTX) (map[string]interface{}, error)

	// ----------------------------------------------------------------------
	// Maintenance Operations
	// ----------------------------------------------------------------------

	ArchiveInactiveUsers(ctx context.Context, db client.DBTX, before time.Time) (int, error)
	UpdateUserFields(ctx context.Context, db client.DBTX, userID uuid.UUID, fields map[string]interface{}) error
	GetRecentlyActiveUsers(ctx context.Context, db client.DBTX, since time.Time, limit int) ([]*models.User, error)
	GetInactiveUsersSince(ctx context.Context, db client.DBTX, since time.Time, limit int) ([]*models.User, error)

	// ----------------------------------------------------------------------
	// Maintenance & Optimization
	//
	// These MUST be called with a pool DBTX (not a tx) because
	// REINDEX CONCURRENTLY / VACUUM cannot run inside a transaction.
	// ----------------------------------------------------------------------

	RebuildUserIndexes(ctx context.Context, db client.DBTX) error
	VacuumUserTable(ctx context.Context, db client.DBTX) error

	// ----------------------------------------------------------------------
	// Partition & Performance
	// ----------------------------------------------------------------------

	GetUserByIDWithPartition(ctx context.Context, db client.DBTX, userID uuid.UUID) (*models.User, error)
	HealthCheck(ctx context.Context, db client.DBTX) error
	GetRepositoryStats(ctx context.Context, db client.DBTX) (map[string]interface{}, error)

	// ----------------------------------------------------------------------
	// Company Employee Search Operations
	// ----------------------------------------------------------------------

	SearchCompanyEmployees(ctx context.Context, db client.DBTX, req *models.CompanyEmployeeSearchRequest) ([]*models.CompanyEmployeeSearchResult, int, error)
	SearchCompanyEmployeesAdvanced(
		ctx context.Context,
		db client.DBTX,
		companyID uuid.UUID,
		filters map[string]interface{},
		limit, offset int,
	) ([]*models.EmployeeSearchResult, int, error)

	// For quick employee lookup within a company
	FindCompanyEmployeeByUsername(ctx context.Context, db client.DBTX, companyID uuid.UUID, username string) (*models.CompanyEmployeeUser, error)
	GetCompanyEmployeeSuggestions(ctx context.Context, db client.DBTX, companyID uuid.UUID, prefix string, limit int) ([]*models.UserSuggestion, error)
	GetBannedUsers(ctx context.Context, db client.DBTX, limit, offset int) ([]*models.User, int, error)

	// ----------------------------------------------------------------------
	// Avatars
	// ----------------------------------------------------------------------

	SetUserAvatar(
		ctx context.Context,
		db client.DBTX,
		userID uuid.UUID,
		avatarHash string,
		avatarObjectKey string,
		avatarMimeType string,
	) error

	GetUserAvatar(
		ctx context.Context,
		db client.DBTX,
		userID uuid.UUID,
	) (*models.UserAvatar, error)

	DeactivateUserAvatar(
		ctx context.Context,
		db client.DBTX,
		userID uuid.UUID,
	) error
	GetUserDisplayName(
		ctx context.Context,
		db client.DBTX,
		userID uuid.UUID,
	) (*models.UserDisplayName, error)

	Close() error
}
