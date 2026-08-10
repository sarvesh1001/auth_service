package postgres

import (
	"context"
	"time"

	"auth-service/internal/models"

	"github.com/google/uuid"
)

type UserRepository interface {
	// ----------------------------------------------------------------------
	// Core Operations
	// ----------------------------------------------------------------------
	FindCompanyEmployeeSummaryByUsername(ctx context.Context, companyID uuid.UUID, username string) (*models.EmployeeSummary, error)
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error)
	GetUserByPhoneHash(ctx context.Context, phoneHash string) (*models.User, error)
	GetUserByUsername(ctx context.Context, username string) (*models.User, error)
	GetUserByUsernameExact(ctx context.Context, username string) (*models.UserByUsername, error)
	UpdateUser(ctx context.Context, user *models.User) error
	UpdateUserStatus(ctx context.Context, userID uuid.UUID, isVerified, isActive bool) error
	UpdateLastLogin(ctx context.Context, userID uuid.UUID, timestamp time.Time) error
	DeleteUser(ctx context.Context, userID uuid.UUID) error
	SoftDeleteUser(ctx context.Context, userID uuid.UUID) error
	ReactivateUser(ctx context.Context, userID uuid.UUID) error
	IsUserEmployeeOfCompany(ctx context.Context, userID, companyID uuid.UUID) (bool, error)

	// ----------------------------------------------------------------------
	// Search & Filter Operations
	// ----------------------------------------------------------------------

	SearchUsers(ctx context.Context, req *models.UserSearchRequest) ([]*models.UserSearchResult, int, error)
	SearchUsersByUsername(ctx context.Context, username string, limit int) ([]*models.User, error)
	SearchUsersByFullName(ctx context.Context, fullName string, limit int) ([]*models.User, error)
	SearchUsersByPhoneOrDevice(ctx context.Context, query string, limit, offset int) ([]*models.User, int, error)
	GetUserSuggestions(ctx context.Context, prefix string, limit int) ([]*models.UserSuggestion, error)
	FindUserByUsername(ctx context.Context, username string) (*models.UserByUsername, error)
	SearchUsersAdvanced(ctx context.Context, filters map[string]interface{}, limit, offset int) ([]*models.User, int, error)

	// ----------------------------------------------------------------------
	// Batch Operations
	// ----------------------------------------------------------------------

	CreateUsersBatch(ctx context.Context, users []*models.User) error
	GetUsersByIDBatch(ctx context.Context, userIDs []uuid.UUID) ([]*models.User, error)
	UpdateUserStatusBatch(ctx context.Context, updates []UserStatusUpdate) error

	// ----------------------------------------------------------------------
	// KYC Operations
	// ----------------------------------------------------------------------

	UpdateKYCStatus(ctx context.Context, userID uuid.UUID, status, level string) error
	GetUsersByKYCStatus(ctx context.Context, status string, limit, offset int) ([]*models.User, int, error)

	// ----------------------------------------------------------------------
	// Company User Operations
	// ----------------------------------------------------------------------

	GetUsersByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.User, int, error)

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
	// Search and Analytics
	// ----------------------------------------------------------------------

	GetUsersByRegion(ctx context.Context, region string, limit, offset int) ([]*models.User, int, error)
	GetUsersCreatedAfter(ctx context.Context, after time.Time, limit, offset int) ([]*models.User, int, error)
	GetUsersByCreationDateRange(ctx context.Context, start, end time.Time, limit int) ([]*models.User, error)
	CountUsersByRegion(ctx context.Context) (map[string]int, error)
	CountUsersByKYCStatus(ctx context.Context) (map[string]int, error)
	CountActiveUsers(ctx context.Context) (int, error)
	CountNewUsersSince(ctx context.Context, since time.Time) (int, error)
	GetUserActivityStats(ctx context.Context, since time.Time) (map[string]interface{}, error)
	GetKYCDistribution(ctx context.Context) (map[string]int, error)
	GetActiveUserCountsByRegion(ctx context.Context) (map[string]int, error)
	GetUserGrowthMetrics(ctx context.Context, since time.Time) (map[string]interface{}, error)
	GetUserSearchStats(ctx context.Context) (map[string]interface{}, error)

	// ----------------------------------------------------------------------
	// Maintenance Operations
	// ----------------------------------------------------------------------

	ArchiveInactiveUsers(ctx context.Context, before time.Time) (int, error)
	UpdateUserFields(ctx context.Context, userID uuid.UUID, fields map[string]interface{}) error
	GetRecentlyActiveUsers(ctx context.Context, since time.Time, limit int) ([]*models.User, error)
	GetInactiveUsersSince(ctx context.Context, since time.Time, limit int) ([]*models.User, error)

	// ----------------------------------------------------------------------
	// Maintenance & Optimization
	// ----------------------------------------------------------------------

	RebuildUserIndexes(ctx context.Context) error
	VacuumUserTable(ctx context.Context) error

	// ----------------------------------------------------------------------
	// Partition & Performance
	// ----------------------------------------------------------------------

	GetUserByIDWithPartition(ctx context.Context, userID uuid.UUID) (*models.User, error)
	HealthCheck(ctx context.Context) error
	GetRepositoryStats(ctx context.Context) (map[string]interface{}, error)

	// ----------------------------------------------------------------------
	// Company Employee Search Operations
	// ----------------------------------------------------------------------

	SearchCompanyEmployees(ctx context.Context, req *models.CompanyEmployeeSearchRequest) ([]*models.CompanyEmployeeSearchResult, int, error)
	SearchCompanyEmployeesAdvanced(
		ctx context.Context,
		companyID uuid.UUID,
		filters map[string]interface{},
		limit, offset int,
	) ([]*models.EmployeeSearchResult, int, error)

	// For quick employee lookup within a company
	FindCompanyEmployeeByUsername(ctx context.Context, companyID uuid.UUID, username string) (*models.CompanyEmployeeUser, error) // UPDATED RETURN TYPE
	GetCompanyEmployeeSuggestions(ctx context.Context, companyID uuid.UUID, prefix string, limit int) ([]*models.UserSuggestion, error)
	GetBannedUsers(ctx context.Context, limit, offset int) ([]*models.User, int, error)
	// ----------------------------------------------------------------------
	// Close
	// ----------------------------------------------------------------------
	SetUserAvatar(
		ctx context.Context,
		userID uuid.UUID,
		avatarHash string,
		avatarObjectKey string,
		avatarMimeType string,
	) error

	GetUserAvatar(
		ctx context.Context,
		userID uuid.UUID,
	) (*models.UserAvatar, error)

	DeactivateUserAvatar(
		ctx context.Context,
		userID uuid.UUID,
	) error
	Close() error
}
