package scylla

import (
	"context"
	"time"

	"auth-service/internal/models"

	"github.com/google/uuid"
)

// UserRepository defines the interface for user repository operations
type UserRepository interface {
	// Core Operations
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error)
	GetUserByPhoneHash(ctx context.Context, phoneHash string) (*models.User, error)
	UpdateUser(ctx context.Context, user *models.User) error
	UpdateUserProfile(ctx context.Context, userID uuid.UUID, profileServiceID uuid.UUID) error
	UpdateUserStatus(ctx context.Context, userID uuid.UUID, isVerified, isBlocked, isBanned bool) error
	UpdateLastLogin(ctx context.Context, userID uuid.UUID, timestamp time.Time) error

	// Batch Operations
	CreateUsersBatch(ctx context.Context, users []*models.User) error
	UpdateUsersBatch(ctx context.Context, users []*models.User) error
	GetUsersByIDBatch(ctx context.Context, userIDs []uuid.UUID) ([]*models.User, error)
	UpdateUserStatusBatch(ctx context.Context, updates []UserStatusUpdate) error

	// Compliance & KYC Operations
	UpdateKYCStatus(ctx context.Context, userID uuid.UUID, status, level string, verifiedBy uuid.UUID) error
	GetUsersByKYCStatus(ctx context.Context, status string, limit int, pageState []byte) ([]*models.User, []byte, error)
	UpdateUserConsent(ctx context.Context, userID uuid.UUID, agreed bool, version string) error

	// Administrative Operations
	BanUser(ctx context.Context, userID, bannedBy uuid.UUID, reason string) error
	UnbanUser(ctx context.Context, userID uuid.UUID) error
	GetBannedUsers(ctx context.Context, limit int, pageState []byte) ([]*models.User, []byte, error)

	// Health & Stats
	HealthCheck(ctx context.Context) error
	GetRepositoryStats(ctx context.Context) (map[string]interface{}, error)
}
