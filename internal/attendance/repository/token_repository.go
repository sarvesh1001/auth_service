package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/attendance/models"
)

// TokenRepository defines operations for attendance device tokens.
type TokenRepository interface {
	// CreateToken inserts a new device token.
	CreateToken(ctx context.Context, tx *sql.Tx, token *models.DeviceToken) error

	// GetActiveTokenByHash retrieves an active token by its hash for a specific device.
	GetActiveTokenByHash(ctx context.Context, companyID uuid.UUID, deviceID, tokenHash string) (*models.DeviceToken, error)

	// GetActiveTokensForDevice retrieves all active tokens for a device.
	GetActiveTokensForDevice(ctx context.Context, companyID uuid.UUID, deviceID string) ([]*models.DeviceToken, error)

	// RevokeToken revokes a specific token.
	RevokeToken(ctx context.Context, tokenID uuid.UUID, revokedBy *uuid.UUID, reason string) error

	// RevokeAllDeviceTokens revokes all active tokens for a device.
	RevokeAllDeviceTokens(ctx context.Context, companyID uuid.UUID, deviceID string, revokedBy *uuid.UUID, reason string) error

	// RotateToken revokes the old token and creates a new one in a transaction.
	RotateToken(ctx context.Context, oldTokenID uuid.UUID, newToken *models.DeviceToken, revokedBy *uuid.UUID, reason string) error

	// UpdateTokenLastUsed updates the last_used_at timestamp in metadata.
	UpdateTokenLastUsed(ctx context.Context, tokenID uuid.UUID) error

	// CleanupExpiredTokens removes tokens that expired or were revoked before a given time.
	CleanupExpiredTokens(ctx context.Context, before time.Time) (int64, error)

	// GetTokenByID retrieves a token by its ID.
	GetTokenByID(ctx context.Context, tokenID uuid.UUID) (*models.DeviceToken, error)

	// HealthCheck verifies database connectivity.
	HealthCheck(ctx context.Context) error
}
