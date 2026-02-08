package repository

import (
	"context"
	"time"

	"auth-service/internal/hr/models/attendance"

	"github.com/google/uuid"
)

type DeviceTokenRepository interface {
	// CreateToken creates a new device token with hashed token
	CreateToken(ctx context.Context, token *attendance.DeviceToken) error

	// GetActiveTokenByHash retrieves an active token by its hash
	GetActiveTokenByHash(ctx context.Context, companyID uuid.UUID, deviceID, tokenHash string) (*attendance.DeviceToken, error)

	// GetActiveTokensForDevice retrieves all active tokens for a device
	GetActiveTokensForDevice(ctx context.Context, companyID uuid.UUID, deviceID string) ([]*attendance.DeviceToken, error)

	// RevokeToken marks a token as inactive
	RevokeToken(ctx context.Context, tokenID uuid.UUID, revokedBy *uuid.UUID, reason string) error

	// RevokeAllDeviceTokens revokes all tokens for a device
	RevokeAllDeviceTokens(ctx context.Context, companyID uuid.UUID, deviceID string, revokedBy *uuid.UUID, reason string) error

	// RotateToken creates a new token and revokes the old one
	RotateToken(ctx context.Context, oldTokenID uuid.UUID, newToken *attendance.DeviceToken, revokedBy *uuid.UUID, reason string) error

	// UpdateTokenLastUsed updates the last used timestamp
	UpdateTokenLastUsed(ctx context.Context, tokenID uuid.UUID) error

	// CleanupExpiredTokens removes expired and revoked tokens
	CleanupExpiredTokens(ctx context.Context, before time.Time) (int64, error)

	// GetTokenByID gets token by its ID
	GetTokenByID(ctx context.Context, tokenID uuid.UUID) (*attendance.DeviceToken, error)

	// HealthCheck verifies repository connectivity
	HealthCheck(ctx context.Context) error
}
