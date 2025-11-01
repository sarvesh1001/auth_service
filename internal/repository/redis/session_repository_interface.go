// internal/repository/redis/session_repository_interface.go
package redis

import (
    "context"
    "net"
    "time"

    "auth-service/internal/models"

    "github.com/google/uuid"
)
type SessionRepository interface {
    // Core Operations
    CreateSession(ctx context.Context, session *models.ActiveSession) error
    GetSessionByUserID(ctx context.Context, userID uuid.UUID) (*models.ActiveSession, error)
    GetSessionByToken(ctx context.Context, sessionToken string) (*models.ActiveSession, error)
    UpdateSessionActivity(ctx context.Context, userID uuid.UUID, lastActivity time.Time, ipAddress net.IP) error
    InvalidateSession(ctx context.Context, userID uuid.UUID) error
    InvalidateSessionByToken(ctx context.Context, sessionToken string) error
    RefreshSession(ctx context.Context, userID uuid.UUID, newToken string, expiresAt time.Time) error

    // Bulk Operations
    InvalidateSessionsBatch(ctx context.Context, userIDs []uuid.UUID) error
    GetSessionsBatch(ctx context.Context, userIDs []uuid.UUID) ([]*models.ActiveSession, error)
    CleanupExpiredSessions(ctx context.Context, batchSize int) (int, error)

    // Device Management
    GetSessionsByDevice(ctx context.Context, deviceID string, limit int) ([]*models.ActiveSession, error)
    InvalidateDeviceSessions(ctx context.Context, deviceID string) error
    GetActiveSessionsCount(ctx context.Context, userID uuid.UUID) (int, error)

    // ✅ NEW: Admin Session Support
    GetSessionType(ctx context.Context, sessionToken string) (string, error)
    IsAdminSession(ctx context.Context, sessionToken string) (bool, error)
    GetAdminSessions(ctx context.Context, userID uuid.UUID) ([]*models.ActiveSession, error)
    InvalidateAdminSessions(ctx context.Context, userID uuid.UUID) error
    GetActiveAdminSessionsCount(ctx context.Context, userID uuid.UUID) (int, error)

    // Health & Monitoring
    HealthCheck(ctx context.Context) error
    GetRepositoryStats(ctx context.Context) (map[string]interface{}, error)
}