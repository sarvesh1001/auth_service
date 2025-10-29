// internal/repository/redis/session_repository.go
package redis

import (
    "context"
    "encoding/json"
    "fmt"
    "net"
    "strings"
    "time"

    "auth-service/internal/models"
    "auth-service/internal/util"

    "github.com/google/uuid"
    "github.com/redis/go-redis/v9"
    "go.uber.org/zap"
)

const (
    sessionKeyPrefix       = "session:user:"
    sessionTokenKeyPrefix  = "session:token:"
    sessionDeviceKeyPrefix = "session:device:"
    sessionCountKeyPrefix  = "session:count:"
    sessionTTL            = 30 * 24 * time.Hour // 30 days
)

type SessionRepositoryImpl struct {
    client *redis.Client
    logger *zap.Logger
}

// NewSessionRepository creates a new session repository
func NewSessionRepository(client *redis.Client, logger *zap.Logger) SessionRepository {
    return &SessionRepositoryImpl{
        client: client,
        logger: logger,
    }
}

// CreateSession creates a new session
func (r *SessionRepositoryImpl) CreateSession(ctx context.Context, session *models.ActiveSession) error {
    startTime := time.Now()

    // Serialize session
    sessionData, err := json.Marshal(session)
    if err != nil {
        return fmt.Errorf("failed to serialize session: %w", err)
    }

    pipe := r.client.Pipeline()

    // Store session by user ID
    userKey := fmt.Sprintf("%s%s", sessionKeyPrefix, session.UserID)
    pipe.Set(ctx, userKey, sessionData, sessionTTL)

    // Store session by token for quick lookup
    tokenKey := fmt.Sprintf("%s%s", sessionTokenKeyPrefix, session.SessionToken)
    pipe.Set(ctx, tokenKey, session.UserID, sessionTTL)

    // Add to device sessions set
    if session.DeviceID != "" {
        deviceKey := fmt.Sprintf("%s%s", sessionDeviceKeyPrefix, session.DeviceID)
        pipe.SAdd(ctx, deviceKey, session.UserID)
        pipe.Expire(ctx, deviceKey, sessionTTL)
    }

    // Increment active sessions count
    countKey := fmt.Sprintf("%s%s", sessionCountKeyPrefix, session.UserID)
    pipe.Incr(ctx, countKey)
    pipe.Expire(ctx, countKey, sessionTTL)

    if _, err := pipe.Exec(ctx); err != nil {
        return fmt.Errorf("failed to create session: %w", err)
    }

    r.logger.Debug("Session created",
        util.String("user_id", session.UserID),
        util.String("device_id", session.DeviceID),
        util.Duration("duration", time.Since(startTime)),
    )

    return nil
}

// GetSessionByUserID retrieves a session by user ID
func (r *SessionRepositoryImpl) GetSessionByUserID(ctx context.Context, userID uuid.UUID) (*models.ActiveSession, error) {
    key := fmt.Sprintf("%s%s", sessionKeyPrefix, userID.String())

    data, err := r.client.Get(ctx, key).Bytes()
    if err != nil {
        if err == redis.Nil {
            return nil, fmt.Errorf("session not found for user: %s", userID)
        }
        return nil, fmt.Errorf("failed to get session: %w", err)
    }

    var session models.ActiveSession
    if err := json.Unmarshal(data, &session); err != nil {
        return nil, fmt.Errorf("failed to deserialize session: %w", err)
    }

    // Check if expired
    if time.Now().After(session.ExpiresAt) {
        r.InvalidateSession(ctx, userID)
        return nil, fmt.Errorf("session expired")
    }

    return &session, nil
}

// GetSessionByToken retrieves a session by session token
func (r *SessionRepositoryImpl) GetSessionByToken(ctx context.Context, sessionToken string) (*models.ActiveSession, error) {
    // First get user ID from token
    tokenKey := fmt.Sprintf("%s%s", sessionTokenKeyPrefix, sessionToken)
    userID, err := r.client.Get(ctx, tokenKey).Result()
    if err != nil {
        if err == redis.Nil {
            return nil, fmt.Errorf("session not found for token")
        }
        return nil, fmt.Errorf("failed to get session token: %w", err)
    }

    // Then get full session
    uid, err := uuid.Parse(userID)
    if err != nil {
        return nil, fmt.Errorf("invalid user ID in session: %w", err)
    }

    return r.GetSessionByUserID(ctx, uid)
}

// UpdateSessionActivity updates session activity timestamp
func (r *SessionRepositoryImpl) UpdateSessionActivity(ctx context.Context, userID uuid.UUID, lastActivity time.Time, ipAddress net.IP) error {
    session, err := r.GetSessionByUserID(ctx, userID)
    if err != nil {
        return err
    }

    session.LastActivity = lastActivity
    session.IPAddress = ipAddress

    sessionData, err := json.Marshal(session)
    if err != nil {
        return fmt.Errorf("failed to serialize session: %w", err)
    }

    key := fmt.Sprintf("%s%s", sessionKeyPrefix, userID.String())
    if err := r.client.Set(ctx, key, sessionData, sessionTTL).Err(); err != nil {
        return fmt.Errorf("failed to update session activity: %w", err)
    }

    return nil
}

// InvalidateSession invalidates a session by user ID
func (r *SessionRepositoryImpl) InvalidateSession(ctx context.Context, userID uuid.UUID) error {
    session, err := r.GetSessionByUserID(ctx, userID)
    if err != nil {
        // Session might not exist, which is okay
        return nil
    }

    pipe := r.client.Pipeline()

    // Delete session by user ID
    userKey := fmt.Sprintf("%s%s", sessionKeyPrefix, userID.String())
    pipe.Del(ctx, userKey)

    // Delete session by token
    tokenKey := fmt.Sprintf("%s%s", sessionTokenKeyPrefix, session.SessionToken)
    pipe.Del(ctx, tokenKey)

    // Remove from device sessions
    if session.DeviceID != "" {
        deviceKey := fmt.Sprintf("%s%s", sessionDeviceKeyPrefix, session.DeviceID)
        pipe.SRem(ctx, deviceKey, userID.String())
    }

    // Decrement active sessions count
    countKey := fmt.Sprintf("%s%s", sessionCountKeyPrefix, userID.String())
    pipe.Decr(ctx, countKey)

    if _, err := pipe.Exec(ctx); err != nil {
        return fmt.Errorf("failed to invalidate session: %w", err)
    }

    r.logger.Info("Session invalidated",
        util.String("user_id", userID.String()),
    )

    return nil
}

// InvalidateSessionByToken invalidates a session by session token
func (r *SessionRepositoryImpl) InvalidateSessionByToken(ctx context.Context, sessionToken string) error {
    tokenKey := fmt.Sprintf("%s%s", sessionTokenKeyPrefix, sessionToken)
    userID, err := r.client.Get(ctx, tokenKey).Result()
    if err != nil {
        if err == redis.Nil {
            return nil // Session doesn't exist
        }
        return fmt.Errorf("failed to get session token: %w", err)
    }

    uid, err := uuid.Parse(userID)
    if err != nil {
        return fmt.Errorf("invalid user ID: %w", err)
    }

    return r.InvalidateSession(ctx, uid)
}

// RefreshSession refreshes a session with a new token and expiry
func (r *SessionRepositoryImpl) RefreshSession(ctx context.Context, userID uuid.UUID, newToken string, expiresAt time.Time) error {
    session, err := r.GetSessionByUserID(ctx, userID)
    if err != nil {
        return err
    }

    // Delete old token
    oldTokenKey := fmt.Sprintf("%s%s", sessionTokenKeyPrefix, session.SessionToken)
    r.client.Del(ctx, oldTokenKey)

    // Update session
    session.SessionToken = newToken
    session.ExpiresAt = expiresAt

    sessionData, err := json.Marshal(session)
    if err != nil {
        return fmt.Errorf("failed to serialize session: %w", err)
    }

    pipe := r.client.Pipeline()

    // Update session by user ID
    userKey := fmt.Sprintf("%s%s", sessionKeyPrefix, userID.String())
    pipe.Set(ctx, userKey, sessionData, sessionTTL)

    // Create new token mapping
    newTokenKey := fmt.Sprintf("%s%s", sessionTokenKeyPrefix, newToken)
    pipe.Set(ctx, newTokenKey, userID.String(), sessionTTL)

    if _, err := pipe.Exec(ctx); err != nil {
        return fmt.Errorf("failed to refresh session: %w", err)
    }

    r.logger.Info("Session refreshed",
        util.String("user_id", userID.String()),
    )

    return nil
}

// InvalidateSessionsBatch invalidates multiple sessions
func (r *SessionRepositoryImpl) InvalidateSessionsBatch(ctx context.Context, userIDs []uuid.UUID) error {
    if len(userIDs) == 0 {
        return nil
    }

    for _, userID := range userIDs {
        if err := r.InvalidateSession(ctx, userID); err != nil {
            r.logger.Warn("Failed to invalidate session in batch",
                util.ErrorField(err),
                util.String("user_id", userID.String()),
            )
        }
    }

    r.logger.Info("Batch session invalidation completed",
        util.Int("count", len(userIDs)),
    )

    return nil
}

// GetSessionsBatch retrieves multiple sessions
func (r *SessionRepositoryImpl) GetSessionsBatch(ctx context.Context, userIDs []uuid.UUID) ([]*models.ActiveSession, error) {
    if len(userIDs) == 0 {
        return []*models.ActiveSession{}, nil
    }

    sessions := make([]*models.ActiveSession, 0, len(userIDs))

    for _, userID := range userIDs {
        session, err := r.GetSessionByUserID(ctx, userID)
        if err != nil {
            r.logger.Debug("Session not found in batch",
                util.String("user_id", userID.String()),
            )
            continue
        }
        sessions = append(sessions, session)
    }

    return sessions, nil
}

// CleanupExpiredSessions cleans up expired sessions (Redis TTL handles this automatically)
func (r *SessionRepositoryImpl) CleanupExpiredSessions(ctx context.Context, batchSize int) (int, error) {
    // Redis TTL handles automatic cleanup, but we can scan for any orphaned keys
    cleaned := 0

    // Scan for session keys
    iter := r.client.Scan(ctx, 0, sessionKeyPrefix+"*", int64(batchSize)).Iterator()

    for iter.Next(ctx) {
        key := iter.Val()

        // Get the session
        data, err := r.client.Get(ctx, key).Bytes()
        if err != nil {
            continue
        }

        var session models.ActiveSession
        if err := json.Unmarshal(data, &session); err != nil {
            continue
        }

        // Check if expired
        if time.Now().After(session.ExpiresAt) {
            userID := strings.TrimPrefix(key, sessionKeyPrefix)
            uid, err := uuid.Parse(userID)
            if err != nil {
                continue
            }

            r.InvalidateSession(ctx, uid)
            cleaned++
        }
    }

    if err := iter.Err(); err != nil {
        return cleaned, fmt.Errorf("error scanning sessions: %w", err)
    }

    r.logger.Info("Expired sessions cleanup completed",
        util.Int("cleaned", cleaned),
    )

    return cleaned, nil
}

// GetSessionsByDevice retrieves sessions for a specific device
func (r *SessionRepositoryImpl) GetSessionsByDevice(ctx context.Context, deviceID string, limit int) ([]*models.ActiveSession, error) {
    deviceKey := fmt.Sprintf("%s%s", sessionDeviceKeyPrefix, deviceID)

    userIDs, err := r.client.SMembers(ctx, deviceKey).Result()
    if err != nil {
        if err == redis.Nil {
            return []*models.ActiveSession{}, nil
        }
        return nil, fmt.Errorf("failed to get device sessions: %w", err)
    }

    // Limit results
    if limit > 0 && len(userIDs) > limit {
        userIDs = userIDs[:limit]
    }

    sessions := make([]*models.ActiveSession, 0, len(userIDs))
    for _, userIDStr := range userIDs {
        uid, err := uuid.Parse(userIDStr)
        if err != nil {
            continue
        }

        session, err := r.GetSessionByUserID(ctx, uid)
        if err != nil {
            continue
        }

        sessions = append(sessions, session)
    }

    return sessions, nil
}

// InvalidateDeviceSessions invalidates all sessions for a device
func (r *SessionRepositoryImpl) InvalidateDeviceSessions(ctx context.Context, deviceID string) error {
    sessions, err := r.GetSessionsByDevice(ctx, deviceID, 0)
    if err != nil {
        return err
    }

    for _, session := range sessions {
        uid, err := uuid.Parse(session.UserID)
        if err != nil {
            continue
        }
        r.InvalidateSession(ctx, uid)
    }

    r.logger.Info("Device sessions invalidated",
        util.String("device_id", deviceID),
        util.Int("count", len(sessions)),
    )

    return nil
}

// GetActiveSessionsCount gets the count of active sessions for a user
func (r *SessionRepositoryImpl) GetActiveSessionsCount(ctx context.Context, userID uuid.UUID) (int, error) {
    countKey := fmt.Sprintf("%s%s", sessionCountKeyPrefix, userID.String())

    count, err := r.client.Get(ctx, countKey).Int()
    if err != nil {
        if err == redis.Nil {
            return 0, nil
        }
        return 0, fmt.Errorf("failed to get session count: %w", err)
    }

    return count, nil
}

// HealthCheck performs a health check on the repository
func (r *SessionRepositoryImpl) HealthCheck(ctx context.Context) error {
    if err := r.client.Ping(ctx).Err(); err != nil {
        return fmt.Errorf("session repository health check failed: %w", err)
    }
    return nil
}

// GetRepositoryStats returns repository statistics
func (r *SessionRepositoryImpl) GetRepositoryStats(ctx context.Context) (map[string]interface{}, error) {
    stats := make(map[string]interface{})

    // Count active sessions
    iter := r.client.Scan(ctx, 0, sessionKeyPrefix+"*", 1000).Iterator()
    count := 0
    for iter.Next(ctx) {
        count++
    }

    stats["active_sessions"] = count
    stats["session_ttl_hours"] = int(sessionTTL.Hours())

    return stats, nil
}
