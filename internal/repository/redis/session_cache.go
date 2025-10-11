package redis

import (
    "context"
    "encoding/json"
    "fmt"
    "time"
    "go.uber.org/zap"             // needed for zap.Field in util calls

    "auth-service/internal/client"
    "auth-service/internal/util"
)

const (
    activeSessionPrefix = "active_session:"
    sessionDataPrefix   = "session_data:"
    userSessionsPrefix  = "user_sessions:"
    sessionLockPrefix   = "session_lock:"
)

type SessionCache struct {
    client *client.RedisClient
}

func NewSessionCache(client *client.RedisClient) *SessionCache {
    return &SessionCache{client: client}
}

func (c *SessionCache) SetActiveSession(userID, sessionID string, ttl time.Duration) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    pipe := c.client.Pipeline()
    activeKey := activeSessionPrefix + userID
    pipe.Set(ctx, activeKey, sessionID, ttl)
    userSessionsKey := userSessionsPrefix + userID
    pipe.SAdd(ctx, userSessionsKey, sessionID)
    pipe.Expire(ctx, userSessionsKey, ttl)
    if _, err := pipe.Exec(ctx); err != nil {
        util.Error("Failed to set active session", zap.String("user_id", userID), zap.String("session_id", sessionID), zap.Duration("ttl", ttl), zap.Error(err))
        return fmt.Errorf("failed to set active session: %w", err)
    }
    util.Debug("Active session set", zap.String("user_id", userID), zap.String("session_id", sessionID), zap.Duration("ttl", ttl))
    return nil
}

// ... GetActiveSession, InvalidateSession, SetSessionData, GetSessionData,
//     UpdateSessionField, GetSessionField, DeleteSessionField,
//     AcquireSessionLock, ReleaseSessionLock, IsSessionValid,
//     RefreshSession, GetSessionTTL, GetUserSessions,
//     InvalidateAllUserSessions, SetSessionExpiry, InvalidateSessionByID,
//     GetSessionStats, CleanupExpiredSessions, InvalidateMultipleSessions ...

func (c *SessionCache) GetActiveSession(userID string) (string, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    key := activeSessionPrefix + userID

    sessionID, err := c.client.Get(ctx, key)
    if err != nil {
        if err.Error() == fmt.Sprintf("key not found: %s", key) {
            return "", fmt.Errorf("no active session found for user: %s", userID)
        }
        util.Error("Failed to get active session",
            zap.String("user_id", userID),
            zap.Error(err))
        return "", fmt.Errorf("failed to get active session: %w", err)
    }

    return sessionID, nil
}

func (c *SessionCache) InvalidateSession(userID string) error {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    // Get current active session ID
    activeSessionID, err := c.GetActiveSession(userID)
    if err != nil && err.Error() != fmt.Sprintf("no active session found for user: %s", userID) {
        return err
    }

    // Use pipeline for atomic cleanup
    pipe := c.client.Pipeline()

    // Remove active session
    activeKey := activeSessionPrefix + userID
    pipe.Del(ctx, activeKey)

    // Remove session data if we have the session ID
    if activeSessionID != "" {
        sessionDataKey := sessionDataPrefix + activeSessionID
        pipe.Del(ctx, sessionDataKey)

        // Remove from user sessions set
        userSessionsKey := userSessionsPrefix + userID
        pipe.SRem(ctx, userSessionsKey, activeSessionID)
    }

    _, err = pipe.Exec(ctx)
    if err != nil {
        util.Error("Failed to invalidate session",
            zap.String("user_id", userID),
            zap.String("session_id", activeSessionID),
            zap.Error(err))
        return fmt.Errorf("failed to invalidate session: %w", err)
    }

    util.Info("Session invalidated",
        zap.String("user_id", userID),
        zap.String("session_id", activeSessionID))

    return nil
}

func (c *SessionCache) SetSessionData(sessionID string, data map[string]interface{}, ttl time.Duration) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    key := sessionDataPrefix + sessionID

    // Serialize data to JSON
    jsonData, err := json.Marshal(data)
    if err != nil {
        util.Error("Failed to marshal session data",
            zap.String("session_id", sessionID),
            zap.Error(err))
        return fmt.Errorf("failed to marshal session data: %w", err)
    }

    if err := c.client.Set(ctx, key, string(jsonData), ttl); err != nil {
        util.Error("Failed to set session data",
            zap.String("session_id", sessionID),
            zap.Duration("ttl", ttl),
            zap.Error(err))
        return fmt.Errorf("failed to set session data: %w", err)
    }

    util.Debug("Session data set",
        zap.String("session_id", sessionID),
        zap.Duration("ttl", ttl))

    return nil
}

func (c *SessionCache) GetSessionData(sessionID string) (map[string]interface{}, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    key := sessionDataPrefix + sessionID

    jsonData, err := c.client.Get(ctx, key)
    if err != nil {
        if err.Error() == fmt.Sprintf("key not found: %s", key) {
            return nil, fmt.Errorf("session data not found: %s", sessionID)
        }
        util.Error("Failed to get session data",
            zap.String("session_id", sessionID),
            zap.Error(err))
        return nil, fmt.Errorf("failed to get session data: %w", err)
    }

    // Deserialize JSON data
    var data map[string]interface{}
    if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
        util.Error("Failed to unmarshal session data",
            zap.String("session_id", sessionID),
            zap.Error(err))
        return nil, fmt.Errorf("failed to unmarshal session data: %w", err)
    }

    return data, nil
}

// Advanced session management

func (c *SessionCache) UpdateSessionField(sessionID, field string, value interface{}, ttl time.Duration) error {
    // Get existing session data
    data, err := c.GetSessionData(sessionID)
    if err != nil {
        // If session doesn't exist, create new one
        data = make(map[string]interface{})
    }

    // Update the field
    data[field] = value

    // Save back to cache
    return c.SetSessionData(sessionID, data, ttl)
}

func (c *SessionCache) GetSessionField(sessionID, field string) (interface{}, error) {
    data, err := c.GetSessionData(sessionID)
    if err != nil {
        return nil, err
    }

    value, exists := data[field]
    if !exists {
        return nil, fmt.Errorf("field not found in session: %s", field)
    }

    return value, nil
}

func (c *SessionCache) DeleteSessionField(sessionID, field string, ttl time.Duration) error {
    data, err := c.GetSessionData(sessionID)
    if err != nil {
        return err
    }

    delete(data, field)
    return c.SetSessionData(sessionID, data, ttl)
}

// Session locking for concurrent access control

func (c *SessionCache) AcquireSessionLock(sessionID string, ttl time.Duration) (bool, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    key := sessionLockPrefix + sessionID

    success, err := c.client.SetNX(ctx, key, "locked", ttl)
    if err != nil {
        util.Error("Failed to acquire session lock",
            zap.String("session_id", sessionID),
            zap.Error(err))
        return false, fmt.Errorf("failed to acquire session lock: %w", err)
    }

    if success {
        util.Debug("Session lock acquired",
            zap.String("session_id", sessionID),
            zap.Duration("ttl", ttl))
    }

    return success, nil
}

func (c *SessionCache) ReleaseSessionLock(sessionID string) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    key := sessionLockPrefix + sessionID

    if err := c.client.Del(ctx, key); err != nil {
        util.Error("Failed to release session lock",
            zap.String("session_id", sessionID),
            zap.Error(err))
        return fmt.Errorf("failed to release session lock: %w", err)
    }

    util.Debug("Session lock released",
        zap.String("session_id", sessionID))

    return nil
}

// Session validation and security

func (c *SessionCache) IsSessionValid(sessionID string) (bool, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    key := sessionDataPrefix + sessionID

    exists, err := c.client.Exists(ctx, key)
    if err != nil {
        return false, fmt.Errorf("failed to check session validity: %w", err)
    }

    return exists, nil
}

func (c *SessionCache) RefreshSession(sessionID string, newTTL time.Duration) error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    keys := []string{
        sessionDataPrefix + sessionID,
    }

    pipe := c.client.Pipeline()
    for _, key := range keys {
        pipe.Expire(ctx, key, newTTL)
    }

    _, err := pipe.Exec(ctx)
    if err != nil {
        util.Error("Failed to refresh session",
            zap.String("session_id", sessionID),
            zap.Duration("new_ttl", newTTL),
            zap.Error(err))
        return fmt.Errorf("failed to refresh session: %w", err)
    }

    util.Debug("Session refreshed",
        zap.String("session_id", sessionID),
        zap.Duration("new_ttl", newTTL))

    return nil
}

func (c *SessionCache) GetSessionTTL(sessionID string) (time.Duration, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    key := sessionDataPrefix + sessionID

    ttl, err := c.client.TTL(ctx, key)
    if err != nil {
        return 0, fmt.Errorf("failed to get session TTL: %w", err)
    }

    return ttl, nil
}

// Multi-session management

func (c *SessionCache) GetUserSessions(userID string) ([]string, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    key := userSessionsPrefix + userID

    sessions, err := c.client.SMembers(ctx, key)
    if err != nil {
        util.Error("Failed to get user sessions",
            zap.String("user_id", userID),
            zap.Error(err))
        return nil, fmt.Errorf("failed to get user sessions: %w", err)
    }

    return sessions, nil
}

func (c *SessionCache) InvalidateAllUserSessions(userID string) error {
    ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
    defer cancel()

    // Get all user sessions
    sessions, err := c.GetUserSessions(userID)
    if err != nil {
        return err
    }

    if len(sessions) == 0 {
        return nil // No sessions to invalidate
    }

    // Use pipeline for atomic cleanup
    pipe := c.client.Pipeline()

    // Remove active session
    activeKey := activeSessionPrefix + userID
    pipe.Del(ctx, activeKey)

    // Remove all session data
    for _, sessionID := range sessions {
        sessionDataKey := sessionDataPrefix + sessionID
        pipe.Del(ctx, sessionDataKey)

        sessionLockKey := sessionLockPrefix + sessionID
        pipe.Del(ctx, sessionLockKey)
    }

    // Remove user sessions set
    userSessionsKey := userSessionsPrefix + userID
    pipe.Del(ctx, userSessionsKey)

    _, err = pipe.Exec(ctx)
    if err != nil {
        util.Error("Failed to invalidate all user sessions",
            zap.String("user_id", userID),
            zap.Int("session_count", len(sessions)),
            zap.Error(err))
        return fmt.Errorf("failed to invalidate all user sessions: %w", err)
    }

    util.Info("All user sessions invalidated",
        zap.String("user_id", userID),
        zap.Int("session_count", len(sessions)))

    return nil
}

func (c *SessionCache) SetSessionExpiry(sessionID string, expiryTime time.Time) error {
    ttl := time.Until(expiryTime)
    if ttl <= 0 {
        // Session should expire immediately
        return c.InvalidateSessionByID(sessionID)
    }

    return c.RefreshSession(sessionID, ttl)
}

func (c *SessionCache) InvalidateSessionByID(sessionID string) error {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    // Use pipeline for atomic cleanup
    pipe := c.client.Pipeline()

    // Remove session data
    sessionDataKey := sessionDataPrefix + sessionID
    pipe.Del(ctx, sessionDataKey)

    // Remove session lock
    sessionLockKey := sessionLockPrefix + sessionID
    pipe.Del(ctx, sessionLockKey)

    _, err := pipe.Exec(ctx)
    if err != nil {
        util.Error("Failed to invalidate session by ID",
            zap.String("session_id", sessionID),
            zap.Error(err))
        return fmt.Errorf("failed to invalidate session by ID: %w", err)
    }

    util.Info("Session invalidated by ID",
        zap.String("session_id", sessionID))

    return nil
}

// Statistics and monitoring

func (c *SessionCache) GetSessionStats() (map[string]interface{}, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
    defer cancel()

    stats := make(map[string]interface{})

    patterns := map[string]string{
        "active_sessions":  activeSessionPrefix + "*",
        "session_data":     sessionDataPrefix + "*",
        "user_sessions":    userSessionsPrefix + "*",
        "session_locks":    sessionLockPrefix + "*",
    }

    for statName, pattern := range patterns {
        keys, _, err := c.client.Scan(ctx, 0, pattern, 1000)
        if err != nil {
            util.Warn("Failed to scan keys for session stats",
                zap.String("pattern", pattern),
                zap.Error(err))
            stats[statName] = 0
        } else {
            stats[statName] = len(keys)
        }
    }

    return stats, nil
}

// Cleanup operations

func (c *SessionCache) CleanupExpiredSessions() error {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    patterns := []string{
        activeSessionPrefix + "*",
        sessionDataPrefix + "*",
        userSessionsPrefix + "*",
        sessionLockPrefix + "*",
    }

    totalCleaned := 0
    for _, pattern := range patterns {
        cursor := uint64(0)
        for {
            keys, nextCursor, err := c.client.Scan(ctx, cursor, pattern, 100)
            if err != nil {
                util.Error("Failed to scan keys for session cleanup",
                    zap.String("pattern", pattern),
                    zap.Error(err))
                break
            }

            // Check TTL for each key
            for _, key := range keys {
                ttl, err := c.client.TTL(ctx, key)
                if err != nil {
                    continue
                }

                // Log keys without proper TTL
                if ttl == -1 {
                    util.Warn("Found session cache key without TTL", zap.String("key", key))
                }
            }

            totalCleaned += len(keys)
            cursor = nextCursor
            if cursor == 0 {
                break
            }
        }
    }

    util.Info("Session cache cleanup completed", zap.Int("keys_checked", totalCleaned))
    return nil
}

// Batch session operations

func (c *SessionCache) InvalidateMultipleSessions(sessionIDs []string) error {
    if len(sessionIDs) == 0 {
        return nil
    }

    ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
    defer cancel()

    pipe := c.client.Pipeline()

    for _, sessionID := range sessionIDs {
        // Remove session data
        sessionDataKey := sessionDataPrefix + sessionID
        pipe.Del(ctx, sessionDataKey)

        // Remove session lock
        sessionLockKey := sessionLockPrefix + sessionID
        pipe.Del(ctx, sessionLockKey)
    }

    _, err := pipe.Exec(ctx)
    if err != nil {
        util.Error("Failed to invalidate multiple sessions",
            zap.Int("session_count", len(sessionIDs)),
            zap.Error(err))
        return fmt.Errorf("failed to invalidate multiple sessions: %w", err)
    }

    util.Info("Multiple sessions invalidated",
        zap.Int("session_count", len(sessionIDs)))

    return nil
}
