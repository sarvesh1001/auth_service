package scylla

import (
    "fmt"
    "time"

    "github.com/gocql/gocql"
    "github.com/google/uuid"
    "go.uber.org/zap"

    "auth-service/internal/model"
    "auth-service/internal/util"
)

type DeviceSessionRepository struct {
    client *ScyllaClient
}

func NewDeviceSessionRepository(client *ScyllaClient, logger *zap.Logger) *DeviceSessionRepository {
    // Using global util logger instead of individual logger
    return &DeviceSessionRepository{
        client: client,
    }
}

func (r *DeviceSessionRepository) CreateDeviceSession(session *model.DeviceSession) error {
    if session.SessionID == "" {
        session.SessionID = uuid.New().String()
    }

    now := time.Now().UTC()
    session.CreatedAt = now
    session.LastAccessed = now

    // Use batch operation to maintain consistency across both tables
    batch := r.client.Session.NewBatch(gocql.LoggedBatch)

    // Insert into main device_sessions table
    batch.Query(r.client.Prepared.CreateDeviceSession.Statement(),
        session.UserID, session.SessionID, session.DeviceID, session.IsActive,
        session.AuthToken, session.CreatedAt, session.LastAccessed, session.RevokedReason)

    // Insert into sessions_by_id table for fast lookups
    batch.Query(r.client.Prepared.CreateSessionByID.Statement(),
        session.SessionID, session.UserID, session.DeviceID, session.IsActive,
        session.AuthToken, session.CreatedAt, session.LastAccessed, session.RevokedReason)

    if err := r.client.ExecuteBatch(batch); err != nil {
        util.Error("Failed to create device session",
            zap.String("user_id", session.UserID),
            zap.String("session_id", session.SessionID),
            zap.String("device_id", session.DeviceID),
            zap.Error(err))
        return fmt.Errorf("failed to create device session: %w", err)
    }

    util.Info("Device session created successfully",
        zap.String("user_id", session.UserID),
        zap.String("session_id", session.SessionID),
        zap.String("device_id", session.DeviceID))

    return nil
}

func (r *DeviceSessionRepository) GetActiveSessionByUserID(userID string) (*model.DeviceSession, error) {
    session := &model.DeviceSession{}

    query := r.client.Prepared.GetActiveSessionByUserID.Bind(userID)

    err := r.client.ScanWithRetry(query,
        &session.UserID, &session.SessionID, &session.DeviceID, &session.IsActive,
        &session.AuthToken, &session.CreatedAt, &session.LastAccessed, &session.RevokedReason)

    if err != nil {
        if err == gocql.ErrNotFound {
            return nil, fmt.Errorf("no active session found for user: %s", userID)
        }
        util.Error("Failed to get active session by user ID",
            zap.String("user_id", userID),
            zap.Error(err))
        return nil, fmt.Errorf("failed to get active session by user ID: %w", err)
    }

    return session, nil
}

func (r *DeviceSessionRepository) GetSessionByID(sessionID string) (*model.DeviceSession, error) {
    session := &model.DeviceSession{}

    query := r.client.Prepared.GetSessionByID.Bind(sessionID)

    err := r.client.ScanWithRetry(query,
        &session.SessionID, &session.UserID, &session.DeviceID, &session.IsActive,
        &session.AuthToken, &session.CreatedAt, &session.LastAccessed, &session.RevokedReason)

    if err != nil {
        if err == gocql.ErrNotFound {
            return nil, fmt.Errorf("session not found: %s", sessionID)
        }
        util.Error("Failed to get session by ID",
            zap.String("session_id", sessionID),
            zap.Error(err))
        return nil, fmt.Errorf("failed to get session by ID: %w", err)
    }

    return session, nil
}

func (r *DeviceSessionRepository) RevokeSessionByUserID(userID string, reason string) error {
    // Use batch operation to maintain consistency across both tables
    batch := r.client.Session.NewBatch(gocql.LoggedBatch)

    // First get all sessions for the user to update sessions_by_id table
    sessions, err := r.ListUserSessions(userID)
    if err != nil {
        return fmt.Errorf("failed to get user sessions for revocation: %w", err)
    }

    // Update device_sessions table
    batch.Query(r.client.Prepared.RevokeSessionByUserID.Statement(), reason, userID)

    // Update sessions_by_id table for each session
    for _, session := range sessions {
        if session.IsActive {
            batch.Query(`UPDATE sessions_by_id SET is_active = false, revoked_reason = ? WHERE session_id = ?`,
                reason, session.SessionID)
        }
    }

    if err := r.client.ExecuteBatch(batch); err != nil {
        util.Error("Failed to revoke sessions by user ID",
            zap.String("user_id", userID),
            zap.String("reason", reason),
            zap.Error(err))
        return fmt.Errorf("failed to revoke sessions by user ID: %w", err)
    }

    util.Info("All sessions revoked for user",
        zap.String("user_id", userID),
        zap.String("reason", reason))

    return nil
}

func (r *DeviceSessionRepository) RevokeSessionByDeviceID(deviceID string, reason string) error {
    // First find all sessions for this device
    iter := r.client.Session.Query(`
        SELECT user_id, session_id FROM device_sessions 
        WHERE device_id = ? AND is_active = true ALLOW FILTERING`, deviceID).Iter()

    type sessionInfo struct {
        UserID    string
        SessionID string
    }

    var sessions []sessionInfo
    var userID, sessionID string

    for iter.Scan(&userID, &sessionID) {
        sessions = append(sessions, sessionInfo{UserID: userID, SessionID: sessionID})
    }

    if err := iter.Close(); err != nil {
        return fmt.Errorf("failed to find sessions for device: %w", err)
    }

    if len(sessions) == 0 {
        return fmt.Errorf("no active sessions found for device: %s", deviceID)
    }

    // Use batch operation to revoke all sessions for this device
    batch := r.client.Session.NewBatch(gocql.LoggedBatch)

    for _, session := range sessions {
        // Update device_sessions table
        batch.Query(`UPDATE device_sessions SET is_active = false, revoked_reason = ? 
            WHERE user_id = ? AND session_id = ?`,
            reason, session.UserID, session.SessionID)

        // Update sessions_by_id table
        batch.Query(`UPDATE sessions_by_id SET is_active = false, revoked_reason = ? 
            WHERE session_id = ?`,
            reason, session.SessionID)
    }

    if err := r.client.ExecuteBatch(batch); err != nil {
        util.Error("Failed to revoke sessions by device ID",
            zap.String("device_id", deviceID),
            zap.String("reason", reason),
            zap.Error(err))
        return fmt.Errorf("failed to revoke sessions by device ID: %w", err)
    }

    util.Info("All sessions revoked for device",
        zap.String("device_id", deviceID),
        zap.String("reason", reason),
        zap.Int("sessions_revoked", len(sessions)))

    return nil
}

func (r *DeviceSessionRepository) UpdateSessionAccessTime(sessionID string) error {
    now := time.Now().UTC()

    // First get the session to find user_id (needed for partition key in device_sessions)
    session, err := r.GetSessionByID(sessionID)
    if err != nil {
        return err
    }

    // Use batch operation to update both tables
    batch := r.client.Session.NewBatch(gocql.UnloggedBatch)

    // Update device_sessions table
    batch.Query(r.client.Prepared.UpdateSessionAccessTime.Statement(),
        now, session.UserID, sessionID)

    // Update sessions_by_id table
    batch.Query(`UPDATE sessions_by_id SET last_accessed = ? WHERE session_id = ?`,
        now, sessionID)

    if err := r.client.ExecuteBatch(batch); err != nil {
        util.Error("Failed to update session access time",
            zap.String("session_id", sessionID),
            zap.Error(err))
        return fmt.Errorf("failed to update session access time: %w", err)
    }

    return nil
}

func (r *DeviceSessionRepository) ListUserSessions(userID string) ([]*model.DeviceSession, error) {
    var sessions []*model.DeviceSession

    query := r.client.Prepared.ListUserSessions.Bind(userID)
    iter := query.Iter()

    var session model.DeviceSession
    for iter.Scan(&session.UserID, &session.SessionID, &session.DeviceID, &session.IsActive,
        &session.AuthToken, &session.CreatedAt, &session.LastAccessed, &session.RevokedReason) {
        sessions = append(sessions, &session)
    }

    if err := iter.Close(); err != nil {
        util.Error("Failed to list user sessions",
            zap.String("user_id", userID),
            zap.Error(err))
        return nil, fmt.Errorf("failed to list user sessions: %w", err)
    }

    return sessions, nil
}

// Additional helper methods for session management

func (r *DeviceSessionRepository) IsSessionActive(sessionID string) (bool, error) {
    var isActive bool
    query := r.client.Session.Query(`SELECT is_active FROM sessions_by_id WHERE session_id = ?`, sessionID)

    err := query.Scan(&isActive)
    if err != nil {
        if err == gocql.ErrNotFound {
            return false, fmt.Errorf("session not found: %s", sessionID)
        }
        return false, fmt.Errorf("failed to check session status: %w", err)
    }

    return isActive, nil
}

func (r *DeviceSessionRepository) GetUserActiveSessionCount(userID string) (int, error) {
    var count int
    query := r.client.Session.Query(`
        SELECT COUNT(*) FROM device_sessions 
        WHERE user_id = ? AND is_active = true`, userID)

    err := query.Scan(&count)
    if err != nil {
        return 0, fmt.Errorf("failed to get active session count: %w", err)
    }

    return count, nil
}

func (r *DeviceSessionRepository) RevokeSpecificSession(sessionID string, reason string) error {
    // Get session details first
    session, err := r.GetSessionByID(sessionID)
    if err != nil {
        return err
    }

    // Use batch operation to update both tables
    batch := r.client.Session.NewBatch(gocql.LoggedBatch)

    // Update device_sessions table
    batch.Query(`UPDATE device_sessions SET is_active = false, revoked_reason = ? 
        WHERE user_id = ? AND session_id = ?`,
        reason, session.UserID, sessionID)

    // Update sessions_by_id table
    batch.Query(`UPDATE sessions_by_id SET is_active = false, revoked_reason = ? 
        WHERE session_id = ?`,
        reason, sessionID)

    if err := r.client.ExecuteBatch(batch); err != nil {
        util.Error("Failed to revoke specific session",
            zap.String("session_id", sessionID),
            zap.String("reason", reason),
            zap.Error(err))
        return fmt.Errorf("failed to revoke session: %w", err)
    }

    util.Info("Session revoked successfully",
        zap.String("session_id", sessionID),
        zap.String("user_id", session.UserID),
        zap.String("reason", reason))

    return nil
}

func (r *DeviceSessionRepository) CleanupInactiveSessions(olderThan time.Duration) error {
    cutoffTime := time.Now().UTC().Add(-olderThan)

    // Get old inactive sessions
    iter := r.client.Session.Query(`
        SELECT user_id, session_id FROM device_sessions 
        WHERE last_accessed < ? AND is_active = false ALLOW FILTERING`, cutoffTime).Iter()

    type sessionInfo struct {
        UserID    string
        SessionID string
    }

    var sessionsToDelete []sessionInfo
    var userID, sessionID string

    for iter.Scan(&userID, &sessionID) {
        sessionsToDelete = append(sessionsToDelete, sessionInfo{UserID: userID, SessionID: sessionID})
    }

    if err := iter.Close(); err != nil {
        return fmt.Errorf("failed to query old sessions: %w", err)
    }

    // Delete sessions in batches
    deletedCount := 0
    batchSize := 0
    batch := r.client.Session.NewBatch(gocql.UnloggedBatch)

    for _, session := range sessionsToDelete {
        // Delete from both tables
        batch.Query(`DELETE FROM device_sessions WHERE user_id = ? AND session_id = ?`,
            session.UserID, session.SessionID)
        batch.Query(`DELETE FROM sessions_by_id WHERE session_id = ?`,
            session.SessionID)

        batchSize += 2 // Two queries per session

        // Execute batch when it reaches 100 operations
        if batchSize >= 100 {
            if err := r.client.ExecuteBatch(batch); err != nil {
                util.Error("Failed to execute batch delete for old sessions", zap.Error(err))
                return fmt.Errorf("failed to cleanup old sessions: %w", err)
            }
            deletedCount += batchSize / 2
            batch = r.client.Session.NewBatch(gocql.UnloggedBatch)
            batchSize = 0
        }
    }

    // Execute remaining batch
    if batchSize > 0 {
        if err := r.client.ExecuteBatch(batch); err != nil {
            util.Error("Failed to execute final batch delete for old sessions", zap.Error(err))
            return fmt.Errorf("failed to cleanup old sessions: %w", err)
        }
        deletedCount += batchSize / 2
    }

    util.Info("Old sessions cleaned up successfully",
        zap.Int("deleted_count", deletedCount),
        zap.Duration("older_than", olderThan))

    return nil
}

func (r *DeviceSessionRepository) GetSessionsByDevice(deviceID string) ([]*model.DeviceSession, error) {
    var sessions []*model.DeviceSession

    iter := r.client.Session.Query(`
        SELECT user_id, session_id, device_id, is_active, auth_token, 
               created_at, last_accessed, revoked_reason
        FROM device_sessions WHERE device_id = ? ALLOW FILTERING`, deviceID).Iter()

    var session model.DeviceSession
    for iter.Scan(&session.UserID, &session.SessionID, &session.DeviceID, &session.IsActive,
        &session.AuthToken, &session.CreatedAt, &session.LastAccessed, &session.RevokedReason) {
        sessions = append(sessions, &session)
    }

    if err := iter.Close(); err != nil {
        util.Error("Failed to get sessions by device",
            zap.String("device_id", deviceID),
            zap.Error(err))
        return nil, fmt.Errorf("failed to get sessions by device: %w", err)
    }

    return sessions, nil
}

func (r *DeviceSessionRepository) GetSessionStats() (map[string]interface{}, error) {
    stats := make(map[string]interface{})

    // Get total sessions count
    var totalSessions int64
    if err := r.client.Session.Query(`SELECT COUNT(*) FROM sessions_by_id`).Scan(&totalSessions); err != nil {
        util.Warn("Failed to get total sessions count", zap.Error(err))
    } else {
        stats["total_sessions"] = totalSessions
    }

    // Get active sessions count
    var activeSessions int64
    if err := r.client.Session.Query(`SELECT COUNT(*) FROM sessions_by_id WHERE is_active = true ALLOW FILTERING`).Scan(&activeSessions); err != nil {
        util.Warn("Failed to get active sessions count", zap.Error(err))
    } else {
        stats["active_sessions"] = activeSessions
    }

    return stats, nil
}
