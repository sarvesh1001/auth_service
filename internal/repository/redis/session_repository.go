// internal/repository/redis/session_repository.go - UPDATED WITH ACCESS TOKEN SUPPORT
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
	// Session keys
	sessionKeyPrefix       = "session:user:"
	sessionTokenKeyPrefix  = "session:token:"
	sessionDeviceKeyPrefix = "session:device:"
	sessionCountKeyPrefix  = "session:count:"
	sessionTypeKeyPrefix   = "session:type:"
	adminSessionKeyPrefix  = "admin:session:"
	
	// ✅ JWT Refresh token keys
	refreshTokenKeyPrefix = "refresh:"
	userRefreshSetPrefix  = "user_refreshs:"
	
	// ✅ NEW: Access token keys
	accessTokenKeyPrefix = "access_token:"
	
	// TTLs
	sessionTTL      = 30 * 24 * time.Hour
	adminSessionTTL = 7 * 24 * time.Hour
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

// ============================================================================
// CORE SESSION OPERATIONS
// ============================================================================

// CreateSession creates a new session
func (r *SessionRepositoryImpl) CreateSession(ctx context.Context, session *models.ActiveSession) error {
	startTime := time.Now()

	// Serialize session
	sessionData, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to serialize session: %w", err)
	}

	// Get TTL based on session type
	ttl := sessionTTL // Default 30 days
	if session.SessionType == "admin" {
		ttl = adminSessionTTL // 7 days for admin
	}

	pipe := r.client.Pipeline()

	// Store session by user ID
	userKey := fmt.Sprintf("%s%s", sessionKeyPrefix, session.UserID)
	pipe.Set(ctx, userKey, sessionData, ttl)

	// Store session by token for quick lookup
	tokenKey := fmt.Sprintf("%s%s", sessionTokenKeyPrefix, session.SessionToken)
	pipe.Set(ctx, tokenKey, session.UserID, ttl)

	// Store session type for quick lookup
	typeKey := fmt.Sprintf("%s%s", sessionTypeKeyPrefix, session.SessionToken)
	pipe.Set(ctx, typeKey, session.SessionType, ttl)

	// Add to device sessions set
	if session.DeviceID != "" {
		deviceKey := fmt.Sprintf("%s%s", sessionDeviceKeyPrefix, session.DeviceID)
		pipe.SAdd(ctx, deviceKey, session.UserID)
		pipe.Expire(ctx, deviceKey, ttl)
	}

	// Increment active sessions count
	countKey := fmt.Sprintf("%s%s", sessionCountKeyPrefix, session.UserID)
	pipe.Incr(ctx, countKey)
	pipe.Expire(ctx, countKey, ttl)

	// Store in admin sessions index if admin session
	if session.SessionType == "admin" {
		adminKey := fmt.Sprintf("%s%s", adminSessionKeyPrefix, session.UserID)
		pipe.SAdd(ctx, adminKey, session.SessionToken)
		pipe.Expire(ctx, adminKey, adminSessionTTL)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	r.logger.Debug("Session created",
		util.String("user_id", session.UserID),
		util.String("device_id", session.DeviceID),
		util.String("session_type", session.SessionType),
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

	// Use appropriate TTL based on session type
	ttl := sessionTTL
	if session.SessionType == "admin" {
		ttl = adminSessionTTL
	}

	key := fmt.Sprintf("%s%s", sessionKeyPrefix, userID.String())
	if err := r.client.Set(ctx, key, sessionData, ttl).Err(); err != nil {
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

	// Delete session type
	typeKey := fmt.Sprintf("%s%s", sessionTypeKeyPrefix, session.SessionToken)
	pipe.Del(ctx, typeKey)

	// Remove from device sessions
	if session.DeviceID != "" {
		deviceKey := fmt.Sprintf("%s%s", sessionDeviceKeyPrefix, session.DeviceID)
		pipe.SRem(ctx, deviceKey, userID.String())
	}

	// Decrement active sessions count
	countKey := fmt.Sprintf("%s%s", sessionCountKeyPrefix, userID.String())
	pipe.Decr(ctx, countKey)

	// Remove from admin sessions if admin session
	if session.SessionType == "admin" {
		adminKey := fmt.Sprintf("%s%s", adminSessionKeyPrefix, userID.String())
		pipe.SRem(ctx, adminKey, session.SessionToken)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to invalidate session: %w", err)
	}

	r.logger.Info("Session invalidated",
		util.String("user_id", userID.String()),
		util.String("session_type", session.SessionType),
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

	// Delete old type mapping
	oldTypeKey := fmt.Sprintf("%s%s", sessionTypeKeyPrefix, session.SessionToken)
	r.client.Del(ctx, oldTypeKey)

	// Update session
	session.SessionToken = newToken
	session.ExpiresAt = expiresAt

	sessionData, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to serialize session: %w", err)
	}

	// Get appropriate TTL
	ttl := sessionTTL
	if session.SessionType == "admin" {
		ttl = adminSessionTTL
	}

	pipe := r.client.Pipeline()

	// Update session by user ID
	userKey := fmt.Sprintf("%s%s", sessionKeyPrefix, userID.String())
	pipe.Set(ctx, userKey, sessionData, ttl)

	// Create new token mapping
	newTokenKey := fmt.Sprintf("%s%s", sessionTokenKeyPrefix, newToken)
	pipe.Set(ctx, newTokenKey, userID.String(), ttl)

	// Create new type mapping
	newTypeKey := fmt.Sprintf("%s%s", sessionTypeKeyPrefix, newToken)
	pipe.Set(ctx, newTypeKey, session.SessionType, ttl)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to refresh session: %w", err)
	}

	r.logger.Info("Session refreshed",
		util.String("user_id", userID.String()),
		util.String("session_type", session.SessionType),
	)

	return nil
}

// ============================================================================
// BULK OPERATIONS
// ============================================================================

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

// ============================================================================
// DEVICE MANAGEMENT
// ============================================================================

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

// ============================================================================
// ADMIN SESSION SUPPORT
// ============================================================================

// GetSessionType retrieves the session type quickly without full session
func (r *SessionRepositoryImpl) GetSessionType(ctx context.Context, sessionToken string) (string, error) {
	typeKey := fmt.Sprintf("%s%s", sessionTypeKeyPrefix, sessionToken)
	sessionType, err := r.client.Get(ctx, typeKey).Result()
	if err != nil {
		if err == redis.Nil {
			return "", fmt.Errorf("session type not found for token")
		}
		return "", fmt.Errorf("failed to get session type: %w", err)
	}
	return sessionType, nil
}

// IsAdminSession checks if a token is for an admin session
func (r *SessionRepositoryImpl) IsAdminSession(ctx context.Context, sessionToken string) (bool, error) {
	sessionType, err := r.GetSessionType(ctx, sessionToken)
	if err != nil {
		return false, err
	}
	return sessionType == "admin", nil
}

// GetAdminSessions retrieves all admin sessions for a user
func (r *SessionRepositoryImpl) GetAdminSessions(ctx context.Context, userID uuid.UUID) ([]*models.ActiveSession, error) {
	adminKey := fmt.Sprintf("%s%s", adminSessionKeyPrefix, userID.String())

	tokens, err := r.client.SMembers(ctx, adminKey).Result()
	if err != nil {
		if err == redis.Nil {
			return []*models.ActiveSession{}, nil
		}
		return nil, fmt.Errorf("failed to get admin sessions: %w", err)
	}

	sessions := make([]*models.ActiveSession, 0, len(tokens))
	for _, token := range tokens {
		session, err := r.GetSessionByToken(ctx, token)
		if err != nil {
			continue
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}

// InvalidateAdminSessions invalidates all admin sessions for a user
func (r *SessionRepositoryImpl) InvalidateAdminSessions(ctx context.Context, userID uuid.UUID) error {
	sessions, err := r.GetAdminSessions(ctx, userID)
	if err != nil {
		return err
	}

	for _, session := range sessions {
		r.InvalidateSessionByToken(ctx, session.SessionToken)
	}

	r.logger.Info("Admin sessions invalidated for user",
		util.String("user_id", userID.String()),
		util.Int("count", len(sessions)),
	)

	return nil
}

// GetActiveAdminSessionsCount gets count of admin sessions for a user
func (r *SessionRepositoryImpl) GetActiveAdminSessionsCount(ctx context.Context, userID uuid.UUID) (int, error) {
	adminKey := fmt.Sprintf("%s%s", adminSessionKeyPrefix, userID.String())

	count, err := r.client.SCard(ctx, adminKey).Result()
	if err != nil {
		if err == redis.Nil {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to get admin session count: %w", err)
	}

	return int(count), nil
}

// ============================================================================
// ✅ JWT REFRESH TOKEN OPERATIONS
// ============================================================================

// StoreRefreshToken stores refresh token in Redis
func (r *SessionRepositoryImpl) StoreRefreshToken(ctx context.Context, data *models.RefreshTokenData) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal refresh token: %w", err)
	}

	refreshKey := fmt.Sprintf("%s%s", refreshTokenKeyPrefix, data.RefreshID)
	ttl := time.Until(data.ExpiresAt)

	pipe := r.client.Pipeline()

	// Store refresh token data
	pipe.Set(ctx, refreshKey, jsonData, ttl)

	// Add to user's refresh token set (for session listing / device revocation)
	userSetKey := fmt.Sprintf("%s%s", userRefreshSetPrefix, data.UserID)
	pipe.SAdd(ctx, userSetKey, data.RefreshID)
	pipe.Expire(ctx, userSetKey, ttl)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to store refresh token: %w", err)
	}

	r.logger.Info("Refresh token stored",
		util.String("user_id", data.UserID),
		util.String("session_type", data.SessionType),
	)

	return nil
}

// GetRefreshToken retrieves refresh token from Redis
func (r *SessionRepositoryImpl) GetRefreshToken(ctx context.Context, refreshID string) (*models.RefreshTokenData, error) {
	refreshKey := fmt.Sprintf("%s%s", refreshTokenKeyPrefix, refreshID)

	data, err := r.client.Get(ctx, refreshKey).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("refresh token not found")
		}
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	var refreshData models.RefreshTokenData
	if err := json.Unmarshal(data, &refreshData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal refresh token: %w", err)
	}

	// Update last used time
	refreshData.LastUsed = time.Now().UTC()
	updatedData, _ := json.Marshal(refreshData)
	r.client.Set(ctx, refreshKey, updatedData, time.Until(refreshData.ExpiresAt))

	return &refreshData, nil
}

// DeleteRefreshToken deletes refresh token (logout/rotation)
func (r *SessionRepositoryImpl) DeleteRefreshToken(ctx context.Context, refreshID string) error {
	refreshKey := fmt.Sprintf("%s%s", refreshTokenKeyPrefix, refreshID)

	// Get token data to remove from user set
	data, err := r.GetRefreshToken(ctx, refreshID)
	if err != nil {
		// Token doesn't exist, that's fine
		return nil
	}

	pipe := r.client.Pipeline()

	// Delete refresh token
	pipe.Del(ctx, refreshKey)

	// Remove from user's refresh set
	userSetKey := fmt.Sprintf("%s%s", userRefreshSetPrefix, data.UserID)
	pipe.SRem(ctx, userSetKey, refreshID)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	return nil
}

// GetUserRefreshTokens gets all refresh tokens for a user (for logout all devices)
func (r *SessionRepositoryImpl) GetUserRefreshTokens(ctx context.Context, userID string) ([]string, error) {
	userSetKey := fmt.Sprintf("%s%s", userRefreshSetPrefix, userID)

	tokens, err := r.client.SMembers(ctx, userSetKey).Result()
	if err != nil {
		if err == redis.Nil {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to get user refresh tokens: %w", err)
	}

	return tokens, nil
}

// RevokeAllUserRefreshTokens revokes all refresh tokens for a user
func (r *SessionRepositoryImpl) RevokeAllUserRefreshTokens(ctx context.Context, userID string) error {
	tokens, err := r.GetUserRefreshTokens(ctx, userID)
	if err != nil {
		return err
	}

	for _, token := range tokens {
		r.DeleteRefreshToken(ctx, token)
	}

	r.logger.Info("All user refresh tokens revoked",
		util.String("user_id", userID),
		util.Int("count", len(tokens)),
	)

	return nil
}

// ============================================================================
// ✅ NEW: JWT ACCESS TOKEN OPERATIONS
// ============================================================================

// StoreAccessToken stores access token in Redis
func (r *SessionRepositoryImpl) StoreAccessToken(ctx context.Context, data *models.AccessTokenData) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal access token: %w", err)
	}

	accessKey := fmt.Sprintf("%s%s", accessTokenKeyPrefix, data.JTI)
	ttl := time.Until(data.ExpiresAt)

	if err := r.client.Set(ctx, accessKey, jsonData, ttl).Err(); err != nil {
		return fmt.Errorf("failed to store access token: %w", err)
	}

	r.logger.Debug("Access token stored in Redis",
		util.String("jti", data.JTI),
		util.String("user_id", data.UserID),
		util.String("session_type", data.SessionType),
		util.Duration("ttl", ttl),
	)

	return nil
}

// GetAccessToken retrieves access token from Redis
func (r *SessionRepositoryImpl) GetAccessToken(ctx context.Context, jti string) (*models.AccessTokenData, error) {
	accessKey := fmt.Sprintf("%s%s", accessTokenKeyPrefix, jti)

	data, err := r.client.Get(ctx, accessKey).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("access token not found")
		}
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	var accessData models.AccessTokenData
	if err := json.Unmarshal(data, &accessData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal access token: %w", err)
	}

	return &accessData, nil
}

// DeleteAccessToken deletes access token (logout/token revocation)
func (r *SessionRepositoryImpl) DeleteAccessToken(ctx context.Context, jti string) error {
	accessKey := fmt.Sprintf("%s%s", accessTokenKeyPrefix, jti)

	if err := r.client.Del(ctx, accessKey).Err(); err != nil {
		return fmt.Errorf("failed to delete access token: %w", err)
	}

	r.logger.Debug("Access token deleted from Redis",
		util.String("jti", jti),
	)

	return nil
}

// ============================================================================
// HEALTH MONITORING
// ============================================================================

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

	// Count admin sessions
	adminIter := r.client.Scan(ctx, 0, adminSessionKeyPrefix+"*", 1000).Iterator()
	adminCount := 0
	for adminIter.Next(ctx) {
		adminCount++
	}

	// Count refresh tokens
	refreshIter := r.client.Scan(ctx, 0, refreshTokenKeyPrefix+"*", 1000).Iterator()
	refreshCount := 0
	for refreshIter.Next(ctx) {
		refreshCount++
	}

	// ✅ NEW: Count access tokens
	accessIter := r.client.Scan(ctx, 0, accessTokenKeyPrefix+"*", 1000).Iterator()
	accessCount := 0
	for accessIter.Next(ctx) {
		accessCount++
	}

	stats["active_sessions"] = count
	stats["active_admin_sessions"] = adminCount
	stats["active_refresh_tokens"] = refreshCount
	stats["active_access_tokens"] = accessCount // ✅ NEW
	stats["session_ttl_hours"] = int(sessionTTL.Hours())
	stats["admin_session_ttl_hours"] = int(adminSessionTTL.Hours())

	return stats, nil
}

// // internal/repository/redis/session_repository.go - UPDATED WITH JWT REFRESH TOKEN SUPPORT
// package redis

// import (
// 	"context"
// 	"encoding/json"
// 	"fmt"
// 	"net"
// 	"strings"
// 	"time"

// 	"auth-service/internal/models"
// 	"auth-service/internal/util"

// 	"github.com/google/uuid"
// 	"github.com/redis/go-redis/v9"
// 	"go.uber.org/zap"
// )

// const (
// 	// Session keys
// 	sessionKeyPrefix       = "session:user:"
// 	sessionTokenKeyPrefix  = "session:token:"
// 	sessionDeviceKeyPrefix = "session:device:"
// 	sessionCountKeyPrefix  = "session:count:"
// 	sessionTypeKeyPrefix   = "session:type:"
// 	adminSessionKeyPrefix  = "admin:session:"
	
// 	// ✅ NEW: Refresh token keys
// 	refreshTokenKeyPrefix = "refresh:"
// 	userRefreshSetPrefix  = "user_refreshs:"
	
// 	// TTLs
// 	sessionTTL      = 30 * 24 * time.Hour
// 	adminSessionTTL = 7 * 24 * time.Hour
// )

// type SessionRepositoryImpl struct {
// 	client *redis.Client
// 	logger *zap.Logger
// }

// // NewSessionRepository creates a new session repository
// func NewSessionRepository(client *redis.Client, logger *zap.Logger) SessionRepository {
// 	return &SessionRepositoryImpl{
// 		client: client,
// 		logger: logger,
// 	}
// }

// // ============================================================================
// // CORE SESSION OPERATIONS
// // ============================================================================

// // CreateSession creates a new session
// func (r *SessionRepositoryImpl) CreateSession(ctx context.Context, session *models.ActiveSession) error {
// 	startTime := time.Now()

// 	// Serialize session
// 	sessionData, err := json.Marshal(session)
// 	if err != nil {
// 		return fmt.Errorf("failed to serialize session: %w", err)
// 	}

// 	// Get TTL based on session type
// 	ttl := sessionTTL // Default 30 days
// 	if session.SessionType == "admin" {
// 		ttl = adminSessionTTL // 7 days for admin
// 	}

// 	pipe := r.client.Pipeline()

// 	// Store session by user ID
// 	userKey := fmt.Sprintf("%s%s", sessionKeyPrefix, session.UserID)
// 	pipe.Set(ctx, userKey, sessionData, ttl)

// 	// Store session by token for quick lookup
// 	tokenKey := fmt.Sprintf("%s%s", sessionTokenKeyPrefix, session.SessionToken)
// 	pipe.Set(ctx, tokenKey, session.UserID, ttl)

// 	// Store session type for quick lookup
// 	typeKey := fmt.Sprintf("%s%s", sessionTypeKeyPrefix, session.SessionToken)
// 	pipe.Set(ctx, typeKey, session.SessionType, ttl)

// 	// Add to device sessions set
// 	if session.DeviceID != "" {
// 		deviceKey := fmt.Sprintf("%s%s", sessionDeviceKeyPrefix, session.DeviceID)
// 		pipe.SAdd(ctx, deviceKey, session.UserID)
// 		pipe.Expire(ctx, deviceKey, ttl)
// 	}

// 	// Increment active sessions count
// 	countKey := fmt.Sprintf("%s%s", sessionCountKeyPrefix, session.UserID)
// 	pipe.Incr(ctx, countKey)
// 	pipe.Expire(ctx, countKey, ttl)

// 	// Store in admin sessions index if admin session
// 	if session.SessionType == "admin" {
// 		adminKey := fmt.Sprintf("%s%s", adminSessionKeyPrefix, session.UserID)
// 		pipe.SAdd(ctx, adminKey, session.SessionToken)
// 		pipe.Expire(ctx, adminKey, adminSessionTTL)
// 	}

// 	if _, err := pipe.Exec(ctx); err != nil {
// 		return fmt.Errorf("failed to create session: %w", err)
// 	}

// 	r.logger.Debug("Session created",
// 		util.String("user_id", session.UserID),
// 		util.String("device_id", session.DeviceID),
// 		util.String("session_type", session.SessionType),
// 		util.Duration("duration", time.Since(startTime)),
// 	)

// 	return nil
// }

// // GetSessionByUserID retrieves a session by user ID
// func (r *SessionRepositoryImpl) GetSessionByUserID(ctx context.Context, userID uuid.UUID) (*models.ActiveSession, error) {
// 	key := fmt.Sprintf("%s%s", sessionKeyPrefix, userID.String())

// 	data, err := r.client.Get(ctx, key).Bytes()
// 	if err != nil {
// 		if err == redis.Nil {
// 			return nil, fmt.Errorf("session not found for user: %s", userID)
// 		}
// 		return nil, fmt.Errorf("failed to get session: %w", err)
// 	}

// 	var session models.ActiveSession
// 	if err := json.Unmarshal(data, &session); err != nil {
// 		return nil, fmt.Errorf("failed to deserialize session: %w", err)
// 	}

// 	// Check if expired
// 	if time.Now().After(session.ExpiresAt) {
// 		r.InvalidateSession(ctx, userID)
// 		return nil, fmt.Errorf("session expired")
// 	}

// 	return &session, nil
// }

// // GetSessionByToken retrieves a session by session token
// func (r *SessionRepositoryImpl) GetSessionByToken(ctx context.Context, sessionToken string) (*models.ActiveSession, error) {
// 	// First get user ID from token
// 	tokenKey := fmt.Sprintf("%s%s", sessionTokenKeyPrefix, sessionToken)
// 	userID, err := r.client.Get(ctx, tokenKey).Result()
// 	if err != nil {
// 		if err == redis.Nil {
// 			return nil, fmt.Errorf("session not found for token")
// 		}
// 		return nil, fmt.Errorf("failed to get session token: %w", err)
// 	}

// 	// Then get full session
// 	uid, err := uuid.Parse(userID)
// 	if err != nil {
// 		return nil, fmt.Errorf("invalid user ID in session: %w", err)
// 	}

// 	return r.GetSessionByUserID(ctx, uid)
// }

// // UpdateSessionActivity updates session activity timestamp
// func (r *SessionRepositoryImpl) UpdateSessionActivity(ctx context.Context, userID uuid.UUID, lastActivity time.Time, ipAddress net.IP) error {
// 	session, err := r.GetSessionByUserID(ctx, userID)
// 	if err != nil {
// 		return err
// 	}

// 	session.LastActivity = lastActivity
// 	session.IPAddress = ipAddress

// 	sessionData, err := json.Marshal(session)
// 	if err != nil {
// 		return fmt.Errorf("failed to serialize session: %w", err)
// 	}

// 	// Use appropriate TTL based on session type
// 	ttl := sessionTTL
// 	if session.SessionType == "admin" {
// 		ttl = adminSessionTTL
// 	}

// 	key := fmt.Sprintf("%s%s", sessionKeyPrefix, userID.String())
// 	if err := r.client.Set(ctx, key, sessionData, ttl).Err(); err != nil {
// 		return fmt.Errorf("failed to update session activity: %w", err)
// 	}

// 	return nil
// }

// // InvalidateSession invalidates a session by user ID
// func (r *SessionRepositoryImpl) InvalidateSession(ctx context.Context, userID uuid.UUID) error {
// 	session, err := r.GetSessionByUserID(ctx, userID)
// 	if err != nil {
// 		// Session might not exist, which is okay
// 		return nil
// 	}

// 	pipe := r.client.Pipeline()

// 	// Delete session by user ID
// 	userKey := fmt.Sprintf("%s%s", sessionKeyPrefix, userID.String())
// 	pipe.Del(ctx, userKey)

// 	// Delete session by token
// 	tokenKey := fmt.Sprintf("%s%s", sessionTokenKeyPrefix, session.SessionToken)
// 	pipe.Del(ctx, tokenKey)

// 	// Delete session type
// 	typeKey := fmt.Sprintf("%s%s", sessionTypeKeyPrefix, session.SessionToken)
// 	pipe.Del(ctx, typeKey)

// 	// Remove from device sessions
// 	if session.DeviceID != "" {
// 		deviceKey := fmt.Sprintf("%s%s", sessionDeviceKeyPrefix, session.DeviceID)
// 		pipe.SRem(ctx, deviceKey, userID.String())
// 	}

// 	// Decrement active sessions count
// 	countKey := fmt.Sprintf("%s%s", sessionCountKeyPrefix, userID.String())
// 	pipe.Decr(ctx, countKey)

// 	// Remove from admin sessions if admin session
// 	if session.SessionType == "admin" {
// 		adminKey := fmt.Sprintf("%s%s", adminSessionKeyPrefix, userID.String())
// 		pipe.SRem(ctx, adminKey, session.SessionToken)
// 	}

// 	if _, err := pipe.Exec(ctx); err != nil {
// 		return fmt.Errorf("failed to invalidate session: %w", err)
// 	}

// 	r.logger.Info("Session invalidated",
// 		util.String("user_id", userID.String()),
// 		util.String("session_type", session.SessionType),
// 	)

// 	return nil
// }

// // InvalidateSessionByToken invalidates a session by session token
// func (r *SessionRepositoryImpl) InvalidateSessionByToken(ctx context.Context, sessionToken string) error {
// 	tokenKey := fmt.Sprintf("%s%s", sessionTokenKeyPrefix, sessionToken)
// 	userID, err := r.client.Get(ctx, tokenKey).Result()
// 	if err != nil {
// 		if err == redis.Nil {
// 			return nil // Session doesn't exist
// 		}
// 		return fmt.Errorf("failed to get session token: %w", err)
// 	}

// 	uid, err := uuid.Parse(userID)
// 	if err != nil {
// 		return fmt.Errorf("invalid user ID: %w", err)
// 	}

// 	return r.InvalidateSession(ctx, uid)
// }

// // RefreshSession refreshes a session with a new token and expiry
// func (r *SessionRepositoryImpl) RefreshSession(ctx context.Context, userID uuid.UUID, newToken string, expiresAt time.Time) error {
// 	session, err := r.GetSessionByUserID(ctx, userID)
// 	if err != nil {
// 		return err
// 	}

// 	// Delete old token
// 	oldTokenKey := fmt.Sprintf("%s%s", sessionTokenKeyPrefix, session.SessionToken)
// 	r.client.Del(ctx, oldTokenKey)

// 	// Delete old type mapping
// 	oldTypeKey := fmt.Sprintf("%s%s", sessionTypeKeyPrefix, session.SessionToken)
// 	r.client.Del(ctx, oldTypeKey)

// 	// Update session
// 	session.SessionToken = newToken
// 	session.ExpiresAt = expiresAt

// 	sessionData, err := json.Marshal(session)
// 	if err != nil {
// 		return fmt.Errorf("failed to serialize session: %w", err)
// 	}

// 	// Get appropriate TTL
// 	ttl := sessionTTL
// 	if session.SessionType == "admin" {
// 		ttl = adminSessionTTL
// 	}

// 	pipe := r.client.Pipeline()

// 	// Update session by user ID
// 	userKey := fmt.Sprintf("%s%s", sessionKeyPrefix, userID.String())
// 	pipe.Set(ctx, userKey, sessionData, ttl)

// 	// Create new token mapping
// 	newTokenKey := fmt.Sprintf("%s%s", sessionTokenKeyPrefix, newToken)
// 	pipe.Set(ctx, newTokenKey, userID.String(), ttl)

// 	// Create new type mapping
// 	newTypeKey := fmt.Sprintf("%s%s", sessionTypeKeyPrefix, newToken)
// 	pipe.Set(ctx, newTypeKey, session.SessionType, ttl)

// 	if _, err := pipe.Exec(ctx); err != nil {
// 		return fmt.Errorf("failed to refresh session: %w", err)
// 	}

// 	r.logger.Info("Session refreshed",
// 		util.String("user_id", userID.String()),
// 		util.String("session_type", session.SessionType),
// 	)

// 	return nil
// }

// // ============================================================================
// // BULK OPERATIONS
// // ============================================================================

// // InvalidateSessionsBatch invalidates multiple sessions
// func (r *SessionRepositoryImpl) InvalidateSessionsBatch(ctx context.Context, userIDs []uuid.UUID) error {
// 	if len(userIDs) == 0 {
// 		return nil
// 	}

// 	for _, userID := range userIDs {
// 		if err := r.InvalidateSession(ctx, userID); err != nil {
// 			r.logger.Warn("Failed to invalidate session in batch",
// 				util.ErrorField(err),
// 				util.String("user_id", userID.String()),
// 			)
// 		}
// 	}

// 	r.logger.Info("Batch session invalidation completed",
// 		util.Int("count", len(userIDs)),
// 	)

// 	return nil
// }

// // GetSessionsBatch retrieves multiple sessions
// func (r *SessionRepositoryImpl) GetSessionsBatch(ctx context.Context, userIDs []uuid.UUID) ([]*models.ActiveSession, error) {
// 	if len(userIDs) == 0 {
// 		return []*models.ActiveSession{}, nil
// 	}

// 	sessions := make([]*models.ActiveSession, 0, len(userIDs))

// 	for _, userID := range userIDs {
// 		session, err := r.GetSessionByUserID(ctx, userID)
// 		if err != nil {
// 			r.logger.Debug("Session not found in batch",
// 				util.String("user_id", userID.String()),
// 			)
// 			continue
// 		}
// 		sessions = append(sessions, session)
// 	}

// 	return sessions, nil
// }

// // CleanupExpiredSessions cleans up expired sessions (Redis TTL handles this automatically)
// func (r *SessionRepositoryImpl) CleanupExpiredSessions(ctx context.Context, batchSize int) (int, error) {
// 	// Redis TTL handles automatic cleanup, but we can scan for any orphaned keys
// 	cleaned := 0

// 	// Scan for session keys
// 	iter := r.client.Scan(ctx, 0, sessionKeyPrefix+"*", int64(batchSize)).Iterator()

// 	for iter.Next(ctx) {
// 		key := iter.Val()

// 		// Get the session
// 		data, err := r.client.Get(ctx, key).Bytes()
// 		if err != nil {
// 			continue
// 		}

// 		var session models.ActiveSession
// 		if err := json.Unmarshal(data, &session); err != nil {
// 			continue
// 		}

// 		// Check if expired
// 		if time.Now().After(session.ExpiresAt) {
// 			userID := strings.TrimPrefix(key, sessionKeyPrefix)
// 			uid, err := uuid.Parse(userID)
// 			if err != nil {
// 				continue
// 			}

// 			r.InvalidateSession(ctx, uid)
// 			cleaned++
// 		}
// 	}

// 	if err := iter.Err(); err != nil {
// 		return cleaned, fmt.Errorf("error scanning sessions: %w", err)
// 	}

// 	r.logger.Info("Expired sessions cleanup completed",
// 		util.Int("cleaned", cleaned),
// 	)

// 	return cleaned, nil
// }

// // ============================================================================
// // DEVICE MANAGEMENT
// // ============================================================================

// // GetSessionsByDevice retrieves sessions for a specific device
// func (r *SessionRepositoryImpl) GetSessionsByDevice(ctx context.Context, deviceID string, limit int) ([]*models.ActiveSession, error) {
// 	deviceKey := fmt.Sprintf("%s%s", sessionDeviceKeyPrefix, deviceID)

// 	userIDs, err := r.client.SMembers(ctx, deviceKey).Result()
// 	if err != nil {
// 		if err == redis.Nil {
// 			return []*models.ActiveSession{}, nil
// 		}
// 		return nil, fmt.Errorf("failed to get device sessions: %w", err)
// 	}

// 	// Limit results
// 	if limit > 0 && len(userIDs) > limit {
// 		userIDs = userIDs[:limit]
// 	}

// 	sessions := make([]*models.ActiveSession, 0, len(userIDs))
// 	for _, userIDStr := range userIDs {
// 		uid, err := uuid.Parse(userIDStr)
// 		if err != nil {
// 			continue
// 		}

// 		session, err := r.GetSessionByUserID(ctx, uid)
// 		if err != nil {
// 			continue
// 		}

// 		sessions = append(sessions, session)
// 	}

// 	return sessions, nil
// }

// // InvalidateDeviceSessions invalidates all sessions for a device
// func (r *SessionRepositoryImpl) InvalidateDeviceSessions(ctx context.Context, deviceID string) error {
// 	sessions, err := r.GetSessionsByDevice(ctx, deviceID, 0)
// 	if err != nil {
// 		return err
// 	}

// 	for _, session := range sessions {
// 		uid, err := uuid.Parse(session.UserID)
// 		if err != nil {
// 			continue
// 		}
// 		r.InvalidateSession(ctx, uid)
// 	}

// 	r.logger.Info("Device sessions invalidated",
// 		util.String("device_id", deviceID),
// 		util.Int("count", len(sessions)),
// 	)

// 	return nil
// }

// // GetActiveSessionsCount gets the count of active sessions for a user
// func (r *SessionRepositoryImpl) GetActiveSessionsCount(ctx context.Context, userID uuid.UUID) (int, error) {
// 	countKey := fmt.Sprintf("%s%s", sessionCountKeyPrefix, userID.String())

// 	count, err := r.client.Get(ctx, countKey).Int()
// 	if err != nil {
// 		if err == redis.Nil {
// 			return 0, nil
// 		}
// 		return 0, fmt.Errorf("failed to get session count: %w", err)
// 	}

// 	return count, nil
// }

// // ============================================================================
// // ADMIN SESSION SUPPORT
// // ============================================================================

// // GetSessionType retrieves the session type quickly without full session
// func (r *SessionRepositoryImpl) GetSessionType(ctx context.Context, sessionToken string) (string, error) {
// 	typeKey := fmt.Sprintf("%s%s", sessionTypeKeyPrefix, sessionToken)
// 	sessionType, err := r.client.Get(ctx, typeKey).Result()
// 	if err != nil {
// 		if err == redis.Nil {
// 			return "", fmt.Errorf("session type not found for token")
// 		}
// 		return "", fmt.Errorf("failed to get session type: %w", err)
// 	}
// 	return sessionType, nil
// }

// // IsAdminSession checks if a token is for an admin session
// func (r *SessionRepositoryImpl) IsAdminSession(ctx context.Context, sessionToken string) (bool, error) {
// 	sessionType, err := r.GetSessionType(ctx, sessionToken)
// 	if err != nil {
// 		return false, err
// 	}
// 	return sessionType == "admin", nil
// }

// // GetAdminSessions retrieves all admin sessions for a user
// func (r *SessionRepositoryImpl) GetAdminSessions(ctx context.Context, userID uuid.UUID) ([]*models.ActiveSession, error) {
// 	adminKey := fmt.Sprintf("%s%s", adminSessionKeyPrefix, userID.String())

// 	tokens, err := r.client.SMembers(ctx, adminKey).Result()
// 	if err != nil {
// 		if err == redis.Nil {
// 			return []*models.ActiveSession{}, nil
// 		}
// 		return nil, fmt.Errorf("failed to get admin sessions: %w", err)
// 	}

// 	sessions := make([]*models.ActiveSession, 0, len(tokens))
// 	for _, token := range tokens {
// 		session, err := r.GetSessionByToken(ctx, token)
// 		if err != nil {
// 			continue
// 		}
// 		sessions = append(sessions, session)
// 	}

// 	return sessions, nil
// }

// // InvalidateAdminSessions invalidates all admin sessions for a user
// func (r *SessionRepositoryImpl) InvalidateAdminSessions(ctx context.Context, userID uuid.UUID) error {
// 	sessions, err := r.GetAdminSessions(ctx, userID)
// 	if err != nil {
// 		return err
// 	}

// 	for _, session := range sessions {
// 		r.InvalidateSessionByToken(ctx, session.SessionToken)
// 	}

// 	r.logger.Info("Admin sessions invalidated for user",
// 		util.String("user_id", userID.String()),
// 		util.Int("count", len(sessions)),
// 	)

// 	return nil
// }

// // GetActiveAdminSessionsCount gets count of admin sessions for a user
// func (r *SessionRepositoryImpl) GetActiveAdminSessionsCount(ctx context.Context, userID uuid.UUID) (int, error) {
// 	adminKey := fmt.Sprintf("%s%s", adminSessionKeyPrefix, userID.String())

// 	count, err := r.client.SCard(ctx, adminKey).Result()
// 	if err != nil {
// 		if err == redis.Nil {
// 			return 0, nil
// 		}
// 		return 0, fmt.Errorf("failed to get admin session count: %w", err)
// 	}

// 	return int(count), nil
// }

// // ============================================================================
// // ✅ JWT REFRESH TOKEN OPERATIONS
// // ============================================================================

// // StoreRefreshToken stores refresh token in Redis
// func (r *SessionRepositoryImpl) StoreRefreshToken(ctx context.Context, data *models.RefreshTokenData) error {
// 	jsonData, err := json.Marshal(data)
// 	if err != nil {
// 		return fmt.Errorf("failed to marshal refresh token: %w", err)
// 	}

// 	refreshKey := fmt.Sprintf("%s%s", refreshTokenKeyPrefix, data.RefreshID)
// 	ttl := time.Until(data.ExpiresAt)

// 	pipe := r.client.Pipeline()

// 	// Store refresh token data
// 	pipe.Set(ctx, refreshKey, jsonData, ttl)

// 	// Add to user's refresh token set (for session listing / device revocation)
// 	userSetKey := fmt.Sprintf("%s%s", userRefreshSetPrefix, data.UserID)
// 	pipe.SAdd(ctx, userSetKey, data.RefreshID)
// 	pipe.Expire(ctx, userSetKey, ttl)

// 	if _, err := pipe.Exec(ctx); err != nil {
// 		return fmt.Errorf("failed to store refresh token: %w", err)
// 	}

// 	r.logger.Info("Refresh token stored",
// 		util.String("user_id", data.UserID),
// 		util.String("session_type", data.SessionType),
// 	)

// 	return nil
// }

// // GetRefreshToken retrieves refresh token from Redis
// func (r *SessionRepositoryImpl) GetRefreshToken(ctx context.Context, refreshID string) (*models.RefreshTokenData, error) {
// 	refreshKey := fmt.Sprintf("%s%s", refreshTokenKeyPrefix, refreshID)

// 	data, err := r.client.Get(ctx, refreshKey).Bytes()
// 	if err != nil {
// 		if err == redis.Nil {
// 			return nil, fmt.Errorf("refresh token not found")
// 		}
// 		return nil, fmt.Errorf("failed to get refresh token: %w", err)
// 	}

// 	var refreshData models.RefreshTokenData
// 	if err := json.Unmarshal(data, &refreshData); err != nil {
// 		return nil, fmt.Errorf("failed to unmarshal refresh token: %w", err)
// 	}

// 	// Update last used time
// 	refreshData.LastUsed = time.Now().UTC()
// 	updatedData, _ := json.Marshal(refreshData)
// 	r.client.Set(ctx, refreshKey, updatedData, time.Until(refreshData.ExpiresAt))

// 	return &refreshData, nil
// }

// // DeleteRefreshToken deletes refresh token (logout/rotation)
// func (r *SessionRepositoryImpl) DeleteRefreshToken(ctx context.Context, refreshID string) error {
// 	refreshKey := fmt.Sprintf("%s%s", refreshTokenKeyPrefix, refreshID)

// 	// Get token data to remove from user set
// 	data, err := r.GetRefreshToken(ctx, refreshID)
// 	if err != nil {
// 		// Token doesn't exist, that's fine
// 		return nil
// 	}

// 	pipe := r.client.Pipeline()

// 	// Delete refresh token
// 	pipe.Del(ctx, refreshKey)

// 	// Remove from user's refresh set
// 	userSetKey := fmt.Sprintf("%s%s", userRefreshSetPrefix, data.UserID)
// 	pipe.SRem(ctx, userSetKey, refreshID)

// 	if _, err := pipe.Exec(ctx); err != nil {
// 		return fmt.Errorf("failed to delete refresh token: %w", err)
// 	}

// 	return nil
// }

// // GetUserRefreshTokens gets all refresh tokens for a user (for logout all devices)
// func (r *SessionRepositoryImpl) GetUserRefreshTokens(ctx context.Context, userID string) ([]string, error) {
// 	userSetKey := fmt.Sprintf("%s%s", userRefreshSetPrefix, userID)

// 	tokens, err := r.client.SMembers(ctx, userSetKey).Result()
// 	if err != nil {
// 		if err == redis.Nil {
// 			return []string{}, nil
// 		}
// 		return nil, fmt.Errorf("failed to get user refresh tokens: %w", err)
// 	}

// 	return tokens, nil
// }

// // RevokeAllUserRefreshTokens revokes all refresh tokens for a user
// func (r *SessionRepositoryImpl) RevokeAllUserRefreshTokens(ctx context.Context, userID string) error {
// 	tokens, err := r.GetUserRefreshTokens(ctx, userID)
// 	if err != nil {
// 		return err
// 	}

// 	for _, token := range tokens {
// 		r.DeleteRefreshToken(ctx, token)
// 	}

// 	r.logger.Info("All user refresh tokens revoked",
// 		util.String("user_id", userID),
// 		util.Int("count", len(tokens)),
// 	)

// 	return nil
// }

// // ============================================================================
// // HEALTH MONITORING
// // ============================================================================

// // HealthCheck performs a health check on the repository
// func (r *SessionRepositoryImpl) HealthCheck(ctx context.Context) error {
// 	if err := r.client.Ping(ctx).Err(); err != nil {
// 		return fmt.Errorf("session repository health check failed: %w", err)
// 	}
// 	return nil
// }

// // GetRepositoryStats returns repository statistics
// func (r *SessionRepositoryImpl) GetRepositoryStats(ctx context.Context) (map[string]interface{}, error) {
// 	stats := make(map[string]interface{})

// 	// Count active sessions
// 	iter := r.client.Scan(ctx, 0, sessionKeyPrefix+"*", 1000).Iterator()
// 	count := 0
// 	for iter.Next(ctx) {
// 		count++
// 	}

// 	// Count admin sessions
// 	adminIter := r.client.Scan(ctx, 0, adminSessionKeyPrefix+"*", 1000).Iterator()
// 	adminCount := 0
// 	for adminIter.Next(ctx) {
// 		adminCount++
// 	}

// 	// ✅ NEW: Count refresh tokens
// 	refreshIter := r.client.Scan(ctx, 0, refreshTokenKeyPrefix+"*", 1000).Iterator()
// 	refreshCount := 0
// 	for refreshIter.Next(ctx) {
// 		refreshCount++
// 	}

// 	stats["active_sessions"] = count
// 	stats["active_admin_sessions"] = adminCount
// 	stats["active_refresh_tokens"] = refreshCount // ✅ NEW
// 	stats["session_ttl_hours"] = int(sessionTTL.Hours())
// 	stats["admin_session_ttl_hours"] = int(adminSessionTTL.Hours())

// 	return stats, nil
// }