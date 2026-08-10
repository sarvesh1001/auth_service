package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	apperrors "auth-service/internal/errors"
	"auth-service/internal/models"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// SessionRepositoryImpl implements SessionRepository using Redis.
type SessionRepositoryImpl struct {
	client *redis.Client
}

// NewSessionRepository creates a new session repository.
func NewSessionRepository(client *redis.Client) SessionRepository {
	return &SessionRepositoryImpl{
		client: client,
	}
}

const (
	sessionKeyPrefix       = "session:user:"
	sessionTokenKeyPrefix  = "session:token:"
	sessionDeviceKeyPrefix = "session:device:"
	sessionCountKeyPrefix  = "session:count:"
	sessionTypeKeyPrefix   = "session:type:"
	adminSessionKeyPrefix  = "admin:session:"
	refreshTokenKeyPrefix  = "refresh:"
	userRefreshSetPrefix   = "user_refreshs:"
	accessTokenKeyPrefix   = "access_token:"

	sessionTTL      = 30 * 24 * time.Hour
	adminSessionTTL = 7 * 24 * time.Hour
)

// CreateSession stores a new active session.
func (r *SessionRepositoryImpl) CreateSession(ctx context.Context, session *models.ActiveSession) error {
	sessionData, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to serialize session: %w", err)
	}
	ttl := sessionTTL
	if session.SessionType == "admin" {
		ttl = adminSessionTTL
	}

	pipe := r.client.Pipeline()

	userKey := fmt.Sprintf("%s%s", sessionKeyPrefix, session.UserID)
	pipe.Set(ctx, userKey, sessionData, ttl)

	tokenKey := fmt.Sprintf("%s%s", sessionTokenKeyPrefix, session.SessionToken)
	pipe.Set(ctx, tokenKey, session.UserID, ttl)

	typeKey := fmt.Sprintf("%s%s", sessionTypeKeyPrefix, session.SessionToken)
	pipe.Set(ctx, typeKey, session.SessionType, ttl)

	if session.DeviceID != "" {
		deviceKey := fmt.Sprintf("%s%s", sessionDeviceKeyPrefix, session.DeviceID)
		pipe.SAdd(ctx, deviceKey, session.UserID)
		pipe.Expire(ctx, deviceKey, ttl)
	}

	countKey := fmt.Sprintf("%s%s", sessionCountKeyPrefix, session.UserID)
	pipe.Incr(ctx, countKey)
	pipe.Expire(ctx, countKey, ttl)

	if session.SessionType == "admin" {
		adminKey := fmt.Sprintf("%s%s", adminSessionKeyPrefix, session.UserID)
		pipe.SAdd(ctx, adminKey, session.SessionToken)
		pipe.Expire(ctx, adminKey, adminSessionTTL)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	return nil
}

// GetSessionByUserID retrieves the session for a user.
// Returns apperrors.ErrNotFound if not found or expired.
func (r *SessionRepositoryImpl) GetSessionByUserID(ctx context.Context, userID uuid.UUID) (*models.ActiveSession, error) {
	key := fmt.Sprintf("%s%s", sessionKeyPrefix, userID.String())
	data, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	var session models.ActiveSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("failed to deserialize session: %w", err)
	}
	if time.Now().After(session.ExpiresAt) {
		_ = r.client.Del(ctx, key).Err() // cleanup
		return nil, apperrors.ErrNotFound
	}
	return &session, nil
}

// GetSessionByToken retrieves a session by its token.
func (r *SessionRepositoryImpl) GetSessionByToken(ctx context.Context, sessionToken string) (*models.ActiveSession, error) {
	tokenKey := fmt.Sprintf("%s%s", sessionTokenKeyPrefix, sessionToken)
	userIDStr, err := r.client.Get(ctx, tokenKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get session token: %w", err)
	}
	uid, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID in session: %w", err)
	}
	return r.GetSessionByUserID(ctx, uid)
}

// UpdateSessionActivity updates the last activity and IP.
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

// InvalidateSession removes a session for a user.
func (r *SessionRepositoryImpl) InvalidateSession(ctx context.Context, userID uuid.UUID) error {
	session, err := r.GetSessionByUserID(ctx, userID)
	if err != nil {
		return nil // already gone
	}
	pipe := r.client.Pipeline()

	userKey := fmt.Sprintf("%s%s", sessionKeyPrefix, userID.String())
	pipe.Del(ctx, userKey)

	tokenKey := fmt.Sprintf("%s%s", sessionTokenKeyPrefix, session.SessionToken)
	pipe.Del(ctx, tokenKey)

	typeKey := fmt.Sprintf("%s%s", sessionTypeKeyPrefix, session.SessionToken)
	pipe.Del(ctx, typeKey)

	if session.DeviceID != "" {
		deviceKey := fmt.Sprintf("%s%s", sessionDeviceKeyPrefix, session.DeviceID)
		pipe.SRem(ctx, deviceKey, userID.String())
	}

	countKey := fmt.Sprintf("%s%s", sessionCountKeyPrefix, userID.String())
	pipe.Decr(ctx, countKey)

	if session.SessionType == "admin" {
		adminKey := fmt.Sprintf("%s%s", adminSessionKeyPrefix, userID.String())
		pipe.SRem(ctx, adminKey, session.SessionToken)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to invalidate session: %w", err)
	}
	return nil
}

// InvalidateSessionByToken removes a session by token.
func (r *SessionRepositoryImpl) InvalidateSessionByToken(ctx context.Context, sessionToken string) error {
	tokenKey := fmt.Sprintf("%s%s", sessionTokenKeyPrefix, sessionToken)
	userIDStr, err := r.client.Get(ctx, tokenKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil
		}
		return fmt.Errorf("failed to get session token: %w", err)
	}
	uid, err := uuid.Parse(userIDStr)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}
	return r.InvalidateSession(ctx, uid)
}

// RefreshSession replaces the token with a new one.
func (r *SessionRepositoryImpl) RefreshSession(ctx context.Context, userID uuid.UUID, newToken string, expiresAt time.Time) error {
	session, err := r.GetSessionByUserID(ctx, userID)
	if err != nil {
		return err
	}
	oldTokenKey := fmt.Sprintf("%s%s", sessionTokenKeyPrefix, session.SessionToken)
	_ = r.client.Del(ctx, oldTokenKey).Err()
	oldTypeKey := fmt.Sprintf("%s%s", sessionTypeKeyPrefix, session.SessionToken)
	_ = r.client.Del(ctx, oldTypeKey).Err()

	session.SessionToken = newToken
	session.ExpiresAt = expiresAt

	sessionData, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to serialize session: %w", err)
	}
	ttl := sessionTTL
	if session.SessionType == "admin" {
		ttl = adminSessionTTL
	}
	pipe := r.client.Pipeline()
	userKey := fmt.Sprintf("%s%s", sessionKeyPrefix, userID.String())
	pipe.Set(ctx, userKey, sessionData, ttl)
	newTokenKey := fmt.Sprintf("%s%s", sessionTokenKeyPrefix, newToken)
	pipe.Set(ctx, newTokenKey, userID.String(), ttl)
	newTypeKey := fmt.Sprintf("%s%s", sessionTypeKeyPrefix, newToken)
	pipe.Set(ctx, newTypeKey, session.SessionType, ttl)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to refresh session: %w", err)
	}
	return nil
}

// InvalidateSessionsBatch invalidates sessions for multiple users.
func (r *SessionRepositoryImpl) InvalidateSessionsBatch(ctx context.Context, userIDs []uuid.UUID) error {
	for _, uid := range userIDs {
		_ = r.InvalidateSession(ctx, uid)
	}
	return nil
}

// GetSessionsBatch retrieves sessions for multiple users (best-effort).
func (r *SessionRepositoryImpl) GetSessionsBatch(ctx context.Context, userIDs []uuid.UUID) ([]*models.ActiveSession, error) {
	sessions := make([]*models.ActiveSession, 0, len(userIDs))
	for _, uid := range userIDs {
		s, err := r.GetSessionByUserID(ctx, uid)
		if err == nil {
			sessions = append(sessions, s)
		}
	}
	return sessions, nil
}

// CleanupExpiredSessions scans and removes expired sessions.
func (r *SessionRepositoryImpl) CleanupExpiredSessions(ctx context.Context, batchSize int) (int, error) {
	cleaned := 0
	iter := r.client.Scan(ctx, 0, sessionKeyPrefix+"*", int64(batchSize)).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		data, err := r.client.Get(ctx, key).Bytes()
		if err != nil {
			continue
		}
		var session models.ActiveSession
		if err := json.Unmarshal(data, &session); err != nil {
			continue
		}
		if time.Now().After(session.ExpiresAt) {
			userIDStr := strings.TrimPrefix(key, sessionKeyPrefix)
			uid, err := uuid.Parse(userIDStr)
			if err != nil {
				continue
			}
			_ = r.InvalidateSession(ctx, uid)
			cleaned++
		}
	}
	if err := iter.Err(); err != nil {
		return cleaned, fmt.Errorf("error scanning sessions: %w", err)
	}
	return cleaned, nil
}

// GetSessionsByDevice returns sessions for a given device (limit optional).
func (r *SessionRepositoryImpl) GetSessionsByDevice(ctx context.Context, deviceID string, limit int) ([]*models.ActiveSession, error) {
	deviceKey := fmt.Sprintf("%s%s", sessionDeviceKeyPrefix, deviceID)
	userIDStrs, err := r.client.SMembers(ctx, deviceKey).Result()
	if err != nil {
		if err == redis.Nil {
			return []*models.ActiveSession{}, nil
		}
		return nil, fmt.Errorf("failed to get device sessions: %w", err)
	}
	if limit > 0 && len(userIDStrs) > limit {
		userIDStrs = userIDStrs[:limit]
	}
	sessions := make([]*models.ActiveSession, 0, len(userIDStrs))
	for _, s := range userIDStrs {
		uid, err := uuid.Parse(s)
		if err != nil {
			continue
		}
		sess, err := r.GetSessionByUserID(ctx, uid)
		if err == nil {
			sessions = append(sessions, sess)
		}
	}
	return sessions, nil
}

// InvalidateDeviceSessions removes all sessions for a device.
func (r *SessionRepositoryImpl) InvalidateDeviceSessions(ctx context.Context, deviceID string) error {
	sessions, err := r.GetSessionsByDevice(ctx, deviceID, 0)
	if err != nil {
		return err
	}
	for _, sess := range sessions {
		uid, err := uuid.Parse(sess.UserID)
		if err != nil {
			continue
		}
		_ = r.InvalidateSession(ctx, uid)
	}
	return nil
}

// GetActiveSessionsCount returns the number of active sessions for a user.
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

// GetSessionType returns the type of a session by token.
func (r *SessionRepositoryImpl) GetSessionType(ctx context.Context, sessionToken string) (string, error) {
	typeKey := fmt.Sprintf("%s%s", sessionTypeKeyPrefix, sessionToken)
	sessionType, err := r.client.Get(ctx, typeKey).Result()
	if err != nil {
		if err == redis.Nil {
			return "", apperrors.ErrNotFound
		}
		return "", fmt.Errorf("failed to get session type: %w", err)
	}
	return sessionType, nil
}

// IsAdminSession checks if a token belongs to an admin session.
func (r *SessionRepositoryImpl) IsAdminSession(ctx context.Context, sessionToken string) (bool, error) {
	sessionType, err := r.GetSessionType(ctx, sessionToken)
	if err != nil {
		return false, err
	}
	return sessionType == "admin", nil
}

// GetAdminSessions retrieves all admin sessions for a user.
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
		s, err := r.GetSessionByToken(ctx, token)
		if err == nil {
			sessions = append(sessions, s)
		}
	}
	return sessions, nil
}

// InvalidateAdminSessions removes all admin sessions for a user.
func (r *SessionRepositoryImpl) InvalidateAdminSessions(ctx context.Context, userID uuid.UUID) error {
	sessions, err := r.GetAdminSessions(ctx, userID)
	if err != nil {
		return err
	}
	for _, s := range sessions {
		_ = r.InvalidateSessionByToken(ctx, s.SessionToken)
	}
	return nil
}

// GetActiveAdminSessionsCount returns the number of active admin sessions.
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

// ----- Refresh Tokens -----

// StoreRefreshToken stores a refresh token.
func (r *SessionRepositoryImpl) StoreRefreshToken(ctx context.Context, data *models.RefreshTokenData) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal refresh token: %w", err)
	}
	refreshKey := fmt.Sprintf("%s%s", refreshTokenKeyPrefix, data.RefreshID)
	ttl := time.Until(data.ExpiresAt)
	pipe := r.client.Pipeline()
	pipe.Set(ctx, refreshKey, jsonData, ttl)
	userSetKey := fmt.Sprintf("%s%s", userRefreshSetPrefix, data.UserID)
	pipe.SAdd(ctx, userSetKey, data.RefreshID)
	pipe.Expire(ctx, userSetKey, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to store refresh token: %w", err)
	}
	return nil
}

// GetRefreshToken retrieves a refresh token by ID.
func (r *SessionRepositoryImpl) GetRefreshToken(ctx context.Context, refreshID string) (*models.RefreshTokenData, error) {
	refreshKey := fmt.Sprintf("%s%s", refreshTokenKeyPrefix, refreshID)
	data, err := r.client.Get(ctx, refreshKey).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}
	var refreshData models.RefreshTokenData
	if err := json.Unmarshal(data, &refreshData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal refresh token: %w", err)
	}
	refreshData.LastUsed = time.Now().UTC()
	updated, _ := json.Marshal(refreshData)
	_ = r.client.Set(ctx, refreshKey, updated, time.Until(refreshData.ExpiresAt)).Err()
	return &refreshData, nil
}

// DeleteRefreshToken removes a refresh token.
func (r *SessionRepositoryImpl) DeleteRefreshToken(ctx context.Context, refreshID string) error {
	refreshKey := fmt.Sprintf("%s%s", refreshTokenKeyPrefix, refreshID)
	data, err := r.GetRefreshToken(ctx, refreshID)
	if err != nil {
		return nil // already gone
	}
	pipe := r.client.Pipeline()
	pipe.Del(ctx, refreshKey)
	userSetKey := fmt.Sprintf("%s%s", userRefreshSetPrefix, data.UserID)
	pipe.SRem(ctx, userSetKey, refreshID)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}
	return nil
}

// GetUserRefreshTokens returns all refresh token IDs for a user.
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

// RevokeAllUserRefreshTokens revokes all refresh tokens for a user.
func (r *SessionRepositoryImpl) RevokeAllUserRefreshTokens(ctx context.Context, userID string) error {
	tokens, err := r.GetUserRefreshTokens(ctx, userID)
	if err != nil {
		return err
	}
	for _, token := range tokens {
		_ = r.DeleteRefreshToken(ctx, token)
	}
	return nil
}

// ----- Access Tokens -----

// StoreAccessToken stores an access token.
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
	return nil
}

// GetAccessToken retrieves an access token by JTI.
func (r *SessionRepositoryImpl) GetAccessToken(ctx context.Context, jti string) (*models.AccessTokenData, error) {
	accessKey := fmt.Sprintf("%s%s", accessTokenKeyPrefix, jti)
	data, err := r.client.Get(ctx, accessKey).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}
	var accessData models.AccessTokenData
	if err := json.Unmarshal(data, &accessData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal access token: %w", err)
	}
	return &accessData, nil
}

// DeleteAccessToken removes an access token.
func (r *SessionRepositoryImpl) DeleteAccessToken(ctx context.Context, jti string) error {
	accessKey := fmt.Sprintf("%s%s", accessTokenKeyPrefix, jti)
	if err := r.client.Del(ctx, accessKey).Err(); err != nil {
		return fmt.Errorf("failed to delete access token: %w", err)
	}
	return nil
}

// HealthCheck verifies Redis connectivity.
func (r *SessionRepositoryImpl) HealthCheck(ctx context.Context) error {
	if err := r.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("session repository health check failed: %w", err)
	}
	return nil
}

// GetRepositoryStats returns statistics about the repository.
func (r *SessionRepositoryImpl) GetRepositoryStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	// Count session keys
	iter := r.client.Scan(ctx, 0, sessionKeyPrefix+"*", 1000).Iterator()
	count := 0
	for iter.Next(ctx) {
		count++
	}
	// Count admin session keys
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
	// Count access tokens
	accessIter := r.client.Scan(ctx, 0, accessTokenKeyPrefix+"*", 1000).Iterator()
	accessCount := 0
	for accessIter.Next(ctx) {
		accessCount++
	}
	stats["active_sessions"] = count
	stats["active_admin_sessions"] = adminCount
	stats["active_refresh_tokens"] = refreshCount
	stats["active_access_tokens"] = accessCount
	stats["session_ttl_hours"] = int(sessionTTL.Hours())
	stats["admin_session_ttl_hours"] = int(adminSessionTTL.Hours())
	return stats, nil
}
