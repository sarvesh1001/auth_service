// internal/service/session_service.go
package service

import (
    "context"
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "net"
    "time"

    "auth-service/internal/config"
    "auth-service/internal/models"
    "auth-service/internal/repository/redis"
    "auth-service/internal/util"

    "github.com/google/uuid"
    "go.uber.org/zap"
)

type SessionService struct {
    sessionRepo redis.SessionRepository
    config      *config.Config
    logger      *zap.Logger
}

// NewSessionService creates a new session service
func NewSessionService(
    sessionRepo redis.SessionRepository,
    config *config.Config,
    logger *zap.Logger,
) *SessionService {
    return &SessionService{
        sessionRepo: sessionRepo,
        config:      config,
        logger:      logger,
    }
}

// CreateSessionRequest represents session creation request
type CreateSessionRequest struct {
    UserID            uuid.UUID `json:"user_id" validate:"required"`
    DeviceID          string    `json:"device_id" validate:"required"`
    DeviceFingerprint string    `json:"device_fingerprint"`
    KYCVerified       bool      `json:"kyc_verified"`
    IPAddress         string    `json:"ip_address"`
}

// CreateSession creates a new session
func (s *SessionService) CreateSession(ctx context.Context, req *CreateSessionRequest) (*models.ActiveSession, error) {
    // Generate session token
    token, err := s.generateSessionToken()
    if err != nil {
        return nil, fmt.Errorf("failed to generate session token: %w", err)
    }

    // Parse IP address
    var ipAddr net.IP
    if req.IPAddress != "" {
        ipAddr = net.ParseIP(req.IPAddress)
    }

    // Generate encryption key for session
    encKey := make([]byte, 32)
    if _, err := rand.Read(encKey); err != nil {
        return nil, fmt.Errorf("failed to generate encryption key: %w", err)
    }

    now := time.Now()
    expiresAt := now.Add(time.Duration(s.config.Auth.SessionTTL) * time.Second)

    session := &models.ActiveSession{
        UserID:            req.UserID.String(),
        SessionToken:      token,
        DeviceID:          req.DeviceID,
        DeviceFingerprint: req.DeviceFingerprint,
        KYCVerified:       req.KYCVerified,
        CreatedAt:         now,
        LastActivity:      now,
        ExpiresAt:         expiresAt,
        IPAddress:         ipAddr,
        EncryptionKey:     encKey,
    }

    if err := s.sessionRepo.CreateSession(ctx, session); err != nil {
        return nil, fmt.Errorf("failed to create session: %w", err)
    }

    s.logger.Info("Session created",
        util.String("user_id", req.UserID.String()),
        util.String("device_id", req.DeviceID),
    )

    return session, nil
}

// GetSessionByUserID retrieves session by user ID
func (s *SessionService) GetSessionByUserID(ctx context.Context, userID uuid.UUID) (*models.ActiveSession, error) {
    session, err := s.sessionRepo.GetSessionByUserID(ctx, userID)
    if err != nil {
        return nil, fmt.Errorf("%w: %v", ErrSessionNotFound, err)
    }

    return session, nil
}

// GetSessionByToken retrieves session by token
func (s *SessionService) GetSessionByToken(ctx context.Context, sessionToken string) (*models.ActiveSession, error) {
    session, err := s.sessionRepo.GetSessionByToken(ctx, sessionToken)
    if err != nil {
        return nil, fmt.Errorf("%w: %v", ErrSessionNotFound, err)
    }

    return session, nil
}

// UpdateSessionActivity updates session activity
func (s *SessionService) UpdateSessionActivity(ctx context.Context, userID uuid.UUID, ipAddress string) error {
    var ipAddr net.IP
    if ipAddress != "" {
        ipAddr = net.ParseIP(ipAddress)
    }

    return s.sessionRepo.UpdateSessionActivity(ctx, userID, time.Now(), ipAddr)
}

// InvalidateSession invalidates a session
func (s *SessionService) InvalidateSession(ctx context.Context, userID uuid.UUID) error {
    return s.sessionRepo.InvalidateSession(ctx, userID)
}

// InvalidateSessionByToken invalidates session by token
func (s *SessionService) InvalidateSessionByToken(ctx context.Context, sessionToken string) error {
    return s.sessionRepo.InvalidateSessionByToken(ctx, sessionToken)
}

// RefreshSession refreshes a session
func (s *SessionService) RefreshSession(ctx context.Context, userID uuid.UUID) (string, error) {
    newToken, err := s.generateSessionToken()
    if err != nil {
        return "", fmt.Errorf("failed to generate new token: %w", err)
    }

    expiresAt := time.Now().Add(time.Duration(s.config.Auth.SessionTTL) * time.Second)

    if err := s.sessionRepo.RefreshSession(ctx, userID, newToken, expiresAt); err != nil {
        return "", err
    }

    return newToken, nil
}

// InvalidateSessionsBatch invalidates multiple sessions
func (s *SessionService) InvalidateSessionsBatch(ctx context.Context, userIDs []uuid.UUID) error {
    return s.sessionRepo.InvalidateSessionsBatch(ctx, userIDs)
}

// GetSessionsBatch retrieves multiple sessions
func (s *SessionService) GetSessionsBatch(ctx context.Context, userIDs []uuid.UUID) ([]*models.ActiveSession, error) {
    return s.sessionRepo.GetSessionsBatch(ctx, userIDs)
}

// CleanupExpiredSessions cleans up expired sessions
func (s *SessionService) CleanupExpiredSessions(ctx context.Context, batchSize int) (int, error) {
    if batchSize <= 0 {
        batchSize = 1000
    }

    return s.sessionRepo.CleanupExpiredSessions(ctx, batchSize)
}

// GetSessionsByDevice retrieves sessions by device
func (s *SessionService) GetSessionsByDevice(ctx context.Context, deviceID string, limit int) ([]*models.ActiveSession, error) {
    return s.sessionRepo.GetSessionsByDevice(ctx, deviceID, limit)
}

// InvalidateDeviceSessions invalidates all sessions for a device
func (s *SessionService) InvalidateDeviceSessions(ctx context.Context, deviceID string) error {
    return s.sessionRepo.InvalidateDeviceSessions(ctx, deviceID)
}

// GetActiveSessionsCount gets active session count
func (s *SessionService) GetActiveSessionsCount(ctx context.Context, userID uuid.UUID) (int, error) {
    return s.sessionRepo.GetActiveSessionsCount(ctx, userID)
}

// HealthCheck performs health check
func (s *SessionService) HealthCheck(ctx context.Context) error {
    return s.sessionRepo.HealthCheck(ctx)
}

// GetSessionStats gets session statistics
func (s *SessionService) GetSessionStats(ctx context.Context) (map[string]interface{}, error) {
    return s.sessionRepo.GetRepositoryStats(ctx)
}

// generateSessionToken generates a secure session token
func (s *SessionService) generateSessionToken() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(b), nil
}
