package service

import (
    "auth-service/internal/config"
    "auth-service/internal/models"
    "auth-service/internal/repository/postgres"
    "auth-service/internal/repository/redis"
    "auth-service/internal/util"
    "context"
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "net"
    "time"

    "github.com/google/uuid"
    "go.uber.org/zap"
)

type SessionService struct {
    sessionRepo redis.SessionRepository
    config      *config.Config
    jwtService  *JWTService
    logger      *zap.Logger
    logProducer *LogProducerService
    companyRepo postgres.CompanyRepository
}

// NewSessionService creates a new session service
func NewSessionService(
    sessionRepo redis.SessionRepository,
    config *config.Config,
    jwtService *JWTService,
    logger *zap.Logger,
    logProducer *LogProducerService,
    companyRepo postgres.CompanyRepository,
) *SessionService {
    return &SessionService{
        sessionRepo: sessionRepo,
        config:      config,
        jwtService:  jwtService,
        logger:      logger,
        logProducer: logProducer,
        companyRepo: companyRepo,
    }
}

// CreateSessionRequest represents session creation request
type CreateSessionRequest struct {
    UserID            uuid.UUID `json:"user_id" validate:"required"`
    DeviceID          string    `json:"device_id" validate:"required"`
    DeviceFingerprint string    `json:"device_fingerprint"`
    KYCVerified       bool      `json:"kyc_verified"`
    IPAddress         string    `json:"ip_address"`
    SessionType       string    `json:"session_type" validate:"oneof=user admin"`
}

// CreateAdminSessionRequest for admin-specific session creation
type CreateAdminSessionRequest struct {
    AdminID           uuid.UUID `json:"admin_id" validate:"required"`
    AdminRoleMask     uint64    `json:"admin_role_mask" validate:"required"`
    DeviceID          string    `json:"device_id" validate:"required"`
    DeviceFingerprint string    `json:"device_fingerprint"`
    IPAddress         string    `json:"ip_address"`
    PermissionMask    []uint64  `json:"permission_mask"`
}

// IssueTokenPairRequest for JWT token pair issuance - UPDATED
type IssueTokenPairRequest struct {
    UserID          string
    Role            string
    DeviceID        string
    SessionType     string
    IPAddress       string
    CompanyID       string
    AdminRoleMask   uint64
    PermissionMask  []uint64
}

// logSessionEvent helper method
func (s *SessionService) logSessionEvent(ctx context.Context, event *models.SessionLogEvent) {
    if s.logProducer != nil {
        _ = s.logProducer.ProduceSessionEvent(ctx, event)
    }
}

// IssueTokenPair issues JWT access + opaque refresh tokens with CompanyID
func (s *SessionService) IssueTokenPair(ctx context.Context, req *IssueTokenPairRequest) (*models.TokenPairResponse, error) {
    // ---------------------------------------------------------
    // 1️⃣ Validate required fields
    // ---------------------------------------------------------
    if req.UserID == "" {
        return nil, fmt.Errorf("user ID is required")
    }
    
    if req.DeviceID == "" {
        return nil, fmt.Errorf("device ID is required")
    }

    // ---------------------------------------------------------
    // 2️⃣ Generate JWT Access Token with CompanyID
    // ---------------------------------------------------------
    accessToken, jti, err := s.jwtService.CreateAccessToken(ctx, &CreateAccessTokenRequest{
        UserID:         req.UserID,
        Role:           req.Role,
        DeviceID:       req.DeviceID,
        SessionType:    req.SessionType,
        CompanyID:      req.CompanyID,
        AdminRoleMask:  req.AdminRoleMask,
        PermissionMask: req.PermissionMask,
    })
    if err != nil {
        s.logger.Error("Failed to create access token",
            util.ErrorField(err),
            util.String("user_id", req.UserID),
            util.String("company_id", req.CompanyID))
        return nil, fmt.Errorf("failed to create access token: %w", err)
    }

    // ---------------------------------------------------------
    // 3️⃣ Store Access Token in Redis
    // ---------------------------------------------------------
    now := time.Now().UTC()
    
    accessTokenData := &models.AccessTokenData{
        JTI:         jti,
        UserID:      req.UserID,
        DeviceID:    req.DeviceID,
        CompanyID:   req.CompanyID,
        SessionType: req.SessionType,
        Active:      true,
        ExpiresAt:   now.Add(s.config.JWT.AccessTTL),
        IPAddress:   req.IPAddress,
    }

    if err := s.sessionRepo.StoreAccessToken(ctx, accessTokenData); err != nil {
        s.logger.Error("Failed to store access token in Redis",
            util.ErrorField(err),
            util.String("jti", jti),
            util.String("user_id", req.UserID))
        return nil, fmt.Errorf("failed to store access token: %w", err)
    }

    // ---------------------------------------------------------
    // 4️⃣ Generate Opaque Refresh Token
    // ---------------------------------------------------------
    refreshToken, err := s.jwtService.GenerateRefreshToken()
    if err != nil {
        s.logger.Error("Failed to generate refresh token",
            util.ErrorField(err),
            util.String("user_id", req.UserID))
        // Clean up access token if refresh token generation fails
        s.sessionRepo.DeleteAccessToken(ctx, jti)
        return nil, fmt.Errorf("failed to generate refresh token: %w", err)
    }

    // ---------------------------------------------------------
    // 5️⃣ Store refresh token in Redis WITH JTI reference
    // ---------------------------------------------------------
    refreshData := &models.RefreshTokenData{
        RefreshID:   refreshToken,
        UserID:      req.UserID,
        DeviceID:    req.DeviceID,
        SessionType: req.SessionType,
        CompanyID:   req.CompanyID,
        IssuedAt:    now,
        ExpiresAt:   now.Add(s.config.JWT.RefreshTTL),
        LastUsed:    now,
        Revoked:     false,
        IPAddress:   req.IPAddress,
        AdminRoleMask: req.AdminRoleMask,
        JTI:         jti, // Store reference to access token
    }

    if err := s.sessionRepo.StoreRefreshToken(ctx, refreshData); err != nil {
        s.logger.Error("Failed to store refresh token",
            util.ErrorField(err),
            util.String("user_id", req.UserID),
            util.String("company_id", req.CompanyID))
        // Clean up access token if refresh token storage fails
        s.sessionRepo.DeleteAccessToken(ctx, jti)
        return nil, fmt.Errorf("failed to store refresh token: %w", err)
    }

    // ---------------------------------------------------------
    // 6️⃣ Log token issuance with CompanyID
    // ---------------------------------------------------------
    s.logger.Info("Token pair issued",
        util.String("user_id", req.UserID),
        util.String("session_type", req.SessionType),
        util.String("company_id", req.CompanyID),
        util.String("jti", jti),
        util.String("device_id", req.DeviceID),
        util.Uint64("admin_role_mask", req.AdminRoleMask),
        util.Int64("refresh_ttl_seconds", int64(s.config.JWT.RefreshTTL.Seconds())),
    )

    // ---------------------------------------------------------
    // 7️⃣ Final response
    // ---------------------------------------------------------
    return &models.TokenPairResponse{
        AccessToken:  accessToken,
        RefreshToken: refreshToken,
        ExpiresIn:    int(s.config.JWT.AccessTTL.Seconds()),
        TokenType:    "Bearer",
        CompanyID:    req.CompanyID,
    }, nil
}

// RefreshTokenPair rotates refresh token and issues new access token
func (s *SessionService) RefreshTokenPair(ctx context.Context, refreshToken string, ipAddress string) (*models.TokenPairResponse, error) {
    // Get refresh token from Redis
    refreshData, err := s.sessionRepo.GetRefreshToken(ctx, refreshToken)
    if err != nil {
        s.logger.Warn("Invalid refresh token provided",
            util.ErrorField(err),
            util.String("refresh_token", util.MaskString(refreshToken, 8)))
        return nil, fmt.Errorf("invalid refresh token: %w", err)
    }

    // Validate refresh token
    if refreshData.Revoked {
        s.logger.Warn("Refresh token revoked",
            util.String("user_id", refreshData.UserID),
            util.String("refresh_id", refreshData.RefreshID))
        return nil, fmt.Errorf("refresh token revoked")
    }

    if time.Now().After(refreshData.ExpiresAt) {
        s.logger.Warn("Refresh token expired",
            util.String("user_id", refreshData.UserID),
            util.Time("expires_at", refreshData.ExpiresAt))
        return nil, fmt.Errorf("refresh token expired")
    }

    // Update last used timestamp
    refreshData.LastUsed = time.Now().UTC()
    if err := s.sessionRepo.StoreRefreshToken(ctx, refreshData); err != nil {
        s.logger.Warn("Failed to update refresh token last used", util.ErrorField(err))
    }

    // Delete old access token using stored JTI
    if refreshData.JTI != "" {
        if err := s.sessionRepo.DeleteAccessToken(ctx, refreshData.JTI); err != nil {
            s.logger.Warn("Failed to delete old access token during refresh", 
                util.ErrorField(err),
                util.String("jti", refreshData.JTI))
        }
    }

    // Rotate refresh token (delete old, create new) if configured
    if s.config.JWT.RotateRefreshTokens {
        if err := s.sessionRepo.DeleteRefreshToken(ctx, refreshToken); err != nil {
            s.logger.Warn("Failed to delete old refresh token", util.ErrorField(err))
        }
    }

    // Issue new token pair with same CompanyID
    return s.IssueTokenPair(ctx, &IssueTokenPairRequest{
        UserID:        refreshData.UserID,
        Role:          refreshData.SessionType, // Use session type as role
        DeviceID:      refreshData.DeviceID,
        SessionType:   refreshData.SessionType,
        IPAddress:     ipAddress,
        CompanyID:     refreshData.CompanyID, // PRESERVE COMPANY ID
        AdminRoleMask: refreshData.AdminRoleMask,
    })
}

// ValidateAccessToken validates JWT and checks Redis for active status
func (s *SessionService) ValidateAccessToken(ctx context.Context, tokenStr string) (*models.JWTClaims, error) {
    // Validate JWT signature and parse claims
    claims, err := s.jwtService.ValidateAccessToken(ctx, tokenStr)
    if err != nil {
        return nil, fmt.Errorf("invalid JWT: %w", err)
    }

    // Check Redis for active access token
    accessData, err := s.sessionRepo.GetAccessToken(ctx, claims.JTI)
    if err != nil {
        return nil, fmt.Errorf("access token not found or revoked: %w", err)
    }

    // Check if token is active
    if !accessData.Active {
        return nil, fmt.Errorf("access token revoked")
    }

    // Validate device match
    if accessData.DeviceID != claims.DeviceID {
        s.logger.Warn("Device ID mismatch",
            util.String("jti", claims.JTI),
            util.String("redis_device", accessData.DeviceID),
            util.String("token_device", claims.DeviceID))
        return nil, fmt.Errorf("device mismatch")
    }

    // For user sessions, validate company ID
    if claims.SessionType == "user" {
        if accessData.CompanyID != claims.CompanyID {
            s.logger.Warn("Company ID mismatch for user session",
                util.String("jti", claims.JTI),
                util.String("redis_company", accessData.CompanyID),
                util.String("token_company", claims.CompanyID))
            return nil, fmt.Errorf("company mismatch")
        }
        
        // Additional check: company ID should not be empty for user sessions
        if accessData.CompanyID == "" || claims.CompanyID == "" {
            return nil, fmt.Errorf("company ID required for user sessions")
        }
    }
    // For admin sessions, skip company ID validation (admins have access to all companies)

    return claims, nil
}

// RevokeAccessToken revokes an access token by JTI
func (s *SessionService) RevokeAccessToken(ctx context.Context, jti string) error {
    s.logger.Info("Revoking access token",
        util.String("jti", jti))
    
    if err := s.sessionRepo.DeleteAccessToken(ctx, jti); err != nil {
        s.logger.Error("Failed to revoke access token", 
            util.ErrorField(err),
            util.String("jti", jti))
        return fmt.Errorf("failed to revoke access token: %w", err)
    }
    
    s.logger.Info("Access token revoked successfully",
        util.String("jti", jti))
    return nil
}

// RevokeRefreshToken revokes both refresh token and associated access token
func (s *SessionService) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
    s.logger.Info("Revoking refresh token",
        util.String("refresh_token", util.MaskString(refreshToken, 8)))
    
    // Get refresh token data to get the JTI
    refreshData, err := s.sessionRepo.GetRefreshToken(ctx, refreshToken)
    if err != nil {
        s.logger.Warn("Refresh token not found, might already be revoked",
            util.String("refresh_token", util.MaskString(refreshToken, 8)))
        // Still try to delete it
    } else {
        // Delete associated access token if JTI exists
        if refreshData.JTI != "" {
            if err := s.sessionRepo.DeleteAccessToken(ctx, refreshData.JTI); err != nil {
                s.logger.Warn("Failed to delete associated access token",
                    util.ErrorField(err),
                    util.String("jti", refreshData.JTI))
            }
        }
    }
    
    // Delete refresh token
    if err := s.sessionRepo.DeleteRefreshToken(ctx, refreshToken); err != nil {
        s.logger.Error("Failed to revoke refresh token", util.ErrorField(err))
        return fmt.Errorf("failed to revoke refresh token: %w", err)
    }
    
    s.logger.Info("Refresh token and associated access token revoked successfully")
    return nil
}

// RevokeAllUserRefreshTokens revokes all tokens for a user
func (s *SessionService) RevokeAllUserRefreshTokens(ctx context.Context, userID string) error {
    s.logger.Info("Revoking all refresh tokens for user",
        util.String("user_id", userID))
    
    // Get all refresh tokens for user
    refreshTokens, err := s.sessionRepo.GetUserRefreshTokens(ctx, userID)
    if err != nil {
        return fmt.Errorf("failed to get user refresh tokens: %w", err)
    }
    
    // Revoke each refresh token (which will also delete associated access tokens)
    for _, refreshToken := range refreshTokens {
        s.RevokeRefreshToken(ctx, refreshToken)
    }
    
    s.logger.Info("All refresh tokens revoked for user",
        util.String("user_id", userID),
        util.Int("count", len(refreshTokens)))
    return nil
}

// CreateSession creates a new session (legacy - now returns JWT tokens)
func (s *SessionService) CreateSession(ctx context.Context, req *CreateSessionRequest) (*models.ActiveSession, error) {
    startTime := time.Now()

    // Generate session token
    token, err := s.generateSessionToken()
    if err != nil {
        s.logSessionEvent(ctx, &models.SessionLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeSession),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelError),
                Message:     "Failed to generate session token",
            },
            UserID:    req.UserID.String(),
            SessionID: "",
            Status:    "failed",
            DeviceID:  req.DeviceID,
            IPAddress: req.IPAddress,
            ErrorCode: "TOKEN_GENERATION_FAILED",
        })
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
        s.logSessionEvent(ctx, &models.SessionLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeSession),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelError),
                Message:     "Failed to generate encryption key",
            },
            UserID:    req.UserID.String(),
            SessionID: token,
            Status:    "failed",
            DeviceID:  req.DeviceID,
            IPAddress: req.IPAddress,
            ErrorCode: "ENCRYPTION_KEY_FAILED",
        })
        return nil, fmt.Errorf("failed to generate encryption key: %w", err)
    }

    now := time.Now()

    // Get TTL based on session type
    ttl := time.Duration(s.config.Auth.SessionTTL) * time.Second
    if req.SessionType == "admin" {
        ttl = 7 * 24 * time.Hour
    }

    expiresAt := now.Add(ttl)

    // Set default session type to "user"
    sessionType := req.SessionType
    if sessionType == "" {
        sessionType = "user"
    }

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
        SessionType:       sessionType,
    }

    if err := s.sessionRepo.CreateSession(ctx, session); err != nil {
        s.logSessionEvent(ctx, &models.SessionLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeSession),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelError),
                Message:     "Failed to create session in repository",
            },
            UserID:      req.UserID.String(),
            SessionID:   token,
            Status:      "failed",
            DeviceID:    req.DeviceID,
            IPAddress:   req.IPAddress,
            SessionType: sessionType,
            TTL:         int64(ttl.Seconds()),
            ErrorCode:   "REPOSITORY_CREATE_FAILED",
        })
        return nil, fmt.Errorf("failed to create session: %w", err)
    }

    s.logSessionEvent(ctx, &models.SessionLogEvent{
        LogEnvelope: models.LogEnvelope{
            EventID:     uuid.New().String(),
            EventType:   string(models.LogEventTypeSession),
            ServiceName: "auth-service",
            Timestamp:   time.Now(),
            Environment: s.config.Environment,
            Version:     ServiceVersion,
            Level:       string(models.LogLevelInfo),
            Message:     "Session created successfully",
        },
        UserID:      req.UserID.String(),
        SessionID:   token,
        Status:      "created",
        DeviceID:    req.DeviceID,
        IPAddress:   req.IPAddress,
        SessionType: sessionType,
        TTL:         int64(ttl.Seconds()),
    })

    s.logger.Info("Session created",
        util.String("user_id", req.UserID.String()),
        util.String("device_id", req.DeviceID),
        util.String("session_type", sessionType),
        util.Duration("duration", time.Since(startTime)),
    )

    return session, nil
}
// CreateAdminSession creates a new admin session - UPDATED for bitmask
func (s *SessionService) CreateAdminSession(ctx context.Context, req *CreateAdminSessionRequest) (*models.ActiveSession, error) {
    startTime := time.Now()

    token, err := s.generateSessionToken()
    if err != nil {
        s.logSessionEvent(ctx, &models.SessionLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeSession),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelError),
                Message:     "Failed to generate admin session token",
            },
            UserID:    req.AdminID.String(),
            SessionID: "",
            Status:    "failed",
            DeviceID:  req.DeviceID,
            IPAddress: req.IPAddress,
            ErrorCode: "TOKEN_GENERATION_FAILED",
        })
        return nil, fmt.Errorf("failed to generate session token: %w", err)
    }

    var ipAddr net.IP
    if req.IPAddress != "" {
        ipAddr = net.ParseIP(req.IPAddress)
    }

    encKey := make([]byte, 32)
    if _, err := rand.Read(encKey); err != nil {
        s.logSessionEvent(ctx, &models.SessionLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeSession),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelError),
                Message:     "Failed to generate admin encryption key",
            },
            UserID:    req.AdminID.String(),
            SessionID: token,
            Status:    "failed",
            DeviceID:  req.DeviceID,
            IPAddress: req.IPAddress,
            ErrorCode: "ENCRYPTION_KEY_FAILED",
        })
        return nil, fmt.Errorf("failed to generate encryption key: %w", err)
    }

    now := time.Now()
    adminTTL := 7 * 24 * time.Hour
    expiresAt := now.Add(adminTTL)

    // ✅ FIXED: Use bitmask fields instead of old string fields
    session := &models.ActiveSession{
        UserID:             req.AdminID.String(),
        SessionToken:       token,
        DeviceID:          req.DeviceID,
        DeviceFingerprint: req.DeviceFingerprint,
        CreatedAt:         now,
        LastActivity:      now,
        ExpiresAt:         expiresAt,
        IPAddress:         ipAddr,
        EncryptionKey:     encKey,
        SessionType:       "admin",
        AdminRoleMask:     req.AdminRoleMask,           // ✅ Use bitmask
        AdminPermissionMask: req.PermissionMask,        // ✅ Use bitmask
    }

    if err := s.sessionRepo.CreateSession(ctx, session); err != nil {
        s.logSessionEvent(ctx, &models.SessionLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeSession),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelError),
                Message:     "Failed to create admin session in repository",
            },
            UserID:      req.AdminID.String(),
            SessionID:   token,
            Status:      "failed",
            DeviceID:    req.DeviceID,
            IPAddress:   req.IPAddress,
            SessionType: "admin",
            TTL:         int64(adminTTL.Seconds()),
            ErrorCode:   "REPOSITORY_CREATE_FAILED",
        })
        return nil, fmt.Errorf("failed to create admin session: %w", err)
    }

    s.logSessionEvent(ctx, &models.SessionLogEvent{
        LogEnvelope: models.LogEnvelope{
            EventID:     uuid.New().String(),
            EventType:   string(models.LogEventTypeSession),
            ServiceName: "auth-service",
            Timestamp:   time.Now(),
            Environment: s.config.Environment,
            Version:     ServiceVersion,
            Level:       string(models.LogLevelInfo),
            Message:     "Admin session created successfully",
        },
        UserID:      req.AdminID.String(),
        SessionID:   token,
        Status:      "created",
        DeviceID:    req.DeviceID,
        IPAddress:   req.IPAddress,
        SessionType: "admin",
        TTL:         int64(adminTTL.Seconds()),
    })

    s.logger.Info("Admin session created",
        util.String("admin_id", req.AdminID.String()),
        util.Uint64("role_mask", req.AdminRoleMask),
        util.String("device_id", req.DeviceID),
        util.Int("permission_mask_segments", len(req.PermissionMask)),
        util.Duration("duration", time.Since(startTime)),
    )

    return session, nil
}
// GetSessionByUserID retrieves session by user ID
func (s *SessionService) GetSessionByUserID(ctx context.Context, userID uuid.UUID) (*models.ActiveSession, error) {
    session, err := s.sessionRepo.GetSessionByUserID(ctx, userID)
    if err != nil {
        s.logSessionEvent(ctx, &models.SessionLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeSession),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelWarning),
                Message:     "Session not found by user ID",
            },
            UserID:    userID.String(),
            SessionID: "",
            Status:    "not_found",
            ErrorCode: "SESSION_NOT_FOUND",
        })
        return nil, fmt.Errorf("%w: %v", ErrSessionNotFound, err)
    }

    return session, nil
}

// GetSessionByToken retrieves session by token
func (s *SessionService) GetSessionByToken(ctx context.Context, sessionToken string) (*models.ActiveSession, error) {
    session, err := s.sessionRepo.GetSessionByToken(ctx, sessionToken)
    if err != nil {
        s.logSessionEvent(ctx, &models.SessionLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeSession),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelWarning),
                Message:     "Session not found by token",
            },
            UserID:    "",
            SessionID: sessionToken,
            Status:    "not_found",
            ErrorCode: "SESSION_NOT_FOUND",
        })
        return nil, fmt.Errorf("%w: %v", ErrSessionNotFound, err)
    }

    return session, nil
}

// GetSessionType quickly retrieves session type
func (s *SessionService) GetSessionType(ctx context.Context, sessionToken string) (string, error) {
    sessionType, err := s.sessionRepo.GetSessionType(ctx, sessionToken)
    if err != nil {
        s.logSessionEvent(ctx, &models.SessionLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeSession),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelError),
                Message:     "Failed to get session type",
            },
            SessionID: sessionToken,
            Status:    "failed",
            ErrorCode: "GET_TYPE_FAILED",
        })
        return "", fmt.Errorf("failed to get session type: %w", err)
    }
    return sessionType, nil
}

// IsAdminSession checks if a token is an admin session
func (s *SessionService) IsAdminSession(ctx context.Context, sessionToken string) (bool, error) {
    isAdmin, err := s.sessionRepo.IsAdminSession(ctx, sessionToken)
    if err != nil {
        s.logSessionEvent(ctx, &models.SessionLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeSession),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelError),
                Message:     "Failed to check admin session",
            },
            SessionID: sessionToken,
            Status:    "failed",
            ErrorCode: "CHECK_ADMIN_FAILED",
        })
        return false, fmt.Errorf("failed to check admin session: %w", err)
    }
    return isAdmin, nil
}

// UpdateSessionActivity updates session activity
func (s *SessionService) UpdateSessionActivity(ctx context.Context, userID uuid.UUID, ipAddress string) error {
    startTime := time.Now()

    var ipAddr net.IP
    if ipAddress != "" {
        ipAddr = net.ParseIP(ipAddress)
    }

    err := s.sessionRepo.UpdateSessionActivity(ctx, userID, time.Now(), ipAddr)
    if err != nil {
        s.logSessionEvent(ctx, &models.SessionLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeSession),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelError),
                Message:     "Failed to update session activity",
            },
            UserID:    userID.String(),
            Status:    "failed",
            IPAddress: ipAddress,
            ErrorCode: "UPDATE_ACTIVITY_FAILED",
        })
        return err
    }

    s.logSessionEvent(ctx, &models.SessionLogEvent{
        LogEnvelope: models.LogEnvelope{
            EventID:     uuid.New().String(),
            EventType:   string(models.LogEventTypeSession),
            ServiceName: "auth-service",
            Timestamp:   time.Now(),
            Environment: s.config.Environment,
            Version:     ServiceVersion,
            Level:       string(models.LogLevelDebug),
            Message:     "Session activity updated",
        },
        UserID:    userID.String(),
        Status:    "activity_updated",
        IPAddress: ipAddress,
    })

    s.logger.Debug("Session activity updated",
        util.String("user_id", userID.String()),
        util.Duration("duration", time.Since(startTime)),
    )

    return nil
}

// InvalidateSession invalidates a session
func (s *SessionService) InvalidateSession(ctx context.Context, userID uuid.UUID) error {
    startTime := time.Now()

    err := s.sessionRepo.InvalidateSession(ctx, userID)
    if err != nil {
        s.logSessionEvent(ctx, &models.SessionLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeSession),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelError),
                Message:     "Failed to invalidate session by user ID",
            },
            UserID:    userID.String(),
            Status:    "failed",
            ErrorCode: "INVALIDATE_FAILED",
        })
        return err
    }

    s.logSessionEvent(ctx, &models.SessionLogEvent{
        LogEnvelope: models.LogEnvelope{
            EventID:     uuid.New().String(),
            EventType:   string(models.LogEventTypeSession),
            ServiceName: "auth-service",
            Timestamp:   time.Now(),
            Environment: s.config.Environment,
            Version:     ServiceVersion,
            Level:       string(models.LogLevelInfo),
            Message:     "Session invalidated by user ID",
        },
        UserID: userID.String(),
        Status: "invalidated",
    })

    s.logger.Info("Session invalidated",
        util.String("user_id", userID.String()),
        util.Duration("duration", time.Since(startTime)),
    )

    return nil
}

// InvalidateSessionByToken invalidates session by token
func (s *SessionService) InvalidateSessionByToken(ctx context.Context, sessionToken string) error {
    startTime := time.Now()

    err := s.sessionRepo.InvalidateSessionByToken(ctx, sessionToken)
    if err != nil {
        s.logSessionEvent(ctx, &models.SessionLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeSession),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelError),
                Message:     "Failed to invalidate session by token",
            },
            SessionID: sessionToken,
            Status:    "failed",
            ErrorCode: "INVALIDATE_BY_TOKEN_FAILED",
        })
        return err
    }

    s.logSessionEvent(ctx, &models.SessionLogEvent{
        LogEnvelope: models.LogEnvelope{
            EventID:     uuid.New().String(),
            EventType:   string(models.LogEventTypeSession),
            ServiceName: "auth-service",
            Timestamp:   time.Now(),
            Environment: s.config.Environment,
            Version:     ServiceVersion,
            Level:       string(models.LogLevelInfo),
            Message:     "Session invalidated by token",
        },
        SessionID: sessionToken,
        Status:    "invalidated",
    })

    s.logger.Info("Session invalidated by token",
        util.Duration("duration", time.Since(startTime)),
    )

    return nil
}

// RefreshSession refreshes a session
func (s *SessionService) RefreshSession(ctx context.Context, userID uuid.UUID) (string, error) {
    startTime := time.Now()

    newToken, err := s.generateSessionToken()
    if err != nil {
        s.logSessionEvent(ctx, &models.SessionLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeSession),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelError),
                Message:     "Failed to generate new session token for refresh",
            },
            UserID:    userID.String(),
            Status:    "failed",
            ErrorCode: "TOKEN_GENERATION_FAILED",
        })
        return "", fmt.Errorf("failed to generate new token: %w", err)
    }

    expiresAt := time.Now().Add(time.Duration(s.config.Auth.SessionTTL) * time.Second)

    if err := s.sessionRepo.RefreshSession(ctx, userID, newToken, expiresAt); err != nil {
        s.logSessionEvent(ctx, &models.SessionLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeSession),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelError),
                Message:     "Failed to refresh session in repository",
            },
            UserID:    userID.String(),
            SessionID: newToken,
            Status:    "failed",
            ErrorCode: "REFRESH_FAILED",
        })
        return "", err
    }

    s.logSessionEvent(ctx, &models.SessionLogEvent{
        LogEnvelope: models.LogEnvelope{
            EventID:     uuid.New().String(),
            EventType:   string(models.LogEventTypeSession),
            ServiceName: "auth-service",
            Timestamp:   time.Now(),
            Environment: s.config.Environment,
            Version:     ServiceVersion,
            Level:       string(models.LogLevelInfo),
            Message:     "Session refreshed successfully",
        },
        UserID:    userID.String(),
        SessionID: newToken,
        Status:    "refreshed",
    })

    s.logger.Info("Session refreshed",
        util.String("user_id", userID.String()),
        util.Duration("duration", time.Since(startTime)),
    )

    return newToken, nil
}

// InvalidateSessionsBatch invalidates multiple sessions
func (s *SessionService) InvalidateSessionsBatch(ctx context.Context, userIDs []uuid.UUID) error {
    startTime := time.Now()

    err := s.sessionRepo.InvalidateSessionsBatch(ctx, userIDs)
    if err != nil {
        s.logSessionEvent(ctx, &models.SessionLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeSession),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelError),
                Message:     "Failed to invalidate sessions batch",
            },
            Status:    "failed",
            ErrorCode: "BATCH_INVALIDATE_FAILED",
        })
        return err
    }

    s.logSessionEvent(ctx, &models.SessionLogEvent{
        LogEnvelope: models.LogEnvelope{
            EventID:     uuid.New().String(),
            EventType:   string(models.LogEventTypeSession),
            ServiceName: "auth-service",
            Timestamp:   time.Now(),
            Environment: s.config.Environment,
            Version:     ServiceVersion,
            Level:       string(models.LogLevelInfo),
            Message:     "Batch sessions invalidated successfully",
        },
        Status: "batch_invalidated",
    })

    s.logger.Info("Batch sessions invalidated",
        util.Int("user_count", len(userIDs)),
        util.Duration("duration", time.Since(startTime)),
    )

    return nil
}

// GetSessionsBatch retrieves multiple sessions
func (s *SessionService) GetSessionsBatch(ctx context.Context, userIDs []uuid.UUID) ([]*models.ActiveSession, error) {
    return s.sessionRepo.GetSessionsBatch(ctx, userIDs)
}

// CleanupExpiredSessions cleans up expired sessions
func (s *SessionService) CleanupExpiredSessions(ctx context.Context, batchSize int) (int, error) {
    startTime := time.Now()

    if batchSize <= 0 {
        batchSize = 1000
    }

    cleanedCount, err := s.sessionRepo.CleanupExpiredSessions(ctx, batchSize)
    if err != nil {
        s.logSessionEvent(ctx, &models.SessionLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeSession),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelError),
                Message:     "Failed to cleanup expired sessions",
            },
            Status:    "failed",
            ErrorCode: "CLEANUP_FAILED",
        })
        return 0, err
    }

    if cleanedCount > 0 {
        s.logSessionEvent(ctx, &models.SessionLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeSession),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelInfo),
                Message:     "Expired sessions cleaned up",
            },
            Status: "cleanup_completed",
        })

        s.logger.Info("Expired sessions cleaned up",
            util.Int("cleaned_count", cleanedCount),
            util.Duration("duration", time.Since(startTime)),
        )
    }

    return cleanedCount, nil
}

// GetSessionsByDevice retrieves sessions by device
func (s *SessionService) GetSessionsByDevice(ctx context.Context, deviceID string, limit int) ([]*models.ActiveSession, error) {
    return s.sessionRepo.GetSessionsByDevice(ctx, deviceID, limit)
}

// InvalidateDeviceSessions invalidates all sessions for a device
func (s *SessionService) InvalidateDeviceSessions(ctx context.Context, deviceID string) error {
    startTime := time.Now()

    err := s.sessionRepo.InvalidateDeviceSessions(ctx, deviceID)
    if err != nil {
        s.logSessionEvent(ctx, &models.SessionLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeSession),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelError),
                Message:     "Failed to invalidate device sessions",
            },
            DeviceID:  deviceID,
            Status:    "failed",
            ErrorCode: "DEVICE_INVALIDATE_FAILED",
        })
        return err
    }

    s.logSessionEvent(ctx, &models.SessionLogEvent{
        LogEnvelope: models.LogEnvelope{
            EventID:     uuid.New().String(),
            EventType:   string(models.LogEventTypeSession),
            ServiceName: "auth-service",
            Timestamp:   time.Now(),
            Environment: s.config.Environment,
            Version:     ServiceVersion,
            Level:       string(models.LogLevelInfo),
            Message:     "Device sessions invalidated",
        },
        DeviceID: deviceID,
        Status:   "device_invalidated",
    })

    s.logger.Info("Device sessions invalidated",
        util.String("device_id", deviceID),
        util.Duration("duration", time.Since(startTime)),
    )

    return nil
}

// GetActiveSessionsCount gets active session count
func (s *SessionService) GetActiveSessionsCount(ctx context.Context, userID uuid.UUID) (int, error) {
    return s.sessionRepo.GetActiveSessionsCount(ctx, userID)
}

// GetAdminSessions retrieves all admin sessions for a user
func (s *SessionService) GetAdminSessions(ctx context.Context, userID uuid.UUID) ([]*models.ActiveSession, error) {
    sessions, err := s.sessionRepo.GetAdminSessions(ctx, userID)
    if err != nil {
        s.logSessionEvent(ctx, &models.SessionLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeSession),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelError),
                Message:     "Failed to get admin sessions",
            },
            UserID:    userID.String(),
            Status:    "failed",
            ErrorCode: "GET_ADMIN_SESSIONS_FAILED",
        })
        return nil, fmt.Errorf("failed to get admin sessions: %w", err)
    }
    return sessions, nil
}

// InvalidateAdminSessions invalidates all admin sessions for a user
func (s *SessionService) InvalidateAdminSessions(ctx context.Context, userID uuid.UUID) error {
    startTime := time.Now()

    err := s.sessionRepo.InvalidateAdminSessions(ctx, userID)
    if err != nil {
        s.logSessionEvent(ctx, &models.SessionLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeSession),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelError),
                Message:     "Failed to invalidate admin sessions",
            },
            UserID:    userID.String(),
            Status:    "failed",
            ErrorCode: "INVALIDATE_ADMIN_SESSIONS_FAILED",
        })
        return fmt.Errorf("failed to invalidate admin sessions: %w", err)
    }

    s.logSessionEvent(ctx, &models.SessionLogEvent{
        LogEnvelope: models.LogEnvelope{
            EventID:     uuid.New().String(),
            EventType:   string(models.LogEventTypeSession),
            ServiceName: "auth-service",
            Timestamp:   time.Now(),
            Environment: s.config.Environment,
            Version:     ServiceVersion,
            Level:       string(models.LogLevelInfo),
            Message:     "Admin sessions invalidated",
        },
        UserID: userID.String(),
        Status: "admin_sessions_invalidated",
    })

    s.logger.Info("All admin sessions invalidated",
        util.String("user_id", userID.String()),
        util.Duration("duration", time.Since(startTime)),
    )

    return nil
}

// GetActiveAdminSessionsCount gets count of active admin sessions
func (s *SessionService) GetActiveAdminSessionsCount(ctx context.Context, userID uuid.UUID) (int, error) {
    count, err := s.sessionRepo.GetActiveAdminSessionsCount(ctx, userID)
    if err != nil {
        s.logSessionEvent(ctx, &models.SessionLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeSession),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelError),
                Message:     "Failed to get admin session count",
            },
            UserID:    userID.String(),
            Status:    "failed",
            ErrorCode: "GET_ADMIN_COUNT_FAILED",
        })
        return 0, fmt.Errorf("failed to get admin session count: %w", err)
    }
    return count, nil
}

// LogoutAdminSessions is an alias for InvalidateAdminSessions
func (s *SessionService) LogoutAdminSessions(ctx context.Context, userID uuid.UUID) error {
    return s.InvalidateAdminSessions(ctx, userID)
}

// HealthCheck performs health check
func (s *SessionService) HealthCheck(ctx context.Context) error {
    return s.sessionRepo.HealthCheck(ctx)
}

// GetSessionStats gets session statistics
func (s *SessionService) GetSessionStats(ctx context.Context) (map[string]interface{}, error) {
    stats, err := s.sessionRepo.GetRepositoryStats(ctx)
    if err != nil {
        s.logSessionEvent(ctx, &models.SessionLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeSession),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelError),
                Message:     "Failed to get session stats",
            },
            Status:    "failed",
            ErrorCode: "GET_STATS_FAILED",
        })
        return nil, fmt.Errorf("failed to get session stats: %w", err)
    }

    // Add session type breakdown to stats
    stats["session_types"] = map[string]interface{}{
        "user_sessions":  "tracked_separately",
        "admin_sessions": "tracked_separately",
        "admin_ttl_days": 7,
        "user_ttl_days":  30,
    }

    return stats, nil
}

// generateSessionToken generates a secure session token
func (s *SessionService) generateSessionToken() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(b), nil
}

// SetLogProducerService sets Kafka log producer service
func (s *SessionService) SetLogProducerService(logProducer *LogProducerService) {
    s.logProducer = logProducer
}

func (s *SessionService) GetAccessTokenDataByJTI(ctx context.Context, jti string) (*models.AccessTokenData, error) {
    data, err := s.sessionRepo.GetAccessToken(ctx, jti)
    if err != nil {
        return nil, err
    }
    return data, nil
}