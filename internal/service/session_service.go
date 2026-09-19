package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/client"
	"auth-service/internal/config"
	appErrors "auth-service/internal/errors"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/models"
	"auth-service/internal/repository/postgres"
	"auth-service/internal/repository/redis"
)

// SessionService handles session management, JWT issuance, and token lifecycle.
type SessionService struct {
	sessionRepo  redis.SessionRepository
	config       *config.Config
	jwtService   *JWTService
	companyRepo  postgres.CompanyRepository
	auditService *audit.AuditService
	locationRepo postgres.LocationRepository
	pgClient     *client.PostgresClient // 🆕 for DBTX pool access
}

// NewSessionService creates a new session service.
func NewSessionService(
	sessionRepo redis.SessionRepository,
	config *config.Config,
	jwtService *JWTService,
	companyRepo postgres.CompanyRepository,
	auditService *audit.AuditService,
	locationRepo postgres.LocationRepository,
	pgClient *client.PostgresClient, // 🆕
) *SessionService {
	return &SessionService{
		sessionRepo:  sessionRepo,
		config:       config,
		jwtService:   jwtService,
		companyRepo:  companyRepo,
		auditService: auditService,
		locationRepo: locationRepo,
		pgClient:     pgClient, // 🆕
	}
}

// --------------------------------------------------------------------
// REQUEST / RESPONSE TYPES
// --------------------------------------------------------------------

type CreateSessionRequest struct {
	UserID            uuid.UUID `json:"user_id" validate:"required"`
	DeviceID          string    `json:"device_id" validate:"required"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	KYCVerified       bool      `json:"kyc_verified"`
	IPAddress         string    `json:"ip_address"`
	SessionType       string    `json:"session_type" validate:"oneof=user admin"`
}

type CreateAdminSessionRequest struct {
	AdminID           uuid.UUID `json:"admin_id" validate:"required"`
	Role              string    `json:"role" validate:"required,oneof=super_admin admin_manager admin_employee"`
	DeviceID          string    `json:"device_id" validate:"required"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	IPAddress         string    `json:"ip_address"`
	PermissionMask    []uint64  `json:"permission_mask"`
}

// IssueTokenPairRequest now includes location fields
type IssueTokenPairRequest struct {
	UserID            string
	Role              string
	DeviceID          string
	SessionType       string
	IPAddress         string
	CompanyID         string
	PermissionMask    []uint64
	PrimaryLocationID string
	LocationScope     string
}

// --------------------------------------------------------------------
// TOKEN ISSUANCE
// --------------------------------------------------------------------

func (s *SessionService) IssueTokenPair(ctx context.Context, req *IssueTokenPairRequest) (*models.TokenPairResponse, error) {
	ip, _ := ctx.Value("ip_address").(string)
	if ip == "" {
		ip = req.IPAddress
	}

	if req.UserID == "" || req.DeviceID == "" || req.Role == "" {
		return nil, appErrors.ErrInvalidInput
	}

	// Generate JWT Access Token – pass location fields
	accessToken, jti, err := s.jwtService.CreateAccessToken(ctx, &CreateAccessTokenRequest{
		UserID:            req.UserID,
		Role:              req.Role,
		DeviceID:          req.DeviceID,
		SessionType:       req.SessionType,
		CompanyID:         req.CompanyID,
		PermissionMask:    req.PermissionMask,
		PrimaryLocationID: req.PrimaryLocationID,
		LocationScope:     req.LocationScope,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create access token", appErrors.ErrInternal)
	}

	// Store Access Token in Redis
	now := time.Now().UTC()
	accessData := &models.AccessTokenData{
		JTI:         jti,
		UserID:      req.UserID,
		DeviceID:    req.DeviceID,
		CompanyID:   req.CompanyID,
		SessionType: req.SessionType,
		Active:      true,
		ExpiresAt:   now.Add(s.config.JWT.AccessTTL),
		IPAddress:   ip,
	}
	if err := s.sessionRepo.StoreAccessToken(ctx, accessData); err != nil {
		return nil, fmt.Errorf("%w: failed to store access token", appErrors.ErrInternal)
	}

	// Generate Refresh Token
	refreshToken, err := s.jwtService.GenerateRefreshToken()
	if err != nil {
		_ = s.sessionRepo.DeleteAccessToken(ctx, jti)
		return nil, fmt.Errorf("%w: failed to generate refresh token", appErrors.ErrInternal)
	}

	// Store Refresh Token
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
		IPAddress:   ip,
		JTI:         jti,
	}
	if err := s.sessionRepo.StoreRefreshToken(ctx, refreshData); err != nil {
		_ = s.sessionRepo.DeleteAccessToken(ctx, jti)
		return nil, fmt.Errorf("%w: failed to store refresh token", appErrors.ErrInternal)
	}

	// Audit
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "session", "issue_token_pair", "user",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"user_id":        req.UserID,
				"session_type":   req.SessionType,
				"role":           req.Role,
				"device_id":      req.DeviceID,
				"company_id":     req.CompanyID,
				"primary_loc":    req.PrimaryLocationID,
				"location_scope": req.LocationScope,
				"ip":             ip,
			})
	}

	return &models.TokenPairResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(s.config.JWT.AccessTTL.Seconds()),
		TokenType:    "Bearer",
		CompanyID:    req.CompanyID,
	}, nil
}

// --------------------------------------------------------------------
// REFRESH TOKEN
// --------------------------------------------------------------------

func (s *SessionService) RefreshTokenPair(ctx context.Context, refreshToken string, ipAddress string) (*models.TokenPairResponse, error) {
	ip, _ := ctx.Value("ip_address").(string)
	if ip == "" {
		ip = ipAddress
	}

	refreshData, err := s.sessionRepo.GetRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid refresh token", appErrors.ErrUnauthorized)
	}
	if refreshData.Revoked {
		return nil, appErrors.ErrUnauthorized
	}
	if time.Now().After(refreshData.ExpiresAt) {
		return nil, appErrors.ErrUnauthorized
	}

	// Update last used
	refreshData.LastUsed = time.Now().UTC()
	_ = s.sessionRepo.StoreRefreshToken(ctx, refreshData)

	// Delete old access token
	if refreshData.JTI != "" {
		_ = s.sessionRepo.DeleteAccessToken(ctx, refreshData.JTI)
	}

	// Optionally rotate refresh token
	if s.config.JWT.RotateRefreshTokens {
		_ = s.sessionRepo.DeleteRefreshToken(ctx, refreshToken)
	}

	// Get permission mask if admin
	var permMask []uint64
	if refreshData.SessionType == "admin" {
		// In production, fetch from DB or session store
		permMask = []uint64{}
	}

	// Fetch fresh location details for user sessions
	var primaryLoc string
	var scope string
	if refreshData.SessionType == "user" {
		companyID, _ := uuid.Parse(refreshData.CompanyID)
		userID, _ := uuid.Parse(refreshData.UserID)
		// ✅ CHANGED: pass s.pgClient.Pool() as the DBTX argument
		loc, err := s.locationRepo.GetEmployeeLocationDetails(ctx, s.pgClient.Pool(), companyID, userID)
		if err == nil && loc != nil {
			if loc.PrimaryLocationID != uuid.Nil {
				primaryLoc = loc.PrimaryLocationID.String()
			}
			scope = loc.LocationScope
		} else {
			// Default to ALL if not found
			scope = "ALL"
		}
	}

	// Issue new pair with fresh location data
	newReq := &IssueTokenPairRequest{
		UserID:            refreshData.UserID,
		Role:              refreshData.SessionType, // adjust if you store actual role separately
		DeviceID:          refreshData.DeviceID,
		SessionType:       refreshData.SessionType,
		IPAddress:         ip,
		CompanyID:         refreshData.CompanyID,
		PermissionMask:    permMask,
		PrimaryLocationID: primaryLoc,
		LocationScope:     scope,
	}
	resp, err := s.IssueTokenPair(ctx, newReq)
	if err != nil {
		return nil, err
	}

	// Audit refresh
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "session", "refresh_token", "user",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"user_id": refreshData.UserID,
				"ip":      ip,
			})
	}

	return resp, nil
}

// --------------------------------------------------------------------
// TOKEN VALIDATION
// --------------------------------------------------------------------

func (s *SessionService) ValidateAccessToken(ctx context.Context, tokenStr string) (*models.JWTClaims, error) {
	claims, err := s.jwtService.ValidateAccessToken(ctx, tokenStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid JWT", appErrors.ErrUnauthorized)
	}

	accessData, err := s.sessionRepo.GetAccessToken(ctx, claims.JTI)
	if err != nil {
		return nil, fmt.Errorf("%w: access token not found", appErrors.ErrUnauthorized)
	}
	if !accessData.Active {
		return nil, fmt.Errorf("%w: access token revoked", appErrors.ErrUnauthorized)
	}
	if accessData.DeviceID != claims.DeviceID {
		return nil, fmt.Errorf("%w: device mismatch", appErrors.ErrUnauthorized)
	}

	// For user sessions, validate company ID
	if claims.SessionType == "user" {
		if accessData.CompanyID != claims.CompanyID || accessData.CompanyID == "" {
			return nil, fmt.Errorf("%w: company mismatch", appErrors.ErrUnauthorized)
		}
	}

	return claims, nil
}

// --------------------------------------------------------------------
// REVOCATION
// --------------------------------------------------------------------

func (s *SessionService) RevokeAccessToken(ctx context.Context, jti string) error {
	ip, _ := ctx.Value("ip_address").(string)

	if err := s.sessionRepo.DeleteAccessToken(ctx, jti); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "session", "revoke_access_token", "access_token",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"jti": jti,
				"ip":  ip,
			})
	}
	return nil
}

func (s *SessionService) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	ip, _ := ctx.Value("ip_address").(string)

	refreshData, err := s.sessionRepo.GetRefreshToken(ctx, refreshToken)
	if err == nil && refreshData.JTI != "" {
		_ = s.sessionRepo.DeleteAccessToken(ctx, refreshData.JTI)
	}
	if err := s.sessionRepo.DeleteRefreshToken(ctx, refreshToken); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "session", "revoke_refresh_token", "refresh_token",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"ip": ip,
			})
	}
	return nil
}

func (s *SessionService) RevokeAllUserRefreshTokens(ctx context.Context, userID string) error {
	ip, _ := ctx.Value("ip_address").(string)

	tokens, err := s.sessionRepo.GetUserRefreshTokens(ctx, userID)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	for _, rt := range tokens {
		_ = s.RevokeRefreshToken(ctx, rt)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "session", "revoke_all_user_tokens", "user",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"user_id": userID,
				"count":   len(tokens),
				"ip":      ip,
			})
	}
	return nil
}

// --------------------------------------------------------------------
// LEGACY SESSION METHODS (unchanged)
// --------------------------------------------------------------------

func (s *SessionService) CreateSession(ctx context.Context, req *CreateSessionRequest) (*models.ActiveSession, error) {
	token, err := s.generateSessionToken()
	if err != nil {
		return nil, fmt.Errorf("%w: failed to generate token", appErrors.ErrInternal)
	}

	var ipAddr net.IP
	if req.IPAddress != "" {
		ipAddr = net.ParseIP(req.IPAddress)
	}
	encKey := make([]byte, 32)
	if _, err := rand.Read(encKey); err != nil {
		return nil, fmt.Errorf("%w: failed to generate encryption key", appErrors.ErrInternal)
	}

	now := time.Now()
	ttl := time.Duration(s.config.Auth.SessionTTL) * time.Second
	if req.SessionType == "admin" {
		ttl = 7 * 24 * time.Hour
	}
	expiresAt := now.Add(ttl)
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
		return nil, fmt.Errorf("%w: failed to create session", appErrors.ErrInternal)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "session", "create_session", "user",
			&req.UserID, "system", nil, nil, nil, map[string]interface{}{
				"device_id":    req.DeviceID,
				"session_type": sessionType,
				"ip":           req.IPAddress,
			})
	}
	return session, nil
}

func (s *SessionService) CreateAdminSession(ctx context.Context, req *CreateAdminSessionRequest) (*models.ActiveSession, error) {
	token, err := s.generateSessionToken()
	if err != nil {
		return nil, fmt.Errorf("%w: failed to generate token", appErrors.ErrInternal)
	}

	var ipAddr net.IP
	if req.IPAddress != "" {
		ipAddr = net.ParseIP(req.IPAddress)
	}
	encKey := make([]byte, 32)
	if _, err := rand.Read(encKey); err != nil {
		return nil, fmt.Errorf("%w: failed to generate encryption key", appErrors.ErrInternal)
	}

	now := time.Now()
	adminTTL := 7 * 24 * time.Hour
	expiresAt := now.Add(adminTTL)

	session := &models.ActiveSession{
		UserID:            req.AdminID.String(),
		SessionToken:      token,
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		CreatedAt:         now,
		LastActivity:      now,
		ExpiresAt:         expiresAt,
		IPAddress:         ipAddr,
		EncryptionKey:     encKey,
		SessionType:       "admin",
		Role:              req.Role,
		PermissionMask:    req.PermissionMask,
	}

	if err := s.sessionRepo.CreateSession(ctx, session); err != nil {
		return nil, fmt.Errorf("%w: failed to create admin session", appErrors.ErrInternal)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "session", "create_admin_session", "admin_user",
			&req.AdminID, "system", nil, nil, nil, map[string]interface{}{
				"role":      req.Role,
				"device_id": req.DeviceID,
				"ip":        req.IPAddress,
			})
	}
	return session, nil
}

// --------------------------------------------------------------------
// SESSION RETRIEVAL
// --------------------------------------------------------------------

func (s *SessionService) GetSessionByUserID(ctx context.Context, userID uuid.UUID) (*models.ActiveSession, error) {
	session, err := s.sessionRepo.GetSessionByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	return session, nil
}

func (s *SessionService) GetSessionByToken(ctx context.Context, sessionToken string) (*models.ActiveSession, error) {
	session, err := s.sessionRepo.GetSessionByToken(ctx, sessionToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	return session, nil
}

func (s *SessionService) GetSessionType(ctx context.Context, sessionToken string) (string, error) {
	sessionType, err := s.sessionRepo.GetSessionType(ctx, sessionToken)
	if err != nil {
		return "", fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return sessionType, nil
}

func (s *SessionService) IsAdminSession(ctx context.Context, sessionToken string) (bool, error) {
	isAdmin, err := s.sessionRepo.IsAdminSession(ctx, sessionToken)
	if err != nil {
		return false, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return isAdmin, nil
}

// --------------------------------------------------------------------
// SESSION INVALIDATION / ACTIVITY
// --------------------------------------------------------------------

func (s *SessionService) UpdateSessionActivity(ctx context.Context, userID uuid.UUID, ipAddress string) error {
	var ipAddr net.IP
	if ipAddress != "" {
		ipAddr = net.ParseIP(ipAddress)
	}
	err := s.sessionRepo.UpdateSessionActivity(ctx, userID, time.Now(), ipAddr)
	if err != nil {
		return err
	}
	return nil
}

func (s *SessionService) InvalidateSession(ctx context.Context, userID uuid.UUID) error {
	ip, _ := ctx.Value("ip_address").(string)

	if err := s.sessionRepo.InvalidateSession(ctx, userID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "session", "invalidate_session", "user",
			&userID, "system", nil, nil, nil, map[string]interface{}{
				"ip": ip,
			})
	}
	return nil
}

func (s *SessionService) InvalidateSessionByToken(ctx context.Context, sessionToken string) error {
	ip, _ := ctx.Value("ip_address").(string)

	if err := s.sessionRepo.InvalidateSessionByToken(ctx, sessionToken); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "session", "invalidate_session_by_token", "session",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"session_token": sessionToken,
				"ip":            ip,
			})
	}
	return nil
}

func (s *SessionService) RefreshSession(ctx context.Context, userID uuid.UUID) (string, error) {
	ip, _ := ctx.Value("ip_address").(string)

	newToken, err := s.generateSessionToken()
	if err != nil {
		return "", fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	expiresAt := time.Now().Add(time.Duration(s.config.Auth.SessionTTL) * time.Second)
	if err := s.sessionRepo.RefreshSession(ctx, userID, newToken, expiresAt); err != nil {
		return "", fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "session", "refresh_session", "user",
			&userID, "system", nil, nil, nil, map[string]interface{}{
				"new_token": newToken,
				"ip":        ip,
			})
	}
	return newToken, nil
}

func (s *SessionService) InvalidateSessionsBatch(ctx context.Context, userIDs []uuid.UUID) error {
	ip, _ := ctx.Value("ip_address").(string)

	if err := s.sessionRepo.InvalidateSessionsBatch(ctx, userIDs); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "session", "invalidate_batch", "user",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"count": len(userIDs),
				"ip":    ip,
			})
	}
	return nil
}

// --------------------------------------------------------------------
// BULK / DEVICE OPERATIONS
// --------------------------------------------------------------------

func (s *SessionService) GetSessionsBatch(ctx context.Context, userIDs []uuid.UUID) ([]*models.ActiveSession, error) {
	return s.sessionRepo.GetSessionsBatch(ctx, userIDs)
}

func (s *SessionService) CleanupExpiredSessions(ctx context.Context, batchSize int) (int, error) {
	if batchSize <= 0 {
		batchSize = 1000
	}
	count, err := s.sessionRepo.CleanupExpiredSessions(ctx, batchSize)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if count > 0 && s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "session", "cleanup_expired", "system",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"deleted_count": count,
			})
	}
	return count, nil
}

func (s *SessionService) GetSessionsByDevice(ctx context.Context, deviceID string, limit int) ([]*models.ActiveSession, error) {
	return s.sessionRepo.GetSessionsByDevice(ctx, deviceID, limit)
}

func (s *SessionService) InvalidateDeviceSessions(ctx context.Context, deviceID string) error {
	ip, _ := ctx.Value("ip_address").(string)

	if err := s.sessionRepo.InvalidateDeviceSessions(ctx, deviceID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "session", "invalidate_device", "device",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"device_id": deviceID,
				"ip":        ip,
			})
	}
	return nil
}

// --------------------------------------------------------------------
// ADMIN SESSION SPECIFIC METHODS
// --------------------------------------------------------------------

func (s *SessionService) GetAdminSessions(ctx context.Context, userID uuid.UUID) ([]*models.ActiveSession, error) {
	sessions, err := s.sessionRepo.GetAdminSessions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return sessions, nil
}

func (s *SessionService) InvalidateAdminSessions(ctx context.Context, userID uuid.UUID) error {
	ip, _ := ctx.Value("ip_address").(string)

	if err := s.sessionRepo.InvalidateAdminSessions(ctx, userID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "session", "invalidate_admin_sessions", "admin_user",
			&userID, "system", nil, nil, nil, map[string]interface{}{
				"ip": ip,
			})
	}
	return nil
}

func (s *SessionService) LogoutAdminSessions(ctx context.Context, userID uuid.UUID) error {
	return s.InvalidateAdminSessions(ctx, userID)
}

func (s *SessionService) GetActiveAdminSessionsCount(ctx context.Context, userID uuid.UUID) (int, error) {
	count, err := s.sessionRepo.GetActiveAdminSessionsCount(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return count, nil
}

// --------------------------------------------------------------------
// STATS & HEALTH
// --------------------------------------------------------------------

func (s *SessionService) HealthCheck(ctx context.Context) error {
	return s.sessionRepo.HealthCheck(ctx)
}

func (s *SessionService) GetSessionStats(ctx context.Context) (map[string]interface{}, error) {
	stats, err := s.sessionRepo.GetRepositoryStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	stats["session_types"] = map[string]interface{}{
		"user_sessions":  "tracked_separately",
		"admin_sessions": "tracked_separately",
		"admin_ttl_days": 7,
		"user_ttl_days":  30,
	}
	return stats, nil
}

// --------------------------------------------------------------------
// HELPERS
// --------------------------------------------------------------------

func (s *SessionService) generateSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func (s *SessionService) GetAccessTokenDataByJTI(ctx context.Context, jti string) (*models.AccessTokenData, error) {
	return s.sessionRepo.GetAccessToken(ctx, jti)
}
