package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"auth-service/internal/config"
	appErrors "auth-service/internal/errors"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/models"
	"auth-service/internal/repository/postgres"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWTService handles JWT token creation, validation, and refresh token generation.
// It uses audit logging for token operations and does not use zap logger.
type JWTService struct {
	config       *config.Config
	companyRepo  postgres.CompanyRepository
	adminRepo    postgres.AdminRepository
	auditService *audit.AuditService
}

// NewJWTService creates a new JWTService with audit capability.
func NewJWTService(
	cfg *config.Config,
	companyRepo postgres.CompanyRepository,
	adminRepo postgres.AdminRepository,
	auditService *audit.AuditService,
) *JWTService {
	return &JWTService{
		config:       cfg,
		companyRepo:  companyRepo,
		adminRepo:    adminRepo,
		auditService: auditService,
	}
}

// CreateAccessTokenRequest holds parameters for access token creation.
type CreateAccessTokenRequest struct {
	UserID         string
	Role           string
	DeviceID       string
	SessionType    string
	CompanyID      string
	IPAddress      string
	PermissionMask []uint64
}

// CreateAccessToken generates a new JWT access token with the given claims.
// It validates required fields and builds a permission mask if not provided.
func (s *JWTService) CreateAccessToken(ctx context.Context, req *CreateAccessTokenRequest) (string, string, error) {
	if req.UserID == "" {
		return "", "", appErrors.ErrInvalidInput
	}
	if req.DeviceID == "" {
		return "", "", appErrors.ErrInvalidInput
	}
	if req.SessionType == "" {
		return "", "", appErrors.ErrInvalidInput
	}
	if req.Role == "" {
		return "", "", appErrors.ErrInvalidInput
	}

	// Extract IP from context if not provided in request
	ip, _ := ctx.Value("ip_address").(string)
	if ip == "" && req.IPAddress != "" {
		ip = req.IPAddress
	}

	jti := uuid.NewString()
	now := time.Now()

	var permissionMask []uint64

	// Use provided permission mask if given
	if req.PermissionMask != nil {
		permissionMask = req.PermissionMask
	} else {
		// Fallback to fetching based on session type
		switch req.SessionType {
		case "admin":
			adminID, err := uuid.Parse(req.UserID)
			if err != nil {
				return "", "", fmt.Errorf("%w: invalid admin ID format", appErrors.ErrInvalidInput)
			}
			mask, err := s.adminRepo.GetAdminPermissionBitmask(ctx, adminID)
			if err != nil {
				// On error, use full access mask (13 blocks)
				permissionMask = models.CreateFullPermissionMask()
			} else {
				permissionMask = mask
			}
		case "user":
			if req.CompanyID == "" {
				return "", "", fmt.Errorf("%w: company ID required for user session", appErrors.ErrInvalidInput)
			}
			userID, err := uuid.Parse(req.UserID)
			if err != nil {
				return "", "", fmt.Errorf("%w: invalid user ID format", appErrors.ErrInvalidInput)
			}
			companyID, err := uuid.Parse(req.CompanyID)
			if err != nil {
				return "", "", fmt.Errorf("%w: invalid company ID format", appErrors.ErrInvalidInput)
			}
			mask, err := s.companyRepo.GetUserPermissionBitmask(ctx, companyID, userID)
			if err != nil {
				// On error, use empty mask (13 zeros)
				permissionMask = make([]uint64, 13)
			} else {
				permissionMask = mask
			}
		default:
			// For other session types, use empty mask (13 blocks)
			permissionMask = make([]uint64, 13)
		}
	}

	// Normalise mask to exactly 13 blocks
	if len(permissionMask) < 13 {
		fullMask := make([]uint64, 13)
		copy(fullMask, permissionMask)
		permissionMask = fullMask
	}

	claims := &models.JWTClaims{
		UserID:         req.UserID,
		Role:           req.Role,
		DeviceID:       req.DeviceID,
		SessionType:    req.SessionType,
		CompanyID:      req.CompanyID,
		JTI:            jti,
		IssuedAt:       now.Unix(),
		ExpiresAt:      now.Add(s.config.JWT.AccessTTL).Unix(),
		PermissionMask: permissionMask,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(s.config.JWT.Secret))
	if err != nil {
		return "", "", fmt.Errorf("%w: failed to sign token", appErrors.ErrInternal)
	}

	// Audit log for token creation
	if s.auditService != nil {
		actorID, _ := uuid.Parse(req.UserID)
		_ = s.auditService.LogAction(ctx, nil, nil, "jwt", "create_access_token", "session",
			nil, req.SessionType, &actorID, nil, nil, map[string]interface{}{
				"jti":          jti,
				"device_id":    req.DeviceID,
				"session_type": req.SessionType,
				"role":         req.Role,
				"company_id":   req.CompanyID,
				"ip_address":   ip,
				"expires_at":   claims.ExpiresAt,
			})
	}

	return signed, jti, nil
}

// ValidateAccessToken parses and validates a JWT token string.
// It returns the claims if valid, or an error.
func (s *JWTService) ValidateAccessToken(ctx context.Context, tokenStr string) (*models.JWTClaims, error) {
	if tokenStr == "" {
		return nil, appErrors.ErrInvalidInput
	}

	token, err := jwt.ParseWithClaims(tokenStr, &models.JWTClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(s.config.JWT.Secret), nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: token parse failed", appErrors.ErrUnauthorized)
	}
	if !token.Valid {
		return nil, fmt.Errorf("%w: invalid token", appErrors.ErrUnauthorized)
	}

	claims, ok := token.Claims.(*models.JWTClaims)
	if !ok {
		return nil, fmt.Errorf("%w: invalid claims", appErrors.ErrUnauthorized)
	}

	if claims.UserID == "" || claims.SessionType == "" || claims.Role == "" {
		return nil, fmt.Errorf("%w: missing required claims", appErrors.ErrUnauthorized)
	}
	if claims.SessionType != "admin" && claims.CompanyID == "" {
		return nil, fmt.Errorf("%w: non-admin token missing company ID", appErrors.ErrUnauthorized)
	}

	// Audit log for validation success (only if claims are valid)
	if s.auditService != nil {
		actorID, _ := uuid.Parse(claims.UserID)
		ip, _ := ctx.Value("ip_address").(string)
		_ = s.auditService.LogAction(ctx, nil, nil, "jwt", "validate_access_token", "session",
			nil, claims.SessionType, &actorID, nil, nil, map[string]interface{}{
				"jti":          claims.JTI,
				"user_id":      claims.UserID,
				"session_type": claims.SessionType,
				"ip_address":   ip,
				"valid":        true,
			})
	}

	return claims, nil
}

// GenerateRefreshToken creates a cryptographically secure refresh token (hex string).
func (s *JWTService) GenerateRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("%w: failed to generate random token", appErrors.ErrInternal)
	}
	return hex.EncodeToString(b), nil
}

// CreateTokenPair generates both an access token and a refresh token.
// It uses CreateAccessToken internally and adds audit logging for the pair creation.
func (s *JWTService) CreateTokenPair(ctx context.Context, req *CreateAccessTokenRequest) (*models.TokenPairResponse, error) {
	accessToken, jti, err := s.CreateAccessToken(ctx, req)
	if err != nil {
		return nil, err
	}
	refreshToken, err := s.GenerateRefreshToken()
	if err != nil {
		return nil, err
	}

	// Audit log for token pair creation
	if s.auditService != nil {
		actorID, _ := uuid.Parse(req.UserID)
		ip, _ := ctx.Value("ip_address").(string)
		if ip == "" && req.IPAddress != "" {
			ip = req.IPAddress
		}
		_ = s.auditService.LogAction(ctx, nil, nil, "jwt", "create_token_pair", "session",
			nil, req.SessionType, &actorID, nil, nil, map[string]interface{}{
				"jti":          jti,
				"device_id":    req.DeviceID,
				"session_type": req.SessionType,
				"role":         req.Role,
				"company_id":   req.CompanyID,
				"ip_address":   ip,
			})
	}

	return &models.TokenPairResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(s.config.JWT.AccessTTL.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

// VerifyTokenExpiration checks if the token claims are still valid based on expiry.
func (s *JWTService) VerifyTokenExpiration(claims *models.JWTClaims) bool {
	if claims == nil {
		return false
	}
	return claims.ExpiresAt > time.Now().Unix()
}
