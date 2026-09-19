package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"auth-service/internal/client"
	"auth-service/internal/config"
	appErrors "auth-service/internal/errors"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/models"
	"auth-service/internal/repository/postgres"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWTService handles JWT token creation, validation, and refresh token generation.
type JWTService struct {
	pgClient     *client.PostgresClient
	config       *config.Config
	companyRepo  postgres.CompanyRepository
	adminRepo    postgres.AdminRepository
	auditService *audit.AuditService
	locationRepo postgres.LocationRepository
}

// NewJWTService creates a new JWTService with audit capability.
// NOTE: `pgClient` is a new first parameter — update the wire/main call site.
func NewJWTService(
	pgClient *client.PostgresClient,
	cfg *config.Config,
	companyRepo postgres.CompanyRepository,
	adminRepo postgres.AdminRepository,
	auditService *audit.AuditService,
	locationRepo postgres.LocationRepository,
) *JWTService {
	return &JWTService{
		pgClient:     pgClient,
		config:       cfg,
		companyRepo:  companyRepo,
		adminRepo:    adminRepo,
		auditService: auditService,
		locationRepo: locationRepo,
	}
}

// CreateAccessTokenRequest holds parameters for access token creation.
type CreateAccessTokenRequest struct {
	UserID            string
	Role              string
	DeviceID          string
	SessionType       string
	CompanyID         string
	IPAddress         string
	PermissionMask    []uint64
	PrimaryLocationID string
	LocationScope     string
}

// CreateAccessToken generates a new JWT access token with the given claims.
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

	ip, _ := ctx.Value("ip_address").(string)
	if ip == "" && req.IPAddress != "" {
		ip = req.IPAddress
	}

	jti := uuid.NewString()
	now := time.Now()

	var permissionMask []uint64

	if req.PermissionMask != nil {
		permissionMask = req.PermissionMask
	} else {
		switch req.SessionType {
		case "admin":
			adminID, err := uuid.Parse(req.UserID)
			if err != nil {
				return "", "", fmt.Errorf("%w: invalid admin ID format", appErrors.ErrInvalidInput)
			}
			mask, err := s.adminRepo.GetAdminPermissionBitmask(ctx, adminID)
			if err != nil {
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
				permissionMask = make([]uint64, 13)
			} else {
				permissionMask = mask
			}
		default:
			permissionMask = make([]uint64, 13)
		}
	}

	if len(permissionMask) < 13 {
		fullMask := make([]uint64, 13)
		copy(fullMask, permissionMask)
		permissionMask = fullMask
	}

	// ──────────────────────────────────────────────────────────────────────────────
	// FETCH LOCATION DETAILS FOR USER SESSIONS
	// Uses s.pgClient.Pool() — this is a read-only lookup outside any transaction.
	// ──────────────────────────────────────────────────────────────────────────────
	var primaryLocationID string
	var locationScope string

	if req.SessionType == "user" {
		if req.PrimaryLocationID != "" && req.LocationScope != "" {
			primaryLocationID = req.PrimaryLocationID
			locationScope = req.LocationScope
		} else {
			companyID, _ := uuid.Parse(req.CompanyID)
			userID, _ := uuid.Parse(req.UserID)

			loc, err := s.locationRepo.GetEmployeeLocationDetails(ctx, s.pgClient.Pool(), companyID, userID)
			if err != nil {
				if errors.Is(err, appErrors.ErrNotFound) {
					locationScope = "ALL"
				} else {
					locationScope = "ALL"
				}
			} else if loc != nil {
				if loc.PrimaryLocationID != uuid.Nil {
					primaryLocationID = loc.PrimaryLocationID.String()
				}
				locationScope = loc.LocationScope
			} else {
				locationScope = "ALL"
			}
		}
	}

	claims := &models.JWTClaims{
		UserID:            req.UserID,
		Role:              req.Role,
		DeviceID:          req.DeviceID,
		SessionType:       req.SessionType,
		CompanyID:         req.CompanyID,
		JTI:               jti,
		IssuedAt:          now.Unix(),
		ExpiresAt:         now.Add(s.config.JWT.AccessTTL).Unix(),
		PermissionMask:    permissionMask,
		PrimaryLocationID: primaryLocationID,
		LocationScope:     locationScope,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(s.config.JWT.Secret))
	if err != nil {
		return "", "", fmt.Errorf("%w: failed to sign token", appErrors.ErrInternal)
	}

	if s.auditService != nil {
		actorID, _ := uuid.Parse(req.UserID)
		_ = s.auditService.LogAction(ctx, nil, nil, "jwt", "create_access_token", "session",
			nil, req.SessionType, &actorID, nil, nil, map[string]interface{}{
				"jti":                 jti,
				"device_id":           req.DeviceID,
				"session_type":        req.SessionType,
				"role":                req.Role,
				"company_id":          req.CompanyID,
				"primary_location_id": primaryLocationID,
				"location_scope":      locationScope,
				"ip_address":          ip,
				"expires_at":          claims.ExpiresAt,
			})
	}

	return signed, jti, nil
}

// ValidateAccessToken parses and validates a JWT token string.
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
func (s *JWTService) CreateTokenPair(ctx context.Context, req *CreateAccessTokenRequest) (*models.TokenPairResponse, error) {
	accessToken, jti, err := s.CreateAccessToken(ctx, req)
	if err != nil {
		return nil, err
	}
	refreshToken, err := s.GenerateRefreshToken()
	if err != nil {
		return nil, err
	}

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
