package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"auth-service/internal/config"
	"auth-service/internal/models"
	"auth-service/internal/repository/postgres"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type JWTService struct {
	config      *config.Config
	companyRepo postgres.CompanyRepository
	adminRepo   postgres.AdminRepository
	logger      *zap.Logger
}

func NewJWTService(
	cfg *config.Config,
	companyRepo postgres.CompanyRepository,
	adminRepo postgres.AdminRepository,
	logger *zap.Logger,
) *JWTService {
	return &JWTService{
		config:      cfg,
		companyRepo: companyRepo,
		adminRepo:   adminRepo,
		logger:      logger,
	}
}

type CreateAccessTokenRequest struct {
	UserID         string
	Role           string
	DeviceID       string
	SessionType    string
	CompanyID      string
	IPAddress      string
	PermissionMask []uint64
}

func (s *JWTService) CreateAccessToken(ctx context.Context, req *CreateAccessTokenRequest) (string, string, error) {
	if req.UserID == "" {
		return "", "", fmt.Errorf("user ID is required")
	}
	if req.DeviceID == "" {
		return "", "", fmt.Errorf("device ID is required")
	}
	if req.SessionType == "" {
		return "", "", fmt.Errorf("session type is required")
	}
	if req.Role == "" {
		return "", "", fmt.Errorf("role is required")
	}

	jti := uuid.NewString()
	now := time.Now()

	var permissionMask []uint64

	// Use provided permission mask if given
	if req.PermissionMask != nil {
		permissionMask = req.PermissionMask
		s.logger.Info("Using provided permission mask",
			zap.String("user_id", req.UserID),
			zap.String("session_type", req.SessionType),
			zap.Int("mask_segments", len(permissionMask)))
	} else {
		// Fallback to fetching based on session type
		switch req.SessionType {
		case "admin":
			adminID, err := uuid.Parse(req.UserID)
			if err != nil {
				return "", "", fmt.Errorf("invalid admin ID format: %w", err)
			}
			mask, err := s.adminRepo.GetAdminPermissionBitmask(ctx, adminID)
			if err != nil {
				s.logger.Warn("Failed to get admin permission mask, using full access",
					zap.String("admin_id", req.UserID),
					zap.Error(err))
				permissionMask = models.CreateFullPermissionMask()
			} else {
				permissionMask = mask
			}
			s.logger.Info("🔐 ADMIN session token created",
				zap.String("admin_id", req.UserID),
				zap.String("role", req.Role),
				zap.Int("mask_segments", len(permissionMask)),
				zap.Any("permission_mask", permissionMask))

		case "user":
			userID, err := uuid.Parse(req.UserID)
			if err != nil {
				return "", "", fmt.Errorf("invalid user ID format: %w", err)
			}
			if req.CompanyID == "" {
				return "", "", fmt.Errorf("company ID is required for user sessions")
			}
			companyID, err := uuid.Parse(req.CompanyID)
			if err != nil {
				return "", "", fmt.Errorf("invalid company ID format: %w", err)
			}
			s.logger.Info("🔍 Fetching USER permission bitmask",
				zap.String("user_id", req.UserID),
				zap.String("company_id", req.CompanyID),
				zap.String("session_type", req.SessionType),
				zap.String("role", req.Role))
			mask, err := s.companyRepo.GetUserPermissionBitmask(ctx, companyID, userID)
			if err != nil {
				s.logger.Warn("⚠️ Failed to get user permission mask, using empty mask",
					zap.String("user_id", req.UserID),
					zap.String("company_id", req.CompanyID),
					zap.Error(err))
				permissionMask = []uint64{0, 0, 0, 0}
			} else {
				permissionMask = mask
				s.logger.Info("✅ User permission mask retrieved",
					zap.String("user_id", req.UserID),
					zap.String("company_id", req.CompanyID),
					zap.Int("mask_segments", len(permissionMask)))
			}

		default:
			// For other session types like "student", use empty permission mask
			permissionMask = []uint64{}
			s.logger.Info("Using empty permission mask for session type",
				zap.String("user_id", req.UserID),
				zap.String("session_type", req.SessionType))
		}
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
		return "", "", fmt.Errorf("failed to sign token: %w", err)
	}

	s.logger.Info("🎫 JWT access token created",
		zap.String("user_id", req.UserID),
		zap.String("session_type", req.SessionType),
		zap.String("company_id", req.CompanyID),
		zap.String("role", req.Role),
		zap.String("jti", jti),
		zap.Int64("expires_at", claims.ExpiresAt))

	return signed, jti, nil
}

func (s *JWTService) ValidateAccessToken(ctx context.Context, tokenStr string) (*models.JWTClaims, error) {
	if tokenStr == "" {
		return nil, fmt.Errorf("token string is empty")
	}

	token, err := jwt.ParseWithClaims(tokenStr, &models.JWTClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(s.config.JWT.Secret), nil
	})
	if err != nil {
		s.logger.Warn("JWT token parse failed", zap.Error(err))
		return nil, fmt.Errorf("token parse error: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*models.JWTClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	if claims.UserID == "" {
		return nil, fmt.Errorf("token missing user ID")
	}
	if claims.SessionType == "" {
		return nil, fmt.Errorf("token missing session type")
	}
	if claims.Role == "" {
		return nil, fmt.Errorf("token missing role")
	}
	if claims.SessionType != "admin" && claims.CompanyID == "" {
		return nil, fmt.Errorf("non-admin token missing company ID")
	}

	s.logger.Debug("JWT token validated successfully",
		zap.String("user_id", claims.UserID),
		zap.String("session_type", claims.SessionType),
		zap.String("role", claims.Role),
		zap.String("jti", claims.JTI))

	return claims, nil
}

func (s *JWTService) GenerateRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func (s *JWTService) CreateTokenPair(ctx context.Context, req *CreateAccessTokenRequest) (*models.TokenPairResponse, error) {
	accessToken, _, err := s.CreateAccessToken(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create access token: %w", err)
	}
	refreshToken, err := s.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}
	return &models.TokenPairResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(s.config.JWT.AccessTTL.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

func (s *JWTService) VerifyTokenExpiration(claims *models.JWTClaims) bool {
	now := time.Now().Unix()
	return claims.ExpiresAt > now
}
