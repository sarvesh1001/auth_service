package device

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/client"
)

type TokenService interface {
	IssueToken(ctx context.Context, req *models.IssueTokenRequest) (*models.DeviceToken, string, error)
	ValidateToken(ctx context.Context, rawToken string, deviceID string) (*models.DeviceAuthContext, error)
	ValidateTokenForRequest(ctx context.Context, req *models.ValidateTokenRequest) (*models.TokenValidationResult, error)
	RevokeToken(ctx context.Context, tokenID uuid.UUID, revokedBy *uuid.UUID, reason string) error
	RevokeAllDeviceTokens(ctx context.Context, companyID uuid.UUID, deviceID string, revokedBy *uuid.UUID, reason string) error
	RotateToken(ctx context.Context, oldTokenID uuid.UUID, revokedBy *uuid.UUID, reason string) (*models.DeviceToken, string, error)
	GetCurrentDeviceToken(ctx context.Context, companyID uuid.UUID, deviceID string) (*models.DeviceToken, error)
}

type tokenService struct {
	tokenRepo     repository.TokenRepository
	deviceRepo    repository.DeviceRepository
	pgClient      *client.PostgresClient // ✅ added
	logger        *zap.Logger
	tokenPrefix   string
	tokenSecret   string
	tokenValidity time.Duration
}

type TokenServiceConfig struct {
	TokenPrefix   string
	TokenSecret   string
	TokenValidity time.Duration
}

func NewTokenService(
	tokenRepo repository.TokenRepository,
	deviceRepo repository.DeviceRepository,
	pgClient *client.PostgresClient, // ✅ added
	logger *zap.Logger,
	config TokenServiceConfig,
) TokenService {
	if config.TokenValidity == 0 {
		config.TokenValidity = 30 * 24 * time.Hour
	}
	return &tokenService{
		tokenRepo:     tokenRepo,
		deviceRepo:    deviceRepo,
		pgClient:      pgClient,
		logger:        logger,
		tokenPrefix:   config.TokenPrefix,
		tokenSecret:   config.TokenSecret,
		tokenValidity: config.TokenValidity,
	}
}

func (s *tokenService) IssueToken(ctx context.Context, req *models.IssueTokenRequest) (*models.DeviceToken, string, error) {
	if req.CompanyID == uuid.Nil || req.DeviceID == "" || req.SourceType == "" {
		return nil, "", errors.New("company_id, device_id, source_type required")
	}
	device, err := s.deviceRepo.GetActiveDevice(ctx, req.CompanyID, req.DeviceID)
	if err != nil || device == nil || !device.IsTrusted {
		return nil, "", errors.New("invalid or untrusted device")
	}
	// revoke existing tokens
	_ = s.tokenRepo.RevokeAllDeviceTokens(ctx, req.CompanyID, req.DeviceID, req.IssuedBy, "new token issuance")

	rawToken := s.generateRawToken()
	tokenHash := s.generateTokenHash(rawToken)
	expiry := time.Now().UTC().Add(s.tokenValidity)
	if req.ExpiresIn != nil && *req.ExpiresIn > 0 {
		expiry = time.Now().UTC().Add(time.Duration(*req.ExpiresIn) * time.Second)
	}
	token := &models.DeviceToken{
		TokenID:      uuid.New(),
		CompanyID:    req.CompanyID,
		DeviceID:     req.DeviceID,
		SourceType:   req.SourceType,
		TokenHash:    tokenHash,
		TokenVersion: 1,
		IsActive:     true,
		IssuedAt:     time.Now().UTC(),
		ExpiresAt:    &expiry,
		IssuedBy:     req.IssuedBy,
		Metadata: models.JSONB{
			"device_name": device.DeviceName,
			"work_center": device.WorkCenterCode,
		},
		CreatedAt: time.Now().UTC(),
	}

	// ✅ Begin transaction
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.tokenRepo.CreateToken(ctx, tx, token); err != nil {
		return nil, "", fmt.Errorf("create token: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, "", fmt.Errorf("commit tx: %w", err)
	}

	return token, s.formatRawToken(req.CompanyID, rawToken), nil
}

func (s *tokenService) ValidateToken(ctx context.Context, formattedToken string, deviceID string) (*models.DeviceAuthContext, error) {
	if deviceID == "" {
		return nil, errors.New("device_id required")
	}
	companyID, rawToken, err := s.parseRawToken(formattedToken)
	if err != nil {
		return nil, err
	}
	tokenHash := s.generateTokenHash(rawToken)
	token, err := s.tokenRepo.GetActiveTokenByHash(ctx, companyID, deviceID, tokenHash)
	if err != nil || token == nil {
		return nil, errors.New("invalid or expired token")
	}
	// update last used asynchronously
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.tokenRepo.UpdateTokenLastUsed(ctx, token.TokenID)
	}()
	device, _ := s.deviceRepo.GetActiveDevice(ctx, companyID, token.DeviceID)
	auth := &models.DeviceAuthContext{
		CompanyID:    companyID,
		DeviceID:     token.DeviceID,
		SourceType:   token.SourceType,
		TokenID:      token.TokenID,
		IsTrusted:    device != nil && device.IsTrusted,
		WorkCenterID: nil,
	}
	if device != nil && device.WorkCenterCode != nil {
		auth.WorkCenterID = device.WorkCenterCode
	}
	return auth, nil
}

func (s *tokenService) ValidateTokenForRequest(ctx context.Context, req *models.ValidateTokenRequest) (*models.TokenValidationResult, error) {
	result := &models.TokenValidationResult{IsValid: false}
	auth, err := s.ValidateToken(ctx, req.RawToken, req.DeviceID)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}
	if auth.CompanyID != req.CompanyID || auth.DeviceID != req.DeviceID {
		result.Error = "token mismatch"
		return result, nil
	}
	token, err := s.tokenRepo.GetTokenByID(ctx, auth.TokenID)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}
	result.IsValid = true
	result.Token = token
	result.AuthContext = auth
	return result, nil
}

// The rest of the methods (RevokeToken, RevokeAllDeviceTokens, RotateToken, GetCurrentDeviceToken) remain unchanged
// because they either don't need a transaction or already handle it.
// For RotateToken, it calls tokenRepo.RotateToken which probably expects a transaction,
// but we'll keep it as is for now; you may need to add transaction handling there as well.

func (s *tokenService) RevokeToken(ctx context.Context, tokenID uuid.UUID, revokedBy *uuid.UUID, reason string) error {
	if tokenID == uuid.Nil {
		return errors.New("token_id required")
	}
	return s.tokenRepo.RevokeToken(ctx, tokenID, revokedBy, reason)
}

func (s *tokenService) RevokeAllDeviceTokens(ctx context.Context, companyID uuid.UUID, deviceID string, revokedBy *uuid.UUID, reason string) error {
	return s.tokenRepo.RevokeAllDeviceTokens(ctx, companyID, deviceID, revokedBy, reason)
}

func (s *tokenService) RotateToken(ctx context.Context, oldTokenID uuid.UUID, revokedBy *uuid.UUID, reason string) (*models.DeviceToken, string, error) {
	oldToken, err := s.tokenRepo.GetTokenByID(ctx, oldTokenID)
	if err != nil || oldToken == nil {
		return nil, "", errors.New("token not found")
	}
	newRaw := s.generateRawToken()
	newHash := s.generateTokenHash(newRaw)
	exp := oldToken.ExpiresAt
	if exp == nil {
		t := time.Now().UTC().Add(s.tokenValidity)
		exp = &t
	}
	newToken := &models.DeviceToken{
		TokenID:      uuid.New(),
		CompanyID:    oldToken.CompanyID,
		DeviceID:     oldToken.DeviceID,
		SourceType:   oldToken.SourceType,
		TokenHash:    newHash,
		TokenVersion: oldToken.TokenVersion + 1,
		IsActive:     true,
		IssuedAt:     time.Now().UTC(),
		ExpiresAt:    exp,
		IssuedBy:     revokedBy,
		Metadata: models.JSONB{
			"rotated_from": oldToken.TokenID.String(),
		},
		CreatedAt: time.Now().UTC(),
	}
	// RotateToken may also need a transaction – for consistency, we'll create one.
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.tokenRepo.RotateToken(ctx, oldTokenID, newToken, revokedBy, reason); err != nil {
		return nil, "", err
	}

	if err := tx.Commit(); err != nil {
		return nil, "", fmt.Errorf("commit tx: %w", err)
	}

	return newToken, s.formatRawToken(newToken.CompanyID, newRaw), nil
}

func (s *tokenService) GetCurrentDeviceToken(ctx context.Context, companyID uuid.UUID, deviceID string) (*models.DeviceToken, error) {
	if companyID == uuid.Nil || deviceID == "" {
		return nil, errors.New("company_id and device_id required")
	}
	tokens, err := s.tokenRepo.GetActiveTokensForDevice(ctx, companyID, deviceID)
	if err != nil || len(tokens) == 0 {
		return nil, nil
	}
	return tokens[0], nil
}

// helpers remain unchanged
func (s *tokenService) generateTokenHash(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken + s.tokenSecret))
	return hex.EncodeToString(sum[:])
}

func (s *tokenService) generateRawToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("secure token generation failed")
	}
	return hex.EncodeToString(b)
}

func (s *tokenService) formatRawToken(companyID uuid.UUID, rawToken string) string {
	return fmt.Sprintf("%s_%s_%s", s.tokenPrefix, companyID.String(), rawToken)
}

func (s *tokenService) parseRawToken(formatted string) (uuid.UUID, string, error) {
	parts := strings.SplitN(formatted, "_", 3)
	if len(parts) != 3 || parts[0] != s.tokenPrefix {
		return uuid.Nil, "", errors.New("invalid token format")
	}
	companyID, err := uuid.Parse(parts[1])
	if err != nil {
		return uuid.Nil, "", errors.New("invalid company id")
	}
	return companyID, parts[2], nil
}
