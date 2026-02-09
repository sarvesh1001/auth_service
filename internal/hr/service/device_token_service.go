package service

import (
	"auth-service/internal/hr/models/attendance"
	"auth-service/internal/hr/repository"
	"auth-service/internal/util"
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
)

type DeviceTokenService interface {
	IssueToken(ctx context.Context, req *attendance.IssueTokenRequest) (*attendance.DeviceToken, string, error)

	// 🔴 UPDATED SIGNATURE
	ValidateToken(
		ctx context.Context,
		rawToken string,
		deviceID string,
	) (*attendance.DeviceAuthContext, error)

	ValidateTokenForRequest(
		ctx context.Context,
		req *attendance.ValidateTokenRequest,
	) (*attendance.TokenValidationResult, error)

	RevokeToken(ctx context.Context, tokenID uuid.UUID, revokedBy *uuid.UUID, reason string) error
	RevokeAllDeviceTokens(ctx context.Context, companyID uuid.UUID, deviceID string, revokedBy *uuid.UUID, reason string) error
	RotateToken(ctx context.Context, oldTokenID uuid.UUID, revokedBy *uuid.UUID, reason string) (*attendance.DeviceToken, string, error)

	GenerateTokenHash(rawToken string) string

	GetCurrentDeviceToken(
		ctx context.Context,
		companyID uuid.UUID,
		deviceID string,
	) (*attendance.DeviceToken, error)
}

type deviceTokenService struct {
	tokenRepo     repository.DeviceTokenRepository
	deviceRepo    repository.AttendanceDeviceRepository
	logger        *zap.Logger
	tokenPrefix   string
	tokenSecret   string
	tokenValidity time.Duration
}

type DeviceTokenServiceConfig struct {
	TokenPrefix   string
	TokenSecret   string
	TokenValidity time.Duration
}

func NewDeviceTokenService(
	tokenRepo repository.DeviceTokenRepository,
	deviceRepo repository.AttendanceDeviceRepository,
	logger *zap.Logger,
	config DeviceTokenServiceConfig,
) DeviceTokenService {
	if config.TokenValidity == 0 {
		config.TokenValidity = 30 * 24 * time.Hour
	}

	return &deviceTokenService{
		tokenRepo:     tokenRepo,
		deviceRepo:    deviceRepo,
		logger:        logger,
		tokenPrefix:   config.TokenPrefix,
		tokenSecret:   config.TokenSecret,
		tokenValidity: config.TokenValidity,
	}
}

// ==========================
// ISSUE TOKEN
// ==========================
func (s *deviceTokenService) IssueToken(
	ctx context.Context,
	req *attendance.IssueTokenRequest,
) (*attendance.DeviceToken, string, error) {

	if req.CompanyID == uuid.Nil {
		return nil, "", errors.New("company_id required")
	}
	if req.DeviceID == "" {
		return nil, "", errors.New("device_id required")
	}
	if req.SourceType == "" {
		return nil, "", errors.New("source_type required")
	}

	device, err := s.deviceRepo.GetActiveDevice(ctx, req.CompanyID, req.DeviceID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get device: %w", err)
	}
	if device == nil {
		return nil, "", errors.New("device not found")
	}
	if !device.IsTrusted {
		return nil, "", errors.New("device is not trusted")
	}

	_ = s.tokenRepo.RevokeAllDeviceTokens(
		ctx,
		req.CompanyID,
		req.DeviceID,
		req.IssuedBy,
		"revoked due to new token issuance",
	)

	rawToken := s.generateRawToken()
	tokenHash := s.GenerateTokenHash(rawToken)

	expiry := time.Now().UTC().Add(s.tokenValidity)
	if req.ExpiresIn != nil && *req.ExpiresIn > 0 {
		expiry = time.Now().UTC().Add(time.Duration(*req.ExpiresIn) * time.Second)
	}

	token := &attendance.DeviceToken{
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
		Metadata: attendance.JSONB{
			"device_name": device.DeviceName,
			"work_center": device.WorkCenterCode,
		},
		CreatedAt: time.Now().UTC(),
	}

	if err := s.tokenRepo.CreateToken(ctx, token); err != nil {
		return nil, "", fmt.Errorf("failed to create token: %w", err)
	}

	s.logger.Info("Device token issued",
		util.String("token_id", token.TokenID.String()),
		util.String("device_id", req.DeviceID),
		util.String("company_id", req.CompanyID.String()),
	)

	return token, s.formatRawToken(req.CompanyID, rawToken), nil
}

// ==========================
// VALIDATE TOKEN (FIXED)
// ==========================
func (s *deviceTokenService) ValidateToken(
	ctx context.Context,
	formattedToken string,
	deviceID string,
) (*attendance.DeviceAuthContext, error) {

	if deviceID == "" {
		return nil, errors.New("device_id required for token validation")
	}

	companyID, rawToken, err := s.parseRawToken(formattedToken)
	if err != nil {
		return nil, err
	}

	tokenHash := s.GenerateTokenHash(rawToken)

	// ✅ FIX: deviceID is REQUIRED here
	token, err := s.tokenRepo.GetActiveTokenByHash(
		ctx,
		companyID,
		deviceID,
		tokenHash,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}
	if token == nil {
		return nil, errors.New("invalid or expired token")
	}
	go func(tokenID uuid.UUID) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		if err := s.tokenRepo.UpdateTokenLastUsed(ctx, tokenID); err != nil {
			s.logger.Debug(
				"failed to update device token last_used_at",
				util.String("token_id", tokenID.String()),
				util.ErrorField(err),
			)
		}
	}(token.TokenID)

	device, _ := s.deviceRepo.GetActiveDevice(ctx, companyID, token.DeviceID)

	auth := &attendance.DeviceAuthContext{
		CompanyID:  companyID,
		DeviceID:   token.DeviceID,
		SourceType: token.SourceType,
		TokenID:    token.TokenID,
		IsTrusted:  device != nil && device.IsTrusted,
	}

	if device != nil && device.WorkCenterCode != nil {
		auth.WorkCenterID = device.WorkCenterCode
	}

	return auth, nil
}

// ==========================
// VALIDATE TOKEN (REQUEST STYLE)
// ==========================
func (s *deviceTokenService) ValidateTokenForRequest(
	ctx context.Context,
	req *attendance.ValidateTokenRequest,
) (*attendance.TokenValidationResult, error) {

	result := &attendance.TokenValidationResult{IsValid: false}

	auth, err := s.ValidateToken(ctx, req.RawToken, req.DeviceID)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	if auth.CompanyID != req.CompanyID {
		result.Error = "token company mismatch"
		return result, nil
	}
	if auth.DeviceID != req.DeviceID {
		result.Error = "token device mismatch"
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

// ==========================
// REVOKE / ROTATE / HELPERS
// ==========================
func (s *deviceTokenService) RevokeToken(
	ctx context.Context,
	tokenID uuid.UUID,
	revokedBy *uuid.UUID,
	reason string,
) error {
	if tokenID == uuid.Nil {
		return errors.New("token_id required")
	}
	return s.tokenRepo.RevokeToken(ctx, tokenID, revokedBy, reason)
}

func (s *deviceTokenService) RevokeAllDeviceTokens(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
	revokedBy *uuid.UUID,
	reason string,
) error {
	return s.tokenRepo.RevokeAllDeviceTokens(ctx, companyID, deviceID, revokedBy, reason)
}

func (s *deviceTokenService) RotateToken(
	ctx context.Context,
	oldTokenID uuid.UUID,
	revokedBy *uuid.UUID,
	reason string,
) (*attendance.DeviceToken, string, error) {

	oldToken, err := s.tokenRepo.GetTokenByID(ctx, oldTokenID)
	if err != nil || oldToken == nil {
		return nil, "", errors.New("token not found")
	}

	newRaw := s.generateRawToken()
	newHash := s.GenerateTokenHash(newRaw)

	exp := oldToken.ExpiresAt
	if exp == nil {
		t := time.Now().UTC().Add(s.tokenValidity)
		exp = &t
	}

	newToken := &attendance.DeviceToken{
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
		Metadata: attendance.JSONB{
			"rotated_from": oldToken.TokenID.String(),
		},
		CreatedAt: time.Now().UTC(),
	}

	if err := s.tokenRepo.RotateToken(ctx, oldTokenID, newToken, revokedBy, reason); err != nil {
		return nil, "", err
	}

	return newToken, s.formatRawToken(newToken.CompanyID, newRaw), nil
}

// ==========================
// HELPERS
// ==========================
func (s *deviceTokenService) GenerateTokenHash(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken + s.tokenSecret))
	return hex.EncodeToString(sum[:])
}

func (s *deviceTokenService) generateRawToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("secure token generation failed")
	}
	return hex.EncodeToString(b)
}

func (s *deviceTokenService) formatRawToken(companyID uuid.UUID, rawToken string) string {
	return fmt.Sprintf("%s_%s_%s", s.tokenPrefix, companyID.String(), rawToken)
}

func (s *deviceTokenService) parseRawToken(formatted string) (uuid.UUID, string, error) {
	parts := strings.SplitN(formatted, "_", 3)
	if len(parts) != 3 {
		return uuid.Nil, "", errors.New("invalid token format")
	}
	if parts[0] != s.tokenPrefix {
		return uuid.Nil, "", errors.New("invalid token prefix")
	}
	companyID, err := uuid.Parse(parts[1])
	if err != nil {
		return uuid.Nil, "", errors.New("invalid company id")
	}
	return companyID, parts[2], nil
}

func (s *deviceTokenService) GetCurrentDeviceToken(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
) (*attendance.DeviceToken, error) {

	if companyID == uuid.Nil {
		return nil, errors.New("company_id required")
	}
	if deviceID == "" {
		return nil, errors.New("device_id required")
	}

	tokens, err := s.tokenRepo.GetActiveTokensForDevice(ctx, companyID, deviceID)
	if err != nil {
		return nil, err
	}

	if len(tokens) == 0 {
		return nil, nil
	}

	return tokens[0], nil
}
