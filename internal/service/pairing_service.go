package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/config"
	appErrors "auth-service/internal/errors"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/models"
	"auth-service/internal/repository/redis"
	"auth-service/internal/util"
)

// PairingService handles QR-based device pairing for both users and admins.
type PairingService struct {
	pairingRepo      redis.PairingRepository
	sessionService   *SessionService
	qrUtil           *util.QRUtil
	config           *config.Config
	auditService     *audit.AuditService
	idempotencyStore idempotency.Store
	companyService   *CompanyService // Injected to fetch role/permissions from DB
}

// NewPairingService creates a new PairingService.
func NewPairingService(
	pairingRepo redis.PairingRepository,
	sessionService *SessionService,
	qrUtil *util.QRUtil,
	config *config.Config,
	auditService *audit.AuditService,
	idempotencyStore idempotency.Store,
	companyService *CompanyService,
) *PairingService {
	return &PairingService{
		pairingRepo:      pairingRepo,
		sessionService:   sessionService,
		qrUtil:           qrUtil,
		config:           config,
		auditService:     auditService,
		idempotencyStore: idempotencyStore,
		companyService:   companyService,
	}
}

// --------------------------------------------------------------------
// REQUEST / RESPONSE MODELS
// --------------------------------------------------------------------

type GenerateQRRequest struct {
	IPAddress string `json:"ip_address"`
	UserAgent string `json:"user_agent"`
}

type GenerateQRResponse struct {
	SessionID string `json:"session_id"`
	QRCode    string `json:"qr_code"`
	ExpiresIn int64  `json:"expires_in"`
	StatusURL string `json:"status_url"`
}

type PairRequest struct {
	SessionID   string   `json:"session_id"`
	QRData      string   `json:"qr_data"`
	UserID      string   `json:"user_id"`
	PhoneNumber string   `json:"phone_number"`
	DeviceID    string   `json:"device_id"`
	SessionType string   `json:"session_type"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	CompanyID   string   `json:"company_id"`
}

// --------------------------------------------------------------------
// GENERATE QR
// --------------------------------------------------------------------

func (s *PairingService) GenerateQRCode(ctx context.Context, req *GenerateQRRequest) (*GenerateQRResponse, error) {
	sessionID := uuid.New().String()
	webDeviceID := generateWebDeviceID(req.UserAgent, req.IPAddress)

	qrData, nonce, err := s.qrUtil.GenerateQRCode(sessionID)
	if err != nil {
		zap.L().Error("QR generation failed", zap.Error(err))
		return nil, fmt.Errorf("%w: QR generation failed", appErrors.ErrInternal)
	}

	session := &models.PairingSession{
		SessionID:   sessionID,
		Status:      "pending",
		Nonce:       nonce,
		QRPayload:   qrData,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		IPAddress:   req.IPAddress,
		UserAgent:   req.UserAgent,
		WebDeviceID: webDeviceID,
	}

	if err := s.pairingRepo.CreatePairingSession(ctx, session); err != nil {
		zap.L().Error("Failed to create pairing session", zap.Error(err))
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	zap.L().Info("QR generated",
		zap.String("session_id", sessionID),
		zap.String("web_device_id", webDeviceID),
	)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "pairing", "generate_qr", "pairing_session",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"session_id":    sessionID,
				"web_device_id": webDeviceID,
				"ip":            req.IPAddress,
				"user_agent":    req.UserAgent,
			})
	}

	return &GenerateQRResponse{
		SessionID: sessionID,
		QRCode:    qrData,
		ExpiresIn: 600,
		StatusURL: "/web/login/status?session_id=" + sessionID,
	}, nil
}

// --------------------------------------------------------------------
// PAIR DEVICE (mobile scans QR)
// --------------------------------------------------------------------

func (s *PairingService) PairDevice(ctx context.Context, req *PairRequest) error {
	logger := zap.L().With(
		zap.String("session_id", req.SessionID),
		zap.String("user_id", req.UserID),
		zap.String("company_id", req.CompanyID),
	)
	logger.Info("PairDevice called")

	qrPayload, err := s.qrUtil.ParseQRCode(req.QRData)
	if err != nil {
		logger.Error("Invalid QR data", zap.Error(err))
		return fmt.Errorf("%w: invalid QR code", appErrors.ErrInvalidInput)
	}
	if qrPayload.SessionID != req.SessionID {
		logger.Error("Session mismatch", zap.String("qr_session", qrPayload.SessionID))
		return fmt.Errorf("%w: session mismatch", appErrors.ErrInvalidInput)
	}

	_, err = s.pairingRepo.GetPairingSession(ctx, req.SessionID)
	if err != nil {
		logger.Error("Session not found", zap.Error(err))
		return fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}

	err = s.pairingRepo.ScanPairingSession(
		ctx,
		req.SessionID,
		req.UserID,
		req.PhoneNumber,
		req.DeviceID,
		req.SessionType,
		req.Role,
		req.Permissions,
		req.CompanyID,
	)
	if err != nil {
		logger.Error("Failed to scan pairing session", zap.Error(err))
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	logger.Info("PairDevice succeeded, session marked as scanned")

	if s.auditService != nil {
		ip, _ := ctx.Value("ip_address").(string)
		_ = s.auditService.LogAction(ctx, nil, nil, "pairing", "pair_device", "pairing_session",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"session_id":   req.SessionID,
				"user_id":      req.UserID,
				"session_type": req.SessionType,
				"role":         req.Role,
				"phone_number": req.PhoneNumber,
				"device_id":    req.DeviceID,
				"company_id":   req.CompanyID,
				"ip":           ip,
			})
	}

	return nil
}

// --------------------------------------------------------------------
// GET PAIRING STATUS
// --------------------------------------------------------------------

func (s *PairingService) GetPairingStatus(ctx context.Context, sessionID string) (*models.PairingStatusResponse, error) {
	session, err := s.pairingRepo.GetPairingSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	return &models.PairingStatusResponse{
		SessionID:   session.SessionID,
		Status:      session.Status,
		UserID:      session.UserID,
		PhoneNumber: session.PhoneNumber,
		SessionType: session.SessionType,
		Role:        session.Role,
		ExpiresAt:   session.ExpiresAt,
	}, nil
}

// --------------------------------------------------------------------
// CONFIRM PAIRING – now identical to MPIN: let JWTService fetch permissions
// --------------------------------------------------------------------

func (s *PairingService) ConfirmPairing(ctx context.Context, sessionID string) (*models.TokenPairResponse, error) {
	logger := zap.L().With(zap.String("session_id", sessionID))
	logger.Info("ConfirmPairing started")

	// Idempotency
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("confirm_pairing-%s", sessionID)
	}
	var cached *models.TokenPairResponse
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		logger.Info("Returning cached token pair")
		return cached, nil
	}
	ip, _ := ctx.Value("ip_address").(string)

	// Get session
	session, err := s.pairingRepo.GetPairingSession(ctx, sessionID)
	if err != nil {
		logger.Error("Failed to get session", zap.Error(err))
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	logger.Info("Session retrieved",
		zap.String("status", session.Status),
		zap.String("user_id", session.UserID),
		zap.String("company_id", session.CompanyID),
		zap.String("session_type", session.SessionType),
	)

	if session.Status != "scanned" {
		logger.Warn("Session not scanned", zap.String("status", session.Status))
		return nil, fmt.Errorf("%w: session not scanned", appErrors.ErrInvalidState)
	}
	if session.UserID == "" {
		logger.Warn("Missing user_id")
		return nil, fmt.Errorf("%w: missing user", appErrors.ErrInvalidState)
	}
	if session.CompanyID == "" {
		logger.Warn("Missing company_id")
		return nil, fmt.Errorf("%w: missing company", appErrors.ErrInvalidState)
	}

	// Parse UUIDs
	userID, err := uuid.Parse(session.UserID)
	if err != nil {
		logger.Error("Invalid user_id UUID", zap.Error(err))
		return nil, fmt.Errorf("%w: invalid user_id", appErrors.ErrInvalidInput)
	}
	companyID, err := uuid.Parse(session.CompanyID)
	if err != nil {
		logger.Error("Invalid company_id UUID", zap.Error(err))
		return nil, fmt.Errorf("%w: invalid company_id", appErrors.ErrInvalidInput)
	}
	logger.Debug("Parsed UUIDs", zap.String("user_uuid", userID.String()), zap.String("company_uuid", companyID.String()))

	// Fetch company context (only needed for role; permissions will be fetched by JWTService)
	logger.Info("Calling GetCompanyContextForCompany for role")
	companyCtx, err := s.companyService.GetCompanyContextForCompany(ctx, userID, companyID)
	if err != nil {
		logger.Error("GetCompanyContextForCompany failed", zap.Error(err))
		return nil, fmt.Errorf("%w: user not active in company", appErrors.ErrPermissionDenied)
	}
	logger.Info("Company context fetched",
		zap.String("role", companyCtx.RoleName),
		zap.Int("permission_count", len(companyCtx.Permissions)), // just for logging
		zap.String("company_id", companyCtx.CompanyID),
	)

	// Mark session as confirmed
	if err := s.pairingRepo.ConfirmPairingSession(ctx, sessionID); err != nil {
		logger.Error("Failed to confirm session", zap.Error(err))
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	// ────────────────────────────────────────────────────────────────
	// 🔥 FIX: Pass nil PermissionMask – JWTService will fetch from DB
	// This matches the MPIN behaviour exactly.
	// ────────────────────────────────────────────────────────────────
	tokenReq := &IssueTokenPairRequest{
		UserID:         session.UserID,
		Role:           companyCtx.RoleName,
		DeviceID:       session.WebDeviceID,
		SessionType:    session.SessionType,
		IPAddress:      session.IPAddress,
		CompanyID:      session.CompanyID,
		PermissionMask: nil, // 👈 Let JWTService fetch permissions from DB
	}
	logger.Info("Issuing token pair (mask will be fetched from DB by JWTService)",
		zap.String("role", tokenReq.Role),
	)

	tokenPair, err := s.sessionService.IssueTokenPair(ctx, tokenReq)
	if err != nil {
		logger.Error("Token issuance failed", zap.Error(err))
		return nil, fmt.Errorf("%w: token issue failed", appErrors.ErrInternal)
	}

	// Audit
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "pairing", "confirm_pairing", "pairing_session",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"session_id":   sessionID,
				"user_id":      session.UserID,
				"session_type": session.SessionType,
				"role":         companyCtx.RoleName,
				"company_id":   session.CompanyID,
				"ip":           ip,
			})
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, tokenPair)

	// Cleanup after delay
	go func() {
		time.Sleep(30 * time.Second)
		_ = s.pairingRepo.DeletePairingSession(context.Background(), sessionID)
	}()

	logger.Info("ConfirmPairing completed successfully")
	return tokenPair, nil
}

// --------------------------------------------------------------------
// CLEANUP
// --------------------------------------------------------------------

func (s *PairingService) CleanupExpiredSessions(ctx context.Context) (int, error) {
	count, err := s.pairingRepo.CleanupExpiredSessions(ctx)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "pairing", "cleanup_expired", "pairing_session",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"deleted_count": count,
			})
	}
	return count, nil
}

// --------------------------------------------------------------------
// HELPERS
// --------------------------------------------------------------------

func generateWebDeviceID(userAgent, ip string) string {
	h := sha256.New()
	h.Write([]byte(userAgent + ":" + ip))
	hash := hex.EncodeToString(h.Sum(nil))
	return "web-" + hash[:16]
}
