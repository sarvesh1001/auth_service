// service/pairing.go
package service

import (
    "auth-service/internal/config"
    "auth-service/internal/models"
    "auth-service/internal/repository/redis"
    "auth-service/internal/util"
    "context"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "time"

    "github.com/google/uuid"
    "go.uber.org/zap"
)

type PairingService struct {
    pairingRepo    redis.PairingRepository
    sessionService *SessionService
    qrUtil         *util.QRUtil
    config         *config.Config
    logger         *zap.Logger
}

func NewPairingService(
    pairingRepo redis.PairingRepository,
    sessionService *SessionService,
    qrUtil *util.QRUtil,
    config *config.Config,
    logger *zap.Logger,
) *PairingService {
    return &PairingService{
        pairingRepo:    pairingRepo,
        sessionService: sessionService,
        qrUtil:         qrUtil,
        config:         config,
        logger:         logger,
    }
}

/* -----------------------------------------------------------
   REQUEST / RESPONSE MODELS
----------------------------------------------------------- */

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

// SIMPLIFIED PairRequest
type PairRequest struct {
    SessionID   string   `json:"session_id"`
    QRData      string   `json:"qr_data"`
    UserID      string   `json:"user_id"`
    PhoneNumber string   `json:"phone_number"`
    DeviceID    string   `json:"device_id"`
    SessionType string   `json:"session_type"` // "user" or "admin"
    Role        string   `json:"role"`         // role string (e.g., "super_admin", "owner", "employee")
    Permissions []string `json:"permissions"`  // admin permissions (for admin sessions)
}

/* -----------------------------------------------------------
   GENERATE QR
----------------------------------------------------------- */

func (s *PairingService) GenerateQRCode(ctx context.Context, req *GenerateQRRequest) (*GenerateQRResponse, error) {
    sessionID := uuid.New().String()
    webDeviceID := generateWebDeviceID(req.UserAgent, req.IPAddress)

    qrData, nonce, err := s.qrUtil.GenerateQRCode(sessionID)
    if err != nil {
        return nil, fmt.Errorf("failed to generate QR: %w", err)
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
        return nil, fmt.Errorf("failed to create pairing session: %w", err)
    }

    s.logger.Info("QR generated",
        util.String("session_id", sessionID),
        util.String("web_device_id", webDeviceID),
    )

    return &GenerateQRResponse{
        SessionID: sessionID,
        QRCode:    qrData,
        ExpiresIn: 600,
        StatusURL: "/web/login/status?session_id=" + sessionID,
    }, nil
}

/* -----------------------------------------------------------
   PAIR DEVICE
----------------------------------------------------------- */

func (s *PairingService) PairDevice(ctx context.Context, req *PairRequest) error {
    qrPayload, err := s.qrUtil.ParseQRCode(req.QRData)
    if err != nil {
        return fmt.Errorf("invalid QR code: %w", err)
    }

    if qrPayload.SessionID != req.SessionID {
        return fmt.Errorf("session mismatch")
    }

    _, err = s.pairingRepo.GetPairingSession(ctx, req.SessionID)
    if err != nil {
        return fmt.Errorf("invalid session: %w", err)
    }

    // Store user/admin data in redis
    err = s.pairingRepo.ScanPairingSession(
        ctx,
        req.SessionID,
        req.UserID,
        req.PhoneNumber,
        req.DeviceID,
        req.SessionType,
        req.Role,
        req.Permissions,
    )

    if err != nil {
        return fmt.Errorf("failed to pair device: %w", err)
    }

    s.logger.Info("Device paired",
        util.String("session_id", req.SessionID),
        util.String("user_id", req.UserID),
        util.String("session_type", req.SessionType),
        util.String("role", req.Role),
    )

    return nil
}

/* -----------------------------------------------------------
   GET STATUS
----------------------------------------------------------- */

func (s *PairingService) GetPairingStatus(ctx context.Context, sessionID string) (*models.PairingStatusResponse, error) {
    session, err := s.pairingRepo.GetPairingSession(ctx, sessionID)
    if err != nil {
        return nil, err
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

/* -----------------------------------------------------------
   CONFIRM PAIRING (ADMIN + USER) - SIMPLIFIED
----------------------------------------------------------- */

func (s *PairingService) ConfirmPairing(ctx context.Context, sessionID string) (*models.TokenPairResponse, error) {
    session, err := s.pairingRepo.GetPairingSession(ctx, sessionID)
    if err != nil {
        return nil, fmt.Errorf("invalid session: %w", err)
    }

    if session.Status != "scanned" {
        return nil, fmt.Errorf("session not scanned yet")
    }

    if session.UserID == "" {
        return nil, fmt.Errorf("missing user")
    }

    // mark as confirmed
    if err := s.pairingRepo.ConfirmPairingSession(ctx, sessionID); err != nil {
        return nil, fmt.Errorf("failed confirm: %w", err)
    }

    var tokenPair *models.TokenPairResponse
    var errPair error

    // Build permission mask from permissions (for admin sessions)
    var permissionMask []uint64
    if session.SessionType == "admin" && len(session.Permissions) > 0 {
        permissionMask = s.buildPermissionMask(session.Permissions)
    }

    // Issue token pair
    tokenPair, errPair = s.sessionService.IssueTokenPair(ctx, &IssueTokenPairRequest{
        UserID:         session.UserID,
        Role:           session.Role,
        DeviceID:       session.WebDeviceID,
        SessionType:    session.SessionType,
        IPAddress:      session.IPAddress,
        CompanyID:      "", // Admin sessions don't need company ID
        PermissionMask: permissionMask,
    })

    if errPair != nil {
        return nil, fmt.Errorf("token issue failed: %w", errPair)
    }

    // delete pairing after 30 sec
    go func() {
        time.Sleep(30 * time.Second)
        s.pairingRepo.DeletePairingSession(context.Background(), sessionID)
    }()

    s.logger.Info("Pairing confirmed",
        util.String("session_id", sessionID),
        util.String("user_id", session.UserID),
        util.String("session_type", session.SessionType),
        util.String("role", session.Role),
    )

    return tokenPair, nil
}

// buildPermissionMask converts permission strings to bitmask
func (s *PairingService) buildPermissionMask(permissions []string) []uint64 {
    // This should use your permission registry
    // For now, returning empty mask
    return []uint64{0, 0, 0, 0}
}

/* -----------------------------------------------------------
   CLEAN EXPIRED
----------------------------------------------------------- */

func (s *PairingService) CleanupExpiredSessions(ctx context.Context) (int, error) {
    return s.pairingRepo.CleanupExpiredSessions(ctx)
}

/* -----------------------------------------------------------
   HELPERS
----------------------------------------------------------- */

func generateWebDeviceID(userAgent, ip string) string {
    h := sha256.New()
    h.Write([]byte(userAgent + ":" + ip))
    hash := hex.EncodeToString(h.Sum(nil))
    return "web-" + hash[:16]
}

func generateNonce() (string, error) {
    bytes := make([]byte, 16)
    _, err := rand.Read(bytes)
    if err != nil {
        return "", err
    }
    return hex.EncodeToString(bytes), nil
}