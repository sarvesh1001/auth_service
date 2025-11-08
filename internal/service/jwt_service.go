package service

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "time"
    
    "auth-service/internal/config"
    "auth-service/internal/models"
    
    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
    "go.uber.org/zap"
)

type JWTService struct {
    config *config.Config
    logger *zap.Logger
}

func NewJWTService(cfg *config.Config, logger *zap.Logger) *JWTService {
    return &JWTService{
        config: cfg,
        logger: logger,
    }
}

// CreateAccessToken generates a signed JWT access token
func (s *JWTService) CreateAccessToken(ctx context.Context, req *CreateAccessTokenRequest) (string, string, error) {
    jti := uuid.NewString()
    now := time.Now()
    
    claims := jwt.MapClaims{
        "sub":         req.UserID,
        "role":        req.Role,
        "device_id":   req.DeviceID,
        "session_type": req.SessionType,
        "jti":         jti,
        "iat":         now.Unix(),
        "exp":         now.Add(s.config.JWT.AccessTTL).Unix(),
    }
    
    // Add admin-specific claims if admin session
    if req.SessionType == "admin" {
        claims["admin_role_level"] = req.AdminRoleLevel
        claims["admin_permissions"] = req.AdminPermissions
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    signed, err := token.SignedString([]byte(s.config.JWT.Secret))
    if err != nil {
        return "", "", fmt.Errorf("failed to sign token: %w", err)
    }
    
    return signed, jti, nil
}

// ValidateAccessToken validates and parses JWT access token
func (s *JWTService) ValidateAccessToken(ctx context.Context, tokenStr string) (*models.JWTClaims, error) {
    token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
        // Verify signing method
        if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
        }
        return []byte(s.config.JWT.Secret), nil
    })
    
    if err != nil {
        return nil, fmt.Errorf("token parse error: %w", err)
    }
    
    if !token.Valid {
        return nil, fmt.Errorf("invalid token")
    }
    
    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        return nil, fmt.Errorf("invalid token claims")
    }
    
    // Extract claims
    jwtClaims := &models.JWTClaims{
        UserID:      getStringClaim(claims, "sub"),
        Role:        getStringClaim(claims, "role"),
        DeviceID:    getStringClaim(claims, "device_id"),
        SessionType: getStringClaim(claims, "session_type"),
        JTI:         getStringClaim(claims, "jti"),
        IssuedAt:    getInt64Claim(claims, "iat"),
        ExpiresAt:   getInt64Claim(claims, "exp"),
    }
    
    // Extract admin-specific claims if present
    if jwtClaims.SessionType == "admin" {
        jwtClaims.AdminRoleLevel = getStringClaim(claims, "admin_role_level")
        if perms, ok := claims["admin_permissions"].([]interface{}); ok {
            for _, p := range perms {
                if perm, ok := p.(string); ok {
                    jwtClaims.AdminPermissions = append(jwtClaims.AdminPermissions, perm)
                }
            }
        }
    }
    
    return jwtClaims, nil
}

// GenerateRefreshToken generates opaque refresh token
func (s *JWTService) GenerateRefreshToken() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", fmt.Errorf("failed to generate random token: %w", err)
    }
    return hex.EncodeToString(b), nil
}

// Helper functions
func getStringClaim(claims jwt.MapClaims, key string) string {
    if val, ok := claims[key].(string); ok {
        return val
    }
    return ""
}

func getInt64Claim(claims jwt.MapClaims, key string) int64 {
    if val, ok := claims[key].(float64); ok {
        return int64(val)
    }
    return 0
}

// Request structs
type CreateAccessTokenRequest struct {
    UserID           string
    Role             string
    DeviceID         string
    SessionType      string
    AdminRoleLevel   string
    AdminPermissions []string
}
