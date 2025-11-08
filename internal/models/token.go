package models

import (
    "time"
)

// JWTClaims represents access token claims
type JWTClaims struct {
    UserID      string   `json:"sub"`
    Role        string   `json:"role"`
    DeviceID    string   `json:"device_id"`
    SessionType string   `json:"session_type"` // "user" or "admin"
    JTI         string   `json:"jti"` // JWT ID for tracking
    IssuedAt    int64    `json:"iat"`
    ExpiresAt   int64    `json:"exp"`
    
    // Optional admin-specific fields
    AdminRoleLevel   string   `json:"admin_role_level,omitempty"`
    AdminPermissions []string `json:"admin_permissions,omitempty"`
}

// RefreshTokenData stored in Redis
type RefreshTokenData struct {
    RefreshID        string    `json:"refresh_id"`
    UserID           string    `json:"user_id"`
    DeviceID         string    `json:"device_id"`
    SessionType      string    `json:"session_type"` // "user" or "admin"
    IssuedAt         time.Time `json:"issued_at"`
    ExpiresAt        time.Time `json:"expires_at"`
    LastUsed         time.Time `json:"last_used"`
    Revoked          bool      `json:"revoked"`
    IPAddress        string    `json:"ip_address"`
    
    // Admin-specific fields
    AdminRoleLevel   string   `json:"admin_role_level,omitempty"`
    AdminPermissions []string `json:"admin_permissions,omitempty"`
}

// TokenPairResponse returned to client
type TokenPairResponse struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
    ExpiresIn    int    `json:"expires_in"` // seconds until access token expires
    TokenType    string `json:"token_type"` // "Bearer"
}
