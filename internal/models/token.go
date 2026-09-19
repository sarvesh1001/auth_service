package models

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTClaims represents the JWT claims structure
type JWTClaims struct {
	UserID         string   `json:"user_id"`
	Role           string   `json:"role"`
	DeviceID       string   `json:"device_id"`
	SessionType    string   `json:"session_type"` // "user" or "admin"
	CompanyID      string   `json:"company_id"`
	JTI            string   `json:"jti"`
	IssuedAt       int64    `json:"iat"`
	ExpiresAt      int64    `json:"exp"`
	PermissionMask []uint64 `json:"permission_mask,omitempty"`

	// 🆕 Location claims
	PrimaryLocationID string `json:"primary_location_id,omitempty"`
	LocationScope     string `json:"location_scope,omitempty"` // "PRIMARY", "SELECTED", "ALL"

	jwt.RegisteredClaims
}

// RefreshTokenData represents refresh token stored in Redis
type RefreshTokenData struct {
	RefreshID   string    `json:"refresh_id"`
	UserID      string    `json:"user_id"`
	DeviceID    string    `json:"device_id"`
	SessionType string    `json:"session_type"`
	CompanyID   string    `json:"company_id"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	LastUsed    time.Time `json:"last_used"`
	Revoked     bool      `json:"revoked"`
	IPAddress   string    `json:"ip_address,omitempty"`
	JTI         string    `json:"jti,omitempty"`
}

// AccessTokenData represents access token stored in Redis
type AccessTokenData struct {
	JTI         string    `json:"jti"`
	UserID      string    `json:"user_id"`
	DeviceID    string    `json:"device_id"`
	CompanyID   string    `json:"company_id"`
	SessionType string    `json:"session_type"`
	Active      bool      `json:"active"`
	ExpiresAt   time.Time `json:"expires_at"`
	IPAddress   string    `json:"ip_address,omitempty"`
}

// TokenPairResponse represents token pair response
type TokenPairResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	CompanyID    string `json:"company_id,omitempty"`
}

// IssueTokenPairRequest (used internally) – add location fields
type IssueTokenPairRequest struct {
	UserID            string
	Role              string
	DeviceID          string
	SessionType       string
	IPAddress         string
	CompanyID         string
	PermissionMask    []uint64
	PrimaryLocationID string // 🆕
	LocationScope     string // 🆕
}
