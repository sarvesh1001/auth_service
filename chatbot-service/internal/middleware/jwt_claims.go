package middleware

import "github.com/golang-jwt/jwt/v5"

type JWTClaims struct {
	UserID         string   `json:"user_id"`
	Role           string   `json:"role"`
	DeviceID       string   `json:"device_id"`
	SessionType    string   `json:"session_type"`
	CompanyID      string   `json:"company_id"`
	JTI            string   `json:"jti"`
	IssuedAt       int64    `json:"iat"`
	ExpiresAt      int64    `json:"exp"`
	PermissionMask []uint64 `json:"permission_mask,omitempty"`
	jwt.RegisteredClaims
}
