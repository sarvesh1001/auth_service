
// internal/models/token_models.go
package models

import (
	"time"
	"github.com/golang-jwt/jwt/v5"

)

// JWTClaims represents the JWT claims structure
type JWTClaims struct {
	UserID           string    `json:"user_id"`
	Role             string    `json:"role"`
	DeviceID         string    `json:"device_id"`
	SessionType      string    `json:"session_type"`
	CompanyID        string    `json:"company_id"`
	JTI              string    `json:"jti"`
	IssuedAt         int64     `json:"iat"`
	ExpiresAt        int64     `json:"exp"`
	PermissionMask   []uint64  `json:"permission_mask,omitempty"`
	AdminRoleLevel   string    `json:"admin_role_level,omitempty"`
	AdminPermissions []string  `json:"admin_permissions,omitempty"`
	jwt.RegisteredClaims
}

// RefreshTokenData represents refresh token stored in Redis
type RefreshTokenData struct {
	RefreshID        string    `json:"refresh_id"`
	UserID           string    `json:"user_id"`
	DeviceID         string    `json:"device_id"`
	SessionType      string    `json:"session_type"`
	CompanyID        string    `json:"company_id"`
	IssuedAt         time.Time `json:"issued_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	LastUsed         time.Time `json:"last_used"`
	Revoked          bool      `json:"revoked"`
	IPAddress        string    `json:"ip_address,omitempty"`
	AdminRoleLevel   string    `json:"admin_role_level,omitempty"`
	AdminPermissions []string  `json:"admin_permissions,omitempty"`
	JTI              string    `json:"jti,omitempty"` // Associated access token JTI
}

// ✅ NEW: AccessTokenData represents access token stored in Redis
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

// // auth-service/internal/models/tokens.go (or wherever your token models are defined)

// package models

// import (
// 	"time"

// 	"github.com/golang-jwt/jwt/v5"
// )

// type JWTClaims struct {
// 	UserID           string   `json:"sub"`
// 	Role             string   `json:"role"`
// 	DeviceID         string   `json:"device_id"`
// 	SessionType      string   `json:"session_type"`
// 	CompanyID        string   `json:"company_id,omitempty"` // ✅ Keep this
// 	JTI              string   `json:"jti"`
// 	IssuedAt         int64    `json:"iat"`
// 	ExpiresAt        int64    `json:"exp"`
// 	PermissionMask   []uint64 `json:"permission_mask,omitempty"`
// 	AdminRoleLevel   string   `json:"admin_role_level,omitempty"`
// 	AdminPermissions []string `json:"admin_permissions,omitempty"`
// 	jwt.RegisteredClaims
// }

// // RefreshTokenData stored in Redis
// type RefreshTokenData struct {
// 	RefreshID        string    `json:"refresh_id"`
// 	UserID           string    `json:"user_id"`
// 	DeviceID         string    `json:"device_id"`
// 	SessionType      string    `json:"session_type"` // "user" or "admin"
// 	CompanyID        string    `json:"company_id,omitempty"` // ✅ ADD THIS FIELD
// 	IssuedAt         time.Time `json:"issued_at"`
// 	ExpiresAt        time.Time `json:"expires_at"`
// 	LastUsed         time.Time `json:"last_used"`
// 	Revoked          bool      `json:"revoked"`
// 	IPAddress        string    `json:"ip_address"`
	
// 	// Admin-specific fields
// 	AdminRoleLevel   string   `json:"admin_role_level,omitempty"`
// 	AdminPermissions []string `json:"admin_permissions,omitempty"`
// }

// // TokenPairResponse returned to client
// type TokenPairResponse struct {
// 	AccessToken  string `json:"access_token"`
// 	RefreshToken string `json:"refresh_token"`
// 	ExpiresIn    int    `json:"expires_in"` // seconds until access token expires
// 	TokenType    string `json:"token_type"` // "Bearer"
// 	CompanyID    string `json:"company_id,omitempty"` // ✅ ADD THIS FIELD
// }

// // package models

// // import (
// // 	"time"

// // 	"github.com/golang-jwt/jwt/v5"
// // )

// // type JWTClaims struct {
// // 	UserID           string   `json:"sub"`
// // 	Role             string   `json:"role"`
// // 	DeviceID         string   `json:"device_id"`
// // 	SessionType      string   `json:"session_type"`
// // 	CompanyID        string   `json:"company_id,omitempty"` // 🆕 ADD THIS
// // 	JTI              string   `json:"jti"`
// // 	IssuedAt         int64    `json:"iat"`
// // 	ExpiresAt        int64    `json:"exp"`
// // 	PermissionMask   []uint64 `json:"permission_mask,omitempty"`
// // 	AdminRoleLevel   string   `json:"admin_role_level,omitempty"`
// // 	AdminPermissions []string `json:"admin_permissions,omitempty"`
// // 	jwt.RegisteredClaims
// // }

// // // RefreshTokenData stored in Redis
// // type RefreshTokenData struct {
// // 	RefreshID   string    `json:"refresh_id"`
// // 	UserID      string    `json:"user_id"`
// // 	DeviceID    string    `json:"device_id"`
// // 	SessionType string    `json:"session_type"` // "user" or "admin"
// // 	IssuedAt    time.Time `json:"issued_at"`
// // 	ExpiresAt   time.Time `json:"expires_at"`
// // 	LastUsed    time.Time `json:"last_used"`
// // 	Revoked     bool      `json:"revoked"`
// // 	IPAddress   string    `json:"ip_address"`

// // 	// Admin-specific fields
// // 	AdminRoleLevel   string   `json:"admin_role_level,omitempty"`
// // 	AdminPermissions []string `json:"admin_permissions,omitempty"`
// // 	// CompanyContext *CompanyContext `json:"company_context,omitempty"`

// // }

// // // TokenPairResponse returned to client
// // type TokenPairResponse struct {
// // 	AccessToken  string `json:"access_token"`
// // 	RefreshToken string `json:"refresh_token"`
// // 	ExpiresIn    int    `json:"expires_in"` // seconds until access token expires
// // 	TokenType    string `json:"token_type"` // "Bearer"
// // 	CompanyID        string   `json:"company_id,omitempty"` // 🆕 ADD THIS

// // }

// // // type CompanyContext struct {
// // //     CompanyID    string   `json:"company_id"`
// // //     EmployeeID   string   `json:"employee_id,omitempty"`
// // //     RoleID       string   `json:"role_id,omitempty"`
// // //     RoleLevel    string   `json:"role_level,omitempty"`
// // //     DepartmentID string   `json:"department_id,omitempty"`
// // //     Permissions  []string `json:"permissions"`
// // //     SubscriptionTier string `json:"subscription_tier,omitempty"`
// // // }
