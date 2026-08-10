package models

import (
	"time"
)

type QRCodeResponse struct {
	SessionID string `json:"session_id"`
	QRCode    string `json:"qr_code"`
	ExpiresIn int64  `json:"expires_in"`
	StatusURL string `json:"status_url"`
}

type PairingRequest struct {
	SessionID string `json:"session_id" validate:"required"`
	Signature string `json:"signature" validate:"required"`
}

type WebSocketMessage struct {
	Type    string      `json:"type"` // status_update, error, paired
	Payload interface{} `json:"payload"`
}
type PairingSession struct {
	SessionID   string    `json:"session_id"`
	UserID      string    `json:"user_id,omitempty"`
	PhoneNumber string    `json:"phone_number,omitempty"`
	DeviceID    string    `json:"device_id,omitempty"`
	CompanyID   string    `json:"company_id,omitempty"` // 👈 NEW
	Status      string    `json:"status"`               // pending, scanned, confirmed, expired
	Nonce       string    `json:"nonce"`
	QRPayload   string    `json:"qr_payload"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	ScannedAt   time.Time `json:"scanned_at,omitempty"`
	ConfirmedAt time.Time `json:"confirmed_at,omitempty"`
	IPAddress   string    `json:"ip_address,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	WebDeviceID string    `json:"web_device_id"`
	SessionType string    `json:"session_type,omitempty"`
	Role        string    `json:"role,omitempty"`
	Permissions []string  `json:"permissions,omitempty"`
}

// // GetRoleMask converts role string to role mask
// func (p *PairingSession) GetRoleMask() uint64 {
// 	switch p.Role {
// 	case "owner":
// 		return RoleMaskOwner
// 	case "super_employee":
// 		return RoleMaskSuperEmployee
// 	case "employee":
// 		return RoleMaskEmployee
// 	default:
// 		return 0
// 	}
// }

// // GetPermissionMask converts permission strings to bitmask
// func (p *PairingSession) GetPermissionMask() []uint64 {
// 	mask := make([]uint64, 4)
// 	for _, perm := range p.Permissions {
// 		if bitIndex, exists := AdminPermissionBitIndices[perm]; exists {
// 			mask = SetPermission(mask, bitIndex, true)
// 		}
// 	}
// 	return mask
// }

// PairingStatusResponse
type PairingStatusResponse struct {
	SessionID   string    `json:"session_id"`
	Status      string    `json:"status"`
	UserID      string    `json:"user_id,omitempty"`
	PhoneNumber string    `json:"phone_number,omitempty"`
	SessionType string    `json:"session_type,omitempty"`
	Role        string    `json:"role,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// GetRoleString converts role type int to role string
func GetRoleString(roleType int, sessionType string) string {
	if sessionType == "admin" {
		switch roleType {
		case RoleTypeSuperAdmin:
			return RoleAdminSuperAdmin
		case RoleTypeManager:
			return RoleAdminManager
		case RoleTypeEmployee:
			return RoleAdminEmployee
		default:
			return ""
		}
	}
	return ""
}

// GetRoleTypeFromString converts role string to role type int
func GetRoleTypeFromString(role string) int {
	switch role {
	case RoleAdminSuperAdmin:
		return RoleTypeSuperAdmin
	case RoleAdminManager:
		return RoleTypeManager
	case RoleAdminEmployee:
		return RoleTypeEmployee
	default:
		return 0
	}
}
