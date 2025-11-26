// internal/models/pairing.go
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

// internal/models/pairing.go

type PairingSession struct {
	SessionID   string    `json:"session_id"`
	UserID      string    `json:"user_id,omitempty"`
	PhoneNumber string    `json:"phone_number,omitempty"`
	DeviceID    string    `json:"device_id,omitempty"`
	Status      string    `json:"status"` // pending, scanned, confirmed, expired
	Nonce       string    `json:"nonce"`
	QRPayload   string    `json:"qr_payload"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	ScannedAt   time.Time `json:"scanned_at,omitempty"`
	ConfirmedAt time.Time `json:"confirmed_at,omitempty"`
	IPAddress   string    `json:"ip_address,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	WebDeviceID string    `json:"web_device_id"`

	// ✅ NEW: Session type and role information
	SessionType string   `json:"session_type,omitempty"` // "user" or "admin"
	Role        string   `json:"role,omitempty"`         // user role or admin role level
	Permissions []string `json:"permissions,omitempty"`  // admin permissions
}

// Update PairingStatusResponse to include session type
type PairingStatusResponse struct {
	SessionID   string    `json:"session_id"`
	Status      string    `json:"status"`
	UserID      string    `json:"user_id,omitempty"`
	PhoneNumber string    `json:"phone_number,omitempty"`
	SessionType string    `json:"session_type,omitempty"` // ✅ NEW
	Role        string    `json:"role,omitempty"`         // ✅ NEW
	ExpiresAt   time.Time `json:"expires_at"`
}
