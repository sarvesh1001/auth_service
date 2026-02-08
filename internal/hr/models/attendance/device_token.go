package attendance

import (
	"time"

	"github.com/google/uuid"
)

type DeviceToken struct {
	TokenID      uuid.UUID  `json:"token_id" db:"token_id"`
	CompanyID    uuid.UUID  `json:"company_id" db:"company_id"`
	DeviceID     string     `json:"device_id" db:"device_id"`
	SourceType   string     `json:"source_type" db:"source_type"`
	TokenHash    string     `json:"token_hash" db:"token_hash"`
	TokenVersion int        `json:"token_version" db:"token_version"`
	IsActive     bool       `json:"is_active" db:"is_active"`
	IssuedAt     time.Time  `json:"issued_at" db:"issued_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	IssuedBy     *uuid.UUID `json:"issued_by,omitempty" db:"issued_by"`
	RevokedBy    *uuid.UUID `json:"revoked_by,omitempty" db:"revoked_by"`
	RevokeReason *string    `json:"revoke_reason,omitempty" db:"revoke_reason"`
	Metadata     JSONB      `json:"metadata,omitempty" db:"metadata"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
}

type DeviceAuthContext struct {
	CompanyID    uuid.UUID `json:"company_id"`
	DeviceID     string    `json:"device_id"`
	SourceType   string    `json:"source_type"`
	TokenID      uuid.UUID `json:"token_id"`
	IsTrusted    bool      `json:"is_trusted"`
	WorkCenterID *string   `json:"work_center_id,omitempty"`
}

type IssueTokenRequest struct {
	CompanyID  uuid.UUID  `json:"company_id"`
	DeviceID   string     `json:"device_id"`
	SourceType string     `json:"source_type"`
	ExpiresIn  *int64     `json:"expires_in,omitempty"` // seconds
	IssuedBy   *uuid.UUID `json:"issued_by,omitempty"`
	Metadata   JSONB      `json:"metadata,omitempty"`
}

type ValidateTokenRequest struct {
	RawToken  string    `json:"raw_token"`
	CompanyID uuid.UUID `json:"company_id"`
	DeviceID  string    `json:"device_id"`
}

type TokenValidationResult struct {
	IsValid     bool               `json:"is_valid"`
	Token       *DeviceToken       `json:"token,omitempty"`
	AuthContext *DeviceAuthContext `json:"auth_context,omitempty"`
	Error       string             `json:"error,omitempty"`
}
