package models

import (
	"time"

	"github.com/google/uuid"
)

type AttendanceDevice struct {
	DeviceID       string                 `json:"device_id" db:"device_id"`
	CompanyID      uuid.UUID              `json:"company_id" db:"company_id"`
	SourceType     string                 `json:"source_type" db:"source_type"`
	DeviceCode     string                 `json:"device_code" db:"device_code"`
	DeviceName     *string                `json:"device_name,omitempty" db:"device_name"`
	Manufacturer   *string                `json:"manufacturer,omitempty" db:"manufacturer"`
	Model          *string                `json:"model,omitempty" db:"model"`
	WorkCenterCode *string                `json:"work_center_code,omitempty" db:"work_center_code"`
	LocationID     *uuid.UUID             `json:"location_id,omitempty" db:"location_id"`
	IPAddress      *string                `json:"ip_address,omitempty" db:"ip_address"`
	MacAddress     *string                `json:"mac_address,omitempty" db:"mac_address"`
	IsActive       bool                   `json:"is_active" db:"is_active"`
	IsTrusted      bool                   `json:"is_trusted" db:"is_trusted"`
	LastSeenAt     *time.Time             `json:"last_seen_at,omitempty" db:"last_seen_at"`
	InstalledAt    *time.Time             `json:"installed_at,omitempty" db:"installed_at"`
	Metadata       map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
	CreatedAt      time.Time              `json:"created_at" db:"created_at"`
}
