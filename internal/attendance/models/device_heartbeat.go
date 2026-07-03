package models

import (
	"time"

	"github.com/google/uuid"
)

type DeviceHeartbeat struct {
	HeartbeatID     uuid.UUID  `json:"heartbeat_id" db:"heartbeat_id"`
	CompanyID       uuid.UUID  `json:"company_id" db:"company_id"`
	DeviceID        string     `json:"device_id" db:"device_id"`
	SourceType      string     `json:"source_type" db:"source_type"`
	DeviceTime      *time.Time `json:"device_time,omitempty" db:"device_time"`
	ServerTime      time.Time  `json:"server_time" db:"server_time"`
	FirmwareVersion *string    `json:"firmware_version,omitempty" db:"firmware_version"`
	IPAddress       *string    `json:"ip_address,omitempty" db:"ip_address"`
	Status          string     `json:"status" db:"status"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
}

type DeviceHeartbeatRequest struct {
	DeviceTime      *time.Time `json:"device_time"`
	FirmwareVersion *string    `json:"firmware_version"`
	IPAddress       *string    `json:"ip_address"`
}
