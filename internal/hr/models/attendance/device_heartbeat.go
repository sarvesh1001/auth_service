package attendance

import (
	"time"

	"github.com/google/uuid"
)

type DeviceHeartbeat struct {
	HeartbeatID     uuid.UUID
	CompanyID       uuid.UUID
	DeviceID        string
	SourceType      string
	DeviceTime      *time.Time
	ServerTime      time.Time
	FirmwareVersion *string
	IPAddress       *string
	Status          string
	CreatedAt       time.Time
}

type DeviceHeartbeatRequest struct {
	DeviceTime      *time.Time `json:"device_time"`
	FirmwareVersion *string    `json:"firmware_version"`
	IPAddress       *string    `json:"ip_address"`
}
