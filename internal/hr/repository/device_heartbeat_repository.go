package repository

import (
	"context"
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

type DeviceHeartbeatRepository interface {
	Insert(ctx context.Context, hb *DeviceHeartbeat) error
	GetLatestByDevice(
		ctx context.Context,
		companyID uuid.UUID,
		deviceID string,
	) (*DeviceHeartbeat, error)
}
