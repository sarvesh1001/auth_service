package repository

import (
	"context"

	"github.com/google/uuid"

	"auth-service/internal/attendance/models"
)

// DeviceHeartbeatRepository defines operations for device heartbeats
type DeviceHeartbeatRepository interface {
	// Insert stores a new heartbeat record
	Insert(ctx context.Context, hb *models.DeviceHeartbeat) error

	// GetLatestByDevice returns the most recent heartbeat for a given device
	GetLatestByDevice(ctx context.Context, companyID uuid.UUID, deviceID string) (*models.DeviceHeartbeat, error)
}
