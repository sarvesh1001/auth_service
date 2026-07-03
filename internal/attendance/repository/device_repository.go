package repository

import (
	"context"

	"github.com/google/uuid"

	"auth-service/internal/attendance/models"
)

// DeviceStatistics holds aggregated device stats
type DeviceStatistics struct {
	TotalDevices      int            `json:"total_devices"`
	ActiveDevices     int            `json:"active_devices"`
	TrustedDevices    int            `json:"trusted_devices"`
	BySourceType      map[string]int `json:"by_source_type"`
	ByWorkCenter      map[string]int `json:"by_work_center"`
	AverageUptimeDays float64        `json:"average_uptime_days"`
}

// DeviceRepository defines operations for attendance devices
type DeviceRepository interface {
	// GetDevice retrieves a device by ID and company
	GetDevice(ctx context.Context, companyID uuid.UUID, deviceID string) (*models.AttendanceDevice, error)

	// GetActiveDevice retrieves an active device (is_active = true)
	GetActiveDevice(ctx context.Context, companyID uuid.UUID, deviceID string) (*models.AttendanceDevice, error)

	// GetDeviceByCode retrieves a device by its device_code (unique per company)
	GetDeviceByCode(ctx context.Context, companyID uuid.UUID, deviceCode string) (*models.AttendanceDevice, error)

	// GetDevicesByCompany lists devices for a company (optionally only active)
	GetDevicesByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.AttendanceDevice, error)

	// GetDevicesByWorkCenter lists devices by work center code
	GetDevicesByWorkCenter(ctx context.Context, companyID uuid.UUID, workCenterCode string, activeOnly bool) ([]*models.AttendanceDevice, error)

	// GetDevicesBySourceType lists devices by source type
	GetDevicesBySourceType(ctx context.Context, companyID uuid.UUID, sourceType string, activeOnly bool) ([]*models.AttendanceDevice, error)

	// CreateDevice inserts a new device
	CreateDevice(ctx context.Context, device *models.AttendanceDevice) error

	// UpdateDevice updates an existing device
	UpdateDevice(ctx context.Context, device *models.AttendanceDevice) error

	// UpdateLastSeen updates the last_seen_at timestamp for a device
	UpdateLastSeen(ctx context.Context, deviceID string) error

	// DeactivateDevice sets is_active = false
	DeactivateDevice(ctx context.Context, companyID uuid.UUID, deviceID string) error

	// ActivateDevice sets is_active = true
	ActivateDevice(ctx context.Context, companyID uuid.UUID, deviceID string) error

	// MarkAsTrusted sets is_trusted = true
	MarkAsTrusted(ctx context.Context, companyID uuid.UUID, deviceID string) error

	// RevokeTrust sets is_trusted = false
	RevokeTrust(ctx context.Context, companyID uuid.UUID, deviceID string) error

	// UpdateDeviceMetadata updates the metadata JSONB field
	UpdateDeviceMetadata(ctx context.Context, deviceID string, metadata map[string]interface{}) error

	// CountDevicesByCompany counts devices for a company (optionally active only)
	CountDevicesByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) (int, error)

	// GetDeviceStatistics returns aggregated stats
	GetDeviceStatistics(ctx context.Context, companyID uuid.UUID) (*DeviceStatistics, error)

	// HealthCheck verifies DB connectivity
	HealthCheck(ctx context.Context) error
}
