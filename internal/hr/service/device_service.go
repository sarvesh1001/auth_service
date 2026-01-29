package service

import (
	"auth-service/internal/hr/models/attendance"
	"auth-service/internal/hr/repository"
	"auth-service/internal/util"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AttendanceDeviceService defines the interface for device management
type AttendanceDeviceService interface {
	// Device Registration & Management
	RegisterDevice(ctx context.Context, device *attendance.AttendanceDevice) error
	UpdateDevice(ctx context.Context, device *attendance.AttendanceDevice) error
	GetDevice(ctx context.Context, companyID uuid.UUID, deviceID string) (*attendance.AttendanceDevice, error)
	ListDevices(ctx context.Context, companyID uuid.UUID, filter DeviceFilter) ([]*attendance.AttendanceDevice, error)
	DeleteDevice(ctx context.Context, companyID uuid.UUID, deviceID string) error

	// Device Activation/Deactivation
	ActivateDevice(ctx context.Context, companyID uuid.UUID, deviceID string) error
	DeactivateDevice(ctx context.Context, companyID uuid.UUID, deviceID string) error

	// Device Trust Management
	MarkAsTrusted(ctx context.Context, companyID uuid.UUID, deviceID string) error
	RevokeTrust(ctx context.Context, companyID uuid.UUID, deviceID string) error

	// Device Validation
	ValidateDevice(ctx context.Context, companyID uuid.UUID, deviceID, sourceType string) (*DeviceValidationResult, error)

	// Device Statistics
	GetDeviceStatistics(ctx context.Context, companyID uuid.UUID) (*repository.DeviceStatistics, error)
}

// DeviceFilter for listing devices
type DeviceFilter struct {
	SourceType      *string
	WorkCenterCode  *string
	LocationID      *uuid.UUID
	IsActive        *bool
	IsTrusted       *bool
	IncludeInactive bool
	Page            int
	PageSize        int
}

// DeviceValidationResult for device validation
type DeviceValidationResult struct {
	IsValid    bool   `json:"is_valid"`
	IsActive   bool   `json:"is_active"`
	IsTrusted  bool   `json:"is_trusted"`
	DeviceName string `json:"device_name"`
	Message    string `json:"message,omitempty"`
}

// attendanceDeviceService implements AttendanceDeviceService
type attendanceDeviceService struct {
	deviceRepo     repository.AttendanceDeviceRepository
	attendanceRepo repository.AttendanceRepository
	logger         *zap.Logger
}

// NewAttendanceDeviceService creates a new device service
func NewAttendanceDeviceService(
	deviceRepo repository.AttendanceDeviceRepository,
	attendanceRepo repository.AttendanceRepository,
	logger *zap.Logger,
) AttendanceDeviceService {
	return &attendanceDeviceService{
		deviceRepo:     deviceRepo,
		attendanceRepo: attendanceRepo,
		logger:         logger,
	}
}

// RegisterDevice registers a new attendance device
func (s *attendanceDeviceService) RegisterDevice(
	ctx context.Context,
	device *attendance.AttendanceDevice,
) error {
	startTime := time.Now()

	// Validate required fields
	if err := s.validateDeviceRegistration(device); err != nil {
		s.logger.Error("Device registration validation failed",
			util.String("company_id", device.CompanyID.String()),
			util.String("device_code", device.DeviceCode),
			util.ErrorField(err))
		return fmt.Errorf("device validation failed: %w", err)
	}

	// Check if device code already exists for this company
	existingDevice, err := s.deviceRepo.GetDeviceByCode(ctx, device.CompanyID, device.DeviceCode)
	if err != nil && !errors.Is(err, repository.ErrDeviceNotFound) {
		return fmt.Errorf("failed to check device existence: %w", err)
	}

	if existingDevice != nil {
		return fmt.Errorf("device code '%s' already exists for company %s",
			device.DeviceCode, device.CompanyID.String())
	}

	// Set default values
	if device.DeviceName == nil || *device.DeviceName == "" {
		device.DeviceName = &device.DeviceCode
	}

	if device.CreatedAt.IsZero() {
		device.CreatedAt = time.Now().UTC()
	}

	// Default to active and trusted for new devices
	device.IsActive = true
	device.IsTrusted = true

	// Create the device
	if err := s.deviceRepo.CreateDevice(ctx, device); err != nil {
		s.logger.Error("Failed to register device",
			util.String("device_id", device.DeviceID),
			util.String("company_id", device.CompanyID.String()),
			util.String("device_code", device.DeviceCode),
			util.ErrorField(err))
		return fmt.Errorf("failed to register device: %w", err)
	}

	s.logger.Info("Device registered successfully",
		util.String("device_id", device.DeviceID),
		util.String("company_id", device.CompanyID.String()),
		util.String("device_code", device.DeviceCode),
		util.String("device_name", *device.DeviceName),
		util.String("source_type", device.SourceType),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// UpdateDevice updates an existing device
func (s *attendanceDeviceService) UpdateDevice(
	ctx context.Context,
	device *attendance.AttendanceDevice,
) error {
	startTime := time.Now()

	// Validate device exists and belongs to company
	existingDevice, err := s.deviceRepo.GetActiveDevice(ctx, device.CompanyID, device.DeviceID)
	if err != nil {
		if errors.Is(err, repository.ErrDeviceNotFound) {
			return fmt.Errorf("device not found: %s", device.DeviceID)
		}
		return fmt.Errorf("failed to get device: %w", err)
	}

	// Preserve immutable fields
	device.CompanyID = existingDevice.CompanyID
	device.DeviceID = existingDevice.DeviceID
	device.DeviceCode = existingDevice.DeviceCode
	device.SourceType = existingDevice.SourceType
	device.CreatedAt = existingDevice.CreatedAt

	// Update the device
	if err := s.deviceRepo.UpdateDevice(ctx, device); err != nil {
		s.logger.Error("Failed to update device",
			util.String("device_id", device.DeviceID),
			util.String("company_id", device.CompanyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update device: %w", err)
	}

	s.logger.Info("Device updated successfully",
		util.String("device_id", device.DeviceID),
		util.String("company_id", device.CompanyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// GetDevice retrieves a device by ID
func (s *attendanceDeviceService) GetDevice(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
) (*attendance.AttendanceDevice, error) {
	startTime := time.Now()

	device, err := s.deviceRepo.GetActiveDevice(ctx, companyID, deviceID)
	if err != nil {
		if errors.Is(err, repository.ErrDeviceNotFound) {
			return nil, nil
		}
		s.logger.Error("Failed to get device",
			util.String("company_id", companyID.String()),
			util.String("device_id", deviceID),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	s.logger.Debug("Device retrieved",
		util.String("device_id", deviceID),
		util.String("company_id", companyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return device, nil
}

// ListDevices lists devices with optional filters
func (s *attendanceDeviceService) ListDevices(
	ctx context.Context,
	companyID uuid.UUID,
	filter DeviceFilter,
) ([]*attendance.AttendanceDevice, error) {
	startTime := time.Now()

	var devices []*attendance.AttendanceDevice
	var err error

	// Apply filters
	if filter.SourceType != nil && filter.WorkCenterCode != nil {
		// Both source type and work center filter
		devices, err = s.deviceRepo.GetDevicesByWorkCenter(ctx, companyID, *filter.WorkCenterCode, !filter.IncludeInactive)
		if err != nil {
			s.logger.Error("Failed to list devices by work center",
				util.String("company_id", companyID.String()),
				util.String("work_center_code", *filter.WorkCenterCode),
				util.ErrorField(err))
			return nil, fmt.Errorf("failed to list devices: %w", err)
		}

		// Filter by source type
		if filter.SourceType != nil {
			filteredDevices := make([]*attendance.AttendanceDevice, 0)
			for _, device := range devices {
				if device.SourceType == *filter.SourceType {
					filteredDevices = append(filteredDevices, device)
				}
			}
			devices = filteredDevices
		}
	} else if filter.SourceType != nil {
		// Filter by source type only
		devices, err = s.deviceRepo.GetDevicesBySourceType(ctx, companyID, *filter.SourceType, !filter.IncludeInactive)
		if err != nil {
			s.logger.Error("Failed to list devices by source type",
				util.String("company_id", companyID.String()),
				util.String("source_type", *filter.SourceType),
				util.ErrorField(err))
			return nil, fmt.Errorf("failed to list devices: %w", err)
		}
	} else if filter.WorkCenterCode != nil {
		// Filter by work center only
		devices, err = s.deviceRepo.GetDevicesByWorkCenter(ctx, companyID, *filter.WorkCenterCode, !filter.IncludeInactive)
		if err != nil {
			s.logger.Error("Failed to list devices by work center",
				util.String("company_id", companyID.String()),
				util.String("work_center_code", *filter.WorkCenterCode),
				util.ErrorField(err))
			return nil, fmt.Errorf("failed to list devices: %w", err)
		}
	} else {
		// Get all devices
		devices, err = s.deviceRepo.GetDevicesByCompany(ctx, companyID, !filter.IncludeInactive)
		if err != nil {
			s.logger.Error("Failed to list devices by company",
				util.String("company_id", companyID.String()),
				util.ErrorField(err))
			return nil, fmt.Errorf("failed to list devices: %w", err)
		}
	}

	// Apply additional filters
	devices = s.applyAdditionalFilters(devices, filter)

	// Apply pagination
	if filter.Page > 0 && filter.PageSize > 0 {
		start := (filter.Page - 1) * filter.PageSize
		end := start + filter.PageSize
		if start >= len(devices) {
			devices = []*attendance.AttendanceDevice{}
		} else if end > len(devices) {
			devices = devices[start:]
		} else {
			devices = devices[start:end]
		}
	}

	s.logger.Debug("Devices listed",
		util.String("company_id", companyID.String()),
		util.Int("device_count", len(devices)),
		util.Duration("duration", time.Since(startTime)))

	return devices, nil
}

// DeleteDevice soft deletes a device
func (s *attendanceDeviceService) DeleteDevice(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
) error {
	startTime := time.Now()

	// Verify device exists and belongs to company
	_, err := s.deviceRepo.GetActiveDevice(ctx, companyID, deviceID)
	if err != nil {
		if errors.Is(err, repository.ErrDeviceNotFound) {
			return fmt.Errorf("device not found: %s", deviceID)
		}
		return fmt.Errorf("failed to get device: %w", err)
	}

	// Deactivate the device (soft delete)
	if err := s.deviceRepo.DeactivateDevice(ctx, deviceID); err != nil {
		s.logger.Error("Failed to delete device",
			util.String("company_id", companyID.String()),
			util.String("device_id", deviceID),
			util.ErrorField(err))
		return fmt.Errorf("failed to delete device: %w", err)
	}

	s.logger.Info("Device deleted successfully",
		util.String("device_id", deviceID),
		util.String("company_id", companyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// ActivateDevice activates a device
func (s *attendanceDeviceService) ActivateDevice(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
) error {
	startTime := time.Now()

	// Verify device exists
	device, err := s.deviceRepo.GetDeviceByCode(ctx, companyID, deviceID)
	if err != nil {
		return fmt.Errorf("device not found: %s", deviceID)
	}

	if device.IsActive {
		return fmt.Errorf("device is already active")
	}

	// Activate the device
	if err := s.deviceRepo.ActivateDevice(ctx, deviceID); err != nil {
		s.logger.Error("Failed to activate device",
			util.String("company_id", companyID.String()),
			util.String("device_id", deviceID),
			util.ErrorField(err))
		return fmt.Errorf("failed to activate device: %w", err)
	}

	s.logger.Info("Device activated",
		util.String("device_id", deviceID),
		util.String("company_id", companyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// DeactivateDevice deactivates a device
func (s *attendanceDeviceService) DeactivateDevice(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
) error {
	startTime := time.Now()

	// Verify device exists
	device, err := s.deviceRepo.GetActiveDevice(ctx, companyID, deviceID)
	if err != nil {
		return fmt.Errorf("device not found: %s", deviceID)
	}

	if !device.IsActive {
		return fmt.Errorf("device is already inactive")
	}

	// Deactivate the device
	if err := s.deviceRepo.DeactivateDevice(ctx, deviceID); err != nil {
		s.logger.Error("Failed to deactivate device",
			util.String("company_id", companyID.String()),
			util.String("device_id", deviceID),
			util.ErrorField(err))
		return fmt.Errorf("failed to deactivate device: %w", err)
	}

	s.logger.Info("Device deactivated",
		util.String("device_id", deviceID),
		util.String("company_id", companyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// MarkAsTrusted marks a device as trusted
func (s *attendanceDeviceService) MarkAsTrusted(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
) error {
	startTime := time.Now()

	// Get the device
	device, err := s.deviceRepo.GetActiveDevice(ctx, companyID, deviceID)
	if err != nil {
		return fmt.Errorf("device not found: %s", deviceID)
	}

	if device.IsTrusted {
		return fmt.Errorf("device is already trusted")
	}

	// Update device to trusted
	device.IsTrusted = true
	if err := s.deviceRepo.UpdateDevice(ctx, device); err != nil {
		s.logger.Error("Failed to mark device as trusted",
			util.String("company_id", companyID.String()),
			util.String("device_id", deviceID),
			util.ErrorField(err))
		return fmt.Errorf("failed to mark device as trusted: %w", err)
	}

	s.logger.Info("Device marked as trusted",
		util.String("device_id", deviceID),
		util.String("company_id", companyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// RevokeTrust revokes trust from a device
func (s *attendanceDeviceService) RevokeTrust(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
) error {
	startTime := time.Now()

	// Get the device
	device, err := s.deviceRepo.GetActiveDevice(ctx, companyID, deviceID)
	if err != nil {
		return fmt.Errorf("device not found: %s", deviceID)
	}

	if !device.IsTrusted {
		return fmt.Errorf("device is already not trusted")
	}

	// Update device to not trusted
	device.IsTrusted = false
	if err := s.deviceRepo.UpdateDevice(ctx, device); err != nil {
		s.logger.Error("Failed to revoke device trust",
			util.String("company_id", companyID.String()),
			util.String("device_id", deviceID),
			util.ErrorField(err))
		return fmt.Errorf("failed to revoke device trust: %w", err)
	}

	s.logger.Info("Device trust revoked",
		util.String("device_id", deviceID),
		util.String("company_id", companyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// ValidateDevice validates a device for attendance capture
func (s *attendanceDeviceService) ValidateDevice(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID, sourceType string,
) (*DeviceValidationResult, error) {
	startTime := time.Now()

	// Get the device
	device, err := s.deviceRepo.GetActiveDevice(ctx, companyID, deviceID)
	if err != nil {
		if errors.Is(err, repository.ErrDeviceNotFound) {
			return &DeviceValidationResult{
				IsValid:   false,
				IsActive:  false,
				IsTrusted: false,
				Message:   "Device not found",
			}, nil
		}
		return nil, fmt.Errorf("failed to validate device: %w", err)
	}

	// Check source type match
	if device.SourceType != sourceType {
		return &DeviceValidationResult{
			IsValid:    false,
			IsActive:   device.IsActive,
			IsTrusted:  device.IsTrusted,
			DeviceName: *device.DeviceName,
			Message:    fmt.Sprintf("Device source type mismatch: expected %s, got %s", device.SourceType, sourceType),
		}, nil
	}

	// Update last seen
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.deviceRepo.UpdateLastSeen(ctx, deviceID); err != nil {
			s.logger.Warn("Failed to update device last seen",
				util.String("device_id", deviceID),
				util.ErrorField(err))
		}
	}()

	s.logger.Debug("Device validated",
		util.String("device_id", deviceID),
		util.String("company_id", companyID.String()),
		util.Bool("is_valid", true),
		util.Duration("duration", time.Since(startTime)))

	return &DeviceValidationResult{
		IsValid:    true,
		IsActive:   device.IsActive,
		IsTrusted:  device.IsTrusted,
		DeviceName: *device.DeviceName,
		Message:    "Device is valid",
	}, nil
}

// GetDeviceStatistics returns device statistics
func (s *attendanceDeviceService) GetDeviceStatistics(
	ctx context.Context,
	companyID uuid.UUID,
) (*repository.DeviceStatistics, error) {
	startTime := time.Now()

	stats, err := s.deviceRepo.GetDeviceStatistics(ctx, companyID)
	if err != nil {
		s.logger.Error("Failed to get device statistics",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get device statistics: %w", err)
	}

	s.logger.Debug("Device statistics retrieved",
		util.String("company_id", companyID.String()),
		util.Int("total_devices", stats.TotalDevices),
		util.Int("active_devices", stats.ActiveDevices),
		util.Duration("duration", time.Since(startTime)))

	return stats, nil
}

// validateDeviceRegistration validates device registration request
func (s *attendanceDeviceService) validateDeviceRegistration(device *attendance.AttendanceDevice) error {
	if device.DeviceID == "" {
		return errors.New("device ID is required")
	}

	if device.CompanyID == uuid.Nil {
		return errors.New("company ID is required")
	}

	if device.SourceType == "" {
		return errors.New("source type is required")
	}

	if device.DeviceCode == "" {
		return errors.New("device code is required")
	}

	// Validate source type is supported
	supportedSourceTypes := map[string]bool{
		"mobile":    true,
		"biometric": true,
		"rfid":      true,
		"kiosk":     true,
		"factory":   true,
		"classroom": true,
	}

	if !supportedSourceTypes[device.SourceType] {
		return fmt.Errorf("unsupported source type: %s", device.SourceType)
	}

	return nil
}

// applyAdditionalFilters applies additional filters to devices
func (s *attendanceDeviceService) applyAdditionalFilters(
	devices []*attendance.AttendanceDevice,
	filter DeviceFilter,
) []*attendance.AttendanceDevice {
	if filter.IsActive == nil && filter.IsTrusted == nil && filter.LocationID == nil {
		return devices
	}

	filtered := make([]*attendance.AttendanceDevice, 0, len(devices))
	for _, device := range devices {
		// Filter by active status
		if filter.IsActive != nil && device.IsActive != *filter.IsActive {
			continue
		}

		// Filter by trusted status
		if filter.IsTrusted != nil && device.IsTrusted != *filter.IsTrusted {
			continue
		}

		// Filter by location
		if filter.LocationID != nil && device.LocationID != nil {
			if *device.LocationID != *filter.LocationID {
				continue
			}
		}

		filtered = append(filtered, device)
	}

	return filtered
}
