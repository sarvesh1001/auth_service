package device

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
)

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

type DeviceValidationResult struct {
	IsValid    bool   `json:"is_valid"`
	IsActive   bool   `json:"is_active"`
	IsTrusted  bool   `json:"is_trusted"`
	DeviceName string `json:"device_name"`
	Message    string `json:"message,omitempty"`
}

type DeviceService interface {
	RegisterDevice(ctx context.Context, device *models.AttendanceDevice) error
	UpdateDevice(ctx context.Context, device *models.AttendanceDevice) error
	GetDevice(ctx context.Context, companyID uuid.UUID, deviceID string) (*models.AttendanceDevice, error)
	ListDevices(ctx context.Context, companyID uuid.UUID, filter DeviceFilter) ([]*models.AttendanceDevice, error)
	DeleteDevice(ctx context.Context, companyID uuid.UUID, deviceID string) error
	ActivateDevice(ctx context.Context, companyID uuid.UUID, deviceID string) error
	DeactivateDevice(ctx context.Context, companyID uuid.UUID, deviceID string) error
	MarkAsTrusted(ctx context.Context, companyID uuid.UUID, deviceID string) error
	RevokeTrust(ctx context.Context, companyID uuid.UUID, deviceID string) error
	ValidateDevice(ctx context.Context, companyID uuid.UUID, deviceID, sourceType string) (*DeviceValidationResult, error)
	GetDeviceStatistics(ctx context.Context, companyID uuid.UUID) (*repository.DeviceStatistics, error)
}

type deviceService struct {
	deviceRepo repository.DeviceRepository
	logger     *zap.Logger
}

func NewDeviceService(
	deviceRepo repository.DeviceRepository,
	logger *zap.Logger,
) DeviceService {
	return &deviceService{
		deviceRepo: deviceRepo,
		logger:     logger,
	}
}

func (s *deviceService) RegisterDevice(ctx context.Context, device *models.AttendanceDevice) error {
	if err := s.validateDeviceRegistration(device); err != nil {
		return err
	}
	existing, err := s.deviceRepo.GetDeviceByCode(ctx, device.CompanyID, device.DeviceCode)
	if err != nil && !errors.Is(err, repository.ErrDeviceNotFound) {
		return err
	}
	if existing != nil {
		return fmt.Errorf("device code '%s' already exists", device.DeviceCode)
	}
	if device.DeviceName == nil || *device.DeviceName == "" {
		device.DeviceName = &device.DeviceCode
	}
	if device.CreatedAt.IsZero() {
		device.CreatedAt = time.Now().UTC()
	}
	device.IsActive = true
	device.IsTrusted = false
	return s.deviceRepo.CreateDevice(ctx, device)
}

func (s *deviceService) UpdateDevice(ctx context.Context, device *models.AttendanceDevice) error {
	existing, err := s.deviceRepo.GetDevice(ctx, device.CompanyID, device.DeviceID)
	if err != nil {
		return err
	}
	if existing == nil {
		return repository.ErrDeviceNotFound
	}
	// Preserve immutable fields
	device.DeviceCode = existing.DeviceCode
	device.SourceType = existing.SourceType
	device.CreatedAt = existing.CreatedAt
	return s.deviceRepo.UpdateDevice(ctx, device)
}

func (s *deviceService) GetDevice(ctx context.Context, companyID uuid.UUID, deviceID string) (*models.AttendanceDevice, error) {
	return s.deviceRepo.GetDevice(ctx, companyID, deviceID)
}

func (s *deviceService) ListDevices(ctx context.Context, companyID uuid.UUID, filter DeviceFilter) ([]*models.AttendanceDevice, error) {
	var devices []*models.AttendanceDevice
	var err error

	activeOnly := !filter.IncludeInactive
	if filter.SourceType != nil && filter.WorkCenterCode != nil {
		devices, err = s.deviceRepo.GetDevicesByWorkCenter(ctx, companyID, *filter.WorkCenterCode, activeOnly)
		if err == nil && filter.SourceType != nil {
			filtered := make([]*models.AttendanceDevice, 0)
			for _, d := range devices {
				if d.SourceType == *filter.SourceType {
					filtered = append(filtered, d)
				}
			}
			devices = filtered
		}
	} else if filter.SourceType != nil {
		devices, err = s.deviceRepo.GetDevicesBySourceType(ctx, companyID, *filter.SourceType, activeOnly)
	} else if filter.WorkCenterCode != nil {
		devices, err = s.deviceRepo.GetDevicesByWorkCenter(ctx, companyID, *filter.WorkCenterCode, activeOnly)
	} else {
		devices, err = s.deviceRepo.GetDevicesByCompany(ctx, companyID, activeOnly)
	}
	if err != nil {
		return nil, err
	}

	// Apply additional filters
	devices = s.applyFilters(devices, filter)

	// Pagination
	if filter.Page > 0 && filter.PageSize > 0 {
		start := (filter.Page - 1) * filter.PageSize
		end := start + filter.PageSize
		if start < len(devices) {
			if end > len(devices) {
				end = len(devices)
			}
			devices = devices[start:end]
		} else {
			devices = []*models.AttendanceDevice{}
		}
	}
	return devices, nil
}

func (s *deviceService) DeleteDevice(ctx context.Context, companyID uuid.UUID, deviceID string) error {
	existing, err := s.deviceRepo.GetDevice(ctx, companyID, deviceID)
	if err != nil || existing == nil {
		return repository.ErrDeviceNotFound
	}
	return s.deviceRepo.DeactivateDevice(ctx, companyID, deviceID)
}

func (s *deviceService) ActivateDevice(ctx context.Context, companyID uuid.UUID, deviceID string) error {
	device, err := s.deviceRepo.GetDevice(ctx, companyID, deviceID)
	if err != nil || device == nil {
		return repository.ErrDeviceNotFound
	}
	if device.IsActive {
		return errors.New("device already active")
	}
	return s.deviceRepo.ActivateDevice(ctx, companyID, deviceID)
}

func (s *deviceService) DeactivateDevice(ctx context.Context, companyID uuid.UUID, deviceID string) error {
	device, err := s.deviceRepo.GetDevice(ctx, companyID, deviceID)
	if err != nil || device == nil {
		return repository.ErrDeviceNotFound
	}
	if !device.IsActive {
		return errors.New("device already inactive")
	}
	return s.deviceRepo.DeactivateDevice(ctx, companyID, deviceID)
}

func (s *deviceService) MarkAsTrusted(ctx context.Context, companyID uuid.UUID, deviceID string) error {
	device, err := s.deviceRepo.GetDevice(ctx, companyID, deviceID)
	if err != nil || device == nil {
		return repository.ErrDeviceNotFound
	}
	if device.IsTrusted {
		return errors.New("device already trusted")
	}
	return s.deviceRepo.MarkAsTrusted(ctx, companyID, deviceID)
}

func (s *deviceService) RevokeTrust(ctx context.Context, companyID uuid.UUID, deviceID string) error {
	device, err := s.deviceRepo.GetDevice(ctx, companyID, deviceID)
	if err != nil || device == nil {
		return repository.ErrDeviceNotFound
	}
	if !device.IsTrusted {
		return errors.New("device already not trusted")
	}
	return s.deviceRepo.RevokeTrust(ctx, companyID, deviceID)
}

func (s *deviceService) ValidateDevice(ctx context.Context, companyID uuid.UUID, deviceID, sourceType string) (*DeviceValidationResult, error) {
	device, err := s.deviceRepo.GetDevice(ctx, companyID, deviceID)
	if err != nil {
		if errors.Is(err, repository.ErrDeviceNotFound) {
			return &DeviceValidationResult{IsValid: false, Message: "Device not found"}, nil
		}
		return nil, err
	}
	if device == nil {
		return &DeviceValidationResult{IsValid: false, Message: "Device not found"}, nil
	}
	if device.SourceType != sourceType {
		return &DeviceValidationResult{
			IsValid:    false,
			IsActive:   device.IsActive,
			IsTrusted:  device.IsTrusted,
			DeviceName: *device.DeviceName,
			Message:    fmt.Sprintf("Source type mismatch: expected %s, got %s", device.SourceType, sourceType),
		}, nil
	}
	// Update last seen asynchronously
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.deviceRepo.UpdateLastSeen(ctx, deviceID)
	}()
	return &DeviceValidationResult{
		IsValid:    true,
		IsActive:   device.IsActive,
		IsTrusted:  device.IsTrusted,
		DeviceName: *device.DeviceName,
		Message:    "Device is valid",
	}, nil
}

func (s *deviceService) GetDeviceStatistics(ctx context.Context, companyID uuid.UUID) (*repository.DeviceStatistics, error) {
	return s.deviceRepo.GetDeviceStatistics(ctx, companyID)
}

// --- helpers ---

func (s *deviceService) validateDeviceRegistration(device *models.AttendanceDevice) error {
	if device.DeviceID == "" {
		return errors.New("device_id required")
	}
	if device.CompanyID == uuid.Nil {
		return errors.New("company_id required")
	}
	if device.SourceType == "" {
		return errors.New("source_type required")
	}
	if device.DeviceCode == "" {
		return errors.New("device_code required")
	}
	return nil
}

func (s *deviceService) applyFilters(devices []*models.AttendanceDevice, filter DeviceFilter) []*models.AttendanceDevice {
	if filter.IsActive == nil && filter.IsTrusted == nil && filter.LocationID == nil {
		return devices
	}
	result := make([]*models.AttendanceDevice, 0, len(devices))
	for _, d := range devices {
		if filter.IsActive != nil && d.IsActive != *filter.IsActive {
			continue
		}
		if filter.IsTrusted != nil && d.IsTrusted != *filter.IsTrusted {
			continue
		}
		if filter.LocationID != nil && (d.LocationID == nil || *d.LocationID != *filter.LocationID) {
			continue
		}
		result = append(result, d)
	}
	return result
}
