package service

import (
	"context"
	"time"

	"auth-service/internal/hr/repository"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ============================================
// REQUEST DTO
// ============================================

type DeviceHeartbeatRequest struct {
	CompanyID       uuid.UUID
	DeviceID        string
	SourceType      string
	DeviceTime      *time.Time
	FirmwareVersion *string
	IPAddress       *string
}

// ============================================
// SERVICE INTERFACE
// ============================================

type DeviceHeartbeatService interface {
	Heartbeat(ctx context.Context, req *DeviceHeartbeatRequest) error
}

// ============================================
// IMPLEMENTATION
// ============================================

type deviceHeartbeatService struct {
	heartbeatRepo repository.DeviceHeartbeatRepository
	deviceRepo    repository.AttendanceDeviceRepository
	logger        *zap.Logger
}

func NewDeviceHeartbeatService(
	heartbeatRepo repository.DeviceHeartbeatRepository,
	deviceRepo repository.AttendanceDeviceRepository,
	logger *zap.Logger,
) DeviceHeartbeatService {
	return &deviceHeartbeatService{
		heartbeatRepo: heartbeatRepo,
		deviceRepo:    deviceRepo,
		logger:        logger,
	}
}

// ============================================
// CORE LOGIC
// ============================================

func (s *deviceHeartbeatService) Heartbeat(
	ctx context.Context,
	req *DeviceHeartbeatRequest,
) error {

	// ─────────────────────────────
	// 1️⃣ Validate device
	// ─────────────────────────────
	device, err := s.deviceRepo.GetActiveDevice(
		ctx,
		req.CompanyID,
		req.DeviceID,
	)
	if err != nil {
		return err
	}
	if device == nil || !device.IsTrusted {
		return repository.ErrValidationFailed
	}

	// ─────────────────────────────
	// 2️⃣ Compute status (clock drift)
	// ─────────────────────────────
	serverTime := time.Now().UTC()
	status := "online"

	if req.DeviceTime != nil {
		drift := serverTime.Sub(*req.DeviceTime)
		if drift < 0 {
			drift = -drift
		}
		if drift > 5*time.Minute {
			status = "degraded"
		}
	}

	// ─────────────────────────────
	// 3️⃣ Build REPOSITORY heartbeat
	// IMPORTANT: repo struct, not model
	// ─────────────────────────────
	heartbeat := &repository.DeviceHeartbeat{
		HeartbeatID:     uuid.New(),
		CompanyID:       req.CompanyID,
		DeviceID:        req.DeviceID,
		SourceType:      req.SourceType,
		DeviceTime:      req.DeviceTime,
		ServerTime:      serverTime,
		FirmwareVersion: req.FirmwareVersion,
		IPAddress:       req.IPAddress,
		Status:          status,
		CreatedAt:       serverTime,
	}

	// ─────────────────────────────
	// 4️⃣ Persist heartbeat
	// ─────────────────────────────
	if err := s.heartbeatRepo.Insert(ctx, heartbeat); err != nil {
		s.logger.Error(
			"Failed to insert device heartbeat",
			zap.String("device_id", req.DeviceID),
			zap.String("company_id", req.CompanyID.String()),
			zap.Error(err),
		)
		return err
	}

	// ─────────────────────────────
	// 5️⃣ Update device last_seen
	// ─────────────────────────────
	if err := s.deviceRepo.UpdateLastSeen(
		ctx,
		req.DeviceID,
	); err != nil {
		s.logger.Warn(
			"Failed to update device last_seen",
			zap.String("device_id", req.DeviceID),
			zap.Error(err),
		)
	}

	return nil
}
