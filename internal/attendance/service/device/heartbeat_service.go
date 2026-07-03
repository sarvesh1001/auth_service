package device

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
)

type HeartbeatRequest struct {
	CompanyID       uuid.UUID
	DeviceID        string
	SourceType      string
	DeviceTime      *time.Time
	FirmwareVersion *string
	IPAddress       *string
}

type HeartbeatService interface {
	Heartbeat(ctx context.Context, req *HeartbeatRequest) error
}

type heartbeatService struct {
	heartbeatRepo repository.DeviceHeartbeatRepository // ✅ fixed
	deviceRepo    repository.DeviceRepository
	logger        *zap.Logger
}

func NewHeartbeatService(
	heartbeatRepo repository.DeviceHeartbeatRepository, // ✅ fixed
	deviceRepo repository.DeviceRepository,
	logger *zap.Logger,
) HeartbeatService {
	return &heartbeatService{
		heartbeatRepo: heartbeatRepo,
		deviceRepo:    deviceRepo,
		logger:        logger,
	}
}

func (s *heartbeatService) Heartbeat(ctx context.Context, req *HeartbeatRequest) error {
	device, err := s.deviceRepo.GetActiveDevice(ctx, req.CompanyID, req.DeviceID)
	if err != nil {
		return err
	}
	if device == nil || !device.IsTrusted {
		return repository.ErrDeviceNotFound
	}

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

	heartbeat := &models.DeviceHeartbeat{
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

	if err := s.heartbeatRepo.Insert(ctx, heartbeat); err != nil {
		s.logger.Error("Failed to insert heartbeat", zap.Error(err))
		return err
	}

	if err := s.deviceRepo.UpdateLastSeen(ctx, req.DeviceID); err != nil {
		s.logger.Warn("Failed to update device last_seen", zap.Error(err))
	}

	return nil
}
