package service

import (
	"context"
	"time"

	"auth-service/internal/hr/models/attendance"
	"auth-service/internal/hr/repository"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ============================================
// DTOs
// ============================================

type OfflinePunchEvent struct {
	EventType   string    `json:"event_type"`
	EventTime   time.Time `json:"event_time"`
	ExternalRef string    `json:"external_ref"`
}

type AttendanceBatchIngestRequest struct {
	CompanyID  uuid.UUID
	DeviceID   string
	SourceType string
	BatchRef   string
	Events     []OfflinePunchEvent
}

// ============================================
// SERVICE INTERFACE
// ============================================

type AttendanceBatchIngestService interface {
	IngestBatch(
		ctx context.Context,
		req *AttendanceBatchIngestRequest,
	) error
}

// ============================================
// IMPLEMENTATION
// ============================================

type attendanceBatchIngestService struct {
	batchRepo         repository.AttendanceBatchRepository
	deviceRepo        repository.AttendanceDeviceRepository
	ingestService     AttendanceIngestService
	enrollmentService AttendanceDeviceEnrollmentService
	logger            *zap.Logger
}

func NewAttendanceBatchIngestService(
	batchRepo repository.AttendanceBatchRepository,
	deviceRepo repository.AttendanceDeviceRepository,
	ingestService AttendanceIngestService,
	enrollmentService AttendanceDeviceEnrollmentService,
	logger *zap.Logger,
) AttendanceBatchIngestService {
	return &attendanceBatchIngestService{
		batchRepo:         batchRepo,
		deviceRepo:        deviceRepo,
		ingestService:     ingestService,
		enrollmentService: enrollmentService,
		logger:            logger,
	}
}

// ============================================
// CORE LOGIC
// ============================================

func (s *attendanceBatchIngestService) IngestBatch(
	ctx context.Context,
	req *AttendanceBatchIngestRequest,
) error {

	// ─────────────────────────────
	// 1️⃣ Validate device
	// ─────────────────────────────
	device, err := s.deviceRepo.GetActiveDevice(
		ctx,
		req.CompanyID,
		req.DeviceID,
	)
	if err != nil || device == nil || !device.IsTrusted {
		return repository.ErrValidationFailed
	}

	// ─────────────────────────────
	// 2️⃣ De-dup batch
	// ─────────────────────────────
	exists, err := s.batchRepo.ExistsByRef(
		ctx,
		req.CompanyID,
		req.DeviceID,
		req.BatchRef,
	)
	if err != nil {
		return err
	}
	if exists {
		s.logger.Info("Batch already processed",
			zap.String("batch_ref", req.BatchRef),
			zap.String("device_id", req.DeviceID),
		)
		return nil
	}

	// ─────────────────────────────
	// 3️⃣ Create batch record
	// (REPOSITORY struct, not model)
	// ─────────────────────────────
	batch := &repository.AttendancePunchBatch{
		BatchID:     uuid.New(),
		CompanyID:   req.CompanyID,
		DeviceID:    req.DeviceID,
		BatchRef:    req.BatchRef,
		TotalEvents: len(req.Events),
		Status:      "pending",
		ReceivedAt:  time.Now().UTC(),
	}

	if err := s.batchRepo.CreateBatch(ctx, batch); err != nil {
		return err
	}

	// ─────────────────────────────
	// 4️⃣ Process events (partial success)
	// ─────────────────────────────
	successCount := 0
	failureCount := 0

	for _, event := range req.Events {

		// Resolve user via enrollment
		userID, err := s.enrollmentService.ResolveUser(
			ctx,
			req.CompanyID,
			req.DeviceID,
			req.SourceType,
			event.ExternalRef,
		)
		if err != nil {
			s.logger.Warn("Failed to resolve user for batch event",
				zap.String("external_ref", event.ExternalRef),
				zap.Error(err),
			)
			failureCount++
			continue
		}

		// Build punch request
		punchReq := &PunchRequest{
			CompanyID:    req.CompanyID,
			TargetUserID: userID,
			EventType:    event.EventType,
			EventTime:    &event.EventTime,
			Source: PunchSource{
				SourceType: req.SourceType,
				DeviceID:   &req.DeviceID,
			},
			Context: &attendance.EventContext{
				ExternalRef: &event.ExternalRef,
			},
		}

		_, err = s.ingestService.IngestPunch(ctx, punchReq)
		if err != nil {
			s.logger.Warn("Failed to ingest batch punch",
				zap.String("external_ref", event.ExternalRef),
				zap.Error(err),
			)
			failureCount++
		} else {
			successCount++
		}
	}

	// ─────────────────────────────
	// 5️⃣ Final batch status
	// ─────────────────────────────
	if successCount == 0 && failureCount > 0 {
		err = s.batchRepo.MarkFailed(
			ctx,
			batch.BatchID,
			"all_events_failed",
		)
	} else {
		err = s.batchRepo.MarkProcessed(
			ctx,
			batch.BatchID,
		)
	}

	if err != nil {
		s.logger.Error("Failed to update batch status",
			zap.String("batch_id", batch.BatchID.String()),
			zap.Error(err),
		)
	}

	return nil
}
