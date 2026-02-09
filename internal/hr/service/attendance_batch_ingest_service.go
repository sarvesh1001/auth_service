package service

import (
	"context"
	"encoding/json" // 👈 ADD THIS
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

	GetFailures(
		ctx context.Context,
		companyID uuid.UUID,
		deviceID string,
		batchRef string,
		limit int,
		offset int,
	) ([]repository.AttendancePunchFailureView, error)

	GetStatus(
		ctx context.Context,
		companyID uuid.UUID,
		deviceID string,
		batchRef string,
	) (*repository.AttendanceBatchStatus, error)
}

// ============================================
// IMPLEMENTATION
// ============================================

type attendanceBatchIngestService struct {
	batchRepo         repository.AttendanceBatchRepository
	outboxRepo        repository.AttendanceBatchOutboxRepository
	deviceRepo        repository.AttendanceDeviceRepository
	ingestService     AttendanceIngestService
	enrollmentService AttendanceDeviceEnrollmentService
	logger            *zap.Logger
}

func NewAttendanceBatchIngestService(
	batchRepo repository.AttendanceBatchRepository,
	outboxRepo repository.AttendanceBatchOutboxRepository,
	deviceRepo repository.AttendanceDeviceRepository,
	ingestService AttendanceIngestService,
	enrollmentService AttendanceDeviceEnrollmentService,
	logger *zap.Logger,
) AttendanceBatchIngestService {
	return &attendanceBatchIngestService{
		batchRepo:         batchRepo,
		outboxRepo:        outboxRepo,
		deviceRepo:        deviceRepo,
		ingestService:     ingestService,
		enrollmentService: enrollmentService,
		logger:            logger,
	}
}

// ============================================
// QUERY
// ============================================

func (s *attendanceBatchIngestService) GetStatus(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
	batchRef string,
) (*repository.AttendanceBatchStatus, error) {
	return s.batchRepo.GetByRef(ctx, companyID, deviceID, batchRef)
}

// ============================================
// CORE INGEST (PARTIAL FAILURE SAFE)
// ============================================

func (s *attendanceBatchIngestService) IngestBatch(
	ctx context.Context,
	req *AttendanceBatchIngestRequest,
) error {

	// 1️⃣ Validate device
	device, err := s.deviceRepo.GetActiveDevice(ctx, req.CompanyID, req.DeviceID)
	if err != nil || device == nil || !device.IsTrusted {
		return repository.ErrValidationFailed
	}

	// 2️⃣ Idempotency
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

	// 3️⃣ Create batch
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

	successCount := 0
	failureCount := 0

	// 4️⃣ Emit batch received outbox (ONCE)
	_ = s.outboxRepo.Insert(ctx, &repository.AttendanceBatchOutbox{
		OutboxID:    uuid.New(),
		EventType:   "attendance.batch.received",
		AggregateID: batch.BatchID,
		Payload: map[string]interface{}{
			"batch_id":     batch.BatchID,
			"batch_ref":    batch.BatchRef,
			"company_id":   batch.CompanyID,
			"device_id":    batch.DeviceID,
			"total_events": batch.TotalEvents,
			"received_at":  batch.ReceivedAt,
		},
		CreatedAt: time.Now().UTC(),
	})

	// 5️⃣ Process events (PARTIAL FAILURE SAFE)
	for _, event := range req.Events {

		userID, err := s.enrollmentService.ResolveUser(
			ctx,
			req.CompanyID,
			req.DeviceID,
			req.SourceType,
			event.ExternalRef,
		)
		if err != nil {
			s.recordFailure(ctx, batch, event, "user_resolution_failed: "+err.Error())
			failureCount++
			continue
		}

		punchReq := &PunchRequest{
			CompanyID:    req.CompanyID,
			TargetUserID: userID,
			EventType:    event.EventType,
			EventTime:    &event.EventTime,

			// 🔥 REQUIRED FOR DEVICE SOURCES (THIS WAS MISSING)
			DeviceUserCode: &event.ExternalRef,

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
			s.recordFailure(ctx, batch, event, "punch_ingest_failed: "+err.Error())
			failureCount++
			continue
		}

		successCount++

		// 🔥 Emit raw event outbox (PER SUCCESS)
		_ = s.outboxRepo.Insert(ctx, &repository.AttendanceBatchOutbox{
			OutboxID:    uuid.New(),
			EventType:   "attendance.raw.events",
			AggregateID: batch.BatchID,
			Payload: map[string]interface{}{
				"company_id":   req.CompanyID,
				"device_id":    req.DeviceID,
				"batch_ref":    req.BatchRef,
				"user_id":      userID,
				"event_type":   event.EventType,
				"event_time":   event.EventTime,
				"external_ref": event.ExternalRef,
				"source_type":  req.SourceType,
			},
			CreatedAt: time.Now().UTC(),
		})
	}

	// 6️⃣ Final batch status
	if successCount == 0 && failureCount > 0 {
		err = s.batchRepo.MarkFailed(ctx, batch.BatchID, "all_events_failed")
	} else {
		err = s.batchRepo.MarkProcessed(ctx, batch.BatchID)
	}

	if err != nil {
		s.logger.Error(
			"Failed to update batch status",
			zap.String("batch_id", batch.BatchID.String()),
			zap.Error(err),
		)
	}

	return nil
}

// ============================================
// FAILURE LOGGER
// ============================================

func (s *attendanceBatchIngestService) recordFailure(
	ctx context.Context,
	batch *repository.AttendancePunchBatch,
	event OfflinePunchEvent,
	reason string,
) {
	rawEvent := map[string]interface{}{
		"event_type":   event.EventType,
		"event_time":   event.EventTime,
		"external_ref": event.ExternalRef,
	}

	rawJSON, err := json.Marshal(rawEvent)
	if err != nil {
		s.logger.Error(
			"Failed to marshal raw failure event",
			zap.String("batch_id", batch.BatchID.String()),
			zap.Error(err),
		)
		return
	}

	failure := &repository.AttendancePunchFailure{
		FailureID:      uuid.New(),
		BatchID:        batch.BatchID,
		CompanyID:      batch.CompanyID,
		DeviceID:       batch.DeviceID,
		DeviceUserCode: &event.ExternalRef,
		EventType:      &event.EventType,
		EventTime:      &event.EventTime,
		FailureReason:  reason,
		RawEvent:       rawJSON, // ✅ FIXED (jsonb safe)
		CreatedAt:      time.Now().UTC(),
	}

	if err := s.batchRepo.InsertFailure(ctx, failure); err != nil {
		s.logger.Error(
			"Failed to persist batch failure",
			zap.String("batch_id", batch.BatchID.String()),
			zap.Error(err),
		)
	}
}

func (s *attendanceBatchIngestService) GetFailures(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
	batchRef string,
	limit int,
	offset int,
) ([]repository.AttendancePunchFailureView, error) {
	return s.batchRepo.ListFailuresByBatch(
		ctx,
		companyID,
		deviceID,
		batchRef,
		limit,
		offset,
	)
}
