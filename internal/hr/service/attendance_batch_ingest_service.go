package service

import (
	"context"
	"encoding/json"
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

	// 🔥 ENTRY LOG
	s.logger.Info("IngestBatch START",
		zap.String("company_id", req.CompanyID.String()),
		zap.String("device_id", req.DeviceID),
		zap.String("source_type", req.SourceType),
		zap.String("batch_ref", req.BatchRef),
		zap.Int("event_count", len(req.Events)),
	)

	// 1️⃣ Validate device
	device, err := s.deviceRepo.GetActiveDevice(ctx, req.CompanyID, req.DeviceID)
	if err != nil || device == nil || !device.IsTrusted {
		s.logger.Error("Device validation failed",
			zap.String("device_id", req.DeviceID),
			zap.Error(err),
		)
		return repository.ErrValidationFailed
	}
	s.logger.Info("Device validated",
		zap.String("device_id", device.DeviceID),
		zap.Bool("is_trusted", device.IsTrusted),
	)

	// 2️⃣ Idempotency
	exists, err := s.batchRepo.ExistsByRef(
		ctx,
		req.CompanyID,
		req.DeviceID,
		req.BatchRef,
	)
	if err != nil {
		s.logger.Error("Idempotency check failed",
			zap.String("batch_ref", req.BatchRef),
			zap.Error(err),
		)
		return err
	}
	if exists {
		s.logger.Info("Batch already processed, skipping",
			zap.String("batch_ref", req.BatchRef),
			zap.String("device_id", req.DeviceID),
		)
		return nil
	}
	s.logger.Info("Batch is new, proceeding",
		zap.String("batch_ref", req.BatchRef),
	)

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
		s.logger.Error("Failed to create batch record",
			zap.String("batch_id", batch.BatchID.String()),
			zap.Error(err),
		)
		return err
	}
	s.logger.Info("Batch record created",
		zap.String("batch_id", batch.BatchID.String()),
		zap.Int("total_events", batch.TotalEvents),
	)

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
	for i, event := range req.Events {
		s.logger.Info("Processing event",
			zap.Int("event_index", i),
			zap.String("external_ref", event.ExternalRef),
			zap.String("event_type", event.EventType),
			zap.Time("event_time", event.EventTime),
		)

		// Resolve user
		userID, err := s.enrollmentService.ResolveUser(
			ctx,
			req.CompanyID,
			req.DeviceID,
			req.SourceType,
			event.ExternalRef,
		)
		if err != nil {
			s.logger.Error("User resolution failed",
				zap.String("external_ref", event.ExternalRef),
				zap.Error(err),
			)
			s.recordFailure(ctx, batch, event, "user_resolution_failed: "+err.Error())
			failureCount++
			continue
		}
		s.logger.Info("User resolved",
			zap.String("external_ref", event.ExternalRef),
			zap.String("user_id", userID.String()),
		)

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

		// 🔥 Log before calling IngestPunch
		s.logger.Info("Calling IngestPunch for event",
			zap.String("external_ref", event.ExternalRef),
			zap.String("user_id", userID.String()),
		)

		eventResult, err := s.ingestService.IngestPunch(ctx, punchReq)
		if err != nil {
			s.logger.Error("IngestPunch failed",
				zap.String("external_ref", event.ExternalRef),
				zap.Error(err),
			)
			s.recordFailure(ctx, batch, event, "punch_ingest_failed: "+err.Error())
			failureCount++
			continue
		}

		// 🔥 Log after successful ingest
		s.logger.Info("IngestPunch SUCCESS for event",
			zap.String("external_ref", event.ExternalRef),
			zap.String("event_id", eventResult.AttendanceEventID.String()),
		)

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

	// 6️⃣ Log summary after processing all events
	s.logger.Info("Batch processing completed",
		zap.String("batch_id", batch.BatchID.String()),
		zap.Int("success_count", successCount),
		zap.Int("failure_count", failureCount),
		zap.Int("total_events", len(req.Events)),
	)

	// 7️⃣ Final batch status
	var updateErr error
	if successCount == 0 && failureCount > 0 {
		updateErr = s.batchRepo.MarkFailed(ctx, batch.BatchID, "all_events_failed")
	} else {
		updateErr = s.batchRepo.MarkProcessed(ctx, batch.BatchID)
	}

	if updateErr != nil {
		s.logger.Error(
			"Failed to update batch status",
			zap.String("batch_id", batch.BatchID.String()),
			zap.Error(updateErr),
		)
	} else {
		s.logger.Info("Batch status updated successfully",
			zap.String("batch_id", batch.BatchID.String()),
			zap.String("status", func() string {
				if successCount == 0 && failureCount > 0 {
					return "failed"
				}
				return "processed"
			}()),
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
		RawEvent:       rawJSON,
		CreatedAt:      time.Now().UTC(),
	}

	if err := s.batchRepo.InsertFailure(ctx, failure); err != nil {
		s.logger.Error(
			"Failed to persist batch failure",
			zap.String("batch_id", batch.BatchID.String()),
			zap.Error(err),
		)
	} else {
		s.logger.Info("Batch failure recorded",
			zap.String("failure_id", failure.FailureID.String()),
			zap.String("external_ref", event.ExternalRef),
			zap.String("reason", reason),
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
