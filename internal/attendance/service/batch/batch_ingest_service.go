package batch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/attendance/service/enrollment"
	"auth-service/internal/attendance/service/ingest"
	"auth-service/internal/attendance/service/resolver"
	"auth-service/internal/infrastructure/outbox"
)

type OfflinePunchEvent struct {
	EventType   string    `json:"event_type"`
	EventTime   time.Time `json:"event_time"`
	ExternalRef string    `json:"external_ref"`
}

type BatchIngestRequest struct {
	CompanyID  uuid.UUID
	DeviceID   string
	SourceType string
	BatchRef   string
	Events     []OfflinePunchEvent
}

var ErrAllEventsFailed = errors.New("all events in batch failed")

type BatchIngestService interface {
	IngestBatch(ctx context.Context, req *BatchIngestRequest) error
	GetFailures(ctx context.Context, companyID uuid.UUID, deviceID, batchRef string, limit, offset int) ([]repository.AttendancePunchFailureView, error)
	GetStatus(ctx context.Context, companyID uuid.UUID, deviceID, batchRef string) (*repository.AttendanceBatchStatus, error)
}

type batchIngestService struct {
	batchRepo     repository.AttendanceBatchRepository
	centralOutbox outbox.Repository
	deviceRepo    repository.DeviceRepository
	ingestSvc     ingest.IngestService
	enrollSvc     enrollment.EnrollmentService
	subjectRes    resolver.SubjectResolver
	logger        *zap.Logger
}

func NewBatchIngestService(
	batchRepo repository.AttendanceBatchRepository,
	centralOutbox outbox.Repository,
	deviceRepo repository.DeviceRepository,
	ingestSvc ingest.IngestService,
	enrollSvc enrollment.EnrollmentService,
	subjectRes resolver.SubjectResolver,
	logger *zap.Logger,
) BatchIngestService {
	return &batchIngestService{
		batchRepo:     batchRepo,
		centralOutbox: centralOutbox,
		deviceRepo:    deviceRepo,
		ingestSvc:     ingestSvc,
		enrollSvc:     enrollSvc,
		subjectRes:    subjectRes,
		logger:        logger,
	}
}

func (s *batchIngestService) GetStatus(ctx context.Context, companyID uuid.UUID, deviceID, batchRef string) (*repository.AttendanceBatchStatus, error) {
	return s.batchRepo.GetByRef(ctx, companyID, deviceID, batchRef)
}

func (s *batchIngestService) IngestBatch(ctx context.Context, req *BatchIngestRequest) error {
	s.logger.Info("IngestBatch START",
		zap.String("company_id", req.CompanyID.String()),
		zap.String("device_id", req.DeviceID),
		zap.String("source_type", req.SourceType),
		zap.String("batch_ref", req.BatchRef),
		zap.Int("event_count", len(req.Events)),
	)

	device, err := s.deviceRepo.GetActiveDevice(ctx, req.CompanyID, req.DeviceID)
	if err != nil || device == nil || !device.IsTrusted {
		s.logger.Error("Device validation failed", zap.String("device_id", req.DeviceID), zap.Error(err))
		return repository.ErrValidationFailed
	}

	exists, err := s.batchRepo.ExistsByRef(ctx, req.CompanyID, req.DeviceID, req.BatchRef)
	if err != nil {
		return fmt.Errorf("idempotency check: %w", err)
	}
	if exists {
		s.logger.Info("Batch already processed, skipping", zap.String("batch_ref", req.BatchRef))
		return nil
	}

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
		return fmt.Errorf("create batch: %w", err)
	}

	s.logger.Info("Batch record created", zap.String("batch_id", batch.BatchID.String()))

	successCount, failureCount := 0, 0

	// Emit batch.received outbox event.
	payloadBytes, _ := json.Marshal(map[string]interface{}{
		"batch_id":     batch.BatchID,
		"batch_ref":    batch.BatchRef,
		"company_id":   batch.CompanyID,
		"device_id":    batch.DeviceID,
		"total_events": batch.TotalEvents,
		"received_at":  batch.ReceivedAt,
	})
	centralEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "attendance_batch",
		AggregateID:   batch.BatchID.String(),
		EventType:     "attendance.batch.received",
		Topic:         "attendance.events",
		Payload:       payloadBytes,
		Headers: map[string]string{
			"source": "attendance-batch",
		},
	}
	if err := s.centralOutbox.Store(ctx, nil, centralEvent); err != nil {
		s.logger.Error("Failed to store batch received outbox", zap.Error(err))
	}

	for i, event := range req.Events {
		s.logger.Info("Processing event",
			zap.Int("index", i),
			zap.String("external_ref", event.ExternalRef),
			zap.Time("event_time", event.EventTime),
		)

		enrollment, err := s.enrollSvc.ResolveEnrollment(ctx, req.CompanyID, req.DeviceID, req.SourceType, event.ExternalRef)
		if err != nil {
			s.recordFailure(ctx, batch, event, "enrollment_resolution_failed: "+err.Error())
			failureCount++
			continue
		}

		subjectType := enrollment.SubjectType
		subjectID := enrollment.SubjectID

		// ── CHANGED: pass EventTime as UTC. The IngestService resolves
		//    the tz via the canonical chain and computes EventTZ,
		//    EventOffsetMinutes, EventDateLocal.
		punchReq := &ingest.PunchRequest{
			CompanyID:      req.CompanyID,
			ActorID:        uuid.Nil,
			SubjectType:    subjectType,
			SubjectID:      subjectID,
			EventType:      event.EventType,
			EventTime:      &event.EventTime,
			DeviceUserCode: &event.ExternalRef,
			Source: ingest.PunchSource{
				SourceType: req.SourceType,
				DeviceID:   &req.DeviceID,
			},
			Context: &models.EventContext{
				ExternalRef: &event.ExternalRef,
			},
		}

		_, err = s.ingestSvc.IngestPunch(ctx, punchReq)
		if err != nil {
			s.recordFailure(ctx, batch, event, "punch_ingest_failed: "+err.Error())
			failureCount++
			continue
		}

		successCount++

		rawPayload, _ := json.Marshal(map[string]interface{}{
			"company_id":   req.CompanyID,
			"device_id":    req.DeviceID,
			"batch_ref":    req.BatchRef,
			"subject_type": subjectType,
			"subject_id":   subjectID,
			"event_type":   event.EventType,
			"event_time":   event.EventTime,
			"external_ref": event.ExternalRef,
			"source_type":  req.SourceType,
		})
		rawCentralEvent := &outbox.Event{
			EventID:       uuid.New().String(),
			AggregateType: "attendance_punch",
			AggregateID:   batch.BatchID.String(),
			EventType:     "attendance.raw.events",
			Topic:         "attendance.events",
			Payload:       rawPayload,
			Headers: map[string]string{
				"source": "attendance-batch",
			},
		}
		_ = s.centralOutbox.Store(ctx, nil, rawCentralEvent)
	}

	allFailed := successCount == 0 && failureCount > 0

	var updateErr error
	if allFailed {
		updateErr = s.batchRepo.MarkFailed(ctx, batch.BatchID, "all_events_failed")
	} else {
		updateErr = s.batchRepo.MarkProcessed(ctx, batch.BatchID)
	}
	if updateErr != nil {
		s.logger.Error("Failed to update batch status", zap.Error(updateErr))
	} else {
		s.logger.Info("Batch status updated",
			zap.String("batch_id", batch.BatchID.String()),
			zap.Int("success", successCount),
			zap.Int("failures", failureCount))
	}

	if allFailed {
		return fmt.Errorf("%w: %d events rejected; see GET .../failures", ErrAllEventsFailed, failureCount)
	}
	return nil
}

func (s *batchIngestService) recordFailure(ctx context.Context, batch *repository.AttendancePunchBatch, event OfflinePunchEvent, reason string) {
	rawEvent := map[string]interface{}{
		"event_type":   event.EventType,
		"event_time":   event.EventTime,
		"external_ref": event.ExternalRef,
	}
	rawJSON, _ := json.Marshal(rawEvent)
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
		s.logger.Error("Failed to persist batch failure", zap.Error(err))
	} else {
		s.logger.Info("Batch failure recorded", zap.String("failure_id", failure.FailureID.String()))
	}
}

func (s *batchIngestService) GetFailures(ctx context.Context, companyID uuid.UUID, deviceID, batchRef string, limit, offset int) ([]repository.AttendancePunchFailureView, error) {
	return s.batchRepo.ListFailuresByBatch(ctx, companyID, deviceID, batchRef, limit, offset)
}
