package batch

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/attendance/service/enrollment"
	"auth-service/internal/attendance/service/ingest"
	"auth-service/internal/attendance/service/resolver"
)

// OfflinePunchEvent represents a single punch from a device batch.
type OfflinePunchEvent struct {
	EventType   string    `json:"event_type"`
	EventTime   time.Time `json:"event_time"`
	ExternalRef string    `json:"external_ref"` // device_user_code
}

// BatchIngestRequest is the input for ingesting a batch.
type BatchIngestRequest struct {
	CompanyID  uuid.UUID
	DeviceID   string
	SourceType string
	BatchRef   string
	Events     []OfflinePunchEvent
}

// BatchIngestService defines the batch ingestion operations.
type BatchIngestService interface {
	IngestBatch(ctx context.Context, req *BatchIngestRequest) error
	GetFailures(ctx context.Context, companyID uuid.UUID, deviceID, batchRef string, limit, offset int) ([]repository.AttendancePunchFailureView, error)
	GetStatus(ctx context.Context, companyID uuid.UUID, deviceID, batchRef string) (*repository.AttendanceBatchStatus, error)
}

type batchIngestService struct {
	batchRepo  repository.AttendanceBatchRepository
	outboxRepo repository.OutboxRepository
	deviceRepo repository.DeviceRepository
	ingestSvc  ingest.IngestService
	enrollSvc  enrollment.EnrollmentService
	subjectRes resolver.SubjectResolver
	logger     *zap.Logger
}

// NewBatchIngestService creates a new batch ingest service.
func NewBatchIngestService(
	batchRepo repository.AttendanceBatchRepository,
	outboxRepo repository.OutboxRepository,
	deviceRepo repository.DeviceRepository,
	ingestSvc ingest.IngestService,
	enrollSvc enrollment.EnrollmentService,
	subjectRes resolver.SubjectResolver,
	logger *zap.Logger,
) BatchIngestService {
	return &batchIngestService{
		batchRepo:  batchRepo,
		outboxRepo: outboxRepo,
		deviceRepo: deviceRepo,
		ingestSvc:  ingestSvc,
		enrollSvc:  enrollSvc,
		subjectRes: subjectRes,
		logger:     logger,
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

	// 1. Validate device
	device, err := s.deviceRepo.GetActiveDevice(ctx, req.CompanyID, req.DeviceID)
	if err != nil || device == nil || !device.IsTrusted {
		s.logger.Error("Device validation failed", zap.String("device_id", req.DeviceID), zap.Error(err))
		return repository.ErrValidationFailed
	}

	// 2. Idempotency check
	exists, err := s.batchRepo.ExistsByRef(ctx, req.CompanyID, req.DeviceID, req.BatchRef)
	if err != nil {
		return fmt.Errorf("idempotency check: %w", err)
	}
	if exists {
		s.logger.Info("Batch already processed, skipping", zap.String("batch_ref", req.BatchRef))
		return nil
	}

	// 3. Create batch record
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

	// 4. Emit batch received outbox (once)
	payloadBytes, _ := json.Marshal(map[string]interface{}{
		"batch_id":     batch.BatchID,
		"batch_ref":    batch.BatchRef,
		"company_id":   batch.CompanyID,
		"device_id":    batch.DeviceID,
		"total_events": batch.TotalEvents,
		"received_at":  batch.ReceivedAt,
	})
	outboxEvent := &repository.OutboxEvent{
		EventID:     uuid.New(),
		EventType:   "attendance.batch.received",
		AggregateID: batch.BatchID,
		Payload:     payloadBytes,
		CreatedAt:   time.Now().UTC(),
	}
	// Store outbox event (no transaction for simplicity; can be wrapped if needed)
	if err := s.outboxRepo.Store(ctx, nil, outboxEvent); err != nil {
		s.logger.Error("Failed to store batch received outbox", zap.Error(err))
	}

	// 5. Process each event
	for i, event := range req.Events {
		s.logger.Info("Processing event", zap.Int("index", i), zap.String("external_ref", event.ExternalRef))

		// Resolve subject using enrollment
		enrollment, err := s.enrollSvc.ResolveEnrollment(ctx, req.CompanyID, req.DeviceID, req.SourceType, event.ExternalRef)
		if err != nil {
			s.recordFailure(ctx, batch, event, "enrollment_resolution_failed: "+err.Error())
			failureCount++
			continue
		}
		subjectType := enrollment.SubjectType
		subjectID := enrollment.SubjectID

		// Prepare punch request
		punchReq := &ingest.PunchRequest{
			CompanyID:      req.CompanyID,
			ActorID:        uuid.Nil, // device punch, no actor
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

		// Call ingest service
		_, err = s.ingestSvc.IngestPunch(ctx, punchReq)
		if err != nil {
			s.recordFailure(ctx, batch, event, "punch_ingest_failed: "+err.Error())
			failureCount++
			continue
		}

		successCount++

		// Emit raw event outbox per success
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
		rawOutbox := &repository.OutboxEvent{
			EventID:     uuid.New(),
			EventType:   "attendance.raw.events",
			AggregateID: batch.BatchID,
			Payload:     rawPayload,
			CreatedAt:   time.Now().UTC(),
		}
		_ = s.outboxRepo.Store(ctx, nil, rawOutbox)
	}

	// 6. Update batch status
	var updateErr error
	if successCount == 0 && failureCount > 0 {
		updateErr = s.batchRepo.MarkFailed(ctx, batch.BatchID, "all_events_failed")
	} else {
		updateErr = s.batchRepo.MarkProcessed(ctx, batch.BatchID)
	}
	if updateErr != nil {
		s.logger.Error("Failed to update batch status", zap.Error(updateErr))
	} else {
		s.logger.Info("Batch status updated", zap.String("batch_id", batch.BatchID.String()), zap.Int("success", successCount), zap.Int("failures", failureCount))
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
