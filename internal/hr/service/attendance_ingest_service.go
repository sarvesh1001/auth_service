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

// ===========================
// SERVICE-LEVEL DTOs (STRICT)
// ===========================
const (
	EventCheckIn      = "check_in"
	EventCheckOut     = "check_out"
	EventAutoCheckOut = "auto_check_out"
	EventCorrection   = "correction"
)

// PunchRequest is the service-level DTO for attendance ingestion
// This isolates service logic from HTTP/database concerns forever
type PunchRequest struct {
	CompanyID    uuid.UUID
	ActorID      uuid.UUID
	TargetUserID uuid.UUID
	EventType    string
	EventTime    time.Time
	Source       PunchSource
	Context      *attendance.EventContext
}

// PunchSource contains source information for the punch
type PunchSource struct {
	SourceType string
	SourceID   *uuid.UUID
	DeviceID   *string
	IPAddress  *string
}

// ===========================
// SERVICE INTERFACE
// ===========================

// AttendanceIngestService orchestrates attendance capture
// Single responsibility: Take a punch request → validate it → persist an immutable attendance event
// Does NOT apply OM mapping, calculate late/OT, or generate summaries
type AttendanceIngestService interface {
	IngestPunch(
		ctx context.Context,
		req *PunchRequest,
	) (*attendance.AttendanceEvent, error)
}

// ===========================
// SERVICE IMPLEMENTATION
// ===========================

type attendanceIngestService struct {
	attendanceRepo repository.AttendanceRepository
	deviceRepo     repository.AttendanceDeviceRepository
	identityRepo   repository.AttendanceIdentityRepository
	sourceResolver AttendanceSourceResolver
	logger         *zap.Logger
}

// NewAttendanceIngestService creates a new attendance ingest service
func NewAttendanceIngestService(
	attendanceRepo repository.AttendanceRepository,
	deviceRepo repository.AttendanceDeviceRepository,
	identityRepo repository.AttendanceIdentityRepository,
	sourceResolver AttendanceSourceResolver,
	logger *zap.Logger,
) AttendanceIngestService {
	return &attendanceIngestService{
		attendanceRepo: attendanceRepo,
		deviceRepo:     deviceRepo,
		identityRepo:   identityRepo,
		sourceResolver: sourceResolver,
		logger:         logger,
	}
}

// ===========================
// INGEST FLOW (NON-NEGOTIABLE ORDER)
// ===========================

// IngestPunch implements the TEVEN-layer attendance capture
// STEP 1-8 as specified in requirements
// func (s *attendanceIngestService) IngestPunch(
// 	ctx context.Context,
// 	req *PunchRequest,
// ) (*attendance.AttendanceEvent, error) {
// 	startTime := time.Now()

// 	// STEP 1: Basic validation (cheap checks)
// 	if err := s.validateBasicRequest(req); err != nil {
// 		s.logger.Error("Basic validation failed",
// 			util.String("company_id", req.CompanyID.String()),
// 			util.String("user_id", req.TargetUserID.String()),
// 			util.ErrorField(err))
// 		return nil, fmt.Errorf("basic validation failed: %w", err)
// 	}

// 	// STEP 2: Resolve source rules
// 	rules, err := s.sourceResolver.Resolve(ctx, req.Source.SourceType)
// 	if err != nil {
// 		s.logger.Error("Failed to resolve source rules",
// 			util.String("source_type", req.Source.SourceType),
// 			util.ErrorField(err))
// 		return nil, fmt.Errorf("failed to resolve source rules: %w", err)
// 	}

// 	// STEP 3: Time validation (SOURCE-DRIVEN)
// 	if err := s.validateEventTime(req, rules); err != nil {
// 		s.logger.Error("Time validation failed",
// 			util.String("source_type", req.Source.SourceType),
// 			util.Time("event_time", req.EventTime),
// 			util.ErrorField(err))
// 		return nil, fmt.Errorf("time validation failed: %w", err)
// 	}

// 	// STEP 4: Device validation (ONLY if required)
// 	if rules.RequiresDevice {
// 		if err := s.validateDevice(ctx, req); err != nil {
// 			s.logger.Error("Device validation failed",
// 				util.String("company_id", req.CompanyID.String()),
// 				util.String("device_id", *req.Source.DeviceID),
// 				util.ErrorField(err))
// 			return nil, fmt.Errorf("device validation failed: %w", err)
// 		}
// 	}

// 	// STEP 5: Identity resolution (hardware only)
// 	// This is where RFID/biometric mapping is used — nowhere else
// 	if rules.RequiresDevice && req.Source.SourceID != nil {
// 		userID, err := s.identityRepo.ResolveUserByDeviceCode(
// 			ctx,
// 			req.CompanyID,
// 			*req.Source.DeviceID,
// 			req.Source.SourceType,
// 			getExternalRef(req.Context),
// 		)
// 		if err != nil {
// 			s.logger.Error("Identity resolution failed",
// 				util.String("device_id", *req.Source.DeviceID),
// 				util.String("source_type", req.Source.SourceType),
// 				util.ErrorField(err))
// 			return nil, fmt.Errorf("identity resolution failed: %w", err)
// 		}
// 		// Update target user ID with resolved identity
// 		req.TargetUserID = userID
// 	}

// 	// STEP 6: Create immutable attendance event
// 	event := s.createAttendanceEvent(req)

// 	// STEP 7: Persist
// 	if err := s.attendanceRepo.CreateAttendanceEvent(ctx, event); err != nil {
// 		s.logger.Error("Failed to persist attendance event",
// 			util.String("event_id", event.AttendanceEventID.String()),
// 			util.String("user_id", event.UserID.String()),
// 			util.ErrorField(err))
// 		return nil, fmt.Errorf("failed to persist attendance event: %w", err)
// 	}

// 	// STEP 8: Return event (DO NOT mutate later)
// 	s.logger.Info("Attendance event ingested successfully",
// 		util.String("event_id", event.AttendanceEventID.String()),
// 		util.String("company_id", event.CompanyID.String()),
// 		util.String("user_id", event.UserID.String()),
// 		util.String("event_type", event.EventType),
// 		util.String("source_type", event.SourceType),
// 		util.Time("event_time", event.EventTime),
// 		util.Duration("duration", time.Since(startTime)))

// 	return event, nil
// }

func (s *attendanceIngestService) IngestPunch(
	ctx context.Context,
	req *PunchRequest,
) (*attendance.AttendanceEvent, error) {
	startTime := time.Now()

	// STEP 1: Basic validation (cheap checks)
	if err := s.validateBasicRequest(req); err != nil {
		s.logger.Error("Basic validation failed",
			util.String("company_id", req.CompanyID.String()),
			util.String("user_id", req.TargetUserID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("basic validation failed: %w", err)
	}

	// STEP 2: Resolve source rules
	rules, err := s.sourceResolver.Resolve(ctx, req.Source.SourceType)
	if err != nil {
		s.logger.Error("Failed to resolve source rules",
			util.String("source_type", req.Source.SourceType),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to resolve source rules: %w", err)
	}

	// STEP 3: Time validation (SOURCE-DRIVEN)
	if err := s.validateEventTime(req, rules); err != nil {
		s.logger.Error("Time validation failed",
			util.String("source_type", req.Source.SourceType),
			util.Time("event_time", req.EventTime),
			util.ErrorField(err))
		return nil, fmt.Errorf("time validation failed: %w", err)
	}

	// STEP 4: Device validation (ONLY if required)
	if rules.RequiresDevice {
		if err := s.validateDevice(ctx, req); err != nil {
			s.logger.Error("Device validation failed",
				util.String("company_id", req.CompanyID.String()),
				util.String("device_id", *req.Source.DeviceID),
				util.ErrorField(err))
			return nil, fmt.Errorf("device validation failed: %w", err)
		}
	}

	// STEP 5: Identity resolution (hardware only)
	if rules.RequiresDevice && req.Source.DeviceID != nil {
		userID, err := s.identityRepo.ResolveUserByDeviceCode(
			ctx,
			req.CompanyID,
			*req.Source.DeviceID,
			req.Source.SourceType,
			getExternalRef(req.Context),
		)
		if err != nil {
			s.logger.Error("Identity resolution failed",
				util.String("device_id", *req.Source.DeviceID),
				util.String("source_type", req.Source.SourceType),
				util.ErrorField(err))
			return nil, fmt.Errorf("identity resolution failed: %w", err)
		}
		req.TargetUserID = userID
	}

	// STEP 6: Create immutable attendance event
	event := s.createAttendanceEvent(req)

	// STEP 7: Persist attendance event (includes outbox insert)
	if err := s.attendanceRepo.CreateAttendanceEvent(ctx, event); err != nil {
		s.logger.Error("Failed to persist attendance event",
			util.String("event_id", event.AttendanceEventID.String()),
			util.String("user_id", event.UserID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to persist attendance event: %w", err)
	}

	// STEP 8: Final success log
	s.logger.Info("Attendance event ingested successfully",
		util.String("event_id", event.AttendanceEventID.String()),
		util.String("company_id", event.CompanyID.String()),
		util.String("user_id", event.UserID.String()),
		util.String("event_type", event.EventType),
		util.String("source_type", event.SourceType),
		util.Time("event_time", event.EventTime),
		util.Duration("duration", time.Since(startTime)),
	)

	return event, nil
}

// ===========================
// PRIVATE HELPER METHODS
// ===========================

// validateBasicRequest performs STEP 1: Basic validation
func (s *attendanceIngestService) validateBasicRequest(req *PunchRequest) error {
	if req.CompanyID == uuid.Nil {
		return errors.New("company ID is required")
	}
	if req.TargetUserID == uuid.Nil {
		return errors.New("target user ID is required")
	}
	if req.ActorID == uuid.Nil {
		return errors.New("actor ID is required")
	}
	if req.EventType == "" {
		return errors.New("event type is required")
	}
	if req.EventTime.IsZero() {
		return errors.New("event time is required")
	}
	if req.Source.SourceType == "" {
		return errors.New("source type is required")
	}
	// Allow manual source without device validation
	if req.Source.SourceType == "manual" {
		return nil
	}
	if req.Context == nil {
		return errors.New("context is required")
	}
	return nil
}

// validateEventTime performs STEP 3: Time validation (source-driven)
func (s *attendanceIngestService) validateEventTime(req *PunchRequest, rules *ResolvedSourceRules) error {
	now := time.Now().UTC()

	// Check backdated punches
	grace := 2 * time.Minute

	if !rules.AllowBackdated && req.EventTime.Before(now.Add(-grace)) {
		return errors.New("backdated punch not allowed for this source type")
	}

	// Check future punches with 2-minute tolerance for clock drift
	if !rules.AllowFuture && req.EventTime.After(now.Add(2*time.Minute)) {
		return errors.New("future punch not allowed for this source type")
	}

	return nil
}

// validateDevice performs STEP 4: Device validation
func (s *attendanceIngestService) validateDevice(
	ctx context.Context,
	req *PunchRequest,
) error {
	// Skip device validation for manual source
	if req.Source.SourceType == "manual" {
		return nil
	}

	// For all non-manual sources, device ID is mandatory
	if req.Source.DeviceID == nil {
		return errors.New("device ID required for this source type")
	}

	device, err := s.deviceRepo.GetActiveDevice(
		ctx,
		req.CompanyID,
		*req.Source.DeviceID,
	)
	if err != nil {
		return fmt.Errorf("failed to fetch device: %w", err)
	}

	if device == nil {
		return errors.New("invalid or inactive device")
	}

	if !device.IsTrusted {
		return errors.New("untrusted device")
	}

	return nil
}

// getExternalRef extracts external reference from context
func getExternalRef(context *attendance.EventContext) string {
	if context != nil && context.ExternalRef != nil {
		return *context.ExternalRef
	}
	return ""
}

// createAttendanceEvent performs STEP 6: Create immutable attendance event
func (s *attendanceIngestService) createAttendanceEvent(req *PunchRequest) *attendance.AttendanceEvent {
	now := time.Now().UTC()

	return &attendance.AttendanceEvent{
		AttendanceEventID: uuid.New(),
		CompanyID:         req.CompanyID,
		UserID:            req.TargetUserID,
		EventType:         req.EventType,
		EventTime:         req.EventTime,
		SourceType:        req.Source.SourceType,
		SourceID:          req.Source.SourceID,
		DeviceID:          req.Source.DeviceID,
		IPAddress:         req.Source.IPAddress,
		Context:           *req.Context,
		Metadata: attendance.EventMetadata{
			// Metadata can be extended later by other services
			IsAutoGenerated: boolPtr(false),
			IsCorrection:    boolPtr(false),
		},
		CreatedAt: now,
		CreatedBy: &req.ActorID,
	}
}

// boolPtr is a helper to create boolean pointers
