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

//
// ===========================
// SERVICE-LEVEL DTOs
// ===========================
//

type PunchRequest struct {
	CompanyID         uuid.UUID
	ActorID           uuid.UUID // uuid.Nil for device/system punches
	TargetUserID      uuid.UUID
	EventType         string
	EventTime         *time.Time // RAW input (optional)
	ResolvedEventTime time.Time  // FINAL authoritative time
	Source            PunchSource
	Context           *attendance.EventContext
}

type PunchSource struct {
	SourceType string
	SourceID   *uuid.UUID
	DeviceID   *string
	IPAddress  *string
}

//
// ===========================
// SERVICE INTERFACE
// ===========================
//

type AttendanceIngestService interface {
	IngestPunch(
		ctx context.Context,
		req *PunchRequest,
	) (*attendance.AttendanceEvent, error)
}

//
// ===========================
// SERVICE IMPLEMENTATION
// ===========================
//

type attendanceIngestService struct {
	attendanceRepo repository.AttendanceRepository
	deviceRepo     repository.AttendanceDeviceRepository
	identityRepo   repository.AttendanceIdentityRepository
	sourceResolver AttendanceSourceResolver
	omService      AttendanceOMService
	auditService   *AuditService
	logger         *zap.Logger
}

func NewAttendanceIngestService(
	attendanceRepo repository.AttendanceRepository,
	deviceRepo repository.AttendanceDeviceRepository,
	identityRepo repository.AttendanceIdentityRepository,
	sourceResolver AttendanceSourceResolver,
	omService AttendanceOMService,
	auditService *AuditService,
	logger *zap.Logger,
) AttendanceIngestService {
	return &attendanceIngestService{
		attendanceRepo: attendanceRepo,
		deviceRepo:     deviceRepo,
		identityRepo:   identityRepo,
		sourceResolver: sourceResolver,
		omService:      omService,
		auditService:   auditService,
		logger:         logger,
	}
}

//
// ===========================
// INGEST FLOW
// ===========================
//

func (s *attendanceIngestService) IngestPunch(
	ctx context.Context,
	req *PunchRequest,
) (*attendance.AttendanceEvent, error) {

	startTime := time.Now().UTC()

	// --------------------------------------------------
	// AUDIT METADATA
	// --------------------------------------------------
	auditMetadata := map[string]interface{}{
		"event_type":     req.EventType,
		"source_type":    req.Source.SourceType,
		"target_user_id": req.TargetUserID.String(),
	}
	if req.EventTime != nil {
		auditMetadata["input_event_time"] = req.EventTime.UTC()
	}
	if req.Source.DeviceID != nil {
		auditMetadata["device_id"] = *req.Source.DeviceID
	}
	if req.Source.IPAddress != nil {
		auditMetadata["ip_address"] = *req.Source.IPAddress
	}

	// --------------------------------------------------
	// STEP 1: BASIC VALIDATION
	// --------------------------------------------------
	if err := s.validateBasicRequest(req); err != nil {
		return nil, err
	}

	if req.Context == nil {
		req.Context = &attendance.EventContext{}
	}

	// --------------------------------------------------
	// STEP 2: SOURCE RULES
	// --------------------------------------------------
	rules, err := s.sourceResolver.Resolve(ctx, req.Source.SourceType)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve source rules: %w", err)
	}

	// --------------------------------------------------
	// STEP 3: RESOLVE + VALIDATE EVENT TIME (CORE CHANGE)
	// --------------------------------------------------
	resolvedTime, err := s.resolveAndValidateEventTime(req, rules)
	if err != nil {
		return nil, err
	}
	req.ResolvedEventTime = resolvedTime
	auditMetadata["resolved_event_time"] = resolvedTime

	// --------------------------------------------------
	// STEP 4: DEVICE VALIDATION
	// --------------------------------------------------
	var device *attendance.AttendanceDevice

	if rules.RequiresDevice {
		if req.Source.DeviceID == nil {
			return nil, errors.New("device_id required for this source")
		}

		device, err = s.deviceRepo.GetActiveDevice(
			ctx,
			req.CompanyID,
			*req.Source.DeviceID,
		)
		if err != nil || device == nil {
			return nil, errors.New("invalid or inactive device")
		}

		if !device.IsTrusted {
			return nil, errors.New("untrusted device")
		}

		req.Context.WorkCenterCode = device.WorkCenterCode
	}

	// --------------------------------------------------
	// STEP 5: IDENTITY RESOLUTION (DEVICE SOURCES)
	// --------------------------------------------------
	if rules.RequiresDevice {
		externalRef := getExternalRef(req.Context)
		if externalRef == "" {
			return nil, errors.New("external_ref required for device punch")
		}

		userID, err := s.identityRepo.ResolveUserByDeviceCode(
			ctx,
			req.CompanyID,
			externalRef,
			req.Source.SourceType,
			externalRef,
		)
		if err != nil {
			return nil, fmt.Errorf("identity resolution failed: %w", err)
		}
		req.TargetUserID = userID
	}

	// --------------------------------------------------
	// STEP 6: OM AUTHORIZATION
	// --------------------------------------------------
	if !rules.IsSystem {
		var actorID *uuid.UUID
		if req.ActorID != uuid.Nil {
			actorID = &req.ActorID
		}

		allowed, reason := s.omService.CanPunchAttendance(
			ctx,
			req.CompanyID,
			actorID,
			req.TargetUserID,
			req.Source.SourceType,
			req.Context.WorkCenterCode,
		)
		if !allowed {
			return nil, fmt.Errorf("attendance punch not allowed: %s", reason)
		}
	}

	// --------------------------------------------------
	// STEP 7: CREATE EVENT
	// --------------------------------------------------
	event := s.createAttendanceEvent(req, rules)

	// --------------------------------------------------
	// STEP 8: PERSIST
	// --------------------------------------------------
	if err := s.attendanceRepo.CreateAttendanceEvent(ctx, event); err != nil {
		return nil, fmt.Errorf("failed to persist attendance event: %w", err)
	}

	// --------------------------------------------------
	// STEP 9: DEVICE HEARTBEAT
	// --------------------------------------------------
	if device != nil {
		_ = s.deviceRepo.UpdateLastSeen(ctx, device.DeviceID)
	}

	// --------------------------------------------------
	// FINAL LOG
	// --------------------------------------------------
	s.logger.Info("Attendance event ingested",
		util.String("event_id", event.AttendanceEventID.String()),
		util.String("user_id", event.UserID.String()),
		util.String("source", event.SourceType),
		util.Duration("duration", time.Since(startTime)),
	)

	return event, nil
}

//
// ===========================
// TIME RESOLUTION (CORE SAP LOGIC)
// ===========================
//

func (s *attendanceIngestService) resolveAndValidateEventTime(
	req *PunchRequest,
	rules *ResolvedSourceRules,
) (time.Time, error) {

	now := time.Now().UTC()

	// SERVER-AUTHORITATIVE SOURCES
	if rules.IsSystem || !rules.RequiresDevice {
		return now, nil
	}

	// DEVICE / MANUAL / IMPORT MUST PROVIDE TIME
	if req.EventTime == nil || req.EventTime.IsZero() {
		return time.Time{}, errors.New("event_time required for this source")
	}

	eventTime := req.EventTime.UTC()

	// BACKDATED CHECK
	if !rules.AllowBackdated && eventTime.Before(now.Add(-2*time.Minute)) {
		return time.Time{}, errors.New("backdated punch not allowed")
	}

	// FUTURE CHECK
	if !rules.AllowFuture && eventTime.After(now.Add(2*time.Minute)) {
		return time.Time{}, errors.New("future punch not allowed")
	}

	return eventTime, nil
}

//
// ===========================
// HELPERS
// ===========================
//

func (s *attendanceIngestService) validateBasicRequest(req *PunchRequest) error {
	if req.CompanyID == uuid.Nil {
		return errors.New("company_id required")
	}
	if req.EventType == "" {
		return errors.New("event_type required")
	}
	if req.Source.SourceType == "" {
		return errors.New("source_type required")
	}
	return nil
}

func getExternalRef(ctx *attendance.EventContext) string {
	if ctx != nil && ctx.ExternalRef != nil {
		return *ctx.ExternalRef
	}
	return ""
}

func (s *attendanceIngestService) createAttendanceEvent(
	req *PunchRequest,
	rules *ResolvedSourceRules,
) *attendance.AttendanceEvent {

	now := time.Now().UTC()

	return &attendance.AttendanceEvent{
		AttendanceEventID: uuid.New(),
		CompanyID:         req.CompanyID,
		UserID:            req.TargetUserID,
		EventType:         req.EventType,
		EventTime:         req.ResolvedEventTime,
		SourceType:        req.Source.SourceType,
		SourceID:          req.Source.SourceID,
		DeviceID:          req.Source.DeviceID,
		IPAddress:         req.Source.IPAddress,
		Context:           *req.Context,
		Metadata: attendance.EventMetadata{
			IsAutoGenerated: boolPtr(rules.IsSystem),
			IsCorrection:    boolPtr(req.Source.SourceType == "correction"),
		},
		CreatedAt: now,
		CreatedBy: func() *uuid.UUID {
			if req.ActorID != uuid.Nil {
				return &req.ActorID
			}
			return nil
		}(),
	}
}
