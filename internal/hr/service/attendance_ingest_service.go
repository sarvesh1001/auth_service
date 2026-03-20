package service

import (
	"auth-service/internal/hr/models/attendance"
	"auth-service/internal/hr/repository"
	a "auth-service/internal/infrastructure/audit"
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
// DTOs
// ===========================
//

type PunchRequest struct {
	CompanyID         uuid.UUID
	ActorID           uuid.UUID // uuid.Nil for device/system
	TargetUserID      uuid.UUID
	EventType         string
	EventTime         *time.Time
	ResolvedEventTime time.Time

	// 🔥 REQUIRED FOR DEVICE SOURCES
	DeviceUserCode *string

	// 🔥 NEW (POPULATED INTERNALLY)
	DeviceEnrollmentID *uuid.UUID

	Source  PunchSource
	Context *attendance.EventContext
}

type PunchSource struct {
	SourceType string
	SourceID   *uuid.UUID
	DeviceID   *string
	IPAddress  *string
}

//
// ===========================
// INTERFACE
// ===========================
//

type AttendanceIngestService interface {
	IngestPunch(ctx context.Context, req *PunchRequest) (*attendance.AttendanceEvent, error)
}

//
// ===========================
// IMPLEMENTATION
// ===========================
//

type attendanceIngestService struct {
	attendanceRepo    repository.AttendanceRepository
	deviceRepo        repository.AttendanceDeviceRepository
	identityRepo      repository.AttendanceIdentityRepository
	enrollmentService AttendanceDeviceEnrollmentService
	sourceResolver    AttendanceSourceResolver
	adminService      AttendanceAdminService
	omService         AttendanceOMService
	auditService      *a.AuditService
	logger            *zap.Logger
}

func NewAttendanceIngestService(
	attendanceRepo repository.AttendanceRepository,
	deviceRepo repository.AttendanceDeviceRepository,
	identityRepo repository.AttendanceIdentityRepository,
	enrollmentService AttendanceDeviceEnrollmentService,
	sourceResolver AttendanceSourceResolver,
	adminService AttendanceAdminService,
	omService AttendanceOMService,
	auditService *a.AuditService,
	logger *zap.Logger,
) AttendanceIngestService {
	return &attendanceIngestService{
		attendanceRepo:    attendanceRepo,
		deviceRepo:        deviceRepo,
		identityRepo:      identityRepo,
		enrollmentService: enrollmentService,
		sourceResolver:    sourceResolver,
		adminService:      adminService,
		omService:         omService,
		auditService:      auditService,
		logger:            logger,
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

	start := time.Now().UTC()

	s.logger.Info("IngestPunch START",
		zap.String("company_id", req.CompanyID.String()),
		zap.String("event_type", req.EventType),
		zap.String("source_type", req.Source.SourceType),
		zap.Any("event_time_input", req.EventTime),
	)

	// --------------------------------------------------
	// BASIC VALIDATION
	// --------------------------------------------------
	if req.CompanyID == uuid.Nil {
		return nil, errors.New("company_id required")
	}
	if req.EventType == "" {
		return nil, errors.New("event_type required")
	}
	if req.Source.SourceType == "" {
		return nil, errors.New("source_type required")
	}
	if req.Context == nil {
		req.Context = &attendance.EventContext{}
	}

	// --------------------------------------------------
	// SOURCE RULES
	// --------------------------------------------------
	sourceRules, err := s.sourceResolver.Resolve(ctx, req.Source.SourceType)
	if err != nil {
		return nil, fmt.Errorf("invalid source type: %w", err)
	}

	// --------------------------------------------------
	// EVENT TIME RESOLUTION
	// --------------------------------------------------
	eventTime, err := s.resolveEventTime(ctx, req, sourceRules)
	if err != nil {
		return nil, err
	}
	req.ResolvedEventTime = eventTime

	s.logger.Info("EventTime resolved",
		zap.Time("resolved_event_time", eventTime),
	)

	// --------------------------------------------------
	// ATTENDANCE RULE RESOLUTION
	// --------------------------------------------------
	resolvedRules, err := s.adminService.ResolveAttendanceRules(
		ctx,
		req.TargetUserID,
		req.CompanyID,
		derefString(req.Context.WorkCenterCode),
		nil,
		eventTime,
	)
	if err != nil {
		return nil, err
	}

	if !resolvedRules.AllowedSourceTypesMap[req.Source.SourceType] {
		return nil, fmt.Errorf("source '%s' not allowed", req.Source.SourceType)
	}

	// --------------------------------------------------
	// RESOLVE SOURCE ID
	// --------------------------------------------------
	if req.Source.SourceID == nil {
		source, err := s.attendanceRepo.GetAttendanceSourceByType(
			ctx,
			req.CompanyID,
			req.Source.SourceType,
		)
		if err != nil {
			return nil, err
		}
		if source == nil {
			return nil, errors.New("attendance source not configured")
		}
		req.Source.SourceID = &source.SourceID
	}

	// --------------------------------------------------
	// DEVICE VALIDATION
	// --------------------------------------------------
	var device *attendance.AttendanceDevice

	if sourceRules.RequiresDevice {
		if req.Source.DeviceID == nil {
			return nil, errors.New("device_id required")
		}

		device, err = s.deviceRepo.GetActiveDevice(
			ctx,
			req.CompanyID,
			*req.Source.DeviceID,
		)
		if err != nil || device == nil || !device.IsTrusted {
			return nil, errors.New("invalid or untrusted device")
		}

		req.Context.WorkCenterCode = device.WorkCenterCode
	}

	// --------------------------------------------------
	// DEVICE USER RESOLUTION
	// --------------------------------------------------
	if sourceRules.RequiresDevice {
		if req.DeviceUserCode == nil || *req.DeviceUserCode == "" {
			return nil, errors.New("device_user_code required")
		}

		enrollment, err := s.enrollmentService.ResolveEnrollment(
			ctx,
			req.CompanyID,
			*req.Source.DeviceID,
			req.Source.SourceType,
			*req.DeviceUserCode,
		)
		if err != nil {
			return nil, err
		}

		req.TargetUserID = enrollment.UserID
		req.DeviceEnrollmentID = &enrollment.MappingID
	}

	// --------------------------------------------------
	// 🔥🔥🔥 OM AUTHORIZATION CHECK (NEW)
	// --------------------------------------------------
	var actorPtr *uuid.UUID
	if req.ActorID != uuid.Nil {
		actorPtr = &req.ActorID
	}

	allowed, reason := s.omService.CanPunchAttendance(
		ctx,
		req.CompanyID,
		actorPtr,
		req.TargetUserID,
		req.Source.SourceType,
		req.Context.WorkCenterCode,
	)

	if !allowed {
		s.logger.Warn("OM authorization denied",
			zap.String("actor_id", req.ActorID.String()),
			zap.String("target_user_id", req.TargetUserID.String()),
			zap.String("reason", reason),
		)
		return nil, fmt.Errorf("not authorized: %s", reason)
	}

	// --------------------------------------------------
	// CREATE EVENT
	// --------------------------------------------------
	event := s.createAttendanceEvent(req, sourceRules)

	if err := s.attendanceRepo.CreateAttendanceEvent(ctx, event); err != nil {
		return nil, err
	}

	if device != nil {
		_ = s.deviceRepo.UpdateLastSeen(ctx, device.DeviceID)
	}

	s.logger.Info(
		"Attendance punch ingested",
		util.String("event_id", event.AttendanceEventID.String()),
		util.String("user_id", event.UserID.String()),
		util.Duration("duration", time.Since(start)),
	)

	return event, nil
}

//
// ===========================
// HELPERS
// ===========================
//

func derefString(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}

func (s *attendanceIngestService) resolveEventTime(
	ctx context.Context,
	req *PunchRequest,
	rules *ResolvedSourceRules,
) (time.Time, error) {

	// 🔥 Load company attendance rules (for timezone)
	companyRules, err := s.attendanceRepo.GetCompanyAttendanceRules(
		ctx,
		req.CompanyID,
	)
	if err != nil {
		return time.Time{}, err
	}

	loc, err := time.LoadLocation(companyRules.Timezone)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid company timezone: %w", err)
	}

	// --------------------------------------------------
	// DEVICE EVENT
	// --------------------------------------------------
	if rules.RequiresDevice {

		if req.EventTime == nil {
			return time.Time{}, errors.New("event_time required for device events")
		}

		// Device time interpreted in company timezone
		deviceLocalTime := req.EventTime.In(loc)

		// Store in UTC
		return deviceLocalTime.UTC(), nil
	}

	// --------------------------------------------------
	// SYSTEM EVENT
	// --------------------------------------------------
	if rules.IsSystem {
		return time.Now().UTC(), nil
	}

	// --------------------------------------------------
	// SELF PUNCH (🔥 YOUR CASE)
	// --------------------------------------------------

	// Ignore client time completely
	nowUTC := time.Now().UTC()

	// Convert to company timezone
	nowInPolicyZone := nowUTC.In(loc)

	// Store back in UTC (Postgres will handle internally)
	return nowInPolicyZone.UTC(), nil
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

		// 🔥 DB CONSTRAINT FIX
		DeviceUserCode:     req.DeviceUserCode,
		DeviceEnrollmentID: req.DeviceEnrollmentID,

		IPAddress: req.Source.IPAddress,
		Context:   *req.Context,
		Metadata: attendance.EventMetadata{
			IsAutoGenerated: boolPtr(rules.IsSystem),
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
