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
	attendanceRepo repository.AttendanceRepository
	deviceRepo     repository.AttendanceDeviceRepository
	identityRepo   repository.AttendanceIdentityRepository
	sourceResolver AttendanceSourceResolver
	adminService   AttendanceAdminService // 🔥 NEW
	omService      AttendanceOMService
	auditService   *AuditService
	logger         *zap.Logger
}

func NewAttendanceIngestService(
	attendanceRepo repository.AttendanceRepository,
	deviceRepo repository.AttendanceDeviceRepository,
	identityRepo repository.AttendanceIdentityRepository,
	sourceResolver AttendanceSourceResolver,
	adminService AttendanceAdminService,
	omService AttendanceOMService,
	auditService *AuditService,
	logger *zap.Logger,
) AttendanceIngestService {
	return &attendanceIngestService{
		attendanceRepo: attendanceRepo,
		deviceRepo:     deviceRepo,
		identityRepo:   identityRepo,
		sourceResolver: sourceResolver,
		adminService:   adminService,
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

	start := time.Now().UTC()

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
	// RESOLVE ATTENDANCE RULES (🔥 CORE FIX)
	// --------------------------------------------------
	resolvedRules, err := s.adminService.ResolveAttendanceRules(
		ctx,
		req.TargetUserID,
		req.CompanyID,
		derefString(req.Context.WorkCenterCode),
		nil,
		time.Now().UTC(),
	)
	if err != nil {
		return nil, err
	}

	// --------------------------------------------------
	// ENFORCE SOURCE PER POLICY
	// --------------------------------------------------
	if !resolvedRules.AllowedSourceTypesMap[req.Source.SourceType] {
		return nil, fmt.Errorf(
			"source '%s' not allowed for this user",
			req.Source.SourceType,
		)
	}

	// --------------------------------------------------
	// ENFORCE CAPABILITIES
	// --------------------------------------------------
	if resolvedRules.PolicyRules != nil {

		// Self-service (mobile / web)
		if sourceRules.IsSelfService {
			if resolvedRules.PolicyRules.AllowSelfService != nil &&
				!*resolvedRules.PolicyRules.AllowSelfService {
				return nil, errors.New("self-service attendance not allowed")
			}
		}

		// Admin marking
		if req.ActorID != uuid.Nil && !sourceRules.IsSelfService {
			if resolvedRules.PolicyRules.AllowAdminMarking != nil &&
				!*resolvedRules.PolicyRules.AllowAdminMarking {
				return nil, errors.New("admin marking not allowed")
			}
		}

		// Device marking
		if sourceRules.RequiresDevice {
			if resolvedRules.PolicyRules.AllowDeviceMarking != nil &&
				!*resolvedRules.PolicyRules.AllowDeviceMarking {
				return nil, errors.New("device attendance not allowed")
			}
		}
	}

	// --------------------------------------------------
	// RESOLVE + VALIDATE EVENT TIME (🔥 FIXED)
	// --------------------------------------------------
	eventTime, err := s.resolveEventTime(req, sourceRules)
	if err != nil {
		return nil, err
	}
	req.ResolvedEventTime = eventTime

	// --------------------------------------------------
	// DEVICE VALIDATION
	// --------------------------------------------------
	var device *attendance.AttendanceDevice

	if sourceRules.RequiresDevice {
		if req.Source.DeviceID == nil {
			return nil, errors.New("device_id required")
		}

		device, err = s.deviceRepo.GetActiveDevice(ctx, req.CompanyID, *req.Source.DeviceID)
		if err != nil || device == nil || !device.IsTrusted {
			return nil, errors.New("invalid or untrusted device")
		}

		req.Context.WorkCenterCode = device.WorkCenterCode
	}

	// --------------------------------------------------
	// IDENTITY RESOLUTION
	// --------------------------------------------------
	if sourceRules.RequiresDevice {
		ref := getExternalRef(req.Context)
		if ref == "" {
			return nil, errors.New("external_ref required")
		}

		userID, err := s.identityRepo.ResolveUserByDeviceCode(
			ctx, req.CompanyID, ref, req.Source.SourceType, ref,
		)
		if err != nil {
			return nil, err
		}
		req.TargetUserID = userID
	}

	// --------------------------------------------------
	// OM AUTHORIZATION (LAST GATE)
	// --------------------------------------------------
	if !sourceRules.IsSystem {
		var actor *uuid.UUID
		if req.ActorID != uuid.Nil {
			actor = &req.ActorID
		}

		ok, reason := s.omService.CanPunchAttendance(
			ctx,
			req.CompanyID,
			actor,
			req.TargetUserID,
			req.Source.SourceType,
			req.Context.WorkCenterCode,
		)
		if !ok {
			return nil, fmt.Errorf("attendance punch not allowed: %s", reason)
		}
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

	s.logger.Info("Attendance punch ingested",
		util.String("event_id", event.AttendanceEventID.String()),
		util.String("user_id", event.UserID.String()),
		util.Duration("duration", time.Since(start)),
	)

	return event, nil
}

//
// ===========================
// EVENT TIME LOGIC (FIXED)
// ===========================
//

func (s *attendanceIngestService) resolveEventTime(
	req *PunchRequest,
	sourceRules *ResolvedSourceRules,
) (time.Time, error) {

	now := time.Now().UTC()

	// --------------------------------------------------
	// SERVER-AUTHORITATIVE SOURCES
	// --------------------------------------------------
	// system-generated OR self-service (mobile / web)
	// → server time is ALWAYS used
	if sourceRules.IsSystem || sourceRules.IsSelfService {
		return now, nil
	}

	// --------------------------------------------------
	// DEVICE / IMPORT / MANUAL SOURCES
	// --------------------------------------------------
	// These sources MUST provide event_time
	if req.EventTime == nil || req.EventTime.IsZero() {
		return time.Time{}, errors.New("event_time required")
	}

	eventTime := req.EventTime.UTC()

	// --------------------------------------------------
	// BACKDATED PROTECTION
	// --------------------------------------------------
	if !sourceRules.AllowBackdated && eventTime.Before(now.Add(-2*time.Minute)) {
		return time.Time{}, errors.New("backdated punch not allowed")
	}

	// --------------------------------------------------
	// FUTURE PROTECTION
	// --------------------------------------------------
	if !sourceRules.AllowFuture && eventTime.After(now.Add(2*time.Minute)) {
		return time.Time{}, errors.New("future punch not allowed")
	}

	return eventTime, nil
}

//
// ===========================
// HELPERS
// ===========================
//

func getExternalRef(ctx *attendance.EventContext) string {
	if ctx != nil && ctx.ExternalRef != nil {
		return *ctx.ExternalRef
	}
	return ""
}

func derefString(s *string) string {
	if s != nil {
		return *s
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
