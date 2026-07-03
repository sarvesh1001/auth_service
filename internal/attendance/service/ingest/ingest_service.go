package ingest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/attendance/service/admin"
	"auth-service/internal/attendance/service/enrollment"
	"auth-service/internal/attendance/service/source"
	auditservice "auth-service/internal/infrastructure/audit"
)

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

type PunchRequest struct {
	CompanyID      uuid.UUID
	ActorID        uuid.UUID
	SubjectType    string
	SubjectID      uuid.UUID
	EventType      string
	EventTime      *time.Time
	Source         PunchSource
	Context        *models.EventContext
	DeviceUserCode *string
}

type PunchSource struct {
	SourceType string
	SourceID   *uuid.UUID
	DeviceID   *string
	IPAddress  *string
}

// ---------------------------------------------------------------------------
// Main interface and service struct
// ---------------------------------------------------------------------------

type IngestService interface {
	IngestPunch(ctx context.Context, req *PunchRequest) (*models.AttendanceEvent, error)
}

type OMService interface {
	CanPunchAttendance(ctx context.Context, companyID uuid.UUID, actorID *uuid.UUID, subjectType string, subjectID uuid.UUID, sourceType string, workCenterCode *string) (bool, string)
}

type ingestService struct {
	eventRepo          repository.EventRepository
	deviceRepo         repository.DeviceRepository
	sourceRepo         repository.SourceRepository
	enrollmentService  enrollment.EnrollmentService
	sourceResolver     source.SourceResolver
	adminService       admin.AdminService
	omService          OMService
	audit              *auditservice.AuditService
	logger             *zap.Logger
	sessionSummaryRepo repository.AttendanceSessionSummaryRepository
}

func NewIngestService(
	eventRepo repository.EventRepository,
	deviceRepo repository.DeviceRepository,
	sourceRepo repository.SourceRepository,
	enrollmentService enrollment.EnrollmentService,
	sourceResolver source.SourceResolver,
	adminService admin.AdminService,
	omService OMService,
	audit *auditservice.AuditService,
	logger *zap.Logger,
	sessionSummaryRepo repository.AttendanceSessionSummaryRepository,
) IngestService {
	return &ingestService{
		eventRepo:          eventRepo,
		deviceRepo:         deviceRepo,
		sourceRepo:         sourceRepo,
		enrollmentService:  enrollmentService,
		sourceResolver:     sourceResolver,
		adminService:       adminService,
		omService:          omService,
		audit:              audit,
		logger:             logger,
		sessionSummaryRepo: sessionSummaryRepo,
	}
}

// ---------------------------------------------------------------------------
// Core ingest logic
// ---------------------------------------------------------------------------

func (s *ingestService) IngestPunch(ctx context.Context, req *PunchRequest) (*models.AttendanceEvent, error) {
	start := time.Now().UTC()
	s.logger.Info("IngestPunch START",
		zap.String("company_id", req.CompanyID.String()),
		zap.String("event_type", req.EventType),
		zap.String("source_type", req.Source.SourceType),
	)

	// 1. Basic validation
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
		req.Context = &models.EventContext{}
	}

	// 2. Resolve source rules
	sourceRules, err := s.sourceResolver.Resolve(ctx, req.Source.SourceType)
	if err != nil {
		return nil, fmt.Errorf("invalid source type: %w", err)
	}

	// 3. Resolve event time
	eventTime, err := s.resolveEventTime(ctx, req, sourceRules)
	if err != nil {
		return nil, err
	}

	// 4. Determine subject (via enrollment if device)
	subjectType := req.SubjectType
	subjectID := req.SubjectID
	var deviceID *string

	if sourceRules.RequiresDevice {
		if req.Source.DeviceID == nil || *req.Source.DeviceID == "" {
			return nil, errors.New("device_id required for this source type")
		}
		deviceID = req.Source.DeviceID
		device, err := s.deviceRepo.GetActiveDevice(ctx, req.CompanyID, *deviceID)
		if err != nil || device == nil || !device.IsTrusted {
			return nil, errors.New("invalid or untrusted device")
		}
		if device.WorkCenterCode != nil {
			req.Context.WorkCenterCode = device.WorkCenterCode
		}
		if req.DeviceUserCode == nil || *req.DeviceUserCode == "" {
			return nil, errors.New("device_user_code required for device source")
		}
		enrollment, err := s.enrollmentService.ResolveEnrollment(ctx, req.CompanyID, *deviceID, req.Source.SourceType, *req.DeviceUserCode)
		if err != nil {
			return nil, fmt.Errorf("enrollment resolution failed: %w", err)
		}
		subjectType = enrollment.SubjectType
		subjectID = enrollment.SubjectID
	} else {
		if subjectID == uuid.Nil || subjectType == "" {
			return nil, errors.New("subject_type and subject_id required for non-device sources")
		}
	}

	// 5. Resolve attendance rules (policy)
	// --- FIX: add subjectType to the call ---
	resolvedRules, err := s.adminService.ResolveAttendanceRules(
		ctx,
		subjectID,
		req.CompanyID,
		subjectType, // <-- added
		derefString(req.Context.WorkCenterCode),
		nil, // positionID
		eventTime,
	)
	if err != nil {
		return nil, fmt.Errorf("resolve attendance rules: %w", err)
	}
	if !resolvedRules.AllowedSourceTypesMap[req.Source.SourceType] {
		return nil, fmt.Errorf("source '%s' not allowed by rules", req.Source.SourceType)
	}

	// 6. Ensure attendance source exists
	if req.Source.SourceID == nil {
		src, err := s.sourceRepo.GetByType(ctx, req.CompanyID, req.Source.SourceType)
		if err != nil {
			return nil, fmt.Errorf("get attendance source: %w", err)
		}
		if src == nil {
			return nil, errors.New("attendance source not configured for this company")
		}
		req.Source.SourceID = &src.SourceID
	}

	// 7. OM authorization
	var actorPtr *uuid.UUID
	if req.ActorID != uuid.Nil {
		actorPtr = &req.ActorID
	}
	allowed, reason := s.omService.CanPunchAttendance(
		ctx,
		req.CompanyID,
		actorPtr,
		subjectType,
		subjectID,
		req.Source.SourceType,
		req.Context.WorkCenterCode,
	)
	if !allowed {
		s.logger.Warn("OM authorization denied",
			zap.String("actor_id", req.ActorID.String()),
			zap.String("subject_type", subjectType),
			zap.String("subject_id", subjectID.String()),
			zap.String("reason", reason),
		)
		return nil, fmt.Errorf("not authorized: %s", reason)
	}

	// 8. Build and store the event
	event := &models.AttendanceEvent{
		AttendanceEventID: uuid.New(),
		CompanyID:         req.CompanyID,
		SubjectType:       subjectType,
		SubjectID:         subjectID,
		EventType:         req.EventType,
		EventTime:         eventTime,
		SourceType:        req.Source.SourceType,
		SourceID:          req.Source.SourceID,
		DeviceID:          deviceID,
		DeviceUserCode:    req.DeviceUserCode,
		IPAddress:         req.Source.IPAddress,
		Context:           *req.Context,
		Metadata: models.EventMetadata{
			IsAutoGenerated: boolPtr(sourceRules.IsSystem),
		},
		CreatedAt: time.Now().UTC(),
		CreatedBy: actorPtr,
	}

	tx, err := s.eventRepo.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.eventRepo.CreateEvent(ctx, tx, event); err != nil {
		return nil, fmt.Errorf("create event: %w", err)
	}

	if deviceID != nil {
		_ = s.deviceRepo.UpdateLastSeen(ctx, *deviceID)
	}

	// 9. If this punch is linked to a session, upsert the session summary
	if req.Context.SessionID != nil && *req.Context.SessionID != uuid.Nil {
		if err := s.updateSessionSummary(ctx, tx, event, *req.Context.SessionID); err != nil {
			// Do not fail the whole transaction; just log.
			s.logger.Warn("Failed to update session summary",
				zap.String("event_id", event.AttendanceEventID.String()),
				zap.String("session_id", req.Context.SessionID.String()),
				zap.Error(err),
			)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	s.logger.Info("IngestPunch SUCCESS",
		zap.String("event_id", event.AttendanceEventID.String()),
		zap.String("subject_type", subjectType),
		zap.String("subject_id", subjectID.String()),
		zap.Duration("duration", time.Since(start)),
	)
	return event, nil
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

func derefString(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}

func boolPtr(b bool) *bool {
	return &b
}

// resolveEventTime determines the event timestamp based on source rules and company timezone.
func (s *ingestService) resolveEventTime(ctx context.Context, req *PunchRequest, rules *source.ResolvedSourceRules) (time.Time, error) {
	companyRules, err := s.adminService.GetCompanyAttendanceRules(ctx, req.CompanyID)
	if err != nil {
		return time.Time{}, fmt.Errorf("get company rules: %w", err)
	}
	loc, err := time.LoadLocation(companyRules.Timezone)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid timezone: %w", err)
	}
	if rules.RequiresDevice {
		if req.EventTime == nil {
			return time.Time{}, errors.New("event_time required for device events")
		}
		return req.EventTime.In(loc).UTC(), nil
	}
	if rules.IsSystem {
		return time.Now().UTC(), nil
	}
	nowUTC := time.Now().UTC()
	nowInLoc := nowUTC.In(loc)
	return nowInLoc.UTC(), nil
}

// updateSessionSummary creates or updates the session summary based on the event.
// Note: tx is *sql.Tx because that's what the repository expects.
func (s *ingestService) updateSessionSummary(ctx context.Context, tx *sql.Tx, event *models.AttendanceEvent, sessionID uuid.UUID) error {
	// Determine session date from event time (use UTC for simplicity; can be enhanced with company timezone)
	sessionDate := event.EventTime.UTC().Truncate(24 * time.Hour)

	status := mapEventTypeToSessionStatus(event.EventType)

	summary := &models.AttendanceSessionSummary{
		CompanyID:   event.CompanyID,
		SubjectType: event.SubjectType,
		SubjectID:   event.SubjectID,
		SessionID:   sessionID,
		SessionDate: sessionDate,
		Status:      status,
		MarkedAt:    event.EventTime,
		MarkedBy:    event.CreatedBy,
		SourceType:  event.SourceType,
		DeviceID:    event.DeviceID,
		IsAuto:      event.Metadata.IsAutoGenerated != nil && *event.Metadata.IsAutoGenerated,
		Remarks:     nil,
		Metadata: models.JSONB{
			"event_id": event.AttendanceEventID.String(),
		},
	}

	return s.sessionSummaryRepo.Upsert(ctx, tx, summary)
}

// mapEventTypeToSessionStatus converts an attendance event type to a session status.
// Customize this mapping based on your business rules.
func mapEventTypeToSessionStatus(eventType string) string {
	switch eventType {
	case "check_in", "shift_start", "class_start", "session_join", "present":
		return "present"
	case "absent_marked", "missing_punch", "absent":
		return "absent"
	case "late_entry", "late":
		return "late"
	case "excused", "exempted":
		return "excused"
	default:
		// Default to "present" for unknown event types
		return "present"
	}
}
