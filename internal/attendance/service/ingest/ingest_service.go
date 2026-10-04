package ingest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/attendance/service/admin"
	"auth-service/internal/attendance/service/enrollment"
	"auth-service/internal/attendance/service/resolver"
	"auth-service/internal/attendance/service/source"
	"auth-service/internal/attendance/service/usage_integration"
	auditservice "auth-service/internal/infrastructure/audit"
	"auth-service/internal/locationctx"
	"auth-service/internal/util"
)

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
	usageService       *usage_integration.UsageIntegrationService
	locationResolver   resolver.SubjectLocationResolver

	// ── NEW: canonical timezone resolver
	tzProvider resolver.TimezoneProvider
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
	usageService *usage_integration.UsageIntegrationService,
	locationResolver resolver.SubjectLocationResolver,
	tzProvider resolver.TimezoneProvider, // ── NEW
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
		usageService:       usageService,
		locationResolver:   locationResolver,
		tzProvider:         tzProvider,
	}
}

func (s *ingestService) IngestPunch(ctx context.Context, req *PunchRequest) (*models.AttendanceEvent, error) {
	start := time.Now().UTC()
	s.logger.Info("IngestPunch START",
		zap.String("company_id", req.CompanyID.String()),
		zap.String("event_type", req.EventType),
		zap.String("source_type", req.Source.SourceType),
	)

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

	sourceRules, err := s.sourceResolver.Resolve(ctx, req.Source.SourceType)
	if err != nil {
		return nil, fmt.Errorf("invalid source type: %w", err)
	}

	eventTime, err := s.resolveEventTime(ctx, req, sourceRules)
	if err != nil {
		return nil, err
	}

	subjectType := req.SubjectType
	subjectID := req.SubjectID
	var deviceID *string
	var device *models.AttendanceDevice

	if sourceRules.RequiresDevice {
		if req.Source.DeviceID == nil || *req.Source.DeviceID == "" {
			return nil, errors.New("device_id required for this source type")
		}
		deviceID = req.Source.DeviceID
		device, err = s.deviceRepo.GetActiveDevice(ctx, req.CompanyID, *deviceID)
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

	resolvedRules, err := s.adminService.ResolveAttendanceRules(
		ctx,
		subjectID,
		req.CompanyID,
		subjectType,
		derefString(req.Context.WorkCenterCode),
		nil,
		eventTime,
	)
	if err != nil {
		return nil, fmt.Errorf("resolve attendance rules: %w", err)
	}

	if !resolvedRules.AllowedSourceTypesMap[req.Source.SourceType] {
		return nil, fmt.Errorf("source '%s' not allowed by rules", req.Source.SourceType)
	}

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

	if err := s.ensureActorCanActOnSubject(ctx, req.CompanyID, req.ActorID, subjectType, subjectID); err != nil {
		s.logger.Warn("Actor not authorized for subject location",
			zap.String("actor_id", req.ActorID.String()),
			zap.String("subject_type", subjectType),
			zap.String("subject_id", subjectID.String()),
			zap.Error(err),
		)
		return nil, err
	}

	subjectLocation, err := s.locationResolver.ResolveLocation(ctx, req.CompanyID, subjectType, subjectID)
	if err != nil {
		s.logger.Error("Failed to resolve subject location",
			zap.String("subject_type", subjectType),
			zap.String("subject_id", subjectID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("resolve subject location: %w", err)
	}

	// ── NEW: resolve timezone via the canonical chain.
	//    Priority: position.location → position.work_center →
	//    work_center.location → company.default_timezone.
	//
	//    We pass what we have. For device punches the work center comes
	//    from the device. For non-device punches it comes from Context.
	//    The subject's location is the last resort before company default.
	effectiveTz, tzErr := s.tzProvider.ResolveTimezone(
		ctx,
		req.CompanyID,
		nil, // positionID — we don't have it here; work center wins
		req.Context.WorkCenterCode,
		subjectLocation,
	)
	if tzErr != nil {
		s.logger.Error("tz resolution failed, defaulting to UTC",
			zap.String("company_id", req.CompanyID.String()),
			zap.String("subject_id", subjectID.String()),
			zap.Error(tzErr),
		)
		effectiveTz = "UTC"
	}
	if effectiveTz == "" {
		effectiveTz = "UTC"
	}

	// Compute the three tz-derived columns.
	offsetMinutes := util.OffsetMinutes(eventTime, effectiveTz)
	eventDateLocal := util.CalendarDateInTz(eventTime, effectiveTz)

	// Optional country code from the location (for tax-residency reports).
	eventCountry := s.resolveEventCountry(ctx, req.CompanyID, subjectLocation)

	event := &models.AttendanceEvent{
		AttendanceEventID:    uuid.New(),
		CompanyID:            req.CompanyID,
		SubjectType:          subjectType,
		SubjectID:            subjectID,
		EventType:            req.EventType,
		EventTime:            eventTime,
		EventTZ:              effectiveTz,
		EventOffsetMinutes:   int16(offsetMinutes),
		EventDateLocal:       eventDateLocal,
		EventCountry:         eventCountry,
		EmploymentLocationID: subjectLocation,
		GeofenceID:           deviceGeofence(device),
		SourceType:           req.Source.SourceType,
		SourceID:             req.Source.SourceID,
		DeviceID:             deviceID,
		DeviceUserCode:       req.DeviceUserCode,
		IPAddress:            req.Source.IPAddress,
		Context:              *req.Context,
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
	if tx == nil {
		s.logger.Error("Transaction is nil but no error returned from BeginTx")
		return nil, errors.New("failed to begin transaction: tx is nil")
	}
	defer tx.Rollback()

	if err := s.eventRepo.CreateEvent(ctx, tx, event); err != nil {
		return nil, fmt.Errorf("create event: %w", err)
	}
	if deviceID != nil {
		_ = s.deviceRepo.UpdateLastSeen(ctx, *deviceID)
	}

	if req.Context.SessionID != nil && *req.Context.SessionID != uuid.Nil {
		// ── CHANGED: pass effectiveTz so the session summary is bucketed
		//    into the correct local day.
		if err := s.updateSessionSummary(ctx, tx, event, *req.Context.SessionID, subjectLocation, effectiveTz); err != nil {
			s.logger.Warn("Failed to update session summary",
				zap.String("event_id", event.AttendanceEventID.String()),
				zap.String("session_id", req.Context.SessionID.String()),
				zap.Error(err),
			)
		}
	}

	if subjectType == "customer" && req.EventType == "check_in" {
		featureKey := s.getFeatureKeyForEvent(req.EventType, req.Source.SourceType)
		if featureKey != "" {
			if s.usageService == nil {
				s.logger.Error("usageService is nil; cannot process usage")
				return nil, errors.New("usage service not available")
			}
			if err := s.usageService.ProcessCheckIn(
				ctx,
				tx,
				req.CompanyID,
				subjectID,
				event.AttendanceEventID,
				featureKey,
				decimal.NewFromInt(1),
			); err != nil {
				s.logger.Error("Usage processing failed, rejecting punch",
					zap.Error(err),
					zap.String("customer_id", subjectID.String()),
				)
				return nil, fmt.Errorf("usage processing failed: %w", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	s.logger.Info("IngestPunch SUCCESS",
		zap.String("event_id", event.AttendanceEventID.String()),
		zap.String("subject_type", subjectType),
		zap.String("subject_id", subjectID.String()),
		zap.String("event_tz", effectiveTz),
		zap.Int("offset_minutes", offsetMinutes),
		zap.Time("event_date_local", eventDateLocal),
		zap.Duration("duration", time.Since(start)),
	)
	return event, nil
}

// resolveEventCountry looks up locations.country for the subject's location.
// Returns nil if not resolvable. Never fails the write — country is optional.
func (s *ingestService) resolveEventCountry(
	ctx context.Context,
	companyID uuid.UUID,
	locationID *uuid.UUID,
) *string {
	if locationID == nil || *locationID == uuid.Nil {
		return nil
	}
	var country sql.NullString
	err := s.eventRepo.(interface {
		QueryRow(ctx context.Context, query string, args ...interface{}) *sql.Row
	}).QueryRow(ctx, `
		SELECT country FROM locations
		WHERE company_id = $1 AND location_id = $2
	`, companyID, *locationID).Scan(&country)
	if err != nil {
		return nil
	}
	if !country.Valid || country.String == "" {
		return nil
	}
	// Truncate to alpha-2
	c := country.String
	if len(c) > 2 {
		c = c[:2]
	}
	c = strings.ToUpper(c)
	return &c
}

func (s *ingestService) ensureActorCanActOnSubject(
	ctx context.Context,
	companyID, actorID uuid.UUID,
	subjectType string,
	subjectID uuid.UUID,
) error {
	if actorID == uuid.Nil {
		return nil
	}
	if actorID == subjectID {
		return nil
	}
	locCtx, err := locationctx.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("location context missing for cross-subject write: %w", resolver.ErrSubjectOutsideScope)
	}
	if locCtx.Mode == locationctx.ScopeAll {
		return nil
	}
	subjectLoc, err := s.locationResolver.ResolveLocation(ctx, companyID, subjectType, subjectID)
	if err != nil {
		return err
	}
	if subjectLoc == nil {
		return resolver.ErrSubjectHasNoLocation
	}
	if locCtx.LocationID == nil || *subjectLoc != *locCtx.LocationID {
		return resolver.ErrSubjectOutsideScope
	}
	return nil
}

func deviceGeofence(device *models.AttendanceDevice) *uuid.UUID {
	if device == nil {
		return nil
	}
	return device.GeofenceID
}

func derefString(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}

func boolPtr(b bool) *bool {
	return &b
}

func (s *ingestService) resolveEventTime(
	ctx context.Context,
	req *PunchRequest,
	rules *source.ResolvedSourceRules,
) (time.Time, error) {
	if rules.RequiresDevice {
		if req.EventTime == nil {
			return time.Time{}, errors.New("event_time required for device events")
		}
		if _, offset := req.EventTime.Zone(); offset == 0 {
			s.logger.Warn("Device event_time has zero offset; timezone may be missing from payload",
				zap.String("company_id", req.CompanyID.String()),
				zap.Time("event_time", *req.EventTime),
			)
		}
		return req.EventTime.UTC(), nil
	}
	if rules.IsSystem {
		return time.Now().UTC(), nil
	}
	if req.EventTime != nil {
		return req.EventTime.UTC(), nil
	}
	return time.Now().UTC(), nil
}

// updateSessionSummary buckets the session into the subject's LOCAL day
// (per `tz`), not UTC.
func (s *ingestService) updateSessionSummary(
	ctx context.Context,
	tx *sql.Tx,
	event *models.AttendanceEvent,
	sessionID uuid.UUID,
	subjectLocation *uuid.UUID,
	tz string,
) error {
	sessionDate := util.CalendarDateInTz(event.EventTime, tz)
	status := mapEventTypeToSessionStatus(event.EventType)
	summary := &models.AttendanceSessionSummary{
		CompanyID:            event.CompanyID,
		SubjectType:          event.SubjectType,
		SubjectID:            event.SubjectID,
		EmploymentLocationID: subjectLocation,
		SessionID:            sessionID,
		SessionDate:          sessionDate,
		Timezone:             tz,
		Status:               status,
		MarkedAt:             event.EventTime,
		MarkedBy:             event.CreatedBy,
		SourceType:           event.SourceType,
		DeviceID:             event.DeviceID,
		IsAuto:               event.Metadata.IsAutoGenerated != nil && *event.Metadata.IsAutoGenerated,
		Remarks:              nil,
		Metadata: models.JSONB{
			"event_id": event.AttendanceEventID.String(),
			"tz":       tz,
		},
	}
	return s.sessionSummaryRepo.Upsert(ctx, tx, summary)
}

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
		return "present"
	}
}

func (s *ingestService) getFeatureKeyForEvent(eventType, sourceType string) string {
	switch eventType {
	case "check_in":
		return "gym_visit"
	case "class_start":
		return "class_attendance"
	default:
		return ""
	}
}
