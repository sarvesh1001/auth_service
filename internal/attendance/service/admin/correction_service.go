package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/attendance/service/resolver"
	auditservice "auth-service/internal/infrastructure/audit"
	"auth-service/internal/locationctx"
	"auth-service/internal/util"
)

type CorrectionRequest struct {
	CompanyID      uuid.UUID
	ActorID        uuid.UUID
	ActorType      string
	SubjectType    string
	SubjectID      uuid.UUID
	BusinessDate   time.Time
	CorrectionType string
	EventTime      *time.Time
	OverrideStatus string
	Reason         string
}

type CorrectionService interface {
	CreateCorrection(ctx context.Context, req *CorrectionRequest) error
}

type correctionService struct {
	eventRepo        repository.EventRepository
	summaryRepo      repository.SummaryRepository
	admin            AdminService
	resolver         resolver.SubjectResolver
	locationResolver resolver.SubjectLocationResolver
	resolution       ResolutionService
	logger           *zap.Logger
	audit            *auditservice.AuditService

	// ── NEW: canonical timezone resolver
	tzProvider resolver.TimezoneProvider
}

type ResolutionService interface {
	RecalculateDay(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, date time.Time) error
}

func NewCorrectionService(
	eventRepo repository.EventRepository,
	summaryRepo repository.SummaryRepository,
	admin AdminService,
	resolver resolver.SubjectResolver,
	locationResolver resolver.SubjectLocationResolver,
	resolution ResolutionService,
	logger *zap.Logger,
	audit *auditservice.AuditService,
	tzProvider resolver.TimezoneProvider, // ── NEW
) CorrectionService {
	return &correctionService{
		eventRepo:        eventRepo,
		summaryRepo:      summaryRepo,
		admin:            admin,
		resolver:         resolver,
		locationResolver: locationResolver,
		resolution:       resolution,
		logger:           logger,
		audit:            audit,
		tzProvider:       tzProvider,
	}
}

func (s *correctionService) CreateCorrection(ctx context.Context, req *CorrectionRequest) error {
	startTime := time.Now()

	if !isValidCorrectionType(req.CorrectionType) {
		return fmt.Errorf("invalid correction type: %s", req.CorrectionType)
	}
	if req.CorrectionType == "manual_check_in" || req.CorrectionType == "manual_check_out" {
		if req.EventTime == nil {
			return fmt.Errorf("event_time required for %s", req.CorrectionType)
		}
	}
	if req.CorrectionType == "manual_override" || req.CorrectionType == "attendance_adjustment" {
		if req.OverrideStatus == "" {
			return fmt.Errorf("override_status required for %s", req.CorrectionType)
		}
		if !isValidStatus(req.OverrideStatus) {
			return fmt.Errorf("invalid override_status: %s", req.OverrideStatus)
		}
	}

	// ── NEW: resolve subject tz via the canonical chain.
	subjectTZ := s.resolveSubjectTimezone(ctx, req.CompanyID, req.SubjectType, req.SubjectID)

	loc, err := time.LoadLocation(subjectTZ)
	if err != nil {
		loc = time.UTC
	}

	var eventTime time.Time
	if req.EventTime != nil {
		eventTime = *req.EventTime
		evtLocal := eventTime.In(loc).Format("2006-01-02")
		bizLocal := req.BusinessDate.In(loc).Format("2006-01-02")
		if evtLocal != bizLocal {
			return fmt.Errorf("event_time %s does not belong to business_date %s (subject tz %s)",
				eventTime.In(loc).Format(time.RFC3339),
				req.BusinessDate.In(loc).Format("2006-01-02"),
				subjectTZ)
		}
	} else {
		// No explicit event time — use midnight of the business date in subject tz.
		eventTime = time.Date(
			req.BusinessDate.Year(), req.BusinessDate.Month(), req.BusinessDate.Day(),
			0, 0, 0, 0, loc,
		).UTC()
	}

	existing, err := s.eventRepo.FindCorrection(ctx, req.CompanyID, req.SubjectID, req.SubjectType, req.CorrectionType, eventTime)
	if err != nil {
		return fmt.Errorf("check existing correction: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("correction already exists for this event")
	}

	if err := s.ensureSubjectInScope(ctx, req.CompanyID, req.SubjectType, req.SubjectID); err != nil {
		s.logger.Warn("Correction target outside caller scope",
			zap.String("subject_type", req.SubjectType),
			zap.String("subject_id", req.SubjectID.String()),
			zap.Error(err),
		)
		return err
	}

	subjectLocation, err := s.locationResolver.ResolveLocation(ctx, req.CompanyID, req.SubjectType, req.SubjectID)
	if err != nil {
		return fmt.Errorf("resolve subject location: %w", err)
	}

	// ── NEW: compute tz-derived columns for the correction event.
	offsetMinutes := util.OffsetMinutes(eventTime, subjectTZ)
	eventDateLocal := util.CalendarDateInTz(eventTime, subjectTZ)

	event := &models.AttendanceEvent{
		AttendanceEventID:    uuid.New(),
		CompanyID:            req.CompanyID,
		SubjectType:          req.SubjectType,
		SubjectID:            req.SubjectID,
		EventType:            req.CorrectionType,
		EventTime:            eventTime,
		EventTZ:              subjectTZ,
		EventOffsetMinutes:   int16(offsetMinutes),
		EventDateLocal:       eventDateLocal,
		EmploymentLocationID: subjectLocation,
		SourceType:           "correction",
		SourceID:             nil,
		DeviceID:             nil,
		IPAddress:            nil,
		Context: models.EventContext{
			CorrectionReason: &req.Reason,
		},
		Metadata: models.EventMetadata{
			IsCorrection:   boolPtr(true),
			OverrideStatus: &req.OverrideStatus,
			CorrectedBy:    &req.ActorID,
		},
		CreatedAt: time.Now().UTC(),
		CreatedBy: &req.ActorID,
	}

	tx, err := s.eventRepo.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.eventRepo.CreateEvent(ctx, tx, event); err != nil {
		return fmt.Errorf("create correction event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.resolution != nil {
		if err := s.resolution.RecalculateDay(ctx, req.CompanyID, req.SubjectID, req.SubjectType, req.BusinessDate); err != nil {
			s.logger.Warn("Correction created but recalculation failed",
				zap.String("event_id", event.AttendanceEventID.String()),
				zap.Error(err))
		}
	}

	s.logAudit(ctx, req.CompanyID, "attendance.correction.create", event.AttendanceEventID,
		req.ActorType, req.ActorID, nil, event, map[string]interface{}{
			"correction_type": req.CorrectionType,
			"business_date":   req.BusinessDate.Format("2006-01-02"),
			"event_time":      eventTime.Format(time.RFC3339),
			"override_status": req.OverrideStatus,
			"reason":          req.Reason,
			"event_tz":        subjectTZ,
		})
	s.logger.Info("Attendance correction created",
		zap.String("event_id", event.AttendanceEventID.String()),
		zap.String("subject_type", req.SubjectType),
		zap.String("subject_id", req.SubjectID.String()),
		zap.String("correction_type", req.CorrectionType),
		zap.String("tz", subjectTZ),
		zap.Duration("duration", time.Since(startTime)),
	)
	return nil
}

// resolveSubjectTimezone uses the TimezoneProvider chain. Falls back to
// "UTC" only if the chain itself errors.
func (s *correctionService) resolveSubjectTimezone(
	ctx context.Context,
	companyID uuid.UUID,
	subjectType string,
	subjectID uuid.UUID,
) string {
	// Fetch the subject once to get position + work center hints.
	resolved, err := s.resolver.Resolve(ctx, companyID, subjectType, subjectID, time.Now())
	if err == nil && resolved != nil && resolved.Timezone != "" {
		return resolved.Timezone
	}

	// Fall back to provider with what we have.
	var positionID *uuid.UUID
	var workCenterCode *string
	if resolved != nil {
		positionID = resolved.PositionID
		workCenterCode = resolved.WorkCenterCode
	}
	tz, err := s.tzProvider.ResolveTimezone(ctx, companyID, positionID, workCenterCode, nil)
	if err == nil && tz != "" {
		return tz
	}

	s.logger.Warn("correction tz resolution failed, defaulting to UTC",
		zap.String("company_id", companyID.String()),
		zap.String("subject_id", subjectID.String()),
	)
	return "UTC"
}

func (s *correctionService) ensureSubjectInScope(
	ctx context.Context,
	companyID uuid.UUID,
	subjectType string,
	subjectID uuid.UUID,
) error {
	locCtx, err := locationctx.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("location context missing: %w", err)
	}
	if locCtx.Mode == locationctx.ScopeAll {
		return nil
	}
	if s.locationResolver == nil {
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

func isValidCorrectionType(t string) bool {
	valid := map[string]bool{
		"manual_check_in":       true,
		"manual_check_out":      true,
		"attendance_adjustment": true,
		"manual_override":       true,
	}
	return valid[t]
}

func isValidStatus(s string) bool {
	valid := []string{"present", "absent", "late", "half_day", "incomplete", "weekly_off", "holiday", "on_leave", "not_scheduled"}
	for _, v := range valid {
		if s == v {
			return true
		}
	}
	return false
}

func boolPtr(b bool) *bool {
	return &b
}

func (s *correctionService) logAudit(ctx context.Context, companyID uuid.UUID, action string, resourceID uuid.UUID, actorType string, actorID uuid.UUID, before, after interface{}, metadata map[string]interface{}) {
	if s.audit == nil {
		return
	}
	var beforeJSON, afterJSON []byte
	if before != nil {
		beforeJSON, _ = json.Marshal(before)
	}
	if after != nil {
		afterJSON, _ = json.Marshal(after)
	}
	_ = s.audit.LogAction(ctx, nil, &companyID, "attendance", action, strings.Split(action, ".")[0], &resourceID, actorType, &actorID, beforeJSON, afterJSON, metadata)
}
