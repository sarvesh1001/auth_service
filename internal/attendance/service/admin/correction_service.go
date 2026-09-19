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
)

// CorrectionRequest is the input for creating an attendance correction.
type CorrectionRequest struct {
	CompanyID      uuid.UUID
	ActorID        uuid.UUID
	ActorType      string
	SubjectType    string
	SubjectID      uuid.UUID
	BusinessDate   time.Time
	CorrectionType string // manual_check_in, manual_check_out, attendance_adjustment, manual_override
	EventTime      *time.Time
	OverrideStatus string // present, absent, late, half_day, etc.
	Reason         string
}

// CorrectionService handles creation of attendance corrections.
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
}

// ResolutionService is a minimal interface for recalculating a day.
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
	}
}

func (s *correctionService) CreateCorrection(ctx context.Context, req *CorrectionRequest) error {
	startTime := time.Now()

	// 1. Validate correction type
	if !isValidCorrectionType(req.CorrectionType) {
		return fmt.Errorf("invalid correction type: %s", req.CorrectionType)
	}

	// 2. Required fields based on type
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

	// 3. Ensure event_time belongs to business_date (if provided)
	var eventTime time.Time
	if req.EventTime != nil {
		eventTime = *req.EventTime
		if eventTime.UTC().Format("2006-01-02") != req.BusinessDate.UTC().Format("2006-01-02") {
			return fmt.Errorf("event_time %s does not belong to business_date %s",
				eventTime.Format("2006-01-02"), req.BusinessDate.Format("2006-01-02"))
		}
	} else {
		// Default to midnight on business date
		eventTime = time.Date(req.BusinessDate.Year(), req.BusinessDate.Month(), req.BusinessDate.Day(),
			0, 0, 0, 0, req.BusinessDate.Location())
	}

	// 4. Idempotency: check if correction already exists for this event_time and subject
	existing, err := s.eventRepo.FindCorrection(ctx, req.CompanyID, req.SubjectID, req.SubjectType, req.CorrectionType, eventTime)
	if err != nil {
		return fmt.Errorf("check existing correction: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("correction already exists for this event")
	}

	// 5. Row-level authorization — the target subject must be in the caller's scope.
	if err := s.ensureSubjectInScope(ctx, req.CompanyID, req.SubjectType, req.SubjectID); err != nil {
		s.logger.Warn("Correction target outside caller scope",
			zap.String("subject_type", req.SubjectType),
			zap.String("subject_id", req.SubjectID.String()),
			zap.Error(err),
		)
		return err
	}

	// 5b. Resolve and stamp the subject's location (snapshot).
	subjectLocation, err := s.locationResolver.ResolveLocation(ctx, req.CompanyID, req.SubjectType, req.SubjectID)
	if err != nil {
		return fmt.Errorf("resolve subject location: %w", err)
	}

	// 6. Create event
	event := &models.AttendanceEvent{
		AttendanceEventID: uuid.New(),
		CompanyID:         req.CompanyID,
		SubjectType:       req.SubjectType,
		SubjectID:         req.SubjectID,
		EventType:         req.CorrectionType,
		EventTime:         eventTime,

		EmploymentLocationID: subjectLocation,

		SourceType: "correction",
		SourceID:   nil,
		DeviceID:   nil,
		IPAddress:  nil,
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

	// 7. Recalculate attendance for that day
	if s.resolution != nil {
		if err := s.resolution.RecalculateDay(ctx, req.CompanyID, req.SubjectID, req.SubjectType, req.BusinessDate); err != nil {
			s.logger.Warn("Correction created but recalculation failed",
				zap.String("event_id", event.AttendanceEventID.String()),
				zap.Error(err))
		}
	}

	// 8. Audit
	s.logAudit(ctx, req.CompanyID, "attendance.correction.create", event.AttendanceEventID,
		req.ActorType, req.ActorID, nil, event, map[string]interface{}{
			"correction_type": req.CorrectionType,
			"business_date":   req.BusinessDate.Format("2006-01-02"),
			"event_time":      eventTime.Format(time.RFC3339),
			"override_status": req.OverrideStatus,
			"reason":          req.Reason,
		})

	s.logger.Info("Attendance correction created",
		zap.String("event_id", event.AttendanceEventID.String()),
		zap.String("subject_type", req.SubjectType),
		zap.String("subject_id", req.SubjectID.String()),
		zap.String("correction_type", req.CorrectionType),
		zap.Time("business_date", req.BusinessDate),
		zap.Duration("duration", time.Since(startTime)),
	)
	return nil
}

// ensureSubjectInScope verifies the target subject is within the caller's
// current location scope.
//
//   - ScopeAll      → permitted
//   - ScopeLocation → target's employment location must match the scope
//   - No location context → error (correction routes are always wrapped)
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

	subjectLoc, err := s.locationResolver.ResolveLocation(ctx, companyID, subjectType, subjectID)
	if err != nil {
		return err
	}
	if subjectLoc == nil {
		return resolver.ErrSubjectHasNoLocation
	}
	if *subjectLoc != *locCtx.LocationID {
		return resolver.ErrSubjectOutsideScope
	}
	return nil
}

// helpers
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
