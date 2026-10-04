package resolution

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/attendance/service/admin"
	"auth-service/internal/attendance/service/resolver"
	auditservice "auth-service/internal/infrastructure/audit"
	"auth-service/internal/util"
)

const (
	defaultMaxShiftDurationHours = 20
)

type PairedEvent struct {
	CheckIn      *models.AttendanceEvent
	CheckOut     *models.AttendanceEvent
	CheckInTime  *time.Time
	CheckOutTime *time.Time
	BreakStart   *time.Time
	BreakEnd     *time.Time
}

type DailyMetrics struct {
	WorkedMinutes   *int
	OvertimeMinutes *int
	LateMinutes     *int
	BreakMinutes    *int
	ExpectedMinutes *int
	CheckIns        int
	CheckOuts       int
	FirstCheckIn    *time.Time
	LastCheckOut    *time.Time
	Status          string
	PairedEvents    []PairedEvent
}

type ResolutionService interface {
	ResolveEvent(ctx context.Context, eventID uuid.UUID) error
	ResolveDay(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, date time.Time) error
	ResolvePeriod(ctx context.Context, companyID uuid.UUID, subjectIDs []uuid.UUID, subjectType string, startDate, endDate time.Time, recalculate bool) error
	BatchResolveEvents(ctx context.Context, eventIDs []uuid.UUID) error
	RecalculateDay(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, date time.Time) error
}

type resolutionService struct {
	eventRepo        repository.EventRepository
	summaryRepo      repository.SummaryRepository
	scheduleRepo     repository.ScheduleRepository
	policyRepo       repository.PolicyRepository
	subjectRes       resolver.SubjectResolver
	locationResolver resolver.SubjectLocationResolver
	adminSvc         admin.AdminService
	exemptionRepo    repository.AttendanceExemptionRepository
	logger           *zap.Logger
	audit            *auditservice.AuditService

	// ── NEW
	tzProvider resolver.TimezoneProvider
}

func NewResolutionService(
	eventRepo repository.EventRepository,
	summaryRepo repository.SummaryRepository,
	scheduleRepo repository.ScheduleRepository,
	policyRepo repository.PolicyRepository,
	subjectRes resolver.SubjectResolver,
	locationResolver resolver.SubjectLocationResolver,
	adminSvc admin.AdminService,
	exemptionRepo repository.AttendanceExemptionRepository,
	logger *zap.Logger,
	audit *auditservice.AuditService,
	tzProvider resolver.TimezoneProvider, // ── NEW
) ResolutionService {
	return &resolutionService{
		eventRepo:        eventRepo,
		summaryRepo:      summaryRepo,
		scheduleRepo:     scheduleRepo,
		policyRepo:       policyRepo,
		subjectRes:       subjectRes,
		locationResolver: locationResolver,
		adminSvc:         adminSvc,
		exemptionRepo:    exemptionRepo,
		logger:           logger,
		audit:            audit,
		tzProvider:       tzProvider,
	}
}

func (s *resolutionService) ResolveEvent(ctx context.Context, eventID uuid.UUID) error {
	if eventID == uuid.Nil {
		return fmt.Errorf("eventID is required")
	}
	event, err := s.eventRepo.GetEventByID(ctx, eventID)
	if err != nil {
		return fmt.Errorf("get event: %w", err)
	}
	if event == nil {
		return fmt.Errorf("event not found")
	}
	return s.resolveSubjectDay(ctx, event.CompanyID, event.SubjectID, event.SubjectType, event.EventTime)
}

func (s *resolutionService) ResolveDay(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, date time.Time) error {
	return s.resolveSubjectDay(ctx, companyID, subjectID, subjectType, date)
}

// ResolvePeriod iterates calendar days in the subject's local tz, not UTC.
// Each subject may have a different tz; we resolve per subject.
func (s *resolutionService) ResolvePeriod(
	ctx context.Context,
	companyID uuid.UUID,
	subjectIDs []uuid.UUID,
	subjectType string,
	startDate, endDate time.Time,
	recalculate bool,
) error {
	if len(subjectIDs) == 0 {
		return nil
	}
	for _, subjectID := range subjectIDs {
		tz := s.resolveSubjectTz(ctx, companyID, subjectType, subjectID, startDate)
		loc, _ := time.LoadLocation(tz)
		if loc == nil {
			loc = time.UTC
		}
		// Iterate days in local tz.
		current := time.Date(startDate.Year(), startDate.Month(), startDate.Day(), 0, 0, 0, 0, loc)
		last := time.Date(endDate.Year(), endDate.Month(), endDate.Day(), 0, 0, 0, 0, loc)
		for !current.After(last) {
			var err error
			if recalculate {
				err = s.RecalculateDay(ctx, companyID, subjectID, subjectType, current)
			} else {
				err = s.ResolveDay(ctx, companyID, subjectID, subjectType, current)
			}
			if err != nil {
				s.logger.Error("Failed to resolve day",
					zap.String("subject_type", subjectType),
					zap.String("subject_id", subjectID.String()),
					zap.Time("date", current),
					zap.String("tz", tz),
					zap.Error(err),
				)
			}
			current = current.AddDate(0, 0, 1)
		}
	}
	return nil
}

// BatchResolveEvents dedups by (subject, local-midnight-in-that-tz).
func (s *resolutionService) BatchResolveEvents(ctx context.Context, eventIDs []uuid.UUID) error {
	if len(eventIDs) == 0 {
		return fmt.Errorf("no event IDs provided")
	}
	type dayKey struct {
		CompanyID    uuid.UUID
		SubjectType  string
		SubjectID    uuid.UUID
		BusinessDate string // YYYY-MM-DD in the subject's tz
	}
	processed := make(map[dayKey]bool)
	for _, id := range eventIDs {
		evt, err := s.eventRepo.GetEventByID(ctx, id)
		if err != nil {
			s.logger.Error("Failed to load event in batch", zap.String("event_id", id.String()), zap.Error(err))
			continue
		}
		if evt == nil {
			continue
		}
		tz := s.resolveSubjectTz(ctx, evt.CompanyID, evt.SubjectType, evt.SubjectID, evt.EventTime)
		businessDate := util.CalendarDateInTz(evt.EventTime, tz)
		key := dayKey{
			CompanyID:    evt.CompanyID,
			SubjectType:  evt.SubjectType,
			SubjectID:    evt.SubjectID,
			BusinessDate: businessDate.Format("2006-01-02"),
		}
		if processed[key] {
			continue
		}
		processed[key] = true
		if err := s.resolveSubjectDay(ctx, evt.CompanyID, evt.SubjectID, evt.SubjectType, evt.EventTime); err != nil {
			s.logger.Error("Failed to resolve day in batch",
				zap.String("subject_type", evt.SubjectType),
				zap.String("subject_id", evt.SubjectID.String()),
				zap.Time("date", evt.EventTime),
				zap.String("tz", tz),
				zap.Error(err),
			)
		}
	}
	return nil
}

func (s *resolutionService) RecalculateDay(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, date time.Time) error {
	tz := s.resolveSubjectTz(ctx, companyID, subjectType, subjectID, date)
	normalized := util.CalendarDateInTz(date, tz)

	existing, err := s.summaryRepo.GetBySubjectDate(ctx, companyID, subjectID, subjectType, normalized)
	if err == nil && existing != nil {
		if existing.IsPayrollLocked {
			s.logger.Info("Attendance locked by payroll, skipping recalculation",
				zap.String("subject_type", subjectType),
				zap.String("subject_id", subjectID.String()),
				zap.Time("date", normalized),
				zap.String("tz", tz),
			)
			return nil
		}
		if err := s.summaryRepo.DeleteByID(ctx, existing.AttendanceSummaryID); err != nil {
			s.logger.Warn("Failed to delete existing summary", zap.String("summary_id", existing.AttendanceSummaryID.String()), zap.Error(err))
		}
	}
	return s.resolveSubjectDay(ctx, companyID, subjectID, subjectType, normalized)
}

// resolveSubjectTz uses the subject resolver first (it already walked the
// chain), falling back to the provider.
func (s *resolutionService) resolveSubjectTz(
	ctx context.Context,
	companyID uuid.UUID,
	subjectType string,
	subjectID uuid.UUID,
	refTime time.Time,
) string {
	resolved, err := s.subjectRes.Resolve(ctx, companyID, subjectType, subjectID, refTime)
	if err == nil && resolved != nil && resolved.Timezone != "" {
		return resolved.Timezone
	}
	var positionID *uuid.UUID
	var wcCode *string
	if resolved != nil {
		positionID = resolved.PositionID
		wcCode = resolved.WorkCenterCode
	}
	tz, err := s.tzProvider.ResolveTimezone(ctx, companyID, positionID, wcCode, nil)
	if err == nil && tz != "" {
		return tz
	}
	s.logger.Warn("subject tz unresolved, defaulting to UTC",
		zap.String("subject_type", subjectType),
		zap.String("subject_id", subjectID.String()),
	)
	return "UTC"
}

func (s *resolutionService) resolveSubjectDay(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, refTime time.Time) error {
	resolved, err := s.subjectRes.Resolve(ctx, companyID, subjectType, subjectID, refTime)
	if err != nil {
		return fmt.Errorf("resolve subject: %w", err)
	}
	if !resolved.IsActive {
		s.logger.Debug("Subject inactive, skipping resolution",
			zap.String("subject_type", subjectType),
			zap.String("subject_id", subjectID.String()),
		)
		return nil
	}

	tz := resolved.Timezone
	if tz == "" {
		tz, _ = s.tzProvider.ResolveTimezone(ctx, companyID, resolved.PositionID, resolved.WorkCenterCode, nil)
	}
	if tz == "" {
		tz = "UTC"
	}

	// ── CHANGED: businessDate is local midnight of the subject's tz.
	businessDate := util.CalendarDateInTz(refTime, tz)

	existingSummary, _ := s.summaryRepo.GetBySubjectDate(ctx, companyID, subjectID, subjectType, businessDate)
	if existingSummary != nil && existingSummary.IsPayrollLocked {
		s.logger.Info("Attendance locked by payroll, skipping resolution",
			zap.String("subject_type", subjectType),
			zap.String("subject_id", subjectID.String()),
			zap.Time("date", businessDate),
			zap.String("tz", tz),
		)
		return nil
	}

	// Fetch a wide UTC window that covers the local day + DST slack.
	fetchStart := businessDate.Add(-6 * time.Hour)
	fetchEnd := businessDate.Add(30 * time.Hour)

	events, err := s.eventRepo.GetEventsBySubject(ctx, companyID, subjectID, subjectType, fetchStart, fetchEnd)
	if err != nil {
		return fmt.Errorf("fetch events: %w", err)
	}

	rules, err := s.adminSvc.ResolveAttendanceRules(
		ctx,
		subjectID,
		companyID,
		subjectType,
		derefString(resolved.WorkCenterCode),
		resolved.PositionID,
		refTime,
	)
	if err != nil {
		return fmt.Errorf("resolve rules: %w", err)
	}

	return s.applyAttendanceRules(ctx, events, companyID, subjectID, subjectType, businessDate, resolved, rules, existingSummary, tz)
}

func (s *resolutionService) applyAttendanceRules(
	ctx context.Context,
	events []*models.AttendanceEvent,
	companyID, subjectID uuid.UUID,
	subjectType string,
	businessDate time.Time,
	resolved *resolver.ResolvedSubject,
	rules *models.ResolvedAttendanceRules,
	existingSummary *models.AttendanceDailySummary,
	tz string,
) error {
	subjectLocation, locErr := s.locationResolver.ResolveLocation(ctx, companyID, subjectType, subjectID)
	if locErr != nil {
		s.logger.Warn("Failed to resolve subject location, proceeding without",
			zap.String("subject_type", subjectType),
			zap.String("subject_id", subjectID.String()),
			zap.Error(locErr),
		)
		subjectLocation = nil
	}

	offsetMinutes := int16(util.OffsetMinutes(businessDate, tz))

	upsertStatus := func(status string, anomalies []string) error {
		isPayable := status != models.StatusAbsent &&
			status != models.StatusLeaveUnpaid &&
			status != models.StatusNotScheduled &&
			status != models.StatusExcused
		summary := &models.AttendanceDailySummary{
			AttendanceSummaryID:  uuid.New(),
			CompanyID:            companyID,
			SubjectType:          subjectType,
			SubjectID:            subjectID,
			EmploymentLocationID: subjectLocation,
			AttendanceDate:       businessDate,
			Timezone:             tz,
			OffsetMinutes:        offsetMinutes,
			Status:               status,
			IsPayrollLocked:      false,
			IsPayable:            isPayable,
			GeneratedAt:          time.Now().UTC(),
			GeneratedBy:          "attendance_resolution_service",
			Metadata: models.SummaryMetadata{
				ScheduleStatus: &resolved.ScheduleStatus,
				Timezone:       &tz,
				Anomalies:      anomalies,
			},
		}
		if existingSummary != nil {
			summary.AttendanceSummaryID = existingSummary.AttendanceSummaryID
		}
		return s.summaryRepo.UpsertSummary(ctx, nil, summary)
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].EventTime.Before(events[j].EventTime)
	})

	exemptions, err := s.exemptionRepo.GetActiveForSubject(ctx, nil, companyID, subjectID, subjectType, businessDate)
	if err != nil {
		s.logger.Warn("Failed to check exemptions", zap.Error(err))
	}
	if len(exemptions) > 0 {
		s.logger.Info("Subject excused via exemption",
			zap.String("subject_type", subjectType),
			zap.String("subject_id", subjectID.String()),
			zap.Time("date", businessDate),
			zap.Int("count", len(exemptions)),
		)
		return upsertStatus(models.StatusExcused, nil)
	}

	pairedEvents := s.pairCheckInCheckOut(events)

	var dayPairs []PairedEvent
	for _, pair := range pairedEvents {
		if pair.CheckInTime == nil {
			continue
		}
		checkInDate := util.CalendarDateInTz(*pair.CheckInTime, tz)
		if checkInDate.Equal(businessDate) {
			dayPairs = append(dayPairs, pair)
		}
	}

	for _, evt := range events {
		if evt.Metadata.IsCorrection != nil && *evt.Metadata.IsCorrection {
			if evt.EventType == "manual_override" && evt.Metadata.OverrideStatus != nil {
				status := *evt.Metadata.OverrideStatus
				anomalies := s.detectAnomaliesFromPairs(dayPairs, rules.AllowMultipleCheckins)
				return upsertStatus(status, anomalies)
			}
		}
	}

	if resolved.IsOnLeave {
		var status string
		if resolved.IsLeavePaid {
			status = models.StatusLeavePaid
		} else {
			status = models.StatusLeaveUnpaid
		}
		return upsertStatus(status, nil)
	}

	switch resolved.ScheduleStatus {
	case "weekly_off":
		return upsertStatus(models.StatusWeeklyOff, nil)
	case "holiday":
		return upsertStatus(models.StatusHoliday, nil)
	case "not_schedulable":
		return upsertStatus(models.StatusNotScheduled, nil)
	}

	if len(events) == 0 {
		return upsertStatus(models.StatusAbsent, nil)
	}

	anomalies := s.detectAnomaliesFromPairs(dayPairs, rules.AllowMultipleCheckins)

	policy, err := s.resolvePolicy(ctx, companyID, subjectID, subjectType, businessDate, resolved)
	if err != nil {
		s.logger.Warn("Failed to resolve policy, using default", zap.Error(err))
		policy = s.defaultPolicy()
	}

	metrics := s.calculateMetrics(dayPairs, resolved, policy, anomalies, businessDate, tz)
	status := s.determineStatus(metrics, resolved, policy)
	isPayable := status != models.StatusAbsent &&
		status != models.StatusLeaveUnpaid &&
		status != models.StatusNotScheduled &&
		status != models.StatusExcused

	summary := &models.AttendanceDailySummary{
		AttendanceSummaryID:  uuid.New(),
		CompanyID:            companyID,
		SubjectType:          subjectType,
		SubjectID:            subjectID,
		EmploymentLocationID: subjectLocation,
		AttendanceDate:       businessDate,
		Timezone:             tz,
		OffsetMinutes:        offsetMinutes,
		Status:               status,
		IsPayrollLocked:      false,
		IsPayable:            isPayable,
		WorkedMinutes:        metrics.WorkedMinutes,
		ExpectedMinutes:      metrics.ExpectedMinutes,
		OvertimeMinutes:      metrics.OvertimeMinutes,
		LateMinutes:          metrics.LateMinutes,
		GeneratedAt:          time.Now().UTC(),
		GeneratedBy:          "attendance_resolution_service",
		Metadata: models.SummaryMetadata{
			CheckInTime:    metrics.FirstCheckIn,
			CheckOutTime:   metrics.LastCheckOut,
			TotalCheckIns:  &metrics.CheckIns,
			TotalCheckOuts: &metrics.CheckOuts,
			BreakMinutes:   metrics.BreakMinutes,
			ScheduleStatus: &resolved.ScheduleStatus,
			ShiftID:        resolved.ScheduleInstanceID,
			Timezone:       &tz,
			Anomalies:      anomalies,
			PairedEvents:   convertPairedEvents(dayPairs),
			LeaveTypeID:    resolved.LeaveTypeID,
			LeaveRequestID: resolved.LeaveRequestID,
			IsLeavePaid:    &resolved.IsLeavePaid,
		},
	}
	if existingSummary != nil {
		summary.AttendanceSummaryID = existingSummary.AttendanceSummaryID
	}
	if err := s.summaryRepo.UpsertSummary(ctx, nil, summary); err != nil {
		return fmt.Errorf("upsert summary: %w", err)
	}

	s.logger.Info("Attendance summary saved",
		zap.String("subject_type", subjectType),
		zap.String("subject_id", subjectID.String()),
		zap.String("status", status),
		zap.Time("date", businessDate),
		zap.String("tz", tz),
		zap.Int("worked_minutes", intValue(metrics.WorkedMinutes)),
		zap.Int("expected_minutes", intValue(metrics.ExpectedMinutes)),
	)
	return nil
}

func (s *resolutionService) pairCheckInCheckOut(events []*models.AttendanceEvent) []PairedEvent {
	sort.Slice(events, func(i, j int) bool {
		if !events[i].EventTime.Equal(events[j].EventTime) {
			return events[i].EventTime.Before(events[j].EventTime)
		}
		prioI := s.getSourcePriority(events[i].SourceType, events[i].Metadata.IsCorrection)
		prioJ := s.getSourcePriority(events[j].SourceType, events[j].Metadata.IsCorrection)
		return prioI > prioJ
	})

	var paired []PairedEvent
	var current *PairedEvent
	for _, evt := range events {
		eventTime := evt.EventTime
		evtType := s.normalizeEventType(evt.EventType)
		switch evtType {
		case "check_in", "shift_start":
			if current != nil && current.CheckOut == nil {
				paired = append(paired, *current)
			}
			current = &PairedEvent{
				CheckIn:     evt,
				CheckInTime: &eventTime,
			}
		case "check_out", "shift_end":
			if current != nil && current.CheckOut == nil {
				current.CheckOut = evt
				current.CheckOutTime = &eventTime
				paired = append(paired, *current)
				current = nil
			} else {
				paired = append(paired, PairedEvent{
					CheckOut:     evt,
					CheckOutTime: &eventTime,
				})
			}
		case "break_start":
			if current != nil {
				current.BreakStart = &eventTime
			}
		case "break_end":
			if current != nil && current.BreakStart != nil {
				current.BreakEnd = &eventTime
			}
		}
	}
	if current != nil && current.CheckOut == nil {
		paired = append(paired, *current)
	}
	return paired
}

func (s *resolutionService) getSourcePriority(sourceType string, isCorrection *bool) int {
	if isCorrection != nil && *isCorrection {
		return 100
	}
	prio := map[string]int{
		"manual":    90,
		"biometric": 80,
		"kiosk":     60,
		"mobile":    50,
		"web":       40,
		"api":       30,
		"system":    20,
		"import":    10,
	}
	if p, ok := prio[sourceType]; ok {
		return p
	}
	return 0
}

func (s *resolutionService) normalizeEventType(t string) string {
	switch t {
	case "manual_check_in":
		return "check_in"
	case "manual_check_out":
		return "check_out"
	case "manual_shift_start":
		return "shift_start"
	case "manual_shift_end":
		return "shift_end"
	default:
		return t
	}
}

func (s *resolutionService) detectAnomaliesFromPairs(pairs []PairedEvent, allowMultiple bool) []string {
	var anomalies []string
	maxDur := time.Duration(defaultMaxShiftDurationHours) * time.Hour
	completePairs := 0
	for _, p := range pairs {
		switch {
		case p.CheckIn != nil && p.CheckOut != nil:
			completePairs++
		case p.CheckIn != nil:
			anomalies = append(anomalies, "missing_checkout")
		case p.CheckOut != nil:
			anomalies = append(anomalies, "missing_checkin")
		}
		if p.CheckInTime != nil && p.CheckOutTime != nil {
			if p.CheckOutTime.Sub(*p.CheckInTime) > maxDur {
				anomalies = append(anomalies, "excessive_shift_duration")
			}
		}
	}
	if completePairs > 1 && !allowMultiple {
		anomalies = append(anomalies, "multiple_pairs")
	}
	return anomalies
}

func (s *resolutionService) calculateMetrics(
	pairs []PairedEvent,
	resolved *resolver.ResolvedSubject,
	policy *models.AttendancePolicy,
	anomalies []string,
	businessDate time.Time,
	tz string,
) *DailyMetrics {
	metrics := &DailyMetrics{
		Status:       models.StatusPresent,
		PairedEvents: pairs,
	}

	loc, _ := time.LoadLocation(tz)
	if loc == nil {
		loc = time.UTC
	}

	var totalWorkedSec, totalBreakSec int64
	var expectedStartLocal, expectedEndLocal *time.Time
	if resolved.ExpectedStart != nil {
		t := resolved.ExpectedStart.In(loc)
		expectedStartLocal = &t
	}
	if resolved.ExpectedEnd != nil {
		t := resolved.ExpectedEnd.In(loc)
		expectedEndLocal = &t
	}
	if expectedStartLocal != nil && expectedEndLocal != nil {
		expSec := expectedEndLocal.Sub(*expectedStartLocal).Seconds()
		if expSec > 0 {
			expMin := int(expSec / 60)
			metrics.ExpectedMinutes = &expMin
		}
	}

	var earliestCheckIn, latestCheckOut *time.Time
	for _, p := range pairs {
		if p.CheckIn != nil {
			metrics.CheckIns++
			if metrics.FirstCheckIn == nil || p.CheckInTime.Before(*metrics.FirstCheckIn) {
				metrics.FirstCheckIn = p.CheckInTime
			}
			if earliestCheckIn == nil || p.CheckInTime.Before(*earliestCheckIn) {
				earliestCheckIn = p.CheckInTime
			}
		}
		if p.CheckOut != nil {
			metrics.CheckOuts++
			if metrics.LastCheckOut == nil || p.CheckOutTime.After(*metrics.LastCheckOut) {
				metrics.LastCheckOut = p.CheckOutTime
			}
			if latestCheckOut == nil || p.CheckOutTime.After(*latestCheckOut) {
				latestCheckOut = p.CheckOutTime
			}
			if p.CheckInTime != nil && p.CheckOutTime != nil {
				workDur := p.CheckOutTime.Sub(*p.CheckInTime)
				maxDur := time.Duration(defaultMaxShiftDurationHours) * time.Hour
				if workDur > maxDur {
					workDur = maxDur
				}
				totalWorkedSec += int64(workDur.Seconds())
				if p.BreakStart != nil && p.BreakEnd != nil {
					breakDur := p.BreakEnd.Sub(*p.BreakStart)
					totalBreakSec += int64(breakDur.Seconds())
				}
			}
		}
	}
	for _, p := range pairs {
		if p.CheckIn != nil && p.CheckOut == nil {
			closeTime := expectedEndLocal
			if closeTime == nil {
				endOfDay := time.Date(businessDate.Year(), businessDate.Month(), businessDate.Day(), 23, 59, 59, 0, loc)
				closeTime = &endOfDay
			}
			if p.CheckInTime != nil && closeTime != nil {
				workDur := closeTime.Sub(*p.CheckInTime)
				if workDur > 0 {
					totalWorkedSec += int64(workDur.Seconds())
				}
			}
		}
	}

	netSec := totalWorkedSec - totalBreakSec
	if netSec > 0 {
		workedMin := int(netSec / 60)
		metrics.WorkedMinutes = &workedMin
	} else {
		zero := 0
		metrics.WorkedMinutes = &zero
	}
	if totalBreakSec > 0 {
		breakMin := int(totalBreakSec / 60)
		metrics.BreakMinutes = &breakMin
	}
	if expectedStartLocal != nil && earliestCheckIn != nil {
		if earliestCheckIn.After(*expectedStartLocal) {
			lateSec := earliestCheckIn.Sub(*expectedStartLocal).Seconds()
			lateMin := int(lateSec / 60)
			if policy != nil && policy.Rules.GracePeriod != nil && lateMin <= *policy.Rules.GracePeriod {
				lateMin = 0
			}
			metrics.LateMinutes = &lateMin
		}
	}
	if metrics.LateMinutes == nil {
		zero := 0
		metrics.LateMinutes = &zero
	}
	if expectedEndLocal != nil && latestCheckOut != nil {
		if latestCheckOut.After(*expectedEndLocal) {
			otSec := latestCheckOut.Sub(*expectedEndLocal).Seconds()
			otMin := int(otSec / 60)
			if policy != nil && policy.Rules.OvertimeThreshold != nil && otMin < *policy.Rules.OvertimeThreshold {
				otMin = 0
			}
			metrics.OvertimeMinutes = &otMin
		}
	}
	if metrics.OvertimeMinutes == nil {
		zero := 0
		metrics.OvertimeMinutes = &zero
	}
	if metrics.ExpectedMinutes == nil && expectedStartLocal != nil && expectedEndLocal != nil {
		expSec := expectedEndLocal.Sub(*expectedStartLocal).Seconds()
		if expSec > 0 {
			expMin := int(expSec / 60)
			metrics.ExpectedMinutes = &expMin
		}
	}
	return metrics
}

func (s *resolutionService) determineStatus(
	metrics *DailyMetrics,
	resolved *resolver.ResolvedSubject,
	policy *models.AttendancePolicy,
) string {
	if resolved.ScheduleStatus != "" {
		switch resolved.ScheduleStatus {
		case "weekly_off":
			return models.StatusWeeklyOff
		case "holiday":
			return models.StatusHoliday
		case "on_leave":
			if resolved.IsLeavePaid {
				return models.StatusLeavePaid
			}
			return models.StatusLeaveUnpaid
		}
	}
	if metrics.CheckIns == 0 {
		return models.StatusAbsent
	}
	if metrics.LateMinutes != nil && *metrics.LateMinutes > 0 {
		if policy != nil && policy.Rules.MaxLateAllowed != nil && *metrics.LateMinutes > *policy.Rules.MaxLateAllowed {
			return models.StatusAbsent
		}
		return models.StatusLate
	}
	if policy != nil && policy.Rules.HalfDayAfter != nil && metrics.WorkedMinutes != nil && metrics.ExpectedMinutes != nil {
		if *metrics.WorkedMinutes < *policy.Rules.HalfDayAfter {
			return models.StatusHalfDay
		}
	}
	if metrics.CheckIns > 0 && metrics.CheckOuts == 0 {
		if policy != nil && policy.Rules.AutoCheckout != nil && *policy.Rules.AutoCheckout {
			if metrics.WorkedMinutes != nil && *metrics.WorkedMinutes >= 240 {
				return models.StatusPresent
			}
		}
		if metrics.WorkedMinutes != nil && *metrics.WorkedMinutes > 0 {
			return models.StatusHalfDay
		}
		return models.StatusAbsent
	}
	if metrics.WorkedMinutes != nil && *metrics.WorkedMinutes > 0 {
		return models.StatusPresent
	}
	return models.StatusAbsent
}

func (s *resolutionService) resolvePolicy(
	ctx context.Context,
	companyID, subjectID uuid.UUID,
	subjectType string,
	date time.Time,
	resolved *resolver.ResolvedSubject,
) (*models.AttendancePolicy, error) {
	policy, err := s.policyRepo.GetActivePolicyBySubject(ctx, subjectType, subjectID, date)
	if err == nil && policy != nil {
		return policy, nil
	}
	if subjectType == models.SubjectTypeEmployee {
		if resolved.PositionID != nil {
			posPolicy, err := s.policyRepo.GetPositionPolicy(ctx, *resolved.PositionID)
			if err == nil && posPolicy != nil {
				return posPolicy, nil
			}
		}
		if resolved.WorkCenterCode != nil {
			wcPolicy, err := s.policyRepo.GetWorkCenterPolicy(ctx, companyID, *resolved.WorkCenterCode)
			if err == nil && wcPolicy != nil {
				return wcPolicy, nil
			}
		}
	}
	return s.defaultPolicy(), nil
}

func (s *resolutionService) defaultPolicy() *models.AttendancePolicy {
	return &models.AttendancePolicy{
		PolicyID:   uuid.New(),
		PolicyCode: "DEFAULT",
		PolicyType: "company_default",
		Rules: models.PolicyRules{
			GracePeriod:         intPtr(15),
			MaxLateAllowed:      intPtr(60),
			HalfDayAfter:        intPtr(240),
			AutoCheckout:        boolPtr(false),
			OvertimeThreshold:   intPtr(15),
			AutoApproveOvertime: boolPtr(false),
			AllowShiftOverlap:   boolPtr(false),
		},
		IsActive: true,
	}
}

func derefString(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}

func intValue(i *int) int {
	if i == nil {
		return 0
	}
	return *i
}

func intPtr(i int) *int    { return &i }
func boolPtr(b bool) *bool { return &b }

func convertPairedEvents(pairs []PairedEvent) []models.PairedEvent {
	result := make([]models.PairedEvent, 0, len(pairs))
	for _, p := range pairs {
		pe := models.PairedEvent{
			CheckInTime:  time.Time{},
			CheckOutTime: p.CheckOutTime,
		}
		if p.CheckIn != nil {
			pe.CheckInEventID = p.CheckIn.AttendanceEventID
			pe.CheckInTime = *p.CheckInTime
		}
		if p.CheckOut != nil {
			id := p.CheckOut.AttendanceEventID
			pe.CheckOutEventID = &id
		}
		result = append(result, pe)
	}
	return result
}
