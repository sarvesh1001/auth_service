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
)

const (
	defaultMaxShiftDurationHours = 20
)

// PairedEvent represents a matched check‑in/check‑out pair (with optional breaks)
type PairedEvent struct {
	CheckIn      *models.AttendanceEvent
	CheckOut     *models.AttendanceEvent
	CheckInTime  *time.Time
	CheckOutTime *time.Time
	BreakStart   *time.Time
	BreakEnd     *time.Time
}

// DailyMetrics holds computed values for a single day
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

// ResolutionService is the core engine for turning raw events into daily summaries.
type ResolutionService interface {
	ResolveEvent(ctx context.Context, eventID uuid.UUID) error
	ResolveDay(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, date time.Time) error
	ResolvePeriod(ctx context.Context, companyID uuid.UUID, subjectIDs []uuid.UUID, subjectType string, startDate, endDate time.Time, recalculate bool) error
	BatchResolveEvents(ctx context.Context, eventIDs []uuid.UUID) error
	RecalculateDay(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, date time.Time) error
}

type resolutionService struct {
	eventRepo     repository.EventRepository
	summaryRepo   repository.SummaryRepository
	scheduleRepo  repository.ScheduleRepository
	policyRepo    repository.PolicyRepository
	subjectRes    resolver.SubjectResolver
	adminSvc      admin.AdminService
	exemptionRepo repository.AttendanceExemptionRepository
	logger        *zap.Logger
	audit         *auditservice.AuditService
}

// NewResolutionService creates a new resolution service.
func NewResolutionService(
	eventRepo repository.EventRepository,
	summaryRepo repository.SummaryRepository,
	scheduleRepo repository.ScheduleRepository,
	policyRepo repository.PolicyRepository,
	subjectRes resolver.SubjectResolver,
	adminSvc admin.AdminService,
	exemptionRepo repository.AttendanceExemptionRepository,
	logger *zap.Logger,
	audit *auditservice.AuditService,
) ResolutionService {
	return &resolutionService{
		eventRepo:     eventRepo,
		summaryRepo:   summaryRepo,
		scheduleRepo:  scheduleRepo,
		policyRepo:    policyRepo,
		subjectRes:    subjectRes,
		adminSvc:      adminSvc,
		exemptionRepo: exemptionRepo,
		logger:        logger,
		audit:         audit,
	}
}

// ─────────────────────────────────────────────────────────────
// Public methods
// ─────────────────────────────────────────────────────────────

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

	start := startDate.UTC().Truncate(24 * time.Hour)
	end := endDate.UTC().Truncate(24 * time.Hour)

	for _, subjectID := range subjectIDs {
		current := start
		for !current.After(end) {
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
					zap.Error(err),
				)
			}
			current = current.AddDate(0, 0, 1)
		}
	}
	return nil
}

func (s *resolutionService) BatchResolveEvents(ctx context.Context, eventIDs []uuid.UUID) error {
	if len(eventIDs) == 0 {
		return fmt.Errorf("no event IDs provided")
	}

	type dayKey struct {
		CompanyID    uuid.UUID
		SubjectType  string
		SubjectID    uuid.UUID
		BusinessDate time.Time
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

		key := dayKey{
			CompanyID:    evt.CompanyID,
			SubjectType:  evt.SubjectType,
			SubjectID:    evt.SubjectID,
			BusinessDate: evt.EventTime.UTC().Truncate(24 * time.Hour),
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
				zap.Error(err),
			)
		}
	}
	return nil
}

func (s *resolutionService) RecalculateDay(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, date time.Time) error {
	existing, err := s.summaryRepo.GetBySubjectDate(ctx, companyID, subjectID, subjectType, date)
	if err == nil && existing != nil {
		if existing.IsPayrollLocked {
			s.logger.Info("Attendance locked by payroll, skipping recalculation",
				zap.String("subject_type", subjectType),
				zap.String("subject_id", subjectID.String()),
				zap.Time("date", date),
			)
			return nil
		}
		if err := s.summaryRepo.DeleteByID(ctx, existing.AttendanceSummaryID); err != nil {
			s.logger.Warn("Failed to delete existing summary", zap.String("summary_id", existing.AttendanceSummaryID.String()), zap.Error(err))
		}
	}
	return s.resolveSubjectDay(ctx, companyID, subjectID, subjectType, date)
}

// ─────────────────────────────────────────────────────────────
// Internal resolution core
// ─────────────────────────────────────────────────────────────

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

	loc, err := time.LoadLocation(resolved.Timezone)
	if err != nil {
		loc = time.UTC
	}
	refLocal := refTime.In(loc)
	businessDate := time.Date(refLocal.Year(), refLocal.Month(), refLocal.Day(), 0, 0, 0, 0, loc)

	existingSummary, _ := s.summaryRepo.GetBySubjectDate(ctx, companyID, subjectID, subjectType, businessDate)
	if existingSummary != nil && existingSummary.IsPayrollLocked {
		s.logger.Info("Attendance locked by payroll, skipping resolution",
			zap.String("subject_type", subjectType),
			zap.String("subject_id", subjectID.String()),
			zap.Time("date", businessDate),
		)
		return nil
	}

	fetchStart := businessDate.Add(-6 * time.Hour)
	fetchEnd := businessDate.Add(36 * time.Hour)
	events, err := s.eventRepo.GetEventsBySubject(ctx, companyID, subjectID, subjectType, fetchStart, fetchEnd)
	if err != nil {
		return fmt.Errorf("fetch events: %w", err)
	}

	// FIX: added subjectType as 4th argument
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

	return s.applyAttendanceRules(ctx, events, companyID, subjectID, subjectType, businessDate, resolved, rules)
}

// applyAttendanceRules does the heavy lifting: exemptions, pairing, overrides, metrics, status, upsert
func (s *resolutionService) applyAttendanceRules(
	ctx context.Context,
	events []*models.AttendanceEvent,
	companyID, subjectID uuid.UUID,
	subjectType string,
	businessDate time.Time,
	resolved *resolver.ResolvedSubject,
	rules *models.ResolvedAttendanceRules,
) error {
	// ── Helper to upsert a summary with a given status and anomalies ──
	upsertStatus := func(status string, anomalies []string) error {
		isPayable := status != models.StatusAbsent &&
			status != models.StatusLeaveUnpaid &&
			status != models.StatusNotScheduled &&
			status != models.StatusExcused

		summary := &models.AttendanceDailySummary{
			AttendanceSummaryID: uuid.New(),
			CompanyID:           companyID,
			SubjectType:         subjectType,
			SubjectID:           subjectID,
			AttendanceDate:      businessDate,
			Status:              status,
			IsPayrollLocked:     false,
			IsPayable:           isPayable,
			GeneratedAt:         time.Now().UTC(),
			GeneratedBy:         "attendance_resolution_service",
			Metadata: models.SummaryMetadata{
				ScheduleStatus: &resolved.ScheduleStatus,
				Timezone:       &resolved.Timezone,
				Anomalies:      anomalies,
			},
		}

		if existing, _ := s.summaryRepo.GetBySubjectDate(ctx, companyID, subjectID, subjectType, businessDate); existing != nil {
			summary.AttendanceSummaryID = existing.AttendanceSummaryID
		}

		return s.summaryRepo.UpsertSummary(ctx, nil, summary)
	}

	// 1. Sort events chronologically
	sort.Slice(events, func(i, j int) bool {
		return events[i].EventTime.Before(events[j].EventTime)
	})

	// 2. Check exemptions
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

	// 3. Pair check‑in/out
	pairedEvents := s.pairCheckInCheckOut(events)

	// 4. Filter pairs belonging to this business date
	loc, _ := time.LoadLocation(resolved.Timezone)
	if loc == nil {
		loc = time.UTC
	}
	var dayPairs []PairedEvent
	for _, pair := range pairedEvents {
		if pair.CheckInTime == nil {
			continue
		}
		checkInLocal := pair.CheckInTime.In(loc)
		checkInDate := time.Date(checkInLocal.Year(), checkInLocal.Month(), checkInLocal.Day(), 0, 0, 0, 0, loc)
		if checkInDate.Equal(businessDate) {
			dayPairs = append(dayPairs, pair)
		}
	}

	// 5. Manual overrides (highest priority)
	for _, evt := range events {
		if evt.Metadata.IsCorrection != nil && *evt.Metadata.IsCorrection {
			if evt.EventType == "manual_override" && evt.Metadata.OverrideStatus != nil {
				status := *evt.Metadata.OverrideStatus
				anomalies := s.detectAnomaliesFromPairs(dayPairs)
				return upsertStatus(status, anomalies)
			}
		}
	}

	// 6. Schedule overrides (leave, holiday, weekly off)
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

	// 7. If no events → absent
	if len(events) == 0 {
		return upsertStatus(models.StatusAbsent, nil)
	}

	// 8. Detect anomalies (informational only)
	anomalies := s.detectAnomaliesFromPairs(dayPairs)

	// 9. Resolve policy
	policy, err := s.resolvePolicy(ctx, companyID, subjectID, subjectType, businessDate, resolved)
	if err != nil {
		s.logger.Warn("Failed to resolve policy, using default", zap.Error(err))
		policy = s.defaultPolicy()
	}

	// 10. Compute metrics (pass businessDate for end-of-day fallback)
	metrics := s.calculateMetrics(dayPairs, resolved, policy, anomalies, businessDate)

	// 11. Determine final status
	status := s.determineStatus(metrics, resolved, policy)

	// 12. Build and upsert summary
	isPayable := status != models.StatusAbsent &&
		status != models.StatusLeaveUnpaid &&
		status != models.StatusNotScheduled &&
		status != models.StatusExcused

	summary := &models.AttendanceDailySummary{
		AttendanceSummaryID: uuid.New(),
		CompanyID:           companyID,
		SubjectType:         subjectType,
		SubjectID:           subjectID,
		AttendanceDate:      businessDate,
		Status:              status,
		IsPayrollLocked:     false,
		IsPayable:           isPayable,
		WorkedMinutes:       metrics.WorkedMinutes,
		ExpectedMinutes:     metrics.ExpectedMinutes,
		OvertimeMinutes:     metrics.OvertimeMinutes,
		LateMinutes:         metrics.LateMinutes,
		GeneratedAt:         time.Now().UTC(),
		GeneratedBy:         "attendance_resolution_service",
		Metadata: models.SummaryMetadata{
			CheckInTime:    metrics.FirstCheckIn,
			CheckOutTime:   metrics.LastCheckOut,
			TotalCheckIns:  &metrics.CheckIns,
			TotalCheckOuts: &metrics.CheckOuts,
			BreakMinutes:   metrics.BreakMinutes,
			ScheduleStatus: &resolved.ScheduleStatus,
			ShiftID:        resolved.ScheduleInstanceID,
			Timezone:       &resolved.Timezone,
			Anomalies:      anomalies,
			PairedEvents:   convertPairedEvents(dayPairs),
			LeaveTypeID:    resolved.LeaveTypeID,
			LeaveRequestID: resolved.LeaveRequestID,
			IsLeavePaid:    &resolved.IsLeavePaid,
		},
	}

	if existing, _ := s.summaryRepo.GetBySubjectDate(ctx, companyID, subjectID, subjectType, businessDate); existing != nil {
		summary.AttendanceSummaryID = existing.AttendanceSummaryID
	}

	if err := s.summaryRepo.UpsertSummary(ctx, nil, summary); err != nil {
		return fmt.Errorf("upsert summary: %w", err)
	}

	s.logger.Info("Attendance summary saved",
		zap.String("subject_type", subjectType),
		zap.String("subject_id", subjectID.String()),
		zap.String("status", status),
		zap.Time("date", businessDate),
		zap.Int("worked_minutes", intValue(metrics.WorkedMinutes)),
		zap.Int("expected_minutes", intValue(metrics.ExpectedMinutes)),
	)
	return nil
}

// ─────────────────────────────────────────────────────────────
// Helper methods
// ─────────────────────────────────────────────────────────────

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

func (s *resolutionService) detectAnomaliesFromPairs(pairs []PairedEvent) []string {
	var anomalies []string
	checkIns, checkOuts := 0, 0
	maxDur := time.Duration(defaultMaxShiftDurationHours) * time.Hour

	for _, p := range pairs {
		if p.CheckIn != nil {
			checkIns++
		}
		if p.CheckOut != nil {
			checkOuts++
		}
		if p.CheckIn != nil && p.CheckOut == nil {
			anomalies = append(anomalies, "missing_checkout")
		}
		if p.CheckIn == nil && p.CheckOut != nil {
			anomalies = append(anomalies, "missing_checkin")
		}
		if p.CheckInTime != nil && p.CheckOutTime != nil {
			if p.CheckOutTime.Sub(*p.CheckInTime) > maxDur {
				anomalies = append(anomalies, "excessive_shift_duration")
			}
		}
	}
	if checkIns > 1 || checkOuts > 1 {
		anomalies = append(anomalies, "multiple_pairs")
	}
	return anomalies
}

// calculateMetrics computes worked minutes, late, overtime, etc. from all pairs.
// It uses the earliest check-in for late minutes and latest check-out for overtime.
// Unmatched check-ins are closed at expected end (or end of day).
func (s *resolutionService) calculateMetrics(
	pairs []PairedEvent,
	resolved *resolver.ResolvedSubject,
	policy *models.AttendancePolicy,
	anomalies []string,
	businessDate time.Time, // added to avoid using resolved.Date
) *DailyMetrics {
	metrics := &DailyMetrics{
		Status:       models.StatusPresent,
		PairedEvents: pairs,
	}

	loc, _ := time.LoadLocation(resolved.Timezone)
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

	// Handle unmatched check-ins (no checkout): close them at expected end (or end-of-day)
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

	// Late minutes: earliest check-in compared to expected start
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

	// Overtime: latest checkout compared to expected end
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

// determineStatus decides final status using metrics, resolved subject, and policy.
func (s *resolutionService) determineStatus(
	metrics *DailyMetrics,
	resolved *resolver.ResolvedSubject,
	policy *models.AttendancePolicy,
) string {
	// Respect schedule overrides (already handled earlier, but double-check)
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

	// No check-ins → absent
	if metrics.CheckIns == 0 {
		return models.StatusAbsent
	}

	// Late logic
	if metrics.LateMinutes != nil && *metrics.LateMinutes > 0 {
		if policy != nil && policy.Rules.MaxLateAllowed != nil && *metrics.LateMinutes > *policy.Rules.MaxLateAllowed {
			return models.StatusAbsent
		}
		return models.StatusLate
	}

	// Half-day: if worked < half-day threshold (and policy has threshold)
	if policy != nil && policy.Rules.HalfDayAfter != nil && metrics.WorkedMinutes != nil && metrics.ExpectedMinutes != nil {
		if *metrics.WorkedMinutes < *policy.Rules.HalfDayAfter {
			return models.StatusHalfDay
		}
	}

	// If there is at least one check-in, but no check-outs, and auto-checkout is allowed
	if metrics.CheckIns > 0 && metrics.CheckOuts == 0 {
		if policy != nil && policy.Rules.AutoCheckout != nil && *policy.Rules.AutoCheckout {
			if metrics.WorkedMinutes != nil && *metrics.WorkedMinutes >= 240 { // 4 hours minimum to be considered present
				return models.StatusPresent
			}
		}
		// Otherwise, it's a half-day or absent (if no work)
		if metrics.WorkedMinutes != nil && *metrics.WorkedMinutes > 0 {
			return models.StatusHalfDay
		}
		return models.StatusAbsent
	}

	// If some work was done, mark present
	if metrics.WorkedMinutes != nil && *metrics.WorkedMinutes > 0 {
		return models.StatusPresent
	}

	// Fallback
	return models.StatusAbsent
}

func (s *resolutionService) resolvePolicy(
	ctx context.Context,
	companyID, subjectID uuid.UUID,
	subjectType string,
	date time.Time,
	resolved *resolver.ResolvedSubject,
) (*models.AttendancePolicy, error) {
	// 1. Try subject-specific policy (polymorphic – works for any subject type)
	policy, err := s.policyRepo.GetActivePolicyBySubject(ctx, subjectType, subjectID, date)
	if err == nil && policy != nil {
		return policy, nil
	}

	// 2. For employees only, fallback to position/work center policies (legacy)
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

// ─────────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────────

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

func intPtr(i int) *int {
	return &i
}

func boolPtr(b bool) *bool {
	return &b
}

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
