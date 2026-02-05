package service

import (
	"context"
	"fmt"
	"sort"
	"time"

	"auth-service/internal/hr/models/attendance"
	"auth-service/internal/hr/repository"

	attconstants "auth-service/internal/hr/models/attendance"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ============================================
// INTERFACES
// ============================================

type AttendanceResolutionService interface {
	ResolveEvent(
		ctx context.Context,
		eventID uuid.UUID,
	) error

	ResolveDay(
		ctx context.Context,
		companyID, userID uuid.UUID,
		date time.Time,
	) error

	BatchResolveEvents(
		ctx context.Context,
		eventIDs []uuid.UUID,
	) error

	RecalculateDay(
		ctx context.Context,
		companyID, userID uuid.UUID,
		date time.Time,
	) error
}

// ============================================
// HELPER TYPES
// ============================================

type PairedEvent struct {
	CheckIn      *attendance.AttendanceEvent
	CheckOut     *attendance.AttendanceEvent
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
	CheckIns        int
	CheckOuts       int
	FirstCheckIn    *time.Time
	LastCheckOut    *time.Time
	Status          string
	PairedEvents    []PairedEvent
}

// ============================================
// MAIN SERVICE IMPLEMENTATION WITH AUDIT LOGS
// ============================================

type attendanceResolutionService struct {
	attendanceRepo repository.AttendanceRepository
	schedulingQS   SchedulingQueryService
	schedulingQSA  SchedulingService
	auditService   *AuditService
	logger         *zap.Logger
}

func NewAttendanceResolutionService(
	attendanceRepo repository.AttendanceRepository,
	schedulingQS SchedulingQueryService,
	schedulingQSA SchedulingService,
	auditService *AuditService,
	logger *zap.Logger,
) AttendanceResolutionService {
	return &attendanceResolutionService{
		attendanceRepo: attendanceRepo,
		schedulingQS:   schedulingQS,
		schedulingQSA:  schedulingQSA,
		auditService:   auditService,
		logger:         logger,
	}
}

// ============================================
// PUBLIC METHODS WITH AUDIT LOGS
// ============================================

func (s *attendanceResolutionService) ResolveEvent(
	ctx context.Context,
	eventID uuid.UUID,
) error {
	startTime := time.Now()

	// 🎯 Initialize audit metadata
	auditMetadata := map[string]interface{}{
		"event_id":  eventID.String(),
		"operation": "resolve_event",
	}

	if eventID == uuid.Nil {
		err := fmt.Errorf("eventID is required")
		if s.auditService != nil {
			auditMetadata["error"] = err.Error()
			s.auditService.LogAction(ctx,
				nil,
				"attendance",
				"resolution.event.invalid",
				"attendance_event",
				&eventID,
				"system",
				nil,
				nil,
				nil,
				auditMetadata,
			)
		}
		return err
	}

	// Load the event
	event, err := s.attendanceRepo.GetAttendanceEventByID(ctx, eventID)
	if err != nil {
		if s.auditService != nil {
			auditMetadata["error"] = err.Error()
			s.auditService.LogAction(ctx,
				nil,
				"attendance",
				"resolution.event.load_failed",
				"attendance_event",
				&eventID,
				"system",
				nil,
				nil,
				nil,
				auditMetadata,
			)
		}
		return fmt.Errorf("failed to load attendance event: %w", err)
	}
	if event == nil {
		err := fmt.Errorf("attendance event not found")
		if s.auditService != nil {
			auditMetadata["error"] = err.Error()
			s.auditService.LogAction(ctx,
				nil,
				"attendance",
				"resolution.event.not_found",
				"attendance_event",
				&eventID,
				"system",
				nil,
				nil,
				nil,
				auditMetadata,
			)
		}
		return err
	}

	// 🎯 Log event loaded
	if s.auditService != nil {
		auditMetadata["user_id"] = event.UserID.String()
		auditMetadata["company_id"] = event.CompanyID.String()
		auditMetadata["event_type"] = event.EventType
		s.auditService.LogAction(ctx,
			&event.CompanyID,
			"attendance",
			"resolution.event.loaded",
			"attendance_event",
			&eventID,
			"system",
			nil,
			nil,
			nil,
			auditMetadata,
		)
	}

	// Get shift information for timezone
	shift, err := s.resolveShift(ctx, event.CompanyID, event.UserID, event.EventTime)
	if err != nil {
		s.logger.Warn("Failed to resolve shift for event",
			zap.String("event_id", eventID.String()),
			zap.String("user_id", event.UserID.String()),
			zap.Error(err),
		)
		shift = &ShiftContext{
			ScheduleDate:   event.EventTime,
			ScheduleStatus: "unknown",
			Timezone:       "UTC", // Default fallback
		}

		// 🎯 Log shift resolution failure
		if s.auditService != nil {
			auditMetadata["shift_resolution_error"] = err.Error()
			auditMetadata["timezone_fallback"] = "UTC"
			s.auditService.LogAction(ctx,
				&event.CompanyID,
				"attendance",
				"resolution.event.shift_fallback",
				"user",
				&event.UserID,
				"system",
				nil,
				nil,
				nil,
				auditMetadata,
			)
		}
	}

	// 🔴 FIX 1: TIMEZONE BUG - Truncate in business timezone, not UTC
	loc, err := time.LoadLocation(shift.Timezone)
	if err != nil {
		s.logger.Warn("Failed to load timezone, using UTC",
			zap.String("timezone", shift.Timezone),
			zap.Error(err),
		)
		loc = time.UTC

		// 🎯 Log timezone load failure
		if s.auditService != nil {
			auditMetadata["timezone_load_error"] = err.Error()
			s.auditService.LogAction(ctx,
				&event.CompanyID,
				"attendance",
				"resolution.event.timezone_fallback",
				"user",
				&event.UserID,
				"system",
				nil,
				nil,
				nil,
				auditMetadata,
			)
		}
	}

	// Convert event time to business timezone and extract date
	eventTimeInLoc := event.EventTime.In(loc)
	businessDate := time.Date(
		eventTimeInLoc.Year(),
		eventTimeInLoc.Month(),
		eventTimeInLoc.Day(),
		0, 0, 0, 0,
		loc,
	)

	// ✅ NEW PAYROLL LOCK CHECK
	existingSummary, _ := s.attendanceRepo.GetAttendanceDailySummaryByUserDate(
		ctx, event.UserID, businessDate,
	)
	if existingSummary != nil && existingSummary.IsPayrollLocked {
		s.logger.Info("Attendance locked by payroll, skipping resolution",
			zap.String("user_id", event.UserID.String()),
			zap.Time("date", businessDate),
		)

		// 🎯 Log payroll lock
		if s.auditService != nil {
			auditMetadata["payroll_locked"] = true
			auditMetadata["summary_id"] = existingSummary.AttendanceSummaryID.String()
			auditMetadata["business_date"] = businessDate.Format("2006-01-02")
			s.auditService.LogAction(ctx,
				&event.CompanyID,
				"attendance",
				"resolution.event.payroll_locked",
				"attendance_summary",
				&existingSummary.AttendanceSummaryID,
				"system",
				nil,
				nil,
				nil,
				auditMetadata,
			)
		}
		return nil
	}

	// 🔴 FIX 3: IDEMPOTENCY - Check if already resolved
	if existingSummary != nil && existingSummary.GeneratedBy == "attendance_resolution_service" {
		// Already resolved by our service, skip unless forced
		s.logger.Debug("Day already resolved, skipping",
			zap.String("user_id", event.UserID.String()),
			zap.Time("business_date", businessDate),
		)

		// 🎯 Log already resolved
		if s.auditService != nil {
			auditMetadata["already_resolved"] = true
			auditMetadata["summary_id"] = existingSummary.AttendanceSummaryID.String()
			s.auditService.LogAction(ctx,
				&event.CompanyID,
				"attendance",
				"resolution.event.already_resolved",
				"attendance_summary",
				&existingSummary.AttendanceSummaryID,
				"system",
				nil,
				nil,
				nil,
				auditMetadata,
			)
		}
		return nil
	}

	// 🔴 FIX 2: EVENT FETCH WINDOW - Capture overnight shifts
	// Fetch events from 6 hours before to 36 hours after business date
	fetchStart := businessDate.Add(-6 * time.Hour)
	fetchEnd := businessDate.Add(36 * time.Hour)

	events, err := s.attendanceRepo.GetAttendanceEventsByUser(
		ctx,
		event.UserID,
		fetchStart,
		fetchEnd,
		0, // no limit
	)
	if err != nil {
		if s.auditService != nil {
			auditMetadata["error"] = err.Error()
			s.auditService.LogAction(ctx,
				&event.CompanyID,
				"attendance",
				"resolution.event.fetch_events_failed",
				"user",
				&event.UserID,
				"system",
				nil,
				nil,
				nil,
				auditMetadata,
			)
		}
		return fmt.Errorf("failed to get user events for date: %w", err)
	}

	// Filter events to only include those that belong to this business date
	var filteredEvents []*attendance.AttendanceEvent
	for _, evt := range events {
		// Convert each event to business timezone to check date
		evtTimeInLoc := evt.EventTime.In(loc)
		evtBusinessDate := time.Date(
			evtTimeInLoc.Year(),
			evtTimeInLoc.Month(),
			evtTimeInLoc.Day(),
			0, 0, 0, 0,
			loc,
		)
		if evtBusinessDate.Equal(businessDate) {
			filteredEvents = append(filteredEvents, evt)
		}
	}

	// 🎯 Log event filtering
	if s.auditService != nil {
		auditMetadata["total_events"] = len(events)
		auditMetadata["filtered_events"] = len(filteredEvents)
		auditMetadata["fetch_window_start"] = fetchStart.Format(time.RFC3339)
		auditMetadata["fetch_window_end"] = fetchEnd.Format(time.RFC3339)
		s.auditService.LogAction(ctx,
			&event.CompanyID,
			"attendance",
			"resolution.event.filtered",
			"user",
			&event.UserID,
			"system",
			nil,
			nil,
			nil,
			auditMetadata,
		)
	}

	// Apply attendance rules
	err = s.applyAttendanceRules(ctx, filteredEvents, event.CompanyID, event.UserID, businessDate, shift)
	if err != nil {
		if s.auditService != nil {
			auditMetadata["error"] = err.Error()
			auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
			s.auditService.LogAction(ctx,
				&event.CompanyID,
				"attendance",
				"resolution.event.rules_failed",
				"user",
				&event.UserID,
				"system",
				nil,
				nil,
				nil,
				auditMetadata,
			)
		}
		return fmt.Errorf("failed to apply attendance rules: %w", err)
	}

	// 🎯 Log successful resolution
	if s.auditService != nil {
		auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
		s.auditService.LogAction(ctx,
			&event.CompanyID,
			"attendance",
			"resolution.event.completed",
			"user",
			&event.UserID,
			"system",
			nil,
			nil,
			nil,
			auditMetadata,
		)
	}

	s.logger.Info("Attendance event resolved",
		zap.String("event_id", eventID.String()),
		zap.String("user_id", event.UserID.String()),
		zap.Time("business_date", businessDate),
		zap.String("timezone", shift.Timezone),
		zap.String("event_type", event.EventType),
	)

	return nil
}

func (s *attendanceResolutionService) ResolveDay(
	ctx context.Context,
	companyID, userID uuid.UUID,
	date time.Time,
) error {
	startTime := time.Now()

	// 🎯 Initialize audit metadata
	auditMetadata := map[string]interface{}{
		"user_id":    userID.String(),
		"company_id": companyID.String(),
		"date":       date.Format("2006-01-02"),
		"operation":  "resolve_day",
	}

	// Get shift information for timezone
	shift, err := s.resolveShift(ctx, companyID, userID, date)
	if err != nil {
		s.logger.Warn("Failed to resolve shift for day",
			zap.String("user_id", userID.String()),
			zap.Time("date", date),
			zap.Error(err),
		)
		shift = &ShiftContext{
			ScheduleDate:   date,
			ScheduleStatus: "unknown",
			Timezone:       "UTC",
		}

		// 🎯 Log shift resolution failure
		if s.auditService != nil {
			auditMetadata["shift_resolution_error"] = err.Error()
			s.auditService.LogAction(ctx,
				&companyID,
				"attendance",
				"resolution.day.shift_fallback",
				"user",
				&userID,
				"system",
				nil,
				nil,
				nil,
				auditMetadata,
			)
		}
	}

	// 🔴 FIX 1: TIMEZONE BUG - Truncate in business timezone
	loc, err := time.LoadLocation(shift.Timezone)
	if err != nil {
		loc = time.UTC
		// 🎯 Log timezone load failure
		if s.auditService != nil {
			auditMetadata["timezone_load_error"] = err.Error()
			s.auditService.LogAction(ctx,
				&companyID,
				"attendance",
				"resolution.day.timezone_fallback",
				"user",
				&userID,
				"system",
				nil,
				nil,
				nil,
				auditMetadata,
			)
		}
	}

	dateInLoc := date.In(loc)
	businessDate := time.Date(
		dateInLoc.Year(),
		dateInLoc.Month(),
		dateInLoc.Day(),
		0, 0, 0, 0,
		loc,
	)

	// 🔴 FIX 2: EVENT FETCH WINDOW
	fetchStart := businessDate.Add(-6 * time.Hour)
	fetchEnd := businessDate.Add(36 * time.Hour)

	events, err := s.attendanceRepo.GetAttendanceEventsByUser(
		ctx,
		userID,
		fetchStart,
		fetchEnd,
		0,
	)
	if err != nil {
		if s.auditService != nil {
			auditMetadata["error"] = err.Error()
			auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
			s.auditService.LogAction(ctx,
				&companyID,
				"attendance",
				"resolution.day.fetch_events_failed",
				"user",
				&userID,
				"system",
				nil,
				nil,
				nil,
				auditMetadata,
			)
		}
		return fmt.Errorf("failed to get user events for date: %w", err)
	}

	// Filter to business date
	var filteredEvents []*attendance.AttendanceEvent
	for _, evt := range events {
		evtTimeInLoc := evt.EventTime.In(loc)
		evtBusinessDate := time.Date(
			evtTimeInLoc.Year(),
			evtTimeInLoc.Month(),
			evtTimeInLoc.Day(),
			0, 0, 0, 0,
			loc,
		)
		if evtBusinessDate.Equal(businessDate) {
			filteredEvents = append(filteredEvents, evt)
		}
	}

	// 🎯 Log event statistics
	if s.auditService != nil {
		auditMetadata["total_events"] = len(events)
		auditMetadata["filtered_events"] = len(filteredEvents)
		s.auditService.LogAction(ctx,
			&companyID,
			"attendance",
			"resolution.day.events_loaded",
			"user",
			&userID,
			"system",
			nil,
			nil,
			nil,
			auditMetadata,
		)
	}

	err = s.applyAttendanceRules(ctx, filteredEvents, companyID, userID, businessDate, shift)
	if err != nil {
		if s.auditService != nil {
			auditMetadata["error"] = err.Error()
			auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
			s.auditService.LogAction(ctx,
				&companyID,
				"attendance",
				"resolution.day.rules_failed",
				"user",
				&userID,
				"system",
				nil,
				nil,
				nil,
				auditMetadata,
			)
		}
		return err
	}

	// 🎯 Log successful resolution
	if s.auditService != nil {
		auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
		s.auditService.LogAction(ctx,
			&companyID,
			"attendance",
			"resolution.day.completed",
			"user",
			&userID,
			"system",
			nil,
			nil,
			nil,
			auditMetadata,
		)
	}

	return nil
}

func (s *attendanceResolutionService) BatchResolveEvents(
	ctx context.Context,
	eventIDs []uuid.UUID,
) error {
	startTime := time.Now()

	if len(eventIDs) == 0 {
		return fmt.Errorf("no event IDs provided")
	}

	// 🎯 Log batch start
	auditMetadata := map[string]interface{}{
		"event_count": len(eventIDs),
		"operation":   "batch_resolve_events",
	}
	if s.auditService != nil {
		s.auditService.LogAction(ctx,
			nil,
			"attendance",
			"resolution.batch.start",
			"batch_operation",
			nil,
			"system",
			nil,
			nil,
			nil,
			auditMetadata,
		)
	}

	// Group by (user, business_date) to avoid duplicate processing
	type userDateKey struct {
		UserID       uuid.UUID
		CompanyID    uuid.UUID
		BusinessDate time.Time
		Timezone     string
	}

	processedDays := make(map[userDateKey]struct{})
	processedCount := 0
	skippedCount := 0

	for _, eventID := range eventIDs {
		event, err := s.attendanceRepo.GetAttendanceEventByID(ctx, eventID)
		if err != nil {
			s.logger.Error("Failed to load event in batch",
				zap.String("event_id", eventID.String()),
				zap.Error(err),
			)
			continue
		}
		if event == nil {
			continue
		}

		// Get shift for timezone
		shift, err := s.resolveShift(ctx, event.CompanyID, event.UserID, event.EventTime)
		if err != nil {
			s.logger.Warn("Failed to resolve shift, using UTC",
				zap.String("event_id", eventID.String()),
				zap.Error(err),
			)
			shift = &ShiftContext{Timezone: "UTC"}
		}

		// Calculate business date
		loc, _ := time.LoadLocation(shift.Timezone)
		if loc == nil {
			loc = time.UTC
		}

		eventTimeInLoc := event.EventTime.In(loc)
		businessDate := time.Date(
			eventTimeInLoc.Year(),
			eventTimeInLoc.Month(),
			eventTimeInLoc.Day(),
			0, 0, 0, 0,
			loc,
		)

		// ✅ NEW PAYROLL LOCK CHECK for batch processing
		existingSummary, _ := s.attendanceRepo.GetAttendanceDailySummaryByUserDate(
			ctx, event.UserID, businessDate,
		)
		if existingSummary != nil && existingSummary.IsPayrollLocked {
			s.logger.Info("Attendance locked by payroll, skipping resolution in batch",
				zap.String("user_id", event.UserID.String()),
				zap.Time("date", businessDate),
			)
			skippedCount++
			continue
		}

		key := userDateKey{
			UserID:       event.UserID,
			CompanyID:    event.CompanyID,
			BusinessDate: businessDate,
			Timezone:     shift.Timezone,
		}

		if _, exists := processedDays[key]; !exists {
			processedDays[key] = struct{}{}
			if err := s.ResolveDay(ctx, event.CompanyID, event.UserID, businessDate); err != nil {
				s.logger.Error("Failed to resolve day in batch",
					zap.String("user_id", event.UserID.String()),
					zap.Time("business_date", businessDate),
					zap.Error(err),
				)
			} else {
				processedCount++
			}
		} else {
			skippedCount++
		}
	}

	// 🎯 Log batch completion
	if s.auditService != nil {
		auditMetadata["processed_days"] = processedCount
		auditMetadata["skipped_days"] = skippedCount
		auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
		s.auditService.LogAction(ctx,
			nil,
			"attendance",
			"resolution.batch.completed",
			"batch_operation",
			nil,
			"system",
			nil,
			nil,
			nil,
			auditMetadata,
		)
	}

	return nil
}

func (s *attendanceResolutionService) RecalculateDay(
	ctx context.Context,
	companyID, userID uuid.UUID,
	date time.Time,
) error {
	startTime := time.Now()

	// 🎯 Initialize audit metadata
	auditMetadata := map[string]interface{}{
		"user_id":    userID.String(),
		"company_id": companyID.String(),
		"date":       date.Format("2006-01-02"),
		"operation":  "recalculate_day",
	}

	// Get shift for timezone
	shift, err := s.resolveShift(ctx, companyID, userID, date)
	if err != nil {
		shift = &ShiftContext{Timezone: "UTC"}

		// 🎯 Log shift resolution failure
		if s.auditService != nil {
			auditMetadata["shift_resolution_error"] = err.Error()
			s.auditService.LogAction(ctx,
				&companyID,
				"attendance",
				"recalculation.day.shift_fallback",
				"user",
				&userID,
				"system",
				nil,
				nil,
				nil,
				auditMetadata,
			)
		}
	}

	// Calculate business date
	loc, _ := time.LoadLocation(shift.Timezone)
	if loc == nil {
		loc = time.UTC
	}

	dateInLoc := date.In(loc)
	businessDate := time.Date(
		dateInLoc.Year(),
		dateInLoc.Month(),
		dateInLoc.Day(),
		0, 0, 0, 0,
		loc,
	)

	// ✅ NEW PAYROLL LOCK CHECK
	existingSummary, err := s.attendanceRepo.GetAttendanceDailySummaryByUserDate(ctx, userID, businessDate)
	if err == nil && existingSummary != nil {
		if existingSummary.IsPayrollLocked {
			s.logger.Info("Attendance locked by payroll, skipping recalculation",
				zap.String("user_id", userID.String()),
				zap.Time("business_date", businessDate),
			)

			// 🎯 Log payroll lock
			if s.auditService != nil {
				auditMetadata["payroll_locked"] = true
				auditMetadata["summary_id"] = existingSummary.AttendanceSummaryID.String()
				auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
				s.auditService.LogAction(ctx,
					&companyID,
					"attendance",
					"recalculation.day.payroll_locked",
					"attendance_summary",
					&existingSummary.AttendanceSummaryID,
					"system",
					nil,
					nil,
					nil,
					auditMetadata,
				)
			}
			return nil
		}

		// Delete existing summary if not payroll locked
		if err := s.attendanceRepo.DeleteAttendanceDailySummary(ctx, existingSummary.AttendanceSummaryID); err != nil {
			s.logger.Warn("Failed to delete existing summary",
				zap.String("summary_id", existingSummary.AttendanceSummaryID.String()),
				zap.Error(err),
			)

			// 🎯 Log deletion failure
			if s.auditService != nil {
				auditMetadata["delete_summary_error"] = err.Error()
				s.auditService.LogAction(ctx,
					&companyID,
					"attendance",
					"recalculation.day.delete_failed",
					"attendance_summary",
					&existingSummary.AttendanceSummaryID,
					"system",
					nil,
					nil,
					nil,
					auditMetadata,
				)
			}
		} else {
			// 🎯 Log successful deletion
			if s.auditService != nil {
				auditMetadata["summary_deleted"] = true
				s.auditService.LogAction(ctx,
					&companyID,
					"attendance",
					"recalculation.day.deleted",
					"attendance_summary",
					&existingSummary.AttendanceSummaryID,
					"system",
					nil,
					nil,
					nil,
					auditMetadata,
				)
			}
		}
	}

	// 🎯 Log recalculation start
	if s.auditService != nil {
		s.auditService.LogAction(ctx,
			&companyID,
			"attendance",
			"recalculation.day.start",
			"user",
			&userID,
			"system",
			nil,
			nil,
			nil,
			auditMetadata,
		)
	}

	// Resolve the day
	err = s.ResolveDay(ctx, companyID, userID, date)

	// 🎯 Log recalculation completion
	if s.auditService != nil {
		if err != nil {
			auditMetadata["error"] = err.Error()
		}
		auditMetadata["duration_ms"] = time.Since(startTime).Milliseconds()
		s.auditService.LogAction(ctx,
			&companyID,
			"attendance",
			"recalculation.day.completed",
			"user",
			&userID,
			"system",
			nil,
			nil,
			nil,
			auditMetadata,
		)
	}

	return err
}

// ============================================
// CORE LOGIC - applyAttendanceRules WITH AUDIT LOGS
// ============================================
func (s *attendanceResolutionService) applyAttendanceRules(
	ctx context.Context,
	events []*attendance.AttendanceEvent,
	companyID, userID uuid.UUID,
	businessDate time.Time,
	shift *ShiftContext,
) error {
	// 🎯 Initialize audit metadata for rule application
	auditMetadata := map[string]interface{}{
		"user_id":         userID.String(),
		"company_id":      companyID.String(),
		"business_date":   businessDate.Format("2006-01-02"),
		"event_count":     len(events),
		"timezone":        shift.Timezone,
		"schedule_status": shift.ScheduleStatus,
	}

	// 🎯 Log rule application start
	if s.auditService != nil {
		s.auditService.LogAction(ctx,
			&companyID,
			"attendance",
			"rules.apply.start",
			"user",
			&userID,
			"system",
			nil,
			nil,
			nil,
			auditMetadata,
		)
	}

	// 🔴 FIX 4.2: STATUS UPSERT HELPER (define BEFORE usage)
	upsertStatus := func(status string, anomalies []string) error {
		summary := &attendance.AttendanceDailySummary{
			AttendanceSummaryID: uuid.New(),
			CompanyID:           companyID,
			UserID:              userID,
			AttendanceDate:      businessDate,
			Status:              status,
			IsPayrollLocked:     false, // ✅ Always false when created by resolution service
			GeneratedAt:         time.Now().UTC(),
			GeneratedBy:         "attendance_resolution_service",
			Metadata: attendance.SummaryMetadata{
				ScheduleStatus: &shift.ScheduleStatus,
				Timezone:       &shift.Timezone,
				Anomalies:      anomalies,
			},
		}

		// Preserve existing ID if present
		if existing, err := s.attendanceRepo.
			GetAttendanceDailySummaryByUserDate(ctx, userID, businessDate); err == nil && existing != nil {
			summary.AttendanceSummaryID = existing.AttendanceSummaryID
			auditMetadata["existing_summary_id"] = existing.AttendanceSummaryID.String()
		}

		// 🎯 Log before upsert
		if s.auditService != nil {
			upsertMetadata := map[string]interface{}{
				"user_id":       userID.String(),
				"business_date": businessDate.Format("2006-01-02"),
				"status":        status,
				"anomalies":     anomalies,
				"summary_id":    summary.AttendanceSummaryID.String(),
			}
			s.auditService.LogAction(ctx,
				&companyID,
				"attendance",
				"rules.upsert.before",
				"attendance_summary",
				&summary.AttendanceSummaryID,
				"system",
				nil,
				nil,
				nil,
				upsertMetadata,
			)
		}

		err := s.attendanceRepo.UpsertAttendanceDailySummary(ctx, summary)

		// 🎯 Log after upsert
		if s.auditService != nil {
			upsertMetadata := map[string]interface{}{
				"user_id":       userID.String(),
				"business_date": businessDate.Format("2006-01-02"),
				"status":        status,
				"anomalies":     anomalies,
				"summary_id":    summary.AttendanceSummaryID.String(),
				"success":       err == nil,
			}
			if err != nil {
				upsertMetadata["error"] = err.Error()
			}
			s.auditService.LogAction(ctx,
				&companyID,
				"attendance",
				"rules.upsert.after",
				"attendance_summary",
				&summary.AttendanceSummaryID,
				"system",
				nil,
				nil,
				nil,
				upsertMetadata,
			)
		}

		return err
	}

	// 🔴 FIX 4.1: MANUAL OVERRIDE CORRECTIONS (HIGHEST PRIORITY)
	for _, event := range events {
		if event.Metadata.IsCorrection != nil && *event.Metadata.IsCorrection {
			if event.EventType == "manual_override" && event.Metadata.OverrideStatus != nil {

				status := *event.Metadata.OverrideStatus
				anomalies := s.detectAnomalies(events)

				// 🎯 Log manual override detection
				if s.auditService != nil {
					overrideMetadata := map[string]interface{}{
						"user_id":         userID.String(),
						"business_date":   businessDate.Format("2006-01-02"),
						"event_id":        event.AttendanceEventID.String(),
						"override_status": status,
						"anomalies":       anomalies,
						"event_type":      event.EventType,
					}
					s.auditService.LogAction(ctx,
						&companyID,
						"attendance",
						"rules.manual_override.detected",
						"attendance_event",
						&event.AttendanceEventID,
						"system",
						nil,
						nil,
						nil,
						overrideMetadata,
					)
				}

				// ✅ call closure directly
				return upsertStatus(status, anomalies)
			}
		}
	}

	// 🟠 Schedule-level overrides
	if shift != nil {
		switch shift.ScheduleStatus {
		case "weekly_off", "off":
			// 🎯 Log schedule override
			if s.auditService != nil {
				scheduleMetadata := map[string]interface{}{
					"user_id":          userID.String(),
					"business_date":    businessDate.Format("2006-01-02"),
					"schedule_status":  shift.ScheduleStatus,
					"resulting_status": attconstants.StatusWeeklyOff,
				}
				s.auditService.LogAction(ctx,
					&companyID,
					"attendance",
					"rules.schedule_override",
					"user",
					&userID,
					"system",
					nil,
					nil,
					nil,
					scheduleMetadata,
				)
			}
			return upsertStatus(attconstants.StatusWeeklyOff, nil)
		case "holiday":
			if s.auditService != nil {
				scheduleMetadata := map[string]interface{}{
					"user_id":          userID.String(),
					"business_date":    businessDate.Format("2006-01-02"),
					"schedule_status":  shift.ScheduleStatus,
					"resulting_status": attconstants.StatusHoliday,
				}
				s.auditService.LogAction(ctx,
					&companyID,
					"attendance",
					"rules.schedule_override",
					"user",
					&userID,
					"system",
					nil,
					nil,
					nil,
					scheduleMetadata,
				)
			}
			return upsertStatus(attconstants.StatusHoliday, nil)
		case "on_leave":
			if s.auditService != nil {
				scheduleMetadata := map[string]interface{}{
					"user_id":          userID.String(),
					"business_date":    businessDate.Format("2006-01-02"),
					"schedule_status":  shift.ScheduleStatus,
					"resulting_status": attconstants.StatusLeavePaid,
				}
				s.auditService.LogAction(ctx,
					&companyID,
					"attendance",
					"rules.schedule_override",
					"user",
					&userID,
					"system",
					nil,
					nil,
					nil,
					scheduleMetadata,
				)
			}
			return upsertStatus(attconstants.StatusLeavePaid, nil)
		case "not_schedulable":
			if s.auditService != nil {
				scheduleMetadata := map[string]interface{}{
					"user_id":          userID.String(),
					"business_date":    businessDate.Format("2006-01-02"),
					"schedule_status":  shift.ScheduleStatus,
					"resulting_status": attconstants.StatusNotScheduled,
				}
				s.auditService.LogAction(ctx,
					&companyID,
					"attendance",
					"rules.schedule_override",
					"user",
					&userID,
					"system",
					nil,
					nil,
					nil,
					scheduleMetadata,
				)
			}
			return upsertStatus(attconstants.StatusNotScheduled, nil)
		}
	}

	// ⚪ No events → absent
	if len(events) == 0 {
		// 🎯 Log no events scenario
		if s.auditService != nil {
			s.auditService.LogAction(ctx,
				&companyID,
				"attendance",
				"rules.no_events",
				"user",
				&userID,
				"system",
				nil,
				nil,
				nil,
				auditMetadata,
			)
		}
		// ✅ FIX 1: Use status constant
		return upsertStatus(attconstants.StatusAbsent, nil)
	}

	// 1️⃣ Sort events by time
	sort.Slice(events, func(i, j int) bool {
		return events[i].EventTime.Before(events[j].EventTime)
	})

	// 2️⃣ Detect anomalies
	anomalies := s.detectAnomalies(events)

	// 🎯 Log anomaly detection
	if s.auditService != nil {
		anomalyMetadata := map[string]interface{}{
			"user_id":       userID.String(),
			"business_date": businessDate.Format("2006-01-02"),
			"anomalies":     anomalies,
			"anomaly_count": len(anomalies),
		}
		s.auditService.LogAction(ctx,
			&companyID,
			"attendance",
			"rules.anomalies.detected",
			"user",
			&userID,
			"system",
			nil,
			nil,
			nil,
			anomalyMetadata,
		)
	}

	// 3️⃣ Pair check-in / check-out
	pairedEvents := s.pairCheckInCheckOut(events)

	// 4️⃣ Resolve policy
	policy, err := s.resolvePolicy(
		ctx,
		companyID,
		userID,
		businessDate,
		shift,
	)
	if err != nil {
		s.logger.Warn("Failed to resolve policy",
			zap.String("user_id", userID.String()),
			zap.Time("date", businessDate),
			zap.Error(err),
		)

		// 🎯 Log policy resolution failure
		if s.auditService != nil {
			policyMetadata := map[string]interface{}{
				"user_id":       userID.String(),
				"business_date": businessDate.Format("2006-01-02"),
				"error":         err.Error(),
			}
			s.auditService.LogAction(ctx,
				&companyID,
				"attendance",
				"rules.policy.resolution_failed",
				"user",
				&userID,
				"system",
				nil,
				nil,
				nil,
				policyMetadata,
			)
		}
	} else {
		// 🎯 Log policy resolution success
		if s.auditService != nil {
			policyMetadata := map[string]interface{}{
				"user_id":       userID.String(),
				"business_date": businessDate.Format("2006-01-02"),
				"policy_id":     policy.PolicyID.String(),
				"policy_code":   policy.PolicyCode,
				"policy_type":   policy.PolicyType,
			}
			s.auditService.LogAction(ctx,
				&companyID,
				"attendance",
				"rules.policy.resolved",
				"attendance_policy",
				&policy.PolicyID,
				"system",
				nil,
				nil,
				nil,
				policyMetadata,
			)
		}
	}

	// 5️⃣ Calculate metrics
	metrics := s.calculateMetrics(pairedEvents, shift, policy, anomalies)

	// 6️⃣ Determine final status
	status := s.determineStatus(metrics, shift, policy)

	// 🎯 Log status determination
	if s.auditService != nil {
		statusMetadata := map[string]interface{}{
			"user_id":        userID.String(),
			"business_date":  businessDate.Format("2006-01-02"),
			"final_status":   status,
			"checkins":       metrics.CheckIns,
			"checkouts":      metrics.CheckOuts,
			"worked_minutes": intValue(metrics.WorkedMinutes),
			"late_minutes":   intValue(metrics.LateMinutes),
			"paired_events":  len(pairedEvents),
		}
		s.auditService.LogAction(ctx,
			&companyID,
			"attendance",
			"rules.status.determined",
			"user",
			&userID,
			"system",
			nil,
			nil,
			nil,
			statusMetadata,
		)
	}

	// 7️⃣ Build summary
	summary := &attendance.AttendanceDailySummary{
		AttendanceSummaryID: uuid.New(),
		CompanyID:           companyID,
		UserID:              userID,
		AttendanceDate:      businessDate,
		Status:              status,
		IsPayrollLocked:     false, // ✅ Always false when created by resolution service
		WorkedMinutes:       metrics.WorkedMinutes,
		OvertimeMinutes:     metrics.OvertimeMinutes,
		LateMinutes:         metrics.LateMinutes,
		Metadata: attendance.SummaryMetadata{
			CheckInTime:    metrics.FirstCheckIn,
			CheckOutTime:   metrics.LastCheckOut,
			TotalCheckIns:  &metrics.CheckIns,
			TotalCheckOuts: &metrics.CheckOuts,
			BreakMinutes:   metrics.BreakMinutes,
			ScheduleStatus: &shift.ScheduleStatus,
			ShiftID:        shift.ShiftID,
			Timezone:       &shift.Timezone,
			Anomalies:      anomalies,
			PairedEvents:   convertPairedEvents(metrics.PairedEvents),
		},
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "attendance_resolution_service",
	}

	// Preserve existing ID
	if existing, err := s.attendanceRepo.
		GetAttendanceDailySummaryByUserDate(ctx, userID, businessDate); err == nil && existing != nil {
		summary.AttendanceSummaryID = existing.AttendanceSummaryID
	}

	// 8️⃣ Save summary
	if err := s.attendanceRepo.UpsertAttendanceDailySummary(ctx, summary); err != nil {
		// 🎯 Log save failure
		if s.auditService != nil {
			saveMetadata := map[string]interface{}{
				"user_id":       userID.String(),
				"business_date": businessDate.Format("2006-01-02"),
				"summary_id":    summary.AttendanceSummaryID.String(),
				"status":        status,
				"error":         err.Error(),
			}
			s.auditService.LogAction(ctx,
				&companyID,
				"attendance",
				"rules.summary.save_failed",
				"attendance_summary",
				&summary.AttendanceSummaryID,
				"system",
				nil,
				nil,
				nil,
				saveMetadata,
			)
		}
		return fmt.Errorf("failed to save attendance summary: %w", err)
	}

	// 🎯 Log successful save
	if s.auditService != nil {
		saveMetadata := map[string]interface{}{
			"user_id":          userID.String(),
			"business_date":    businessDate.Format("2006-01-02"),
			"summary_id":       summary.AttendanceSummaryID.String(),
			"status":           status,
			"worked_minutes":   intValue(metrics.WorkedMinutes),
			"late_minutes":     intValue(metrics.LateMinutes),
			"overtime_minutes": intValue(metrics.OvertimeMinutes),
			"anomalies":        anomalies,
			"timezone":         shift.Timezone,
		}
		s.auditService.LogAction(ctx,
			&companyID,
			"attendance",
			"rules.summary.saved",
			"attendance_summary",
			&summary.AttendanceSummaryID,
			"system",
			nil,
			nil,
			nil,
			saveMetadata,
		)
	}

	s.logger.Info("Attendance summary saved",
		zap.String("summary_id", summary.AttendanceSummaryID.String()),
		zap.String("user_id", userID.String()),
		zap.String("status", status),
		zap.Time("business_date", businessDate),
		zap.String("timezone", shift.Timezone),
		zap.Int("worked_minutes", intValue(metrics.WorkedMinutes)),
		zap.Int("late_minutes", intValue(metrics.LateMinutes)),
		zap.Int("overtime_minutes", intValue(metrics.OvertimeMinutes)),
		zap.Strings("anomalies", anomalies),
	)

	return nil
}

// ============================================
// HELPER METHODS (copied from original)
// ============================================

func (s *attendanceResolutionService) resolveShift(
	ctx context.Context,
	companyID, userID uuid.UUID,
	date time.Time,
) (*ShiftContext, error) {
	// Call scheduling service to resolve the day
	resolvedDay, err := s.schedulingQSA.ResolveUserDay(ctx, companyID, userID, date)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve schedule: %w", err)
	}

	shiftCtx := &ShiftContext{
		ScheduleDate:   resolvedDay.Date,
		ScheduleStatus: resolvedDay.ScheduleStatus,
		Timezone:       resolvedDay.Timezone,
		IsOnLeave:      resolvedDay.IsOnLeave,
		IsOverride:     resolvedDay.IsOverride,
		OverrideType:   resolvedDay.OverrideType,
		ExpectedStart:  resolvedDay.ExpectedStart,
		ExpectedEnd:    resolvedDay.ExpectedEnd,
		WorkCenterCode: resolvedDay.WorkCenterCode,
		PositionID:     resolvedDay.PositionID,
		DepartmentID:   resolvedDay.DepartmentID,
	}

	// Get shift details if schedule instance exists
	if resolvedDay.ScheduleInstanceID != nil {
		instance, err := s.schedulingQS.GetScheduleInstanceByID(ctx, *resolvedDay.ScheduleInstanceID)
		if err == nil && instance != nil {
			shiftCtx.ShiftID = &instance.ScheduleTemplateID
			shiftCtx.Timezone = instance.Timezone // Use instance timezone if available
		}
	}

	// Get shift name
	if shiftCtx.ShiftID != nil {
		template, err := s.schedulingQS.GetScheduleTemplateByID(ctx, *shiftCtx.ShiftID)
		if err == nil && template != nil {
			shiftCtx.ShiftName = &template.Name
		}
	}

	return shiftCtx, nil
}

func (s *attendanceResolutionService) detectAnomalies(events []*attendance.AttendanceEvent) []string {
	var anomalies []string

	checkIns := 0
	checkOuts := 0
	var lastEventType string

	for i, event := range events {
		switch event.EventType {
		case "check_in", "shift_start":
			checkIns++
			// Check for duplicate check-in
			if i > 0 && (lastEventType == "check_in" || lastEventType == "shift_start") {
				anomalies = append(anomalies, "duplicate_checkin")
			}
		case "check_out", "shift_end":
			checkOuts++
			// Check for orphan check-out (no preceding check-in)
			if checkIns == 0 || (i > 0 && lastEventType == "check_out") {
				anomalies = append(anomalies, "orphan_checkout")
			}
		}
		lastEventType = event.EventType
	}

	// Check for missing check-out
	if checkIns > 0 && checkOuts == 0 {
		anomalies = append(anomalies, "missing_checkout")
	}

	// Check for missing check-in
	if checkIns == 0 && checkOuts > 0 {
		anomalies = append(anomalies, "missing_checkin")
	}

	// Check for multiple pairs
	if checkIns > 1 || checkOuts > 1 {
		anomalies = append(anomalies, "multiple_pairs")
	}

	return anomalies
}

func (s *attendanceResolutionService) pairCheckInCheckOut(
	events []*attendance.AttendanceEvent,
) []PairedEvent {

	// 1️⃣ Sort events by:
	//   - EventTime ASC
	//   - Correction > Source priority
	sort.Slice(events, func(i, j int) bool {
		// First: time
		if !events[i].EventTime.Equal(events[j].EventTime) {
			return events[i].EventTime.Before(events[j].EventTime)
		}

		// Second: priority (higher wins)
		priorityI := s.getSourcePriority(
			events[i].SourceType,
			events[i].Metadata.IsCorrection,
		)
		priorityJ := s.getSourcePriority(
			events[j].SourceType,
			events[j].Metadata.IsCorrection,
		)

		return priorityI > priorityJ
	})

	var paired []PairedEvent
	var currentPair *PairedEvent

	// 2️⃣ Existing pairing logic (unchanged behavior)
	for _, event := range events {
		eventTime := event.EventTime

		switch event.EventType {

		case "check_in", "shift_start":
			// Close previous open pair
			if currentPair != nil && currentPair.CheckOut == nil {
				paired = append(paired, *currentPair)
			}

			currentPair = &PairedEvent{
				CheckIn:     event,
				CheckInTime: &eventTime,
			}

		case "check_out", "shift_end":
			if currentPair != nil && currentPair.CheckOut == nil {
				currentPair.CheckOut = event
				currentPair.CheckOutTime = &eventTime
				paired = append(paired, *currentPair)
				currentPair = nil
			} else {
				// Orphaned checkout
				paired = append(paired, PairedEvent{
					CheckOut:     event,
					CheckOutTime: &eventTime,
				})
			}

		case "break_start":
			if currentPair != nil {
				currentPair.BreakStart = &eventTime
			}

		case "break_end":
			if currentPair != nil && currentPair.BreakStart != nil {
				currentPair.BreakEnd = &eventTime
				// 🔜 Break duration logic can plug in here
			}
		}
	}

	// 3️⃣ Dangling check-in
	if currentPair != nil && currentPair.CheckOut == nil {
		paired = append(paired, *currentPair)
	}

	return paired
}

func (s *attendanceResolutionService) getSourcePriority(sourceType string, isCorrection *bool) int {
	// Corrections always win
	if isCorrection != nil && *isCorrection {
		return 100
	}

	priorityMap := map[string]int{
		"manual":    90,
		"biometric": 80,
		"kiosk":     60,
		"mobile":    50,
		"web":       40,
		"api":       30,
		"system":    20,
		"import":    10,
	}

	if p, ok := priorityMap[sourceType]; ok {
		return p
	}

	return 0
}

func (s *attendanceResolutionService) calculateMetrics(
	pairedEvents []PairedEvent,
	shift *ShiftContext,
	policy *attendance.AttendancePolicy,
	anomalies []string,
) *DailyMetrics {
	metrics := &DailyMetrics{
		Status:       attconstants.StatusPresent,
		PairedEvents: pairedEvents,
	}

	var totalWorkedSeconds int64
	var totalBreakSeconds int64

	// Convert shift times to UTC for comparison
	var expectedStartUTC, expectedEndUTC *time.Time
	if shift.ExpectedStart != nil {
		est := shift.ExpectedStart.UTC()
		expectedStartUTC = &est
	}
	if shift.ExpectedEnd != nil {
		eet := shift.ExpectedEnd.UTC()
		expectedEndUTC = &eet
	}

	// Process each pair
	for _, pair := range pairedEvents {
		if pair.CheckIn != nil {
			metrics.CheckIns++

			// Track first check-in
			if metrics.FirstCheckIn == nil || pair.CheckInTime.Before(*metrics.FirstCheckIn) {
				metrics.FirstCheckIn = pair.CheckInTime
			}

			// Calculate late minutes
			if pair.CheckInTime != nil && expectedStartUTC != nil {
				if pair.CheckInTime.After(*expectedStartUTC) {
					lateSeconds := pair.CheckInTime.Sub(*expectedStartUTC).Seconds()
					lateMinutes := int(lateSeconds / 60)

					// Apply grace period
					if policy != nil && policy.Rules.GracePeriod != nil && lateMinutes <= *policy.Rules.GracePeriod {
						lateMinutes = 0
					}

					if lateMinutes > 0 {
						metrics.LateMinutes = &lateMinutes
					}
				}
			}
		}

		if pair.CheckOut != nil {
			metrics.CheckOuts++

			// Track last check-out
			if metrics.LastCheckOut == nil || pair.CheckOutTime.After(*metrics.LastCheckOut) {
				metrics.LastCheckOut = pair.CheckOutTime
			}

			// Calculate worked time
			if pair.CheckInTime != nil && pair.CheckOutTime != nil {
				workedDuration := pair.CheckOutTime.Sub(*pair.CheckInTime)
				totalWorkedSeconds += int64(workedDuration.Seconds())

				// Deduct break time if present
				if pair.BreakStart != nil && pair.BreakEnd != nil {
					breakDuration := pair.BreakEnd.Sub(*pair.BreakStart)
					totalBreakSeconds += int64(breakDuration.Seconds())
				}

				// Calculate overtime
				if expectedEndUTC != nil && pair.CheckOutTime.After(*expectedEndUTC) {
					overtimeSeconds := pair.CheckOutTime.Sub(*expectedEndUTC).Seconds()
					overtimeMinutes := int(overtimeSeconds / 60)

					// Apply overtime threshold
					if policy != nil && policy.Rules.OvertimeThreshold != nil && overtimeMinutes < *policy.Rules.OvertimeThreshold {
						overtimeMinutes = 0
					}

					if overtimeMinutes > 0 {
						if metrics.OvertimeMinutes == nil {
							metrics.OvertimeMinutes = &overtimeMinutes
						} else {
							*metrics.OvertimeMinutes += overtimeMinutes
						}
					}
				}
			}
		}
	}

	// Calculate net worked minutes (minus breaks)
	netWorkedSeconds := totalWorkedSeconds - totalBreakSeconds
	if netWorkedSeconds > 0 {
		workedMinutes := int(netWorkedSeconds / 60)
		metrics.WorkedMinutes = &workedMinutes
	}

	// Calculate break minutes
	if totalBreakSeconds > 0 {
		breakMinutes := int(totalBreakSeconds / 60)
		metrics.BreakMinutes = &breakMinutes
	}

	return metrics
}

func (s *attendanceResolutionService) determineStatus(
	metrics *DailyMetrics,
	shift *ShiftContext,
	policy *attendance.AttendancePolicy,
) string {
	// ✅ FIX 2: Don't overwrite schedule statuses blindly
	if shift != nil && shift.ScheduleStatus != "" {
		switch shift.ScheduleStatus {
		case "weekly_off":
			return attconstants.StatusWeeklyOff
		case "holiday":
			return attconstants.StatusHoliday
		case "on_leave":
			return attconstants.StatusLeavePaid
			// For "active", "scheduled", or any other status, continue with normal flow
		}
	}

	// No check-ins at all
	if metrics.CheckIns == 0 {
		// ✅ FIX 1: Use status constant
		return attconstants.StatusAbsent
	}

	// Late arrival handling
	if metrics.LateMinutes != nil && *metrics.LateMinutes > 0 {
		if policy != nil && policy.Rules.MaxLateAllowed != nil &&
			*metrics.LateMinutes > *policy.Rules.MaxLateAllowed {
			// ✅ FIX 1: Use status constant
			return attconstants.StatusAbsent
		}
		// ✅ FIX 1: Use status constant
		return attconstants.StatusLate
	}

	// Half day check
	if metrics.WorkedMinutes != nil && policy != nil && policy.Rules.HalfDayAfter != nil {
		if *metrics.WorkedMinutes < *policy.Rules.HalfDayAfter {
			// ✅ FIX 1: Use status constant
			return attconstants.StatusHalfDay
		}
	}

	// Check-in without check-out
	if metrics.CheckIns > 0 && metrics.CheckOuts == 0 {
		if policy != nil && policy.Rules.AutoCheckout != nil && *policy.Rules.AutoCheckout {
			if metrics.WorkedMinutes != nil && *metrics.WorkedMinutes >= 240 { // 4 hours
				// ✅ FIX 1: Use status constant
				return attconstants.StatusPresent
			}
		}
		// No constant for "incomplete" - using string literal
		return "incomplete"
	}

	// Check-out without check-in
	if metrics.CheckIns == 0 && metrics.CheckOuts > 0 {
		// No constant for "incomplete" - using string literal
		return "incomplete"
	}

	// Default to present
	// ✅ FIX 1: Use status constant
	return attconstants.StatusPresent
}

// ✅ UPDATED: resolvePolicy with work center and position hierarchy
func (s *attendanceResolutionService) resolvePolicy(
	ctx context.Context,
	companyID, userID uuid.UUID,
	date time.Time,
	shift *ShiftContext,
) (*attendance.AttendancePolicy, error) {

	// 1️⃣ USER-LEVEL OVERRIDE (temporary)
	userPolicy, err := s.attendanceRepo.GetUserActiveAttendancePolicy(ctx, userID, date)
	if err == nil && userPolicy != nil {
		return userPolicy, nil
	}

	// 2️⃣ POSITION-LEVEL OVERRIDE
	if shift != nil && shift.PositionID != nil {
		positionPolicy, err := s.attendanceRepo.GetPositionAttendancePolicy(ctx, *shift.PositionID)
		if err == nil && positionPolicy != nil {
			return positionPolicy, nil
		}
	}

	// 3️⃣ WORK CENTER POLICY (PRIMARY)
	if shift != nil && shift.WorkCenterCode != nil {
		wcPolicy, err := s.attendanceRepo.GetWorkCenterAttendancePolicy(
			ctx,
			companyID,
			*shift.WorkCenterCode,
		)
		if err == nil && wcPolicy != nil {
			return wcPolicy, nil
		}
	}

	// 4️⃣ COMPANY DEFAULT (SAFE FALLBACK)
	return &attendance.AttendancePolicy{
		PolicyID:   uuid.New(),
		PolicyCode: "DEFAULT",
		PolicyType: "company_default",
		Rules: attendance.PolicyRules{
			GracePeriod:         intPtr(15),
			MaxLateAllowed:      intPtr(60),
			HalfDayAfter:        intPtr(240),
			AutoCheckout:        boolPtr(false),
			OvertimeThreshold:   intPtr(15),
			AutoApproveOvertime: boolPtr(false),
			AllowShiftOverlap:   boolPtr(false),
		},
		IsActive: true,
	}, nil
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

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

func convertPairedEvents(
	pairs []PairedEvent,
) []attendance.PairedEvent {

	result := make([]attendance.PairedEvent, 0, len(pairs))

	for _, p := range pairs {

		var checkIn time.Time
		if p.CheckInTime != nil {
			checkIn = *p.CheckInTime
		}

		var checkOut *time.Time
		if p.CheckOutTime != nil {
			t := *p.CheckOutTime
			checkOut = &t
		}

		pe := attendance.PairedEvent{
			CheckInTime:  checkIn,
			CheckOutTime: checkOut,
		}

		if p.CheckIn != nil {
			pe.CheckInEventID = p.CheckIn.AttendanceEventID
		}

		if p.CheckOut != nil {
			id := p.CheckOut.AttendanceEventID
			pe.CheckOutEventID = &id
		}

		result = append(result, pe)
	}

	return result
}
