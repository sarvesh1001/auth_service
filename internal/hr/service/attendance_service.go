package service

import (
	"auth-service/internal/hr/models/attendance"
	"auth-service/internal/hr/repository"
	"auth-service/internal/util"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort" // ✅ ADD THIS LINE
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ==============================================
// INTERNAL TYPES AND CONSTANTS
// ==============================================
type AttendanceService interface {
	// =========================
	// Events
	// =========================
	CreateAttendanceEvent(
		ctx context.Context,
		event *attendance.AttendanceEvent,
		actorType string,
		actorID uuid.UUID,
		metadata map[string]interface{},
	) (*attendance.AttendanceEvent, error)

	CreateBulkAttendanceEvents(
		ctx context.Context,
		events []*attendance.AttendanceEvent,
		actorType string,
		actorID uuid.UUID,
		metadata map[string]interface{},
	) error

	ProcessSAPAttendanceEvent(
		ctx context.Context,
		sapEvent *SAPAttendanceEvent,
		companyID uuid.UUID,
		sourceType string,
		sourceID *uuid.UUID,
	) (*attendance.AttendanceEvent, error)

	CompleteSAPAttendanceFlow(
		ctx context.Context,
		sapEvent *SAPAttendanceEvent,
		companyID uuid.UUID,
	) error

	SyncFactoryAttendance(
		ctx context.Context,
		factoryData *FactoryAttendanceData,
		companyID uuid.UUID,
	) error

	GetAttendanceEventByID(
		ctx context.Context,
		eventID uuid.UUID,
	) (*attendance.AttendanceEvent, error)

	SearchAttendanceEvents(
		ctx context.Context,
		filter AttendanceSearchFilters,
		page, pageSize int,
	) ([]*attendance.AttendanceEvent, int, error)

	// =========================
	// Policies
	// =========================
	CreateAttendancePolicy(
		ctx context.Context,
		policy *attendance.AttendancePolicy,
		actorType string,
		actorID uuid.UUID,
		metadata map[string]interface{},
	) (*attendance.AttendancePolicy, error)

	UpdateAttendancePolicy(
		ctx context.Context,
		policy *attendance.AttendancePolicy,
	) error

	DeleteAttendancePolicy(
		ctx context.Context,
		policyID uuid.UUID,
	) error

	AssignUserAttendancePolicy(
		ctx context.Context,
		userPolicy *attendance.UserAttendancePolicy,
		actorType string,
		actorID uuid.UUID,
		metadata map[string]interface{},
	) error

	// =========================
	// Rules
	// =========================
	GetCompanyAttendanceRules(
		ctx context.Context,
		companyID uuid.UUID,
	) (*attendance.CompanyAttendanceRules, error)

	UpdateCompanyAttendanceRules(
		ctx context.Context,
		rules *attendance.CompanyAttendanceRules,
		updatedBy uuid.UUID,
	) error

	GetDepartmentAttendanceRules(
		ctx context.Context,
		companyID, departmentID uuid.UUID,
	) (*attendance.DepartmentAttendanceRules, error)

	UpsertDepartmentAttendanceRules(
		ctx context.Context,
		rules *attendance.DepartmentAttendanceRules,
	) error

	ResolveAttendanceRules(
		ctx context.Context,
		userID, companyID, departmentID uuid.UUID,
	) (*attendance.ResolvedAttendanceRules, error)

	// =========================
	// Profiles
	// =========================
	GetUserAttendanceProfile(
		ctx context.Context,
		userID uuid.UUID,
	) (*attendance.UserAttendanceProfile, error)

	UpsertUserAttendanceProfile(
		ctx context.Context,
		profile *attendance.UserAttendanceProfile,
	) error

	// =========================
	// Summaries & Stats
	// =========================
	GenerateDailySummary(
		ctx context.Context,
		companyID, userID uuid.UUID,
		date time.Time,
		timezone string,
	) (*attendance.AttendanceDailySummary, error)

	GenerateBulkDailySummaries(
		ctx context.Context,
		companyID uuid.UUID,
		timezone string,
		startDate, endDate time.Time,
	) ([]*attendance.AttendanceDailySummary, error)

	GetAttendanceStats(
		ctx context.Context,
		companyID uuid.UUID,
		startDate, endDate time.Time,
	) (*attendance.AttendanceStats, error)

	GetUserAttendanceStats(
		ctx context.Context,
		userID uuid.UUID,
		startDate, endDate time.Time,
	) (*attendance.UserAttendanceStats, error)

	GetAttendanceDailySummariesByCompany(
		ctx context.Context,
		companyID uuid.UUID,
		startDate, endDate time.Time,
		page, pageSize int,
	) ([]*attendance.AttendanceDailySummary, int64, error)

	// =========================
	// RFID
	// =========================
	AssignRFIDToEmployee(
		ctx context.Context,
		companyID, userID uuid.UUID,
		rfidTag string,
		assignedBy uuid.UUID,
	) error

	GetEmployeeByRFID(
		ctx context.Context,
		rfidTag string,
		companyID uuid.UUID,
	) (*attendance.EmployeeRFIDMapping, error)

	UnassignRFID(
		ctx context.Context,
		rfidID uuid.UUID,
		unassignedBy uuid.UUID,
	) error

	// =========================
	// Work Centers
	// =========================
	MapWorkCenterToShift(
		ctx context.Context,
		companyID uuid.UUID,
		workCenterCode string,
		shiftID uuid.UUID,
		effectiveFrom time.Time,
		effectiveTo *time.Time,
		createdBy uuid.UUID,
	) error

	GetShiftForWorkCenter(
		ctx context.Context,
		workCenterCode string,
		companyID uuid.UUID,
	) (*attendance.WorkCenterShift, error)

	// =========================
	// SAP Rules
	// =========================

	// =========================
	// Validation
	// =========================
	ValidateAttendanceEventType(
		ctx context.Context,
		eventType string,
	) error

	ValidateAttendanceSourceType(
		ctx context.Context,
		sourceType string,
		sourceID *uuid.UUID,
	) error

	ValidateEventAgainstRules(
		ctx context.Context,
		event *attendance.AttendanceEvent,
		rules *attendance.ResolvedAttendanceRules,
	) error

	// =========================
	// Health
	// =========================
	HealthCheck(ctx context.Context) error
}

type AttendanceQueryService interface {
	// =========================
	// Events
	// =========================
	GetAttendanceEventByID(
		ctx context.Context,
		eventID uuid.UUID,
	) (*attendance.AttendanceEvent, error)

	GetAttendanceEventsByUser(
		ctx context.Context,
		userID uuid.UUID,
		startDate, endDate time.Time,
		limit int,
	) ([]*attendance.AttendanceEvent, error)

	GetAttendanceEventsByCompany(
		ctx context.Context,
		companyID uuid.UUID,
		startDate, endDate time.Time,
		page, pageSize int,
	) ([]*attendance.AttendanceEvent, int, error)

	SearchAttendanceEventsTyped(
		ctx context.Context,
		companyID uuid.UUID,
		filters AttendanceSearchFilters,
		page, pageSize int,
	) ([]*attendance.AttendanceEvent, int, error)

	// =========================
	// Policies
	// =========================
	GetAttendancePolicyByID(
		ctx context.Context,
		policyID uuid.UUID,
	) (*attendance.AttendancePolicy, error)

	GetAttendancePoliciesByCompany(
		ctx context.Context,
		companyID uuid.UUID,
		activeOnly bool,
	) ([]*attendance.AttendancePolicy, error)

	GetUserCurrentAttendancePolicy(
		ctx context.Context,
		userID uuid.UUID,
		date time.Time,
	) (*attendance.AttendancePolicy, error)

	// =========================
	// Summaries & Reports
	// =========================
	GetAttendanceDailySummaryByUserDate(
		ctx context.Context,
		userID uuid.UUID,
		date time.Time,
	) (*attendance.AttendanceDailySummary, error)

	GetAttendanceDailySummariesByUser(
		ctx context.Context,
		userID uuid.UUID,
		startDate, endDate time.Time,
	) ([]*attendance.AttendanceDailySummary, error)

	GetAttendanceSummaryStats(
		ctx context.Context,
		companyID uuid.UUID,
		startDate, endDate time.Time,
	) (*AttendanceSummaryStats, error)

	GenerateAttendanceReport(
		ctx context.Context,
		companyID uuid.UUID,
		reportType string,
		startDate, endDate time.Time,
	) ([]byte, string, error)

	StreamAttendanceEvents(
		ctx context.Context,
		companyID uuid.UUID,
		startDate, endDate time.Time,
		writer io.Writer,
		format string,
	) error

	// =========================
	// Metadata
	// =========================
	ListAttendanceEventTypes(
		ctx context.Context,
		activeOnly bool,
	) ([]*attendance.AttendanceEventType, error)

	ListAttendanceSourceTypes(
		ctx context.Context,
	) ([]*attendance.AttendanceSourceType, error)

	// =========================
	// Health
	// =========================
	HealthCheck(ctx context.Context) error
}

// AttendanceDayContext is the result of resolving scheduling for a user day
type AttendanceDayContext struct {
	// Authoritative business date (schedule timezone)
	Date time.Time

	// Timezone resolved by scheduling
	Timezone string

	IsWorkingDay bool
	IsHoliday    bool
	IsOnLeave    bool
	IsForceWork  bool

	ExpectedStart *time.Time
	ExpectedEnd   *time.Time
	ShiftID       *uuid.UUID
}

// SAPAttendanceEvent represents attendance data from SAP system
type SAPAttendanceEvent struct {
	EmployeeID      string    `json:"employee_id"`
	WorkCenterCode  string    `json:"work_center_code"`
	EventType       string    `json:"event_type"`
	EventTime       time.Time `json:"event_time"`
	RFIDTag         string    `json:"rfid_tag,omitempty"`
	BiometricID     string    `json:"biometric_id,omitempty"`
	MachineCode     string    `json:"machine_code,omitempty"`
	ReasonCode      string    `json:"reason_code,omitempty"`
	CostCenter      string    `json:"cost_center,omitempty"`
	ProductionOrder string    `json:"production_order,omitempty"`
}

// FactoryAttendanceData represents batch attendance data from factory systems
type FactoryAttendanceData struct {
	CompanyID      uuid.UUID            `json:"company_id"`
	WorkCenterCode string               `json:"work_center_code"`
	Events         []SAPAttendanceEvent `json:"events"`
	SyncTimestamp  time.Time            `json:"sync_timestamp"`
	SourceSystem   string               `json:"source_system"`
}

// AttendanceSearchFilters for querying attendance events
type AttendanceSearchFilters struct {
	CompanyID    uuid.UUID
	UserID       *uuid.UUID
	StartDate    time.Time
	EndDate      time.Time
	EventType    *string
	SourceType   *string
	DepartmentID *uuid.UUID
	ShiftID      *uuid.UUID
}

// AttendanceSummaryStats contains aggregated attendance statistics
type AttendanceSummaryStats struct {
	CompanyID           uuid.UUID                  `json:"company_id"`
	StartDate           time.Time                  `json:"start_date"`
	EndDate             time.Time                  `json:"end_date"`
	TotalEmployees      int                        `json:"total_employees"`
	SummaryByStatus     map[string]int             `json:"summary_by_status"`
	AverageHours        float64                    `json:"average_hours"`
	OvertimeHours       float64                    `json:"overtime_hours"`
	LateArrivals        int                        `json:"late_arrivals"`
	TopLateEmployees    []LateEmployeeSummary      `json:"top_late_employees"`
	DepartmentBreakdown map[string]DepartmentStats `json:"department_breakdown"`
}

// LateEmployeeSummary represents an employee with frequent late arrivals
type LateEmployeeSummary struct {
	UserID             uuid.UUID `json:"user_id"`
	Username           string    `json:"username"`
	FullName           string    `json:"full_name"`
	LateCount          int       `json:"late_count"`
	AverageLateMinutes int       `json:"average_late_minutes"`
}

// DepartmentStats contains attendance statistics for a department
type DepartmentStats struct {
	DepartmentID   uuid.UUID `json:"department_id"`
	DepartmentName string    `json:"department_name"`
	PresentCount   int       `json:"present_count"`
	AbsentCount    int       `json:"absent_count"`
	LateCount      int       `json:"late_count"`
	AverageHours   float64   `json:"average_hours"`
}

// ==============================================
// ATTENDANCE SERVICE IMPLEMENTATION
// ==============================================

type attendanceServiceImpl struct {
	attendanceRepo    repository.AttendanceRepository
	schedulingService SchedulingService
	logger            *zap.Logger
	mu                sync.RWMutex
	auditService      *AuditService // Optional, for audit logging
}

func NewAttendanceService(
	attendanceRepo repository.AttendanceRepository,
	schedulingService SchedulingService,
	logger *zap.Logger,
	auditService *AuditService,
) AttendanceService {
	return &attendanceServiceImpl{
		attendanceRepo:    attendanceRepo,
		schedulingService: schedulingService,
		logger:            logger,
		auditService:      auditService,
	}
}

// ==============================================
// SCHEDULING BRIDGE LAYER
// ==============================================
func (s *attendanceServiceImpl) resolveAttendanceDay(
	ctx context.Context,
	userID uuid.UUID,
	at time.Time,
	_ string, // ⚠️ timezone param is intentionally ignored
) (*AttendanceDayContext, error) {

	startTime := time.Now()

	// 🔥 Scheduling is AUTHORITATIVE
	resolvedDay, err := s.schedulingService.ResolveUserDay(ctx, userID, at)
	if err != nil {
		s.logger.Error("Failed to resolve user day",
			util.String("user_id", userID.String()),
			util.String("at", at.Format(time.RFC3339)),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to resolve user day: %w", err)
	}

	context := &AttendanceDayContext{
		// ✅ BUSINESS DATE decided by scheduling
		Date: resolvedDay.Date,

		// ✅ TIMEZONE decided by scheduling
		Timezone: resolvedDay.Timezone,

		IsWorkingDay:  resolvedDay.IsWorkingDay,
		IsHoliday:     resolvedDay.IsHoliday,
		IsOnLeave:     resolvedDay.IsOnLeave,
		IsForceWork:   resolvedDay.IsForceWork,
		ExpectedStart: resolvedDay.ExpectedStart,
		ExpectedEnd:   resolvedDay.ExpectedEnd,
		ShiftID:       resolvedDay.ShiftID,
	}

	s.logger.Debug("Resolved attendance day",
		util.String("user_id", userID.String()),
		util.String("business_date", context.Date.Format("2006-01-02")),
		util.String("timezone", context.Timezone),
		util.Bool("is_working_day", context.IsWorkingDay),
		util.Bool("is_holiday", context.IsHoliday),
		util.Bool("is_on_leave", context.IsOnLeave),
		util.Bool("is_force_work", context.IsForceWork),
		util.Duration("duration", time.Since(startTime)),
	)

	return context, nil
}

// ==============================================
// ATTENDANCE VALIDATION LAYER
// ==============================================
func (s *attendanceServiceImpl) validateEventAgainstDay(
	ctx context.Context,
	event *attendance.AttendanceEvent,
	day *AttendanceDayContext,
) error {

	if day.IsHoliday && !day.IsForceWork {
		return fmt.Errorf("cannot create attendance event on holiday")
	}

	if day.IsOnLeave {
		return fmt.Errorf("cannot create attendance event while on leave")
	}

	if !day.IsWorkingDay {
		return fmt.Errorf("cannot create attendance event on non-working day")
	}

	// Only validate time window for check-in / check-out
	if event.EventType != "check_in" && event.EventType != "check_out" {
		return nil
	}

	if day.ExpectedStart == nil || day.ExpectedEnd == nil {
		return nil
	}

	loc, err := time.LoadLocation(day.Timezone)
	if err != nil {
		return fmt.Errorf("invalid schedule timezone: %s", day.Timezone)
	}

	eventLocal := event.EventTime.In(loc)

	// ✅ BUSINESS DATE MUST COME FROM SCHEDULING
	businessDate := day.Date.In(loc)

	expectedStart := time.Date(
		businessDate.Year(),
		businessDate.Month(),
		businessDate.Day(),
		day.ExpectedStart.Hour(),
		day.ExpectedStart.Minute(),
		0, 0,
		loc,
	)

	expectedEnd := time.Date(
		businessDate.Year(),
		businessDate.Month(),
		businessDate.Day(),
		day.ExpectedEnd.Hour(),
		day.ExpectedEnd.Minute(),
		0, 0,
		loc,
	)

	// ✅ Handle night / cross-midnight shifts
	if expectedEnd.Before(expectedStart) {
		expectedEnd = expectedEnd.Add(24 * time.Hour)
	}

	if event.EventType == "check_in" {
		earliestAllowed := expectedStart.Add(-4 * time.Hour)
		latestAllowed := expectedEnd.Add(2 * time.Hour)

		if eventLocal.Before(earliestAllowed) || eventLocal.After(latestAllowed) {
			return fmt.Errorf(
				"check-in time %s is outside allowed range (%s - %s)",
				eventLocal.Format(time.RFC3339),
				earliestAllowed.Format(time.RFC3339),
				latestAllowed.Format(time.RFC3339),
			)
		}
	}

	return nil
}

// validateEventRules validates event against business rules
func (s *attendanceServiceImpl) validateEventRules(
	ctx context.Context,
	event *attendance.AttendanceEvent,
) error {
	// Get resolved rules for the user
	rules, err := s.ResolveAttendanceRules(ctx, event.UserID, event.CompanyID, uuid.Nil)
	if err != nil {
		return fmt.Errorf("failed to resolve attendance rules: %w", err)
	}

	// Validate source type is allowed
	if !rules.AllowedSourceTypesMap[event.SourceType] {
		return fmt.Errorf("source type %s is not allowed", event.SourceType)
	}

	// Validate event type is allowed (if not all events are allowed)
	if !rules.AllowAllEventTypes && !rules.AllowedEventTypesMap[event.EventType] {
		return fmt.Errorf("event type %s is not allowed", event.EventType)
	}

	// Validate reference requirement
	if rules.RequireReference && event.SourceID == nil {
		return fmt.Errorf("source reference is required for source type %s", event.SourceType)
	}

	// Validate location requirement
	if rules.RequireLocation && (event.Metadata.LocationID == nil || *event.Metadata.LocationID == uuid.Nil) {
		return fmt.Errorf("location is required for this department")
	}

	return nil
}

// ==============================================
// PUBLIC SERVICE METHODS
// ==============================================

// func (s *attendanceServiceImpl) CreateAttendanceEvent(
// 	ctx context.Context,
// 	event *attendance.AttendanceEvent,
// 	actorType string,
// 	actorID uuid.UUID,
// 	metadata map[string]interface{},
// ) (*attendance.AttendanceEvent, error) {
// 	startTime := time.Now()

// 	// 1. Validate basic event fields
// 	if event.UserID == uuid.Nil {
// 		return nil, fmt.Errorf("user ID is required")
// 	}
// 	if event.CompanyID == uuid.Nil {
// 		return nil, fmt.Errorf("company ID is required")
// 	}
// 	if event.EventType == "" {
// 		return nil, fmt.Errorf("event type is required")
// 	}
// 	if event.EventTime.IsZero() {
// 		return nil, fmt.Errorf("event time is required")
// 	}
// 	if event.SourceType == "" {
// 		return nil, fmt.Errorf("source type is required")
// 	}

// 	// 2. Validate event type
// 	if err := s.ValidateAttendanceEventType(ctx, event.EventType); err != nil {
// 		return nil, err
// 	}

// 	// 3. Validate source type
// 	if err := s.ValidateAttendanceSourceType(ctx, event.SourceType, event.SourceID); err != nil {
// 		return nil, err
// 	}

// 	// 4. Resolve the day context
// 	dayContext, err := s.resolveAttendanceDay(ctx, event.UserID, event.EventTime, "UTC")
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to resolve attendance day: %w", err)
// 	}

// 	// 5. Validate event against day
// 	if err := s.validateEventAgainstDay(ctx, event, dayContext); err != nil {
// 		return nil, err
// 	}

// 	// 6. Validate against business rules
// 	if err := s.validateEventRules(ctx, event); err != nil {
// 		return nil, err
// 	}

// 	// 7. Create the event
// 	if event.AttendanceEventID == uuid.Nil {
// 		event.AttendanceEventID = uuid.New()
// 	}
// 	if event.CreatedAt.IsZero() {
// 		event.CreatedAt = time.Now().UTC()
// 	}
// 	if event.CreatedBy == nil {
// 		event.CreatedBy = &actorID
// 	}

// 	if err := s.attendanceRepo.CreateAttendanceEvent(ctx, event); err != nil {
// 		s.logger.Error("Failed to create attendance event",
// 			util.String("event_id", event.AttendanceEventID.String()),
// 			util.String("user_id", event.UserID.String()),
// 			util.String("event_type", event.EventType),
// 			util.ErrorField(err))
// 		return nil, fmt.Errorf("failed to create attendance event: %w", err)
// 	}

// 	// 8. Audit log
// 	if s.auditService != nil {
// 		go s.logAuditAction(ctx, event.CompanyID, "attendance_event.create",
// 			event.AttendanceEventID, actorType, actorID, nil, event, metadata)
// 	}

// 	s.logger.Info("Attendance event created",
// 		util.String("event_id", event.AttendanceEventID.String()),
// 		util.String("user_id", event.UserID.String()),
// 		util.String("event_type", event.EventType),
// 		util.String("source_type", event.SourceType),
// 		util.Time("event_time", event.EventTime),
// 		util.Duration("duration", time.Since(startTime)))

// 	return event, nil
// }

func (s *attendanceServiceImpl) CreateBulkAttendanceEvents(
	ctx context.Context,
	events []*attendance.AttendanceEvent,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	if len(events) == 0 {
		return fmt.Errorf("no events provided for bulk creation")
	}

	// Validate and process each event
	validEvents := make([]*attendance.AttendanceEvent, 0, len(events))
	for i, event := range events {
		// Basic validation
		if event.UserID == uuid.Nil || event.CompanyID == uuid.Nil || event.EventType == "" {
			s.logger.Warn("Skipping invalid event in bulk creation",
				util.Int("index", i),
				util.String("user_id", event.UserID.String()),
				util.String("company_id", event.CompanyID.String()),
				util.String("event_type", event.EventType))
			continue
		}

		// Set defaults
		if event.AttendanceEventID == uuid.Nil {
			event.AttendanceEventID = uuid.New()
		}
		if event.CreatedAt.IsZero() {
			event.CreatedAt = time.Now().UTC()
		}
		if event.CreatedBy == nil {
			event.CreatedBy = &actorID
		}

		validEvents = append(validEvents, event)
	}

	if len(validEvents) == 0 {
		return fmt.Errorf("no valid events to create")
	}

	// Create in bulk
	if err := s.attendanceRepo.CreateBulkAttendanceEvents(ctx, validEvents); err != nil {
		s.logger.Error("Failed to create bulk attendance events",
			util.Int("event_count", len(validEvents)),
			util.String("company_id", validEvents[0].CompanyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create bulk attendance events: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			s.auditService.LogAction(auditCtx,
				&validEvents[0].CompanyID,
				"attendance",
				"attendance_event.bulk_create",
				"attendance_event",
				nil,
				actorType,
				&actorID,
				nil,
				nil,
				map[string]interface{}{
					"event_count": len(validEvents),
					"company_id":  validEvents[0].CompanyID.String(),
					"metadata":    metadata,
				})
		}()
	}

	s.logger.Info("Bulk attendance events created",
		util.Int("total_events", len(events)),
		util.Int("created_events", len(validEvents)),
		util.String("company_id", validEvents[0].CompanyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *attendanceServiceImpl) ProcessSAPAttendanceEvent(
	ctx context.Context,
	sapEvent *SAPAttendanceEvent,
	companyID uuid.UUID,
	sourceType string,
	sourceID *uuid.UUID,
) (*attendance.AttendanceEvent, error) {
	startTime := time.Now()

	// 1. Validate SAP event
	if sapEvent.EmployeeID == "" {
		return nil, fmt.Errorf("employee ID is required in SAP event")
	}
	if sapEvent.EventType == "" {
		return nil, fmt.Errorf("event type is required in SAP event")
	}
	if sapEvent.EventTime.IsZero() {
		return nil, fmt.Errorf("event time is required in SAP event")
	}

	// 2. Find user by RFID or other identifiers
	var userID uuid.UUID
	if sapEvent.RFIDTag != "" {
		rfidMapping, err := s.attendanceRepo.GetEmployeeRFIDMapping(ctx, sapEvent.RFIDTag)
		if err != nil {
			return nil, fmt.Errorf("failed to find RFID mapping: %w", err)
		}
		if rfidMapping == nil {
			return nil, fmt.Errorf("no employee found for RFID tag: %s", sapEvent.RFIDTag)
		}
		if rfidMapping.CompanyID != companyID {
			return nil, fmt.Errorf("RFID tag belongs to different company")
		}
		userID = rfidMapping.UserID
	} else {
		// If no RFID, we need another way to identify the employee
		// This would typically involve looking up by employee ID in company_employees
		// For now, we'll return an error
		return nil, fmt.Errorf("RFID tag is required for SAP event processing")
	}

	// 3. Map SAP event to attendance event
	attendanceEvent := &attendance.AttendanceEvent{
		AttendanceEventID: uuid.New(),
		CompanyID:         companyID,
		UserID:            userID,
		EventType:         sapEvent.EventType,
		EventTime:         sapEvent.EventTime,
		SourceType:        sourceType,
		SourceID:          sourceID,
		CreatedAt:         time.Now().UTC(),
		Metadata: attendance.EventMetadata{
			ShiftID:    nil, // Will be resolved later
			Reason:     &sapEvent.ReasonCode,
			LocationID: nil,
		},
	}

	// 4. If work center code is provided, map to shift
	if sapEvent.WorkCenterCode != "" {
		workCenterShift, err := s.attendanceRepo.GetWorkCenterShiftByCode(ctx, companyID, sapEvent.WorkCenterCode)
		if err == nil && workCenterShift != nil {
			attendanceEvent.Metadata.ShiftID = &workCenterShift.ShiftID
		}
	}

	// 5. Create the attendance event using the standard flow
	createdEvent, err := s.CreateAttendanceEvent(ctx, attendanceEvent, "system", uuid.Nil, map[string]interface{}{
		"sap_data":    sapEvent,
		"work_center": sapEvent.WorkCenterCode,
		"source":      "sap_integration",
	})

	if err != nil {
		s.logger.Error("Failed to process SAP attendance event",
			util.String("employee_id", sapEvent.EmployeeID),
			util.String("work_center", sapEvent.WorkCenterCode),
			util.String("event_type", sapEvent.EventType),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to process SAP attendance event: %w", err)
	}

	s.logger.Info("SAP attendance event processed",
		util.String("employee_id", sapEvent.EmployeeID),
		util.String("user_id", userID.String()),
		util.String("event_type", sapEvent.EventType),
		util.String("work_center", sapEvent.WorkCenterCode),
		util.Duration("duration", time.Since(startTime)))

	return createdEvent, nil
}

func (s *attendanceServiceImpl) SyncFactoryAttendance(
	ctx context.Context,
	factoryData *FactoryAttendanceData,
	companyID uuid.UUID,
) error {
	startTime := time.Now()

	if factoryData == nil {
		return fmt.Errorf("factory data is required")
	}

	if factoryData.CompanyID != companyID {
		return fmt.Errorf("factory data company ID mismatch")
	}

	if len(factoryData.Events) == 0 {
		return fmt.Errorf("no events in factory data")
	}

	s.logger.Info("Starting factory attendance sync",
		util.String("company_id", companyID.String()),
		util.String("work_center", factoryData.WorkCenterCode),
		util.Int("event_count", len(factoryData.Events)),
		util.String("source_system", factoryData.SourceSystem))

	// Process events in batches
	batchSize := 100
	successCount := 0
	errorCount := 0

	for i := 0; i < len(factoryData.Events); i += batchSize {
		end := i + batchSize
		if end > len(factoryData.Events) {
			end = len(factoryData.Events)
		}

		batch := factoryData.Events[i:end]

		for _, sapEvent := range batch {
			// Process each SAP event
			_, err := s.ProcessSAPAttendanceEvent(ctx, &sapEvent, companyID, "machine", nil)
			if err != nil {
				errorCount++
				s.logger.Warn("Failed to process factory attendance event",
					util.String("employee_id", sapEvent.EmployeeID),
					util.String("event_type", sapEvent.EventType),
					util.ErrorField(err))
				// Continue with other events
			} else {
				successCount++
			}
		}
	}

	s.logger.Info("Factory attendance sync completed",
		util.String("company_id", companyID.String()),
		util.String("work_center", factoryData.WorkCenterCode),
		util.Int("total_events", len(factoryData.Events)),
		util.Int("success_count", successCount),
		util.Int("error_count", errorCount),
		util.Duration("duration", time.Since(startTime)))

	if errorCount > 0 {
		return fmt.Errorf("factory sync completed with %d errors", errorCount)
	}

	return nil
}

func (s *attendanceServiceImpl) CreateAttendancePolicy(
	ctx context.Context,
	policy *attendance.AttendancePolicy,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*attendance.AttendancePolicy, error) {
	startTime := time.Now()

	// Validate policy
	if policy.CompanyID == uuid.Nil {
		return nil, fmt.Errorf("company ID is required")
	}
	if policy.PolicyCode == "" {
		return nil, fmt.Errorf("policy code is required")
	}
	if policy.PolicyType == "" {
		return nil, fmt.Errorf("policy type is required")
	}

	// Check for duplicate policy code
	existingPolicies, err := s.attendanceRepo.GetAttendancePoliciesByCompany(ctx, policy.CompanyID, false)
	if err == nil {
		for _, existing := range existingPolicies {
			if existing.PolicyCode == policy.PolicyCode {
				return nil, fmt.Errorf("policy with code %s already exists", policy.PolicyCode)
			}
		}
	}

	// Create policy
	if policy.PolicyID == uuid.Nil {
		policy.PolicyID = uuid.New()
	}

	now := time.Now().UTC()
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}
	policy.UpdatedAt = now

	if err := s.attendanceRepo.CreateAttendancePolicy(ctx, policy); err != nil {
		s.logger.Error("Failed to create attendance policy",
			util.String("company_id", policy.CompanyID.String()),
			util.String("policy_code", policy.PolicyCode),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create attendance policy: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		go s.logAuditAction(ctx, policy.CompanyID, "attendance_policy.create",
			policy.PolicyID, actorType, actorID, nil, policy, metadata)
	}

	s.logger.Info("Attendance policy created",
		util.String("policy_id", policy.PolicyID.String()),
		util.String("company_id", policy.CompanyID.String()),
		util.String("policy_code", policy.PolicyCode),
		util.String("policy_type", policy.PolicyType),
		util.Duration("duration", time.Since(startTime)))

	return policy, nil
}

func (s *attendanceServiceImpl) AssignUserAttendancePolicy(
	ctx context.Context,
	userPolicy *attendance.UserAttendancePolicy,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	if userPolicy.UserID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}
	if userPolicy.PolicyID == uuid.Nil {
		return fmt.Errorf("policy ID is required")
	}
	if userPolicy.EffectiveFrom.IsZero() {
		userPolicy.EffectiveFrom = time.Now().UTC()
	}

	// Verify policy exists and is active
	policy, err := s.attendanceRepo.GetAttendancePolicyByID(ctx, userPolicy.PolicyID)
	if err != nil {
		return fmt.Errorf("failed to get attendance policy: %w", err)
	}
	if policy == nil {
		return fmt.Errorf("attendance policy not found")
	}
	if !policy.IsActive {
		return fmt.Errorf("attendance policy is not active")
	}

	// End any existing active policy for the user
	existingPolicy, err := s.attendanceRepo.GetUserActiveAttendancePolicy(ctx, userPolicy.UserID, time.Now())
	if err == nil && existingPolicy != nil {
		if existingPolicy.PolicyID == userPolicy.PolicyID {
			// User already has this policy active
			return nil
		}

		// End the previous policy
		if err := s.attendanceRepo.EndUserAttendancePolicy(ctx, userPolicy.UserID, existingPolicy.PolicyID, userPolicy.EffectiveFrom); err != nil {
			s.logger.Warn("Failed to end previous attendance policy",
				util.String("user_id", userPolicy.UserID.String()),
				util.String("policy_id", existingPolicy.PolicyID.String()),
				util.ErrorField(err))
		}
	}

	// Assign new policy
	if userPolicy.AssignedBy == nil {
		userPolicy.AssignedBy = &actorID
	}
	if userPolicy.CreatedAt.IsZero() {
		userPolicy.CreatedAt = time.Now().UTC()
	}

	if err := s.attendanceRepo.AssignUserAttendancePolicy(ctx, userPolicy); err != nil {
		s.logger.Error("Failed to assign user attendance policy",
			util.String("user_id", userPolicy.UserID.String()),
			util.String("policy_id", userPolicy.PolicyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to assign user attendance policy: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		go s.logAuditAction(ctx, policy.CompanyID, "user_attendance_policy.assign",
			userPolicy.PolicyID, actorType, actorID, nil, userPolicy, metadata)
	}

	s.logger.Info("User attendance policy assigned",
		util.String("user_id", userPolicy.UserID.String()),
		util.String("policy_id", userPolicy.PolicyID.String()),
		util.String("policy_code", policy.PolicyCode),
		util.Time("effective_from", userPolicy.EffectiveFrom),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *attendanceServiceImpl) GenerateBulkDailySummaries(
	ctx context.Context,
	companyID uuid.UUID,
	timezone string,
	startDate, endDate time.Time,
) ([]*attendance.AttendanceDailySummary, error) {

	if startDate.After(endDate) {
		return nil, fmt.Errorf("start date cannot be after end date")
	}

	maxDays := 31
	if endDate.Sub(startDate).Hours()/24 > float64(maxDays) {
		return nil, fmt.Errorf("date range cannot exceed %d days", maxDays)
	}

	// ⚠️ TEMP: get users from summaries/events (safe fallback)
	userIDs, err := s.attendanceRepo.GetDistinctUsersWithEvents(
		ctx,
		companyID,
		startDate,
		endDate,
	)
	if err != nil {
		return nil, err
	}

	var summaries []*attendance.AttendanceDailySummary

	for _, userID := range userIDs {
		for d := startDate; !d.After(endDate); d = d.AddDate(0, 0, 1) {
			summary, err := s.GenerateDailySummary(ctx, companyID, userID, d, timezone)
			if err != nil {
				s.logger.Error("Failed bulk daily summary",
					util.String("user_id", userID.String()),
					util.Time("date", d),
					util.ErrorField(err))
				continue
			}
			summaries = append(summaries, summary)
		}
	}

	return summaries, nil
}

func (s *attendanceServiceImpl) AssignRFIDToEmployee(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	rfidTag string,
	assignedBy uuid.UUID,
) error {
	startTime := time.Now()

	if rfidTag == "" {
		return fmt.Errorf("RFID tag is required")
	}

	// Check if RFID is already assigned to another active employee
	existingMapping, err := s.attendanceRepo.GetEmployeeRFIDMapping(ctx, rfidTag)
	if err != nil {
		return fmt.Errorf("failed to check RFID mapping: %w", err)
	}

	if existingMapping != nil && existingMapping.UserID != userID && existingMapping.IsActive {
		return fmt.Errorf("RFID tag %s is already assigned to another employee", rfidTag)
	}

	// Deactivate any existing active mapping for this user
	userMapping, err := s.attendanceRepo.GetEmployeeRFIDMappingByUser(ctx, userID)
	if err == nil && userMapping != nil && userMapping.IsActive {
		if err := s.attendanceRepo.DeactivateEmployeeRFIDMapping(ctx, userMapping.RFIDID); err != nil {
			s.logger.Warn("Failed to deactivate existing RFID mapping",
				util.String("user_id", userID.String()),
				util.String("rfid_tag", userMapping.RFIDTag),
				util.ErrorField(err))
		}
	}

	// Create new mapping
	mapping := &attendance.EmployeeRFIDMapping{
		RFIDID:     uuid.New(),
		UserID:     userID,
		CompanyID:  companyID,
		RFIDTag:    rfidTag,
		IsActive:   true,
		AssignedAt: time.Now().UTC(),
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}

	if err := s.attendanceRepo.CreateEmployeeRFIDMapping(ctx, mapping); err != nil {
		s.logger.Error("Failed to assign RFID to employee",
			util.String("user_id", userID.String()),
			util.String("rfid_tag", rfidTag),
			util.ErrorField(err))
		return fmt.Errorf("failed to assign RFID to employee: %w", err)
	}

	s.logger.Info("RFID assigned to employee",
		util.String("user_id", userID.String()),
		util.String("rfid_tag", rfidTag),
		util.String("company_id", companyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *attendanceServiceImpl) UnassignRFID(
	ctx context.Context,
	rfidID uuid.UUID,
	unassignedBy uuid.UUID,
) error {
	startTime := time.Now()

	mapping, err := s.attendanceRepo.GetAttendanceSourceByID(ctx, rfidID)
	if err != nil {
		return fmt.Errorf("failed to get RFID mapping: %w", err)
	}
	if mapping == nil {
		return fmt.Errorf("RFID mapping not found")
	}

	if err := s.attendanceRepo.DeactivateEmployeeRFIDMapping(ctx, rfidID); err != nil {
		s.logger.Error("Failed to unassign RFID",
			util.String("rfid_id", rfidID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to unassign RFID: %w", err)
	}

	s.logger.Info("RFID unassigned",
		util.String("rfid_id", rfidID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *attendanceServiceImpl) GetEmployeeByRFID(
	ctx context.Context,
	rfidTag string,
	companyID uuid.UUID,
) (*attendance.EmployeeRFIDMapping, error) {
	mapping, err := s.attendanceRepo.GetEmployeeRFIDMapping(ctx, rfidTag)
	if err != nil {
		return nil, fmt.Errorf("failed to get employee by RFID: %w", err)
	}

	if mapping == nil {
		return nil, nil
	}

	// Verify the mapping belongs to the requested company
	if mapping.CompanyID != companyID {
		return nil, fmt.Errorf("RFID tag does not belong to this company")
	}

	if !mapping.IsActive {
		return nil, fmt.Errorf("RFID mapping is not active")
	}

	return mapping, nil
}

func (s *attendanceServiceImpl) MapWorkCenterToShift(
	ctx context.Context,
	companyID uuid.UUID,
	workCenterCode string,
	shiftID uuid.UUID,
	effectiveFrom time.Time,
	effectiveTo *time.Time,
	createdBy uuid.UUID,
) error {
	startTime := time.Now()

	if workCenterCode == "" {
		return fmt.Errorf("work center code is required")
	}
	if shiftID == uuid.Nil {
		return fmt.Errorf("shift ID is required")
	}
	if effectiveFrom.IsZero() {
		effectiveFrom = time.Now().UTC()
	}

	// Check for overlapping mappings
	existingMappings, err := s.attendanceRepo.GetWorkCenterShiftsByCompany(ctx, companyID, true)
	if err == nil {
		for _, existing := range existingMappings {
			if existing.WorkCenterCode == workCenterCode && existing.IsActive {
				// Check for overlap
				existingTo := time.Now().AddDate(100, 0, 0) // Far future
				if existing.EffectiveTo != nil {
					existingTo = *existing.EffectiveTo
				}

				newTo := time.Now().AddDate(100, 0, 0)
				if effectiveTo != nil {
					newTo = *effectiveTo
				}

				if effectiveFrom.Before(newTo) && existing.EffectiveFrom.Before(existingTo) {
					// Overlap detected, deactivate existing
					if err := s.attendanceRepo.DeactivateWorkCenterShift(ctx, existing.MappingID); err != nil {
						s.logger.Warn("Failed to deactivate overlapping work center shift",
							util.String("mapping_id", existing.MappingID.String()),
							util.ErrorField(err))
					}
				}
			}
		}
	}

	// Create new mapping
	mapping := &attendance.WorkCenterShift{
		MappingID:      uuid.New(),
		CompanyID:      companyID,
		WorkCenterCode: workCenterCode,
		ShiftID:        shiftID,
		EffectiveFrom:  effectiveFrom,
		EffectiveTo:    effectiveTo,
		IsActive:       true,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}

	if err := s.attendanceRepo.CreateWorkCenterShift(ctx, mapping); err != nil {
		s.logger.Error("Failed to map work center to shift",
			util.String("company_id", companyID.String()),
			util.String("work_center_code", workCenterCode),
			util.String("shift_id", shiftID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to map work center to shift: %w", err)
	}

	s.logger.Info("Work center mapped to shift",
		util.String("company_id", companyID.String()),
		util.String("work_center_code", workCenterCode),
		util.String("shift_id", shiftID.String()),
		util.Time("effective_from", effectiveFrom),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *attendanceServiceImpl) GetShiftForWorkCenter(
	ctx context.Context,
	workCenterCode string,
	companyID uuid.UUID,
) (*attendance.WorkCenterShift, error) {
	mapping, err := s.attendanceRepo.GetWorkCenterShiftByCode(ctx, companyID, workCenterCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get shift for work center: %w", err)
	}
	return mapping, nil
}

func (s *attendanceServiceImpl) GetAttendanceEventType(
	ctx context.Context,
	eventType string,
) (*attendance.AttendanceEventType, error) {
	eventTypes, err := s.attendanceRepo.GetAttendanceEventTypes(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance event types: %w", err)
	}

	for _, et := range eventTypes {
		if et.EventType == eventType {
			return et, nil
		}
	}

	return nil, fmt.Errorf("attendance event type %s not found", eventType)
}

func (s *attendanceQueryServiceImpl) ListAttendanceEventTypes(
	ctx context.Context,
	activeOnly bool,
) ([]*attendance.AttendanceEventType, error) {
	eventTypes, err := s.attendanceRepo.GetAttendanceEventTypes(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance event types: %w", err)
	}

	if activeOnly {
		var activeTypes []*attendance.AttendanceEventType
		for _, et := range eventTypes {
			if et.IsActive {
				activeTypes = append(activeTypes, et)
			}
		}
		return activeTypes, nil
	}

	return eventTypes, nil
}

func (s *attendanceServiceImpl) GetAttendanceSourceType(
	ctx context.Context,
	sourceType string,
) (*attendance.AttendanceSourceType, error) {
	sourceTypes, err := s.attendanceRepo.GetAttendanceSourceTypes(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance source types: %w", err)
	}

	for _, st := range sourceTypes {
		if st.SourceType == sourceType {
			return st, nil
		}
	}

	return nil, fmt.Errorf("attendance source type %s not found", sourceType)
}

func (qs *attendanceQueryServiceImpl) ListAttendanceSourceTypes(
	ctx context.Context,
) ([]*attendance.AttendanceSourceType, error) {
	sourceTypes, err := qs.attendanceRepo.GetAttendanceSourceTypes(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance source types: %w", err)
	}
	return sourceTypes, nil
}

func (s *attendanceServiceImpl) GetCompanyAttendanceRules(
	ctx context.Context,
	companyID uuid.UUID,
) (*attendance.CompanyAttendanceRules, error) {
	rules, err := s.attendanceRepo.GetCompanyAttendanceRules(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get company attendance rules: %w", err)
	}
	return rules, nil
}

func (s *attendanceServiceImpl) UpdateCompanyAttendanceRules(
	ctx context.Context,
	rules *attendance.CompanyAttendanceRules,
	updatedBy uuid.UUID,
) error {

	if rules == nil {
		return fmt.Errorf("company attendance rules are required")
	}
	if rules.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}

	// --------------------------------------------
	// 1️⃣ Load valid source types from DB
	// --------------------------------------------
	sourceTypes, err := s.attendanceRepo.GetAttendanceSourceTypes(ctx)
	if err != nil {
		return fmt.Errorf("failed to load attendance source types: %w", err)
	}

	validSources := make(map[string]struct{}, len(sourceTypes))
	for _, st := range sourceTypes {
		validSources[st.SourceType] = struct{}{}
	}

	// --------------------------------------------
	// 2️⃣ Validate & normalize input
	// --------------------------------------------
	if len(rules.AllowedSourceTypes) == 0 {
		// default
		rules.AllowedSourceTypes = []string{"mobile", "web", "biometric", "rfid"}
	} else {
		seen := make(map[string]struct{})
		validated := make([]string, 0, len(rules.AllowedSourceTypes))

		for _, src := range rules.AllowedSourceTypes {
			src = normalizeSourceType(src)

			if _, ok := validSources[src]; !ok {
				return fmt.Errorf("invalid attendance source type: %s", src)
			}

			if _, exists := seen[src]; !exists {
				seen[src] = struct{}{}
				validated = append(validated, src)
			}
		}

		rules.AllowedSourceTypes = validated
	}

	// --------------------------------------------
	// 3️⃣ Defaults & persistence
	// --------------------------------------------
	if rules.Timezone == "" {
		rules.Timezone = "UTC"
	}
	if rules.CreatedAt.IsZero() {
		rules.CreatedAt = time.Now().UTC()
	}

	if err := s.attendanceRepo.UpsertCompanyAttendanceRules(ctx, rules); err != nil {
		s.logger.Error("Failed to update company attendance rules",
			util.String("company_id", rules.CompanyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update company attendance rules: %w", err)
	}

	s.logger.Info("Company attendance rules updated",
		util.String("company_id", rules.CompanyID.String()),
		util.String("updated_by", updatedBy.String()))

	return nil
}

func (s *attendanceServiceImpl) GetDepartmentAttendanceRules(
	ctx context.Context,
	companyID, departmentID uuid.UUID,
) (*attendance.DepartmentAttendanceRules, error) {
	rules, err := s.attendanceRepo.GetDepartmentAttendanceRules(ctx, companyID, departmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to get department attendance rules: %w", err)
	}
	return rules, nil
}

func (s *attendanceServiceImpl) GetUserAttendanceProfile(
	ctx context.Context,
	userID uuid.UUID,
) (*attendance.UserAttendanceProfile, error) {
	profile, err := s.attendanceRepo.GetUserAttendanceProfile(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user attendance profile: %w", err)
	}
	return profile, nil
}

func (s *attendanceServiceImpl) ResolveAttendanceRules(
	ctx context.Context,
	userID, companyID, departmentID uuid.UUID,
) (*attendance.ResolvedAttendanceRules, error) {
	resolved := &attendance.ResolvedAttendanceRules{
		AllowedSourceTypesMap: make(map[string]bool),
		AllowedEventTypesMap:  make(map[string]bool),
		AppliedAt:             time.Now().UTC(),
	}

	// 1. Get company-level rules (always applied)
	companyRules, err := s.attendanceRepo.GetCompanyAttendanceRules(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get company attendance rules: %w", err)
	}

	resolved.CompanyID = companyID
	resolved.Timezone = companyRules.Timezone
	resolved.AllowMultipleCheckins = companyRules.AllowMultipleCheckins
	resolved.AllowedSourceTypes = companyRules.AllowedSourceTypes

	// Build source types map
	for _, sourceType := range companyRules.AllowedSourceTypes {
		resolved.AllowedSourceTypesMap[sourceType] = true
	}

	// 2. Get department-level rules (if department provided)
	if departmentID != uuid.Nil {
		deptRules, err := s.attendanceRepo.GetDepartmentAttendanceRules(ctx, companyID, departmentID)
		if err == nil && deptRules != nil {
			resolved.RequireLocation = deptRules.RequireLocation
			resolved.RequireDevice = deptRules.RequireDevice
			resolved.SourceLevel = "department"

			// If department has source types, they override company ones
			if len(deptRules.AllowedSourceTypes) > 0 {
				resolved.AllowedSourceTypes = deptRules.AllowedSourceTypes
				resolved.AllowedSourceTypesMap = make(map[string]bool)
				for _, sourceType := range deptRules.AllowedSourceTypes {
					resolved.AllowedSourceTypesMap[sourceType] = true
				}
			}

			// Set allowed event types
			if len(deptRules.AllowedEventTypes) > 0 {
				resolved.AllowedEventTypes = deptRules.AllowedEventTypes
				for _, eventType := range deptRules.AllowedEventTypes {
					resolved.AllowedEventTypesMap[eventType] = true
				}
			} else {
				resolved.AllowAllEventTypes = true
			}
		}
	}

	// 3. Get user-level overrides (if user provided)
	if userID != uuid.Nil {
		userProfile, err := s.attendanceRepo.GetUserAttendanceProfile(ctx, userID)
		if err == nil && userProfile != nil {
			resolved.SourceLevel = "user"

			// User source types override department/company
			if userProfile.OverrideSourceTypes != nil && len(userProfile.OverrideSourceTypes) > 0 {
				resolved.AllowedSourceTypes = userProfile.OverrideSourceTypes
				resolved.AllowedSourceTypesMap = make(map[string]bool)
				for _, sourceType := range userProfile.OverrideSourceTypes {
					resolved.AllowedSourceTypesMap[sourceType] = true
				}
			}

			// User event types override department
			if userProfile.OverrideEventTypes != nil && len(userProfile.OverrideEventTypes) > 0 {
				resolved.AllowedEventTypes = userProfile.OverrideEventTypes
				resolved.AllowedEventTypesMap = make(map[string]bool)
				for _, eventType := range userProfile.OverrideEventTypes {
					resolved.AllowedEventTypesMap[eventType] = true
				}
				resolved.AllowAllEventTypes = false
			}
		}
	}

	// 4. If no event types specified at any level, allow all
	if len(resolved.AllowedEventTypes) == 0 {
		resolved.AllowAllEventTypes = true
	}

	// 5. Set reference requirement based on source type
	// This would typically involve checking the source type definition
	// For now, we'll set a default
	resolved.RequireReference = false

	return resolved, nil
}
func (s *attendanceServiceImpl) ValidateAttendanceEventType(
	ctx context.Context,
	eventType string,
) error {
	eventTypes, err := s.attendanceRepo.GetAttendanceEventTypes(ctx)
	if err != nil {
		return fmt.Errorf("failed to validate attendance event type: %w", err)
	}

	for _, et := range eventTypes {
		if et.EventType == eventType && et.IsActive {
			return nil
		}
	}

	return fmt.Errorf("invalid or inactive attendance event type: %s", eventType)
}

func (s *attendanceServiceImpl) ValidateAttendanceSourceType(
	ctx context.Context,
	sourceType string,
	sourceID *uuid.UUID,
) error {
	sourceTypeDef, err := s.GetAttendanceSourceType(ctx, sourceType)
	if err != nil {
		return fmt.Errorf("failed to validate attendance source type: %w", err)
	}

	// Check if reference is required but not provided
	if sourceTypeDef.RequiresReference && (sourceID == nil || *sourceID == uuid.Nil) {
		return fmt.Errorf("source reference is required for source type %s", sourceType)
	}

	return nil
}

func (s *attendanceServiceImpl) ValidateEventAgainstRules(
	ctx context.Context,
	event *attendance.AttendanceEvent,
	rules *attendance.ResolvedAttendanceRules,
) error {
	// This is already implemented in validateEventRules
	return s.validateEventRules(ctx, event)
}

func (s *attendanceServiceImpl) CompleteSAPAttendanceFlow(
	ctx context.Context,
	sapEvent *SAPAttendanceEvent,
	companyID uuid.UUID,
) error {
	// This is essentially the same as ProcessSAPAttendanceEvent
	_, err := s.ProcessSAPAttendanceEvent(ctx, sapEvent, companyID, "system", nil)
	return err
}

func (s *attendanceServiceImpl) UpsertDepartmentAttendanceRules(
	ctx context.Context,
	rules *attendance.DepartmentAttendanceRules,
) error {
	if rules == nil {
		return fmt.Errorf("department attendance rules are required")
	}

	if rules.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}

	if rules.DepartmentID == uuid.Nil {
		return fmt.Errorf("department ID is required")
	}

	// --------------------------------------------------
	// 1. Load company attendance rules
	// --------------------------------------------------
	companyRules, err := s.attendanceRepo.GetCompanyAttendanceRules(ctx, rules.CompanyID)
	if err != nil {
		return fmt.Errorf("failed to load company attendance rules: %w", err)
	}

	// Build company source type map
	companySourceMap := make(map[string]bool, len(companyRules.AllowedSourceTypes))
	for _, src := range companyRules.AllowedSourceTypes {
		companySourceMap[src] = true
	}

	// --------------------------------------------------
	// 2. Validate allowed_source_types
	// --------------------------------------------------
	for _, src := range rules.AllowedSourceTypes {
		if !companySourceMap[src] {
			return fmt.Errorf(
				"invalid source type '%s': not allowed by company",
				src,
			)
		}
	}

	// --------------------------------------------------
	// 3. Validate allowed_event_types
	// --------------------------------------------------
	for _, eventType := range rules.AllowedEventTypes {
		if !validAttendanceEventTypes[eventType] {
			return fmt.Errorf(
				"invalid event type '%s': not a supported attendance event",
				eventType,
			)
		}
	}

	// --------------------------------------------------
	// 4. Persist rules
	// --------------------------------------------------
	if err := s.attendanceRepo.UpsertDepartmentAttendanceRules(ctx, rules); err != nil {
		s.logger.Error(
			"Failed to upsert department attendance rules",
			util.String("company_id", rules.CompanyID.String()),
			util.String("department_id", rules.DepartmentID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to upsert department attendance rules: %w", err)
	}

	s.logger.Info(
		"Department attendance rules upserted",
		util.String("company_id", rules.CompanyID.String()),
		util.String("department_id", rules.DepartmentID.String()),
	)

	return nil
}

func (s *attendanceServiceImpl) UpsertUserAttendanceProfile(
	ctx context.Context,
	profile *attendance.UserAttendanceProfile,
) error {
	if profile == nil {
		return fmt.Errorf("user attendance profile is required")
	}

	if profile.UserID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}

	if profile.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}

	if profile.CreatedAt.IsZero() {
		profile.CreatedAt = time.Now().UTC()
	}

	if err := s.attendanceRepo.UpsertUserAttendanceProfile(ctx, profile); err != nil {
		s.logger.Error("Failed to upsert user attendance profile",
			util.String("user_id", profile.UserID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to upsert user attendance profile: %w", err)
	}

	s.logger.Info("User attendance profile upserted",
		util.String("user_id", profile.UserID.String()),
		util.String("company_id", profile.CompanyID.String()))

	return nil
}

func (s *attendanceServiceImpl) HealthCheck(ctx context.Context) error {
	if err := s.attendanceRepo.HealthCheck(ctx); err != nil {
		return fmt.Errorf("attendance repository health check failed: %w", err)
	}
	return nil
}

// ==============================================
// HELPER METHODS
// ==============================================

func (s *attendanceServiceImpl) logAuditAction(
	ctx context.Context,
	companyID uuid.UUID,
	action string,
	resourceID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	beforeState, afterState interface{},
	metadata map[string]interface{},
) {
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			var beforeJSON, afterJSON []byte
			if beforeState != nil {
				beforeJSON, _ = json.Marshal(beforeState)
			}
			if afterState != nil {
				afterJSON, _ = json.Marshal(afterState)
			}

			s.auditService.LogAction(auditCtx,
				&companyID,
				"attendance",
				action,
				strings.Split(action, ".")[0],
				&resourceID,
				actorType,
				&actorID,
				beforeJSON,
				afterJSON,
				metadata,
			)
		}()
	}
}

// Helper functions for pointer creation
func intPtr(i int) *int {
	return &i
}

func boolPtr(b bool) *bool {
	return &b
}

// ==============================================
// ATTENDANCE QUERY SERVICE IMPLEMENTATION
// ==============================================

type attendanceQueryServiceImpl struct {
	attendanceRepo repository.AttendanceRepository
	logger         *zap.Logger
}

func NewAttendanceQueryService(
	attendanceRepo repository.AttendanceRepository,
	logger *zap.Logger,
) AttendanceQueryService {
	return &attendanceQueryServiceImpl{
		attendanceRepo: attendanceRepo,
		logger:         logger,
	}
}

func (qs *attendanceQueryServiceImpl) GetAttendanceEventByID(
	ctx context.Context,
	eventID uuid.UUID,
) (*attendance.AttendanceEvent, error) {
	startTime := time.Now()

	event, err := qs.attendanceRepo.GetAttendanceEventByID(ctx, eventID)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance event: %w", err)
	}

	qs.logger.Debug("Attendance event retrieved by ID",
		util.String("event_id", eventID.String()),
		util.Duration("duration", time.Since(startTime)))

	return event, nil
}

func (qs *attendanceQueryServiceImpl) GetAttendanceEventsByUser(
	ctx context.Context,
	userID uuid.UUID,
	startDate, endDate time.Time,
	limit int,
) ([]*attendance.AttendanceEvent, error) {
	startTime := time.Now()

	// Validate date range
	if startDate.After(endDate) {
		return nil, fmt.Errorf("start date cannot be after end date")
	}

	maxDays := 90
	if endDate.Sub(startDate).Hours()/24 > float64(maxDays) {
		return nil, fmt.Errorf("date range cannot exceed %d days", maxDays)
	}

	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	events, err := qs.attendanceRepo.GetAttendanceEventsByUser(ctx, userID, startDate, endDate, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance events by user: %w", err)
	}

	qs.logger.Debug("Attendance events retrieved by user",
		util.String("user_id", userID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("limit", limit),
		util.Int("event_count", len(events)),
		util.Duration("duration", time.Since(startTime)))

	return events, nil
}

func (qs *attendanceQueryServiceImpl) GetAttendanceEventsByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
	page, pageSize int,
) ([]*attendance.AttendanceEvent, int, error) {
	startTime := time.Now()

	// Validate parameters
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}

	maxDays := 31
	if endDate.Sub(startDate).Hours()/24 > float64(maxDays) {
		return nil, 0, fmt.Errorf("date range cannot exceed %d days", maxDays)
	}

	events, total, err := qs.attendanceRepo.GetAttendanceEventsByCompany(ctx, companyID, startDate, endDate, page, pageSize)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get attendance events by company: %w", err)
	}

	totalPages := (int(total) + pageSize - 1) / pageSize

	qs.logger.Debug("Attendance events retrieved by company",
		util.String("company_id", companyID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("page", page),
		util.Int("page_size", pageSize),
		util.Int("total_events", int(total)),
		util.Int("total_pages", totalPages),
		util.Int("returned_events", len(events)),
		util.Duration("duration", time.Since(startTime)))

	return events, int(total), nil
}

func (qs *attendanceQueryServiceImpl) SearchAttendanceEvents(
	ctx context.Context,
	companyID uuid.UUID,
	filters map[string]interface{},
	page, pageSize int,
) ([]*attendance.AttendanceEvent, int, error) {
	_ = time.Now()

	// Convert map filters to typed filter
	typedFilter := AttendanceSearchFilters{
		CompanyID: companyID,
	}

	// Parse filters from map (this is a simplified version)
	if userID, ok := filters["user_id"].(uuid.UUID); ok {
		typedFilter.UserID = &userID
	}
	if startDate, ok := filters["start_date"].(time.Time); ok {
		typedFilter.StartDate = startDate
	}
	if endDate, ok := filters["end_date"].(time.Time); ok {
		typedFilter.EndDate = endDate
	}
	if eventType, ok := filters["event_type"].(string); ok {
		typedFilter.EventType = &eventType
	}
	if sourceType, ok := filters["source_type"].(string); ok {
		typedFilter.SourceType = &sourceType
	}

	return qs.SearchAttendanceEventsTyped(ctx, companyID, typedFilter, page, pageSize)
}

func (qs *attendanceQueryServiceImpl) SearchAttendanceEventsTyped(
	ctx context.Context,
	companyID uuid.UUID,
	filters AttendanceSearchFilters,
	page, pageSize int,
) ([]*attendance.AttendanceEvent, int, error) {
	startTime := time.Now()

	// Validate parameters
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}

	// Validate date range
	if filters.StartDate.IsZero() {
		filters.StartDate = time.Now().AddDate(0, 0, -30) // Default to last 30 days
	}
	if filters.EndDate.IsZero() {
		filters.EndDate = time.Now()
	}
	if filters.StartDate.After(filters.EndDate) {
		return nil, 0, fmt.Errorf("start date cannot be after end date")
	}

	maxDays := 90
	if filters.EndDate.Sub(filters.StartDate).Hours()/24 > float64(maxDays) {
		return nil, 0, fmt.Errorf("date range cannot exceed %d days", maxDays)
	}

	// Convert to repository filter
	repoFilter := repository.AttendanceEventFilter{
		CompanyID:  companyID,
		UserID:     filters.UserID,
		StartDate:  filters.StartDate,
		EndDate:    filters.EndDate,
		EventType:  filters.EventType,
		SourceType: filters.SourceType,
		Page:       page,
		PageSize:   pageSize,
	}

	events, total, err := qs.attendanceRepo.SearchAttendanceEvents(ctx, repoFilter)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search attendance events: %w", err)
	}

	totalPages := (int(total) + pageSize - 1) / pageSize

	qs.logger.Debug("Attendance events searched",
		util.String("company_id", companyID.String()),
		util.Time("start_date", filters.StartDate),
		util.Time("end_date", filters.EndDate),
		util.Int("page", page),
		util.Int("page_size", pageSize),
		util.Int("total_events", int(total)),
		util.Int("total_pages", totalPages),
		util.Int("returned_events", len(events)),
		util.Duration("duration", time.Since(startTime)))

	return events, int(total), nil
}

func (qs *attendanceQueryServiceImpl) GetAttendancePolicyByID(
	ctx context.Context,
	policyID uuid.UUID,
) (*attendance.AttendancePolicy, error) {
	startTime := time.Now()

	policy, err := qs.attendanceRepo.GetAttendancePolicyByID(ctx, policyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance policy: %w", err)
	}

	qs.logger.Debug("Attendance policy retrieved by ID",
		util.String("policy_id", policyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return policy, nil
}

func (qs *attendanceQueryServiceImpl) GetAttendancePoliciesByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	activeOnly bool,
) ([]*attendance.AttendancePolicy, error) {
	startTime := time.Now()

	policies, err := qs.attendanceRepo.GetAttendancePoliciesByCompany(ctx, companyID, activeOnly)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance policies by company: %w", err)
	}

	qs.logger.Debug("Attendance policies retrieved by company",
		util.String("company_id", companyID.String()),
		util.Bool("active_only", activeOnly),
		util.Int("policy_count", len(policies)),
		util.Duration("duration", time.Since(startTime)))

	return policies, nil
}

func (qs *attendanceQueryServiceImpl) GetUserCurrentAttendancePolicy(
	ctx context.Context,
	userID uuid.UUID,
	date time.Time,
) (*attendance.AttendancePolicy, error) {
	startTime := time.Now()

	if date.IsZero() {
		date = time.Now()
	}

	policy, err := qs.attendanceRepo.GetUserActiveAttendancePolicy(ctx, userID, date)
	if err != nil {
		return nil, fmt.Errorf("failed to get user current attendance policy: %w", err)
	}

	qs.logger.Debug("User current attendance policy retrieved",
		util.String("user_id", userID.String()),
		util.Time("date", date),
		util.Duration("duration", time.Since(startTime)))

	return policy, nil
}

func (qs *attendanceQueryServiceImpl) GetAttendanceDailySummaryByUserDate(
	ctx context.Context,
	userID uuid.UUID,
	date time.Time,
) (*attendance.AttendanceDailySummary, error) {
	startTime := time.Now()

	summary, err := qs.attendanceRepo.GetAttendanceDailySummaryByUserDate(ctx, userID, date)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance daily summary: %w", err)
	}

	qs.logger.Debug("Attendance daily summary retrieved",
		util.String("user_id", userID.String()),
		util.String("date", date.Format("2006-01-02")),
		util.Duration("duration", time.Since(startTime)))

	return summary, nil
}

func (qs *attendanceQueryServiceImpl) GetAttendanceDailySummariesByUser(
	ctx context.Context,
	userID uuid.UUID,
	startDate, endDate time.Time,
) ([]*attendance.AttendanceDailySummary, error) {
	startTime := time.Now()

	// Validate date range
	if startDate.After(endDate) {
		return nil, fmt.Errorf("start date cannot be after end date")
	}

	maxDays := 365
	if endDate.Sub(startDate).Hours()/24 > float64(maxDays) {
		return nil, fmt.Errorf("date range cannot exceed %d days", maxDays)
	}

	summaries, err := qs.attendanceRepo.GetAttendanceDailySummariesByUser(ctx, userID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance daily summaries: %w", err)
	}

	qs.logger.Debug("Attendance daily summaries retrieved",
		util.String("user_id", userID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("summary_count", len(summaries)),
		util.Duration("duration", time.Since(startTime)))

	return summaries, nil
}

func (qs *attendanceQueryServiceImpl) GetAttendanceSummaryStats(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) (*AttendanceSummaryStats, error) {
	startTime := time.Now()

	// Validate date range
	if startDate.After(endDate) {
		return nil, fmt.Errorf("start date cannot be after end date")
	}

	maxDays := 31
	if endDate.Sub(startDate).Hours()/24 > float64(maxDays) {
		return nil, fmt.Errorf("date range cannot exceed %d days", maxDays)
	}

	// Get stats from repository
	stats, err := qs.attendanceRepo.GetAttendanceStats(ctx, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance stats: %w", err)
	}

	// Convert to summary stats format
	summaryStats := &AttendanceSummaryStats{
		CompanyID:      companyID,
		StartDate:      startDate,
		EndDate:        endDate,
		TotalEmployees: stats.TotalEmployees,
		SummaryByStatus: map[string]int{
			"present":  stats.PresentCount,
			"absent":   stats.AbsentCount,
			"late":     stats.LateCount,
			"half_day": stats.HalfDayCount,
			"leave":    stats.LeaveCount,
			"holiday":  stats.HolidayCount,
		},
		AverageHours:        stats.TotalWorkedHours,
		OvertimeHours:       stats.TotalOvertimeHours,
		LateArrivals:        stats.LateCount,
		TopLateEmployees:    []LateEmployeeSummary{},
		DepartmentBreakdown: map[string]DepartmentStats{},
	}

	qs.logger.Debug("Attendance summary stats retrieved",
		util.String("company_id", companyID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("total_employees", stats.TotalEmployees),
		util.Int("present_count", stats.PresentCount),
		util.Int("late_count", stats.LateCount),
		util.Float64("average_attendance", stats.AverageAttendance),
		util.Duration("duration", time.Since(startTime)))

	return summaryStats, nil
}

func (qs *attendanceQueryServiceImpl) GenerateAttendanceReport(
	ctx context.Context,
	companyID uuid.UUID,
	reportType string,
	startDate, endDate time.Time,
) ([]byte, string, error) {
	startTime := time.Now()

	// Validate parameters
	if reportType != "csv" && reportType != "json" {
		return nil, "", fmt.Errorf("unsupported report type: %s. Supported types: csv, json", reportType)
	}

	maxDays := 31
	if endDate.Sub(startDate).Hours()/24 > float64(maxDays) {
		return nil, "", fmt.Errorf("date range cannot exceed %d days", maxDays)
	}

	// Get summaries for the date range
	summaries, _, err := qs.attendanceRepo.GetAttendanceDailySummariesByCompany(ctx, companyID, startDate, endDate, 1, 10000)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get attendance summaries: %w", err)
	}

	var reportData []byte
	var contentType string

	switch reportType {
	case "csv":
		reportData, err = qs.generateCSVReport(summaries)
		contentType = "text/csv"
	case "json":
		reportData, err = qs.generateJSONReport(summaries)
		contentType = "application/json"
	}

	if err != nil {
		return nil, "", fmt.Errorf("failed to generate %s report: %w", reportType, err)
	}

	qs.logger.Info("Attendance report generated",
		util.String("company_id", companyID.String()),
		util.String("report_type", reportType),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("record_count", len(summaries)),
		util.Duration("duration", time.Since(startTime)))

	return reportData, contentType, nil
}

func (qs *attendanceQueryServiceImpl) generateCSVReport(summaries []*attendance.AttendanceDailySummary) ([]byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write header
	header := []string{
		"Date", "User ID", "Status", "Worked Hours", "Overtime Hours",
		"Late Minutes", "Generated At",
	}
	if err := writer.Write(header); err != nil {
		return nil, err
	}

	// Write data rows
	for _, summary := range summaries {
		var workedHours, overtimeHours, lateMinutes string

		if summary.WorkedMinutes != nil {
			workedHours = fmt.Sprintf("%.2f", float64(*summary.WorkedMinutes)/60.0)
		}
		if summary.OvertimeMinutes != nil {
			overtimeHours = fmt.Sprintf("%.2f", float64(*summary.OvertimeMinutes)/60.0)
		}
		if summary.LateMinutes != nil {
			lateMinutes = fmt.Sprintf("%d", *summary.LateMinutes)
		}

		row := []string{
			summary.AttendanceDate.Format("2006-01-02"),
			summary.UserID.String(),
			summary.Status,
			workedHours,
			overtimeHours,
			lateMinutes,
			summary.GeneratedAt.Format("2006-01-02 15:04:05"),
		}

		if err := writer.Write(row); err != nil {
			return nil, err
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (qs *attendanceQueryServiceImpl) generateJSONReport(summaries []*attendance.AttendanceDailySummary) ([]byte, error) {
	report := map[string]interface{}{
		"summaries":    summaries,
		"generated_at": time.Now().UTC(),
		"total_count":  len(summaries),
	}

	return json.MarshalIndent(report, "", "  ")
}

func (qs *attendanceQueryServiceImpl) StreamAttendanceEvents(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
	writer io.Writer,
	format string,
) error {
	startTime := time.Now()

	if format != "csv" && format != "jsonl" {
		return fmt.Errorf("unsupported stream format: %s. Supported formats: csv, jsonl", format)
	}

	maxDays := 7
	if endDate.Sub(startDate).Hours()/24 > float64(maxDays) {
		return fmt.Errorf("date range cannot exceed %d days for streaming", maxDays)
	}

	// Get events in batches
	page := 1
	pageSize := 1000
	totalEvents := 0

	for {
		events, total, err := qs.attendanceRepo.GetAttendanceEventsByCompany(ctx, companyID, startDate, endDate, page, pageSize)
		if err != nil {
			return fmt.Errorf("failed to get attendance events: %w", err)
		}

		if len(events) == 0 {
			break
		}

		// Stream events in requested format
		switch format {
		case "csv":
			if err := qs.streamEventsAsCSV(events, writer, page == 1); err != nil {
				return err
			}
		case "jsonl":
			if err := qs.streamEventsAsJSONL(events, writer); err != nil {
				return err
			}
		}

		totalEvents += len(events)

		// Check if we've processed all events
		if page*pageSize >= int(total) {
			break
		}

		page++

		// Check for context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Continue
		}
	}

	qs.logger.Info("Attendance events streamed",
		util.String("company_id", companyID.String()),
		util.String("format", format),
		util.Int("total_events", totalEvents),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (qs *attendanceQueryServiceImpl) streamEventsAsCSV(events []*attendance.AttendanceEvent, writer io.Writer, writeHeader bool) error {
	csvWriter := csv.NewWriter(writer)

	if writeHeader {
		header := []string{
			"Event ID", "User ID", "Event Type", "Event Time", "Source Type",
			"Device ID", "IP Address", "Created At",
		}
		if err := csvWriter.Write(header); err != nil {
			return err
		}
	}

	for _, event := range events {
		var deviceID, ipAddress string
		if event.DeviceID != nil {
			deviceID = *event.DeviceID
		}
		if event.IPAddress != nil {
			ipAddress = *event.IPAddress
		}

		row := []string{
			event.AttendanceEventID.String(),
			event.UserID.String(),
			event.EventType,
			event.EventTime.Format("2006-01-02 15:04:05"),
			event.SourceType,
			deviceID,
			ipAddress,
			event.CreatedAt.Format("2006-01-02 15:04:05"),
		}

		if err := csvWriter.Write(row); err != nil {
			return err
		}
	}

	csvWriter.Flush()
	return csvWriter.Error()
}

func (qs *attendanceQueryServiceImpl) streamEventsAsJSONL(events []*attendance.AttendanceEvent, writer io.Writer) error {
	for _, event := range events {
		data, err := json.Marshal(event)
		if err != nil {
			return err
		}

		if _, err := writer.Write(data); err != nil {
			return err
		}

		if _, err := writer.Write([]byte("\n")); err != nil {
			return err
		}
	}

	return nil
}

func (qs *attendanceQueryServiceImpl) HealthCheck(ctx context.Context) error {
	if err := qs.attendanceRepo.HealthCheck(ctx); err != nil {
		return fmt.Errorf("attendance repository health check failed: %w", err)
	}
	return nil
}

func (s *attendanceServiceImpl) UpdateAttendancePolicy(
	ctx context.Context,
	policy *attendance.AttendancePolicy,
) error {
	startTime := time.Now()

	if policy.PolicyID == uuid.Nil {
		return fmt.Errorf("policy ID is required")
	}

	if policy.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}

	if policy.PolicyCode == "" {
		return fmt.Errorf("policy code is required")
	}

	if policy.PolicyType == "" {
		return fmt.Errorf("policy type is required")
	}

	// Check if policy exists
	existingPolicy, err := s.attendanceRepo.GetAttendancePolicyByID(ctx, policy.PolicyID)
	if err != nil {
		return fmt.Errorf("failed to get attendance policy: %w", err)
	}

	if existingPolicy == nil {
		return fmt.Errorf("attendance policy not found")
	}

	// Check for duplicate policy code within the same company
	existingPolicies, err := s.attendanceRepo.GetAttendancePoliciesByCompany(ctx, policy.CompanyID, false)
	if err == nil {
		for _, p := range existingPolicies {
			if p.PolicyID != policy.PolicyID && p.PolicyCode == policy.PolicyCode {
				return fmt.Errorf("policy with code %s already exists", policy.PolicyCode)
			}
		}
	}

	policy.UpdatedAt = time.Now().UTC()

	if err := s.attendanceRepo.UpdateAttendancePolicy(ctx, policy); err != nil {
		s.logger.Error("Failed to update attendance policy",
			util.String("policy_id", policy.PolicyID.String()),
			util.String("policy_code", policy.PolicyCode),
			util.ErrorField(err))
		return fmt.Errorf("failed to update attendance policy: %w", err)
	}

	s.logger.Info("Attendance policy updated",
		util.String("policy_id", policy.PolicyID.String()),
		util.String("policy_code", policy.PolicyCode),
		util.String("company_id", policy.CompanyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *attendanceServiceImpl) DeleteAttendancePolicy(
	ctx context.Context,
	policyID uuid.UUID,
) error {
	startTime := time.Now()

	if policyID == uuid.Nil {
		return fmt.Errorf("policy ID is required")
	}

	// Check if policy exists and get company ID for audit
	policy, err := s.attendanceRepo.GetAttendancePolicyByID(ctx, policyID)
	if err != nil {
		return fmt.Errorf("failed to get attendance policy: %w", err)
	}

	if policy == nil {
		return fmt.Errorf("attendance policy not found")
	}

	// Check if any users are assigned to this policy
	// Note: You might need to add a method to check active assignments
	// For now, we'll delete and rely on cascade deletion or separate cleanup

	if err := s.attendanceRepo.DeleteAttendancePolicy(ctx, policyID); err != nil {
		s.logger.Error("Failed to delete attendance policy",
			util.String("policy_id", policyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to delete attendance policy: %w", err)
	}

	s.logger.Info("Attendance policy deleted",
		util.String("policy_id", policyID.String()),
		util.String("policy_code", policy.PolicyCode),
		util.String("company_id", policy.CompanyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *attendanceServiceImpl) GetUserAttendanceStats(
	ctx context.Context,
	userID uuid.UUID,
	startDate, endDate time.Time,
) (*attendance.UserAttendanceStats, error) {
	startTime := time.Now()

	if userID == uuid.Nil {
		return nil, fmt.Errorf("user ID is required")
	}

	if startDate.IsZero() || endDate.IsZero() {
		return nil, fmt.Errorf("start date and end date are required")
	}

	if startDate.After(endDate) {
		return nil, fmt.Errorf("start date cannot be after end date")
	}

	// Validate date range (e.g., not too large)
	maxDays := 365
	if endDate.Sub(startDate).Hours()/24 > float64(maxDays) {
		return nil, fmt.Errorf("date range cannot exceed %d days", maxDays)
	}

	// Get user's company to ensure proper authorization
	// This might need to be adjusted based on your authorization model
	_, err := s.attendanceRepo.GetUserAttendanceProfile(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user attendance profile: %w", err)
	}

	// Get attendance stats from repository
	stats, err := s.attendanceRepo.GetUserAttendanceStats(ctx, userID, startDate, endDate)
	if err != nil {
		s.logger.Error("Failed to get user attendance stats",
			util.String("user_id", userID.String()),
			util.Time("start_date", startDate),
			util.Time("end_date", endDate),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get user attendance stats: %w", err)
	}

	// If stats is nil, create an empty one
	if stats == nil {
		stats = &attendance.UserAttendanceStats{
			UserID:             userID,
			StartDate:          startDate,
			EndDate:            endDate,
			PresentDays:        0,
			AbsentDays:         0,
			LateDays:           0,
			HalfDays:           0,
			LeaveDays:          0,
			TotalWorkedHours:   0,
			TotalOvertimeHours: 0,
			AverageInTime:      "",
			AverageOutTime:     "",
			AttendancePercent:  0,
		}
	}

	s.logger.Debug("User attendance stats retrieved",
		util.String("user_id", userID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("present_days", stats.PresentDays),
		util.Int("absent_days", stats.AbsentDays),
		util.Int("late_days", stats.LateDays),
		util.Float64("attendance_percent", stats.AttendancePercent),
		util.Duration("duration", time.Since(startTime)))

	return stats, nil
}
func (s *attendanceServiceImpl) GetAttendanceStats(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) (*attendance.AttendanceStats, error) {
	startTime := time.Now()

	if companyID == uuid.Nil {
		return nil, fmt.Errorf("company ID is required")
	}

	if startDate.IsZero() || endDate.IsZero() {
		return nil, fmt.Errorf("start date and end date are required")
	}

	if startDate.After(endDate) {
		return nil, fmt.Errorf("start date cannot be after end date")
	}

	// Validate date range
	maxDays := 31
	if endDate.Sub(startDate).Hours()/24 > float64(maxDays) {
		return nil, fmt.Errorf("date range cannot exceed %d days", maxDays)
	}

	// Get attendance stats from repository
	stats, err := s.attendanceRepo.GetAttendanceStats(ctx, companyID, startDate, endDate)
	if err != nil {
		s.logger.Error("Failed to get attendance stats",
			util.String("company_id", companyID.String()),
			util.Time("start_date", startDate),
			util.Time("end_date", endDate),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get attendance stats: %w", err)
	}

	// If stats is nil, create an empty one
	if stats == nil {
		stats = &attendance.AttendanceStats{
			CompanyID:          companyID,
			StartDate:          startDate,
			EndDate:            endDate,
			TotalEmployees:     0,
			PresentCount:       0,
			AbsentCount:        0,
			LateCount:          0,
			HalfDayCount:       0,
			LeaveCount:         0,
			HolidayCount:       0,
			TotalWorkedHours:   0,
			TotalOvertimeHours: 0,
			AverageAttendance:  0,
		}
	}

	s.logger.Debug("Company attendance stats retrieved",
		util.String("company_id", companyID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("total_employees", stats.TotalEmployees),
		util.Int("present_count", stats.PresentCount),
		util.Int("late_count", stats.LateCount),
		util.Float64("average_attendance", stats.AverageAttendance),
		util.Duration("duration", time.Since(startTime)))

	return stats, nil
}

func (s *attendanceServiceImpl) GetAttendanceDailySummariesByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
	page, pageSize int,
) ([]*attendance.AttendanceDailySummary, int64, error) {
	startTime := time.Now()

	if companyID == uuid.Nil {
		return nil, 0, fmt.Errorf("company ID is required")
	}

	if startDate.IsZero() || endDate.IsZero() {
		return nil, 0, fmt.Errorf("start date and end date are required")
	}

	if startDate.After(endDate) {
		return nil, 0, fmt.Errorf("start date cannot be after end date")
	}

	if page < 1 {
		page = 1
	}

	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}

	// Get summaries from repository
	summaries, total, err := s.attendanceRepo.GetAttendanceDailySummariesByCompany(ctx, companyID, startDate, endDate, page, pageSize)
	if err != nil {
		s.logger.Error("Failed to get attendance daily summaries by company",
			util.String("company_id", companyID.String()),
			util.Time("start_date", startDate),
			util.Time("end_date", endDate),
			util.ErrorField(err))
		return nil, 0, fmt.Errorf("failed to get attendance daily summaries: %w", err)
	}

	s.logger.Debug("Attendance daily summaries retrieved for company",
		util.String("company_id", companyID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("page", page),
		util.Int("page_size", pageSize),
		util.Int64("total", total),
		util.Int("returned_count", len(summaries)),
		util.Duration("duration", time.Since(startTime)))

	return summaries, total, nil
}

func (s *attendanceServiceImpl) SearchAttendanceEvents(
	ctx context.Context,
	filter AttendanceSearchFilters,
	page, pageSize int,
) ([]*attendance.AttendanceEvent, int, error) {
	startTime := time.Now()

	if filter.CompanyID == uuid.Nil {
		return nil, 0, fmt.Errorf("company ID is required")
	}

	if filter.StartDate.IsZero() || filter.EndDate.IsZero() {
		return nil, 0, fmt.Errorf("start date and end date are required")
	}

	if filter.StartDate.After(filter.EndDate) {
		return nil, 0, fmt.Errorf("start date cannot be after end date")
	}

	if page < 1 {
		page = 1
	}

	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}

	// Convert to repository filter
	repoFilter := repository.AttendanceEventFilter{
		CompanyID:  filter.CompanyID,
		UserID:     filter.UserID,
		StartDate:  filter.StartDate,
		EndDate:    filter.EndDate,
		EventType:  filter.EventType,
		SourceType: filter.SourceType,
		Page:       page,
		PageSize:   pageSize,
	}

	// Search events from repository
	events, total, err := s.attendanceRepo.SearchAttendanceEvents(ctx, repoFilter)
	if err != nil {
		s.logger.Error("Failed to search attendance events",
			util.String("company_id", filter.CompanyID.String()),
			util.Time("start_date", filter.StartDate),
			util.Time("end_date", filter.EndDate),
			util.ErrorField(err))
		return nil, 0, fmt.Errorf("failed to search attendance events: %w", err)
	}

	totalPages := (int(total) + pageSize - 1) / pageSize

	s.logger.Debug("Attendance events searched",
		util.String("company_id", filter.CompanyID.String()),
		util.Time("start_date", filter.StartDate),
		util.Time("end_date", filter.EndDate),
		util.Int("page", page),
		util.Int("page_size", pageSize),
		util.Int("total_events", int(total)),
		util.Int("total_pages", totalPages),
		util.Int("returned_events", len(events)),
		util.Duration("duration", time.Since(startTime)))

	return events, int(total), nil
}

func (s *attendanceServiceImpl) GetAttendanceEventByID(
	ctx context.Context,
	eventID uuid.UUID,
) (*attendance.AttendanceEvent, error) {
	startTime := time.Now()

	if eventID == uuid.Nil {
		return nil, fmt.Errorf("event ID is required")
	}

	// Get event from repository
	event, err := s.attendanceRepo.GetAttendanceEventByID(ctx, eventID)
	if err != nil {
		s.logger.Error("Failed to get attendance event by ID",
			util.String("event_id", eventID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get attendance event: %w", err)
	}

	if event == nil {
		return nil, nil
	}

	s.logger.Debug("Attendance event retrieved by ID",
		util.String("event_id", eventID.String()),
		util.String("user_id", event.UserID.String()),
		util.String("event_type", event.EventType),
		util.Duration("duration", time.Since(startTime)))

	return event, nil
}

func normalizeSourceType(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

var validAttendanceEventTypes = map[string]bool{
	// Core
	"check_in":    true,
	"check_out":   true,
	"break_start": true,
	"break_end":   true,

	// Shift
	"shift_start":    true,
	"shift_end":      true,
	"overtime_start": true,
	"overtime_end":   true,
	"early_exit":     true,
	"late_entry":     true,

	// Location
	"gate_entry": true,
	"gate_exit":  true,
	"zone_entry": true,
	"zone_exit":  true,

	// Class / Session
	"class_start":   true,
	"class_end":     true,
	"session_join":  true,
	"session_leave": true,

	// Leave
	"leave_start":    true,
	"leave_end":      true,
	"absent_marked":  true,
	"holiday_marked": true,
	"weekly_off":     true,

	// Manual / HR
	"manual_check_in":       true,
	"manual_check_out":      true,
	"manual_override":       true,
	"attendance_adjustment": true,

	// System
	"biometric_sync":   true,
	"rfid_scan":        true,
	"system_generated": true,
	"imported_event":   true,

	// Exceptions
	"missing_punch":    true,
	"duplicate_punch":  true,
	"invalid_punch":    true,
	"policy_violation": true,
}

// CreateAttendanceEvent - UPDATED with duplicate protection
func (s *attendanceServiceImpl) CreateAttendanceEvent(
	ctx context.Context,
	event *attendance.AttendanceEvent,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*attendance.AttendanceEvent, error) {

	startTime := time.Now()

	// =========================
	// Basic validation
	// =========================
	if event.UserID == uuid.Nil {
		return nil, fmt.Errorf("user ID is required")
	}
	if event.CompanyID == uuid.Nil {
		return nil, fmt.Errorf("company ID is required")
	}
	if event.EventType == "" {
		return nil, fmt.Errorf("event type is required")
	}
	if event.EventTime.IsZero() {
		return nil, fmt.Errorf("event time is required")
	}
	if event.SourceType == "" {
		return nil, fmt.Errorf("source type is required")
	}

	if err := s.ValidateAttendanceEventType(ctx, event.EventType); err != nil {
		return nil, err
	}
	if err := s.ValidateAttendanceSourceType(ctx, event.SourceType, event.SourceID); err != nil {
		return nil, err
	}

	// =========================
	// Duplicate protection
	// =========================
	if event.SourceType == "correction" {
		existing, err := s.attendanceRepo.FindExistingCorrection(
			ctx,
			event.CompanyID,
			event.UserID,
			event.EventType,
			event.EventTime,
		)
		if err != nil {
			return nil, err
		}
		if existing != nil {
			return existing, nil
		}
	} else {
		lastEvent, err := s.attendanceRepo.GetLastAttendanceEvent(
			ctx,
			event.CompanyID,
			event.UserID,
			event.EventType,
			event.EventTime.Add(-5*time.Minute),
		)
		if err != nil {
			return nil, err
		}
		if lastEvent != nil && event.EventTime.Sub(lastEvent.EventTime).Abs() <= 5*time.Minute {
			return lastEvent, nil
		}
	}

	// =========================
	// Rules validation (SOURCE / EVENT only)
	// =========================
	if err := s.validateEventRules(ctx, event); err != nil {
		return nil, err
	}

	// =========================
	// Persist event (FACT)
	// =========================
	if event.AttendanceEventID == uuid.Nil {
		event.AttendanceEventID = uuid.New()
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	if event.CreatedBy == nil {
		event.CreatedBy = &actorID
	}

	if err := s.attendanceRepo.CreateAttendanceEvent(ctx, event); err != nil {
		return nil, err
	}

	// =========================
	// Audit
	// =========================
	if s.auditService != nil {
		go s.logAuditAction(
			context.Background(),
			event.CompanyID,
			"attendance_event.create",
			event.AttendanceEventID,
			actorType,
			actorID,
			nil,
			event,
			metadata,
		)
	}

	s.logger.Info(
		"Attendance event created",
		util.String("event_id", event.AttendanceEventID.String()),
		util.String("event_type", event.EventType),
		util.Time("event_time", event.EventTime),
		util.Duration("duration", time.Since(startTime)),
	)

	return event, nil
}

// func (s *attendanceServiceImpl) GenerateDailySummary(
// 	ctx context.Context,
// 	companyID, userID uuid.UUID,
// 	at time.Time,
// 	_ string,
// ) (*attendance.AttendanceDailySummary, error) {

// 	dayContext, err := s.resolveAttendanceDay(ctx, userID, at, "")
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to resolve attendance day: %w", err)
// 	}

// 	attendanceDate := dayContext.Date

// 	loc, err := time.LoadLocation(dayContext.Timezone)
// 	if err != nil {
// 		return nil, fmt.Errorf("invalid schedule timezone: %s", dayContext.Timezone)
// 	}

// 	// =====================================================
// 	// 🔥 BUILD EXTENDED EVENT WINDOW (early + late + night)
// 	// =====================================================
// 	var from, to time.Time

// 	if dayContext.ExpectedStart != nil && dayContext.ExpectedEnd != nil {
// 		shiftStart := time.Date(
// 			attendanceDate.Year(),
// 			attendanceDate.Month(),
// 			attendanceDate.Day(),
// 			dayContext.ExpectedStart.Hour(),
// 			dayContext.ExpectedStart.Minute(),
// 			0, 0,
// 			loc,
// 		)

// 		shiftEnd := time.Date(
// 			attendanceDate.Year(),
// 			attendanceDate.Month(),
// 			attendanceDate.Day(),
// 			dayContext.ExpectedEnd.Hour(),
// 			dayContext.ExpectedEnd.Minute(),
// 			0, 0,
// 			loc,
// 		)

// 		// Night shift
// 		if shiftEnd.Before(shiftStart) {
// 			shiftEnd = shiftEnd.Add(24 * time.Hour)
// 		}

// 		from = shiftStart.Add(-6 * time.Hour)
// 		to = shiftEnd.Add(6 * time.Hour)

// 	} else {
// 		from = time.Date(attendanceDate.Year(), attendanceDate.Month(), attendanceDate.Day(), 0, 0, 0, 0, loc)
// 		to = from.Add(24 * time.Hour)
// 	}

// 	events, err := s.attendanceRepo.GetAttendanceEventsByUser(
// 		ctx,
// 		userID,
// 		from,
// 		to,
// 		100,
// 	)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// =====================================================
// 	// STATUS RESOLUTION
// 	// =====================================================
// 	var (
// 		status   string
// 		worked   *int
// 		late     *int
// 		overtime *int
// 	)

// 	switch {
// 	case dayContext.IsOnLeave && len(events) == 0:
// 		status = "leave"

// 	case dayContext.IsHoliday && len(events) == 0:
// 		status = "holiday"

// 	case !dayContext.IsWorkingDay && len(events) == 0:
// 		status = "week_off"

// 	case len(events) == 0:
// 		status = "absent"

// 	default:
// 		policy, err := s.attendanceRepo.GetUserActiveAttendancePolicy(ctx, userID, from)
// 		if err != nil {
// 			return nil, err
// 		}

// 		calculated, err := s.calculateDailySummary(
// 			ctx,
// 			userID,
// 			attendanceDate,
// 			events,
// 			policy,
// 			dayContext,
// 		)
// 		if err != nil {
// 			return nil, err
// 		}

// 		status = calculated.Status
// 		worked = calculated.WorkedMinutes
// 		late = calculated.LateMinutes
// 		overtime = calculated.OvertimeMinutes

// 		// ✅ FINAL SAP-STYLE OVERRIDE (ONLY IF WORK EXISTS)
// 		if dayContext.IsHoliday {
// 			if worked != nil && *worked > 0 {
// 				status = "worked_on_holiday"
// 			} else {
// 				status = "holiday"
// 			}
// 		} else if !dayContext.IsWorkingDay {
// 			if worked != nil && *worked > 0 {
// 				status = "worked_on_week_off"
// 			} else {
// 				status = "week_off"
// 			}
// 		}
// 	}

// 	summary := &attendance.AttendanceDailySummary{
// 		AttendanceSummaryID: uuid.New(),
// 		CompanyID:           companyID,
// 		UserID:              userID,
// 		AttendanceDate:      attendanceDate,
// 		Status:              status,
// 		WorkedMinutes:       worked,
// 		LateMinutes:         late,
// 		OvertimeMinutes:     overtime,
// 		Metadata:            attendance.SummaryMetadata{},
// 		GeneratedAt:         time.Now().UTC(),
// 		GeneratedBy:         "system",
// 	}

// 	if err := s.attendanceRepo.UpsertAttendanceDailySummary(ctx, summary); err != nil {
// 		return nil, err
// 	}

//		return summary, nil
//	}
// func (s *attendanceServiceImpl) calculateDailySummary(
// 	ctx context.Context,
// 	userID uuid.UUID,
// 	date time.Time,
// 	events []*attendance.AttendanceEvent,
// 	policy *attendance.AttendancePolicy,
// 	dayContext *AttendanceDayContext,
// ) (*attendance.AttendanceDailySummary, error) {

// 	loc, err := time.LoadLocation(dayContext.Timezone)
// 	if err != nil {
// 		return nil, fmt.Errorf("invalid schedule timezone: %s", dayContext.Timezone)
// 	}

// 	// =====================================================
// 	// Sort events ASCENDING (CRITICAL)
// 	// =====================================================
// 	sort.Slice(events, func(i, j int) bool {
// 		return events[i].EventTime.Before(events[j].EventTime)
// 	})

// 	var (
// 		totalWorkedMinutes int
// 		lateMinutes        int
// 		overtimeMinutes    int
// 		lastCheckIn        *time.Time
// 	)

// 	for _, event := range events {
// 		t := event.EventTime.In(loc)

// 		switch event.EventType {

// 		case "check_in":
// 			lastCheckIn = &t

// 		case "check_out":
// 			if lastCheckIn != nil && t.After(*lastCheckIn) {
// 				totalWorkedMinutes += int(t.Sub(*lastCheckIn).Minutes())
// 				lastCheckIn = nil
// 			}
// 		}
// 	}

// 	// =====================================================
// 	// Late calculation
// 	// =====================================================
// 	if dayContext.ExpectedStart != nil && len(events) > 0 {
// 		expectedStart := time.Date(
// 			date.Year(), date.Month(), date.Day(),
// 			dayContext.ExpectedStart.Hour(),
// 			dayContext.ExpectedStart.Minute(),
// 			0, 0, loc,
// 		)

// 		for _, e := range events {
// 			if e.EventType == "check_in" {
// 				in := e.EventTime.In(loc)
// 				if in.After(expectedStart) {
// 					lateMinutes = int(in.Sub(expectedStart).Minutes())
// 				}
// 				break
// 			}
// 		}
// 	}

// 	// =====================================================
// 	// Overtime calculation
// 	// =====================================================
// 	if dayContext.ExpectedEnd != nil && len(events) > 0 {
// 		expectedEnd := time.Date(
// 			date.Year(), date.Month(), date.Day(),
// 			dayContext.ExpectedEnd.Hour(),
// 			dayContext.ExpectedEnd.Minute(),
// 			0, 0, loc,
// 		)

// 		for i := len(events) - 1; i >= 0; i-- {
// 			if events[i].EventType == "check_out" {
// 				out := events[i].EventTime.In(loc)
// 				if out.After(expectedEnd) {
// 					overtimeMinutes = int(out.Sub(expectedEnd).Minutes())
// 				}
// 				break
// 			}
// 		}
// 	}

// 	// =====================================================
// 	// Status resolution
// 	// =====================================================
// 	status := "present"

// 	if policy != nil && policy.Rules.HalfDayAfter != nil {
// 		if totalWorkedMinutes < (*policy.Rules.HalfDayAfter * 60) {
// 			status = "half_day"
// 		}
// 	}

// 	if policy != nil && policy.Rules.GracePeriod != nil {
// 		if lateMinutes > *policy.Rules.GracePeriod {
// 			status = "late"
// 		}
// 	}

// 	return &attendance.AttendanceDailySummary{
// 		Status:          status,
// 		WorkedMinutes:   &totalWorkedMinutes,
// 		LateMinutes:     &lateMinutes,
// 		OvertimeMinutes: &overtimeMinutes,
// 		Metadata:        attendance.SummaryMetadata{},
// 	}, nil
// }

// func (s *attendanceServiceImpl) GenerateDailySummary(
// 	ctx context.Context,
// 	companyID, userID uuid.UUID,
// 	at time.Time,
// 	_ string,
// ) (*attendance.AttendanceDailySummary, error) {

// 	// =====================================================
// 	// Resolve authoritative business context
// 	// =====================================================
// 	dayContext, err := s.resolveAttendanceDay(ctx, userID, at, "")
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to resolve attendance day: %w", err)
// 	}

// 	loc, err := time.LoadLocation(dayContext.Timezone)
// 	if err != nil {
// 		return nil, fmt.Errorf("invalid schedule timezone: %s", dayContext.Timezone)
// 	}

// 	// =====================================================
// 	// ✅ AUTHORITATIVE attendance date (FROM INPUT TIME)
// 	// =====================================================
// 	atLocal := at.In(loc)
// 	attendanceDate := time.Date(
// 		atLocal.Year(),
// 		atLocal.Month(),
// 		atLocal.Day(),
// 		0, 0, 0, 0,
// 		loc,
// 	)

// 	// =====================================================
// 	// Build LOCAL event window
// 	// =====================================================
// 	var localFrom, localTo time.Time

// 	if dayContext.ExpectedStart != nil && dayContext.ExpectedEnd != nil {

// 		shiftStart := time.Date(
// 			attendanceDate.Year(),
// 			attendanceDate.Month(),
// 			attendanceDate.Day(),
// 			dayContext.ExpectedStart.Hour(),
// 			dayContext.ExpectedStart.Minute(),
// 			0, 0,
// 			loc,
// 		)

// 		shiftEnd := time.Date(
// 			attendanceDate.Year(),
// 			attendanceDate.Month(),
// 			attendanceDate.Day(),
// 			dayContext.ExpectedEnd.Hour(),
// 			dayContext.ExpectedEnd.Minute(),
// 			0, 0,
// 			loc,
// 		)

// 		// Night shift handling
// 		if shiftEnd.Before(shiftStart) {
// 			shiftEnd = shiftEnd.Add(24 * time.Hour)
// 		}

// 		localFrom = shiftStart.Add(-6 * time.Hour)
// 		localTo = shiftEnd.Add(6 * time.Hour)

// 	} else {
// 		// No shift → calendar day
// 		localFrom = attendanceDate
// 		localTo = attendanceDate.Add(24 * time.Hour)
// 	}

// 	// =====================================================
// 	// Convert window to UTC (DB is UTC)
// 	// =====================================================
// 	fromUTC := localFrom.UTC()
// 	toUTC := localTo.UTC()

// 	events, err := s.attendanceRepo.GetAttendanceEventsByUser(
// 		ctx,
// 		userID,
// 		fromUTC,
// 		toUTC,
// 		0,
// 	)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// =====================================================
// 	// Status resolution
// 	// =====================================================
// 	var (
// 		status   string
// 		worked   *int
// 		late     *int
// 		overtime *int
// 	)

// 	switch {
// 	case dayContext.IsOnLeave && len(events) == 0:
// 		status = "leave"

// 	case dayContext.IsHoliday && len(events) == 0:
// 		status = "holiday"

// 	case !dayContext.IsWorkingDay && len(events) == 0:
// 		status = "week_off"

// 	case len(events) == 0:
// 		status = "absent"

// 	default:
// 		policy, err := s.attendanceRepo.GetUserActiveAttendancePolicy(ctx, userID, fromUTC)
// 		if err != nil {
// 			return nil, err
// 		}

// 		calculated, err := s.calculateDailySummary(
// 			ctx,
// 			userID,
// 			attendanceDate,
// 			events,
// 			policy,
// 			dayContext,
// 		)
// 		if err != nil {
// 			return nil, err
// 		}

// 		status = calculated.Status
// 		worked = calculated.WorkedMinutes
// 		late = calculated.LateMinutes
// 		overtime = calculated.OvertimeMinutes

// 		// Holiday / Week-off override
// 		if dayContext.IsHoliday {
// 			if worked != nil && *worked > 0 {
// 				status = "worked_on_holiday"
// 			} else {
// 				status = "holiday"
// 			}
// 		} else if !dayContext.IsWorkingDay {
// 			if worked != nil && *worked > 0 {
// 				status = "worked_on_week_off"
// 			} else {
// 				status = "week_off"
// 			}
// 		}
// 	}

// 	// =====================================================
// 	// Persist summary
// 	// =====================================================
// 	summary := &attendance.AttendanceDailySummary{
// 		AttendanceSummaryID: uuid.New(),
// 		CompanyID:           companyID,
// 		UserID:              userID,
// 		AttendanceDate:      attendanceDate,
// 		Status:              status,
// 		WorkedMinutes:       worked,
// 		LateMinutes:         late,
// 		OvertimeMinutes:     overtime,
// 		Metadata:            attendance.SummaryMetadata{},
// 		GeneratedAt:         time.Now().UTC(),
// 		GeneratedBy:         "system",
// 	}

// 	if err := s.attendanceRepo.UpsertAttendanceDailySummary(ctx, summary); err != nil {
// 		return nil, err
// 	}

// 	return summary, nil
// }

func (s *attendanceServiceImpl) calculateDailySummary(
	ctx context.Context,
	userID uuid.UUID,
	date time.Time,
	events []*attendance.AttendanceEvent,
	policy *attendance.AttendancePolicy,
	dayContext *AttendanceDayContext,
) (*attendance.AttendanceDailySummary, error) {

	loc, err := time.LoadLocation(dayContext.Timezone)
	if err != nil {
		return nil, fmt.Errorf("invalid schedule timezone: %s", dayContext.Timezone)
	}

	s.logger.Info("=== calculateDailySummary START ===",
		util.String("user_id", userID.String()),
		util.String("date_local", date.Format(time.RFC3339)),
	)

	// =====================================================
	// Sort events by time (ASC)
	// =====================================================
	sort.Slice(events, func(i, j int) bool {
		return events[i].EventTime.Before(events[j].EventTime)
	})

	var (
		totalWorkedMinutes int
		lateMinutes        int
		overtimeMinutes    int
		lastCheckIn        *time.Time
	)

	// =====================================================
	// Work duration calculation
	// =====================================================
	for _, event := range events {
		tLocal := event.EventTime.In(loc)

		s.logger.Info("Processing event",
			util.String("event_type", event.EventType),
			util.String("event_time_utc", event.EventTime.Format(time.RFC3339)),
			util.String("event_time_local", tLocal.Format(time.RFC3339)),
		)

		switch event.EventType {

		case "check_in":
			lastCheckIn = &tLocal
			s.logger.Info("Check-in registered",
				util.String("time_local", tLocal.Format(time.RFC3339)),
			)

		case "check_out":
			if lastCheckIn == nil {
				s.logger.Warn("Check-out without matching check-in",
					util.String("time_local", tLocal.Format(time.RFC3339)),
				)
				continue
			}

			if tLocal.After(*lastCheckIn) {
				diff := int(tLocal.Sub(*lastCheckIn).Minutes())
				totalWorkedMinutes += diff

				s.logger.Info("Work segment closed",
					util.Int("minutes", diff),
					util.String("from_local", lastCheckIn.Format(time.RFC3339)),
					util.String("to_local", tLocal.Format(time.RFC3339)),
				)

				lastCheckIn = nil
			}
		}
	}

	// =====================================================
	// Late calculation (FIXED UTC → LOCAL)
	// =====================================================
	if dayContext.ExpectedStart != nil && len(events) > 0 {

		expectedStartLocal := dayContext.ExpectedStart.In(loc)

		expectedStart := time.Date(
			date.Year(),
			date.Month(),
			date.Day(),
			expectedStartLocal.Hour(),
			expectedStartLocal.Minute(),
			0, 0,
			loc,
		)

		s.logger.Info("Expected start resolved",
			util.String("expected_start_utc", dayContext.ExpectedStart.Format(time.RFC3339)),
			util.String("expected_start_local", expectedStart.Format(time.RFC3339)),
		)

		for _, e := range events {
			if e.EventType == "check_in" {
				inLocal := e.EventTime.In(loc)

				if inLocal.After(expectedStart) {
					lateMinutes = int(inLocal.Sub(expectedStart).Minutes())
				}

				s.logger.Info("Late calculation",
					util.String("actual_in_local", inLocal.Format(time.RFC3339)),
					util.Int("late_minutes", lateMinutes),
				)
				break
			}
		}
	}

	// =====================================================
	// Overtime calculation (FIXED UTC → LOCAL)
	// =====================================================
	if dayContext.ExpectedEnd != nil && len(events) > 0 {

		expectedEndLocal := dayContext.ExpectedEnd.In(loc)

		expectedEnd := time.Date(
			date.Year(),
			date.Month(),
			date.Day(),
			expectedEndLocal.Hour(),
			expectedEndLocal.Minute(),
			0, 0,
			loc,
		)

		s.logger.Info("Expected end resolved",
			util.String("expected_end_utc", dayContext.ExpectedEnd.Format(time.RFC3339)),
			util.String("expected_end_local", expectedEnd.Format(time.RFC3339)),
		)

		for i := len(events) - 1; i >= 0; i-- {
			if events[i].EventType == "check_out" {
				outLocal := events[i].EventTime.In(loc)

				if outLocal.After(expectedEnd) {
					overtimeMinutes = int(outLocal.Sub(expectedEnd).Minutes())
				}

				s.logger.Info("Overtime calculation",
					util.String("actual_out_local", outLocal.Format(time.RFC3339)),
					util.Int("overtime_minutes", overtimeMinutes),
				)
				break
			}
		}
	}

	// =====================================================
	// Final summary
	// =====================================================
	s.logger.Info("=== calculateDailySummary END ===",
		util.Int("worked_minutes", totalWorkedMinutes),
		util.Int("late_minutes", lateMinutes),
		util.Int("overtime_minutes", overtimeMinutes),
	)

	status := "present"
	if policy != nil && policy.Rules.GracePeriod != nil && lateMinutes > *policy.Rules.GracePeriod {
		status = "late"
	}

	return &attendance.AttendanceDailySummary{
		Status:          status,
		WorkedMinutes:   &totalWorkedMinutes,
		LateMinutes:     &lateMinutes,
		OvertimeMinutes: &overtimeMinutes,
		Metadata:        attendance.SummaryMetadata{},
	}, nil
}

func (s *attendanceServiceImpl) GenerateDailySummary(
	ctx context.Context,
	companyID, userID uuid.UUID,
	at time.Time,
	_ string,
) (*attendance.AttendanceDailySummary, error) {

	s.logger.Info("=== GenerateDailySummary START ===",
		util.String("user_id", userID.String()),
		util.String("company_id", companyID.String()),
		util.String("input_at", at.Format(time.RFC3339)),
	)

	// =====================================================
	// Resolve business context (calendar intent only)
	// =====================================================
	dayContext, err := s.resolveAttendanceDay(ctx, userID, at, "")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve attendance day: %w", err)
	}

	s.logger.Info("Resolved day context",
		util.String("timezone", dayContext.Timezone),
		util.Bool("is_working_day", dayContext.IsWorkingDay),
		util.Bool("is_holiday", dayContext.IsHoliday),
		util.Bool("is_on_leave", dayContext.IsOnLeave),
		util.Any("expected_start_utc", dayContext.ExpectedStart),
		util.Any("expected_end_utc", dayContext.ExpectedEnd),
	)

	loc, err := time.LoadLocation(dayContext.Timezone)
	if err != nil {
		return nil, fmt.Errorf("invalid schedule timezone: %s", dayContext.Timezone)
	}

	// =====================================================
	// ✅ AUTHORITATIVE attendance date (FROM INPUT TIME)
	// =====================================================
	atLocal := at.In(loc)
	attendanceDate := time.Date(
		atLocal.Year(),
		atLocal.Month(),
		atLocal.Day(),
		0, 0, 0, 0,
		loc,
	)

	s.logger.Info("Attendance date resolved",
		util.String("attendance_date_local", attendanceDate.Format(time.RFC3339)),
	)

	// =====================================================
	// 🔥 FIX: FETCH FULL LOCAL DAY (+ NIGHT SHIFT BUFFER)
	// =====================================================
	localFrom := attendanceDate
	localTo := attendanceDate.Add(36 * time.Hour) // 24h + night shift safety

	fromUTC := localFrom.UTC()
	toUTC := localTo.UTC()

	s.logger.Info("FIXED UTC query window",
		util.String("local_from", localFrom.Format(time.RFC3339)),
		util.String("local_to", localTo.Format(time.RFC3339)),
		util.String("from_utc", fromUTC.Format(time.RFC3339)),
		util.String("to_utc", toUTC.Format(time.RFC3339)),
	)

	// =====================================================
	// Fetch events
	// =====================================================
	events, err := s.attendanceRepo.GetAttendanceEventsByUser(
		ctx,
		userID,
		fromUTC,
		toUTC,
		0,
	)
	if err != nil {
		return nil, err
	}

	s.logger.Info("Events fetched",
		util.Int("event_count", len(events)),
	)

	for i, e := range events {
		s.logger.Info("Event",
			util.Int("idx", i),
			util.String("event_id", e.AttendanceEventID.String()),
			util.String("type", e.EventType),
			util.String("event_time_utc", e.EventTime.Format(time.RFC3339)),
			util.String("event_time_local", e.EventTime.In(loc).Format(time.RFC3339)),
			util.String("source_type", e.SourceType),
		)
	}

	// =====================================================
	// Status resolution
	// =====================================================
	var (
		status   string
		worked   *int
		late     *int
		overtime *int
	)

	switch {
	case dayContext.IsOnLeave && len(events) == 0:
		status = "leave"

	case dayContext.IsHoliday && len(events) == 0:
		status = "holiday"

	case !dayContext.IsWorkingDay && len(events) == 0:
		status = "week_off"

	case len(events) == 0:
		status = "absent"

	default:
		policy, err := s.attendanceRepo.GetUserActiveAttendancePolicy(ctx, userID, fromUTC)
		if err != nil {
			return nil, err
		}

		calculated, err := s.calculateDailySummary(
			ctx,
			userID,
			attendanceDate,
			events,
			policy,
			dayContext,
		)
		if err != nil {
			return nil, err
		}

		status = calculated.Status
		worked = calculated.WorkedMinutes
		late = calculated.LateMinutes
		overtime = calculated.OvertimeMinutes

		// Holiday / Week-off override
		if dayContext.IsHoliday {
			if worked != nil && *worked > 0 {
				status = "worked_on_holiday"
			} else {
				status = "holiday"
			}
		} else if !dayContext.IsWorkingDay {
			if worked != nil && *worked > 0 {
				status = "worked_on_week_off"
			} else {
				status = "week_off"
			}
		}
	}

	s.logger.Info("Summary computed",
		util.String("status", status),
		util.Any("worked_minutes", worked),
		util.Any("late_minutes", late),
		util.Any("overtime_minutes", overtime),
	)

	// =====================================================
	// Persist summary
	// =====================================================
	summary := &attendance.AttendanceDailySummary{
		AttendanceSummaryID: uuid.New(),
		CompanyID:           companyID,
		UserID:              userID,
		AttendanceDate:      attendanceDate,
		Status:              status,
		WorkedMinutes:       worked,
		LateMinutes:         late,
		OvertimeMinutes:     overtime,
		Metadata:            attendance.SummaryMetadata{},
		GeneratedAt:         time.Now().UTC(),
		GeneratedBy:         "system",
	}

	if err := s.attendanceRepo.UpsertAttendanceDailySummary(ctx, summary); err != nil {
		return nil, err
	}

	s.logger.Info("=== GenerateDailySummary END ===",
		util.String("summary_id", summary.AttendanceSummaryID.String()),
	)

	return summary, nil
}
