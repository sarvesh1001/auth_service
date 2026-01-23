package service

import (
	"auth-service/internal/hr/models/attendance"
	"auth-service/internal/hr/repository"
	"auth-service/internal/util"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type AttendanceService interface {
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
	GetUserAttendanceProfile(
		ctx context.Context,
		userID uuid.UUID,
	) (*attendance.UserAttendanceProfile, error)
	UpsertUserAttendanceProfile(
		ctx context.Context,
		profile *attendance.UserAttendanceProfile,
	) error
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
	CheckDateAvailability(
		ctx context.Context,
		userID uuid.UUID,
		date time.Time,
	) (map[string]interface{}, error)
	HealthCheck(ctx context.Context) error
}
type AttendanceQueryService interface {
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
	ListAttendanceEventTypes(
		ctx context.Context,
		activeOnly bool,
	) ([]*attendance.AttendanceEventType, error)
	ListAttendanceSourceTypes(
		ctx context.Context,
	) ([]*attendance.AttendanceSourceType, error)
	HealthCheck(ctx context.Context) error
}
type AttendanceDayContext struct {
	Date               time.Time
	Timezone           string
	ExpectedStart      *time.Time
	ExpectedEnd        *time.Time
	WorkCenterCode     *string
	ScheduleID         *uuid.UUID
	IsSchedulable      bool
	AttendanceRequired bool
	OvertimeAllowed    bool
	ScheduleStatus     string
	IsOverride         bool
	IsOnLeave          bool
	PositionID         *uuid.UUID
	PositionTitle      *string
}
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
type FactoryAttendanceData struct {
	CompanyID      uuid.UUID            `json:"company_id"`
	WorkCenterCode string               `json:"work_center_code"`
	Events         []SAPAttendanceEvent `json:"events"`
	SyncTimestamp  time.Time            `json:"sync_timestamp"`
	SourceSystem   string               `json:"source_system"`
}
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
type LateEmployeeSummary struct {
	UserID             uuid.UUID `json:"user_id"`
	Username           string    `json:"username"`
	FullName           string    `json:"full_name"`
	LateCount          int       `json:"late_count"`
	AverageLateMinutes int       `json:"average_late_minutes"`
}
type DepartmentStats struct {
	DepartmentID   uuid.UUID `json:"department_id"`
	DepartmentName string    `json:"department_name"`
	PresentCount   int       `json:"present_count"`
	AbsentCount    int       `json:"absent_count"`
	LateCount      int       `json:"late_count"`
	AverageHours   float64   `json:"average_hours"`
}

var (
	ErrScheduleNotGenerated   = errors.New("schedule_not_generated")
	ErrPositionNotSchedulable = errors.New("position_not_schedulable")
	ErrAttendanceNotRequired  = errors.New("attendance_not_required")
)

type attendanceServiceImpl struct {
	attendanceRepo    repository.AttendanceRepository
	schedulingRepo    repository.SchedulingRepository
	schedulingService SchedulingService
	logger            *zap.Logger
	mu                sync.RWMutex
	auditService      *AuditService
}

func NewAttendanceService(
	attendanceRepo repository.AttendanceRepository,
	schedulingRepo repository.SchedulingRepository,
	schedulingService SchedulingService,
	logger *zap.Logger,
	auditService *AuditService,
) AttendanceService {
	return &attendanceServiceImpl{
		attendanceRepo:    attendanceRepo,
		schedulingRepo:    schedulingRepo,
		schedulingService: schedulingService,
		logger:            logger,
		auditService:      auditService,
	}
}
func (s *attendanceServiceImpl) resolveAttendanceDay(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	date time.Time,
) (*AttendanceDayContext, error) {
	startTime := time.Now()
	businessDate := date.UTC().Truncate(24 * time.Hour)
	resolvedDay, err := s.schedulingService.ResolveUserDay(ctx, companyID, userID, businessDate)
	if err != nil {
		s.logger.Error("Failed to resolve schedule day",
			util.String("user_id", userID.String()),
			util.String("company_id", companyID.String()),
			util.String("date", businessDate.Format("2006-01-02")),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to resolve schedule day: %w", err)
	}
	context := &AttendanceDayContext{
		Date:               resolvedDay.Date,
		Timezone:           resolvedDay.Timezone,
		ExpectedStart:      resolvedDay.ExpectedStart,
		ExpectedEnd:        resolvedDay.ExpectedEnd,
		WorkCenterCode:     resolvedDay.WorkCenterCode,
		IsSchedulable:      resolvedDay.IsSchedulable,
		AttendanceRequired: resolvedDay.AttendanceRequired,
		OvertimeAllowed:    resolvedDay.OvertimeAllowed,
		ScheduleStatus:     resolvedDay.ScheduleStatus,
		IsOverride:         resolvedDay.IsOverride,
		IsOnLeave:          resolvedDay.IsOnLeave,
		PositionID:         resolvedDay.PositionID,
		PositionTitle:      resolvedDay.PositionTitle,
	}
	if resolvedDay.ScheduleInstanceID != nil {
		context.ScheduleID = resolvedDay.ScheduleInstanceID
	}
	s.logger.Debug("Resolved attendance day",
		util.String("user_id", userID.String()),
		util.String("company_id", companyID.String()),
		util.String("business_date", context.Date.Format("2006-01-02")),
		util.String("timezone", context.Timezone),
		util.Bool("is_schedulable", context.IsSchedulable),
		util.Bool("attendance_required", context.AttendanceRequired),
		util.Bool("overtime_allowed", context.OvertimeAllowed),
		util.String("schedule_status", context.ScheduleStatus),
		util.Any("schedule_id", context.ScheduleID),
		util.Any("expected_start", context.ExpectedStart),
		util.Any("expected_end", context.ExpectedEnd),
		util.Any("work_center_code", context.WorkCenterCode),
		util.Any("position_id", context.PositionID),
		util.Duration("duration", time.Since(startTime)))
	return context, nil
}
func (s *attendanceServiceImpl) validateEventRules(
	ctx context.Context,
	event *attendance.AttendanceEvent,
) error {
	rules, err := s.ResolveAttendanceRules(ctx, event.UserID, event.CompanyID, uuid.Nil)
	if err != nil {
		return fmt.Errorf("failed to resolve attendance rules: %w", err)
	}
	if !rules.AllowedSourceTypesMap[event.SourceType] {
		return fmt.Errorf("source type %s is not allowed", event.SourceType)
	}
	if !rules.AllowAllEventTypes && !rules.AllowedEventTypesMap[event.EventType] {
		return fmt.Errorf("event type %s is not allowed", event.EventType)
	}
	if rules.RequireReference && event.SourceID == nil {
		return fmt.Errorf("source reference is required for source type %s", event.SourceType)
	}
	if rules.RequireLocation && (event.Metadata.LocationID == nil || *event.Metadata.LocationID == uuid.Nil) {
		return fmt.Errorf("location is required for this department")
	}
	return nil
}
func (s *attendanceServiceImpl) CreateAttendanceEvent(
	ctx context.Context,
	event *attendance.AttendanceEvent,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*attendance.AttendanceEvent, error) {
	startTime := time.Now()
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
	if err := s.validateEventRules(ctx, event); err != nil {
		return nil, err
	}
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
	validEvents := make([]*attendance.AttendanceEvent, 0, len(events))
	for i, event := range events {
		if event.UserID == uuid.Nil || event.CompanyID == uuid.Nil || event.EventType == "" {
			s.logger.Warn("Skipping invalid event in bulk creation",
				util.Int("index", i),
				util.String("user_id", event.UserID.String()),
				util.String("company_id", event.CompanyID.String()),
				util.String("event_type", event.EventType))
			continue
		}
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
	if err := s.attendanceRepo.CreateBulkAttendanceEvents(ctx, validEvents); err != nil {
		s.logger.Error("Failed to create bulk attendance events",
			util.Int("event_count", len(validEvents)),
			util.String("company_id", validEvents[0].CompanyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create bulk attendance events: %w", err)
	}
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
	if sapEvent.EmployeeID == "" {
		return nil, fmt.Errorf("employee ID is required in SAP event")
	}
	if sapEvent.EventType == "" {
		return nil, fmt.Errorf("event type is required in SAP event")
	}
	if sapEvent.EventTime.IsZero() {
		return nil, fmt.Errorf("event time is required in SAP event")
	}
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
		return nil, fmt.Errorf("RFID tag is required for SAP event processing")
	}
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
			ShiftID:    nil,
			Reason:     &sapEvent.ReasonCode,
			LocationID: nil,
		},
	}
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
			_, err := s.ProcessSAPAttendanceEvent(ctx, &sapEvent, companyID, "machine", nil)
			if err != nil {
				errorCount++
				s.logger.Warn("Failed to process factory attendance event",
					util.String("employee_id", sapEvent.EmployeeID),
					util.String("event_type", sapEvent.EventType),
					util.ErrorField(err))
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
func (s *attendanceServiceImpl) CompleteSAPAttendanceFlow(
	ctx context.Context,
	sapEvent *SAPAttendanceEvent,
	companyID uuid.UUID,
) error {
	_, err := s.ProcessSAPAttendanceEvent(ctx, sapEvent, companyID, "system", nil)
	return err
}
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
		util.String("position_id", dayContext.PositionID.String()),
		util.Bool("overtime_allowed", dayContext.OvertimeAllowed),
	)
	sort.Slice(events, func(i, j int) bool {
		return events[i].EventTime.Before(events[j].EventTime)
	})
	var (
		totalWorkedMinutes int
		lateMinutes        int
		overtimeMinutes    int
		lastCheckIn        *time.Time
	)
	for _, event := range events {
		tLocal := event.EventTime.In(loc)
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
	if dayContext.ExpectedStart != nil && len(events) > 0 {
		expectedStartLocal := dayContext.ExpectedStart.In(loc)
		for _, e := range events {
			if e.EventType == "check_in" {
				inLocal := e.EventTime.In(loc)
				if inLocal.After(expectedStartLocal) {
					lateMinutes = int(inLocal.Sub(expectedStartLocal).Minutes())
				}
				s.logger.Info("Late calculation",
					util.String("expected_start", expectedStartLocal.Format(time.RFC3339)),
					util.String("actual_in", inLocal.Format(time.RFC3339)),
					util.Int("late_minutes", lateMinutes),
				)
				break
			}
		}
	}
	if dayContext.OvertimeAllowed && dayContext.ExpectedEnd != nil && len(events) > 0 {
		expectedEndLocal := dayContext.ExpectedEnd.In(loc)
		for i := len(events) - 1; i >= 0; i-- {
			if events[i].EventType == "check_out" {
				outLocal := events[i].EventTime.In(loc)
				if outLocal.After(expectedEndLocal) {
					overtimeMinutes = int(outLocal.Sub(expectedEndLocal).Minutes())
				}
				s.logger.Info("Overtime calculation",
					util.String("expected_end", expectedEndLocal.Format(time.RFC3339)),
					util.String("actual_out", outLocal.Format(time.RFC3339)),
					util.Int("overtime_minutes", overtimeMinutes),
				)
				break
			}
		}
	}
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
	dayContext, err := s.resolveAttendanceDay(ctx, companyID, userID, at)
	if err != nil {
		s.logger.Error("Failed to resolve attendance day",
			util.String("user_id", userID.String()),
			util.String("company_id", companyID.String()),
			util.String("date", at.Format("2006-01-02")),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to resolve attendance day: %w", err)
	}
	if !dayContext.IsSchedulable {
		summary := &attendance.AttendanceDailySummary{
			AttendanceSummaryID: uuid.New(),
			CompanyID:           companyID,
			UserID:              userID,
			AttendanceDate:      at.UTC().Truncate(24 * time.Hour),
			Status:              "not_schedulable",
			GeneratedAt:         time.Now().UTC(),
			GeneratedBy:         "system",
		}
		if err := s.attendanceRepo.UpsertAttendanceDailySummary(ctx, summary); err != nil {
			return nil, err
		}
		s.logger.Info("Generated summary for non-schedulable position",
			util.String("user_id", userID.String()),
			util.String("date", at.Format("2006-01-02")),
			util.String("schedule_status", dayContext.ScheduleStatus),
		)
		return summary, nil
	}
	if !dayContext.AttendanceRequired {
		summary := &attendance.AttendanceDailySummary{
			AttendanceSummaryID: uuid.New(),
			CompanyID:           companyID,
			UserID:              userID,
			AttendanceDate:      at.UTC().Truncate(24 * time.Hour),
			Status:              "attendance_not_required",
			GeneratedAt:         time.Now().UTC(),
			GeneratedBy:         "system",
		}
		if err := s.attendanceRepo.UpsertAttendanceDailySummary(ctx, summary); err != nil {
			return nil, err
		}
		s.logger.Info("Generated summary for position where attendance not required",
			util.String("user_id", userID.String()),
			util.String("date", at.Format("2006-01-02")),
			util.String("position_id", dayContext.PositionID.String()),
		)
		return summary, nil
	}
	if dayContext.IsOverride {
		summary := &attendance.AttendanceDailySummary{
			AttendanceSummaryID: uuid.New(),
			CompanyID:           companyID,
			UserID:              userID,
			AttendanceDate:      at.UTC().Truncate(24 * time.Hour),
			Status:              "override",
			GeneratedAt:         time.Now().UTC(),
			GeneratedBy:         "system",
		}
		if err := s.attendanceRepo.UpsertAttendanceDailySummary(ctx, summary); err != nil {
			return nil, err
		}
		s.logger.Info("Generated summary for override day",
			util.String("user_id", userID.String()),
			util.String("date", at.Format("2006-01-02")),
			util.String("schedule_status", dayContext.ScheduleStatus),
		)
		return summary, nil
	}
	if dayContext.IsOnLeave {
		summary := &attendance.AttendanceDailySummary{
			AttendanceSummaryID: uuid.New(),
			CompanyID:           companyID,
			UserID:              userID,
			AttendanceDate:      at.UTC().Truncate(24 * time.Hour),
			Status:              "on_leave",
			GeneratedAt:         time.Now().UTC(),
			GeneratedBy:         "system",
		}
		if err := s.attendanceRepo.UpsertAttendanceDailySummary(ctx, summary); err != nil {
			return nil, err
		}
		s.logger.Info("Generated summary for leave day",
			util.String("user_id", userID.String()),
			util.String("date", at.Format("2006-01-02")),
			util.String("schedule_status", dayContext.ScheduleStatus),
		)
		return summary, nil
	}
	if dayContext.ExpectedStart == nil || dayContext.ExpectedEnd == nil {
		summary := &attendance.AttendanceDailySummary{
			AttendanceSummaryID: uuid.New(),
			CompanyID:           companyID,
			UserID:              userID,
			AttendanceDate:      at.UTC().Truncate(24 * time.Hour),
			Status:              dayContext.ScheduleStatus,
			GeneratedAt:         time.Now().UTC(),
			GeneratedBy:         "system",
		}
		if err := s.attendanceRepo.UpsertAttendanceDailySummary(ctx, summary); err != nil {
			return nil, err
		}
		s.logger.Info("Generated summary for non-working day",
			util.String("user_id", userID.String()),
			util.String("date", at.Format("2006-01-02")),
			util.String("schedule_status", dayContext.ScheduleStatus),
		)
		return summary, nil
	}
	loc, err := time.LoadLocation(dayContext.Timezone)
	if err != nil {
		return nil, fmt.Errorf("invalid schedule timezone: %s", dayContext.Timezone)
	}
	atLocal := at.In(loc)
	attendanceDate := time.Date(
		atLocal.Year(),
		atLocal.Month(),
		atLocal.Day(),
		0, 0, 0, 0,
		loc,
	)
	localFrom := attendanceDate
	localTo := attendanceDate.Add(36 * time.Hour)
	fromUTC := localFrom.UTC()
	toUTC := localTo.UTC()
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
	var (
		status   string
		worked   *int
		late     *int
		overtime *int
	)
	if len(events) == 0 {
		status = "absent"
	} else {
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
	}
	metadata := attendance.SummaryMetadata{
		ShiftID: dayContext.ScheduleID,
	}
	metadataMap := make(map[string]interface{})
	if dayContext.PositionID != nil {
		metadataMap["position_id"] = dayContext.PositionID.String()
	}
	if dayContext.PositionTitle != nil {
		metadataMap["position_title"] = *dayContext.PositionTitle
	}
	if dayContext.WorkCenterCode != nil {
		metadataMap["work_center_code"] = *dayContext.WorkCenterCode
	}
	if dayContext.ScheduleStatus != "" {
		metadataMap["schedule_status"] = dayContext.ScheduleStatus
	}
	summary := &attendance.AttendanceDailySummary{
		AttendanceSummaryID: uuid.New(),
		CompanyID:           companyID,
		UserID:              userID,
		AttendanceDate:      attendanceDate,
		Status:              status,
		WorkedMinutes:       worked,
		LateMinutes:         late,
		OvertimeMinutes:     overtime,
		Metadata:            metadata,
		GeneratedAt:         time.Now().UTC(),
		GeneratedBy:         "system",
	}
	if err := s.attendanceRepo.UpsertAttendanceDailySummary(ctx, summary); err != nil {
		return nil, err
	}
	s.logger.Info("=== GenerateDailySummary END ===",
		util.String("summary_id", summary.AttendanceSummaryID.String()),
		util.String("schedule_status", dayContext.ScheduleStatus),
		util.String("position_id", dayContext.PositionID.String()),
	)
	return summary, nil
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
	existingMapping, err := s.attendanceRepo.GetEmployeeRFIDMapping(ctx, rfidTag)
	if err != nil {
		return fmt.Errorf("failed to check RFID mapping: %w", err)
	}
	if existingMapping != nil && existingMapping.UserID != userID && existingMapping.IsActive {
		return fmt.Errorf("RFID tag %s is already assigned to another employee", rfidTag)
	}
	userMapping, err := s.attendanceRepo.GetEmployeeRFIDMappingByUser(ctx, userID)
	if err == nil && userMapping != nil && userMapping.IsActive {
		if err := s.attendanceRepo.DeactivateEmployeeRFIDMapping(ctx, userMapping.RFIDID); err != nil {
			s.logger.Warn("Failed to deactivate existing RFID mapping",
				util.String("user_id", userID.String()),
				util.String("rfid_tag", userMapping.RFIDTag),
				util.ErrorField(err))
		}
	}
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
	if mapping.CompanyID != companyID {
		return nil, fmt.Errorf("RFID tag does not belong to this company")
	}
	if !mapping.IsActive {
		return nil, fmt.Errorf("RFID mapping is not active")
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
func (s *attendanceServiceImpl) ValidateAttendanceSourceType(
	ctx context.Context,
	sourceType string,
	sourceID *uuid.UUID,
) error {
	sourceTypeDef, err := s.GetAttendanceSourceType(ctx, sourceType)
	if err != nil {
		return fmt.Errorf("failed to validate attendance source type: %w", err)
	}
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
	if err := s.validateEventRules(ctx, event); err != nil {
		return err
	}
	employee, err := s.schedulingRepo.GetUserCompany(ctx, event.UserID)
	if err != nil {
		return fmt.Errorf("failed to get user company: %w", err)
	}
	resolvedDay, err := s.schedulingService.ResolveUserDay(ctx, employee.CompanyID, event.UserID, event.EventTime)
	if err != nil {
		return fmt.Errorf("failed to resolve schedule for validation: %w", err)
	}
	if !resolvedDay.IsSchedulable {
		return fmt.Errorf("position is not schedulable: %s", resolvedDay.ScheduleStatus)
	}
	if !resolvedDay.AttendanceRequired {
		return fmt.Errorf("attendance not required for this position")
	}
	if resolvedDay.IsOverride && resolvedDay.OverrideType != nil && *resolvedDay.OverrideType == "off" {
		return fmt.Errorf("user has scheduled off day")
	}
	if resolvedDay.IsOnLeave {
		return fmt.Errorf("user is on approved leave")
	}
	if resolvedDay.ExpectedStart == nil || resolvedDay.ExpectedEnd == nil {
		return fmt.Errorf("not a working day: %s", resolvedDay.ScheduleStatus)
	}
	if event.EventType == "check_in" || event.EventType == "check_out" {
		eventLocal := event.EventTime.In(time.UTC)
		expectedStart := resolvedDay.ExpectedStart.In(time.UTC)
		expectedEnd := resolvedDay.ExpectedEnd.In(time.UTC)
		buffer := 2 * time.Hour
		earliestAllowed := expectedStart.Add(-buffer)
		latestAllowed := expectedEnd.Add(buffer)
		if eventLocal.Before(earliestAllowed) || eventLocal.After(latestAllowed) {
			return fmt.Errorf("event time %s is outside of allowed window (expected: %s - %s)",
				eventLocal.Format("15:04"),
				expectedStart.Format("15:04"),
				expectedEnd.Format("15:04"))
		}
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
	if policy.CompanyID == uuid.Nil {
		return nil, fmt.Errorf("company ID is required")
	}
	if policy.PolicyCode == "" {
		return nil, fmt.Errorf("policy code is required")
	}
	if policy.PolicyType == "" {
		return nil, fmt.Errorf("policy type is required")
	}
	existingPolicies, err := s.attendanceRepo.GetAttendancePoliciesByCompany(ctx, policy.CompanyID, false)
	if err == nil {
		for _, existing := range existingPolicies {
			if existing.PolicyCode == policy.PolicyCode {
				return nil, fmt.Errorf("policy with code %s already exists", policy.PolicyCode)
			}
		}
	}
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
	existingPolicy, err := s.attendanceRepo.GetAttendancePolicyByID(ctx, policy.PolicyID)
	if err != nil {
		return fmt.Errorf("failed to get attendance policy: %w", err)
	}
	if existingPolicy == nil {
		return fmt.Errorf("attendance policy not found")
	}
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
	policy, err := s.attendanceRepo.GetAttendancePolicyByID(ctx, policyID)
	if err != nil {
		return fmt.Errorf("failed to get attendance policy: %w", err)
	}
	if policy == nil {
		return fmt.Errorf("attendance policy not found")
	}
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
	existingPolicy, err := s.attendanceRepo.GetUserActiveAttendancePolicy(ctx, userPolicy.UserID, time.Now())
	if err == nil && existingPolicy != nil {
		if existingPolicy.PolicyID == userPolicy.PolicyID {
			return nil
		}
		if err := s.attendanceRepo.EndUserAttendancePolicy(ctx, userPolicy.UserID, existingPolicy.PolicyID, userPolicy.EffectiveFrom); err != nil {
			s.logger.Warn("Failed to end previous attendance policy",
				util.String("user_id", userPolicy.UserID.String()),
				util.String("policy_id", existingPolicy.PolicyID.String()),
				util.ErrorField(err))
		}
	}
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
	sourceTypes, err := s.attendanceRepo.GetAttendanceSourceTypes(ctx)
	if err != nil {
		return fmt.Errorf("failed to load attendance source types: %w", err)
	}
	validSources := make(map[string]struct{}, len(sourceTypes))
	for _, st := range sourceTypes {
		validSources[st.SourceType] = struct{}{}
	}
	if len(rules.AllowedSourceTypes) == 0 {
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
	companyRules, err := s.attendanceRepo.GetCompanyAttendanceRules(ctx, rules.CompanyID)
	if err != nil {
		return fmt.Errorf("failed to load company attendance rules: %w", err)
	}
	companySourceMap := make(map[string]bool, len(companyRules.AllowedSourceTypes))
	for _, src := range companyRules.AllowedSourceTypes {
		companySourceMap[src] = true
	}
	for _, src := range rules.AllowedSourceTypes {
		if !companySourceMap[src] {
			return fmt.Errorf(
				"invalid source type '%s': not allowed by company",
				src,
			)
		}
	}
	for _, eventType := range rules.AllowedEventTypes {
		if !validAttendanceEventTypes[eventType] {
			return fmt.Errorf(
				"invalid event type '%s': not a supported attendance event",
				eventType,
			)
		}
	}
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
func (s *attendanceServiceImpl) ResolveAttendanceRules(
	ctx context.Context,
	userID, companyID, departmentID uuid.UUID,
) (*attendance.ResolvedAttendanceRules, error) {
	resolved := &attendance.ResolvedAttendanceRules{
		AllowedSourceTypesMap: make(map[string]bool),
		AllowedEventTypesMap:  make(map[string]bool),
		AppliedAt:             time.Now().UTC(),
	}
	companyRules, err := s.attendanceRepo.GetCompanyAttendanceRules(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get company attendance rules: %w", err)
	}
	resolved.CompanyID = companyID
	resolved.Timezone = companyRules.Timezone
	resolved.AllowMultipleCheckins = companyRules.AllowMultipleCheckins
	resolved.AllowedSourceTypes = companyRules.AllowedSourceTypes
	for _, sourceType := range companyRules.AllowedSourceTypes {
		resolved.AllowedSourceTypesMap[sourceType] = true
	}
	if departmentID != uuid.Nil {
		deptRules, err := s.attendanceRepo.GetDepartmentAttendanceRules(ctx, companyID, departmentID)
		if err == nil && deptRules != nil {
			resolved.RequireLocation = deptRules.RequireLocation
			resolved.RequireDevice = deptRules.RequireDevice
			resolved.SourceLevel = "department"
			if len(deptRules.AllowedSourceTypes) > 0 {
				resolved.AllowedSourceTypes = deptRules.AllowedSourceTypes
				resolved.AllowedSourceTypesMap = make(map[string]bool)
				for _, sourceType := range deptRules.AllowedSourceTypes {
					resolved.AllowedSourceTypesMap[sourceType] = true
				}
			}
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
	if userID != uuid.Nil {
		userProfile, err := s.attendanceRepo.GetUserAttendanceProfile(ctx, userID)
		if err == nil && userProfile != nil {
			resolved.SourceLevel = "user"
			if userProfile.OverrideSourceTypes != nil && len(userProfile.OverrideSourceTypes) > 0 {
				resolved.AllowedSourceTypes = userProfile.OverrideSourceTypes
				resolved.AllowedSourceTypesMap = make(map[string]bool)
				for _, sourceType := range userProfile.OverrideSourceTypes {
					resolved.AllowedSourceTypesMap[sourceType] = true
				}
			}
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
	if len(resolved.AllowedEventTypes) == 0 {
		resolved.AllowAllEventTypes = true
	}
	resolved.RequireReference = false
	return resolved, nil
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
	maxDays := 31
	if endDate.Sub(startDate).Hours()/24 > float64(maxDays) {
		return nil, fmt.Errorf("date range cannot exceed %d days", maxDays)
	}
	stats, err := s.attendanceRepo.GetAttendanceStats(ctx, companyID, startDate, endDate)
	if err != nil {
		s.logger.Error("Failed to get attendance stats",
			util.String("company_id", companyID.String()),
			util.Time("start_date", startDate),
			util.Time("end_date", endDate),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get attendance stats: %w", err)
	}
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
	maxDays := 365
	if endDate.Sub(startDate).Hours()/24 > float64(maxDays) {
		return nil, fmt.Errorf("date range cannot exceed %d days", maxDays)
	}
	_, err := s.attendanceRepo.GetUserAttendanceProfile(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user attendance profile: %w", err)
	}
	stats, err := s.attendanceRepo.GetUserAttendanceStats(ctx, userID, startDate, endDate)
	if err != nil {
		s.logger.Error("Failed to get user attendance stats",
			util.String("user_id", userID.String()),
			util.Time("start_date", startDate),
			util.Time("end_date", endDate),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get user attendance stats: %w", err)
	}
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
func (s *attendanceServiceImpl) CheckDateAvailability(
	ctx context.Context,
	userID uuid.UUID,
	date time.Time,
) (map[string]interface{}, error) {
	result := map[string]interface{}{
		"user_id":   userID,
		"date":      date.Format("2006-01-02"),
		"available": true,
		"reasons":   []string{},
	}
	employee, err := s.schedulingRepo.GetUserCompany(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user company: %w", err)
	}
	resolvedDay, err := s.schedulingService.ResolveUserDay(ctx, employee.CompanyID, userID, date)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve schedule: %w", err)
	}
	result["schedule_resolution"] = map[string]interface{}{
		"is_schedulable":      resolvedDay.IsSchedulable,
		"attendance_required": resolvedDay.AttendanceRequired,
		"schedule_status":     resolvedDay.ScheduleStatus,
		"position_id":         resolvedDay.PositionID,
		"position_title":      resolvedDay.PositionTitle,
		"work_center_code":    resolvedDay.WorkCenterCode,
	}
	if !resolvedDay.IsSchedulable {
		result["available"] = false
		result["reasons"] = append(result["reasons"].([]string),
			fmt.Sprintf("Position not schedulable: %s", resolvedDay.ScheduleStatus))
	}
	if !resolvedDay.AttendanceRequired {
		result["available"] = false
		result["attendance_not_required"] = true
		result["reasons"] = append(result["reasons"].([]string),
			"Attendance not required for this position")
	}
	if resolvedDay.IsOverride {
		result["schedule_override"] = map[string]interface{}{
			"override_type": resolvedDay.OverrideType,
		}
		switch *resolvedDay.OverrideType {
		case "off":
			result["available"] = false
			result["is_off_day"] = true
			result["reasons"] = append(result["reasons"].([]string), "Schedule override: off day")
		case "force_work":
			result["available"] = true
			result["forced_work"] = true
			result["reasons"] = append(result["reasons"].([]string), "Schedule override: forced work")
		}
	}
	if resolvedDay.IsOnLeave {
		result["available"] = false
		result["off_request"] = map[string]interface{}{
			"leave_request_id": resolvedDay.LeaveRequestID,
		}
		result["reasons"] = append(result["reasons"].([]string), "On approved leave")
		result["is_off_day"] = true
	}
	if resolvedDay.ScheduleInstanceID != nil {
		instance, err := s.schedulingRepo.GetScheduleInstanceByID(ctx, *resolvedDay.ScheduleInstanceID)
		if err == nil && instance != nil {
			result["schedule_instance"] = instance
			if instance.ExpectedStart != nil && instance.ExpectedEnd != nil {
				result["scheduled_hours"] = map[string]interface{}{
					"start": instance.ExpectedStart.Format("15:04"),
					"end":   instance.ExpectedEnd.Format("15:04"),
				}
			}
		}
	}
	return result, nil
}
func (s *attendanceServiceImpl) HealthCheck(ctx context.Context) error {
	if err := s.attendanceRepo.HealthCheck(ctx); err != nil {
		return fmt.Errorf("attendance repository health check failed: %w", err)
	}
	return nil
}
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
func normalizeSourceType(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

var validAttendanceEventTypes = map[string]bool{
	"check_in":              true,
	"check_out":             true,
	"break_start":           true,
	"break_end":             true,
	"shift_start":           true,
	"shift_end":             true,
	"overtime_start":        true,
	"overtime_end":          true,
	"early_exit":            true,
	"late_entry":            true,
	"gate_entry":            true,
	"gate_exit":             true,
	"zone_entry":            true,
	"zone_exit":             true,
	"class_start":           true,
	"class_end":             true,
	"session_join":          true,
	"session_leave":         true,
	"leave_start":           true,
	"leave_end":             true,
	"absent_marked":         true,
	"holiday_marked":        true,
	"weekly_off":            true,
	"manual_check_in":       true,
	"manual_check_out":      true,
	"manual_override":       true,
	"attendance_adjustment": true,
	"biometric_sync":        true,
	"rfid_scan":             true,
	"system_generated":      true,
	"imported_event":        true,
	"missing_punch":         true,
	"duplicate_punch":       true,
	"invalid_punch":         true,
	"policy_violation":      true,
}

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
func (qs *attendanceQueryServiceImpl) SearchAttendanceEventsTyped(
	ctx context.Context,
	companyID uuid.UUID,
	filters AttendanceSearchFilters,
	page, pageSize int,
) ([]*attendance.AttendanceEvent, int, error) {
	startTime := time.Now()
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	if filters.StartDate.IsZero() {
		filters.StartDate = time.Now().AddDate(0, 0, -30)
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
		qs.logger.Error("Failed to get attendance policies by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
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
	if startDate.After(endDate) {
		return nil, fmt.Errorf("start date cannot be after end date")
	}
	maxDays := 31
	if endDate.Sub(startDate).Hours()/24 > float64(maxDays) {
		return nil, fmt.Errorf("date range cannot exceed %d days", maxDays)
	}
	stats, err := qs.attendanceRepo.GetAttendanceStats(ctx, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance stats: %w", err)
	}
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
	if reportType != "csv" && reportType != "json" {
		return nil, "", fmt.Errorf("unsupported report type: %s. Supported types: csv, json", reportType)
	}
	maxDays := 31
	if endDate.Sub(startDate).Hours()/24 > float64(maxDays) {
		return nil, "", fmt.Errorf("date range cannot exceed %d days", maxDays)
	}
	summaries, _, err := qs.attendanceRepo.GetAttendanceDailySummariesByCompany(ctx, companyID, startDate, endDate, 1, 10000)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get attendance summaries: %w", err)
	}
	var reportData []byte
	var contentType string
	var err2 error
	switch reportType {
	case "csv":
		reportData, err2 = qs.generateCSVReport(summaries)
		contentType = "text/csv"
	case "json":
		reportData, err2 = qs.generateJSONReport(summaries)
		contentType = "application/json"
	}
	if err2 != nil {
		return nil, "", fmt.Errorf("failed to generate %s report: %w", reportType, err2)
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
	header := []string{
		"Date", "User ID", "Status", "Worked Hours", "Overtime Hours",
		"Late Minutes", "Generated At",
	}
	if err := writer.Write(header); err != nil {
		return nil, err
	}
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
		if page*pageSize >= int(total) {
			break
		}
		page++
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
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
func (qs *attendanceQueryServiceImpl) ListAttendanceEventTypes(
	ctx context.Context,
	activeOnly bool,
) ([]*attendance.AttendanceEventType, error) {
	eventTypes, err := qs.attendanceRepo.GetAttendanceEventTypes(ctx)
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
func (qs *attendanceQueryServiceImpl) ListAttendanceSourceTypes(
	ctx context.Context,
) ([]*attendance.AttendanceSourceType, error) {
	sourceTypes, err := qs.attendanceRepo.GetAttendanceSourceTypes(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance source types: %w", err)
	}
	return sourceTypes, nil
}
func (qs *attendanceQueryServiceImpl) HealthCheck(ctx context.Context) error {
	if err := qs.attendanceRepo.HealthCheck(ctx); err != nil {
		return fmt.Errorf("attendance repository health check failed: %w", err)
	}
	return nil
}
