package service

import (
	"auth-service/internal/hr/models/scheduling"
	"auth-service/internal/hr/repository"
	"auth-service/internal/util"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type WorkCalendarUpdate struct {
	Name        *string              `json:"name,omitempty"`
	Timezone    *string              `json:"timezone,omitempty"`
	WorkingDays []int                `json:"working_days,omitempty"`
	Holidays    []scheduling.Holiday `json:"holidays,omitempty"`
	IsActive    *bool                `json:"is_active,omitempty"`
}

type ScheduleTemplateUpdate struct {
	Name         *string                   `json:"name,omitempty"`
	CalendarID   *uuid.UUID                `json:"calendar_id,omitempty"`
	TemplateType *string                   `json:"template_type,omitempty"`
	Rules        *scheduling.TemplateRules `json:"rules,omitempty"`
	IsActive     *bool                     `json:"is_active,omitempty"`
}

type ScheduleInstanceUpdate struct {
	ExpectedStart *time.Time                   `json:"expected_start,omitempty"`
	ExpectedEnd   *time.Time                   `json:"expected_end,omitempty"`
	Timezone      *string                      `json:"timezone,omitempty"`
	Metadata      *scheduling.InstanceMetadata `json:"metadata,omitempty"`
}

type ScheduleGenerationConfig struct {
	StartDate       time.Time `json:"start_date"`
	EndDate         time.Time `json:"end_date"`
	Timezone        string    `json:"timezone"`
	IncludeHolidays bool      `json:"include_holidays"`
	Overwrite       bool      `json:"overwrite"`
	BatchSize       int       `json:"batch_size"`
}

type SchedulingService interface {
	// Work Calendar Operations
	CreateWorkCalendar(ctx context.Context, calendar *scheduling.WorkCalendar, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*scheduling.WorkCalendar, error)
	UpdateWorkCalendar(ctx context.Context, calendarID uuid.UUID, update WorkCalendarUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*scheduling.WorkCalendar, error)
	DeleteWorkCalendar(ctx context.Context, calendarID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	ValidateWorkCalendar(ctx context.Context, calendar *scheduling.WorkCalendar) error
	AddHolidayToCalendar(ctx context.Context, calendarID uuid.UUID, date string, name string, actorType string, actorID uuid.UUID) error
	ProcessHolidayForDate(ctx context.Context, companyID uuid.UUID, date time.Time, actorType string, actorID uuid.UUID) error

	// Schedule Template Operations
	CreateScheduleTemplate(ctx context.Context, template *scheduling.ScheduleTemplate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*scheduling.ScheduleTemplate, error)
	UpdateScheduleTemplate(ctx context.Context, templateID uuid.UUID, update ScheduleTemplateUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*scheduling.ScheduleTemplate, error)
	DeleteScheduleTemplate(ctx context.Context, templateID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	ValidateScheduleTemplate(ctx context.Context, template *scheduling.ScheduleTemplate) error

	// Schedule Instance Operations
	CreateScheduleInstance(ctx context.Context, instance *scheduling.ScheduleInstance, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*scheduling.ScheduleInstance, error)
	UpdateScheduleInstance(ctx context.Context, instanceID uuid.UUID, update ScheduleInstanceUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*scheduling.ScheduleInstance, error)
	DeleteScheduleInstance(ctx context.Context, instanceID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	BulkCreateScheduleInstances(ctx context.Context, instances []*scheduling.ScheduleInstance, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error

	// Position-Based Schedule Generation
	GenerateScheduleForUser(ctx context.Context, userID uuid.UUID, config ScheduleGenerationConfig, actorType string, actorID uuid.UUID) ([]*scheduling.ScheduleInstance, error)
	GenerateScheduleForCompany(ctx context.Context, companyID uuid.UUID, config ScheduleGenerationConfig, actorType string, actorID uuid.UUID) ([]*scheduling.ScheduleInstance, error)
	GenerateScheduleForTemplate(ctx context.Context, templateID uuid.UUID, config ScheduleGenerationConfig, actorType string, actorID uuid.UUID) ([]*scheduling.ScheduleInstance, error)

	// Schedule Resolution (Position-Based)
	ResolveUserDay(ctx context.Context, companyID, userID uuid.UUID, date time.Time) (*PositionBasedResolvedDay, error)
	CreateScheduleInstanceFromPosition(ctx context.Context, companyID, userID uuid.UUID, date time.Time, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*scheduling.ScheduleInstance, error)

	// Schedule Availability & Conflict Checking
	CheckScheduleAvailability(ctx context.Context, userID uuid.UUID, date time.Time, timezone string) ([]time.Time, error)
	CheckDateAvailability(ctx context.Context, userID uuid.UUID, date time.Time) (map[string]interface{}, error)
	ValidateScheduleConflict(ctx context.Context, userID uuid.UUID, startTime, endTime time.Time, excludeInstanceID *uuid.UUID) (bool, error)

	// Off Management
	CreateOffEntitlement(ctx context.Context, companyID uuid.UUID, entitlement *scheduling.UserOffEntitlement, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*scheduling.UserOffEntitlement, error)
	UpdateOffEntitlement(ctx context.Context, entitlementID uuid.UUID, update scheduling.OffEntitlementUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*scheduling.UserOffEntitlement, error)
	DeleteOffEntitlement(ctx context.Context, entitlementID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	GetUserOffBalance(ctx context.Context, userID uuid.UUID, periodType string, startDate, endDate time.Time) (map[string]interface{}, error)

	// Off Requests
	CreateOffRequest(ctx context.Context, companyID uuid.UUID, request *scheduling.OffRequest, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*scheduling.OffRequest, error)
	UpdateOffRequest(ctx context.Context, requestID uuid.UUID, update scheduling.OffRequestUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*scheduling.OffRequest, error)
	DeleteOffRequest(ctx context.Context, requestID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	ApproveOffRequest(ctx context.Context, requestID uuid.UUID, approvedBy uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	RejectOffRequest(ctx context.Context, requestID uuid.UUID, rejectedBy uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	ValidateOffRequest(ctx context.Context, userID uuid.UUID, requestDates []string, excludeRequestID *uuid.UUID) error
	RequestTimeOff(ctx context.Context, companyID, userID uuid.UUID, requestDates []string, reason string, actorType string, actorID uuid.UUID) (*scheduling.OffRequest, error)
	GetUserTimeOffSummary(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error)

	// Schedule Overrides
	CreateScheduleOverride(ctx context.Context, companyID uuid.UUID, override *scheduling.ScheduleOverride, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*scheduling.ScheduleOverride, error)
	UpdateScheduleOverride(ctx context.Context, overrideID uuid.UUID, update scheduling.ScheduleOverrideUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*scheduling.ScheduleOverride, error)
	DeleteScheduleOverride(ctx context.Context, overrideID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	GetScheduleOverridesByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*scheduling.ScheduleOverride, error)

	// Work Center Operations (NEW)
	CreateWorkCenterShiftMapping(ctx context.Context, companyID uuid.UUID, mapping *scheduling.WorkCenterShiftMapping, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	UpdateWorkCenterShiftMapping(ctx context.Context, mappingID uuid.UUID, update scheduling.WorkCenterShiftMappingUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	AssignUserToWorkCenter(ctx context.Context, companyID uuid.UUID, assignment *scheduling.UserWorkCenterAssignment, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	EndUserWorkCenterAssignment(ctx context.Context, assignmentID uuid.UUID, endDate time.Time, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error

	// Health Check
	HealthCheck(ctx context.Context) error
}

// PositionBasedResolvedDay - New response structure for position-based scheduling
type PositionBasedResolvedDay struct {
	Date               time.Time  `json:"date"`
	Timezone           string     `json:"timezone"`
	IsSchedulable      bool       `json:"is_schedulable"`
	AttendanceRequired bool       `json:"attendance_required"`
	OvertimeAllowed    bool       `json:"overtime_allowed"`
	ExpectedStart      *time.Time `json:"expected_start,omitempty"`
	ExpectedEnd        *time.Time `json:"expected_end,omitempty"`
	PositionID         *uuid.UUID `json:"position_id,omitempty"`
	PositionTitle      *string    `json:"position_title,omitempty"`
	DepartmentID       *uuid.UUID `json:"department_id,omitempty"` // ✅ ADD
	WorkCenterCode     *string    `json:"work_center_code,omitempty"`
	WorkCenterName     *string    `json:"work_center_name,omitempty"`
	ShiftID            *uuid.UUID `json:"shift_id,omitempty"`
	ShiftName          *string    `json:"shift_name,omitempty"`
	ScheduleInstanceID *uuid.UUID `json:"schedule_instance_id,omitempty"`
	ScheduleStatus     string     `json:"schedule_status"`
	IsOverride         bool       `json:"is_override"`
	OverrideType       *string    `json:"override_type,omitempty"`
	IsOnLeave          bool       `json:"is_on_leave"`
	LeaveRequestID     *uuid.UUID `json:"leave_request_id,omitempty"`
}

type schedulingServiceImpl struct {
	schedulingRepo repository.SchedulingRepository
	auditService   *AuditService
	logger         *zap.Logger
	mu             sync.RWMutex
}

func NewSchedulingService(
	schedulingRepo repository.SchedulingRepository,
	auditService *AuditService,
	logger *zap.Logger,
) SchedulingService {
	return &schedulingServiceImpl{
		schedulingRepo: schedulingRepo,
		auditService:   auditService,
		logger:         logger,
	}
}

func (s *schedulingServiceImpl) CreateWorkCalendar(
	ctx context.Context,
	calendar *scheduling.WorkCalendar,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*scheduling.WorkCalendar, error) {
	startTime := time.Now()

	if err := s.validateWorkCalendar(calendar); err != nil {
		return nil, fmt.Errorf("work calendar validation failed: %w", err)
	}

	if calendar.CalendarID == uuid.Nil {
		calendar.CalendarID = uuid.New()
	}

	now := time.Now().UTC()
	if calendar.CreatedAt.IsZero() {
		calendar.CreatedAt = now
	}

	existingCalendars, err := s.schedulingRepo.GetWorkCalendarsByCompany(ctx, calendar.CompanyID)
	if err == nil {
		for _, existing := range existingCalendars {
			if existing.Year == calendar.Year {
				return nil, fmt.Errorf(
					"work calendar already exists for year %d",
					calendar.Year,
				)
			}
		}
	}

	if err := s.validateWorkingDays(calendar.WorkingDays); err != nil {
		return nil, fmt.Errorf("invalid working days: %w", err)
	}

	if err := s.validateHolidays(calendar.Holidays); err != nil {
		return nil, fmt.Errorf("invalid holidays: %w", err)
	}

	if err := s.validateTimezone(calendar.Timezone); err != nil {
		return nil, fmt.Errorf("invalid timezone: %w", err)
	}

	if err := s.schedulingRepo.CreateWorkCalendar(ctx, calendar); err != nil {
		s.logger.Error("Failed to create work calendar",
			util.String("company_id", calendar.CompanyID.String()),
			util.String("name", calendar.Name),
			util.Int("year", calendar.Year),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create work calendar: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			calendarJSON, _ := json.Marshal(calendar)
			s.auditService.LogAction(
				auditCtx,
				&calendar.CompanyID,
				"scheduling",
				"work_calendar.create",
				"work_calendar",
				&calendar.CalendarID,
				actorType,
				&actorID,
				nil,
				calendarJSON,
				metadata,
			)
		}()
	}

	s.logger.Info("Work calendar created",
		util.String("calendar_id", calendar.CalendarID.String()),
		util.String("company_id", calendar.CompanyID.String()),
		util.Int("year", calendar.Year),
		util.String("name", calendar.Name),
		util.Duration("duration", time.Since(startTime)),
	)

	return calendar, nil
}

func (s *schedulingServiceImpl) UpdateWorkCalendar(
	ctx context.Context,
	calendarID uuid.UUID,
	update WorkCalendarUpdate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*scheduling.WorkCalendar, error) {
	startTime := time.Now()

	calendar, err := s.schedulingRepo.GetWorkCalendarByID(ctx, calendarID)
	if err != nil {
		return nil, fmt.Errorf("work calendar not found: %w", err)
	}

	beforeState, _ := json.Marshal(calendar)
	oldName := calendar.Name

	if update.Name != nil {
		calendar.Name = *update.Name
	}

	if update.Timezone != nil {
		if err := s.validateTimezone(*update.Timezone); err != nil {
			return nil, fmt.Errorf("invalid timezone: %w", err)
		}
		calendar.Timezone = *update.Timezone
	}

	if update.WorkingDays != nil {
		if err := s.validateWorkingDays(update.WorkingDays); err != nil {
			return nil, fmt.Errorf("invalid working days: %w", err)
		}
		calendar.WorkingDays = update.WorkingDays
	}

	if update.Holidays != nil {
		oldHolidayMap := make(map[string]bool)
		for _, h := range calendar.Holidays {
			oldHolidayMap[h.Date] = true
		}

		for _, h := range update.Holidays {
			if !oldHolidayMap[h.Date] {
				holidayDate, err := time.Parse("2006-01-02", h.Date)
				if err == nil {
					_ = s.ProcessHolidayForDate(
						ctx,
						calendar.CompanyID,
						holidayDate,
						actorType,
						actorID,
					)
				}
			}
		}
		calendar.Holidays = update.Holidays
	}

	if update.IsActive != nil {
		calendar.IsActive = *update.IsActive
	}

	if err := s.validateWorkCalendar(calendar); err != nil {
		return nil, fmt.Errorf("work calendar validation failed: %w", err)
	}

	if update.Name != nil && *update.Name != oldName {
		existingCalendars, err := s.schedulingRepo.GetWorkCalendarsByCompany(ctx, calendar.CompanyID)
		if err == nil {
			for _, existing := range existingCalendars {
				if existing.CalendarID != calendarID &&
					strings.EqualFold(existing.Name, *update.Name) {
					return nil, fmt.Errorf(
						"work calendar with name '%s' already exists",
						*update.Name,
					)
				}
			}
		}
	}

	if err := s.schedulingRepo.UpdateWorkCalendar(ctx, calendar); err != nil {
		s.logger.Error("Failed to update work calendar",
			util.String("calendar_id", calendarID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to update work calendar: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			afterState, _ := json.Marshal(calendar)
			s.auditService.LogAction(
				auditCtx,
				&calendar.CompanyID,
				"scheduling",
				"work_calendar.update",
				"work_calendar",
				&calendarID,
				actorType,
				&actorID,
				beforeState,
				afterState,
				metadata,
			)
		}()
	}

	s.logger.Info("Work calendar updated",
		util.String("calendar_id", calendarID.String()),
		util.Int("year", calendar.Year),
		util.Duration("duration", time.Since(startTime)),
	)

	return calendar, nil
}

func (s *schedulingServiceImpl) DeleteWorkCalendar(
	ctx context.Context,
	calendarID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	calendar, err := s.schedulingRepo.GetWorkCalendarByID(ctx, calendarID)
	if err != nil {
		return fmt.Errorf("work calendar not found: %w", err)
	}

	templates, err := s.schedulingRepo.GetScheduleTemplatesByCalendar(ctx, calendarID)
	if err == nil && len(templates) > 0 {
		return fmt.Errorf("cannot delete calendar used by %d schedule templates", len(templates))
	}

	beforeState, _ := json.Marshal(calendar)

	err = s.schedulingRepo.DeleteWorkCalendar(ctx, calendarID)
	if err != nil {
		s.logger.Error("Failed to delete work calendar",
			util.String("calendar_id", calendarID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to delete work calendar: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s.auditService.LogAction(auditCtx,
				&calendar.CompanyID,
				"scheduling",
				"work_calendar.delete",
				"work_calendar",
				&calendarID,
				actorType,
				&actorID,
				beforeState,
				nil,
				metadata,
			)
		}()
	}

	s.logger.Info("Work calendar deleted",
		util.String("calendar_id", calendarID.String()),
		util.String("company_id", calendar.CompanyID.String()),
		util.String("name", calendar.Name),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *schedulingServiceImpl) ValidateWorkCalendar(ctx context.Context, calendar *scheduling.WorkCalendar) error {
	return s.validateWorkCalendar(calendar)
}

func (s *schedulingServiceImpl) CreateScheduleTemplate(
	ctx context.Context,
	template *scheduling.ScheduleTemplate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*scheduling.ScheduleTemplate, error) {
	startTime := time.Now()

	if err := s.validateScheduleTemplate(template); err != nil {
		return nil, fmt.Errorf("schedule template validation failed: %w", err)
	}

	if template.ScheduleTemplateID == uuid.Nil {
		template.ScheduleTemplateID = uuid.New()
	}

	now := time.Now().UTC()
	if template.CreatedAt.IsZero() {
		template.CreatedAt = now
	}

	existingTemplates, err := s.schedulingRepo.GetScheduleTemplatesByCompany(ctx, template.CompanyID)
	if err == nil {
		for _, existing := range existingTemplates {
			if strings.EqualFold(existing.Name, template.Name) {
				return nil, fmt.Errorf("schedule template with name '%s' already exists", template.Name)
			}
		}
	}

	calendar, err := s.schedulingRepo.GetWorkCalendarByID(ctx, template.CalendarID)
	if err != nil {
		return nil, fmt.Errorf("work calendar not found: %w", err)
	}

	if calendar.CompanyID != template.CompanyID {
		return nil, fmt.Errorf("calendar does not belong to company")
	}

	if err := s.validateTemplateRules(template.TemplateType, &template.Rules); err != nil {
		return nil, fmt.Errorf("template rules validation failed: %w", err)
	}

	err = s.schedulingRepo.CreateScheduleTemplate(ctx, template)
	if err != nil {
		s.logger.Error("Failed to create schedule template",
			util.String("company_id", template.CompanyID.String()),
			util.String("name", template.Name),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create schedule template: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			templateJSON, _ := json.Marshal(template)
			s.auditService.LogAction(auditCtx,
				&template.CompanyID,
				"scheduling",
				"schedule_template.create",
				"schedule_template",
				&template.ScheduleTemplateID,
				actorType,
				&actorID,
				nil,
				templateJSON,
				metadata,
			)
		}()
	}

	s.logger.Info("Schedule template created",
		util.String("template_id", template.ScheduleTemplateID.String()),
		util.String("company_id", template.CompanyID.String()),
		util.String("name", template.Name),
		util.String("template_type", template.TemplateType),
		util.String("calendar_id", template.CalendarID.String()),
		util.Duration("duration", time.Since(startTime)))

	return template, nil
}

func (s *schedulingServiceImpl) UpdateScheduleTemplate(
	ctx context.Context,
	templateID uuid.UUID,
	update ScheduleTemplateUpdate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*scheduling.ScheduleTemplate, error) {
	startTime := time.Now()

	template, err := s.schedulingRepo.GetScheduleTemplateByID(ctx, templateID)
	if err != nil {
		return nil, fmt.Errorf("schedule template not found: %w", err)
	}

	beforeState, _ := json.Marshal(template)

	if update.Name != nil {
		template.Name = *update.Name
	}

	if update.CalendarID != nil {
		calendar, err := s.schedulingRepo.GetWorkCalendarByID(ctx, *update.CalendarID)
		if err != nil {
			return nil, fmt.Errorf("work calendar not found: %w", err)
		}
		if calendar.CompanyID != template.CompanyID {
			return nil, fmt.Errorf("calendar does not belong to company")
		}
		template.CalendarID = *update.CalendarID
	}

	if update.TemplateType != nil {
		template.TemplateType = *update.TemplateType
	}

	if update.Rules != nil {
		if err := s.validateTemplateRules(template.TemplateType, update.Rules); err != nil {
			return nil, fmt.Errorf("template rules validation failed: %w", err)
		}
		template.Rules = *update.Rules
	}

	if update.IsActive != nil {
		template.IsActive = *update.IsActive
	}

	if err := s.validateScheduleTemplate(template); err != nil {
		return nil, fmt.Errorf("schedule template validation failed: %w", err)
	}

	if update.Name != nil && *update.Name != template.Name {
		existingTemplates, err := s.schedulingRepo.GetScheduleTemplatesByCompany(ctx, template.CompanyID)
		if err == nil {
			for _, existing := range existingTemplates {
				if existing.ScheduleTemplateID != templateID && strings.EqualFold(existing.Name, *update.Name) {
					return nil, fmt.Errorf("schedule template with name '%s' already exists", *update.Name)
				}
			}
		}
	}

	err = s.schedulingRepo.UpdateScheduleTemplate(ctx, template)
	if err != nil {
		s.logger.Error("Failed to update schedule template",
			util.String("template_id", templateID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to update schedule template: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			afterState, _ := json.Marshal(template)
			s.auditService.LogAction(auditCtx,
				&template.CompanyID,
				"scheduling",
				"schedule_template.update",
				"schedule_template",
				&templateID,
				actorType,
				&actorID,
				beforeState,
				afterState,
				metadata,
			)
		}()
	}

	s.logger.Info("Schedule template updated",
		util.String("template_id", templateID.String()),
		util.String("company_id", template.CompanyID.String()),
		util.String("name", template.Name),
		util.Duration("duration", time.Since(startTime)))

	return template, nil
}

func (s *schedulingServiceImpl) DeleteScheduleTemplate(
	ctx context.Context,
	templateID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	template, err := s.schedulingRepo.GetScheduleTemplateByID(ctx, templateID)
	if err != nil {
		return fmt.Errorf("schedule template not found: %w", err)
	}

	// Check if template is used in work center shift mappings
	mappings, err := s.schedulingRepo.GetWorkCenterShiftMappingsByShift(ctx, templateID)
	if err == nil && len(mappings) > 0 {
		return fmt.Errorf("cannot delete template used by %d work center shift mappings", len(mappings))
	}

	instances, err := s.schedulingRepo.GetScheduleInstancesByTemplate(ctx, templateID,
		time.Now().AddDate(0, -1, 0), time.Now())
	if err == nil && len(instances) > 0 {
		return fmt.Errorf("cannot delete template with schedule instances")
	}

	beforeState, _ := json.Marshal(template)

	err = s.schedulingRepo.DeleteScheduleTemplate(ctx, templateID)
	if err != nil {
		s.logger.Error("Failed to delete schedule template",
			util.String("template_id", templateID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to delete schedule template: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s.auditService.LogAction(auditCtx,
				&template.CompanyID,
				"scheduling",
				"schedule_template.delete",
				"schedule_template",
				&templateID,
				actorType,
				&actorID,
				beforeState,
				nil,
				metadata,
			)
		}()
	}

	s.logger.Info("Schedule template deleted",
		util.String("template_id", templateID.String()),
		util.String("company_id", template.CompanyID.String()),
		util.String("name", template.Name),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *schedulingServiceImpl) ValidateScheduleTemplate(ctx context.Context, template *scheduling.ScheduleTemplate) error {
	return s.validateScheduleTemplate(template)
}

// POSITION-BASED SCHEDULE RESOLUTION
func (s *schedulingServiceImpl) ResolveUserDay(
	ctx context.Context,
	companyID, userID uuid.UUID,
	date time.Time,
) (*PositionBasedResolvedDay, error) {

	businessDate := date

	// 1️⃣ Get user's position (from company_employees)
	employee, err := s.schedulingRepo.GetCompanyEmployee(ctx, companyID, userID)
	if err != nil {
		return nil, fmt.Errorf("employee not found: %w", err)
	}

	if employee.PositionID == nil {
		return &PositionBasedResolvedDay{
			Date:           businessDate,
			Timezone:       "UTC",
			IsSchedulable:  false,
			ScheduleStatus: "no_position",
		}, nil
	}

	// 2️⃣ Get position details
	position, err := s.schedulingRepo.GetPositionByID(ctx, *employee.PositionID)
	if err != nil {
		return nil, fmt.Errorf("position not found: %w", err)
	}

	// 3️⃣ Check if position is schedulable
	if !position.IsSchedulable {
		return &PositionBasedResolvedDay{
			Date:               businessDate,
			Timezone:           "UTC",
			IsSchedulable:      false,
			AttendanceRequired: position.AttendanceRequired,
			OvertimeAllowed:    position.OvertimeAllowed,
			PositionID:         &position.PositionID,
			PositionTitle:      &position.Title,
			ScheduleStatus:     "not_schedulable",
		}, nil
	}

	// 4️⃣ Check for schedule overrides
	override, err := s.schedulingRepo.GetScheduleOverrideByUserDate(ctx, userID, businessDate)
	if err == nil && override != nil {
		return &PositionBasedResolvedDay{
			Date:               businessDate,
			Timezone:           "UTC",
			IsSchedulable:      true,
			AttendanceRequired: position.AttendanceRequired,
			OvertimeAllowed:    position.OvertimeAllowed,
			PositionID:         &position.PositionID,
			PositionTitle:      &position.Title,
			ScheduleStatus:     "override",
			IsOverride:         true,
			OverrideType:       &override.OverrideType,
		}, nil
	}

	// 5️⃣ Check for approved leave
	statusApproved := "approved"
	leaveRequests, err := s.schedulingRepo.GetOffRequestsByUser(
		ctx,
		userID,
		&businessDate,
		&businessDate,
		&statusApproved,
	)
	if err == nil && len(leaveRequests) > 0 {
		return &PositionBasedResolvedDay{
			Date:               businessDate,
			Timezone:           "UTC",
			IsSchedulable:      true,
			AttendanceRequired: position.AttendanceRequired,
			OvertimeAllowed:    position.OvertimeAllowed,
			PositionID:         &position.PositionID,
			PositionTitle:      &position.Title,
			ScheduleStatus:     "on_leave",
			IsOnLeave:          true,
			LeaveRequestID:     &leaveRequests[0].OffRequestID,
		}, nil
	}

	// 6️⃣ Check existing schedule instance
	instance, err := s.schedulingRepo.GetScheduleInstanceByUserDate(ctx, userID, businessDate)
	if err == nil && instance != nil {

		// 🔑 Resolve work center (user assignment → position)
		var resolvedWorkCenterCode *string
		var resolvedWorkCenterName *string

		userWC, _ := s.schedulingRepo.GetUserCurrentWorkCenter(ctx, userID, businessDate)
		if userWC != nil && userWC.WorkCenterCode != "" {
			resolvedWorkCenterCode = &userWC.WorkCenterCode
		} else if position.WorkCenterCode != nil {
			resolvedWorkCenterCode = position.WorkCenterCode
		}

		if resolvedWorkCenterCode != nil {
			wc, _ := s.schedulingRepo.GetWorkCenterByCode(ctx, companyID, *resolvedWorkCenterCode)
			if wc != nil {
				resolvedWorkCenterName = &wc.Name
			}
		}

		return &PositionBasedResolvedDay{
			Date:               instance.ScheduleDate,
			Timezone:           instance.Timezone,
			IsSchedulable:      true,
			AttendanceRequired: position.AttendanceRequired,
			OvertimeAllowed:    position.OvertimeAllowed,
			ExpectedStart:      instance.ExpectedStart,
			ExpectedEnd:        instance.ExpectedEnd,
			PositionID:         &position.PositionID,
			PositionTitle:      &position.Title,
			WorkCenterCode:     resolvedWorkCenterCode,
			WorkCenterName:     resolvedWorkCenterName,
			ShiftID:            &instance.ScheduleTemplateID,
			ScheduleInstanceID: &instance.ScheduleInstanceID,
			ScheduleStatus:     instance.Status,
		}, nil
	}

	// 7️⃣ If position has work center → resolve from work center
	if position.WorkCenterCode != nil {

		workCenter, err := s.schedulingRepo.GetWorkCenterByCode(ctx, companyID, *position.WorkCenterCode)
		if err != nil {
			return nil, fmt.Errorf("work center not found: %w", err)
		}

		shiftMapping, err := s.schedulingRepo.GetWorkCenterShiftByCode(
			ctx,
			companyID,
			*position.WorkCenterCode,
			businessDate,
		)
		if err != nil {
			return &PositionBasedResolvedDay{
				Date:               businessDate,
				Timezone:           workCenter.Timezone,
				IsSchedulable:      true,
				AttendanceRequired: position.AttendanceRequired,
				OvertimeAllowed:    position.OvertimeAllowed,
				PositionID:         &position.PositionID,
				PositionTitle:      &position.Title,
				WorkCenterCode:     position.WorkCenterCode,
				WorkCenterName:     &workCenter.Name,
				ScheduleStatus:     "no_shift_mapping",
			}, nil
		}

		shiftTemplate, err := s.schedulingRepo.GetScheduleTemplateByID(ctx, shiftMapping.ShiftID)
		if err != nil {
			return nil, fmt.Errorf("shift template not found: %w", err)
		}

		calendar, err := s.schedulingRepo.GetWorkCalendarByID(ctx, shiftTemplate.CalendarID)
		if err != nil {
			return nil, fmt.Errorf("calendar not found: %w", err)
		}

		weekday := int(businessDate.Weekday())
		isWorking := false
		for _, wd := range calendar.WorkingDays {
			if wd == weekday {
				isWorking = true
				break
			}
		}

		if !isWorking {
			return &PositionBasedResolvedDay{
				Date:               businessDate,
				Timezone:           calendar.Timezone,
				IsSchedulable:      true,
				AttendanceRequired: position.AttendanceRequired,
				OvertimeAllowed:    position.OvertimeAllowed,
				PositionID:         &position.PositionID,
				PositionTitle:      &position.Title,
				WorkCenterCode:     position.WorkCenterCode,
				WorkCenterName:     &workCenter.Name,
				ShiftID:            &shiftTemplate.ScheduleTemplateID,
				ShiftName:          &shiftTemplate.Name,
				ScheduleStatus:     "non_working_day",
			}, nil
		}

		for _, holiday := range calendar.Holidays {
			holidayDate, err := time.Parse("2006-01-02", holiday.Date)
			if err == nil && holidayDate.Equal(businessDate) {
				return &PositionBasedResolvedDay{
					Date:               businessDate,
					Timezone:           calendar.Timezone,
					IsSchedulable:      true,
					AttendanceRequired: position.AttendanceRequired,
					OvertimeAllowed:    position.OvertimeAllowed,
					PositionID:         &position.PositionID,
					PositionTitle:      &position.Title,
					WorkCenterCode:     position.WorkCenterCode,
					WorkCenterName:     &workCenter.Name,
					ShiftID:            &shiftTemplate.ScheduleTemplateID,
					ShiftName:          &shiftTemplate.Name,
					ScheduleStatus:     "holiday",
				}, nil
			}
		}

		expectedStart, expectedEnd, err :=
			s.calculateExpectedTimesFromTemplate(businessDate, shiftTemplate, calendar)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate schedule times: %w", err)
		}

		return &PositionBasedResolvedDay{
			Date:               businessDate,
			Timezone:           calendar.Timezone,
			IsSchedulable:      true,
			AttendanceRequired: position.AttendanceRequired,
			OvertimeAllowed:    position.OvertimeAllowed,
			ExpectedStart:      expectedStart,
			ExpectedEnd:        expectedEnd,
			PositionID:         &position.PositionID,
			PositionTitle:      &position.Title,
			WorkCenterCode:     position.WorkCenterCode,
			WorkCenterName:     &workCenter.Name,
			ShiftID:            &shiftTemplate.ScheduleTemplateID,
			ShiftName:          &shiftTemplate.Name,
			ScheduleStatus:     "scheduled",
		}, nil
	}

	// 8️⃣ Position without work center
	return &PositionBasedResolvedDay{
		Date:               businessDate,
		Timezone:           "UTC",
		IsSchedulable:      true,
		AttendanceRequired: position.AttendanceRequired,
		OvertimeAllowed:    position.OvertimeAllowed,
		PositionID:         &position.PositionID,
		PositionTitle:      &position.Title,
		ScheduleStatus:     "no_work_center",
	}, nil
}

func (s *schedulingServiceImpl) CreateScheduleInstanceFromPosition(
	ctx context.Context,
	companyID, userID uuid.UUID,
	date time.Time,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*scheduling.ScheduleInstance, error) {

	startTime := time.Now()

	// 1️⃣ Business date is already normalized at API boundary
	businessDate := date

	// 2️⃣ Resolve the user's day FIRST
	resolvedDay, err := s.ResolveUserDay(ctx, companyID, userID, businessDate)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve schedule: %w", err)
	}

	// 3️⃣ Compute "today" in the SAME timezone as the schedule
	loc, err := time.LoadLocation(resolvedDay.Timezone)
	if err != nil {
		loc = time.UTC
	}
	now := time.Now().In(loc)
	today := time.Date(
		now.Year(),
		now.Month(),
		now.Day(),
		0, 0, 0, 0,
		loc,
	)

	// 🔒 🔒 🔒 HARD FREEZE CHECK (FIX)
	// Prevent creating schedules for past or today dates
	if !businessDate.After(today) {
		return nil, fmt.Errorf(
			"cannot create schedule instance for past or today date: %s",
			businessDate.Format("2006-01-02"),
		)
	}

	// 4️⃣ Business validations
	if !resolvedDay.IsSchedulable {
		return nil, fmt.Errorf("position is not schedulable")
	}

	if resolvedDay.ScheduleStatus != "scheduled" {
		return nil, fmt.Errorf("cannot create schedule instance: %s", resolvedDay.ScheduleStatus)
	}

	// 5️⃣ Handle existing instance (regeneration case)
	existing, err := s.schedulingRepo.GetScheduleInstanceByUserDate(ctx, userID, businessDate)
	if err == nil && existing != nil {

		reason := "regenerated_from_position"
		cancelledAt := time.Now().UTC()
		existing.Status = "cancelled"
		existing.CancelReason = &reason
		existing.CancelledAt = &cancelledAt

		if err := s.schedulingRepo.UpdateScheduleInstance(ctx, existing); err != nil {
			return nil, fmt.Errorf("failed to cancel existing schedule: %w", err)
		}

		if s.auditService != nil {
			go s.logAuditAction(
				ctx,
				companyID,
				"schedule_instance.cancel",
				existing.ScheduleInstanceID,
				actorType,
				actorID,
				nil,
				existing,
				metadata,
			)
		}
	}

	// 6️⃣ Create new schedule instance
	instance := &scheduling.ScheduleInstance{
		ScheduleInstanceID: uuid.New(),
		CompanyID:          companyID,
		UserID:             userID,
		ScheduleDate:       businessDate,
		ScheduleTemplateID: *resolvedDay.ShiftID,
		ExpectedStart:      resolvedDay.ExpectedStart,
		ExpectedEnd:        resolvedDay.ExpectedEnd,
		Timezone:           resolvedDay.Timezone,
		GeneratedAt:        time.Now().UTC(),
		Status:             "active",
		Metadata:           scheduling.InstanceMetadata{},
	}

	if err := s.schedulingRepo.CreateScheduleInstance(ctx, instance); err != nil {
		return nil, fmt.Errorf("failed to create schedule instance: %w", err)
	}

	// 7️⃣ Audit
	if s.auditService != nil {
		go s.logAuditAction(
			ctx,
			companyID,
			"schedule_instance.create_position_based",
			instance.ScheduleInstanceID,
			actorType,
			actorID,
			nil,
			instance,
			metadata,
		)
	}

	s.logger.Info(
		"Schedule instance created (position-based)",
		util.String("user_id", userID.String()),
		util.String("date", businessDate.Format("2006-01-02")),
		util.Duration("duration", time.Since(startTime)),
	)

	return instance, nil
}

func (s *schedulingServiceImpl) GenerateScheduleForUser(
	ctx context.Context,
	userID uuid.UUID,
	config ScheduleGenerationConfig,
	actorType string,
	actorID uuid.UUID,
) ([]*scheduling.ScheduleInstance, error) {
	startTime := time.Now()

	if err := s.validateScheduleGenerationConfig(config); err != nil {
		return nil, err
	}

	employee, err := s.schedulingRepo.GetUserCompany(ctx, userID)
	if err != nil {
		return nil, err
	}

	loc, err := time.LoadLocation(config.Timezone)
	if err != nil {
		loc = time.UTC
	}

	now := time.Now().In(loc)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)

	var instances []*scheduling.ScheduleInstance
	var skippedDates []string
	var errorDates []string

	for d := config.StartDate; !d.After(config.EndDate); d = d.AddDate(0, 0, 1) {
		businessDate := d

		// Skip past dates
		if !businessDate.After(today) {
			skippedDates = append(skippedDates, businessDate.Format("2006-01-02")+" (past date)")
			continue
		}

		// Check if schedule already exists
		existing, err := s.schedulingRepo.GetScheduleInstanceByUserDate(ctx, userID, businessDate)
		if err == nil && existing != nil {
			if existing.Status == "active" {
				skippedDates = append(skippedDates, businessDate.Format("2006-01-02")+" (already scheduled)")
				continue
			}
		}

		resolvedDay, err := s.ResolveUserDay(ctx, employee.CompanyID, userID, businessDate)
		if err != nil {
			errorDates = append(errorDates, businessDate.Format("2006-01-02")+": "+err.Error())
			continue
		}

		if resolvedDay.ScheduleStatus != "scheduled" {
			skippedDates = append(skippedDates, businessDate.Format("2006-01-02")+": "+resolvedDay.ScheduleStatus)
			continue
		}

		instance := &scheduling.ScheduleInstance{
			ScheduleInstanceID: uuid.New(),
			CompanyID:          employee.CompanyID,
			UserID:             userID,
			ScheduleDate:       businessDate,
			ScheduleTemplateID: *resolvedDay.ShiftID,
			ExpectedStart:      resolvedDay.ExpectedStart,
			ExpectedEnd:        resolvedDay.ExpectedEnd,
			Timezone:           resolvedDay.Timezone,
			WorkCenterCode:     resolvedDay.WorkCenterCode,
			GeneratedAt:        time.Now().UTC(),
			Status:             "active",
		}
		instances = append(instances, instance)
	}

	if len(instances) == 0 {
		s.logger.Info("No schedule instances to generate for user",
			util.String("user_id", userID.String()),
			util.String("start_date", config.StartDate.Format("2006-01-02")),
			util.String("end_date", config.EndDate.Format("2006-01-02")),
			util.Int("skipped_dates", len(skippedDates)),
			util.Int("error_dates", len(errorDates)),
			util.Duration("duration", time.Since(startTime)),
		)

		// Return empty instances but log what was skipped
		if len(skippedDates) > 0 {
			s.logger.Debug("Skipped dates for user",
				util.String("user_id", userID.String()),
				util.Strings("skipped", skippedDates))
		}

		return []*scheduling.ScheduleInstance{}, nil
	}

	if err := s.BulkCreateScheduleInstances(ctx, instances, actorType, actorID, nil); err != nil {
		return nil, err
	}

	s.logger.Info("Schedule generated for user",
		util.String("user_id", userID.String()),
		util.Int("created", len(instances)),
		util.Int("skipped", len(skippedDates)),
		util.Int("errors", len(errorDates)),
		util.Duration("duration", time.Since(startTime)),
	)

	return instances, nil
}

func (s *schedulingServiceImpl) GenerateScheduleForCompany(
	ctx context.Context,
	companyID uuid.UUID,
	config ScheduleGenerationConfig,
	actorType string,
	actorID uuid.UUID,
) ([]*scheduling.ScheduleInstance, error) {
	startTime := time.Now()
	if err := s.validateScheduleGenerationConfig(config); err != nil {
		return nil, err
	}

	employees, err := s.schedulingRepo.GetActiveEmployeesByCompany(ctx, companyID)
	if err != nil {
		return nil, err
	}

	loc, err := time.LoadLocation(config.Timezone)
	if err != nil {
		loc = time.UTC
	}
	now := time.Now().In(loc)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)

	var instances []*scheduling.ScheduleInstance
	for _, emp := range employees {
		if emp.PositionID == nil {
			continue
		}

		for d := config.StartDate; !d.After(config.EndDate); d = d.AddDate(0, 0, 1) {
			businessDate := d
			// Skip past dates - can only generate for future dates
			if !businessDate.After(today) {
				continue
			}

			// Check if schedule already exists for this user and date
			existing, err := s.schedulingRepo.GetScheduleInstanceByUserDate(ctx, emp.UserID, businessDate)
			if err == nil && existing != nil && existing.Status == "active" {
				// Skip if active schedule already exists
				continue
			}

			resolvedDay, err := s.ResolveUserDay(ctx, companyID, emp.UserID, businessDate)
			if err != nil || resolvedDay.ScheduleStatus != "scheduled" {
				continue
			}

			instance := &scheduling.ScheduleInstance{
				ScheduleInstanceID: uuid.New(),
				CompanyID:          companyID,
				UserID:             emp.UserID,
				ScheduleDate:       businessDate,
				ScheduleTemplateID: *resolvedDay.ShiftID,
				ExpectedStart:      resolvedDay.ExpectedStart,
				ExpectedEnd:        resolvedDay.ExpectedEnd,
				Timezone:           resolvedDay.Timezone,
				WorkCenterCode:     resolvedDay.WorkCenterCode,
				GeneratedAt:        time.Now().UTC(),
				Status:             "active",
			}
			instances = append(instances, instance)
		}
	}

	// Return empty slice if no instances to generate
	if len(instances) == 0 {
		s.logger.Info("No schedule instances to generate for company",
			util.String("company_id", companyID.String()),
			util.String("start_date", config.StartDate.Format("2006-01-02")),
			util.String("end_date", config.EndDate.Format("2006-01-02")),
			util.Duration("duration", time.Since(startTime)),
		)
		return []*scheduling.ScheduleInstance{}, nil
	}

	if err := s.BulkCreateScheduleInstances(ctx, instances, actorType, actorID, nil); err != nil {
		return nil, err
	}

	s.logger.Info("Schedule generated for company",
		util.Int("count", len(instances)),
		util.Duration("duration", time.Since(startTime)),
	)
	return instances, nil
}
func (s *schedulingServiceImpl) GenerateScheduleForTemplate(
	ctx context.Context,
	templateID uuid.UUID,
	config ScheduleGenerationConfig,
	actorType string,
	actorID uuid.UUID,
) ([]*scheduling.ScheduleInstance, error) {
	// This method is less relevant in position-based scheduling
	// as schedules are derived from positions and work centers
	s.logger.Warn("GenerateScheduleForTemplate is deprecated in position-based scheduling")
	return nil, fmt.Errorf("template-based scheduling is deprecated, use position-based scheduling")
}

// WORK CENTER OPERATIONS
func (s *schedulingServiceImpl) CreateWorkCenterShiftMapping(
	ctx context.Context,
	companyID uuid.UUID,
	mapping *scheduling.WorkCenterShiftMapping,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	if mapping.WorkCenterCode == "" {
		return fmt.Errorf("work_center_code is required")
	}

	if mapping.ShiftID == uuid.Nil {
		return fmt.Errorf("shift_id is required")
	}

	if mapping.EffectiveFrom.IsZero() {
		mapping.EffectiveFrom = time.Now().UTC()
	}

	// Verify work center exists
	workCenter, err := s.schedulingRepo.GetWorkCenterByCode(ctx, companyID, mapping.WorkCenterCode)
	if err != nil {
		return fmt.Errorf("work center not found: %w", err)
	}

	// Verify shift template exists
	shiftTemplate, err := s.schedulingRepo.GetScheduleTemplateByID(ctx, mapping.ShiftID)
	if err != nil {
		return fmt.Errorf("shift template not found: %w", err)
	}

	if shiftTemplate.CompanyID != companyID {
		return fmt.Errorf("shift template does not belong to company")
	}

	mapping.MappingID = uuid.New()
	mapping.CompanyID = companyID
	mapping.CreatedAt = time.Now().UTC()
	mapping.IsActive = true

	err = s.schedulingRepo.CreateWorkCenterShiftMapping(ctx, mapping)
	if err != nil {
		s.logger.Error("Failed to create work center shift mapping",
			util.String("work_center", mapping.WorkCenterCode),
			util.String("shift_id", mapping.ShiftID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create work center shift mapping: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			mappingJSON, _ := json.Marshal(mapping)
			s.auditService.LogAction(
				auditCtx,
				&companyID,
				"scheduling",
				"work_center_shift_mapping.create",
				"work_center_shift_mapping",
				&mapping.MappingID,
				actorType,
				&actorID,
				nil,
				mappingJSON,
				metadata,
			)
		}()
	}

	s.logger.Info("Work center shift mapping created",
		util.String("mapping_id", mapping.MappingID.String()),
		util.String("work_center", mapping.WorkCenterCode),
		util.String("work_center_name", workCenter.Name),
		util.String("shift_id", mapping.ShiftID.String()),
		util.String("shift_name", shiftTemplate.Name),
		util.Time("effective_from", mapping.EffectiveFrom),
		util.Duration("duration", time.Since(startTime)),
	)

	return nil
}

func (s *schedulingServiceImpl) UpdateWorkCenterShiftMapping(
	ctx context.Context,
	mappingID uuid.UUID,
	update scheduling.WorkCenterShiftMappingUpdate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	mapping, err := s.schedulingRepo.GetWorkCenterShiftMappingByID(ctx, mappingID)
	if err != nil {
		return fmt.Errorf("work center shift mapping not found: %w", err)
	}

	beforeState, _ := json.Marshal(mapping)

	if update.ShiftID != nil {
		// Verify new shift template exists
		shiftTemplate, err := s.schedulingRepo.GetScheduleTemplateByID(ctx, *update.ShiftID)
		if err != nil {
			return fmt.Errorf("shift template not found: %w", err)
		}

		if shiftTemplate.CompanyID != mapping.CompanyID {
			return fmt.Errorf("shift template does not belong to company")
		}
		mapping.ShiftID = *update.ShiftID
	}

	if update.EffectiveTo != nil {
		mapping.EffectiveTo = update.EffectiveTo
		mapping.IsActive = false
	}

	err = s.schedulingRepo.UpdateWorkCenterShiftMapping(ctx, mapping)
	if err != nil {
		s.logger.Error("Failed to update work center shift mapping",
			util.String("mapping_id", mappingID.String()),
			util.String("work_center", mapping.WorkCenterCode),
			util.ErrorField(err))
		return fmt.Errorf("failed to update work center shift mapping: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			afterState, _ := json.Marshal(mapping)
			s.auditService.LogAction(
				auditCtx,
				&mapping.CompanyID,
				"scheduling",
				"work_center_shift_mapping.update",
				"work_center_shift_mapping",
				&mappingID,
				actorType,
				&actorID,
				beforeState,
				afterState,
				metadata,
			)
		}()
	}

	s.logger.Info("Work center shift mapping updated",
		util.String("mapping_id", mappingID.String()),
		util.String("work_center", mapping.WorkCenterCode),
		util.String("shift_id", mapping.ShiftID.String()),
		util.Duration("duration", time.Since(startTime)),
	)

	return nil
}

func (s *schedulingServiceImpl) AssignUserToWorkCenter(
	ctx context.Context,
	companyID uuid.UUID,
	assignment *scheduling.UserWorkCenterAssignment,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	if assignment.UserID == uuid.Nil {
		return fmt.Errorf("user_id is required")
	}

	if assignment.WorkCenterCode == "" {
		return fmt.Errorf("work_center_code is required")
	}

	if assignment.EffectiveFrom.IsZero() {
		assignment.EffectiveFrom = time.Now().UTC()
	}

	// Verify work center exists
	workCenter, err := s.schedulingRepo.GetWorkCenterByCode(ctx, companyID, assignment.WorkCenterCode)
	if err != nil {
		return fmt.Errorf("work center not found: %w", err)
	}

	// Check if user is already assigned to a work center on this date
	current, err := s.schedulingRepo.GetUserWorkCenterAssignment(ctx, assignment.UserID, assignment.EffectiveFrom)
	if err == nil && current != nil {
		if current.WorkCenterCode == assignment.WorkCenterCode {
			return fmt.Errorf("user already assigned to this work center")
		}

		// End previous assignment
		if s.auditService != nil {
			go func() {
				auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				currentJSON, _ := json.Marshal(current)
				s.auditService.LogAction(
					auditCtx,
					&companyID,
					"scheduling",
					"user_work_center_assignment.end",
					"user_work_center_assignment",
					&current.AssignmentID,
					actorType,
					&actorID,
					currentJSON,
					nil,
					map[string]interface{}{
						"ended_for_new_assignment": true,
						"new_work_center":          assignment.WorkCenterCode,
					},
				)
			}()
		}

		err = s.schedulingRepo.EndUserWorkCenterAssignment(
			ctx, current.AssignmentID, assignment.EffectiveFrom,
		)
		if err != nil {
			s.logger.Warn("Failed to end previous work center assignment",
				util.String("user_id", assignment.UserID.String()),
				util.String("assignment_id", current.AssignmentID.String()),
				util.ErrorField(err))
		}
	}

	assignment.AssignmentID = uuid.New()
	assignment.CompanyID = companyID
	assignment.CreatedAt = time.Now().UTC()
	assignment.IsActive = true

	err = s.schedulingRepo.CreateUserWorkCenterAssignment(ctx, assignment)
	if err != nil {
		s.logger.Error("Failed to assign user to work center",
			util.String("user_id", assignment.UserID.String()),
			util.String("work_center", assignment.WorkCenterCode),
			util.ErrorField(err))
		return fmt.Errorf("failed to assign user to work center: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			assignmentJSON, _ := json.Marshal(assignment)
			s.auditService.LogAction(
				auditCtx,
				&companyID,
				"scheduling",
				"user_work_center_assignment.create",
				"user_work_center_assignment",
				&assignment.AssignmentID,
				actorType,
				&actorID,
				nil,
				assignmentJSON,
				metadata,
			)
		}()
	}

	s.logger.Info("User assigned to work center",
		util.String("user_id", assignment.UserID.String()),
		util.String("work_center", assignment.WorkCenterCode),
		util.String("work_center_name", workCenter.Name),
		util.String("assignment_id", assignment.AssignmentID.String()),
		util.Time("effective_from", assignment.EffectiveFrom),
		util.Duration("duration", time.Since(startTime)),
	)

	return nil
}

func (s *schedulingServiceImpl) EndUserWorkCenterAssignment(
	ctx context.Context,
	assignmentID uuid.UUID,
	endDate time.Time,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	if endDate.IsZero() {
		endDate = time.Now().UTC()
	}

	err := s.schedulingRepo.EndUserWorkCenterAssignment(
		ctx, assignmentID, endDate,
	)
	if err != nil {
		s.logger.Error("Failed to end work center assignment",
			util.String("assignment_id", assignmentID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to end work center assignment: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			afterState, _ := json.Marshal(map[string]interface{}{
				"assignment_id": assignmentID.String(),
				"ended_at":      endDate,
				"is_active":     false,
			})
			s.auditService.LogAction(
				auditCtx,
				nil,
				"scheduling",
				"user_work_center_assignment.end",
				"user_work_center_assignment",
				&assignmentID,
				actorType,
				&actorID,
				nil,
				afterState,
				metadata,
			)
		}()
	}

	s.logger.Info("User work center assignment ended",
		util.String("assignment_id", assignmentID.String()),
		util.Time("end_date", endDate),
		util.Duration("duration", time.Since(startTime)),
	)

	return nil
}

// REST OF THE FUNCTIONS (CreateScheduleInstance, UpdateScheduleInstance, etc.)
// These functions need to be updated to use position-based approach

func (s *schedulingServiceImpl) CreateScheduleInstance(
	ctx context.Context,
	instance *scheduling.ScheduleInstance,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*scheduling.ScheduleInstance, error) {

	// ✅ Position-based path
	if instance.ScheduleTemplateID == uuid.Nil {
		return s.CreateScheduleInstanceFromPosition(
			ctx,
			instance.CompanyID,
			instance.UserID,
			instance.ScheduleDate,
			actorType,
			actorID,
			metadata,
		)
	}

	// ❌ REMOVED UTC truncation of ScheduleDate

	if instance.ScheduleInstanceID == uuid.Nil {
		instance.ScheduleInstanceID = uuid.New()
	}

	if instance.GeneratedAt.IsZero() {
		instance.GeneratedAt = time.Now().UTC()
	}

	instance.Status = "active"

	// ✅ Validation (already timezone-safe)
	if err := s.validateScheduleInstance(instance); err != nil {
		return nil, fmt.Errorf("schedule instance validation failed: %w", err)
	}

	// Conflict check
	if instance.ExpectedStart != nil && instance.ExpectedEnd != nil {
		hasConflict, err := s.ValidateScheduleConflict(
			ctx,
			instance.UserID,
			*instance.ExpectedStart,
			*instance.ExpectedEnd,
			nil,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to check schedule conflict: %w", err)
		}
		if hasConflict {
			return nil, fmt.Errorf("schedule conflict detected")
		}
	}

	if err := s.schedulingRepo.CreateScheduleInstance(ctx, instance); err != nil {
		return nil, fmt.Errorf("failed to create schedule instance: %w", err)
	}

	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			instanceJSON, _ := json.Marshal(instance)
			s.auditService.LogAction(
				auditCtx,
				&instance.CompanyID,
				"scheduling",
				"schedule_instance.create",
				"schedule_instance",
				&instance.ScheduleInstanceID,
				actorType,
				&actorID,
				nil,
				instanceJSON,
				metadata,
			)
		}()
	}

	return instance, nil
}
func (s *schedulingServiceImpl) UpdateScheduleInstance(
	ctx context.Context,
	instanceID uuid.UUID,
	update ScheduleInstanceUpdate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*scheduling.ScheduleInstance, error) {

	instance, err := s.schedulingRepo.GetScheduleInstanceByID(ctx, instanceID)
	if err != nil {
		return nil, err
	}

	// ✅ Local-time freeze check
	loc, err := time.LoadLocation(instance.Timezone)
	if err != nil {
		loc = time.UTC
	}
	now := time.Now().In(loc)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)

	if !instance.ScheduleDate.After(today) {
		return nil, fmt.Errorf("schedule is frozen")
	}

	if update.Metadata != nil {
		instance.Metadata = *update.Metadata
	}

	if err := s.schedulingRepo.UpdateScheduleInstance(ctx, instance); err != nil {
		return nil, err
	}

	if s.auditService != nil {
		go s.logAuditAction(
			ctx,
			instance.CompanyID,
			"schedule_instance.update_metadata",
			instanceID,
			actorType,
			actorID,
			nil,
			instance,
			metadata,
		)
	}

	return instance, nil
}

func (s *schedulingServiceImpl) DeleteScheduleInstance(
	ctx context.Context,
	instanceID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	instance, err := s.schedulingRepo.GetScheduleInstanceByID(ctx, instanceID)
	if err != nil {
		return fmt.Errorf("schedule instance not found: %w", err)
	}

	beforeState, _ := json.Marshal(instance)

	err = s.schedulingRepo.DeleteScheduleInstance(ctx, instanceID)
	if err != nil {
		s.logger.Error("Failed to delete schedule instance",
			util.String("instance_id", instanceID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to delete schedule instance: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s.auditService.LogAction(
				auditCtx,
				&instance.CompanyID,
				"scheduling",
				"schedule_instance.delete",
				"schedule_instance",
				&instanceID,
				actorType,
				&actorID,
				beforeState,
				nil,
				metadata,
			)
		}()
	}

	s.logger.Info("Schedule instance deleted",
		util.String("instance_id", instanceID.String()),
		util.String("user_id", instance.UserID.String()),
		util.String("date", instance.ScheduleDate.Format("2006-01-02")),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// VALIDATION FUNCTIONS (unchanged but included for completeness)
func (s *schedulingServiceImpl) validateWorkCalendar(calendar *scheduling.WorkCalendar) error {
	if calendar.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}
	if calendar.Year < 2000 || calendar.Year > 2100 {
		return fmt.Errorf("invalid calendar year")
	}
	if calendar.Name == "" {
		return fmt.Errorf("name is required")
	}
	if calendar.Timezone == "" {
		return fmt.Errorf("timezone is required")
	}
	if len(calendar.WorkingDays) == 0 {
		return fmt.Errorf("working days are required")
	}
	return nil
}

func (s *schedulingServiceImpl) validateWorkingDays(days []int) error {
	validDays := map[int]bool{0: true, 1: true, 2: true, 3: true, 4: true, 5: true, 6: true}
	for _, day := range days {
		if day < 0 || day > 6 {
			return fmt.Errorf("invalid day number: %d (must be 0-6)", day)
		}
		if !validDays[day] {
			return fmt.Errorf("invalid day: %d", day)
		}
	}
	return nil
}

func (s *schedulingServiceImpl) validateHolidays(holidays []scheduling.Holiday) error {
	for _, holiday := range holidays {
		if holiday.Date == "" {
			return fmt.Errorf("holiday date is required")
		}
		if holiday.Name == "" {
			return fmt.Errorf("holiday name is required")
		}
		_, err := time.Parse("2006-01-02", holiday.Date)
		if err != nil {
			return fmt.Errorf("invalid holiday date format: %s (must be YYYY-MM-DD)", holiday.Date)
		}
	}
	return nil
}

func (s *schedulingServiceImpl) validateTimezone(timezone string) error {
	_, err := time.LoadLocation(timezone)
	if err != nil {
		return fmt.Errorf("invalid timezone: %s", timezone)
	}
	return nil
}

func (s *schedulingServiceImpl) validateScheduleTemplate(template *scheduling.ScheduleTemplate) error {
	if template.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}
	if template.CalendarID == uuid.Nil {
		return fmt.Errorf("calendar ID is required")
	}
	if template.TemplateType == "" {
		return fmt.Errorf("template type is required")
	}
	if template.Name == "" {
		return fmt.Errorf("name is required")
	}
	validTypes := map[string]bool{
		"office": true,
		"shift":  true,
		"class":  true,
	}
	if !validTypes[template.TemplateType] {
		return fmt.Errorf("invalid template type: %s", template.TemplateType)
	}
	return nil
}

func (s *schedulingServiceImpl) validateTemplateRules(templateType string, rules *scheduling.TemplateRules) error {
	switch templateType {
	case "office":
		if rules.StartTime == nil || *rules.StartTime == "" {
			return fmt.Errorf("start time is required for office template")
		}
		if rules.EndTime == nil || *rules.EndTime == "" {
			return fmt.Errorf("end time is required for office template")
		}
		if _, err := time.Parse("15:04", *rules.StartTime); err != nil {
			return fmt.Errorf("invalid start time format: %s", *rules.StartTime)
		}
		if _, err := time.Parse("15:04", *rules.EndTime); err != nil {
			return fmt.Errorf("invalid end time format: %s", *rules.EndTime)
		}
	case "shift":
		if rules.BreakMinutes == nil {
			return fmt.Errorf("break minutes are required for shift template")
		}
		if *rules.BreakMinutes < 0 {
			return fmt.Errorf("break minutes cannot be negative")
		}
	case "class":
		if len(rules.Periods) == 0 {
			return fmt.Errorf("periods are required for class template")
		}
		for i, period := range rules.Periods {
			if period.Period <= 0 {
				return fmt.Errorf("period number must be positive for period %d", i)
			}
			if period.Start == "" {
				return fmt.Errorf("start time is required for period %d", i)
			}
			if period.End == "" {
				return fmt.Errorf("end time is required for period %d", i)
			}
			if _, err := time.Parse("15:04", period.Start); err != nil {
				return fmt.Errorf("invalid start time format for period %d: %s", i, period.Start)
			}
			if _, err := time.Parse("15:04", period.End); err != nil {
				return fmt.Errorf("invalid end time format for period %d: %s", i, period.End)
			}
		}
	}
	return nil
}

func (s *schedulingServiceImpl) validateScheduleInstance(
	instance *scheduling.ScheduleInstance,
) error {

	// ---- Required fields ----
	if instance.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}
	if instance.UserID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}
	if instance.ScheduleTemplateID == uuid.Nil {
		return fmt.Errorf("schedule template ID is required")
	}
	if instance.ScheduleDate.IsZero() {
		return fmt.Errorf("schedule date is required")
	}
	if instance.Timezone == "" {
		return fmt.Errorf("timezone is required")
	}

	// ---- Timezone validation ----
	loc, err := time.LoadLocation(instance.Timezone)
	if err != nil {
		return fmt.Errorf("invalid timezone: %s", instance.Timezone)
	}

	// ---- Normalize business date ----
	instance.ScheduleDate = normalizeBusinessDate(
		instance.ScheduleDate,
		instance.Timezone,
	)

	// ---- Freeze logic (Model-3 rule) ----
	nowInLoc := time.Now().In(loc)
	today := time.Date(
		nowInLoc.Year(),
		nowInLoc.Month(),
		nowInLoc.Day(),
		0, 0, 0, 0,
		loc,
	)

	/*
		Model-3 rule:
		- Active schedules cannot exist in past or today
		- Cancelled schedules ARE allowed in past (audit/history)
	*/
	if instance.Status == "active" && !instance.ScheduleDate.After(today) {
		return fmt.Errorf("schedule is frozen for %s",
			instance.ScheduleDate.Format("2006-01-02"),
		)
	}

	// ---- Expected time validation ----
	if instance.ExpectedStart != nil && instance.ExpectedEnd != nil {

		start := instance.ExpectedStart.In(loc)
		end := instance.ExpectedEnd.In(loc)

		if start.After(end) {
			return fmt.Errorf("expected start must be before expected end")
		}

		// Must be same business day
		if start.Year() != end.Year() ||
			start.Month() != end.Month() ||
			start.Day() != end.Day() {
			return fmt.Errorf("expected times must be within the same business day")
		}
	}

	return nil
}

func (s *schedulingServiceImpl) validateScheduleGenerationConfig(config ScheduleGenerationConfig) error {
	if config.StartDate.IsZero() {
		return fmt.Errorf("start date is required")
	}
	if config.EndDate.IsZero() {
		return fmt.Errorf("end date is required")
	}
	if config.StartDate.After(config.EndDate) {
		return fmt.Errorf("start date cannot be after end date")
	}
	maxDays := 90
	if config.EndDate.Sub(config.StartDate).Hours()/24 > float64(maxDays) {
		return fmt.Errorf("date range cannot exceed %d days", maxDays)
	}
	if config.Timezone == "" {
		config.Timezone = "UTC"
	}
	if err := s.validateTimezone(config.Timezone); err != nil {
		return fmt.Errorf("invalid timezone: %w", err)
	}
	return nil
}

func (s *schedulingServiceImpl) calculateExpectedTimesFromTemplate(
	date time.Time,
	template *scheduling.ScheduleTemplate,
	calendar *scheduling.WorkCalendar,
) (*time.Time, *time.Time, error) {
	loc, err := time.LoadLocation(calendar.Timezone)
	if err != nil {
		loc = time.UTC
	}

	day := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, loc)

	switch template.TemplateType {
	case "office":
		startClock, _ := time.Parse("15:04", *template.Rules.StartTime)
		endClock, _ := time.Parse("15:04", *template.Rules.EndTime)
		start := time.Date(day.Year(), day.Month(), day.Day(), startClock.Hour(), startClock.Minute(), 0, 0, loc)
		end := time.Date(day.Year(), day.Month(), day.Day(), endClock.Hour(), endClock.Minute(), 0, 0, loc)
		if end.Before(start) {
			end = end.Add(24 * time.Hour)
		}
		return &start, &end, nil

	case "shift":
		start := time.Date(day.Year(), day.Month(), day.Day(), 9, 0, 0, 0, loc)
		end := time.Date(day.Year(), day.Month(), day.Day(), 17, 0, 0, 0, loc)
		return &start, &end, nil

	case "class":
		if len(template.Rules.Periods) > 0 {
			p := template.Rules.Periods[0]
			startClock, _ := time.Parse("15:04", p.Start)
			endClock, _ := time.Parse("15:04", p.End)
			start := time.Date(day.Year(), day.Month(), day.Day(), startClock.Hour(), startClock.Minute(), 0, 0, loc)
			end := time.Date(day.Year(), day.Month(), day.Day(), endClock.Hour(), endClock.Minute(), 0, 0, loc)
			return &start, &end, nil
		}
	}

	return nil, nil, fmt.Errorf("unsupported template type")
}

// Note: The rest of the functions (off management, schedule overrides, etc.) remain mostly the same
// but need to be included in the complete file. Due to length constraints, I've included the
// most critical position-based functions. The remaining functions follow similar patterns.

func (s *schedulingServiceImpl) HealthCheck(ctx context.Context) error {
	if err := s.schedulingRepo.HealthCheck(ctx); err != nil {
		return fmt.Errorf("scheduling repository health check failed: %w", err)
	}
	return nil
}

func normalizeBusinessDate(date time.Time, timezone string) time.Time {
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		loc = time.UTC
	}
	d := date.In(loc)
	return time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, loc)
}

// Helper function for audit logging
func (s *schedulingServiceImpl) logAuditAction(
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
			entityType := "schedule_instance"
			if strings.Contains(action, "work_center") {
				entityType = "work_center"
			} else if strings.Contains(action, "template") {
				entityType = "schedule_template"
			} else if strings.Contains(action, "calendar") {
				entityType = "work_calendar"
			}
			s.auditService.LogAction(auditCtx,
				&companyID,
				"scheduling",
				action,
				entityType,
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

func (s *schedulingServiceImpl) CreateOffEntitlement(
	ctx context.Context,
	companyID uuid.UUID,
	entitlement *scheduling.UserOffEntitlement,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*scheduling.UserOffEntitlement, error) {
	startTime := time.Now()

	if err := s.validateOffEntitlement(entitlement); err != nil {
		return nil, fmt.Errorf("off entitlement validation failed: %w", err)
	}

	if entitlement.EntitlementID == uuid.Nil {
		entitlement.EntitlementID = uuid.New()
	}

	entitlement.CompanyID = companyID
	entitlement.CreatedAt = time.Now().UTC()

	// Check for overlapping entitlements
	existingEntitlements, err := s.schedulingRepo.GetOffEntitlementsByUser(ctx, entitlement.UserID, true)
	if err == nil {
		for _, existing := range existingEntitlements {
			if s.entitlementsOverlap(existing, entitlement) {
				return nil, fmt.Errorf("overlapping off entitlement exists for user")
			}
		}
	}

	// Verify user belongs to company
	userExists, err := s.schedulingRepo.IsUserActiveInCompany(ctx, companyID, entitlement.UserID)
	if err != nil || !userExists {
		return nil, fmt.Errorf("user not found or not active in company")
	}

	err = s.schedulingRepo.CreateOffEntitlement(ctx, entitlement)
	if err != nil {
		s.logger.Error("Failed to create off entitlement",
			util.String("user_id", entitlement.UserID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create off entitlement: %w", err)
	}

	if s.auditService != nil {
		go s.logAuditAction(ctx, companyID, "off_entitlement.create",
			entitlement.EntitlementID, actorType, actorID, nil, entitlement, metadata)
	}

	s.logger.Info("Off entitlement created",
		util.String("entitlement_id", entitlement.EntitlementID.String()),
		util.String("user_id", entitlement.UserID.String()),
		util.String("period_type", entitlement.PeriodType),
		util.Int("off_count", entitlement.OffCount),
		util.Duration("duration", time.Since(startTime)))

	return entitlement, nil
}

func (s *schedulingServiceImpl) UpdateOffEntitlement(
	ctx context.Context,
	entitlementID uuid.UUID,
	update scheduling.OffEntitlementUpdate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*scheduling.UserOffEntitlement, error) {
	startTime := time.Now()

	entitlement, err := s.schedulingRepo.GetOffEntitlementByID(ctx, entitlementID)
	if err != nil {
		return nil, fmt.Errorf("off entitlement not found: %w", err)
	}

	beforeState, _ := json.Marshal(entitlement)

	if update.PeriodType != nil {
		entitlement.PeriodType = *update.PeriodType
	}
	if update.OffCount != nil {
		entitlement.OffCount = *update.OffCount
	}
	if update.RequiresApproval != nil {
		entitlement.RequiresApproval = *update.RequiresApproval
	}
	if update.EffectiveFrom != nil {
		entitlement.EffectiveFrom = *update.EffectiveFrom
	}
	if update.EffectiveTo != nil {
		entitlement.EffectiveTo = update.EffectiveTo
	}

	if err := s.validateOffEntitlement(entitlement); err != nil {
		return nil, fmt.Errorf("off entitlement validation failed: %w", err)
	}

	err = s.schedulingRepo.UpdateOffEntitlement(ctx, entitlement)
	if err != nil {
		s.logger.Error("Failed to update off entitlement",
			util.String("entitlement_id", entitlementID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to update off entitlement: %w", err)
	}

	s.logAuditAction(ctx, entitlement.CompanyID, "off_entitlement.update",
		entitlementID, actorType, actorID, beforeState, entitlement, metadata)

	s.logger.Info("Off entitlement updated",
		util.String("entitlement_id", entitlementID.String()),
		util.Duration("duration", time.Since(startTime)))

	return entitlement, nil
}

func (s *schedulingServiceImpl) DeleteOffEntitlement(
	ctx context.Context,
	entitlementID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	entitlement, err := s.schedulingRepo.GetOffEntitlementByID(ctx, entitlementID)
	if err != nil {
		return fmt.Errorf("off entitlement not found: %w", err)
	}

	beforeState, _ := json.Marshal(entitlement)

	err = s.schedulingRepo.DeleteOffEntitlement(ctx, entitlementID)
	if err != nil {
		s.logger.Error("Failed to delete off entitlement",
			util.String("entitlement_id", entitlementID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to delete off entitlement: %w", err)
	}

	s.logAuditAction(ctx, entitlement.CompanyID, "off_entitlement.delete",
		entitlementID, actorType, actorID, beforeState, nil, metadata)

	s.logger.Info("Off entitlement deleted",
		util.String("entitlement_id", entitlementID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *schedulingServiceImpl) CreateOffRequest(
	ctx context.Context,
	companyID uuid.UUID,
	request *scheduling.OffRequest,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*scheduling.OffRequest, error) {
	startTime := time.Now()

	if err := s.validateOffRequest(request); err != nil {
		return nil, fmt.Errorf("off request validation failed: %w", err)
	}

	if request.OffRequestID == uuid.Nil {
		request.OffRequestID = uuid.New()
	}

	request.CompanyID = companyID
	if request.Status == "" {
		request.Status = "pending"
	}
	request.CreatedAt = time.Now().UTC()

	// Check if user belongs to company
	userExists, err := s.schedulingRepo.IsUserActiveInCompany(ctx, companyID, request.UserID)
	if err != nil || !userExists {
		return nil, fmt.Errorf("user not found or not active in company")
	}

	// Validate dates are not in the past
	for _, dateStr := range request.RequestDates {
		date, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			return nil, fmt.Errorf("invalid date format: %s", dateStr)
		}
		if date.Before(time.Now().UTC().Truncate(24 * time.Hour)) {
			return nil, fmt.Errorf("cannot request off for past dates: %s", dateStr)
		}

		// Check if there's already a schedule override
		override, err := s.schedulingRepo.GetScheduleOverrideByUserDate(ctx, request.UserID, date)
		if err == nil && override != nil && override.OverrideType == "force_work" {
			return nil, fmt.Errorf("user is scheduled to work on %s", dateStr)
		}
	}

	// Check off entitlement
	entitlement, err := s.schedulingRepo.GetCurrentOffEntitlement(ctx, request.UserID, time.Now())
	if err != nil {
		return nil, fmt.Errorf("no active off entitlement found: %w", err)
	}

	// Check balance
	usedDays, err := s.schedulingRepo.GetOffBalance(ctx, request.UserID, entitlement.PeriodType,
		entitlement.EffectiveFrom, time.Now().AddDate(0, 0, 30))
	if err != nil {
		usedDays = 0
	}

	remaining := entitlement.OffCount - usedDays
	if remaining < len(request.RequestDates) {
		return nil, fmt.Errorf("insufficient off balance: %d days remaining, requested %d days",
			remaining, len(request.RequestDates))
	}

	// Auto-approve if no approval required
	if !entitlement.RequiresApproval {
		request.Status = "approved"
		now := time.Now().UTC()
		request.ApprovedAt = &now
		request.ApprovedBy = &actorID
	}

	err = s.schedulingRepo.CreateOffRequest(ctx, request)
	if err != nil {
		s.logger.Error("Failed to create off request",
			util.String("user_id", request.UserID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create off request: %w", err)
	}

	// Create schedule overrides for approved requests
	if request.Status == "approved" {
		for _, dateStr := range request.RequestDates {
			date, _ := time.Parse("2006-01-02", dateStr)
			override := &scheduling.ScheduleOverride{
				OverrideID:   uuid.New(),
				CompanyID:    companyID,
				UserID:       request.UserID,
				OverrideDate: date,
				OverrideType: "off",
				CreatedBy:    &actorID,
				CreatedAt:    time.Now().UTC(),
			}
			if err := s.schedulingRepo.CreateScheduleOverride(ctx, override); err != nil {
				s.logger.Warn("Failed to create schedule override for off request",
					util.String("user_id", request.UserID.String()),
					util.String("date", dateStr),
					util.ErrorField(err))
			}
		}
	}

	if s.auditService != nil {
		go s.logAuditAction(ctx, companyID, "off_request.create",
			request.OffRequestID, actorType, actorID, nil, request, metadata)
	}

	s.logger.Info("Off request created",
		util.String("request_id", request.OffRequestID.String()),
		util.String("user_id", request.UserID.String()),
		util.String("status", request.Status),
		util.Int("days_requested", len(request.RequestDates)),
		util.Duration("duration", time.Since(startTime)))

	return request, nil
}

func (s *schedulingServiceImpl) UpdateOffRequest(
	ctx context.Context,
	requestID uuid.UUID,
	update scheduling.OffRequestUpdate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*scheduling.OffRequest, error) {
	startTime := time.Now()

	request, err := s.schedulingRepo.GetOffRequestByID(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("off request not found: %w", err)
	}

	beforeState, _ := json.Marshal(request)

	if update.RequestDates != nil {
		request.RequestDates = *update.RequestDates
	}
	if update.Status != nil {
		request.Status = *update.Status
	}
	if update.ApprovedBy != nil {
		request.ApprovedBy = update.ApprovedBy
	}
	if update.ApprovedAt != nil {
		request.ApprovedAt = update.ApprovedAt
	}

	if err := s.validateOffRequest(request); err != nil {
		return nil, fmt.Errorf("off request validation failed: %w", err)
	}

	err = s.schedulingRepo.UpdateOffRequest(ctx, request)
	if err != nil {
		s.logger.Error("Failed to update off request",
			util.String("request_id", requestID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to update off request: %w", err)
	}

	s.logAuditAction(ctx, request.CompanyID, "off_request.update",
		requestID, actorType, actorID, beforeState, request, metadata)

	s.logger.Info("Off request updated",
		util.String("request_id", requestID.String()),
		util.Duration("duration", time.Since(startTime)))

	return request, nil
}

func (s *schedulingServiceImpl) DeleteOffRequest(
	ctx context.Context,
	requestID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	request, err := s.schedulingRepo.GetOffRequestByID(ctx, requestID)
	if err != nil {
		return fmt.Errorf("off request not found: %w", err)
	}

	beforeState, _ := json.Marshal(request)

	err = s.schedulingRepo.DeleteOffRequest(ctx, requestID)
	if err != nil {
		s.logger.Error("Failed to delete off request",
			util.String("request_id", requestID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to delete off request: %w", err)
	}

	s.logAuditAction(ctx, request.CompanyID, "off_request.delete",
		requestID, actorType, actorID, beforeState, nil, metadata)

	s.logger.Info("Off request deleted",
		util.String("request_id", requestID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *schedulingServiceImpl) ApproveOffRequest(
	ctx context.Context,
	requestID uuid.UUID,
	approvedBy uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	request, err := s.schedulingRepo.GetOffRequestByID(ctx, requestID)
	if err != nil {
		return fmt.Errorf("off request not found: %w", err)
	}

	if request.Status != "pending" {
		return fmt.Errorf("cannot approve a request with status: %s", request.Status)
	}

	beforeState, _ := json.Marshal(request)

	now := time.Now().UTC()
	request.Status = "approved"
	request.ApprovedBy = &approvedBy
	request.ApprovedAt = &now

	err = s.schedulingRepo.UpdateOffRequest(ctx, request)
	if err != nil {
		return fmt.Errorf("failed to approve off request: %w", err)
	}

	// Create schedule overrides
	for _, dateStr := range request.RequestDates {
		date, _ := time.Parse("2006-01-02", dateStr)
		override := &scheduling.ScheduleOverride{
			OverrideID:   uuid.New(),
			CompanyID:    request.CompanyID,
			UserID:       request.UserID,
			OverrideDate: date,
			OverrideType: "off",
			CreatedBy:    &approvedBy,
			CreatedAt:    now,
		}
		if err := s.schedulingRepo.CreateScheduleOverride(ctx, override); err != nil {
			s.logger.Warn("Failed to create schedule override for approved off request",
				util.String("user_id", request.UserID.String()),
				util.String("date", dateStr),
				util.ErrorField(err))
		}
	}

	s.logAuditAction(ctx, request.CompanyID, "off_request.approve",
		requestID, actorType, actorID, beforeState, request, metadata)

	s.logger.Info("Off request approved",
		util.String("request_id", requestID.String()),
		util.String("user_id", request.UserID.String()),
		util.String("approved_by", approvedBy.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *schedulingServiceImpl) RejectOffRequest(
	ctx context.Context,
	requestID uuid.UUID,
	rejectedBy uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	request, err := s.schedulingRepo.GetOffRequestByID(ctx, requestID)
	if err != nil {
		return fmt.Errorf("off request not found: %w", err)
	}

	if request.Status != "pending" {
		return fmt.Errorf("cannot reject a request with status: %s", request.Status)
	}

	beforeState, _ := json.Marshal(request)

	now := time.Now().UTC()
	request.Status = "rejected"
	request.ApprovedBy = &rejectedBy
	request.ApprovedAt = &now

	err = s.schedulingRepo.UpdateOffRequest(ctx, request)
	if err != nil {
		return fmt.Errorf("failed to reject off request: %w", err)
	}

	s.logAuditAction(ctx, request.CompanyID, "off_request.reject",
		requestID, actorType, actorID, beforeState, request, metadata)

	s.logger.Info("Off request rejected",
		util.String("request_id", requestID.String()),
		util.String("rejected_by", rejectedBy.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *schedulingServiceImpl) CreateScheduleOverride(
	ctx context.Context,
	companyID uuid.UUID,
	override *scheduling.ScheduleOverride,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*scheduling.ScheduleOverride, error) {
	startTime := time.Now()

	if err := s.validateScheduleOverride(override); err != nil {
		return nil, fmt.Errorf("schedule override validation failed: %w", err)
	}

	if override.OverrideID == uuid.Nil {
		override.OverrideID = uuid.New()
	}

	override.CompanyID = companyID
	override.CreatedAt = time.Now().UTC()

	// Check if user belongs to company
	userExists, err := s.schedulingRepo.IsUserActiveInCompany(ctx, companyID, override.UserID)
	if err != nil || !userExists {
		return nil, fmt.Errorf("user not found or not active in company")
	}

	// Check for conflicts
	existingOverride, err := s.schedulingRepo.GetScheduleOverrideByUserDate(ctx, override.UserID, override.OverrideDate)
	if err == nil && existingOverride != nil {
		return nil, fmt.Errorf("schedule override already exists for user on %s",
			override.OverrideDate.Format("2006-01-02"))
	}

	err = s.schedulingRepo.CreateScheduleOverride(ctx, override)
	if err != nil {
		s.logger.Error("Failed to create schedule override",
			util.String("user_id", override.UserID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create schedule override: %w", err)
	}

	// If overriding to "off", cancel any existing schedule instance
	if override.OverrideType == "off" {
		instance, err := s.schedulingRepo.GetScheduleInstanceByUserDate(ctx, override.UserID, override.OverrideDate)
		if err == nil && instance != nil {
			if err := s.schedulingRepo.CancelScheduleInstance(ctx, instance.ScheduleInstanceID, "off_override"); err != nil {
				s.logger.Warn("Failed to cancel schedule instance for off override",
					util.String("instance_id", instance.ScheduleInstanceID.String()),
					util.ErrorField(err))
			}
		}
	}

	if s.auditService != nil {
		go s.logAuditAction(ctx, companyID, "schedule_override.create",
			override.OverrideID, actorType, actorID, nil, override, metadata)
	}

	s.logger.Info("Schedule override created",
		util.String("override_id", override.OverrideID.String()),
		util.String("user_id", override.UserID.String()),
		util.String("override_type", override.OverrideType),
		util.String("date", override.OverrideDate.Format("2006-01-02")),
		util.Duration("duration", time.Since(startTime)))

	return override, nil
}

func (s *schedulingServiceImpl) UpdateScheduleOverride(
	ctx context.Context,
	overrideID uuid.UUID,
	update scheduling.ScheduleOverrideUpdate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*scheduling.ScheduleOverride, error) {
	startTime := time.Now()

	override, err := s.schedulingRepo.GetScheduleOverrideByID(ctx, overrideID)
	if err != nil {
		return nil, fmt.Errorf("schedule override not found: %w", err)
	}

	beforeState, _ := json.Marshal(override)

	if update.OverrideType != nil {
		override.OverrideType = *update.OverrideType
	}
	if update.Reason != nil {
		override.Reason = update.Reason
	}

	if err := s.validateScheduleOverride(override); err != nil {
		return nil, fmt.Errorf("schedule override validation failed: %w", err)
	}

	err = s.schedulingRepo.UpdateScheduleOverride(ctx, override)
	if err != nil {
		s.logger.Error("Failed to update schedule override",
			util.String("override_id", overrideID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to update schedule override: %w", err)
	}

	s.logAuditAction(ctx, override.CompanyID, "schedule_override.update",
		overrideID, actorType, actorID, beforeState, override, metadata)

	s.logger.Info("Schedule override updated",
		util.String("override_id", overrideID.String()),
		util.Duration("duration", time.Since(startTime)))

	return override, nil
}

func (s *schedulingServiceImpl) DeleteScheduleOverride(
	ctx context.Context,
	overrideID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	override, err := s.schedulingRepo.GetScheduleOverrideByID(ctx, overrideID)
	if err != nil {
		return fmt.Errorf("schedule override not found: %w", err)
	}

	beforeState, _ := json.Marshal(override)

	err = s.schedulingRepo.DeleteScheduleOverride(ctx, overrideID)
	if err != nil {
		s.logger.Error("Failed to delete schedule override",
			util.String("override_id", overrideID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to delete schedule override: %w", err)
	}

	s.logAuditAction(ctx, override.CompanyID, "schedule_override.delete",
		overrideID, actorType, actorID, beforeState, nil, metadata)

	s.logger.Info("Schedule override deleted",
		util.String("override_id", overrideID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *schedulingServiceImpl) GetUserOffBalance(
	ctx context.Context,
	userID uuid.UUID,
	periodType string,
	startDate, endDate time.Time,
) (map[string]interface{}, error) {
	entitlement, err := s.schedulingRepo.GetCurrentOffEntitlement(ctx, userID, time.Now())
	if err != nil {
		return nil, fmt.Errorf("failed to get current entitlement: %w", err)
	}

	usedDays, err := s.schedulingRepo.GetOffBalance(ctx, userID, periodType, startDate, endDate)
	if err != nil {
		usedDays = 0
	}

	result := map[string]interface{}{
		"user_id":     userID,
		"period_type": periodType,
		"start_date":  startDate,
		"end_date":    endDate,
		"used_days":   usedDays,
		"total_days":  entitlement.OffCount,
		"remaining":   entitlement.OffCount - usedDays,
		"entitlement": entitlement,
	}

	return result, nil
}

func (s *schedulingServiceImpl) GetUserTimeOffSummary(
	ctx context.Context,
	userID uuid.UUID,
	startDate, endDate time.Time,
) (map[string]interface{}, error) {
	entitlement, err := s.schedulingRepo.GetCurrentOffEntitlement(ctx, userID, time.Now())
	if err != nil {
		entitlement = nil
	}

	statusApproved := "approved"
	offRequests, err := s.schedulingRepo.GetOffRequestsByUser(ctx, userID, &startDate, &endDate, &statusApproved)
	if err != nil {
		offRequests = []*scheduling.OffRequest{}
	}

	overrides, err := s.schedulingRepo.GetScheduleOverridesByUser(ctx, userID, &startDate, &endDate, nil)
	if err != nil {
		overrides = []*scheduling.ScheduleOverride{}
	}

	usedDays := 0
	for _, req := range offRequests {
		usedDays += len(req.RequestDates)
	}

	result := map[string]interface{}{
		"user_id":            userID,
		"start_date":         startDate.Format("2006-01-02"),
		"end_date":           endDate.Format("2006-01-02"),
		"off_requests":       offRequests,
		"schedule_overrides": overrides,
		"used_days":          usedDays,
	}

	if entitlement != nil {
		result["entitlement"] = entitlement
		result["total_days"] = entitlement.OffCount
		result["remaining_days"] = entitlement.OffCount - usedDays
	}

	return result, nil
}

func (s *schedulingServiceImpl) RequestTimeOff(
	ctx context.Context,
	companyID, userID uuid.UUID,
	requestDates []string,
	reason string,
	actorType string,
	actorID uuid.UUID,
) (*scheduling.OffRequest, error) {
	// This is a convenience method that wraps CreateOffRequest
	request := &scheduling.OffRequest{
		OffRequestID: uuid.New(),
		CompanyID:    companyID,
		UserID:       userID,
		RequestDates: requestDates,
		Status:       "pending",
		RequestedBy:  &actorID,
		CreatedAt:    time.Now().UTC(),
	}

	return s.CreateOffRequest(ctx, companyID, request, actorType, actorID, map[string]interface{}{
		"reason": reason,
	})
}

func (s *schedulingServiceImpl) ValidateOffRequest(
	ctx context.Context,
	userID uuid.UUID,
	requestDates []string,
	excludeRequestID *uuid.UUID,
) error {
	for _, dateStr := range requestDates {
		date, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			return fmt.Errorf("invalid date format: %s", dateStr)
		}

		// Check for schedule overrides
		override, err := s.schedulingRepo.GetScheduleOverrideByUserDate(ctx, userID, date)
		if err == nil && override != nil {
			if override.OverrideType == "force_work" {
				return fmt.Errorf("user is scheduled to work on %s", dateStr)
			}
		}
	}

	// Check for duplicate requests
	statusPending := "pending"
	statusApproved := "approved"

	existingRequests, err := s.schedulingRepo.GetOffRequestsByUser(ctx, userID, nil, nil, &statusPending)
	if err == nil {
		for _, existing := range existingRequests {
			if excludeRequestID != nil && existing.OffRequestID == *excludeRequestID {
				continue
			}
			for _, existingDate := range existing.RequestDates {
				for _, newDate := range requestDates {
					if existingDate == newDate {
						return fmt.Errorf("duplicate request for date: %s", newDate)
					}
				}
			}
		}
	}

	approvedRequests, err := s.schedulingRepo.GetOffRequestsByUser(ctx, userID, nil, nil, &statusApproved)
	if err == nil {
		for _, existing := range approvedRequests {
			if excludeRequestID != nil && existing.OffRequestID == *excludeRequestID {
				continue
			}
			for _, existingDate := range existing.RequestDates {
				for _, newDate := range requestDates {
					if existingDate == newDate {
						return fmt.Errorf("already has approved request for date: %s", newDate)
					}
				}
			}
		}
	}

	return nil
}

func (s *schedulingServiceImpl) GetScheduleOverridesByUser(
	ctx context.Context,
	userID uuid.UUID,
	startDate, endDate time.Time,
) ([]*scheduling.ScheduleOverride, error) {
	return s.schedulingRepo.GetScheduleOverridesByUser(ctx, userID, &startDate, &endDate, nil)
}

func (s *schedulingServiceImpl) AddHolidayToCalendar(
	ctx context.Context,
	calendarID uuid.UUID,
	date string,
	name string,
	actorType string,
	actorID uuid.UUID,
) error {
	calendar, err := s.schedulingRepo.GetWorkCalendarByID(ctx, calendarID)
	if err != nil {
		return fmt.Errorf("work calendar not found: %w", err)
	}

	// Validate date format
	_, err = time.Parse("2006-01-02", date)
	if err != nil {
		return fmt.Errorf("invalid date format: %s (must be YYYY-MM-DD)", date)
	}

	// Check if holiday already exists
	for _, h := range calendar.Holidays {
		if h.Date == date {
			return fmt.Errorf("holiday already exists for date %s", date)
		}
	}

	// Add holiday
	calendar.Holidays = append(calendar.Holidays, scheduling.Holiday{
		Date: date,
		Name: name,
	})

	err = s.schedulingRepo.UpdateWorkCalendar(ctx, calendar)
	if err != nil {
		return fmt.Errorf("failed to update work calendar: %w", err)
	}

	// Process holiday for all users in the company
	holidayDate, _ := time.Parse("2006-01-02", date)
	s.ProcessHolidayForDate(ctx, calendar.CompanyID, holidayDate, actorType, actorID)

	return nil
}

func (s *schedulingServiceImpl) ProcessHolidayForDate(
	ctx context.Context,
	companyID uuid.UUID,
	date time.Time,
	actorType string,
	actorID uuid.UUID,
) error {
	// Get all schedule instances for this date
	instances, err := s.schedulingRepo.GetScheduleInstancesByCompany(ctx, companyID, date, date)
	if err != nil {
		return fmt.Errorf("failed to fetch schedule instances: %w", err)
	}

	for _, instance := range instances {
		// Check if user has force_work override
		override, err := s.schedulingRepo.GetScheduleOverrideByUserDate(ctx, instance.UserID, date)
		if err == nil && override != nil && override.OverrideType == "force_work" {
			continue
		}

		// Cancel the schedule instance
		err = s.schedulingRepo.CancelScheduleInstance(ctx, instance.ScheduleInstanceID, "holiday_declared")
		if err != nil {
			s.logger.Warn("Failed to cancel schedule instance",
				util.String("instance_id", instance.ScheduleInstanceID.String()),
				util.ErrorField(err))
			continue
		}
	}

	return nil
}

func (s *schedulingServiceImpl) CheckScheduleAvailability(
	ctx context.Context,
	userID uuid.UUID,
	date time.Time,
	timezone string,
) ([]time.Time, error) {
	resolvedDay, err := s.ResolveUserDay(ctx, uuid.Nil, userID, date)
	if err != nil {
		return []time.Time{}, fmt.Errorf("failed to resolve schedule: %w", err)
	}

	if !resolvedDay.IsSchedulable || resolvedDay.ScheduleStatus != "scheduled" {
		return []time.Time{}, nil
	}

	if resolvedDay.ExpectedStart == nil || resolvedDay.ExpectedEnd == nil {
		return []time.Time{}, nil
	}

	loc, err := time.LoadLocation(timezone)
	if err != nil {
		loc = time.UTC
	}

	startLocal := resolvedDay.ExpectedStart.In(loc)
	endLocal := resolvedDay.ExpectedEnd.In(loc)

	return []time.Time{startLocal, endLocal}, nil
}

func (s *schedulingServiceImpl) CheckDateAvailability(
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

	// Check for schedule overrides
	override, err := s.schedulingRepo.GetScheduleOverrideByUserDate(ctx, userID, date)
	if err == nil && override != nil {
		result["schedule_override"] = override
		switch override.OverrideType {
		case "off":
			result["available"] = false
			result["is_off_day"] = true
			result["reasons"] = append(result["reasons"].([]string), "Schedule override: off day")
		case "force_work":
			result["available"] = true
			result["forced_work"] = true
			result["reasons"] = append(result["reasons"].([]string), "Schedule override: forced work")
		case "holiday_override":
			result["available"] = true
			result["holiday_work"] = true
			result["reasons"] = append(result["reasons"].([]string), "Schedule override: holiday work")
		}
	}

	// Check for approved off requests
	statusApproved := "approved"
	offRequests, err := s.schedulingRepo.GetOffRequestsByUser(ctx, userID, &date, &date, &statusApproved)
	if err == nil && len(offRequests) > 0 {
		result["available"] = false
		result["off_request"] = offRequests[0]
		result["reasons"] = append(result["reasons"].([]string), "Approved off request")
		result["is_off_day"] = true
	}

	// Check for pending requests
	statusPending := "pending"
	pendingRequests, err := s.schedulingRepo.GetOffRequestsByUser(ctx, userID, &date, &date, &statusPending)
	if err == nil && len(pendingRequests) > 0 {
		result["pending_request"] = pendingRequests[0]
		if result["available"] == true {
			result["reasons"] = append(result["reasons"].([]string), "Pending off request awaiting approval")
		}
	}

	// Check for existing schedule instance
	instance, err := s.schedulingRepo.GetScheduleInstanceByUserDate(ctx, userID, date)
	if err == nil && instance != nil {
		result["schedule_instance"] = instance
		if instance.ExpectedStart != nil && instance.ExpectedEnd != nil {
			result["scheduled_hours"] = map[string]interface{}{
				"start": instance.ExpectedStart.Format("15:04"),
				"end":   instance.ExpectedEnd.Format("15:04"),
			}
		}
	}

	return result, nil
}

func (s *schedulingServiceImpl) ValidateScheduleConflict(
	ctx context.Context,
	userID uuid.UUID,
	startTime, endTime time.Time,
	excludeInstanceID *uuid.UUID,
) (bool, error) {
	// This is a simple conflict check - you might want to implement more sophisticated logic
	// based on your business rules (e.g., buffer times, overlapping rules, etc.)

	instances, err := s.schedulingRepo.GetScheduleInstancesByUser(ctx, userID,
		startTime.AddDate(0, 0, -1), endTime.AddDate(0, 0, 1))
	if err != nil {
		return false, fmt.Errorf("failed to get schedule instances: %w", err)
	}

	for _, instance := range instances {
		if excludeInstanceID != nil && instance.ScheduleInstanceID == *excludeInstanceID {
			continue
		}

		if instance.Status != "active" {
			continue
		}

		if instance.ExpectedStart != nil && instance.ExpectedEnd != nil {
			// Check for overlap
			if startTime.Before(*instance.ExpectedEnd) && endTime.After(*instance.ExpectedStart) {
				return true, nil
			}
		}
	}

	return false, nil
}

func (s *schedulingServiceImpl) BulkCreateScheduleInstances(
	ctx context.Context,
	instances []*scheduling.ScheduleInstance,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()
	if len(instances) == 0 {
		return fmt.Errorf("no instances provided")
	}

	companyID := instances[0].CompanyID
	createdCount := 0
	skippedCount := 0

	for i, instance := range instances {
		loc, err := time.LoadLocation(instance.Timezone)
		if err != nil {
			loc = time.UTC
		}
		now := time.Now().In(loc)
		today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)

		// Skip if date is not in future
		if !instance.ScheduleDate.After(today) {
			s.logger.Debug("Skipping past date for schedule instance",
				util.String("user_id", instance.UserID.String()),
				util.String("date", instance.ScheduleDate.Format("2006-01-02")),
				util.String("timezone", instance.Timezone),
			)
			skippedCount++
			continue
		}

		// Check if schedule already exists (double-check for safety)
		existing, err := s.schedulingRepo.GetScheduleInstanceByUserDate(
			ctx,
			instance.UserID,
			instance.ScheduleDate,
		)
		if err == nil && existing != nil && existing.Status == "active" {
			// Skip if active schedule already exists
			s.logger.Debug("Skipping existing schedule instance",
				util.String("user_id", instance.UserID.String()),
				util.String("date", instance.ScheduleDate.Format("2006-01-02")),
				util.String("instance_id", existing.ScheduleInstanceID.String()),
			)
			skippedCount++
			continue
		}

		// Set instance properties
		if instance.ScheduleInstanceID == uuid.Nil {
			instance.ScheduleInstanceID = uuid.New()
		}
		instance.GeneratedAt = time.Now().UTC()
		instance.Status = "active"

		// Create the instance
		if err := s.schedulingRepo.CreateScheduleInstance(ctx, instance); err != nil {
			return fmt.Errorf("instance %d: create failed: %w", i, err)
		}
		createdCount++
	}

	if s.auditService != nil {
		go s.logAuditAction(
			ctx,
			companyID,
			"schedule_instance.bulk_create",
			uuid.Nil,
			actorType,
			actorID,
			nil,
			nil,
			metadata,
		)
	}

	s.logger.Info("Bulk schedule generation completed",
		util.Int("total_processed", len(instances)),
		util.Int("created", createdCount),
		util.Int("skipped", skippedCount),
		util.Duration("duration", time.Since(startTime)),
	)

	return nil
}

// Helper validation methods
func (s *schedulingServiceImpl) validateOffEntitlement(entitlement *scheduling.UserOffEntitlement) error {
	if entitlement.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}
	if entitlement.UserID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}
	if entitlement.PeriodType != "weekly" && entitlement.PeriodType != "monthly" {
		return fmt.Errorf("period type must be 'weekly' or 'monthly'")
	}
	if entitlement.OffCount < 1 {
		return fmt.Errorf("off count must be at least 1")
	}
	if entitlement.EffectiveFrom.IsZero() {
		return fmt.Errorf("effective from date is required")
	}
	return nil
}

func (s *schedulingServiceImpl) validateOffRequest(request *scheduling.OffRequest) error {
	if request.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}
	if request.UserID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}
	if len(request.RequestDates) == 0 {
		return fmt.Errorf("at least one request date is required")
	}
	for i, dateStr := range request.RequestDates {
		if _, err := time.Parse("2006-01-02", dateStr); err != nil {
			return fmt.Errorf("invalid date format at index %d: %s", i, dateStr)
		}
	}
	if request.Status != "" && request.Status != "pending" &&
		request.Status != "approved" && request.Status != "rejected" {
		return fmt.Errorf("invalid status: %s", request.Status)
	}
	return nil
}

func (s *schedulingServiceImpl) validateScheduleOverride(override *scheduling.ScheduleOverride) error {
	if override.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}
	if override.UserID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}
	if override.OverrideDate.IsZero() {
		return fmt.Errorf("override date is required")
	}
	if override.OverrideType != "off" && override.OverrideType != "force_work" &&
		override.OverrideType != "holiday_override" {
		return fmt.Errorf("override type must be 'off', 'force_work', or 'holiday_override'")
	}
	return nil
}

func (s *schedulingServiceImpl) entitlementsOverlap(e1, e2 *scheduling.UserOffEntitlement) bool {
	e1To := time.Now().AddDate(100, 0, 0)
	if e1.EffectiveTo != nil {
		e1To = *e1.EffectiveTo
	}

	e2To := time.Now().AddDate(100, 0, 0)
	if e2.EffectiveTo != nil {
		e2To = *e2.EffectiveTo
	}

	return e1.EffectiveFrom.Before(e2To) && e2.EffectiveFrom.Before(e1To)
}
