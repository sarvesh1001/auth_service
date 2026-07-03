package scheduling

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/attendance/service/resolver"
	"auth-service/internal/infrastructure/audit"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Local DTOs (not in models)
type ScheduleOverrideUpdate struct {
	OverrideType *string `json:"override_type,omitempty"`
	Reason       *string `json:"reason,omitempty"`
}

type WorkCenterShiftUpdate struct {
	ShiftID     *uuid.UUID `json:"shift_id,omitempty"`
	EffectiveTo *time.Time `json:"effective_to,omitempty"`
}

// Holiday is a local struct for handling JSONB data
type Holiday struct {
	Date string `json:"date"`
	Name string `json:"name"`
}

// SchedulingService defines the main scheduling operations.
type SchedulingService interface {
	// Work Calendars
	CreateWorkCalendar(ctx context.Context, calendar *models.WorkCalendar, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.WorkCalendar, error)
	UpdateWorkCalendar(ctx context.Context, calendarID uuid.UUID, update WorkCalendarUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.WorkCalendar, error)
	DeleteWorkCalendar(ctx context.Context, calendarID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	AddHolidayToCalendar(ctx context.Context, calendarID uuid.UUID, date, name string, actorType string, actorID uuid.UUID) error
	ProcessHolidayForDate(ctx context.Context, companyID uuid.UUID, date time.Time, actorType string, actorID uuid.UUID) error

	// Schedule Templates
	CreateScheduleTemplate(ctx context.Context, template *models.ScheduleTemplate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.ScheduleTemplate, error)
	UpdateScheduleTemplate(ctx context.Context, templateID uuid.UUID, update ScheduleTemplateUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.ScheduleTemplate, error)
	DeleteScheduleTemplate(ctx context.Context, templateID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error

	// Schedule Instances
	CreateScheduleInstance(ctx context.Context, instance *models.ScheduleInstance, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.ScheduleInstance, error)
	UpdateScheduleInstance(ctx context.Context, instanceID uuid.UUID, update ScheduleInstanceUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.ScheduleInstance, error)
	DeleteScheduleInstance(ctx context.Context, instanceID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	BulkCreateScheduleInstances(ctx context.Context, instances []*models.ScheduleInstance, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error

	// Leave Integration
	ApplyApprovedLeave(ctx context.Context, leaveData *LeaveScheduleData, actorType string, actorID uuid.UUID) error
	RollbackCancelledLeave(ctx context.Context, leaveData *LeaveScheduleData, actorType string, actorID uuid.UUID) error

	// Schedule Generation – FIXED: added companyID parameter
	GenerateScheduleForUser(ctx context.Context, companyID, userID uuid.UUID, config ScheduleGenerationConfig, actorType string, actorID uuid.UUID) ([]*models.ScheduleInstance, error)
	GenerateScheduleForCompany(ctx context.Context, companyID uuid.UUID, config ScheduleGenerationConfig, actorType string, actorID uuid.UUID) ([]*models.ScheduleInstance, error)

	// Overrides
	CreateScheduleOverride(ctx context.Context, companyID uuid.UUID, override *models.ScheduleOverride, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.ScheduleOverride, error)
	UpdateScheduleOverride(ctx context.Context, overrideID uuid.UUID, update ScheduleOverrideUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.ScheduleOverride, error)
	DeleteScheduleOverride(ctx context.Context, overrideID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error

	// Work Center Shift Mappings
	CreateWorkCenterShiftMapping(ctx context.Context, companyID uuid.UUID, mapping *models.WorkCenterShift, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	UpdateWorkCenterShiftMappingByKey(ctx context.Context, companyID uuid.UUID, workCenterCode string, update WorkCenterShiftUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error

	// Schedule Resolution
	ResolveUserDay(ctx context.Context, companyID, userID uuid.UUID, date time.Time) (*PositionBasedResolvedDay, error)
	CreateScheduleInstanceFromPosition(ctx context.Context, companyID, userID uuid.UUID, date time.Time, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.ScheduleInstance, error)

	// Availability
	CheckScheduleAvailability(ctx context.Context, companyID, userID uuid.UUID, date time.Time, timezone string) ([]time.Time, error)
	ValidateScheduleConflict(ctx context.Context, userID uuid.UUID, startTime, endTime time.Time, excludeInstanceID *uuid.UUID) (bool, error)

	// Health
	HealthCheck(ctx context.Context) error
}

// DTOs
type WorkCalendarUpdate struct {
	Name        *string   `json:"name,omitempty"`
	Timezone    *string   `json:"timezone,omitempty"`
	WorkingDays []int     `json:"working_days,omitempty"`
	Holidays    []Holiday `json:"holidays,omitempty"`
	IsActive    *bool     `json:"is_active,omitempty"`
}

type ScheduleTemplateUpdate struct {
	Name         *string               `json:"name,omitempty"`
	CalendarID   *uuid.UUID            `json:"calendar_id,omitempty"`
	TemplateType *string               `json:"template_type,omitempty"`
	Rules        *models.TemplateRules `json:"rules,omitempty"`
	IsActive     *bool                 `json:"is_active,omitempty"`
}

type ScheduleInstanceUpdate struct {
	ExpectedStart *time.Time               `json:"expected_start,omitempty"`
	ExpectedEnd   *time.Time               `json:"expected_end,omitempty"`
	Timezone      *string                  `json:"timezone,omitempty"`
	Metadata      *models.InstanceMetadata `json:"metadata,omitempty"`
}

type ScheduleGenerationConfig struct {
	StartDate       time.Time `json:"start_date"`
	EndDate         time.Time `json:"end_date"`
	Timezone        string    `json:"timezone"`
	IncludeHolidays bool      `json:"include_holidays"`
	Overwrite       bool      `json:"overwrite"`
	BatchSize       int       `json:"batch_size"`
}

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
	DepartmentID       *uuid.UUID `json:"department_id,omitempty"`
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
	IsLeavePaid        bool       `json:"is_leave_paid"`
	LeaveTypeID        *uuid.UUID `json:"leave_type_id,omitempty"`
}

// Implementation
type schedulingServiceImpl struct {
	schedulingRepo  repository.ScheduleRepository
	subjectResolver resolver.ScheduleSubjectResolver
	auditService    *audit.AuditService
	logger          *zap.Logger
	mu              sync.RWMutex
}

func NewSchedulingService(
	schedulingRepo repository.ScheduleRepository,
	subjectResolver resolver.ScheduleSubjectResolver,
	auditService *audit.AuditService,
	logger *zap.Logger,
) SchedulingService {
	return &schedulingServiceImpl{
		schedulingRepo:  schedulingRepo,
		subjectResolver: subjectResolver,
		auditService:    auditService,
		logger:          logger,
	}
}

// ---- Work Calendar CRUD ----

func (s *schedulingServiceImpl) CreateWorkCalendar(ctx context.Context, calendar *models.WorkCalendar, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.WorkCalendar, error) {
	if err := s.validateWorkCalendar(calendar); err != nil {
		return nil, err
	}
	if calendar.CalendarID == uuid.Nil {
		calendar.CalendarID = uuid.New()
	}
	calendar.CreatedAt = time.Now().UTC()

	existing, _ := s.schedulingRepo.GetWorkCalendarsByCompany(ctx, calendar.CompanyID)
	for _, e := range existing {
		if e.Year == calendar.Year {
			return nil, fmt.Errorf("calendar for year %d already exists", calendar.Year)
		}
	}

	if err := s.schedulingRepo.CreateWorkCalendar(ctx, calendar); err != nil {
		return nil, err
	}

	after, _ := json.Marshal(calendar)
	s.logAudit(ctx, calendar.CompanyID, "work_calendar.create", calendar.CalendarID, actorType, actorID, nil, after, metadata)
	return calendar, nil
}

func (s *schedulingServiceImpl) UpdateWorkCalendar(ctx context.Context, calendarID uuid.UUID, update WorkCalendarUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.WorkCalendar, error) {
	calendar, err := s.schedulingRepo.GetWorkCalendarByID(ctx, calendarID)
	if err != nil {
		return nil, err
	}
	before, _ := json.Marshal(calendar)

	if update.Name != nil {
		calendar.Name = *update.Name
	}
	if update.Timezone != nil {
		calendar.Timezone = *update.Timezone
	}
	if update.WorkingDays != nil {
		calendar.WorkingDays = update.WorkingDays
	}
	if update.Holidays != nil {
		holidayMap := make(map[string]interface{})
		for _, h := range update.Holidays {
			holidayMap[h.Date] = map[string]interface{}{"date": h.Date, "name": h.Name}
		}
		calendar.Holidays = holidayMap
	}
	if update.IsActive != nil {
		calendar.IsActive = *update.IsActive
	}

	if err := s.validateWorkCalendar(calendar); err != nil {
		return nil, err
	}
	if err := s.schedulingRepo.UpdateWorkCalendar(ctx, calendar); err != nil {
		return nil, err
	}

	after, _ := json.Marshal(calendar)
	s.logAudit(ctx, calendar.CompanyID, "work_calendar.update", calendarID, actorType, actorID, before, after, metadata)
	return calendar, nil
}

func (s *schedulingServiceImpl) DeleteWorkCalendar(ctx context.Context, calendarID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error {
	calendar, err := s.schedulingRepo.GetWorkCalendarByID(ctx, calendarID)
	if err != nil {
		return err
	}
	before, _ := json.Marshal(calendar)

	templates, _ := s.schedulingRepo.GetScheduleTemplatesByCalendar(ctx, calendarID)
	if len(templates) > 0 {
		return fmt.Errorf("cannot delete calendar used by %d templates", len(templates))
	}

	if err := s.schedulingRepo.DeleteWorkCalendar(ctx, calendarID); err != nil {
		return err
	}
	s.logAudit(ctx, calendar.CompanyID, "work_calendar.delete", calendarID, actorType, actorID, before, nil, metadata)
	return nil
}

func (s *schedulingServiceImpl) AddHolidayToCalendar(ctx context.Context, calendarID uuid.UUID, date, name string, actorType string, actorID uuid.UUID) error {
	calendar, err := s.schedulingRepo.GetWorkCalendarByID(ctx, calendarID)
	if err != nil {
		return err
	}
	if calendar.Holidays == nil {
		calendar.Holidays = make(map[string]interface{})
	}
	for k := range calendar.Holidays {
		if k == date {
			return fmt.Errorf("holiday already exists on %s", date)
		}
	}
	calendar.Holidays[date] = map[string]interface{}{"date": date, "name": name}
	return s.schedulingRepo.UpdateWorkCalendar(ctx, calendar)
}

func (s *schedulingServiceImpl) ProcessHolidayForDate(ctx context.Context, companyID uuid.UUID, date time.Time, actorType string, actorID uuid.UUID) error {
	instances, err := s.schedulingRepo.GetScheduleInstancesByCompany(ctx, companyID, date, date)
	if err != nil {
		return err
	}
	for _, inst := range instances {
		override, _ := s.schedulingRepo.GetScheduleOverrideByUserDate(ctx, inst.UserID, date)
		if override != nil && override.OverrideType == "force_work" {
			continue
		}
		_ = s.schedulingRepo.CancelScheduleInstance(ctx, inst.ScheduleInstanceID, "holiday_declared")
	}
	return nil
}

// ---- Schedule Template CRUD ----

func (s *schedulingServiceImpl) CreateScheduleTemplate(ctx context.Context, template *models.ScheduleTemplate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.ScheduleTemplate, error) {
	if err := s.validateScheduleTemplate(template); err != nil {
		return nil, err
	}
	if template.ScheduleTemplateID == uuid.Nil {
		template.ScheduleTemplateID = uuid.New()
	}
	template.CreatedAt = time.Now().UTC()
	if err := s.schedulingRepo.CreateScheduleTemplate(ctx, template); err != nil {
		return nil, err
	}
	after, _ := json.Marshal(template)
	s.logAudit(ctx, template.CompanyID, "schedule_template.create", template.ScheduleTemplateID, actorType, actorID, nil, after, metadata)
	return template, nil
}

func (s *schedulingServiceImpl) UpdateScheduleTemplate(ctx context.Context, templateID uuid.UUID, update ScheduleTemplateUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.ScheduleTemplate, error) {
	template, err := s.schedulingRepo.GetScheduleTemplate(ctx, templateID)
	if err != nil {
		return nil, err
	}
	before, _ := json.Marshal(template)

	if update.Name != nil {
		template.Name = *update.Name
	}
	if update.CalendarID != nil {
		template.CalendarID = *update.CalendarID
	}
	if update.TemplateType != nil {
		template.TemplateType = *update.TemplateType
	}
	if update.Rules != nil {
		template.Rules = *update.Rules
	}
	if update.IsActive != nil {
		template.IsActive = *update.IsActive
	}

	if err := s.validateScheduleTemplate(template); err != nil {
		return nil, err
	}
	if err := s.schedulingRepo.UpdateScheduleTemplate(ctx, template); err != nil {
		return nil, err
	}

	after, _ := json.Marshal(template)
	s.logAudit(ctx, template.CompanyID, "schedule_template.update", templateID, actorType, actorID, before, after, metadata)
	return template, nil
}

func (s *schedulingServiceImpl) DeleteScheduleTemplate(ctx context.Context, templateID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error {
	template, err := s.schedulingRepo.GetScheduleTemplate(ctx, templateID)
	if err != nil {
		return err
	}
	before, _ := json.Marshal(template)

	mappings, _ := s.schedulingRepo.GetWorkCenterShiftMappingsByShift(ctx, templateID)
	if len(mappings) > 0 {
		return fmt.Errorf("cannot delete template used by %d work center mappings", len(mappings))
	}
	if err := s.schedulingRepo.DeleteScheduleTemplate(ctx, templateID); err != nil {
		return err
	}
	s.logAudit(ctx, template.CompanyID, "schedule_template.delete", templateID, actorType, actorID, before, nil, metadata)
	return nil
}

// ---- Schedule Instances ----

func (s *schedulingServiceImpl) CreateScheduleInstance(ctx context.Context, instance *models.ScheduleInstance, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.ScheduleInstance, error) {
	if instance.ScheduleTemplateID == uuid.Nil {
		return s.CreateScheduleInstanceFromPosition(ctx, instance.CompanyID, instance.UserID, instance.ScheduleDate, actorType, actorID, metadata)
	}
	if err := s.validateScheduleInstance(instance); err != nil {
		return nil, err
	}
	if instance.ScheduleInstanceID == uuid.Nil {
		instance.ScheduleInstanceID = uuid.New()
	}
	instance.GeneratedAt = time.Now().UTC()
	instance.Status = "active"

	if err := s.schedulingRepo.CreateScheduleInstance(ctx, nil, instance); err != nil {
		return nil, err
	}
	after, _ := json.Marshal(instance)
	s.logAudit(ctx, instance.CompanyID, "schedule_instance.create", instance.ScheduleInstanceID, actorType, actorID, nil, after, metadata)
	return instance, nil
}

func (s *schedulingServiceImpl) UpdateScheduleInstance(ctx context.Context, instanceID uuid.UUID, update ScheduleInstanceUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.ScheduleInstance, error) {
	instance, err := s.schedulingRepo.GetScheduleInstance(ctx, instanceID)
	if err != nil {
		return nil, err
	}
	if !s.isFutureDate(instance.ScheduleDate, instance.Timezone) {
		return nil, fmt.Errorf("schedule instance is frozen (past or today)")
	}
	if update.Metadata != nil {
		instance.Metadata = *update.Metadata
	}
	if err := s.schedulingRepo.UpdateScheduleInstance(ctx, instance); err != nil {
		return nil, err
	}
	after, _ := json.Marshal(instance)
	s.logAudit(ctx, instance.CompanyID, "schedule_instance.update", instanceID, actorType, actorID, nil, after, metadata)
	return instance, nil
}

func (s *schedulingServiceImpl) DeleteScheduleInstance(ctx context.Context, instanceID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error {
	instance, err := s.schedulingRepo.GetScheduleInstance(ctx, instanceID)
	if err != nil {
		return err
	}
	before, _ := json.Marshal(instance)
	if err := s.schedulingRepo.DeleteScheduleInstance(ctx, instanceID); err != nil {
		return err
	}
	s.logAudit(ctx, instance.CompanyID, "schedule_instance.delete", instanceID, actorType, actorID, before, nil, metadata)
	return nil
}

func (s *schedulingServiceImpl) BulkCreateScheduleInstances(ctx context.Context, instances []*models.ScheduleInstance, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error {
	if len(instances) == 0 {
		return nil
	}
	companyID := instances[0].CompanyID
	created := 0
	for _, inst := range instances {
		if inst.ScheduleInstanceID == uuid.Nil {
			inst.ScheduleInstanceID = uuid.New()
		}
		inst.GeneratedAt = time.Now().UTC()
		inst.Status = "active"
		if err := s.schedulingRepo.CreateScheduleInstance(ctx, nil, inst); err != nil {
			s.logger.Warn("Failed to create instance in bulk", zap.Error(err))
			continue
		}
		created++
	}
	summary := map[string]interface{}{"created": created}
	summaryJSON, _ := json.Marshal(summary)
	s.logAudit(ctx, companyID, "schedule_instance.bulk_create", uuid.Nil, actorType, actorID, nil, summaryJSON, metadata)
	return nil
}

// ---- Generation ----

// GenerateScheduleForUser – FIXED: companyID is passed as parameter
func (s *schedulingServiceImpl) GenerateScheduleForUser(ctx context.Context, companyID, userID uuid.UUID, config ScheduleGenerationConfig, actorType string, actorID uuid.UUID) ([]*models.ScheduleInstance, error) {
	subject, err := s.subjectResolver.ResolveSubject(ctx, companyID, userID, "employee", config.StartDate)
	if err != nil || subject == nil {
		return nil, fmt.Errorf("failed to resolve subject: %w", err)
	}
	// Use the passed companyID, not from subject
	instances := s.generateInstancesForUser(ctx, companyID, userID, config, actorType, actorID)
	if len(instances) == 0 {
		return []*models.ScheduleInstance{}, nil
	}
	if err := s.BulkCreateScheduleInstances(ctx, instances, actorType, actorID, nil); err != nil {
		return nil, err
	}
	return instances, nil
}

func (s *schedulingServiceImpl) GenerateScheduleForCompany(ctx context.Context, companyID uuid.UUID, config ScheduleGenerationConfig, actorType string, actorID uuid.UUID) ([]*models.ScheduleInstance, error) {
	subjects, err := s.subjectResolver.GetActiveSubjectsByCompany(ctx, companyID, nil)
	if err != nil {
		return nil, err
	}
	var allInstances []*models.ScheduleInstance
	for _, subjectID := range subjects {
		instances := s.generateInstancesForUser(ctx, companyID, subjectID, config, actorType, actorID)
		allInstances = append(allInstances, instances...)
	}
	if len(allInstances) == 0 {
		return []*models.ScheduleInstance{}, nil
	}
	if err := s.BulkCreateScheduleInstances(ctx, allInstances, actorType, actorID, nil); err != nil {
		return nil, err
	}
	return allInstances, nil
}

func (s *schedulingServiceImpl) generateInstancesForUser(ctx context.Context, companyID, userID uuid.UUID, config ScheduleGenerationConfig, actorType string, actorID uuid.UUID) []*models.ScheduleInstance {
	var instances []*models.ScheduleInstance
	loc, _ := time.LoadLocation(config.Timezone)
	now := time.Now().In(loc)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)

	s.logger.Info("Starting schedule generation for user",
		zap.String("user_id", userID.String()),
		zap.String("start_date", config.StartDate.Format("2006-01-02")),
		zap.String("end_date", config.EndDate.Format("2006-01-02")),
		zap.Bool("overwrite", config.Overwrite),
	)

	for d := config.StartDate; !d.After(config.EndDate); d = d.AddDate(0, 0, 1) {
		if !d.After(today) {
			s.logger.Debug("Skipping past date",
				zap.String("date", d.Format("2006-01-02")),
				zap.String("today", today.Format("2006-01-02")))
			continue
		}

		if !config.Overwrite {
			exists, _ := s.schedulingRepo.HasActiveSchedule(ctx, companyID, userID, d)
			if exists {
				s.logger.Debug("Active schedule exists, skipping",
					zap.String("user", userID.String()),
					zap.String("date", d.Format("2006-01-02")))
				continue
			}
		}

		resolved, err := s.ResolveUserDay(ctx, companyID, userID, d)
		if err != nil {
			s.logger.Warn("ResolveUserDay failed",
				zap.Error(err),
				zap.String("user", userID.String()),
				zap.String("date", d.Format("2006-01-02")))
			continue
		}

		s.logger.Debug("ResolveUserDay result",
			zap.String("user", userID.String()),
			zap.String("date", d.Format("2006-01-02")),
			zap.String("status", resolved.ScheduleStatus),
			zap.Bool("is_schedulable", resolved.IsSchedulable),
			zap.String("work_center", func() string {
				if resolved.WorkCenterCode != nil {
					return *resolved.WorkCenterCode
				}
				return "<nil>"
			}()),
			zap.Any("shift_id", resolved.ShiftID),
		)

		if resolved.ScheduleStatus != "scheduled" {
			s.logger.Debug("Day not schedulable, skipping",
				zap.String("user", userID.String()),
				zap.String("date", d.Format("2006-01-02")),
				zap.String("status", resolved.ScheduleStatus))
			continue
		}

		if resolved.ShiftID == nil {
			s.logger.Warn("Resolved day has no shift ID, skipping",
				zap.String("user", userID.String()),
				zap.String("date", d.Format("2006-01-02")))
			continue
		}

		inst := &models.ScheduleInstance{
			ScheduleInstanceID: uuid.New(),
			CompanyID:          companyID,
			UserID:             userID,
			ScheduleDate:       d,
			ScheduleTemplateID: *resolved.ShiftID,
			ExpectedStart:      resolved.ExpectedStart,
			ExpectedEnd:        resolved.ExpectedEnd,
			Timezone:           resolved.Timezone,
			WorkCenterCode:     resolved.WorkCenterCode,
			GeneratedAt:        time.Now().UTC(),
			Status:             "active",
		}
		instances = append(instances, inst)
		s.logger.Debug("Created instance for date",
			zap.String("date", d.Format("2006-01-02")),
			zap.String("template_id", resolved.ShiftID.String()))
	}

	s.logger.Info("Generated schedule instances",
		zap.String("user_id", userID.String()),
		zap.Int("count", len(instances)))
	return instances
}

// ---- Overrides ----

func (s *schedulingServiceImpl) CreateScheduleOverride(ctx context.Context, companyID uuid.UUID, override *models.ScheduleOverride, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.ScheduleOverride, error) {
	if err := s.validateScheduleOverride(override); err != nil {
		return nil, err
	}
	if override.OverrideID == uuid.Nil {
		override.OverrideID = uuid.New()
	}
	override.CompanyID = companyID
	override.CreatedAt = time.Now().UTC()

	existing, _ := s.schedulingRepo.GetScheduleOverrideByUserDate(ctx, override.UserID, override.OverrideDate)
	if existing != nil {
		return nil, fmt.Errorf("override already exists for this date")
	}
	if err := s.schedulingRepo.CreateScheduleOverride(ctx, override); err != nil {
		return nil, err
	}
	if override.OverrideType == "off" {
		instances, _ := s.schedulingRepo.GetScheduleInstancesByUserDate(ctx, override.UserID, override.OverrideDate)
		if len(instances) > 0 && instances[0].Status == "active" {
			_ = s.schedulingRepo.CancelScheduleInstance(ctx, instances[0].ScheduleInstanceID, "off_override")
		}
	}
	after, _ := json.Marshal(override)
	s.logAudit(ctx, companyID, "schedule_override.create", override.OverrideID, actorType, actorID, nil, after, metadata)
	return override, nil
}

func (s *schedulingServiceImpl) UpdateScheduleOverride(ctx context.Context, overrideID uuid.UUID, update ScheduleOverrideUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.ScheduleOverride, error) {
	override, err := s.schedulingRepo.GetScheduleOverrideByID(ctx, overrideID)
	if err != nil {
		return nil, err
	}
	before, _ := json.Marshal(override)
	if update.OverrideType != nil {
		override.OverrideType = *update.OverrideType
	}
	if update.Reason != nil {
		override.Reason = update.Reason
	}
	if err := s.schedulingRepo.UpdateScheduleOverride(ctx, override); err != nil {
		return nil, err
	}
	after, _ := json.Marshal(override)
	s.logAudit(ctx, override.CompanyID, "schedule_override.update", overrideID, actorType, actorID, before, after, metadata)
	return override, nil
}

func (s *schedulingServiceImpl) DeleteScheduleOverride(ctx context.Context, overrideID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error {
	override, err := s.schedulingRepo.GetScheduleOverrideByID(ctx, overrideID)
	if err != nil {
		return err
	}
	before, _ := json.Marshal(override)
	if err := s.schedulingRepo.DeleteScheduleOverride(ctx, overrideID); err != nil {
		return err
	}
	s.logAudit(ctx, override.CompanyID, "schedule_override.delete", overrideID, actorType, actorID, before, nil, metadata)
	return nil
}

// ---- Work Center Shift Mappings ----

func (s *schedulingServiceImpl) CreateWorkCenterShiftMapping(ctx context.Context, companyID uuid.UUID, mapping *models.WorkCenterShift, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error {
	if mapping.WorkCenterCode == "" || mapping.ShiftID == uuid.Nil {
		return fmt.Errorf("work_center_code and shift_id required")
	}
	mapping.MappingID = uuid.New()
	mapping.CompanyID = companyID
	mapping.CreatedAt = time.Now().UTC()
	mapping.IsActive = true
	return s.schedulingRepo.CreateWorkCenterShiftMapping(ctx, mapping)
}

func (s *schedulingServiceImpl) UpdateWorkCenterShiftMappingByKey(ctx context.Context, companyID uuid.UUID, workCenterCode string, update WorkCenterShiftUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error {
	mapping, err := s.schedulingRepo.GetWorkCenterShiftByCode(ctx, companyID, workCenterCode, time.Now())
	if err != nil {
		return err
	}
	if mapping == nil {
		return fmt.Errorf("no active shift mapping for work center %s", workCenterCode)
	}
	if update.ShiftID != nil {
		mapping.ShiftID = *update.ShiftID
	}
	if update.EffectiveTo != nil {
		mapping.EffectiveTo = update.EffectiveTo
		mapping.IsActive = false
	}
	return s.schedulingRepo.UpdateWorkCenterShiftMapping(ctx, mapping)
}

// ---- Schedule Resolution ----

func (s *schedulingServiceImpl) ResolveUserDay(ctx context.Context, companyID, userID uuid.UUID, date time.Time) (*PositionBasedResolvedDay, error) {
	s.logger.Info("Resolving user day",
		zap.String("user_id", userID.String()),
		zap.String("date", date.Format("2006-01-02")))

	subject, err := s.subjectResolver.ResolveSubject(ctx, companyID, userID, "employee", date)
	if err != nil {
		s.logger.Error("Failed to resolve subject", zap.Error(err))
		return nil, err
	}
	if subject == nil {
		s.logger.Warn("Subject resolution returned nil", zap.String("user_id", userID.String()))
		return &PositionBasedResolvedDay{IsSchedulable: false, ScheduleStatus: "subject_not_found"}, nil
	}

	s.logger.Info("Subject resolved",
		zap.String("user_id", userID.String()),
		zap.String("position_id", func() string {
			if subject.PositionID != nil {
				return subject.PositionID.String()
			}
			return "<nil>"
		}()),
		zap.String("work_center_code", func() string {
			if subject.WorkCenterCode != nil {
				return *subject.WorkCenterCode
			}
			return "<nil>"
		}()),
		zap.Bool("is_active", subject.IsActive),
		zap.Bool("attendance_required", subject.AttendanceRequired),
		zap.Bool("overtime_allowed", subject.OvertimeAllowed),
	)

	if !subject.IsActive {
		s.logger.Info("Subject is inactive", zap.String("user_id", userID.String()))
		return &PositionBasedResolvedDay{IsSchedulable: false, ScheduleStatus: "inactive"}, nil
	}

	overrideInfo, _ := s.subjectResolver.ResolveOverride(ctx, companyID, userID, "employee", date)
	if overrideInfo != nil && overrideInfo.IsOnLeave {
		s.logger.Info("User on leave", zap.String("user_id", userID.String()))
		return &PositionBasedResolvedDay{
			Date:           date,
			Timezone:       "UTC",
			IsSchedulable:  false,
			ScheduleStatus: "on_leave",
			IsOnLeave:      true,
			IsLeavePaid:    overrideInfo.IsLeavePaid,
			LeaveTypeID:    overrideInfo.LeaveTypeID,
			LeaveRequestID: overrideInfo.LeaveRequestID,
		}, nil
	}

	schOverride, _ := s.schedulingRepo.GetScheduleOverrideByUserDate(ctx, userID, date)
	if schOverride != nil && schOverride.OverrideType == "off" {
		s.logger.Info("Schedule override 'off' found", zap.String("user_id", userID.String()))
		return &PositionBasedResolvedDay{
			IsSchedulable:  false,
			ScheduleStatus: "override_off",
			IsOverride:     true,
			OverrideType:   &schOverride.OverrideType,
		}, nil
	}

	instances, _ := s.schedulingRepo.GetScheduleInstancesByUserDate(ctx, userID, date)
	var instance *models.ScheduleInstance
	if len(instances) > 0 {
		instance = instances[0]
	}
	if instance != nil && instance.Status == "active" {
		s.logger.Info("Active schedule instance exists",
			zap.String("user_id", userID.String()),
			zap.String("instance_id", instance.ScheduleInstanceID.String()))
		return &PositionBasedResolvedDay{
			Date:               instance.ScheduleDate,
			Timezone:           instance.Timezone,
			IsSchedulable:      true,
			AttendanceRequired: subject.AttendanceRequired,
			OvertimeAllowed:    subject.OvertimeAllowed,
			ExpectedStart:      instance.ExpectedStart,
			ExpectedEnd:        instance.ExpectedEnd,
			PositionID:         subject.PositionID,
			PositionTitle:      &subject.PositionTitle,
			WorkCenterCode:     subject.WorkCenterCode,
			WorkCenterName:     &subject.WorkCenterName,
			ShiftID:            &instance.ScheduleTemplateID,
			ScheduleInstanceID: &instance.ScheduleInstanceID,
			ScheduleStatus:     instance.Status,
		}, nil
	}

	if subject.WorkCenterCode == nil {
		s.logger.Info("Subject has no work center code", zap.String("user_id", userID.String()))
		return &PositionBasedResolvedDay{
			Date:           date,
			IsSchedulable:  false,
			ScheduleStatus: "no_work_center",
			PositionID:     subject.PositionID,
			PositionTitle:  &subject.PositionTitle,
		}, nil
	}

	mapping, err := s.schedulingRepo.GetWorkCenterShiftByCode(ctx, companyID, *subject.WorkCenterCode, date)
	if err != nil {
		s.logger.Error("Error fetching work center shift mapping",
			zap.Error(err),
			zap.String("work_center", *subject.WorkCenterCode))
		return nil, err
	}
	if mapping == nil {
		s.logger.Info("No shift mapping found for work center",
			zap.String("work_center", *subject.WorkCenterCode),
			zap.String("user_id", userID.String()),
			zap.String("date", date.Format("2006-01-02")))
		return &PositionBasedResolvedDay{
			Date:               date,
			Timezone:           "UTC",
			IsSchedulable:      true,
			AttendanceRequired: subject.AttendanceRequired,
			OvertimeAllowed:    subject.OvertimeAllowed,
			PositionID:         subject.PositionID,
			PositionTitle:      &subject.PositionTitle,
			WorkCenterCode:     subject.WorkCenterCode,
			WorkCenterName:     &subject.WorkCenterName,
			ScheduleStatus:     "no_shift_mapping",
		}, nil
	}

	template, err := s.schedulingRepo.GetScheduleTemplate(ctx, mapping.ShiftID)
	if err != nil || template == nil {
		s.logger.Error("Shift template not found",
			zap.String("shift_id", mapping.ShiftID.String()),
			zap.Error(err))
		return &PositionBasedResolvedDay{
			Date:           date,
			IsSchedulable:  false,
			ScheduleStatus: "template_not_found",
			PositionID:     subject.PositionID,
			PositionTitle:  &subject.PositionTitle,
			WorkCenterCode: subject.WorkCenterCode,
		}, nil
	}

	expectedStart, expectedEnd, err := s.calculateExpectedTimes(date, template, "UTC")
	if err != nil {
		s.logger.Error("Failed to calculate expected times",
			zap.Error(err),
			zap.String("user_id", userID.String()))
		return nil, err
	}

	s.logger.Info("Resolved to scheduled",
		zap.String("user_id", userID.String()),
		zap.String("work_center", *subject.WorkCenterCode),
		zap.String("shift_id", mapping.ShiftID.String()),
		zap.Time("expected_start", *expectedStart),
		zap.Time("expected_end", *expectedEnd))

	return &PositionBasedResolvedDay{
		Date:               date,
		Timezone:           "UTC",
		IsSchedulable:      true,
		AttendanceRequired: subject.AttendanceRequired,
		OvertimeAllowed:    subject.OvertimeAllowed,
		ExpectedStart:      expectedStart,
		ExpectedEnd:        expectedEnd,
		PositionID:         subject.PositionID,
		PositionTitle:      &subject.PositionTitle,
		WorkCenterCode:     subject.WorkCenterCode,
		WorkCenterName:     &subject.WorkCenterName,
		ShiftID:            &mapping.ShiftID,
		ShiftName:          &template.Name,
		ScheduleStatus:     "scheduled",
	}, nil
}

func (s *schedulingServiceImpl) CreateScheduleInstanceFromPosition(ctx context.Context, companyID, userID uuid.UUID, date time.Time, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.ScheduleInstance, error) {
	resolved, err := s.ResolveUserDay(ctx, companyID, userID, date)
	if err != nil {
		return nil, err
	}
	if resolved.ScheduleStatus != "scheduled" {
		return nil, fmt.Errorf("cannot create schedule: %s", resolved.ScheduleStatus)
	}
	if !s.isFutureDate(date, resolved.Timezone) {
		return nil, fmt.Errorf("cannot create schedule for past or today")
	}
	instances, _ := s.schedulingRepo.GetScheduleInstancesByUserDate(ctx, userID, date)
	if len(instances) > 0 {
		_ = s.schedulingRepo.CancelScheduleInstance(ctx, instances[0].ScheduleInstanceID, "regenerated")
	}
	instance := &models.ScheduleInstance{
		ScheduleInstanceID: uuid.New(),
		CompanyID:          companyID,
		UserID:             userID,
		ScheduleDate:       date,
		ScheduleTemplateID: *resolved.ShiftID,
		ExpectedStart:      resolved.ExpectedStart,
		ExpectedEnd:        resolved.ExpectedEnd,
		Timezone:           resolved.Timezone,
		WorkCenterCode:     resolved.WorkCenterCode,
		GeneratedAt:        time.Now().UTC(),
		Status:             "active",
	}
	if err := s.schedulingRepo.CreateScheduleInstance(ctx, nil, instance); err != nil {
		return nil, err
	}
	after, _ := json.Marshal(instance)
	s.logAudit(ctx, companyID, "schedule_instance.create_from_position", instance.ScheduleInstanceID, actorType, actorID, nil, after, metadata)
	return instance, nil
}

// ---- Availability ----

func (s *schedulingServiceImpl) CheckScheduleAvailability(ctx context.Context, companyID, userID uuid.UUID, date time.Time, timezone string) ([]time.Time, error) {
	resolved, err := s.ResolveUserDay(ctx, companyID, userID, date)
	if err != nil || resolved.ScheduleStatus != "scheduled" {
		return []time.Time{}, nil
	}
	if resolved.ExpectedStart == nil || resolved.ExpectedEnd == nil {
		return []time.Time{}, nil
	}
	loc, _ := time.LoadLocation(timezone)
	start := resolved.ExpectedStart.In(loc)
	end := resolved.ExpectedEnd.In(loc)
	return []time.Time{start, end}, nil
}

func (s *schedulingServiceImpl) ValidateScheduleConflict(ctx context.Context, userID uuid.UUID, startTime, endTime time.Time, excludeInstanceID *uuid.UUID) (bool, error) {
	instances, err := s.schedulingRepo.GetScheduleInstancesByUser(ctx, userID, startTime.AddDate(0, 0, -1), endTime.AddDate(0, 0, 1))
	if err != nil {
		return false, err
	}
	for _, inst := range instances {
		if excludeInstanceID != nil && inst.ScheduleInstanceID == *excludeInstanceID {
			continue
		}
		if inst.Status != "active" {
			continue
		}
		if inst.ExpectedStart != nil && inst.ExpectedEnd != nil {
			if startTime.Before(*inst.ExpectedEnd) && endTime.After(*inst.ExpectedStart) {
				return true, nil
			}
		}
	}
	return false, nil
}

// ---- Health ----

func (s *schedulingServiceImpl) HealthCheck(ctx context.Context) error {
	return s.schedulingRepo.HealthCheck(ctx)
}

// ---- Internal helpers ----

func (s *schedulingServiceImpl) validateWorkCalendar(calendar *models.WorkCalendar) error {
	if calendar.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID required")
	}
	if calendar.Year < 2000 || calendar.Year > 2100 {
		return fmt.Errorf("invalid year")
	}
	if calendar.Name == "" {
		return fmt.Errorf("name required")
	}
	if len(calendar.WorkingDays) == 0 {
		return fmt.Errorf("working days required")
	}
	_, err := time.LoadLocation(calendar.Timezone)
	if err != nil {
		return fmt.Errorf("invalid timezone: %w", err)
	}
	return nil
}

func (s *schedulingServiceImpl) validateScheduleTemplate(template *models.ScheduleTemplate) error {
	if template.CompanyID == uuid.Nil || template.CalendarID == uuid.Nil {
		return fmt.Errorf("company and calendar required")
	}
	if template.Name == "" || template.TemplateType == "" {
		return fmt.Errorf("name and template type required")
	}
	validTypes := map[string]bool{"office": true, "shift": true, "class": true}
	if !validTypes[template.TemplateType] {
		return fmt.Errorf("invalid template type")
	}
	return nil
}

func (s *schedulingServiceImpl) validateScheduleInstance(instance *models.ScheduleInstance) error {
	if instance.CompanyID == uuid.Nil || instance.UserID == uuid.Nil || instance.ScheduleTemplateID == uuid.Nil {
		return fmt.Errorf("company, user, template required")
	}
	if instance.ScheduleDate.IsZero() || instance.Timezone == "" {
		return fmt.Errorf("date and timezone required")
	}
	if !s.isFutureDate(instance.ScheduleDate, instance.Timezone) {
		return fmt.Errorf("schedule date must be in future")
	}
	return nil
}

func (s *schedulingServiceImpl) validateScheduleOverride(override *models.ScheduleOverride) error {
	if override.CompanyID == uuid.Nil || override.UserID == uuid.Nil || override.OverrideDate.IsZero() {
		return fmt.Errorf("company, user, date required")
	}
	if override.OverrideType != "off" && override.OverrideType != "force_work" && override.OverrideType != "holiday_override" {
		return fmt.Errorf("invalid override type")
	}
	return nil
}

func (s *schedulingServiceImpl) isFutureDate(date time.Time, timezone string) bool {
	loc, _ := time.LoadLocation(timezone)
	now := time.Now().In(loc)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	return date.After(today)
}

func (s *schedulingServiceImpl) calculateExpectedTimes(date time.Time, template *models.ScheduleTemplate, timezone string) (*time.Time, *time.Time, error) {
	loc, _ := time.LoadLocation(timezone)
	day := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, loc)
	var start, end time.Time
	switch template.TemplateType {
	case "office":
		startClock, _ := time.Parse("15:04", *template.Rules.StartTime)
		endClock, _ := time.Parse("15:04", *template.Rules.EndTime)
		start = time.Date(day.Year(), day.Month(), day.Day(), startClock.Hour(), startClock.Minute(), 0, 0, loc)
		end = time.Date(day.Year(), day.Month(), day.Day(), endClock.Hour(), endClock.Minute(), 0, 0, loc)
	default:
		return nil, nil, fmt.Errorf("unsupported template type")
	}
	return &start, &end, nil
}

func (s *schedulingServiceImpl) logAudit(ctx context.Context, companyID uuid.UUID, action string, resourceID uuid.UUID, actorType string, actorID uuid.UUID, before, after []byte, metadata map[string]interface{}) {
	if s.auditService == nil {
		return
	}
	_ = s.auditService.LogAction(ctx, nil, &companyID, "scheduling", action, "scheduling", &resourceID, actorType, &actorID, before, after, metadata)
}

// LeaveScheduleData contains the minimal data needed for leave scheduling integration.
type LeaveScheduleData struct {
	LeaveRequestID uuid.UUID
	UserID         uuid.UUID
	CompanyID      uuid.UUID
	StartDate      time.Time
	EndDate        time.Time
}

// ApplyApprovedLeave creates "off" schedule overrides for each day in the leave date range.
func (s *schedulingServiceImpl) ApplyApprovedLeave(ctx context.Context, leaveData *LeaveScheduleData, actorType string, actorID uuid.UUID) error {
	if leaveData == nil {
		return fmt.Errorf("leave data is nil")
	}
	if leaveData.CompanyID == uuid.Nil || leaveData.UserID == uuid.Nil {
		return fmt.Errorf("company and user are required")
	}
	if leaveData.StartDate.IsZero() || leaveData.EndDate.IsZero() {
		return fmt.Errorf("start and end dates are required")
	}
	if leaveData.EndDate.Before(leaveData.StartDate) {
		return fmt.Errorf("end date cannot be before start date")
	}

	reason := fmt.Sprintf("leave_%s", leaveData.LeaveRequestID.String())
	for d := leaveData.StartDate; !d.After(leaveData.EndDate); d = d.AddDate(0, 0, 1) {
		override := &models.ScheduleOverride{
			OverrideID:   uuid.New(),
			CompanyID:    leaveData.CompanyID,
			UserID:       leaveData.UserID,
			OverrideDate: d,
			OverrideType: "off",
			Reason:       &reason,
		}
		if _, err := s.CreateScheduleOverride(ctx, leaveData.CompanyID, override, actorType, actorID, nil); err != nil {
			if !strings.Contains(err.Error(), "already exists") {
				return fmt.Errorf("failed to create override for %s: %w", d.Format("2006-01-02"), err)
			}
		}
	}
	return nil
}

// RollbackCancelledLeave deletes all schedule overrides for the leave request and regenerates schedules for future dates.
func (s *schedulingServiceImpl) RollbackCancelledLeave(ctx context.Context, leaveData *LeaveScheduleData, actorType string, actorID uuid.UUID) error {
	if leaveData == nil {
		return fmt.Errorf("leave data is nil")
	}
	if leaveData.CompanyID == uuid.Nil || leaveData.UserID == uuid.Nil {
		return fmt.Errorf("company and user are required")
	}
	reason := fmt.Sprintf("leave_%s", leaveData.LeaveRequestID.String())

	if err := s.schedulingRepo.DeleteScheduleOverridesByReason(ctx, leaveData.CompanyID, leaveData.UserID, reason); err != nil {
		return fmt.Errorf("failed to delete leave overrides: %w", err)
	}

	now := time.Now().UTC()
	for d := leaveData.StartDate; !d.After(leaveData.EndDate); d = d.AddDate(0, 0, 1) {
		if d.After(now) {
			_, err := s.CreateScheduleInstanceFromPosition(ctx, leaveData.CompanyID, leaveData.UserID, d, actorType, actorID, nil)
			if err != nil {
				s.logger.Warn("Failed to regenerate schedule after leave rollback",
					zap.String("user_id", leaveData.UserID.String()),
					zap.String("date", d.Format("2006-01-02")),
					zap.Error(err),
				)
			}
		}
	}
	return nil
}
