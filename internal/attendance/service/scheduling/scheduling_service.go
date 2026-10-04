package scheduling

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/attendance/service/resolver"
	"auth-service/internal/infrastructure/audit"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type ScheduleOverrideUpdate struct {
	OverrideType *string `json:"override_type,omitempty"`
	Reason       *string `json:"reason,omitempty"`
}

type WorkCenterShiftUpdate struct {
	ShiftID     *uuid.UUID `json:"shift_id,omitempty"`
	EffectiveTo *time.Time `json:"effective_to,omitempty"`
}

type Holiday struct {
	Date string `json:"date"`
	Name string `json:"name"`
}

type SchedulingService interface {
	CreateWorkCalendar(ctx context.Context, calendar *models.WorkCalendar, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.WorkCalendar, error)
	UpdateWorkCalendar(ctx context.Context, calendarID uuid.UUID, update WorkCalendarUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.WorkCalendar, error)
	DeleteWorkCalendar(ctx context.Context, calendarID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	AddHolidayToCalendar(ctx context.Context, calendarID uuid.UUID, date, name string, actorType string, actorID uuid.UUID) error
	ProcessHolidayForDate(ctx context.Context, companyID uuid.UUID, date time.Time, actorType string, actorID uuid.UUID) error
	CreateScheduleTemplate(ctx context.Context, template *models.ScheduleTemplate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.ScheduleTemplate, error)
	UpdateScheduleTemplate(ctx context.Context, templateID uuid.UUID, update ScheduleTemplateUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.ScheduleTemplate, error)
	DeleteScheduleTemplate(ctx context.Context, templateID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	CreateScheduleInstance(ctx context.Context, instance *models.ScheduleInstance, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.ScheduleInstance, error)
	UpdateScheduleInstance(ctx context.Context, instanceID uuid.UUID, update ScheduleInstanceUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.ScheduleInstance, error)
	DeleteScheduleInstance(ctx context.Context, instanceID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	BulkCreateScheduleInstances(ctx context.Context, instances []*models.ScheduleInstance, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	ApplyApprovedLeave(ctx context.Context, leaveData *LeaveScheduleData, actorType string, actorID uuid.UUID) error
	RollbackCancelledLeave(ctx context.Context, leaveData *LeaveScheduleData, actorType string, actorID uuid.UUID) error
	GenerateScheduleForUser(ctx context.Context, companyID, userID uuid.UUID, config ScheduleGenerationConfig, actorType string, actorID uuid.UUID) ([]*models.ScheduleInstance, error)
	GenerateScheduleForCompany(ctx context.Context, companyID uuid.UUID, config ScheduleGenerationConfig, actorType string, actorID uuid.UUID) ([]*models.ScheduleInstance, error)
	CreateScheduleOverride(ctx context.Context, companyID uuid.UUID, override *models.ScheduleOverride, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.ScheduleOverride, error)
	UpdateScheduleOverride(ctx context.Context, overrideID uuid.UUID, update ScheduleOverrideUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.ScheduleOverride, error)
	DeleteScheduleOverride(ctx context.Context, overrideID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	CreateWorkCenterShiftMapping(ctx context.Context, companyID uuid.UUID, mapping *models.WorkCenterShift, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	UpdateWorkCenterShiftMappingByKey(ctx context.Context, companyID uuid.UUID, workCenterCode string, update WorkCenterShiftUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	ResolveUserDay(ctx context.Context, companyID, userID uuid.UUID, date time.Time) (*PositionBasedResolvedDay, error)
	CreateScheduleInstanceFromPosition(ctx context.Context, companyID, userID uuid.UUID, date time.Time, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.ScheduleInstance, error)
	CheckScheduleAvailability(ctx context.Context, companyID, userID uuid.UUID, date time.Time, timezone string) ([]time.Time, error)
	ValidateScheduleConflict(ctx context.Context, userID uuid.UUID, startTime, endTime time.Time, excludeInstanceID *uuid.UUID) (bool, error)
	HealthCheck(ctx context.Context) error
}

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

func (s *schedulingServiceImpl) CreateWorkCalendar(
	ctx context.Context,
	calendar *models.WorkCalendar,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*models.WorkCalendar, error) {
	if err := s.validateWorkCalendar(calendar); err != nil {
		return nil, err
	}
	if calendar.CalendarID == uuid.Nil {
		calendar.CalendarID = uuid.New()
	}
	calendar.CreatedAt = time.Now().UTC()
	existing, _ := s.schedulingRepo.GetWorkCalendarsByCompany(ctx, calendar.CompanyID, nil)
	for _, e := range existing {
		if e.Year != calendar.Year {
			continue
		}
		sameScope := (e.LocationID == nil && calendar.LocationID == nil) ||
			(e.LocationID != nil && calendar.LocationID != nil && *e.LocationID == *calendar.LocationID)
		if sameScope {
			if calendar.LocationID == nil {
				return nil, fmt.Errorf("company-wide calendar for year %d already exists", calendar.Year)
			}
			return nil, fmt.Errorf("calendar for year %d already exists at this location", calendar.Year)
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

func (s *schedulingServiceImpl) AddHolidayToCalendar(
	ctx context.Context,
	calendarID uuid.UUID,
	date, name string,
	actorType string,
	actorID uuid.UUID,
) error {
	if date == "" {
		return fmt.Errorf("date is required")
	}
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if _, err := time.Parse("2006-01-02", date); err != nil {
		return fmt.Errorf("invalid date %q: must be YYYY-MM-DD", date)
	}
	calendar, err := s.schedulingRepo.GetWorkCalendarByID(ctx, calendarID)
	if err != nil {
		return err
	}
	before, _ := json.Marshal(calendar)
	if _, exists := calendar.Holidays[date]; exists {
		return fmt.Errorf("holiday already exists on %s", date)
	}
	newHolidays := make(map[string]interface{}, len(calendar.Holidays)+1)
	for k, v := range calendar.Holidays {
		newHolidays[k] = v
	}
	newHolidays[date] = map[string]interface{}{"date": date, "name": name}
	calendar.Holidays = newHolidays
	if err := s.schedulingRepo.UpdateWorkCalendar(ctx, calendar); err != nil {
		return err
	}
	after, _ := json.Marshal(calendar)
	s.logAudit(ctx, calendar.CompanyID, "work_calendar.add_holiday", calendarID, actorType, actorID, before, after, nil)
	return nil
}

func (s *schedulingServiceImpl) ProcessHolidayForDate(
	ctx context.Context,
	companyID uuid.UUID,
	date time.Time,
	actorType string,
	actorID uuid.UUID,
) error {
	instances, err := s.schedulingRepo.GetScheduleInstancesByCompany(ctx, companyID, nil, date, date)
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

func (s *schedulingServiceImpl) BulkCreateScheduleInstances(
	ctx context.Context,
	instances []*models.ScheduleInstance,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	if len(instances) == 0 {
		return nil
	}
	companyID := instances[0].CompanyID
	now := time.Now().UTC()
	for _, inst := range instances {
		if inst.ScheduleInstanceID == uuid.Nil {
			inst.ScheduleInstanceID = uuid.New()
		}
		inst.GeneratedAt = now
		inst.Status = "active"
	}
	tx, err := s.schedulingRepo.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	for _, inst := range instances {
		if err := s.schedulingRepo.CreateScheduleInstance(ctx, tx, inst); err != nil {
			s.logger.Error("Bulk create failed; transaction will be rolled back",
				zap.String("instance_id", inst.ScheduleInstanceID.String()),
				zap.String("user_id", inst.UserID.String()),
				zap.Time("schedule_date", inst.ScheduleDate),
				zap.Error(err))
			return fmt.Errorf("create instance %s: %w", inst.ScheduleInstanceID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit bulk create: %w", err)
	}
	summary := map[string]interface{}{"created": len(instances)}
	summaryJSON, _ := json.Marshal(summary)
	s.logAudit(ctx, companyID, "schedule_instance.bulk_create", uuid.Nil, actorType, actorID, nil, summaryJSON, metadata)
	return nil
}

func (s *schedulingServiceImpl) GenerateScheduleForUser(ctx context.Context, companyID, userID uuid.UUID, config ScheduleGenerationConfig, actorType string, actorID uuid.UUID) ([]*models.ScheduleInstance, error) {
	subject, err := s.subjectResolver.ResolveSubject(ctx, companyID, userID, "employee", config.StartDate)
	if err != nil || subject == nil {
		return nil, fmt.Errorf("failed to resolve subject: %w", err)
	}
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

	// ── Resolve the user's tz once via the subject resolver.
	//    Falls back to config.Timezone, then "UTC".
	refTime := config.StartDate
	subjectInfo, _ := s.subjectResolver.ResolveSubject(ctx, companyID, userID, "employee", refTime)

	tz := ""
	if subjectInfo != nil && subjectInfo.WorkCenterTimezone != "" {
		tz = subjectInfo.WorkCenterTimezone
	} else if config.Timezone != "" {
		tz = config.Timezone
	} else {
		tz = "UTC"
	}

	loc, _ := time.LoadLocation(tz)
	if loc == nil {
		loc = time.UTC
	}
	now := time.Now().In(loc)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)

	s.logger.Info("Starting schedule generation for user",
		zap.String("user_id", userID.String()),
		zap.String("tz", tz),
		zap.String("start_date", config.StartDate.Format("2006-01-02")),
		zap.String("end_date", config.EndDate.Format("2006-01-02")),
		zap.Bool("overwrite", config.Overwrite),
	)
	for d := config.StartDate; !d.After(config.EndDate); d = d.AddDate(0, 0, 1) {
		if !d.After(today) {
			continue
		}
		if !config.Overwrite {
			exists, _ := s.schedulingRepo.HasActiveSchedule(ctx, companyID, userID, d)
			if exists {
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
		if resolved.ScheduleStatus != "scheduled" {
			continue
		}
		if resolved.ShiftID == nil {
			s.logger.Warn("Resolved day has no shift ID, skipping",
				zap.String("user", userID.String()),
				zap.String("date", d.Format("2006-01-02")))
			continue
		}
		instTz := resolved.Timezone
		if instTz == "" {
			instTz = tz
		}
		inst := &models.ScheduleInstance{
			ScheduleInstanceID: uuid.New(),
			CompanyID:          companyID,
			UserID:             userID,
			ScheduleDate:       d,
			ScheduleTemplateID: *resolved.ShiftID,
			ExpectedStart:      resolved.ExpectedStart,
			ExpectedEnd:        resolved.ExpectedEnd,
			Timezone:           instTz,
			WorkCenterCode:     resolved.WorkCenterCode,
			GeneratedAt:        time.Now().UTC(),
			Status:             "active",
		}
		instances = append(instances, inst)
	}
	return instances
}

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

// ResolveUserDay — fully tz-aware. Never hardcodes UTC.
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

	// ── Resolve effective tz via chain: subject's WC tz > company default > UTC.
	effectiveTz := subject.WorkCenterTimezone
	if effectiveTz == "" {
		effectiveTz = subject.CompanyTimezone
	}
	if effectiveTz == "" {
		effectiveTz = "UTC"
	}

	if !subject.IsActive {
		return &PositionBasedResolvedDay{IsSchedulable: false, ScheduleStatus: "inactive"}, nil
	}

	overrideInfo, _ := s.subjectResolver.ResolveOverride(ctx, companyID, userID, "employee", date)
	if overrideInfo != nil && overrideInfo.IsOnLeave {
		return &PositionBasedResolvedDay{
			Date:           date,
			Timezone:       effectiveTz,
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
		instTz := instance.Timezone
		if instTz == "" {
			instTz = effectiveTz
		}
		return &PositionBasedResolvedDay{
			Date:               instance.ScheduleDate,
			Timezone:           instTz,
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
		return &PositionBasedResolvedDay{
			Date:           date,
			Timezone:       effectiveTz,
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
		return &PositionBasedResolvedDay{
			Date:               date,
			Timezone:           effectiveTz,
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

	// ── Build expected times in the shift's tz.
	expectedStart, expectedEnd, err := s.calculateExpectedTimes(date, template, effectiveTz)
	if err != nil {
		s.logger.Error("Failed to calculate expected times",
			zap.Error(err),
			zap.String("user_id", userID.String()))
		return nil, err
	}

	return &PositionBasedResolvedDay{
		Date:               date,
		Timezone:           effectiveTz,
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

func (s *schedulingServiceImpl) CheckScheduleAvailability(ctx context.Context, companyID, userID uuid.UUID, date time.Time, timezone string) ([]time.Time, error) {
	resolved, err := s.ResolveUserDay(ctx, companyID, userID, date)
	if err != nil || resolved.ScheduleStatus != "scheduled" {
		return []time.Time{}, nil
	}
	if resolved.ExpectedStart == nil || resolved.ExpectedEnd == nil {
		return []time.Time{}, nil
	}
	tz := resolved.Timezone
	if tz == "" {
		tz = timezone
	}
	loc, _ := time.LoadLocation(tz)
	if loc == nil {
		loc = time.UTC
	}
	return []time.Time{
		resolved.ExpectedStart.In(loc),
		resolved.ExpectedEnd.In(loc),
	}, nil
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

func (s *schedulingServiceImpl) HealthCheck(ctx context.Context) error {
	return s.schedulingRepo.HealthCheck(ctx)
}

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
	if _, err := time.LoadLocation(calendar.Timezone); err != nil {
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
	loc, err := time.LoadLocation(timezone)
	if err != nil || loc == nil {
		loc = time.UTC
	}
	now := time.Now().In(loc)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	return date.After(today)
}

// calculateExpectedTimes — builds instants from wall-clock rules in the shift tz.
func (s *schedulingServiceImpl) calculateExpectedTimes(date time.Time, template *models.ScheduleTemplate, timezone string) (*time.Time, *time.Time, error) {
	loc, err := time.LoadLocation(timezone)
	if err != nil || loc == nil {
		loc = time.UTC
	}

	day := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, loc)

	var start, end time.Time
	switch template.TemplateType {
	case "office":
		if template.Rules.StartTime == nil || template.Rules.EndTime == nil {
			return nil, nil, fmt.Errorf("office template missing start_time/end_time")
		}
		startClock, err := time.Parse("15:04", *template.Rules.StartTime)
		if err != nil {
			return nil, nil, fmt.Errorf("parse start_time: %w", err)
		}
		endClock, err := time.Parse("15:04", *template.Rules.EndTime)
		if err != nil {
			return nil, nil, fmt.Errorf("parse end_time: %w", err)
		}
		start = time.Date(day.Year(), day.Month(), day.Day(), startClock.Hour(), startClock.Minute(), 0, 0, loc)
		end = time.Date(day.Year(), day.Month(), day.Day(), endClock.Hour(), endClock.Minute(), 0, 0, loc)

		// Overnight shift: end < start → belongs to next day.
		if !end.After(start) {
			end = end.AddDate(0, 0, 1)
		}
	default:
		return nil, nil, fmt.Errorf("unsupported template type: %s", template.TemplateType)
	}
	return &start, &end, nil
}

func (s *schedulingServiceImpl) logAudit(ctx context.Context, companyID uuid.UUID, action string, resourceID uuid.UUID, actorType string, actorID uuid.UUID, before, after []byte, metadata map[string]interface{}) {
	if s.auditService == nil {
		return
	}
	_ = s.auditService.LogAction(ctx, nil, &companyID, "scheduling", action, "scheduling", &resourceID, actorType, &actorID, before, after, metadata)
}

type LeaveScheduleData struct {
	LeaveRequestID uuid.UUID
	UserID         uuid.UUID
	CompanyID      uuid.UUID
	StartDate      time.Time
	EndDate        time.Time
}

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
