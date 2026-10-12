package scheduling

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
	"auth-service/internal/infrastructure/audit"
)

type ScheduleOverrideUpdate struct {
	OverrideType  *string `json:"override_type,omitempty"`
	Reason        *string `json:"reason,omitempty"`
	ExpectedStart *string `json:"expected_start,omitempty"`
	ExpectedEnd   *string `json:"expected_end,omitempty"`
}

type WorkCenterShiftUpdate struct {
	ShiftID     *uuid.UUID `json:"shift_id,omitempty"`
	EffectiveTo *time.Time `json:"effective_to,omitempty"`
}

type Holiday struct {
	Date string `json:"date"`
	Name string `json:"name"`
}

// SchedulingService — schedules are now derived, not materialized.
//
// There is no longer any "generate schedule" operation. Every read either
// walks the rule chain (WC → shift → template → calendar → override) or
// reads a pre-existing override. The service is now:
//
//   - admin CRUD for the rule tables (calendars, templates, mappings)
//   - admin CRUD for overrides (the only per-user, per-day manual data)
//   - ResolveUserDay, used by both the punch path and the preview endpoint
//
// See SchedulingQueryService.PreviewSchedule for the "show me a schedule"
// entry point.
type SchedulingService interface {
	// Work calendars
	CreateWorkCalendar(ctx context.Context, calendar *models.WorkCalendar, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.WorkCalendar, error)
	UpdateWorkCalendar(ctx context.Context, calendarID uuid.UUID, update WorkCalendarUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.WorkCalendar, error)
	DeleteWorkCalendar(ctx context.Context, calendarID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	AddHolidayToCalendar(ctx context.Context, calendarID uuid.UUID, date, name string, actorType string, actorID uuid.UUID) error

	// Schedule templates
	CreateScheduleTemplate(ctx context.Context, template *models.ScheduleTemplate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.ScheduleTemplate, error)
	UpdateScheduleTemplate(ctx context.Context, templateID uuid.UUID, update ScheduleTemplateUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.ScheduleTemplate, error)
	DeleteScheduleTemplate(ctx context.Context, templateID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error

	// Overrides — the only per-user, per-day manual data we still write.
	CreateScheduleOverride(ctx context.Context, companyID uuid.UUID, override *models.ScheduleOverride, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.ScheduleOverride, error)
	UpdateScheduleOverride(ctx context.Context, overrideID uuid.UUID, update ScheduleOverrideUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.ScheduleOverride, error)
	DeleteScheduleOverride(ctx context.Context, overrideID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error

	// Work center shift mappings
	CreateWorkCenterShiftMapping(ctx context.Context, companyID uuid.UUID, mapping *models.WorkCenterShift, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	UpdateWorkCenterShiftMappingByKey(ctx context.Context, companyID uuid.UUID, workCenterCode string, update WorkCenterShiftUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error

	// Leave integration — writes/deletes overrides only.
	ApplyApprovedLeave(ctx context.Context, leaveData *LeaveScheduleData, actorType string, actorID uuid.UUID) error
	RollbackCancelledLeave(ctx context.Context, leaveData *LeaveScheduleData, actorType string, actorID uuid.UUID) error

	// ResolveUserDay — the shared derivation. Called by the punch path and
	// by SchedulingQueryService.PreviewSchedule.
	ResolveUserDay(ctx context.Context, companyID, userID uuid.UUID, date time.Time) (*PositionBasedResolvedDay, error)

	// CheckScheduleAvailability — returns the [start, end] window for a
	// day if one exists, else an empty slice.
	CheckScheduleAvailability(ctx context.Context, companyID, userID uuid.UUID, date time.Time, timezone string) ([]time.Time, error)

	HealthCheck(ctx context.Context) error
}

type WorkCalendarUpdate struct {
	Name        *string   `json:"name,omitempty"`
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
	PositionID   *uuid.UUID            `json:"position_id,omitempty"`
	LocationID   *uuid.UUID            `json:"location_id,omitempty"`
}

// PositionBasedResolvedDay is the output of ResolveUserDay. It is the sole
// shape used by both the punch path and the preview endpoint.
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

// =============================================================================
// resolveCalendarForUser
// =============================================================================

func (s *schedulingServiceImpl) resolveCalendarForUser(
	ctx context.Context,
	companyID, userID uuid.UUID,
	workCenterCode *string,
	positionLocationID *uuid.UUID,
	primaryLocationID *uuid.UUID,
	date time.Time,
) *models.WorkCalendar {
	year := date.Year()

	// Step 1: work center's location
	if workCenterCode != nil && *workCenterCode != "" {
		wc, err := s.schedulingRepo.GetWorkCenter(ctx, companyID, *workCenterCode)
		if err != nil {
			s.logger.Warn("calendar: work center lookup failed",
				zap.String("company_id", companyID.String()),
				zap.String("work_center", *workCenterCode),
				zap.Error(err),
			)
		} else if wc != nil && wc.LocationID != nil {
			cal, err := s.schedulingRepo.GetWorkCalendarByLocation(ctx, companyID, *wc.LocationID, year)
			if err != nil {
				s.logger.Warn("calendar: work center location lookup failed",
					zap.String("location_id", wc.LocationID.String()),
					zap.Int("year", year),
					zap.Error(err),
				)
			} else if cal != nil {
				return cal
			}
		}
	}

	// Step 2: position's location
	if positionLocationID != nil && *positionLocationID != uuid.Nil {
		cal, err := s.schedulingRepo.GetWorkCalendarByLocation(ctx, companyID, *positionLocationID, year)
		if err != nil {
			s.logger.Warn("calendar: position location lookup failed",
				zap.String("location_id", positionLocationID.String()),
				zap.Int("year", year),
				zap.Error(err),
			)
		} else if cal != nil {
			return cal
		}
	}

	// Step 3: primary location
	if primaryLocationID != nil && *primaryLocationID != uuid.Nil {
		cal, err := s.schedulingRepo.GetWorkCalendarByLocation(ctx, companyID, *primaryLocationID, year)
		if err != nil {
			s.logger.Warn("calendar: primary location lookup failed",
				zap.String("location_id", primaryLocationID.String()),
				zap.Int("year", year),
				zap.Error(err),
			)
		} else if cal != nil {
			return cal
		}
	}

	// Step 4: company-wide
	cal, err := s.schedulingRepo.GetWorkCalendarCompanyWide(ctx, companyID, year)
	if err != nil {
		s.logger.Warn("calendar: company-wide lookup failed",
			zap.String("company_id", companyID.String()),
			zap.Int("year", year),
			zap.Error(err),
		)
		return nil
	}
	return cal
}

// =============================================================================
// Work Calendars — CRUD
// =============================================================================

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

func (s *schedulingServiceImpl) UpdateWorkCalendar(
	ctx context.Context,
	calendarID uuid.UUID,
	update WorkCalendarUpdate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*models.WorkCalendar, error) {
	calendar, err := s.schedulingRepo.GetWorkCalendarByID(ctx, calendarID)
	if err != nil {
		return nil, err
	}
	before, _ := json.Marshal(calendar)

	if update.Name != nil {
		calendar.Name = *update.Name
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

func (s *schedulingServiceImpl) DeleteWorkCalendar(
	ctx context.Context,
	calendarID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
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

// =============================================================================
// Schedule Templates — CRUD
// =============================================================================

func (s *schedulingServiceImpl) CreateScheduleTemplate(
	ctx context.Context,
	template *models.ScheduleTemplate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*models.ScheduleTemplate, error) {
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

func (s *schedulingServiceImpl) UpdateScheduleTemplate(
	ctx context.Context,
	templateID uuid.UUID,
	update ScheduleTemplateUpdate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*models.ScheduleTemplate, error) {
	template, err := s.schedulingRepo.GetScheduleTemplate(ctx, templateID)
	if err != nil {
		return nil, err
	}
	if template == nil {
		return nil, fmt.Errorf("schedule template not found")
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

	// ── scope reassignment ───────────────────────────────────────────────
	// Setting one scope field clears the other, so the pair always stays
	// valid under chk_template_scope. Pass nil explicitly to un-scope
	// (make company-wide).
	if update.PositionID != nil || update.LocationID != nil {
		if update.PositionID != nil && *update.PositionID != uuid.Nil {
			template.PositionID = update.PositionID
			template.LocationID = nil
		} else if update.LocationID != nil && *update.LocationID != uuid.Nil {
			template.LocationID = update.LocationID
			template.PositionID = nil
		} else {
			// both nil → company-wide
			template.PositionID = nil
			template.LocationID = nil
		}
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

func (s *schedulingServiceImpl) DeleteScheduleTemplate(
	ctx context.Context,
	templateID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
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

// =============================================================================
// Schedule Overrides
// =============================================================================

func (s *schedulingServiceImpl) CreateScheduleOverride(
	ctx context.Context,
	companyID uuid.UUID,
	override *models.ScheduleOverride,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*models.ScheduleOverride, error) {
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
	// No more cancel-instances branch: the override row alone tells the
	// resolver what to return. There is nothing to cancel.

	after, _ := json.Marshal(override)
	s.logAudit(ctx, companyID, "schedule_override.create", override.OverrideID, actorType, actorID, nil, after, metadata)
	return override, nil
}

func (s *schedulingServiceImpl) UpdateScheduleOverride(
	ctx context.Context,
	overrideID uuid.UUID,
	update ScheduleOverrideUpdate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*models.ScheduleOverride, error) {
	override, err := s.schedulingRepo.GetScheduleOverrideByID(ctx, overrideID)
	if err != nil {
		return nil, err
	}
	if override == nil {
		return nil, fmt.Errorf("schedule override not found")
	}
	before, _ := json.Marshal(override)

	// ── type ────────────────────────────────────────────────────────────
	if update.OverrideType != nil {
		override.OverrideType = *update.OverrideType
	}

	// ── reason ──────────────────────────────────────────────────────────
	if update.Reason != nil {
		override.Reason = update.Reason
	}

	// ── custom_hours window ─────────────────────────────────────────────
	// Only `custom_hours` carries a window; every other type must have
	// NULL times (enforced by the DB check constraint chk_custom_hours).
	// Coalesce incoming fields against the existing row so partial
	// updates work — e.g. changing only the times keeps the reason.
	if override.OverrideType == "custom_hours" {
		if update.ExpectedStart != nil {
			override.ExpectedStart = update.ExpectedStart
		}
		if update.ExpectedEnd != nil {
			override.ExpectedEnd = update.ExpectedEnd
		}
		if override.ExpectedStart == nil || override.ExpectedEnd == nil {
			return nil, fmt.Errorf("custom_hours requires expected_start and expected_end")
		}
	} else {
		// Non-custom types must not carry wall-clock times.
		override.ExpectedStart = nil
		override.ExpectedEnd = nil
	}

	// Reuse the same validator the create path runs, so a malformed
	// custom_hours update surfaces as a 400 from the service layer
	// instead of a raw pg check-constraint error (500) from the repo.
	if err := s.validateScheduleOverride(override); err != nil {
		return nil, err
	}

	if err := s.schedulingRepo.UpdateScheduleOverride(ctx, override); err != nil {
		return nil, err
	}
	after, _ := json.Marshal(override)
	s.logAudit(ctx, override.CompanyID, "schedule_override.update", overrideID, actorType, actorID, before, after, metadata)
	return override, nil
}

func (s *schedulingServiceImpl) DeleteScheduleOverride(
	ctx context.Context,
	overrideID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
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

// =============================================================================
// Work Center Shift Mappings
// =============================================================================

func (s *schedulingServiceImpl) CreateWorkCenterShiftMapping(
	ctx context.Context,
	companyID uuid.UUID,
	mapping *models.WorkCenterShift,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	if mapping.WorkCenterCode == "" || mapping.ShiftID == uuid.Nil {
		return fmt.Errorf("work_center_code and shift_id required")
	}
	mapping.MappingID = uuid.New()
	mapping.CompanyID = companyID
	mapping.CreatedAt = time.Now().UTC()
	mapping.IsActive = true
	return s.schedulingRepo.CreateWorkCenterShiftMapping(ctx, mapping)
}

func (s *schedulingServiceImpl) UpdateWorkCenterShiftMappingByKey(
	ctx context.Context,
	companyID uuid.UUID,
	workCenterCode string,
	update WorkCenterShiftUpdate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
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

// =============================================================================
// ResolveUserDay
// =============================================================================

func (s *schedulingServiceImpl) ResolveUserDay(
	ctx context.Context,
	companyID, userID uuid.UUID,
	date time.Time,
) (*PositionBasedResolvedDay, error) {
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

	// Leave override wins (from the leave module)
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

	// Off override wins (from schedule_overrides)
	schOverride, _ := s.schedulingRepo.GetScheduleOverrideByUserDate(ctx, userID, date)
	if schOverride != nil && schOverride.OverrideType == "off" {
		return &PositionBasedResolvedDay{
			IsSchedulable:  false,
			ScheduleStatus: "override_off",
			IsOverride:     true,
			OverrideType:   &schOverride.OverrideType,
		}, nil
	}

	// ══════════════════════════════════════════════════════════════════
	// TEMPLATE RESOLUTION — SAP-style fallback chain, most specific first:
	//
	//   1. schedule_templates[position_id, date]         (position scope)
	//   2. work_center_shifts[WC, date] → templates[shift_id]
	//   3. schedule_templates[position.location_id, date]
	//   4. schedule_templates[primary_location_id, date]
	//   5. schedule_templates[location_id IS NULL]       (company-wide)
	//
	// First tier that yields a template wins. `shiftID` is only set when
	// tier 2 resolves — position/location/company tiers have no shift
	// mapping to record.
	// ══════════════════════════════════════════════════════════════════

	var (
		template       *models.ScheduleTemplate
		shiftID        *uuid.UUID
		scheduleSource string
	)

	// ── Tier 1: position-scoped template ───────────────────────────────
	if subject.PositionID != nil && *subject.PositionID != uuid.Nil {
		tmpl, tErr := s.schedulingRepo.GetScheduleTemplateForPositionOnDate(
			ctx, companyID, *subject.PositionID, date,
		)
		if tErr != nil {
			s.logger.Warn("position template lookup failed",
				zap.String("position_id", subject.PositionID.String()),
				zap.Error(tErr))
		} else if tmpl != nil {
			template = tmpl
			scheduleSource = "position"
		}
	}

	// ── Tier 2: WC → shift mapping → template ──────────────────────────
	if template == nil &&
		subject.WorkCenterCode != nil && *subject.WorkCenterCode != "" {
		mapping, mErr := s.schedulingRepo.GetWorkCenterShiftByCode(
			ctx, companyID, *subject.WorkCenterCode, date,
		)
		if mErr != nil {
			s.logger.Warn("shift mapping lookup failed",
				zap.String("work_center", *subject.WorkCenterCode),
				zap.Error(mErr))
		} else if mapping != nil {
			tmpl, tErr := s.schedulingRepo.GetScheduleTemplateOnDate(ctx, mapping.ShiftID, date)
			if tErr != nil {
				s.logger.Warn("template lookup by shift_id failed",
					zap.String("shift_id", mapping.ShiftID.String()),
					zap.Error(tErr))
			} else if tmpl != nil {
				template = tmpl
				id := mapping.ShiftID
				shiftID = &id
				scheduleSource = "work_center_shift"
			}
		}
	}

	// ── Tier 3: position.location_id template ──────────────────────────
	if template == nil &&
		subject.PositionLocationID != nil &&
		*subject.PositionLocationID != uuid.Nil {
		tmpl, tErr := s.schedulingRepo.GetScheduleTemplateForLocationOnDate(
			ctx, companyID, subject.PositionLocationID, date,
		)
		if tErr != nil {
			s.logger.Warn("position.location template lookup failed",
				zap.String("location_id", subject.PositionLocationID.String()),
				zap.Error(tErr))
		} else if tmpl != nil {
			template = tmpl
			scheduleSource = "position_location"
		}
	}

	// ── Tier 4: primary_location_id template ───────────────────────────
	if template == nil &&
		subject.PrimaryLocationID != nil &&
		*subject.PrimaryLocationID != uuid.Nil {
		tmpl, tErr := s.schedulingRepo.GetScheduleTemplateForLocationOnDate(
			ctx, companyID, subject.PrimaryLocationID, date,
		)
		if tErr != nil {
			s.logger.Warn("primary_location template lookup failed",
				zap.String("location_id", subject.PrimaryLocationID.String()),
				zap.Error(tErr))
		} else if tmpl != nil {
			template = tmpl
			scheduleSource = "primary_location"
		}
	}

	// ── Tier 5: company-wide template ──────────────────────────────────
	if template == nil {
		tmpl, tErr := s.schedulingRepo.GetScheduleTemplateForLocationOnDate(
			ctx, companyID, nil, date,
		)
		if tErr != nil {
			s.logger.Warn("company-wide template lookup failed", zap.Error(tErr))
		} else if tmpl != nil {
			template = tmpl
			scheduleSource = "company_wide"
		}
	}

	// ── All tiers missed ───────────────────────────────────────────────
	if template == nil {
		s.logger.Warn("no schedule template resolved for user",
			zap.String("user_id", userID.String()),
			zap.String("date", date.Format("2006-01-02")),
			zap.Any("position_id", subject.PositionID),
			zap.Any("work_center", subject.WorkCenterCode),
			zap.Any("position_location", subject.PositionLocationID),
			zap.Any("primary_location", subject.PrimaryLocationID),
		)
		return &PositionBasedResolvedDay{
			Date:           date,
			Timezone:       effectiveTz,
			IsSchedulable:  false,
			ScheduleStatus: "no_template",
			PositionID:     subject.PositionID,
			PositionTitle:  &subject.PositionTitle,
			WorkCenterCode: subject.WorkCenterCode,
		}, nil
	}

	s.logger.Debug("template resolved",
		zap.String("user_id", userID.String()),
		zap.String("source", scheduleSource),
		zap.String("template_id", template.ScheduleTemplateID.String()),
		zap.String("template_name", template.Name),
	)

	expectedStart, expectedEnd, err := s.calculateExpectedTimes(date, template, effectiveTz)
	if err != nil {
		s.logger.Warn("failed to calculate expected times from template",
			zap.String("user_id", userID.String()),
			zap.String("template_id", template.ScheduleTemplateID.String()),
			zap.String("template_type", template.TemplateType),
			zap.Error(err))
		return &PositionBasedResolvedDay{
			Date:               date,
			Timezone:           effectiveTz,
			IsSchedulable:      false,
			ScheduleStatus:     "template_invalid",
			AttendanceRequired: subject.AttendanceRequired,
			OvertimeAllowed:    subject.OvertimeAllowed,
			PositionID:         subject.PositionID,
			PositionTitle:      &subject.PositionTitle,
			WorkCenterCode:     subject.WorkCenterCode,
			WorkCenterName:     &subject.WorkCenterName,
			ShiftID:            shiftID,
			ShiftName:          &template.Name,
		}, nil
	}

	// ── Calendar check ─────────────────────────────────────────────────
	scheduleStatus := "scheduled"
	if cal := s.resolveCalendarForUser(
		ctx, companyID, userID,
		subject.WorkCenterCode,
		subject.PositionLocationID,
		subject.PrimaryLocationID,
		date,
	); cal != nil {
		switch {
		case cal.IsHoliday(date):
			scheduleStatus = "holiday"
			expectedStart = nil
			expectedEnd = nil
		case !cal.IsWorkingDay(date):
			scheduleStatus = "weekly_off"
			expectedStart = nil
			expectedEnd = nil
		}
	}

	// ── Override patch — applied last ──────────────────────────────────
	if schOverride != nil {
		switch schOverride.OverrideType {
		case "custom_hours":
			if schOverride.ExpectedStart != nil && schOverride.ExpectedEnd != nil {
				loc, lerr := time.LoadLocation(effectiveTz)
				if lerr != nil || loc == nil {
					loc = time.UTC
				}
				s2, sErr := ParseWallClock(date, *schOverride.ExpectedStart, loc)
				e2, eErr := ParseWallClock(date, *schOverride.ExpectedEnd, loc)
				if sErr == nil && eErr == nil {
					if !e2.After(s2) {
						e2 = e2.AddDate(0, 0, 1)
					}
					expectedStart = &s2
					expectedEnd = &e2
				} else {
					s.logger.Warn("custom_hours: invalid wall clock",
						zap.String("start", *schOverride.ExpectedStart),
						zap.String("end", *schOverride.ExpectedEnd),
						zap.String("tz", effectiveTz),
						zap.Error(sErr))
				}
			}
			scheduleStatus = "scheduled"
		case "force_work":
			if expectedStart == nil {
				if s2, e2, cErr := s.calculateExpectedTimes(date, template, effectiveTz); cErr == nil {
					expectedStart = s2
					expectedEnd = e2
				}
			}
			scheduleStatus = "scheduled"
		case "holiday_override":
			scheduleStatus = "holiday"
			expectedStart = nil
			expectedEnd = nil
		}
	}

	return &PositionBasedResolvedDay{
		Date:               date,
		Timezone:           effectiveTz,
		IsSchedulable:      scheduleStatus == "scheduled",
		AttendanceRequired: subject.AttendanceRequired,
		OvertimeAllowed:    subject.OvertimeAllowed,
		ExpectedStart:      expectedStart,
		ExpectedEnd:        expectedEnd,
		PositionID:         subject.PositionID,
		PositionTitle:      &subject.PositionTitle,
		WorkCenterCode:     subject.WorkCenterCode,
		WorkCenterName:     &subject.WorkCenterName,
		ShiftID:            shiftID,
		ShiftName:          &template.Name,
		ScheduleStatus:     scheduleStatus,
		IsOverride:         schOverride != nil,
		OverrideType:       overrideTypeOrNil(schOverride),
	}, nil
}

func overrideTypeOrNil(o *models.ScheduleOverride) *string {
	if o == nil {
		return nil
	}
	return &o.OverrideType
}

func (s *schedulingServiceImpl) CheckScheduleAvailability(
	ctx context.Context,
	companyID, userID uuid.UUID,
	date time.Time,
	timezone string,
) ([]time.Time, error) {
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

func (s *schedulingServiceImpl) HealthCheck(ctx context.Context) error {
	return s.schedulingRepo.HealthCheck(ctx)
}

// =============================================================================
// Validation helpers
// =============================================================================

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

	// Scope exclusivity — mirrors chk_template_scope in the DB. Caught
	// here so the caller sees a 400 instead of a raw pg error.
	hasPosition := template.PositionID != nil && *template.PositionID != uuid.Nil
	hasLocation := template.LocationID != nil && *template.LocationID != uuid.Nil
	if hasPosition && hasLocation {
		return fmt.Errorf("template can be scoped to either position or location, not both")
	}

	return nil
}

func (s *schedulingServiceImpl) validateScheduleOverride(override *models.ScheduleOverride) error {
	if override.CompanyID == uuid.Nil || override.UserID == uuid.Nil || override.OverrideDate.IsZero() {
		return fmt.Errorf("company, user, date required")
	}
	switch override.OverrideType {
	case "off", "force_work", "holiday_override":
		// no extra fields
	case "custom_hours":
		if override.ExpectedStart == nil || override.ExpectedEnd == nil {
			return fmt.Errorf("custom_hours requires expected_start and expected_end")
		}
		if _, err := ParseClockString(*override.ExpectedStart); err != nil {
			return fmt.Errorf("invalid expected_start %q: %w", *override.ExpectedStart, err)
		}
		if _, err := ParseClockString(*override.ExpectedEnd); err != nil {
			return fmt.Errorf("invalid expected_end %q: %w", *override.ExpectedEnd, err)
		}
		if *override.ExpectedStart == *override.ExpectedEnd {
			return fmt.Errorf("expected_end must differ from expected_start")
		}
	default:
		return fmt.Errorf("invalid override type: %s", override.OverrideType)
	}
	return nil
}

func (s *schedulingServiceImpl) calculateExpectedTimes(
	date time.Time,
	template *models.ScheduleTemplate,
	timezone string,
) (*time.Time, *time.Time, error) {
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
		if !end.After(start) {
			end = end.AddDate(0, 0, 1)
		}
	default:
		return nil, nil, fmt.Errorf("unsupported template type: %s", template.TemplateType)
	}
	return &start, &end, nil
}

func (s *schedulingServiceImpl) logAudit(
	ctx context.Context,
	companyID uuid.UUID,
	action string,
	resourceID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	before, after []byte,
	metadata map[string]interface{},
) {
	if s.auditService == nil {
		return
	}
	_ = s.auditService.LogAction(ctx, nil, &companyID, "scheduling", action, "scheduling", &resourceID, actorType, &actorID, before, after, metadata)
}

// =============================================================================
// Leave integration
// =============================================================================

type LeaveScheduleData struct {
	LeaveRequestID uuid.UUID
	UserID         uuid.UUID
	CompanyID      uuid.UUID
	StartDate      time.Time
	EndDate        time.Time
}

func (s *schedulingServiceImpl) ApplyApprovedLeave(
	ctx context.Context,
	leaveData *LeaveScheduleData,
	actorType string,
	actorID uuid.UUID,
) error {
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

func (s *schedulingServiceImpl) RollbackCancelledLeave(
	ctx context.Context,
	leaveData *LeaveScheduleData,
	actorType string,
	actorID uuid.UUID,
) error {
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
	// No regeneration loop. Deleting the override rows is sufficient — the
	// resolver derives the schedule from the rule chain on the next read.
	return nil
}

// ParseClockString parses "HH:MM" or "HH:MM:SS" and returns the time-of-day.
func ParseClockString(hhmm string) (time.Time, error) {
	layout := "15:04:05"
	if len(hhmm) == 5 {
		layout = "15:04"
	}
	return time.Parse(layout, hhmm)
}

// ParseWallClock combines a calendar date and an "HH:MM" / "HH:MM:SS"
// string into an instant in the given location. This is how a
// custom_hours override row (which stores only a wall clock) becomes a
// real time.Time for the resolved day.
func ParseWallClock(date time.Time, hhmm string, loc *time.Location) (time.Time, error) {
	clock, err := ParseClockString(hhmm)
	if err != nil {
		return time.Time{}, err
	}
	return time.Date(
		date.Year(), date.Month(), date.Day(),
		clock.Hour(), clock.Minute(), clock.Second(), 0, loc,
	), nil
}
