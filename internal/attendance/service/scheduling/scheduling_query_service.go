package scheduling

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/attendance/service/resolver"
)

type SchedulingQueryService interface {
	// Work Calendars
	GetWorkCalendarByID(ctx context.Context, calendarID uuid.UUID) (*models.WorkCalendar, error)
	GetWorkCalendarsByCompany(ctx context.Context, companyID uuid.UUID, locationID *uuid.UUID) ([]*models.WorkCalendar, error)
	GetWorkCalendarAvailability(ctx context.Context, calendarID uuid.UUID, startDate, endDate time.Time) ([]CalendarAvailability, error)

	// Schedule Templates
	GetScheduleTemplateByID(ctx context.Context, templateID uuid.UUID) (*models.ScheduleTemplate, error)
	GetScheduleTemplatesByCompany(ctx context.Context, companyID uuid.UUID, locationID *uuid.UUID, activeOnly bool) ([]*models.ScheduleTemplate, error)
	GetScheduleTemplatesByCalendar(ctx context.Context, calendarID uuid.UUID) ([]*models.ScheduleTemplate, error)

	// Work Centers
	GetWorkCenterByCode(ctx context.Context, companyID uuid.UUID, workCenterCode string) (*models.WorkCenter, error)
	GetWorkCentersByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.WorkCenter, error)
	GetWorkCenterShifts(ctx context.Context, companyID uuid.UUID, workCenterCode string, date time.Time) ([]*models.WorkCenterShift, error)

	// Overrides
	GetScheduleOverrideByID(ctx context.Context, overrideID uuid.UUID) (*models.ScheduleOverride, error)
	GetScheduleOverridesByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time, overrideType *string) ([]*models.ScheduleOverride, error)
	GetScheduleOverridesByCompany(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time, overrideType *string) ([]*models.ScheduleOverride, error)
	GetScheduleOverrideByUserDate(ctx context.Context, userID uuid.UUID, date time.Time) (*models.ScheduleOverride, error)

	// PreviewSchedule — computes the schedule for [from, to] without
	// writing anything. Same chain as punch-time resolution: WC → shift →
	// template → calendar → override. No schedule_instances involved.
	PreviewSchedule(ctx context.Context, companyID, userID uuid.UUID, from, to time.Time) ([]PositionBasedResolvedDay, error)

	// Timezone resolution
	ResolveCompanyTimezone(ctx context.Context, companyID uuid.UUID) (string, error)
	ResolveLocationTimezone(ctx context.Context, companyID, locationID uuid.UUID) (string, error)

	// Health
	HealthCheck(ctx context.Context) error
}

type CalendarAvailability struct {
	Date         time.Time `json:"date"`
	IsWorkingDay bool      `json:"is_working_day"`
	IsHoliday    bool      `json:"is_holiday"`
	HolidayName  string    `json:"holiday_name,omitempty"`
}

const maxAvailabilityRangeDays = 366

type schedulingQueryServiceImpl struct {
	schedulingRepo  repository.ScheduleRepository
	subjectResolver resolver.ScheduleSubjectResolver
	tzProvider      resolver.TimezoneProvider
	scheduling      SchedulingService
	logger          *zap.Logger
}

func NewSchedulingQueryService(
	schedulingRepo repository.ScheduleRepository,
	subjectResolver resolver.ScheduleSubjectResolver,
	tzProvider resolver.TimezoneProvider,
	scheduling SchedulingService,
	logger *zap.Logger,
) SchedulingQueryService {
	return &schedulingQueryServiceImpl{
		schedulingRepo:  schedulingRepo,
		subjectResolver: subjectResolver,
		tzProvider:      tzProvider,
		scheduling:      scheduling,
		logger:          logger,
	}
}

// ---- Timezone helpers ----

func (qs *schedulingQueryServiceImpl) ResolveCompanyTimezone(ctx context.Context, companyID uuid.UUID) (string, error) {
	if qs.tzProvider == nil {
		return "UTC", nil
	}
	tz, err := qs.tzProvider.ResolveTimezone(ctx, companyID, nil, nil, nil)
	if err != nil || tz == "" {
		return "UTC", err
	}
	return tz, nil
}

func (qs *schedulingQueryServiceImpl) ResolveLocationTimezone(ctx context.Context, companyID, locationID uuid.UUID) (string, error) {
	if qs.tzProvider == nil {
		return "UTC", nil
	}
	tz, err := qs.tzProvider.ResolveTimezone(ctx, companyID, nil, nil, &locationID)
	if err != nil || tz == "" {
		return "UTC", err
	}
	return tz, nil
}

// ---- Work Calendars ----

func (qs *schedulingQueryServiceImpl) GetWorkCalendarByID(ctx context.Context, calendarID uuid.UUID) (*models.WorkCalendar, error) {
	return qs.schedulingRepo.GetWorkCalendarByID(ctx, calendarID)
}

func (qs *schedulingQueryServiceImpl) GetWorkCalendarsByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	locationID *uuid.UUID,
) ([]*models.WorkCalendar, error) {
	return qs.schedulingRepo.GetWorkCalendarsByCompany(ctx, companyID, locationID)
}

func (qs *schedulingQueryServiceImpl) GetWorkCalendarAvailability(
	ctx context.Context,
	calendarID uuid.UUID,
	startDate, endDate time.Time,
) ([]CalendarAvailability, error) {
	if endDate.Before(startDate) {
		return nil, fmt.Errorf("end_date must be on or after start_date")
	}
	if endDate.Sub(startDate) > maxAvailabilityRangeDays*24*time.Hour {
		return nil, fmt.Errorf("availability range cannot exceed %d days", maxAvailabilityRangeDays)
	}

	cal, err := qs.schedulingRepo.GetWorkCalendarByID(ctx, calendarID)
	if err != nil {
		return nil, err
	}
	if cal == nil {
		return nil, fmt.Errorf("work calendar not found: %s", calendarID)
	}

	holidayMap := make(map[string]string, len(cal.Holidays))
	for dateKey, raw := range cal.Holidays {
		switch v := raw.(type) {
		case map[string]interface{}:
			if name, ok := v["name"].(string); ok {
				holidayMap[dateKey] = name
			} else {
				holidayMap[dateKey] = ""
			}
		case string:
			holidayMap[dateKey] = v
		default:
			holidayMap[dateKey] = ""
		}
	}

	working := make(map[int]struct{}, len(cal.WorkingDays))
	for _, wd := range cal.WorkingDays {
		working[wd] = struct{}{}
	}

	var avail []CalendarAvailability
	for d := startDate; !d.After(endDate); d = d.AddDate(0, 0, 1) {
		dateStr := d.Format("2006-01-02")
		_, isWorking := working[int(d.Weekday())]
		holidayName, isHoliday := holidayMap[dateStr]

		avail = append(avail, CalendarAvailability{
			Date:         d,
			IsWorkingDay: isWorking,
			IsHoliday:    isHoliday,
			HolidayName:  holidayName,
		})
	}
	return avail, nil
}

// ---- Schedule Templates ----

func (qs *schedulingQueryServiceImpl) GetScheduleTemplateByID(ctx context.Context, templateID uuid.UUID) (*models.ScheduleTemplate, error) {
	return qs.schedulingRepo.GetScheduleTemplate(ctx, templateID)
}

func (qs *schedulingQueryServiceImpl) GetScheduleTemplatesByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	locationID *uuid.UUID,
	activeOnly bool,
) ([]*models.ScheduleTemplate, error) {
	return qs.schedulingRepo.GetScheduleTemplatesByCompany(ctx, companyID, locationID, activeOnly)
}

func (qs *schedulingQueryServiceImpl) GetScheduleTemplatesByCalendar(ctx context.Context, calendarID uuid.UUID) ([]*models.ScheduleTemplate, error) {
	return qs.schedulingRepo.GetScheduleTemplatesByCalendar(ctx, calendarID)
}

// ---- Work Centers ----

func (qs *schedulingQueryServiceImpl) GetWorkCenterByCode(ctx context.Context, companyID uuid.UUID, workCenterCode string) (*models.WorkCenter, error) {
	return qs.schedulingRepo.GetWorkCenter(ctx, companyID, workCenterCode)
}

func (qs *schedulingQueryServiceImpl) GetWorkCentersByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.WorkCenter, error) {
	return qs.schedulingRepo.GetWorkCentersByCompany(ctx, companyID, activeOnly)
}

func (qs *schedulingQueryServiceImpl) GetWorkCenterShifts(ctx context.Context, companyID uuid.UUID, workCenterCode string, date time.Time) ([]*models.WorkCenterShift, error) {
	shift, err := qs.schedulingRepo.GetWorkCenterShiftByCode(ctx, companyID, workCenterCode, date)
	if err != nil {
		return nil, err
	}
	if shift == nil {
		return []*models.WorkCenterShift{}, nil
	}
	return []*models.WorkCenterShift{shift}, nil
}

// ---- Overrides ----

func (qs *schedulingQueryServiceImpl) GetScheduleOverrideByID(ctx context.Context, overrideID uuid.UUID) (*models.ScheduleOverride, error) {
	return qs.schedulingRepo.GetScheduleOverrideByID(ctx, overrideID)
}

func (qs *schedulingQueryServiceImpl) GetScheduleOverridesByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time, overrideType *string) ([]*models.ScheduleOverride, error) {
	return qs.schedulingRepo.GetScheduleOverridesByUser(ctx, userID, &startDate, &endDate, overrideType)
}

func (qs *schedulingQueryServiceImpl) GetScheduleOverridesByCompany(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time, overrideType *string) ([]*models.ScheduleOverride, error) {
	return qs.schedulingRepo.GetScheduleOverridesByCompany(ctx, companyID, &startDate, &endDate, overrideType)
}

func (qs *schedulingQueryServiceImpl) GetScheduleOverrideByUserDate(ctx context.Context, userID uuid.UUID, date time.Time) (*models.ScheduleOverride, error) {
	return qs.schedulingRepo.GetScheduleOverrideByUserDate(ctx, userID, date)
}

// ---- PreviewSchedule ----

// PreviewSchedule returns the derived schedule for [from, to] without
// writing anything. It reuses ResolveUserDay — the same code path that
// answers "what is this person's shift on date D?" at punch time. There
// is no materialization and no cache; every call recomputes from the rule
// chain.
//
// Range is capped at one year to keep the per-day loop bounded.
func (qs *schedulingQueryServiceImpl) PreviewSchedule(
	ctx context.Context,
	companyID, userID uuid.UUID,
	from, to time.Time,
) ([]PositionBasedResolvedDay, error) {
	if to.Before(from) {
		return nil, fmt.Errorf("to must be on or after from")
	}
	if to.Sub(from) > maxAvailabilityRangeDays*24*time.Hour {
		return nil, fmt.Errorf("preview range cannot exceed %d days", maxAvailabilityRangeDays)
	}
	days := make([]PositionBasedResolvedDay, 0, 32)
	for d := from; !d.After(to); d = d.AddDate(0, 0, 1) {
		day, err := qs.scheduling.ResolveUserDay(ctx, companyID, userID, d)
		if err != nil || day == nil {
			qs.logger.Warn("PreviewSchedule: day resolve failed",
				zap.String("user_id", userID.String()),
				zap.String("date", d.Format("2006-01-02")),
				zap.Error(err))
			continue
		}
		days = append(days, *day)
	}
	return days, nil
}

// ---- Health ----

func (qs *schedulingQueryServiceImpl) HealthCheck(ctx context.Context) error {
	return qs.schedulingRepo.HealthCheck(ctx)
}
