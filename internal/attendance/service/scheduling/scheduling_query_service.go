package scheduling

import (
	"context"
	"sort"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/attendance/service/resolver"
)

// SchedulingQueryService defines query operations.
//
// Location-scoped methods take a `locationID *uuid.UUID`:
//
//	nil      = no location filter (ALL scope)
//	non-nil  = filter to entities at that employment location
type SchedulingQueryService interface {
	// Work Calendars
	GetWorkCalendarByID(ctx context.Context, calendarID uuid.UUID) (*models.WorkCalendar, error)
	GetWorkCalendarsByCompany(ctx context.Context, companyID uuid.UUID, locationID *uuid.UUID) ([]*models.WorkCalendar, error)
	GetWorkCalendarAvailability(ctx context.Context, calendarID uuid.UUID, startDate, endDate time.Time) ([]CalendarAvailability, error)

	// Schedule Templates
	GetScheduleTemplateByID(ctx context.Context, templateID uuid.UUID) (*models.ScheduleTemplate, error)
	GetScheduleTemplatesByCompany(ctx context.Context, companyID uuid.UUID, locationID *uuid.UUID, activeOnly bool) ([]*models.ScheduleTemplate, error)
	GetScheduleTemplatesByCalendar(ctx context.Context, calendarID uuid.UUID) ([]*models.ScheduleTemplate, error)

	// Schedule Instances
	GetScheduleInstanceByID(ctx context.Context, instanceID uuid.UUID) (*models.ScheduleInstance, error)
	GetScheduleInstancesByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*models.ScheduleInstance, error)
	GetScheduleInstancesByCompany(ctx context.Context, companyID uuid.UUID, locationID *uuid.UUID, startDate, endDate time.Time) ([]*models.ScheduleInstance, error)
	GetScheduleInstancesByTemplate(ctx context.Context, templateID uuid.UUID, startDate, endDate time.Time) ([]*models.ScheduleInstance, error)
	GetScheduleInstancesByPosition(ctx context.Context, positionID uuid.UUID, startDate, endDate time.Time) ([]*models.ScheduleInstance, error)
	GetScheduleInstancesByWorkCenter(ctx context.Context, companyID uuid.UUID, workCenterCode string, startDate, endDate time.Time) ([]*models.ScheduleInstance, error)

	// Work Centers
	GetWorkCenterByCode(ctx context.Context, companyID uuid.UUID, workCenterCode string) (*models.WorkCenter, error)
	GetWorkCentersByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.WorkCenter, error)
	GetWorkCenterShifts(ctx context.Context, companyID uuid.UUID, workCenterCode string, date time.Time) ([]*models.WorkCenterShift, error)

	// Overrides
	GetScheduleOverrideByID(ctx context.Context, overrideID uuid.UUID) (*models.ScheduleOverride, error)
	GetScheduleOverridesByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time, overrideType *string) ([]*models.ScheduleOverride, error)
	GetScheduleOverridesByCompany(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time, overrideType *string) ([]*models.ScheduleOverride, error)
	GetScheduleOverrideByUserDate(ctx context.Context, userID uuid.UUID, date time.Time) (*models.ScheduleOverride, error)

	// Stats
	GetScheduleStats(ctx context.Context, companyID uuid.UUID, locationID *uuid.UUID, startDate, endDate time.Time) (*ScheduleStats, error)

	// Health
	HealthCheck(ctx context.Context) error
}

// CalendarAvailability represents availability for a calendar date.
type CalendarAvailability struct {
	Date         time.Time `json:"date"`
	IsWorkingDay bool      `json:"is_working_day"`
	IsHoliday    bool      `json:"is_holiday"`
	HolidayName  string    `json:"holiday_name,omitempty"`
}

// ScheduleStats aggregates scheduling statistics.
type ScheduleStats struct {
	TotalInstances    int64                     `json:"total_instances"`
	TotalUsers        int64                     `json:"total_users"`
	TotalTemplates    int64                     `json:"total_templates"`
	ByTemplateType    map[string]int64          `json:"by_template_type"`
	ByDate            map[string]int64          `json:"by_date"`
	ByWorkCenter      map[string]int64          `json:"by_work_center"`
	UpcomingSchedules []ScheduleInstanceSummary `json:"upcoming_schedules"`
}

// ScheduleInstanceSummary is a lightweight version of a schedule instance.
type ScheduleInstanceSummary struct {
	InstanceID     uuid.UUID  `json:"instance_id"`
	UserID         uuid.UUID  `json:"user_id"`
	ScheduleDate   time.Time  `json:"schedule_date"`
	ExpectedStart  *time.Time `json:"expected_start,omitempty"`
	ExpectedEnd    *time.Time `json:"expected_end,omitempty"`
	TemplateName   string     `json:"template_name"`
	TemplateType   string     `json:"template_type"`
	PositionTitle  string     `json:"position_title,omitempty"`
	WorkCenterCode string     `json:"work_center_code,omitempty"`
}

// maxUpcomingSchedules caps the size of the UpcomingSchedules list returned
// by GetScheduleStats so responses stay bounded regardless of window size.
const maxUpcomingSchedules = 50

// Implementation
type schedulingQueryServiceImpl struct {
	schedulingRepo  repository.ScheduleRepository
	subjectResolver resolver.ScheduleSubjectResolver
	logger          *zap.Logger
}

func NewSchedulingQueryService(
	schedulingRepo repository.ScheduleRepository,
	subjectResolver resolver.ScheduleSubjectResolver,
	logger *zap.Logger,
) SchedulingQueryService {
	return &schedulingQueryServiceImpl{
		schedulingRepo:  schedulingRepo,
		subjectResolver: subjectResolver,
		logger:          logger,
	}
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

// GetWorkCalendarAvailability returns day-by-day working/holiday info.
//
// FIX (Tier 1): the previous implementation shadowed the outer `holidayMap`
// inside the loop, so entries were never added to the map and `IsHoliday`
// was always false. The map is now built directly from cal.Holidays, which
// is already keyed by "YYYY-MM-DD" (see AddHolidayToCalendar and
// UpdateWorkCalendar). Values are stored as `map[string]interface{}`
// containing "date" and "name".
func (qs *schedulingQueryServiceImpl) GetWorkCalendarAvailability(
	ctx context.Context,
	calendarID uuid.UUID,
	startDate, endDate time.Time,
) ([]CalendarAvailability, error) {
	cal, err := qs.schedulingRepo.GetWorkCalendarByID(ctx, calendarID)
	if err != nil {
		return nil, err
	}

	// Build the holiday lookup: date-string -> holiday name.
	// cal.Holidays is already keyed by date, so we don't need to parse the
	// inner "date" field. We only read "name" from the value.
	holidayMap := make(map[string]string, len(cal.Holidays))
	for dateKey, raw := range cal.Holidays {
		switch v := raw.(type) {
		case map[string]interface{}:
			if name, ok := v["name"].(string); ok {
				holidayMap[dateKey] = name
			} else {
				holidayMap[dateKey] = "" // exists but unnamed
			}
		case string:
			// Some legacy rows may have stored the name as the raw value.
			holidayMap[dateKey] = v
		default:
			holidayMap[dateKey] = ""
		}
	}

	// Precompute working days as a set for O(1) lookup.
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

// ---- Schedule Instances ----

func (qs *schedulingQueryServiceImpl) GetScheduleInstanceByID(ctx context.Context, instanceID uuid.UUID) (*models.ScheduleInstance, error) {
	return qs.schedulingRepo.GetScheduleInstance(ctx, instanceID)
}

func (qs *schedulingQueryServiceImpl) GetScheduleInstancesByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*models.ScheduleInstance, error) {
	return qs.schedulingRepo.GetScheduleInstancesByUser(ctx, userID, startDate, endDate)
}

func (qs *schedulingQueryServiceImpl) GetScheduleInstancesByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	locationID *uuid.UUID,
	startDate, endDate time.Time,
) ([]*models.ScheduleInstance, error) {
	return qs.schedulingRepo.GetScheduleInstancesByCompany(ctx, companyID, locationID, startDate, endDate)
}

func (qs *schedulingQueryServiceImpl) GetScheduleInstancesByTemplate(ctx context.Context, templateID uuid.UUID, startDate, endDate time.Time) ([]*models.ScheduleInstance, error) {
	return qs.schedulingRepo.GetScheduleInstancesByTemplate(ctx, templateID, startDate, endDate)
}

func (qs *schedulingQueryServiceImpl) GetScheduleInstancesByPosition(ctx context.Context, positionID uuid.UUID, startDate, endDate time.Time) ([]*models.ScheduleInstance, error) {
	users, err := qs.subjectResolver.GetUsersByPosition(ctx, positionID)
	if err != nil {
		return nil, err
	}
	var all []*models.ScheduleInstance
	for _, uid := range users {
		insts, err := qs.schedulingRepo.GetScheduleInstancesByUser(ctx, uid, startDate, endDate)
		if err != nil {
			qs.logger.Warn("Failed to fetch instances for user in position query",
				zap.String("position_id", positionID.String()),
				zap.String("user_id", uid.String()),
				zap.Error(err))
			continue
		}
		all = append(all, insts...)
	}
	return all, nil
}

func (qs *schedulingQueryServiceImpl) GetScheduleInstancesByWorkCenter(ctx context.Context, companyID uuid.UUID, workCenterCode string, startDate, endDate time.Time) ([]*models.ScheduleInstance, error) {
	return qs.schedulingRepo.GetScheduleInstancesByWorkCenter(ctx, companyID, workCenterCode, startDate, endDate)
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

// ---- Stats ----

// GetScheduleStats aggregates statistics for a company/location.
//
// FIX (Tier 1): previously issued one GetScheduleTemplate call per
// instance (N+1). Now fetches each unique template exactly once and
// populates UpcomingSchedules (which the struct declared but never set).
func (qs *schedulingQueryServiceImpl) GetScheduleStats(
	ctx context.Context,
	companyID uuid.UUID,
	locationID *uuid.UUID,
	startDate, endDate time.Time,
) (*ScheduleStats, error) {
	stats := &ScheduleStats{
		ByTemplateType:    make(map[string]int64),
		ByDate:            make(map[string]int64),
		ByWorkCenter:      make(map[string]int64),
		UpcomingSchedules: []ScheduleInstanceSummary{},
	}

	instances, err := qs.schedulingRepo.GetScheduleInstancesByCompany(ctx, companyID, locationID, startDate, endDate)
	if err != nil {
		return nil, err
	}
	stats.TotalInstances = int64(len(instances))

	// --- Pass 1: collect unique template IDs ---
	userSet := make(map[uuid.UUID]struct{})
	templateSet := make(map[uuid.UUID]struct{})
	for _, inst := range instances {
		userSet[inst.UserID] = struct{}{}
		templateSet[inst.ScheduleTemplateID] = struct{}{}
	}
	stats.TotalUsers = int64(len(userSet))
	stats.TotalTemplates = int64(len(templateSet))

	// --- Pass 2: fetch each unique template exactly once ---
	templates := make(map[uuid.UUID]*models.ScheduleTemplate, len(templateSet))
	for tplID := range templateSet {
		tmpl, err := qs.schedulingRepo.GetScheduleTemplate(ctx, tplID)
		if err != nil || tmpl == nil {
			qs.logger.Warn("Failed to load schedule template for stats",
				zap.String("template_id", tplID.String()),
				zap.Error(err))
			continue
		}
		templates[tplID] = tmpl
	}

	// --- Pass 3: aggregate ---
	for _, inst := range instances {
		if tmpl, ok := templates[inst.ScheduleTemplateID]; ok {
			stats.ByTemplateType[tmpl.TemplateType]++
		}
		stats.ByDate[inst.ScheduleDate.Format("2006-01-02")]++
		if inst.WorkCenterCode != nil {
			stats.ByWorkCenter[*inst.WorkCenterCode]++
		}
	}

	// --- Pass 4: UpcomingSchedules — the next N instances by date ---
	// Only include instances at or after "now" in the queried window.
	now := time.Now().UTC()
	upcoming := make([]*models.ScheduleInstance, 0, len(instances))
	for _, inst := range instances {
		if inst.ScheduleDate.Before(now) {
			continue
		}
		if inst.Status != "" && inst.Status != "active" {
			continue
		}
		upcoming = append(upcoming, inst)
	}
	sort.Slice(upcoming, func(i, j int) bool {
		return upcoming[i].ScheduleDate.Before(upcoming[j].ScheduleDate)
	})
	if len(upcoming) > maxUpcomingSchedules {
		upcoming = upcoming[:maxUpcomingSchedules]
	}
	for _, inst := range upcoming {
		summary := ScheduleInstanceSummary{
			InstanceID:    inst.ScheduleInstanceID,
			UserID:        inst.UserID,
			ScheduleDate:  inst.ScheduleDate,
			ExpectedStart: inst.ExpectedStart,
			ExpectedEnd:   inst.ExpectedEnd,
		}
		if tmpl, ok := templates[inst.ScheduleTemplateID]; ok {
			summary.TemplateName = tmpl.Name
			summary.TemplateType = tmpl.TemplateType
		}
		if inst.WorkCenterCode != nil {
			summary.WorkCenterCode = *inst.WorkCenterCode
		}
		stats.UpcomingSchedules = append(stats.UpcomingSchedules, summary)
	}

	return stats, nil
}

// ---- Health ----

func (qs *schedulingQueryServiceImpl) HealthCheck(ctx context.Context) error {
	return qs.schedulingRepo.HealthCheck(ctx)
}