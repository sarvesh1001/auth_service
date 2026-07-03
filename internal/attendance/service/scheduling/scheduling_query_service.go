package scheduling

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/attendance/service/resolver"
)

// SchedulingQueryService defines query operations.
type SchedulingQueryService interface {
	// Work Calendars
	GetWorkCalendarByID(ctx context.Context, calendarID uuid.UUID) (*models.WorkCalendar, error)
	GetWorkCalendarsByCompany(ctx context.Context, companyID uuid.UUID) ([]*models.WorkCalendar, error)
	GetWorkCalendarAvailability(ctx context.Context, calendarID uuid.UUID, startDate, endDate time.Time) ([]CalendarAvailability, error)

	// Schedule Templates
	GetScheduleTemplateByID(ctx context.Context, templateID uuid.UUID) (*models.ScheduleTemplate, error)
	GetScheduleTemplatesByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.ScheduleTemplate, error)
	GetScheduleTemplatesByCalendar(ctx context.Context, calendarID uuid.UUID) ([]*models.ScheduleTemplate, error)

	// Schedule Instances
	GetScheduleInstanceByID(ctx context.Context, instanceID uuid.UUID) (*models.ScheduleInstance, error)
	GetScheduleInstancesByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*models.ScheduleInstance, error)
	GetScheduleInstancesByCompany(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]*models.ScheduleInstance, error)
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
	GetScheduleStats(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) (*ScheduleStats, error)

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

func (qs *schedulingQueryServiceImpl) GetWorkCalendarsByCompany(ctx context.Context, companyID uuid.UUID) ([]*models.WorkCalendar, error) {
	return qs.schedulingRepo.GetWorkCalendarsByCompany(ctx, companyID)
}

func (qs *schedulingQueryServiceImpl) GetWorkCalendarAvailability(ctx context.Context, calendarID uuid.UUID, startDate, endDate time.Time) ([]CalendarAvailability, error) {
	cal, err := qs.schedulingRepo.GetWorkCalendarByID(ctx, calendarID)
	if err != nil {
		return nil, err
	}
	// Build holiday map (holidays are stored as JSONB, but we treat them as map)
	holidayMap := make(map[string]string)
	for _, h := range cal.Holidays {
		// h is interface{} from JSON unmarshaling; we need to assert it to a map
		if holidayMap, ok := h.(map[string]interface{}); ok {
			if date, ok := holidayMap["date"].(string); ok {
				if name, ok := holidayMap["name"].(string); ok {
					holidayMap[date] = name
				}
			}
		}
	}
	var avail []CalendarAvailability
	for d := startDate; !d.After(endDate); d = d.AddDate(0, 0, 1) {
		dateStr := d.Format("2006-01-02")
		isWorking := false
		for _, wd := range cal.WorkingDays {
			if int(d.Weekday()) == wd {
				isWorking = true
				break
			}
		}
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

func (qs *schedulingQueryServiceImpl) GetScheduleTemplatesByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.ScheduleTemplate, error) {
	return qs.schedulingRepo.GetScheduleTemplatesByCompany(ctx, companyID, activeOnly)
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

func (qs *schedulingQueryServiceImpl) GetScheduleInstancesByCompany(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]*models.ScheduleInstance, error) {
	return qs.schedulingRepo.GetScheduleInstancesByCompany(ctx, companyID, startDate, endDate)
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

func (qs *schedulingQueryServiceImpl) GetScheduleStats(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) (*ScheduleStats, error) {
	stats := &ScheduleStats{
		ByTemplateType: make(map[string]int64),
		ByDate:         make(map[string]int64),
		ByWorkCenter:   make(map[string]int64),
	}
	instances, err := qs.schedulingRepo.GetScheduleInstancesByCompany(ctx, companyID, startDate, endDate)
	if err != nil {
		return nil, err
	}
	stats.TotalInstances = int64(len(instances))
	userMap := make(map[uuid.UUID]bool)
	templateMap := make(map[uuid.UUID]bool)
	for _, inst := range instances {
		userMap[inst.UserID] = true
		templateMap[inst.ScheduleTemplateID] = true
		tmpl, err := qs.schedulingRepo.GetScheduleTemplate(ctx, inst.ScheduleTemplateID)
		if err == nil && tmpl != nil {
			stats.ByTemplateType[tmpl.TemplateType]++
		}
		dateStr := inst.ScheduleDate.Format("2006-01-02")
		stats.ByDate[dateStr]++
		if inst.WorkCenterCode != nil {
			stats.ByWorkCenter[*inst.WorkCenterCode]++
		}
	}
	stats.TotalUsers = int64(len(userMap))
	stats.TotalTemplates = int64(len(templateMap))
	return stats, nil
}

// ---- Health ----

func (qs *schedulingQueryServiceImpl) HealthCheck(ctx context.Context) error {
	return qs.schedulingRepo.HealthCheck(ctx)
}
