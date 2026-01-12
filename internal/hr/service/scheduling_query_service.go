// service/scheduling_query_service.go
package service

import (
	"auth-service/internal/hr/models/scheduling"
	"auth-service/internal/hr/repository"
	"auth-service/internal/util"
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ============================================================================
// QUERY SERVICE TYPES
// ============================================================================

// ScheduleSearchFilters provides filtering options for schedule searches
type ScheduleSearchFilters struct {
	UserID              *uuid.UUID
	UserIDs             []uuid.UUID
	CompanyID           *uuid.UUID
	ScheduleTemplateID  *uuid.UUID
	ScheduleTemplateIDs []uuid.UUID
	StartDate           *time.Time
	EndDate             *time.Time
	HasExpectedTimes    *bool
	Timezone            *string
}

// ScheduleStats represents scheduling statistics
type ScheduleStats struct {
	TotalInstances    int64                     `json:"total_instances"`
	TotalUsers        int64                     `json:"total_users"`
	TotalTemplates    int64                     `json:"total_templates"`
	ByTemplateType    map[string]int64          `json:"by_template_type"`
	ByDate            map[string]int64          `json:"by_date"` // date -> count
	UpcomingSchedules []ScheduleInstanceSummary `json:"upcoming_schedules"`
	MostActiveUsers   []UserScheduleActivity    `json:"most_active_users"`
}

// ScheduleInstanceSummary represents a summary of a schedule instance
type ScheduleInstanceSummary struct {
	InstanceID    uuid.UUID  `json:"instance_id"`
	UserID        uuid.UUID  `json:"user_id"`
	UserName      string     `json:"user_name,omitempty"`
	ScheduleDate  time.Time  `json:"schedule_date"`
	ExpectedStart *time.Time `json:"expected_start,omitempty"`
	ExpectedEnd   *time.Time `json:"expected_end,omitempty"`
	TemplateName  string     `json:"template_name"`
	TemplateType  string     `json:"template_type"`
}

// UserScheduleActivity represents user scheduling activity
type UserScheduleActivity struct {
	UserID             uuid.UUID  `json:"user_id"`
	UserName           string     `json:"user_name,omitempty"`
	TotalScheduledDays int64      `json:"total_scheduled_days"`
	UpcomingSchedules  int64      `json:"upcoming_schedules"`
	LastScheduledDate  *time.Time `json:"last_scheduled_date,omitempty"`
}

// CalendarAvailability represents availability on a calendar
type CalendarAvailability struct {
	Date           time.Time   `json:"date"`
	IsWorkingDay   bool        `json:"is_working_day"`
	IsHoliday      bool        `json:"is_holiday"`
	HolidayName    string      `json:"holiday_name,omitempty"`
	ScheduledUsers []uuid.UUID `json:"scheduled_users,omitempty"`
}

// ============================================================================
// QUERY SERVICE INTERFACE
// ============================================================================

// SchedulingQueryService defines read-only scheduling operations
type SchedulingQueryService interface {
	// Work Calendar Queries
	GetWorkCalendarByID(ctx context.Context, calendarID uuid.UUID) (*scheduling.WorkCalendar, error)
	GetWorkCalendarsByCompany(ctx context.Context, companyID uuid.UUID) ([]*scheduling.WorkCalendar, error)
	GetWorkCalendarAvailability(ctx context.Context, calendarID uuid.UUID, startDate, endDate time.Time) ([]CalendarAvailability, error)

	// Schedule Template Queries
	GetScheduleTemplateByID(ctx context.Context, templateID uuid.UUID) (*scheduling.ScheduleTemplate, error)
	GetScheduleTemplatesByCompany(ctx context.Context, companyID uuid.UUID) ([]*scheduling.ScheduleTemplate, error)
	GetScheduleTemplatesByCalendar(ctx context.Context, calendarID uuid.UUID) ([]*scheduling.ScheduleTemplate, error)
	GetActiveTemplatesByType(ctx context.Context, companyID uuid.UUID, templateType string) ([]*scheduling.ScheduleTemplate, error)

	// User Schedule Assignment Queries
	GetUserScheduleAssignment(ctx context.Context, userID, templateID uuid.UUID, effectiveFrom time.Time) (*scheduling.UserScheduleAssignment, error)
	GetUserCurrentScheduleAssignment(ctx context.Context, userID uuid.UUID, date time.Time) (*scheduling.UserScheduleAssignment, error)
	GetUserScheduleAssignments(ctx context.Context, userID uuid.UUID, startDate, endDate *time.Time) ([]*scheduling.UserScheduleAssignment, error)
	GetAssignmentsByTemplate(ctx context.Context, templateID uuid.UUID, activeOnly bool) ([]*scheduling.UserScheduleAssignment, error)

	// Schedule Instance Queries
	GetScheduleInstanceByID(ctx context.Context, instanceID uuid.UUID) (*scheduling.ScheduleInstance, error)
	GetScheduleInstanceByUserDate(ctx context.Context, userID uuid.UUID, date time.Time) (*scheduling.ScheduleInstance, error)
	GetScheduleInstancesByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*scheduling.ScheduleInstance, error)
	GetScheduleInstancesByCompany(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]*scheduling.ScheduleInstance, error)
	GetScheduleInstancesByTemplate(ctx context.Context, templateID uuid.UUID, startDate, endDate time.Time) ([]*scheduling.ScheduleInstance, error)
	SearchScheduleInstances(ctx context.Context, filters ScheduleSearchFilters, page, pageSize int) ([]*scheduling.ScheduleInstance, int, error)
	GetOffEntitlementByID(ctx context.Context, entitlementID uuid.UUID) (*scheduling.UserOffEntitlement, error)
	GetOffEntitlementsByUser(ctx context.Context, userID uuid.UUID, activeOnly bool) ([]*scheduling.UserOffEntitlement, error)
	GetOffEntitlementsByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*scheduling.UserOffEntitlement, error)
	GetUserOffBalance(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error)

	// Off Requests
	GetOffRequestByID(ctx context.Context, requestID uuid.UUID) (*scheduling.OffRequest, error)
	GetOffRequestsByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time, status *string) ([]*scheduling.OffRequest, error)
	GetOffRequestsByCompany(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time, status *string) ([]*scheduling.OffRequest, error)
	GetPendingOffRequests(ctx context.Context, companyID uuid.UUID) ([]*scheduling.OffRequest, error)

	// Schedule Overrides
	GetScheduleOverrideByID(ctx context.Context, overrideID uuid.UUID) (*scheduling.ScheduleOverride, error)
	GetScheduleOverridesByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time, overrideType *string) ([]*scheduling.ScheduleOverride, error)
	GetScheduleOverridesByCompany(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time, overrideType *string) ([]*scheduling.ScheduleOverride, error)
	GetScheduleOverrideByUserDate(ctx context.Context, userID uuid.UUID, date time.Time) (*scheduling.ScheduleOverride, error)

	// Combined Queries
	GetUserTimeOffSummary(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error)
	GetCompanyTimeOffStats(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error)
	CheckDateAvailability(ctx context.Context, userID uuid.UUID, date time.Time) (map[string]interface{}, error)
	// Analytics and Reporting
	GetScheduleStats(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) (*ScheduleStats, error)
	GetScheduleCoverage(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error)
	GetUserScheduleSummary(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error)
	GetTemplateUtilization(ctx context.Context, templateID uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error)

	// Health Check
	HealthCheck(ctx context.Context) error
}

// ============================================================================
// QUERY SERVICE IMPLEMENTATION
// ============================================================================

type schedulingQueryServiceImpl struct {
	schedulingRepo repository.SchedulingRepository
	logger         *zap.Logger
}

// NewSchedulingQueryService creates a new scheduling query service
func NewSchedulingQueryService(
	schedulingRepo repository.SchedulingRepository,
	logger *zap.Logger,
) SchedulingQueryService {
	return &schedulingQueryServiceImpl{
		schedulingRepo: schedulingRepo,
		logger:         logger,
	}
}

// ============================================================================
// WORK CALENDAR QUERIES
// ============================================================================

func (qs *schedulingQueryServiceImpl) GetWorkCalendarByID(
	ctx context.Context,
	calendarID uuid.UUID,
) (*scheduling.WorkCalendar, error) {
	startTime := time.Now()

	calendar, err := qs.schedulingRepo.GetWorkCalendarByID(ctx, calendarID)
	if err != nil {
		return nil, fmt.Errorf("failed to get work calendar: %w", err)
	}

	qs.logger.Debug("Work calendar retrieved by ID",
		util.String("calendar_id", calendarID.String()),
		util.Duration("duration", time.Since(startTime)))

	return calendar, nil
}

func (qs *schedulingQueryServiceImpl) GetWorkCalendarsByCompany(
	ctx context.Context,
	companyID uuid.UUID,
) ([]*scheduling.WorkCalendar, error) {
	startTime := time.Now()

	calendars, err := qs.schedulingRepo.GetWorkCalendarsByCompany(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get work calendars by company: %w", err)
	}

	qs.logger.Debug("Work calendars retrieved by company",
		util.String("company_id", companyID.String()),
		util.Int("calendar_count", len(calendars)),
		util.Duration("duration", time.Since(startTime)))

	return calendars, nil
}
func (qs *schedulingQueryServiceImpl) GetWorkCalendarAvailability(
	ctx context.Context,
	calendarID uuid.UUID,
	startDate, endDate time.Time,
) ([]CalendarAvailability, error) {
	startTime := time.Now()

	calendar, err := qs.schedulingRepo.GetWorkCalendarByID(ctx, calendarID)
	if err != nil {
		return nil, fmt.Errorf("failed to get work calendar: %w", err)
	}

	// Enforce calendar year
	if startDate.Year() != calendar.Year || endDate.Year() != calendar.Year {
		return nil, fmt.Errorf(
			"date range must be within calendar year %d",
			calendar.Year,
		)
	}

	calendarDays := int(endDate.Sub(startDate).Hours()/24) + 1
	if calendarDays > 365 {
		return nil, fmt.Errorf("date range cannot exceed 365 days, got %d days", calendarDays)
	}

	holidayMap := make(map[string]scheduling.Holiday)
	for _, holiday := range calendar.Holidays {
		holidayMap[holiday.Date] = holiday
	}

	var availability []CalendarAvailability

	for currentDate := startDate; !currentDate.After(endDate); currentDate = currentDate.AddDate(0, 0, 1) {
		dateStr := currentDate.Format("2006-01-02")
		weekday := int(currentDate.Weekday())

		isWorkingDay := false
		for _, day := range calendar.WorkingDays {
			if day == weekday {
				isWorkingDay = true
				break
			}
		}

		holiday, isHoliday := holidayMap[dateStr]

		availability = append(availability, CalendarAvailability{
			Date:         currentDate,
			IsWorkingDay: isWorkingDay,
			IsHoliday:    isHoliday,
			HolidayName:  holiday.Name,
		})
	}

	qs.logger.Debug("Work calendar availability retrieved",
		util.String("calendar_id", calendarID.String()),
		util.Int("year", calendar.Year),
		util.Duration("duration", time.Since(startTime)),
	)

	return availability, nil
}

// ============================================================================
// SCHEDULE TEMPLATE QUERIES
// ============================================================================

func (qs *schedulingQueryServiceImpl) GetScheduleTemplateByID(
	ctx context.Context,
	templateID uuid.UUID,
) (*scheduling.ScheduleTemplate, error) {
	startTime := time.Now()

	template, err := qs.schedulingRepo.GetScheduleTemplateByID(ctx, templateID)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule template: %w", err)
	}

	qs.logger.Debug("Schedule template retrieved by ID",
		util.String("template_id", templateID.String()),
		util.Duration("duration", time.Since(startTime)))

	return template, nil
}

func (qs *schedulingQueryServiceImpl) GetScheduleTemplatesByCompany(
	ctx context.Context,
	companyID uuid.UUID,
) ([]*scheduling.ScheduleTemplate, error) {
	startTime := time.Now()

	templates, err := qs.schedulingRepo.GetScheduleTemplatesByCompany(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule templates by company: %w", err)
	}

	qs.logger.Debug("Schedule templates retrieved by company",
		util.String("company_id", companyID.String()),
		util.Int("template_count", len(templates)),
		util.Duration("duration", time.Since(startTime)))

	return templates, nil
}

func (qs *schedulingQueryServiceImpl) GetScheduleTemplatesByCalendar(
	ctx context.Context,
	calendarID uuid.UUID,
) ([]*scheduling.ScheduleTemplate, error) {
	startTime := time.Now()

	templates, err := qs.schedulingRepo.GetScheduleTemplatesByCalendar(ctx, calendarID)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule templates by calendar: %w", err)
	}

	qs.logger.Debug("Schedule templates retrieved by calendar",
		util.String("calendar_id", calendarID.String()),
		util.Int("template_count", len(templates)),
		util.Duration("duration", time.Since(startTime)))

	return templates, nil
}

func (qs *schedulingQueryServiceImpl) GetActiveTemplatesByType(
	ctx context.Context,
	companyID uuid.UUID,
	templateType string,
) ([]*scheduling.ScheduleTemplate, error) {
	startTime := time.Now()

	templates, err := qs.schedulingRepo.GetActiveTemplatesByType(ctx, companyID, templateType)
	if err != nil {
		return nil, fmt.Errorf("failed to get active templates by type: %w", err)
	}

	qs.logger.Debug("Active schedule templates retrieved by type",
		util.String("company_id", companyID.String()),
		util.String("template_type", templateType),
		util.Int("template_count", len(templates)),
		util.Duration("duration", time.Since(startTime)))

	return templates, nil
}

// ============================================================================
// USER SCHEDULE ASSIGNMENT QUERIES
// ============================================================================

func (qs *schedulingQueryServiceImpl) GetUserScheduleAssignment(
	ctx context.Context,
	userID, templateID uuid.UUID,
	effectiveFrom time.Time,
) (*scheduling.UserScheduleAssignment, error) {
	startTime := time.Now()

	assignment, err := qs.schedulingRepo.GetUserScheduleAssignment(ctx, userID, templateID, effectiveFrom)
	if err != nil {
		return nil, fmt.Errorf("failed to get user schedule assignment: %w", err)
	}

	qs.logger.Debug("User schedule assignment retrieved",
		util.String("user_id", userID.String()),
		util.String("template_id", templateID.String()),
		util.Time("effective_from", effectiveFrom),
		util.Duration("duration", time.Since(startTime)))

	return assignment, nil
}

func (qs *schedulingQueryServiceImpl) GetUserCurrentScheduleAssignment(
	ctx context.Context,
	userID uuid.UUID,
	date time.Time,
) (*scheduling.UserScheduleAssignment, error) {
	startTime := time.Now()

	if date.IsZero() {
		date = time.Now().UTC()
	}

	assignment, err := qs.schedulingRepo.GetUserCurrentScheduleAssignment(ctx, userID, date)
	if err != nil {
		return nil, fmt.Errorf("failed to get user current schedule assignment: %w", err)
	}

	qs.logger.Debug("User current schedule assignment retrieved",
		util.String("user_id", userID.String()),
		util.Time("date", date),
		util.Duration("duration", time.Since(startTime)))

	return assignment, nil
}

func (qs *schedulingQueryServiceImpl) GetUserScheduleAssignments(
	ctx context.Context,
	userID uuid.UUID,
	startDate, endDate *time.Time,
) ([]*scheduling.UserScheduleAssignment, error) {
	startTime := time.Now()

	assignments, err := qs.schedulingRepo.GetUserScheduleAssignments(ctx, userID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get user schedule assignments: %w", err)
	}

	qs.logger.Debug("User schedule assignments retrieved",
		util.String("user_id", userID.String()),
		util.Int("assignment_count", len(assignments)),
		util.Duration("duration", time.Since(startTime)))

	return assignments, nil
}

func (qs *schedulingQueryServiceImpl) GetAssignmentsByTemplate(
	ctx context.Context,
	templateID uuid.UUID,
	activeOnly bool,
) ([]*scheduling.UserScheduleAssignment, error) {
	startTime := time.Now()

	assignments, err := qs.schedulingRepo.GetAssignmentsByTemplate(ctx, templateID, activeOnly)
	if err != nil {
		return nil, fmt.Errorf("failed to get assignments by template: %w", err)
	}

	qs.logger.Debug("Assignments retrieved by template",
		util.String("template_id", templateID.String()),
		util.Bool("active_only", activeOnly),
		util.Int("assignment_count", len(assignments)),
		util.Duration("duration", time.Since(startTime)))

	return assignments, nil
}

// ============================================================================
// SCHEDULE INSTANCE QUERIES
// ============================================================================

func (qs *schedulingQueryServiceImpl) GetScheduleInstanceByID(
	ctx context.Context,
	instanceID uuid.UUID,
) (*scheduling.ScheduleInstance, error) {
	startTime := time.Now()

	instance, err := qs.schedulingRepo.GetScheduleInstanceByID(ctx, instanceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule instance: %w", err)
	}

	qs.logger.Debug("Schedule instance retrieved by ID",
		util.String("instance_id", instanceID.String()),
		util.Duration("duration", time.Since(startTime)))

	return instance, nil
}

func (qs *schedulingQueryServiceImpl) GetScheduleInstanceByUserDate(
	ctx context.Context,
	userID uuid.UUID,
	date time.Time,
) (*scheduling.ScheduleInstance, error) {
	startTime := time.Now()

	instance, err := qs.schedulingRepo.GetScheduleInstanceByUserDate(ctx, userID, date)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule instance by user date: %w", err)
	}

	qs.logger.Debug("Schedule instance retrieved by user and date",
		util.String("user_id", userID.String()),
		util.String("date", date.Format("2006-01-02")),
		util.Duration("duration", time.Since(startTime)))

	return instance, nil
}

func (qs *schedulingQueryServiceImpl) GetScheduleInstancesByUser(
	ctx context.Context,
	userID uuid.UUID,
	startDate, endDate time.Time,
) ([]*scheduling.ScheduleInstance, error) {
	startTime := time.Now()

	// Validate date range
	calendarDays := int(endDate.Sub(startDate).Hours()/24) + 1
	if calendarDays > 90 {
		return nil, fmt.Errorf("date range cannot exceed 90 days, got %d days", calendarDays)
	}

	instances, err := qs.schedulingRepo.GetScheduleInstancesByUser(ctx, userID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule instances by user: %w", err)
	}

	qs.logger.Debug("Schedule instances retrieved by user",
		util.String("user_id", userID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("calendar_days", calendarDays),
		util.Int("instance_count", len(instances)),
		util.Duration("duration", time.Since(startTime)))

	return instances, nil
}

func (qs *schedulingQueryServiceImpl) GetScheduleInstancesByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) ([]*scheduling.ScheduleInstance, error) {
	startTime := time.Now()

	// Validate date range
	calendarDays := int(endDate.Sub(startDate).Hours()/24) + 1
	if calendarDays > 31 {
		return nil, fmt.Errorf("date range cannot exceed 31 days for company queries, got %d days", calendarDays)
	}

	instances, err := qs.schedulingRepo.GetScheduleInstancesByCompany(ctx, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule instances by company: %w", err)
	}

	qs.logger.Debug("Schedule instances retrieved by company",
		util.String("company_id", companyID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("calendar_days", calendarDays),
		util.Int("instance_count", len(instances)),
		util.Duration("duration", time.Since(startTime)))

	return instances, nil
}

func (qs *schedulingQueryServiceImpl) GetScheduleInstancesByTemplate(
	ctx context.Context,
	templateID uuid.UUID,
	startDate, endDate time.Time,
) ([]*scheduling.ScheduleInstance, error) {
	startTime := time.Now()

	// Validate date range
	calendarDays := int(endDate.Sub(startDate).Hours()/24) + 1
	if calendarDays > 90 {
		return nil, fmt.Errorf("date range cannot exceed 90 days, got %d days", calendarDays)
	}

	instances, err := qs.schedulingRepo.GetScheduleInstancesByTemplate(ctx, templateID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule instances by template: %w", err)
	}

	qs.logger.Debug("Schedule instances retrieved by template",
		util.String("template_id", templateID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("calendar_days", calendarDays),
		util.Int("instance_count", len(instances)),
		util.Duration("duration", time.Since(startTime)))

	return instances, nil
}

func (qs *schedulingQueryServiceImpl) SearchScheduleInstances(
	ctx context.Context,
	filters ScheduleSearchFilters,
	page, pageSize int,
) ([]*scheduling.ScheduleInstance, int, error) {
	startTime := time.Now()

	// Validate pagination parameters
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}

	// Convert filters to repository format
	repoFilters := make(map[string]interface{})

	if filters.UserID != nil {
		repoFilters["user_id"] = *filters.UserID
	}

	if len(filters.UserIDs) > 0 {
		repoFilters["user_ids"] = filters.UserIDs
	}

	if filters.CompanyID != nil {
		repoFilters["company_id"] = *filters.CompanyID
	}

	if filters.ScheduleTemplateID != nil {
		repoFilters["schedule_template_id"] = *filters.ScheduleTemplateID
	}

	if len(filters.ScheduleTemplateIDs) > 0 {
		repoFilters["schedule_template_ids"] = filters.ScheduleTemplateIDs
	}

	if filters.StartDate != nil {
		repoFilters["start_date"] = *filters.StartDate
	}

	if filters.EndDate != nil {
		repoFilters["end_date"] = *filters.EndDate
	}

	if filters.Timezone != nil {
		repoFilters["timezone"] = *filters.Timezone
	}

	// TODO: Implement repository search method
	// For now, return empty results
	instances := []*scheduling.ScheduleInstance{}
	totalCount := 0

	qs.logger.Debug("Schedule instances searched",
		util.Int("filter_count", len(repoFilters)),
		util.Int("page", page),
		util.Int("pageSize", pageSize),
		util.Int("total_count", totalCount),
		util.Int("returned_count", len(instances)),
		util.Duration("duration", time.Since(startTime)))

	return instances, totalCount, nil
}

// ============================================================================
// ANALYTICS AND REPORTING
// ============================================================================

func (qs *schedulingQueryServiceImpl) GetScheduleStats(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) (*ScheduleStats, error) {
	startTime := time.Now()

	// Validate date range
	calendarDays := int(endDate.Sub(startDate).Hours()/24) + 1
	if calendarDays > 365 {
		return nil, fmt.Errorf("date range cannot exceed 365 days for statistics, got %d days", calendarDays)
	}

	// Get schedule coverage data
	coverage, err := qs.schedulingRepo.GetScheduleCoverage(ctx, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule coverage: %w", err)
	}

	// Convert to ScheduleStats
	stats := &ScheduleStats{
		ByTemplateType: make(map[string]int64),
		ByDate:         make(map[string]int64),
	}

	// Extract data from coverage
	if totalInstances, ok := coverage["total_scheduled_days"].(int); ok {
		stats.TotalInstances = int64(totalInstances)
	}

	if totalUsers, ok := coverage["total_scheduled_users"].(int); ok {
		stats.TotalUsers = int64(totalUsers)
	}

	if templateDist, ok := coverage["template_distribution"].(map[string]int); ok {
		for templateType, count := range templateDist {
			stats.ByTemplateType[templateType] = int64(count)
		}
	}

	// Get upcoming schedules (next 7 days)
	today := time.Now().UTC()
	weekFromNow := today.AddDate(0, 0, 7)

	upcomingInstances, err := qs.schedulingRepo.GetScheduleInstancesByCompany(ctx, companyID, today, weekFromNow)
	if err == nil && len(upcomingInstances) > 0 {
		// Convert to summary format
		for _, instance := range upcomingInstances {
			template, _ := qs.schedulingRepo.GetScheduleTemplateByID(ctx, instance.ScheduleTemplateID)
			templateName := ""
			templateType := ""
			if template != nil {
				templateName = template.Name
				templateType = template.TemplateType
			}

			summary := ScheduleInstanceSummary{
				InstanceID:    instance.ScheduleInstanceID,
				UserID:        instance.UserID,
				ScheduleDate:  instance.ScheduleDate,
				ExpectedStart: instance.ExpectedStart,
				ExpectedEnd:   instance.ExpectedEnd,
				TemplateName:  templateName,
				TemplateType:  templateType,
			}

			// Limit to 10 upcoming schedules
			if len(stats.UpcomingSchedules) < 10 {
				stats.UpcomingSchedules = append(stats.UpcomingSchedules, summary)
			}
		}
	}

	// Get total templates
	templates, err := qs.schedulingRepo.GetScheduleTemplatesByCompany(ctx, companyID)
	if err == nil {
		stats.TotalTemplates = int64(len(templates))
	}

	qs.logger.Debug("Schedule statistics retrieved",
		util.String("company_id", companyID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("calendar_days", calendarDays),
		util.Duration("duration", time.Since(startTime)))

	return stats, nil
}

func (qs *schedulingQueryServiceImpl) GetScheduleCoverage(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) (map[string]interface{}, error) {
	startTime := time.Now()

	// Validate date range
	calendarDays := int(endDate.Sub(startDate).Hours()/24) + 1
	if calendarDays > 31 {
		return nil, fmt.Errorf("date range cannot exceed 31 days for coverage report, got %d days", calendarDays)
	}

	coverage, err := qs.schedulingRepo.GetScheduleCoverage(ctx, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule coverage: %w", err)
	}

	qs.logger.Debug("Schedule coverage retrieved",
		util.String("company_id", companyID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("calendar_days", calendarDays),
		util.Duration("duration", time.Since(startTime)))

	return coverage, nil
}

func (qs *schedulingQueryServiceImpl) GetUserScheduleSummary(
	ctx context.Context,
	userID uuid.UUID,
	startDate, endDate time.Time,
) (map[string]interface{}, error) {
	startTime := time.Now()

	// Validate date range
	calendarDays := int(endDate.Sub(startDate).Hours()/24) + 1
	if calendarDays > 90 {
		return nil, fmt.Errorf("date range cannot exceed 90 days, got %d days", calendarDays)
	}

	summary, err := qs.schedulingRepo.GetUserScheduleSummary(ctx, userID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get user schedule summary: %w", err)
	}

	qs.logger.Debug("User schedule summary retrieved",
		util.String("user_id", userID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("calendar_days", calendarDays),
		util.Duration("duration", time.Since(startTime)))

	return summary, nil
}

func (qs *schedulingQueryServiceImpl) GetTemplateUtilization(
	ctx context.Context,
	templateID uuid.UUID,
	startDate, endDate time.Time,
) (map[string]interface{}, error) {
	startTime := time.Now()

	// Validate date range
	calendarDays := int(endDate.Sub(startDate).Hours()/24) + 1
	if calendarDays > 90 {
		return nil, fmt.Errorf("date range cannot exceed 90 days, got %d days", calendarDays)
	}

	utilization, err := qs.schedulingRepo.GetTemplateUtilization(ctx, templateID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get template utilization: %w", err)
	}

	qs.logger.Debug("Template utilization retrieved",
		util.String("template_id", templateID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("calendar_days", calendarDays),
		util.Duration("duration", time.Since(startTime)))

	return utilization, nil
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

func (qs *schedulingQueryServiceImpl) HealthCheck(ctx context.Context) error {
	if err := qs.schedulingRepo.HealthCheck(ctx); err != nil {
		return fmt.Errorf("scheduling repository health check failed: %w", err)
	}
	return nil
}

// Off Entitlement Query Methods
func (qs *schedulingQueryServiceImpl) GetOffEntitlementByID(
	ctx context.Context,
	entitlementID uuid.UUID,
) (*scheduling.UserOffEntitlement, error) {
	startTime := time.Now()

	entitlement, err := qs.schedulingRepo.GetOffEntitlementByID(ctx, entitlementID)
	if err != nil {
		return nil, fmt.Errorf("failed to get off entitlement: %w", err)
	}

	qs.logger.Debug("Off entitlement retrieved by ID",
		util.String("entitlement_id", entitlementID.String()),
		util.Duration("duration", time.Since(startTime)))

	return entitlement, nil
}

func (qs *schedulingQueryServiceImpl) GetOffEntitlementsByUser(
	ctx context.Context,
	userID uuid.UUID,
	activeOnly bool,
) ([]*scheduling.UserOffEntitlement, error) {
	startTime := time.Now()

	entitlements, err := qs.schedulingRepo.GetOffEntitlementsByUser(ctx, userID, activeOnly)
	if err != nil {
		return nil, fmt.Errorf("failed to get off entitlements by user: %w", err)
	}

	qs.logger.Debug("Off entitlements retrieved by user",
		util.String("user_id", userID.String()),
		util.Bool("active_only", activeOnly),
		util.Int("entitlement_count", len(entitlements)),
		util.Duration("duration", time.Since(startTime)))

	return entitlements, nil
}

func (qs *schedulingQueryServiceImpl) GetOffEntitlementsByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	activeOnly bool,
) ([]*scheduling.UserOffEntitlement, error) {
	startTime := time.Now()

	entitlements, err := qs.schedulingRepo.GetOffEntitlementsByCompany(ctx, companyID, activeOnly)
	if err != nil {
		return nil, fmt.Errorf("failed to get off entitlements by company: %w", err)
	}

	qs.logger.Debug("Off entitlements retrieved by company",
		util.String("company_id", companyID.String()),
		util.Bool("active_only", activeOnly),
		util.Int("entitlement_count", len(entitlements)),
		util.Duration("duration", time.Since(startTime)))

	return entitlements, nil
}

func (qs *schedulingQueryServiceImpl) GetUserOffBalance(
	ctx context.Context,
	userID uuid.UUID,
	startDate, endDate time.Time,
) (map[string]interface{}, error) {
	startTime := time.Now()

	// Get current entitlement
	entitlement, err := qs.schedulingRepo.GetCurrentOffEntitlement(ctx, userID, time.Now())
	if err != nil {
		return nil, fmt.Errorf("failed to get current entitlement: %w", err)
	}

	// Get used days
	var periodType string
	if entitlement != nil {
		periodType = entitlement.PeriodType
	} else {
		periodType = "monthly" // default
	}

	usedDays, err := qs.schedulingRepo.GetOffBalance(ctx, userID, periodType, startDate, endDate)
	if err != nil {
		usedDays = 0
	}

	result := map[string]interface{}{
		"user_id":     userID,
		"start_date":  startDate.Format("2006-01-02"),
		"end_date":    endDate.Format("2006-01-02"),
		"period_type": periodType,
		"used_days":   usedDays,
	}

	if entitlement != nil {
		result["entitlement"] = entitlement
		result["total_days"] = entitlement.OffCount
		result["remaining_days"] = entitlement.OffCount - usedDays
		result["requires_approval"] = entitlement.RequiresApproval
	}

	qs.logger.Debug("User off balance retrieved",
		util.String("user_id", userID.String()),
		util.Int("used_days", usedDays),
		util.Duration("duration", time.Since(startTime)))

	return result, nil
}

// Off Request Query Methods
func (qs *schedulingQueryServiceImpl) GetOffRequestByID(
	ctx context.Context,
	requestID uuid.UUID,
) (*scheduling.OffRequest, error) {
	startTime := time.Now()

	request, err := qs.schedulingRepo.GetOffRequestByID(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("failed to get off request: %w", err)
	}

	qs.logger.Debug("Off request retrieved by ID",
		util.String("request_id", requestID.String()),
		util.Duration("duration", time.Since(startTime)))

	return request, nil
}

func (qs *schedulingQueryServiceImpl) GetOffRequestsByUser(
	ctx context.Context,
	userID uuid.UUID,
	startDate, endDate time.Time,
	status *string,
) ([]*scheduling.OffRequest, error) {
	startTime := time.Now()

	var startPtr, endPtr *time.Time
	if !startDate.IsZero() && !endDate.IsZero() {
		startPtr = &startDate
		endPtr = &endDate
	}

	requests, err := qs.schedulingRepo.GetOffRequestsByUser(ctx, userID, startPtr, endPtr, status)
	if err != nil {
		return nil, fmt.Errorf("failed to get off requests by user: %w", err)
	}

	qs.logger.Debug("Off requests retrieved by user",
		util.String("user_id", userID.String()),
		util.String("status", getStatusString(status)),
		util.Int("request_count", len(requests)),
		util.Duration("duration", time.Since(startTime)))

	return requests, nil
}

func (qs *schedulingQueryServiceImpl) GetOffRequestsByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
	status *string,
) ([]*scheduling.OffRequest, error) {
	startTime := time.Now()

	var startPtr, endPtr *time.Time
	if !startDate.IsZero() && !endDate.IsZero() {
		startPtr = &startDate
		endPtr = &endDate
	}

	requests, err := qs.schedulingRepo.GetOffRequestsByCompany(ctx, companyID, startPtr, endPtr, status)
	if err != nil {
		return nil, fmt.Errorf("failed to get off requests by company: %w", err)
	}

	qs.logger.Debug("Off requests retrieved by company",
		util.String("company_id", companyID.String()),
		util.String("status", getStatusString(status)),
		util.Int("request_count", len(requests)),
		util.Duration("duration", time.Since(startTime)))

	return requests, nil
}

func (qs *schedulingQueryServiceImpl) GetPendingOffRequests(
	ctx context.Context,
	companyID uuid.UUID,
) ([]*scheduling.OffRequest, error) {
	startTime := time.Now()

	status := "pending"
	requests, err := qs.schedulingRepo.GetOffRequestsByCompany(ctx, companyID, nil, nil, &status)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending off requests: %w", err)
	}

	qs.logger.Debug("Pending off requests retrieved",
		util.String("company_id", companyID.String()),
		util.Int("request_count", len(requests)),
		util.Duration("duration", time.Since(startTime)))

	return requests, nil
}

// Schedule Override Query Methods
func (qs *schedulingQueryServiceImpl) GetScheduleOverrideByID(
	ctx context.Context,
	overrideID uuid.UUID,
) (*scheduling.ScheduleOverride, error) {
	startTime := time.Now()

	override, err := qs.schedulingRepo.GetScheduleOverrideByID(ctx, overrideID)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule override: %w", err)
	}

	qs.logger.Debug("Schedule override retrieved by ID",
		util.String("override_id", overrideID.String()),
		util.Duration("duration", time.Since(startTime)))

	return override, nil
}

func (qs *schedulingQueryServiceImpl) GetScheduleOverridesByUser(
	ctx context.Context,
	userID uuid.UUID,
	startDate, endDate time.Time,
	overrideType *string,
) ([]*scheduling.ScheduleOverride, error) {
	startTime := time.Now()

	var startPtr, endPtr *time.Time
	if !startDate.IsZero() && !endDate.IsZero() {
		startPtr = &startDate
		endPtr = &endDate
	}

	overrides, err := qs.schedulingRepo.GetScheduleOverridesByUser(ctx, userID, startPtr, endPtr, overrideType)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule overrides by user: %w", err)
	}

	qs.logger.Debug("Schedule overrides retrieved by user",
		util.String("user_id", userID.String()),
		util.String("override_type", getOverrideTypeString(overrideType)),
		util.Int("override_count", len(overrides)),
		util.Duration("duration", time.Since(startTime)))

	return overrides, nil
}

func (qs *schedulingQueryServiceImpl) GetScheduleOverridesByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
	overrideType *string,
) ([]*scheduling.ScheduleOverride, error) {
	startTime := time.Now()

	var startPtr, endPtr *time.Time
	if !startDate.IsZero() && !endDate.IsZero() {
		startPtr = &startDate
		endPtr = &endDate
	}

	overrides, err := qs.schedulingRepo.GetScheduleOverridesByCompany(ctx, companyID, startPtr, endPtr, overrideType)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule overrides by company: %w", err)
	}

	qs.logger.Debug("Schedule overrides retrieved by company",
		util.String("company_id", companyID.String()),
		util.String("override_type", getOverrideTypeString(overrideType)),
		util.Int("override_count", len(overrides)),
		util.Duration("duration", time.Since(startTime)))

	return overrides, nil
}

func (qs *schedulingQueryServiceImpl) GetScheduleOverrideByUserDate(
	ctx context.Context,
	userID uuid.UUID,
	date time.Time,
) (*scheduling.ScheduleOverride, error) {
	startTime := time.Now()

	override, err := qs.schedulingRepo.GetScheduleOverrideByUserDate(ctx, userID, date)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule override by user date: %w", err)
	}

	qs.logger.Debug("Schedule override retrieved by user date",
		util.String("user_id", userID.String()),
		util.String("date", date.Format("2006-01-02")),
		util.Duration("duration", time.Since(startTime)))

	return override, nil
}

// Combined Query Methods
func (qs *schedulingQueryServiceImpl) GetUserTimeOffSummary(
	ctx context.Context,
	userID uuid.UUID,
	startDate, endDate time.Time,
) (map[string]interface{}, error) {
	startTime := time.Now()

	calendarDays := int(endDate.Sub(startDate).Hours()/24) + 1
	if calendarDays > 90 {
		return nil, fmt.Errorf("date range cannot exceed 90 days, got %d days", calendarDays)
	}

	// Get off entitlements
	entitlements, err := qs.schedulingRepo.GetOffEntitlementsByUser(ctx, userID, true)
	if err != nil {
		entitlements = []*scheduling.UserOffEntitlement{}
	}

	// Get off requests
	statusApproved := "approved"
	offRequests, err := qs.schedulingRepo.GetOffRequestsByUser(ctx, userID, &startDate, &endDate, &statusApproved)
	if err != nil {
		offRequests = []*scheduling.OffRequest{}
	}

	// Get pending requests
	statusPending := "pending"
	pendingRequests, err := qs.schedulingRepo.GetOffRequestsByUser(ctx, userID, &startDate, &endDate, &statusPending)
	if err != nil {
		pendingRequests = []*scheduling.OffRequest{}
	}

	// Get schedule overrides
	overrides, err := qs.schedulingRepo.GetScheduleOverridesByUser(ctx, userID, &startDate, &endDate, nil)
	if err != nil {
		overrides = []*scheduling.ScheduleOverride{}
	}

	// Calculate used days
	usedDays := 0
	for _, req := range offRequests {
		usedDays += len(req.RequestDates)
	}

	// Get total entitlement
	totalEntitlement := 0
	if len(entitlements) > 0 {
		totalEntitlement = entitlements[0].OffCount
	}

	summary := map[string]interface{}{
		"user_id":            userID,
		"start_date":         startDate.Format("2006-01-02"),
		"end_date":           endDate.Format("2006-01-02"),
		"entitlements":       entitlements,
		"off_requests":       offRequests,
		"pending_requests":   pendingRequests,
		"schedule_overrides": overrides,
		"total_entitlement":  totalEntitlement,
		"used_days":          usedDays,
		"remaining_days":     totalEntitlement - usedDays,
	}

	qs.logger.Debug("User time off summary retrieved",
		util.String("user_id", userID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("entitlement_count", len(entitlements)),
		util.Int("off_request_count", len(offRequests)),
		util.Int("pending_request_count", len(pendingRequests)),
		util.Int("override_count", len(overrides)),
		util.Duration("duration", time.Since(startTime)))

	return summary, nil
}

func (qs *schedulingQueryServiceImpl) GetCompanyTimeOffStats(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) (map[string]interface{}, error) {
	startTime := time.Now()

	calendarDays := int(endDate.Sub(startDate).Hours()/24) + 1
	if calendarDays > 31 {
		return nil, fmt.Errorf("date range cannot exceed 31 days for stats, got %d days", calendarDays)
	}

	// Get utilization stats
	stats, err := qs.schedulingRepo.GetOffUtilizationStats(ctx, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get off utilization stats: %w", err)
	}

	// Get pending requests count
	pendingRequests, err := qs.GetPendingOffRequests(ctx, companyID)
	if err == nil {
		stats["pending_requests_count"] = len(pendingRequests)
	}

	// Get entitlements
	entitlements, err := qs.schedulingRepo.GetOffEntitlementsByCompany(ctx, companyID, true)
	if err == nil {
		stats["active_entitlements"] = len(entitlements)
	}

	qs.logger.Debug("Company time off stats retrieved",
		util.String("company_id", companyID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("calendar_days", calendarDays),
		util.Duration("duration", time.Since(startTime)))

	return stats, nil
}

func (qs *schedulingQueryServiceImpl) CheckDateAvailability(
	ctx context.Context,
	userID uuid.UUID,
	date time.Time,
) (map[string]interface{}, error) {
	startTime := time.Now()

	result := map[string]interface{}{
		"user_id":   userID,
		"date":      date.Format("2006-01-02"),
		"available": true,
		"reasons":   []string{},
	}

	// Check schedule override
	override, err := qs.schedulingRepo.GetScheduleOverrideByUserDate(ctx, userID, date)
	if err == nil && override != nil {
		result["available"] = false
		result["schedule_override"] = override
		reasons := result["reasons"].([]string)
		reasons = append(reasons, fmt.Sprintf("Schedule override: %s", override.OverrideType))
		result["reasons"] = reasons

		if override.OverrideType == "force_work" {
			result["available"] = true // Force work means they're available
			result["forced_work"] = true
		}
	}

	// Check off requests
	statusApproved := "approved"
	offRequests, err := qs.schedulingRepo.GetOffRequestsByUser(ctx, userID, &date, &date, &statusApproved)
	if err == nil && len(offRequests) > 0 {
		result["available"] = false
		result["off_request"] = offRequests[0]
		reasons := result["reasons"].([]string)
		reasons = append(reasons, "Approved off request")
		result["reasons"] = reasons
	}

	// Check schedule instance
	instance, err := qs.schedulingRepo.GetScheduleInstanceByUserDate(ctx, userID, date)
	if err == nil && instance != nil {
		result["schedule_instance"] = instance
		if instance.ExpectedStart != nil && instance.ExpectedEnd != nil {
			result["scheduled_hours"] = map[string]interface{}{
				"start": instance.ExpectedStart.Format("15:04"),
				"end":   instance.ExpectedEnd.Format("15:04"),
			}
		}
	}

	qs.logger.Debug("Date availability checked",
		util.String("user_id", userID.String()),
		util.String("date", date.Format("2006-01-02")),
		util.Bool("available", result["available"].(bool)),
		util.Duration("duration", time.Since(startTime)))

	return result, nil
}

// Helper functions
func getStatusString(status *string) string {
	if status != nil {
		return *status
	}
	return "all"
}

func getOverrideTypeString(overrideType *string) string {
	if overrideType != nil {
		return *overrideType
	}
	return "all"
}
