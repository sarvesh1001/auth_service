package service

import (
	"auth-service/internal/hr/models/scheduling"
	"auth-service/internal/hr/models/workcenter"
	"auth-service/internal/hr/repository"
	"auth-service/internal/util"
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

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
	PositionID          *uuid.UUID
	WorkCenterCode      *string
}

type ScheduleStats struct {
	TotalInstances    int64                     `json:"total_instances"`
	TotalUsers        int64                     `json:"total_users"`
	TotalTemplates    int64                     `json:"total_templates"`
	TotalPositions    int64                     `json:"total_positions"`
	TotalWorkCenters  int64                     `json:"total_work_centers"`
	ByTemplateType    map[string]int64          `json:"by_template_type"`
	ByDate            map[string]int64          `json:"by_date"`
	ByWorkCenter      map[string]int64          `json:"by_work_center"`
	UpcomingSchedules []ScheduleInstanceSummary `json:"upcoming_schedules"`
	MostActiveUsers   []UserScheduleActivity    `json:"most_active_users"`
}

type ScheduleInstanceSummary struct {
	InstanceID     uuid.UUID  `json:"instance_id"`
	UserID         uuid.UUID  `json:"user_id"`
	UserName       string     `json:"user_name,omitempty"`
	ScheduleDate   time.Time  `json:"schedule_date"`
	ExpectedStart  *time.Time `json:"expected_start,omitempty"`
	ExpectedEnd    *time.Time `json:"expected_end,omitempty"`
	TemplateName   string     `json:"template_name"`
	TemplateType   string     `json:"template_type"`
	PositionID     *uuid.UUID `json:"position_id,omitempty"`
	PositionTitle  string     `json:"position_title,omitempty"`
	WorkCenterCode string     `json:"work_center_code,omitempty"`
	WorkCenterName string     `json:"work_center_name,omitempty"`
}

type UserScheduleActivity struct {
	UserID             uuid.UUID  `json:"user_id"`
	UserName           string     `json:"user_name,omitempty"`
	PositionTitle      string     `json:"position_title,omitempty"`
	WorkCenterCode     string     `json:"work_center_code,omitempty"`
	TotalScheduledDays int64      `json:"total_scheduled_days"`
	UpcomingSchedules  int64      `json:"upcoming_schedules"`
	LastScheduledDate  *time.Time `json:"last_scheduled_date,omitempty"`
}

type CalendarAvailability struct {
	Date           time.Time   `json:"date"`
	IsWorkingDay   bool        `json:"is_working_day"`
	IsHoliday      bool        `json:"is_holiday"`
	HolidayName    string      `json:"holiday_name,omitempty"`
	ScheduledUsers []uuid.UUID `json:"scheduled_users,omitempty"`
}

// New: Position-based scheduling types
type PositionScheduleSummary struct {
	PositionID      uuid.UUID `json:"position_id"`
	PositionTitle   string    `json:"position_title"`
	WorkCenterCode  string    `json:"work_center_code"`
	WorkCenterName  string    `json:"work_center_name"`
	DepartmentID    uuid.UUID `json:"department_id"`
	DepartmentName  string    `json:"department_name"`
	IsSchedulable   bool      `json:"is_schedulable"`
	TotalEmployees  int64     `json:"total_employees"`
	ScheduledCount  int64     `json:"scheduled_count"`
	CoveragePercent float64   `json:"coverage_percent"`
}

type WorkCenterSchedule struct {
	WorkCenterCode string                 `json:"work_center_code"`
	WorkCenterName string                 `json:"work_center_name"`
	CurrentShift   *WorkCenterShiftDetail `json:"current_shift,omitempty"`
	TotalEmployees int64                  `json:"total_employees"`
	ScheduledToday int64                  `json:"scheduled_today"`
	Utilization    float64                `json:"utilization"`
}

type WorkCenterShiftDetail struct {
	ShiftID       uuid.UUID  `json:"shift_id"`
	ShiftName     string     `json:"shift_name"`
	TemplateType  string     `json:"template_type"`
	ExpectedStart *time.Time `json:"expected_start,omitempty"`
	ExpectedEnd   *time.Time `json:"expected_end,omitempty"`
	EffectiveFrom time.Time  `json:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty"`
}

type SchedulingQueryService interface {
	// Work Calendars
	GetWorkCalendarByID(ctx context.Context, calendarID uuid.UUID) (*scheduling.WorkCalendar, error)
	GetWorkCalendarsByCompany(ctx context.Context, companyID uuid.UUID) ([]*scheduling.WorkCalendar, error)
	GetWorkCalendarAvailability(ctx context.Context, calendarID uuid.UUID, startDate, endDate time.Time) ([]CalendarAvailability, error)

	// Work Centers
	GetWorkCenterByCode(ctx context.Context, companyID uuid.UUID, workCenterCode string) (*workcenter.WorkCenter, error)
	GetWorkCentersByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*workcenter.WorkCenter, error)
	GetWorkCenterShifts(
		ctx context.Context,
		companyID uuid.UUID,
		workCenterCode string,
		date time.Time,
	) ([]*scheduling.WorkCenterShiftMapping, error)
	GetWorkCenterSchedule(ctx context.Context, companyID uuid.UUID, workCenterCode string, date time.Time) (*WorkCenterSchedule, error)

	// Schedule Templates
	GetScheduleTemplateByID(ctx context.Context, templateID uuid.UUID) (*scheduling.ScheduleTemplate, error)
	GetScheduleTemplatesByCompany(ctx context.Context, companyID uuid.UUID) ([]*scheduling.ScheduleTemplate, error)
	GetScheduleTemplatesByCalendar(ctx context.Context, calendarID uuid.UUID) ([]*scheduling.ScheduleTemplate, error)
	GetActiveTemplatesByType(ctx context.Context, companyID uuid.UUID, templateType string) ([]*scheduling.ScheduleTemplate, error)
	// Company / Employee
	GetCompanyEmployeeByUserID(
		ctx context.Context,
		userID uuid.UUID,
	) (*scheduling.CompanyEmployee, error)

	// Position
	GetPositionByID(
		ctx context.Context,
		positionID uuid.UUID,
	) (*scheduling.Position, error)

	// User Schedule Assignments (Legacy - for backward compatibility)
	GetUserScheduleAssignment(ctx context.Context, userID, templateID uuid.UUID, effectiveFrom time.Time) (*scheduling.UserScheduleAssignment, error)
	GetUserCurrentScheduleAssignment(ctx context.Context, userID uuid.UUID, date time.Time) (*scheduling.UserScheduleAssignment, error)
	GetUserScheduleAssignments(ctx context.Context, userID uuid.UUID, startDate, endDate *time.Time) ([]*scheduling.UserScheduleAssignment, error)
	GetAssignmentsByTemplate(ctx context.Context, templateID uuid.UUID, activeOnly bool) ([]*scheduling.UserScheduleAssignment, error)

	// Schedule Instances
	GetScheduleInstanceByID(ctx context.Context, instanceID uuid.UUID) (*scheduling.ScheduleInstance, error)
	GetScheduleInstanceByUserDate(ctx context.Context, userID uuid.UUID, date time.Time) (*scheduling.ScheduleInstance, error)
	GetScheduleInstancesByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*scheduling.ScheduleInstance, error)
	GetScheduleInstancesByCompany(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]*scheduling.ScheduleInstance, error)
	GetScheduleInstancesByTemplate(ctx context.Context, templateID uuid.UUID, startDate, endDate time.Time) ([]*scheduling.ScheduleInstance, error)
	GetScheduleInstancesByPosition(ctx context.Context, positionID uuid.UUID, startDate, endDate time.Time) ([]*scheduling.ScheduleInstance, error)
	GetScheduleInstancesByWorkCenter(ctx context.Context, companyID uuid.UUID, workCenterCode string, startDate, endDate time.Time) ([]*scheduling.ScheduleInstance, error)
	SearchScheduleInstances(ctx context.Context, filters ScheduleSearchFilters, page, pageSize int) ([]*scheduling.ScheduleInstance, int, error)

	// Position-based scheduling
	GetPositionScheduleSummary(ctx context.Context, positionID uuid.UUID, startDate, endDate time.Time) (*PositionScheduleSummary, error)
	GetPositionSchedulesByCompany(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]*PositionScheduleSummary, error)
	GetWorkCenterSchedulesByCompany(ctx context.Context, companyID uuid.UUID, date time.Time) ([]*WorkCenterSchedule, error)
	GetUserScheduledPosition(ctx context.Context, userID uuid.UUID, date time.Time) (*scheduling.Position, error)
	GetUsersByPosition(ctx context.Context, positionID uuid.UUID, activeOnly bool) ([]uuid.UUID, error)

	// Schedule Overrides
	GetScheduleOverrideByID(ctx context.Context, overrideID uuid.UUID) (*scheduling.ScheduleOverride, error)
	GetScheduleOverridesByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time, overrideType *string) ([]*scheduling.ScheduleOverride, error)
	GetScheduleOverridesByCompany(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time, overrideType *string) ([]*scheduling.ScheduleOverride, error)
	GetScheduleOverrideByUserDate(ctx context.Context, userID uuid.UUID, date time.Time) (*scheduling.ScheduleOverride, error)

	// Statistics and Coverage
	GetScheduleStats(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) (*ScheduleStats, error)
	GetScheduleCoverage(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error)
	GetUserScheduleSummary(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error)
	GetTemplateUtilization(ctx context.Context, templateID uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error)
	GetPositionCoverage(ctx context.Context, positionID uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error)
	GetWorkCenterUtilization(ctx context.Context, companyID uuid.UUID, workCenterCode string, startDate, endDate time.Time) (map[string]interface{}, error)

	// Health Check
	HealthCheck(ctx context.Context) error
}

type schedulingQueryServiceImpl struct {
	schedulingRepo repository.SchedulingRepository
	logger         *zap.Logger
}

func NewSchedulingQueryService(
	schedulingRepo repository.SchedulingRepository,
	logger *zap.Logger,
) SchedulingQueryService {
	return &schedulingQueryServiceImpl{
		schedulingRepo: schedulingRepo,
		logger:         logger,
	}
}

// ==============================================
// WORK CENTERS - NEW METHODS
// ==============================================

func (qs *schedulingQueryServiceImpl) GetWorkCenterByCode(
	ctx context.Context,
	companyID uuid.UUID,
	workCenterCode string,
) (*workcenter.WorkCenter, error) {
	startTime := time.Now()

	workCenter, err := qs.schedulingRepo.GetWorkCenterByCode(ctx, companyID, workCenterCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get work center: %w", err)
	}

	qs.logger.Debug("Work center retrieved by code",
		util.String("company_id", companyID.String()),
		util.String("work_center_code", workCenterCode),
		util.Duration("duration", time.Since(startTime)))

	return workCenter, nil
}

func (qs *schedulingQueryServiceImpl) GetWorkCentersByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	activeOnly bool,
) ([]*workcenter.WorkCenter, error) {
	startTime := time.Now()

	workCenters, err := qs.schedulingRepo.GetWorkCentersByCompany(ctx, companyID, activeOnly)
	if err != nil {
		return nil, fmt.Errorf("failed to get work centers by company: %w", err)
	}

	qs.logger.Debug("Work centers retrieved by company",
		util.String("company_id", companyID.String()),
		util.Bool("active_only", activeOnly),
		util.Int("work_center_count", len(workCenters)),
		util.Duration("duration", time.Since(startTime)))

	return workCenters, nil
}

func (qs *schedulingQueryServiceImpl) GetWorkCenterShifts(
	ctx context.Context,
	companyID uuid.UUID,
	workCenterCode string,
	date time.Time,
) ([]*scheduling.WorkCenterShiftMapping, error) {

	startTime := time.Now()

	mapping, err := qs.schedulingRepo.GetWorkCenterShiftByCode(
		ctx,
		companyID,
		workCenterCode,
		date,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get work center shift: %w", err)
	}

	var shifts []*scheduling.WorkCenterShiftMapping
	if mapping != nil {
		shifts = append(shifts, mapping)
	}

	qs.logger.Debug("Work center shift retrieved",
		util.String("company_id", companyID.String()),
		util.String("work_center_code", workCenterCode),
		util.Int("shift_count", len(shifts)),
		util.Duration("duration", time.Since(startTime)),
	)

	return shifts, nil
}

// ==============================================
// POSITION-BASED SCHEDULING - NEW METHODS
// ==============================================

func (qs *schedulingQueryServiceImpl) GetWorkCenterSchedule(
	ctx context.Context,
	companyID uuid.UUID,
	workCenterCode string,
	date time.Time,
) (*WorkCenterSchedule, error) {
	startTime := time.Now()

	// 1️⃣ Get work center
	workCenter, err := qs.schedulingRepo.GetWorkCenterByCode(ctx, companyID, workCenterCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get work center: %w", err)
	}
	if workCenter == nil {
		return nil, fmt.Errorf("work center not found: %s", workCenterCode)
	}

	// 2️⃣ Normalize business date in WC timezone
	loc, err := time.LoadLocation(workCenter.Timezone)
	if err != nil {
		loc = time.UTC
	}
	businessDate := time.Date(
		date.In(loc).Year(),
		date.In(loc).Month(),
		date.In(loc).Day(),
		0, 0, 0, 0,
		loc,
	)

	// 3️⃣ Fetch active shift for the date (date <= effective_to)
	shifts, err := qs.schedulingRepo.GetWorkCenterShifts(
		ctx,
		companyID,
		workCenterCode,
		&businessDate,
		nil, // open-ended to catch active shifts
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get work center shifts: %w", err)
	}

	var currentShift *WorkCenterShiftDetail
	if len(shifts) > 0 {
		shift := shifts[0]
		template, err := qs.schedulingRepo.GetScheduleTemplateByID(ctx, shift.ShiftID)
		if err == nil && template != nil {
			currentShift = &WorkCenterShiftDetail{
				ShiftID:       shift.ShiftID,
				ShiftName:     template.Name,
				TemplateType:  template.TemplateType,
				ExpectedStart: &shift.EffectiveFrom,
				ExpectedEnd:   shift.EffectiveTo,
				EffectiveFrom: shift.EffectiveFrom,
				EffectiveTo:   shift.EffectiveTo,
			}
		}
	}

	// 4️⃣ Get positions for work center
	positions, err := qs.schedulingRepo.GetPositionsByWorkCenter(ctx, companyID, workCenterCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get positions by work center: %w", err)
	}

	totalEmployees := int64(0)
	scheduledToday := int64(0)

	for _, position := range positions {
		if !position.IsSchedulable {
			continue
		}

		users, err := qs.schedulingRepo.GetUsersByPosition(ctx, position.PositionID)
		if err != nil {
			continue
		}

		totalEmployees += int64(len(users))

		// 5️⃣ Bulk-safe check (correct date)
		for _, userID := range users {
			instance, err := qs.schedulingRepo.
				GetScheduleInstanceByUserDate(ctx, userID, businessDate)
			if err == nil && instance != nil && instance.Status == "active" {
				scheduledToday++
			}
		}
	}

	utilization := 0.0
	if totalEmployees > 0 {
		utilization = float64(scheduledToday) / float64(totalEmployees) * 100
	}

	result := &WorkCenterSchedule{
		WorkCenterCode: workCenter.WorkCenterCode,
		WorkCenterName: workCenter.Name,
		CurrentShift:   currentShift,
		TotalEmployees: totalEmployees,
		ScheduledToday: scheduledToday,
		Utilization:    utilization,
	}

	qs.logger.Debug("Work center schedule retrieved",
		util.String("company_id", companyID.String()),
		util.String("work_center_code", workCenterCode),
		util.Time("business_date", businessDate),
		util.Duration("duration", time.Since(startTime)))

	return result, nil
}
func (qs *schedulingQueryServiceImpl) GetPositionScheduleSummary(
	ctx context.Context,
	positionID uuid.UUID,
	startDate, endDate time.Time,
) (*PositionScheduleSummary, error) {
	startTime := time.Now()

	// 1️⃣ Get position
	position, err := qs.schedulingRepo.GetPositionByID(ctx, positionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get position: %w", err)
	}
	if position == nil {
		return nil, fmt.Errorf("position not found: %s", positionID.String())
	}

	// 2️⃣ Department
	var departmentName string
	if position.DepartmentID != uuid.Nil {
		dept, err := qs.schedulingRepo.GetDepartmentByID(ctx, position.DepartmentID)
		if err == nil && dept != nil {
			departmentName = dept.DepartmentName
		}
	}

	// 3️⃣ Work center
	var workCenterName string
	if position.WorkCenterCode != nil {
		wc, err := qs.schedulingRepo.GetWorkCenterByCode(
			ctx,
			position.CompanyID,
			*position.WorkCenterCode,
		)
		if err == nil && wc != nil {
			workCenterName = wc.Name
		}
	}

	// 4️⃣ Employees in position
	users, err := qs.schedulingRepo.GetUsersByPosition(ctx, positionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get users by position: %w", err)
	}

	scheduledCount := int64(0)

	// 5️⃣ Correct logic: at least ONE active day in range
	for _, userID := range users {
		instances, err := qs.schedulingRepo.
			GetScheduleInstancesByUser(ctx, userID, startDate, endDate)
		if err != nil {
			continue
		}

		for _, inst := range instances {
			if inst.Status == "active" {
				scheduledCount++
				break
			}
		}
	}

	coverage := 0.0
	if len(users) > 0 {
		coverage = float64(scheduledCount) / float64(len(users)) * 100
	}

	summary := &PositionScheduleSummary{
		PositionID:      position.PositionID,
		PositionTitle:   position.Title,
		WorkCenterCode:  util.StringPtrToString(position.WorkCenterCode),
		WorkCenterName:  workCenterName,
		DepartmentID:    position.DepartmentID,
		DepartmentName:  departmentName,
		IsSchedulable:   position.IsSchedulable,
		TotalEmployees:  int64(len(users)),
		ScheduledCount:  scheduledCount,
		CoveragePercent: coverage,
	}

	qs.logger.Debug("Position schedule summary retrieved",
		util.String("position_id", positionID.String()),
		util.Duration("duration", time.Since(startTime)))

	return summary, nil
}

func (qs *schedulingQueryServiceImpl) GetPositionSchedulesByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) ([]*PositionScheduleSummary, error) {
	startTime := time.Now()

	// Get all positions in company
	positions, err := qs.schedulingRepo.GetPositionsByCompany(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get positions by company: %w", err)
	}

	var summaries []*PositionScheduleSummary
	for _, position := range positions {
		if position.IsSchedulable {
			summary, err := qs.GetPositionScheduleSummary(ctx, position.PositionID, startDate, endDate)
			if err == nil && summary != nil {
				summaries = append(summaries, summary)
			}
		}
	}

	qs.logger.Debug("Position schedules retrieved by company",
		util.String("company_id", companyID.String()),
		util.Int("position_count", len(summaries)),
		util.Duration("duration", time.Since(startTime)))

	return summaries, nil
}

func (qs *schedulingQueryServiceImpl) GetWorkCenterSchedulesByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	date time.Time,
) ([]*WorkCenterSchedule, error) {

	startTime := time.Now()

	// 1️⃣ Get all active work centers
	workCenters, err := qs.schedulingRepo.GetWorkCentersByCompany(ctx, companyID, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get work centers: %w", err)
	}

	results := make([]*WorkCenterSchedule, 0, len(workCenters))

	for _, wc := range workCenters {

		// 2️⃣ Normalize business date using WC timezone
		loc, err := time.LoadLocation(wc.Timezone)
		if err != nil {
			loc = time.UTC
		}

		businessDate := time.Date(
			date.In(loc).Year(),
			date.In(loc).Month(),
			date.In(loc).Day(),
			0, 0, 0, 0,
			loc,
		)

		// 3️⃣ Get active shift (repo call only)
		shifts, _ := qs.schedulingRepo.GetWorkCenterShifts(
			ctx,
			companyID,
			wc.WorkCenterCode,
			&businessDate,
			nil,
		)

		var currentShift *WorkCenterShiftDetail
		if len(shifts) > 0 {
			template, err := qs.schedulingRepo.GetScheduleTemplateByID(ctx, shifts[0].ShiftID)
			if err == nil && template != nil {
				currentShift = &WorkCenterShiftDetail{
					ShiftID:       shifts[0].ShiftID,
					ShiftName:     template.Name,
					TemplateType:  template.TemplateType,
					EffectiveFrom: shifts[0].EffectiveFrom,
					EffectiveTo:   shifts[0].EffectiveTo,
					ExpectedStart: &shifts[0].EffectiveFrom,
					ExpectedEnd:   shifts[0].EffectiveTo,
				}
			}
		}

		// 4️⃣ Employees assigned to this work center
		assignments, err := qs.schedulingRepo.GetUserWorkCenterAssignments(
			ctx,
			uuid.Nil, // we want ALL users
			nil,
			nil,
		)

		var totalEmployees int64
		for _, a := range assignments {
			if a.CompanyID == companyID &&
				a.WorkCenterCode == wc.WorkCenterCode &&
				a.IsActive &&
				a.EffectiveFrom.Before(businessDate.Add(24*time.Hour)) &&
				(a.EffectiveTo == nil || a.EffectiveTo.After(businessDate)) {
				totalEmployees++
			}
		}

		// 5️⃣ Scheduled users today (repo method)
		instances, err := qs.schedulingRepo.GetScheduleInstancesByWorkCenter(
			ctx,
			companyID,
			wc.WorkCenterCode,
			businessDate,
			businessDate,
		)

		var scheduledToday int64
		if err == nil {
			userSet := make(map[uuid.UUID]struct{})
			for _, inst := range instances {
				if inst.Status == "active" {
					userSet[inst.UserID] = struct{}{}
				}
			}
			scheduledToday = int64(len(userSet))
		}

		// 6️⃣ Utilization
		utilization := 0.0
		if totalEmployees > 0 {
			utilization = float64(scheduledToday) / float64(totalEmployees) * 100
		}

		results = append(results, &WorkCenterSchedule{
			WorkCenterCode: wc.WorkCenterCode,
			WorkCenterName: wc.Name,
			CurrentShift:   currentShift,
			TotalEmployees: totalEmployees,
			ScheduledToday: scheduledToday,
			Utilization:    utilization,
		})
	}

	qs.logger.Debug(
		"Work center schedules retrieved",
		util.String("company_id", companyID.String()),
		util.Int("count", len(results)),
		util.Duration("duration", time.Since(startTime)),
	)

	return results, nil
}

func (qs *schedulingQueryServiceImpl) GetUserScheduledPosition(
	ctx context.Context,
	userID uuid.UUID,
	date time.Time,
) (*scheduling.Position, error) {
	startTime := time.Now()

	// Get employee record to find position
	employee, err := qs.schedulingRepo.GetCompanyEmployeeByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get employee record: %w", err)
	}

	if employee == nil || employee.PositionID == nil {
		return nil, nil
	}

	// Get position details
	position, err := qs.schedulingRepo.GetPositionByID(ctx, *employee.PositionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get position: %w", err)
	}

	qs.logger.Debug("User scheduled position retrieved",
		util.String("user_id", userID.String()),
		util.Time("date", date),
		util.Duration("duration", time.Since(startTime)))

	return position, nil
}

func (qs *schedulingQueryServiceImpl) GetUsersByPosition(
	ctx context.Context,
	positionID uuid.UUID,
	activeOnly bool,
) ([]uuid.UUID, error) {
	startTime := time.Now()

	users, err := qs.schedulingRepo.GetUsersByPosition(ctx, positionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get users by position: %w", err)
	}

	// Filter active employees if requested
	if activeOnly {
		var activeUsers []uuid.UUID
		for _, userID := range users {
			employee, err := qs.schedulingRepo.GetCompanyEmployeeByUserID(ctx, userID)
			if err == nil && employee != nil && employee.IsActive {
				activeUsers = append(activeUsers, userID)
			}
		}
		users = activeUsers
	}

	qs.logger.Debug("Users retrieved by position",
		util.String("position_id", positionID.String()),
		util.Bool("active_only", activeOnly),
		util.Int("user_count", len(users)),
		util.Duration("duration", time.Since(startTime)))

	return users, nil
}

// ==============================================
// UPDATED SCHEDULE INSTANCE METHODS
// ==============================================

func (qs *schedulingQueryServiceImpl) GetScheduleInstancesByPosition(
	ctx context.Context,
	positionID uuid.UUID,
	startDate, endDate time.Time,
) ([]*scheduling.ScheduleInstance, error) {
	startTime := time.Now()

	calendarDays := int(endDate.Sub(startDate).Hours()/24) + 1
	if calendarDays > 90 {
		return nil, fmt.Errorf("date range cannot exceed 90 days, got %d days", calendarDays)
	}

	instances, err := qs.schedulingRepo.GetScheduleInstancesByPosition(ctx, positionID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule instances by position: %w", err)
	}

	qs.logger.Debug("Schedule instances retrieved by position",
		util.String("position_id", positionID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("calendar_days", calendarDays),
		util.Int("instance_count", len(instances)),
		util.Duration("duration", time.Since(startTime)))

	return instances, nil
}

func (qs *schedulingQueryServiceImpl) GetScheduleInstancesByWorkCenter(
	ctx context.Context,
	companyID uuid.UUID,
	workCenterCode string,
	startDate, endDate time.Time,
) ([]*scheduling.ScheduleInstance, error) {
	startTime := time.Now()

	calendarDays := int(endDate.Sub(startDate).Hours()/24) + 1
	if calendarDays > 90 {
		return nil, fmt.Errorf("date range cannot exceed 90 days, got %d days", calendarDays)
	}

	instances, err := qs.schedulingRepo.GetScheduleInstancesByWorkCenter(ctx, companyID, workCenterCode, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule instances by work center: %w", err)
	}

	qs.logger.Debug("Schedule instances retrieved by work center",
		util.String("company_id", companyID.String()),
		util.String("work_center_code", workCenterCode),
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

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}

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
	if filters.PositionID != nil {
		repoFilters["position_id"] = *filters.PositionID
	}
	if filters.WorkCenterCode != nil {
		repoFilters["work_center_code"] = *filters.WorkCenterCode
	}

	// Call repository with filters
	instances, totalCount, err := qs.schedulingRepo.SearchScheduleInstances(ctx, repoFilters, page, pageSize)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search schedule instances: %w", err)
	}

	qs.logger.Debug("Schedule instances searched",
		util.Int("filter_count", len(repoFilters)),
		util.Int("page", page),
		util.Int("pageSize", pageSize),
		util.Int("total_count", totalCount),
		util.Int("returned_count", len(instances)),
		util.Duration("duration", time.Since(startTime)))

	return instances, totalCount, nil
}

// ==============================================
// UPDATED STATISTICS METHODS
// ==============================================

func (qs *schedulingQueryServiceImpl) GetScheduleStats(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) (*ScheduleStats, error) {

	startTime := time.Now()

	calendarDays := int(endDate.Sub(startDate).Hours()/24) + 1
	if calendarDays > 365 {
		return nil, fmt.Errorf(
			"date range cannot exceed 365 days for statistics, got %d days",
			calendarDays,
		)
	}

	// 1️⃣ Coverage (single source of truth)
	coverage, err := qs.schedulingRepo.GetScheduleCoverage(ctx, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule coverage: %w", err)
	}

	stats := &ScheduleStats{
		ByTemplateType: make(map[string]int64),
		ByDate:         make(map[string]int64),
		ByWorkCenter:   make(map[string]int64),
	}

	// 2️⃣ Basic totals
	if v, ok := coverage["total_scheduled_days"].(int); ok {
		stats.TotalInstances = int64(v)
	}
	if v, ok := coverage["total_scheduled_users"].(int); ok {
		stats.TotalUsers = int64(v)
	}

	// 3️⃣ Template distribution
	if dist, ok := coverage["template_distribution"].(map[string]int); ok {
		for k, v := range dist {
			stats.ByTemplateType[k] = int64(v)
		}
	}

	// 4️⃣ Upcoming schedules (next 7 days)
	today := time.Now().UTC()
	weekFromNow := today.AddDate(0, 0, 7)

	upcoming, err := qs.schedulingRepo.
		GetScheduleInstancesByCompany(ctx, companyID, today, weekFromNow)
	if err == nil {
		for _, instance := range upcoming {

			if instance.Status != "active" {
				continue
			}

			// Template
			templateName := ""
			templateType := ""
			template, err := qs.schedulingRepo.
				GetScheduleTemplateByID(ctx, instance.ScheduleTemplateID)
			if err == nil && template != nil {
				templateName = template.Name
				templateType = template.TemplateType
			}

			// Position & Work Center
			var positionID *uuid.UUID
			var positionTitle string
			var workCenterCode string

			employee, err := qs.schedulingRepo.
				GetCompanyEmployeeByUserID(ctx, instance.UserID)
			if err == nil && employee != nil && employee.PositionID != nil {
				positionID = employee.PositionID

				position, err := qs.schedulingRepo.
					GetPositionByID(ctx, *employee.PositionID)
				if err == nil && position != nil {
					positionTitle = position.Title
					if position.WorkCenterCode != nil {
						workCenterCode = *position.WorkCenterCode
					}
				}
			}

			stats.UpcomingSchedules = append(
				stats.UpcomingSchedules,
				ScheduleInstanceSummary{
					InstanceID:     instance.ScheduleInstanceID,
					UserID:         instance.UserID,
					ScheduleDate:   instance.ScheduleDate,
					ExpectedStart:  instance.ExpectedStart,
					ExpectedEnd:    instance.ExpectedEnd,
					TemplateName:   templateName,
					TemplateType:   templateType,
					PositionID:     positionID,
					PositionTitle:  positionTitle,
					WorkCenterCode: workCenterCode,
				},
			)

			if len(stats.UpcomingSchedules) >= 10 {
				break
			}
		}
	}

	// 5️⃣ Totals (safe + explicit)
	if templates, err := qs.schedulingRepo.GetScheduleTemplatesByCompany(ctx, companyID); err == nil {
		stats.TotalTemplates = int64(len(templates))
	}
	if positions, err := qs.schedulingRepo.GetPositionsByCompany(ctx, companyID); err == nil {
		stats.TotalPositions = int64(len(positions))
	}
	if workCenters, err := qs.schedulingRepo.
		GetWorkCentersByCompany(ctx, companyID, true); err == nil {
		stats.TotalWorkCenters = int64(len(workCenters))
	}

	qs.logger.Debug("Schedule statistics retrieved",
		util.String("company_id", companyID.String()),
		util.Int("calendar_days", calendarDays),
		util.Duration("duration", time.Since(startTime)),
	)

	return stats, nil
}

func (qs *schedulingQueryServiceImpl) GetPositionCoverage(
	ctx context.Context,
	positionID uuid.UUID,
	startDate, endDate time.Time,
) (map[string]interface{}, error) {
	startTime := time.Now()

	calendarDays := int(endDate.Sub(startDate).Hours()/24) + 1
	if calendarDays > 31 {
		return nil, fmt.Errorf("date range cannot exceed 31 days for coverage report, got %d days", calendarDays)
	}

	coverage, err := qs.schedulingRepo.GetPositionCoverage(ctx, positionID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get position coverage: %w", err)
	}

	qs.logger.Debug("Position coverage retrieved",
		util.String("position_id", positionID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("calendar_days", calendarDays),
		util.Duration("duration", time.Since(startTime)))

	return coverage, nil
}

func (qs *schedulingQueryServiceImpl) GetWorkCenterUtilization(
	ctx context.Context,
	companyID uuid.UUID,
	workCenterCode string,
	startDate, endDate time.Time,
) (map[string]interface{}, error) {
	startTime := time.Now()

	calendarDays := int(endDate.Sub(startDate).Hours()/24) + 1
	if calendarDays > 31 {
		return nil, fmt.Errorf("date range cannot exceed 31 days for utilization report, got %d days", calendarDays)
	}

	utilization, err := qs.schedulingRepo.GetWorkCenterUtilization(ctx, companyID, workCenterCode, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get work center utilization: %w", err)
	}

	qs.logger.Debug("Work center utilization retrieved",
		util.String("company_id", companyID.String()),
		util.String("work_center_code", workCenterCode),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("calendar_days", calendarDays),
		util.Duration("duration", time.Since(startTime)))

	return utilization, nil
}

// ==============================================
// EXISTING METHODS (Updated for position-based model)
// ==============================================

func (qs *schedulingQueryServiceImpl) GetUserScheduleSummary(
	ctx context.Context,
	userID uuid.UUID,
	startDate, endDate time.Time,
) (map[string]interface{}, error) {
	startTime := time.Now()

	calendarDays := int(endDate.Sub(startDate).Hours()/24) + 1
	if calendarDays > 90 {
		return nil, fmt.Errorf("date range cannot exceed 90 days, got %d days", calendarDays)
	}

	employee, err := qs.schedulingRepo.GetCompanyEmployeeByUserID(ctx, userID)
	if err != nil || employee == nil {
		return nil, fmt.Errorf("user does not belong to any company")
	}

	summary, err := qs.schedulingRepo.GetUserScheduleSummary(
		ctx,
		userID,
		startDate,
		endDate,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get user schedule summary: %w", err)
	}

	if employee.PositionID != nil {
		position, err := qs.schedulingRepo.GetPositionByID(ctx, *employee.PositionID)
		if err == nil && position != nil {
			summary["position"] = map[string]interface{}{
				"position_id":         position.PositionID,
				"title":               position.Title,
				"work_center":         position.WorkCenterCode,
				"is_schedulable":      position.IsSchedulable,
				"attendance_required": position.AttendanceRequired,
			}

			if position.WorkCenterCode != nil {
				wc, err := qs.schedulingRepo.GetWorkCenterByCode(ctx, position.CompanyID, *position.WorkCenterCode)
				if err == nil && wc != nil {
					summary["work_center"] = map[string]interface{}{
						"code":     wc.WorkCenterCode,
						"name":     wc.Name,
						"timezone": wc.Timezone,
					}
				}
			}
		}
	}

	qs.logger.Debug("User schedule summary retrieved",
		util.String("user_id", userID.String()),
		util.Int("calendar_days", calendarDays),
		util.Duration("duration", time.Since(startTime)))

	return summary, nil
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

	// Check position-based scheduling first
	position, err := qs.GetUserScheduledPosition(ctx, userID, date)
	if err == nil && position != nil {
		result["position"] = map[string]interface{}{
			"position_id":    position.PositionID,
			"title":          position.Title,
			"is_schedulable": position.IsSchedulable,
			"work_center":    util.StringPtrToString(position.WorkCenterCode),
		}

		// If position is not schedulable, user is not available
		if !position.IsSchedulable {
			result["available"] = false
			reasons := result["reasons"].([]string)
			reasons = append(reasons, "Position is not schedulable")
			result["reasons"] = reasons
			result["scheduling_disabled"] = true
		}

		// Check work center schedule
		if position.WorkCenterCode != nil && *position.WorkCenterCode != "" {
			shifts, err := qs.schedulingRepo.GetWorkCenterShifts(ctx, position.CompanyID, *position.WorkCenterCode, &date, &date)
			if err == nil && len(shifts) > 0 {
				shift := shifts[0]
				template, err := qs.schedulingRepo.GetScheduleTemplateByID(ctx, shift.ShiftID)
				if err == nil && template != nil {
					result["work_center_shift"] = map[string]interface{}{
						"shift_id":   shift.ShiftID,
						"shift_name": template.Name,
						"type":       template.TemplateType,
					}
				}
			} else {
				result["available"] = false
				reasons := result["reasons"].([]string)
				reasons = append(reasons, "No shift scheduled for work center")
				result["reasons"] = reasons
			}
		}
	}

	// Existing checks (overrides, etc.)
	override, err := qs.schedulingRepo.GetScheduleOverrideByUserDate(ctx, userID, date)
	if err == nil && override != nil {
		result["available"] = false
		result["schedule_override"] = override
		reasons := result["reasons"].([]string)
		reasons = append(reasons, fmt.Sprintf("Schedule override: %s", override.OverrideType))
		result["reasons"] = reasons
		if override.OverrideType == "force_work" {
			result["available"] = true
			result["forced_work"] = true
		}
	}

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

// ==============================================
// EXISTING METHODS (Unchanged or minimally changed)
// ==============================================

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

func (qs *schedulingQueryServiceImpl) GetScheduleCoverage(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) (map[string]interface{}, error) {
	startTime := time.Now()

	coverage, err := qs.schedulingRepo.GetScheduleCoverage(ctx, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule coverage: %w", err)
	}

	qs.logger.Debug("Schedule coverage retrieved",
		util.String("company_id", companyID.String()),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Duration("duration", time.Since(startTime)))

	return coverage, nil
}

func (qs *schedulingQueryServiceImpl) GetTemplateUtilization(
	ctx context.Context,
	templateID uuid.UUID,
	startDate, endDate time.Time,
) (map[string]interface{}, error) {
	startTime := time.Now()
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

func (qs *schedulingQueryServiceImpl) HealthCheck(ctx context.Context) error {
	if err := qs.schedulingRepo.HealthCheck(ctx); err != nil {
		return fmt.Errorf("scheduling repository health check failed: %w", err)
	}
	return nil
}

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

func (qs *schedulingQueryServiceImpl) GetCompanyEmployeeByUserID(
	ctx context.Context,
	userID uuid.UUID,
) (*scheduling.CompanyEmployee, error) {
	startTime := time.Now()

	employee, err := qs.schedulingRepo.GetCompanyEmployeeByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get company employee by user id: %w", err)
	}

	qs.logger.Debug("Company employee retrieved by user id",
		util.String("user_id", userID.String()),
		util.Duration("duration", time.Since(startTime)),
	)

	return employee, nil
}

func (qs *schedulingQueryServiceImpl) GetPositionByID(
	ctx context.Context,
	positionID uuid.UUID,
) (*scheduling.Position, error) {
	startTime := time.Now()

	position, err := qs.schedulingRepo.GetPositionByID(ctx, positionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get position by id: %w", err)
	}

	qs.logger.Debug("Position retrieved by id",
		util.String("position_id", positionID.String()),
		util.Duration("duration", time.Since(startTime)),
	)

	return position, nil
}

// Helper function
func getOverrideTypeString(overrideType *string) string {
	if overrideType != nil {
		return *overrideType
	}
	return "all"
}
