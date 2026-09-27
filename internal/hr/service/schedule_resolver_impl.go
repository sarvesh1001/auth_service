package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	attRepo "auth-service/internal/attendance/repository" // WorkCenterRepository (from attendance)
	"auth-service/internal/attendance/service/resolver"
	leaveSvc "auth-service/internal/hr/leave/service" // alias to avoid name conflict
	hrRepo "auth-service/internal/hr/repository"      // EmployeeRepository
)

// EmployeeScheduleResolver implements the ScheduleSubjectResolver interface
// for HR employees. It resolves schedule-related information using HR data.
type EmployeeScheduleResolver struct {
	employeeRepo   hrRepo.EmployeeRepository    // HR employee repository
	workCenterRepo attRepo.WorkCenterRepository // Attendance work center repository
	leaveQuery     leaveSvc.LeaveQueryService   // Leave query service
	logger         *zap.Logger
}

// NewEmployeeScheduleResolver creates a new EmployeeScheduleResolver.
func NewEmployeeScheduleResolver(
	employeeRepo hrRepo.EmployeeRepository,
	workCenterRepo attRepo.WorkCenterRepository,
	leaveQuery leaveSvc.LeaveQueryService,
	logger *zap.Logger,
) resolver.ScheduleSubjectResolver {
	return &EmployeeScheduleResolver{
		employeeRepo:   employeeRepo,
		workCenterRepo: workCenterRepo,
		leaveQuery:     leaveQuery,
		logger:         logger,
	}
}

// ResolveSubject returns schedule-related subject info for an employee.
//
// Reads from GetPositionViewByID (joined with `jobs` and `locations`)
// so the schedule engine gets the job's schedulable / attendance /
// overtime flags along with the seat's work-center.
func (r *EmployeeScheduleResolver) ResolveSubject(
	ctx context.Context,
	companyID, subjectID uuid.UUID,
	subjectType string,
	date time.Time,
) (*resolver.ScheduleSubjectInfo, error) {
	if subjectType != "employee" {
		return nil, fmt.Errorf("unsupported subject type: %s", subjectType)
	}

	// Get company employee record.
	employee, err := r.employeeRepo.GetCompanyEmployeeByUserID(ctx, subjectID)
	if err != nil {
		return nil, err
	}
	if employee == nil || !employee.IsActive {
		return &resolver.ScheduleSubjectInfo{IsActive: false}, nil
	}

	info := &resolver.ScheduleSubjectInfo{
		SubjectID:   subjectID,
		SubjectType: "employee",
		IsActive:    true,
		CompanyID:   companyID,
	}

	if employee.PositionID == nil {
		return info, nil
	}

	// Joined view: seat + job definition + joined names.
	pv, err := r.employeeRepo.GetPositionViewByID(ctx, *employee.PositionID)
	if err != nil || pv == nil {
		// A missing position is not fatal — return the employee
		// without schedule flags; the caller can decide.
		return info, nil
	}

	// Job-level fields — these come from the joined `jobs` row.
	info.PositionID = &pv.PositionID
	info.PositionTitle = pv.EffectiveTitle()
	info.IsSchedulable = pv.IsSchedulable
	info.AttendanceRequired = pv.AttendanceRequired
	info.OvertimeAllowed = pv.OvertimeAllowed

	// Work-center resolution — the seat carries the code; the
	// attendance repo resolves the WC's name and timezone.
	if pv.WorkCenterCode != nil {
		info.WorkCenterCode = pv.WorkCenterCode
		wc, err := r.workCenterRepo.GetByCode(ctx, companyID, *pv.WorkCenterCode)
		if err == nil && wc != nil {
			info.WorkCenterName = wc.Name
			info.WorkCenterTimezone = wc.Timezone
		}
	}

	return info, nil
}

// ResolveOverride resolves leave and override information for an employee.
func (r *EmployeeScheduleResolver) ResolveOverride(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, date time.Time) (*resolver.ScheduleOverrideInfo, error) {
	var overrideInfo resolver.ScheduleOverrideInfo
	if r.leaveQuery != nil {
		isOnLeave, leaveInfo, err := r.leaveQuery.IsUserOnLeave(ctx, companyID, subjectID, date)
		if err == nil && isOnLeave && leaveInfo != nil {
			overrideInfo.IsOnLeave = true
			overrideInfo.LeaveRequestID = &leaveInfo.LeaveRequestID
			overrideInfo.LeaveTypeID = &leaveInfo.LeaveTypeID
			if leaveInfo.LeaveTypeID != uuid.Nil {
				lt, _ := r.leaveQuery.GetLeaveTypeByID(ctx, companyID, leaveInfo.LeaveTypeID)
				if lt != nil {
					overrideInfo.IsLeavePaid = lt.IsPaid
				}
			}
			overrideInfo.OverrideType = "off"
			overrideInfo.IsOverride = true
			reason := "leave_" + leaveInfo.LeaveRequestID.String()
			overrideInfo.Reason = &reason
			return &overrideInfo, nil
		}
	}
	return &overrideInfo, nil
}

// GetUsersByPosition returns subject IDs (user IDs) assigned to a given position.
func (r *EmployeeScheduleResolver) GetUsersByPosition(ctx context.Context, positionID uuid.UUID) ([]uuid.UUID, error) {
	return r.employeeRepo.GetActiveUsersByPosition(ctx, positionID)
}

// GetActiveSubjectsByCompany returns all active employee IDs for a company.
func (r *EmployeeScheduleResolver) GetActiveSubjectsByCompany(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}) ([]uuid.UUID, error) {
	return r.employeeRepo.GetActiveEmployeesByCompany(ctx, companyID)
}
