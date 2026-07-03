package resolver

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/repository"
)

type EmployeeDataProvider interface {
	GetEmployee(ctx context.Context, companyID, userID uuid.UUID) (active bool, positionID *uuid.UUID, workCenterCode *string, err error)
	GetWorkCenterAssignment(ctx context.Context, userID uuid.UUID, date time.Time) (workCenterCode *string, err error)
}

type LeaveDataProvider interface {
	GetLeaveStatus(ctx context.Context, companyID, userID uuid.UUID, date time.Time) (isOnLeave bool, isPaid bool, leaveTypeID, leaveRequestID *uuid.UUID, err error)
}

type EmployeeResolver struct {
	workCenterRepo repository.WorkCenterRepository
	scheduleRepo   repository.ScheduleRepository
	policyRepo     repository.PolicyRepository
	employeeRepo   EmployeeDataProvider
	leaveRepo      LeaveDataProvider
	logger         *zap.Logger
}

func NewEmployeeResolver(
	workCenterRepo repository.WorkCenterRepository,
	scheduleRepo repository.ScheduleRepository,
	policyRepo repository.PolicyRepository,
	employeeRepo EmployeeDataProvider,
	leaveRepo LeaveDataProvider,
	logger *zap.Logger,
) *EmployeeResolver {
	return &EmployeeResolver{
		workCenterRepo: workCenterRepo,
		scheduleRepo:   scheduleRepo,
		policyRepo:     policyRepo,
		employeeRepo:   employeeRepo,
		leaveRepo:      leaveRepo,
		logger:         logger,
	}
}

func (r *EmployeeResolver) Resolve(ctx context.Context, companyID uuid.UUID, subjectType string, subjectID uuid.UUID, date time.Time) (*ResolvedSubject, error) {
	if subjectType != SubjectTypeEmployee {
		return nil, fmt.Errorf("employee resolver called with subject_type=%s", subjectType)
	}

	r.logger.Info("EmployeeResolver.Resolve called",
		zap.String("company_id", companyID.String()),
		zap.String("subject_id", subjectID.String()),
		zap.String("date", date.Format("2006-01-02")),
	)

	active, positionID, workCenterCode, err := r.employeeRepo.GetEmployee(ctx, companyID, subjectID)
	if err != nil {
		r.logger.Error("GetEmployee failed", zap.Error(err))
		return nil, fmt.Errorf("get employee: %w", err)
	}
	if !active {
		r.logger.Warn("Employee inactive", zap.String("subject_id", subjectID.String()))
		return &ResolvedSubject{IsActive: false}, nil
	}

	r.logger.Info("Employee resolved",
		zap.String("position_id", func() string {
			if positionID != nil {
				return positionID.String()
			}
			return "<nil>"
		}()),
		zap.String("work_center", func() string {
			if workCenterCode != nil {
				return *workCenterCode
			}
			return "<nil>"
		}()),
	)

	// If work center still nil, try assignment again (though provider already did)
	if workCenterCode == nil {
		assigned, err := r.employeeRepo.GetWorkCenterAssignment(ctx, subjectID, date)
		if err == nil && assigned != nil {
			workCenterCode = assigned
			r.logger.Info("Work center from assignment (fallback)", zap.String("work_center", *workCenterCode))
		}
	}

	var expectedStart, expectedEnd *time.Time
	var scheduleStatus string
	var scheduleInstanceID *uuid.UUID
	var timezone string

	instances, err := r.scheduleRepo.GetScheduleInstancesByUserDate(ctx, subjectID, date)
	if err == nil && len(instances) > 0 {
		inst := instances[0]
		scheduleInstanceID = &inst.ScheduleInstanceID
		expectedStart = inst.ExpectedStart
		expectedEnd = inst.ExpectedEnd
		timezone = inst.Timezone
		scheduleStatus = "working"
		if inst.WorkCenterCode != nil {
			workCenterCode = inst.WorkCenterCode
			r.logger.Info("Work center from existing schedule instance", zap.String("work_center", *workCenterCode))
		}
	} else {
		scheduleStatus = "not_schedulable"
		timezone = "UTC"
		r.logger.Debug("No schedule instances found for user on date")
	}

	isOnLeave := false
	isLeavePaid := false
	var leaveTypeID, leaveRequestID *uuid.UUID
	if r.leaveRepo != nil {
		onLeave, paid, ltID, lrID, err := r.leaveRepo.GetLeaveStatus(ctx, companyID, subjectID, date)
		if err == nil {
			isOnLeave = onLeave
			isLeavePaid = paid
			leaveTypeID = ltID
			leaveRequestID = lrID
		} else {
			r.logger.Warn("GetLeaveStatus failed", zap.Error(err))
		}
	}
	if isOnLeave {
		scheduleStatus = "on_leave"
	}

	var policyID *uuid.UUID
	var policyCode, policyType *string
	var policyRules interface{}
	userPolicy, err := r.policyRepo.GetUserActivePolicy(ctx, subjectID, date)
	if err == nil && userPolicy != nil {
		policyID = &userPolicy.PolicyID
		policyCode = &userPolicy.PolicyCode
		policyType = &userPolicy.PolicyType
		policyRules = userPolicy.Rules
	} else if workCenterCode != nil {
		wcPolicy, err := r.policyRepo.GetWorkCenterPolicy(ctx, companyID, *workCenterCode)
		if err == nil && wcPolicy != nil {
			policyID = &wcPolicy.PolicyID
			policyCode = &wcPolicy.PolicyCode
			policyType = &wcPolicy.PolicyType
			policyRules = wcPolicy.Rules
		} else {
			r.logger.Warn("Work center policy not found", zap.String("work_center", *workCenterCode), zap.Error(err))
		}
	} else if positionID != nil {
		posPolicy, err := r.policyRepo.GetPositionPolicy(ctx, *positionID)
		if err == nil && posPolicy != nil {
			policyID = &posPolicy.PolicyID
			policyCode = &posPolicy.PolicyCode
			policyType = &posPolicy.PolicyType
			policyRules = posPolicy.Rules
		} else {
			r.logger.Warn("Position policy not found", zap.String("position_id", positionID.String()), zap.Error(err))
		}
	} else {
		r.logger.Warn("No policy source: both workCenterCode and positionID are nil")
	}

	// Override handling
	var isOverride bool
	var overrideType *string
	override, err := r.scheduleRepo.GetScheduleOverride(ctx, subjectID, date)
	if err == nil && override != nil {
		isOverride = true
		overrideType = &override.OverrideType
		switch override.OverrideType {
		case "off":
			scheduleStatus = "weekly_off"
		case "force_work":
			scheduleStatus = "working"
		case "holiday_override":
			scheduleStatus = "holiday"
		}
		r.logger.Info("Schedule override applied", zap.String("type", override.OverrideType))
	}

	resolved := &ResolvedSubject{
		IsActive:           active,
		Timezone:           timezone,
		ScheduleStatus:     scheduleStatus,
		ExpectedStart:      expectedStart,
		ExpectedEnd:        expectedEnd,
		ScheduleInstanceID: scheduleInstanceID,
		WorkCenterCode:     workCenterCode,
		PositionID:         positionID,
		DepartmentID:       nil,
		IsOnLeave:          isOnLeave,
		IsLeavePaid:        isLeavePaid,
		LeaveTypeID:        leaveTypeID,
		LeaveRequestID:     leaveRequestID,
		IsOverride:         isOverride,
		OverrideType:       overrideType,
		PolicyID:           policyID,
		PolicyCode:         policyCode,
		PolicyType:         policyType,
		PolicyRules:        policyRules,
	}

	r.logger.Info("Resolved subject",
		zap.String("position_id", func() string {
			if resolved.PositionID != nil {
				return resolved.PositionID.String()
			}
			return "<nil>"
		}()),
		zap.String("work_center", func() string {
			if resolved.WorkCenterCode != nil {
				return *resolved.WorkCenterCode
			}
			return "<nil>"
		}()),
		zap.String("schedule_status", resolved.ScheduleStatus),
	)

	return resolved, nil
}
