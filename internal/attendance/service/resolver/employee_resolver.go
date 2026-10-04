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

	// ── NEW: canonical tz resolution. Never hardcode "UTC".
	tzProvider TimezoneProvider

	logger *zap.Logger
}

func NewEmployeeResolver(
	workCenterRepo repository.WorkCenterRepository,
	scheduleRepo repository.ScheduleRepository,
	policyRepo repository.PolicyRepository,
	employeeRepo EmployeeDataProvider,
	leaveRepo LeaveDataProvider,
	tzProvider TimezoneProvider,
	logger *zap.Logger,
) *EmployeeResolver {
	return &EmployeeResolver{
		workCenterRepo: workCenterRepo,
		scheduleRepo:   scheduleRepo,
		policyRepo:     policyRepo,
		employeeRepo:   employeeRepo,
		leaveRepo:      leaveRepo,
		tzProvider:     tzProvider,
		logger:         logger,
	}
}

func (r *EmployeeResolver) Resolve(
	ctx context.Context,
	companyID uuid.UUID,
	subjectType string,
	subjectID uuid.UUID,
	date time.Time,
) (*ResolvedSubject, error) {
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
		return &ResolvedSubject{IsActive: false}, nil
	}

	if workCenterCode == nil {
		if assigned, err := r.employeeRepo.GetWorkCenterAssignment(ctx, subjectID, date); err == nil && assigned != nil {
			workCenterCode = assigned
		}
	}

	var (
		expectedStart      *time.Time
		expectedEnd        *time.Time
		scheduleStatus     string
		scheduleInstanceID *uuid.UUID
		timezone           string
	)

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
		}
	} else {
		scheduleStatus = "not_schedulable"
	}

	// ── NEW: always resolve tz via the chain. Even when we have a
	//    schedule instance, prefer the resolved tz if the instance's tz
	//    is empty. When there's no instance, this is the only source.
	if timezone == "" {
		resolvedTz, tzErr := r.tzProvider.ResolveTimezone(
			ctx, companyID, positionID, workCenterCode, nil,
		)
		if tzErr != nil {
			r.logger.Warn("tz resolution failed, defaulting to UTC",
				zap.String("subject_id", subjectID.String()),
				zap.Error(tzErr),
			)
			timezone = "UTC"
		} else if resolvedTz == "" {
			timezone = "UTC"
		} else {
			timezone = resolvedTz
		}
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
		}
	} else if positionID != nil {
		posPolicy, err := r.policyRepo.GetPositionPolicy(ctx, *positionID)
		if err == nil && posPolicy != nil {
			policyID = &posPolicy.PolicyID
			policyCode = &posPolicy.PolicyCode
			policyType = &posPolicy.PolicyType
			policyRules = posPolicy.Rules
		}
	}

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
	}

	return &ResolvedSubject{
		IsActive:           active,
		Timezone:           timezone,
		ScheduleStatus:     scheduleStatus,
		ExpectedStart:      expectedStart,
		ExpectedEnd:        expectedEnd,
		ScheduleInstanceID: scheduleInstanceID,
		WorkCenterCode:     workCenterCode,
		PositionID:         positionID,
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
	}, nil
}
