package resolver

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	leaveService "auth-service/internal/hr/leave/service"
)

type leaveDataProvider struct {
	leaveQuerySvc leaveService.LeaveQueryService
	logger        *zap.Logger
}

func NewLeaveDataProvider(leaveQuerySvc leaveService.LeaveQueryService, logger *zap.Logger) LeaveDataProvider {
	return &leaveDataProvider{
		leaveQuerySvc: leaveQuerySvc,
		logger:        logger,
	}
}

func (p *leaveDataProvider) GetLeaveStatus(ctx context.Context, companyID, userID uuid.UUID, date time.Time) (isOnLeave bool, isPaid bool, leaveTypeID, leaveRequestID *uuid.UUID, err error) {
	// 1. Get approved leave request for the date
	leave, err := p.leaveQuerySvc.GetApprovedLeaveForDate(ctx, companyID, userID, date)
	if err != nil {
		p.logger.Warn("Failed to get leave status", zap.Error(err))
		return false, false, nil, nil, err
	}
	if leave == nil {
		return false, false, nil, nil, nil
	}

	// 2. Fetch leave type to determine if it's paid
	leaveType, err := p.leaveQuerySvc.GetLeaveTypeByID(ctx, companyID, leave.LeaveTypeID)
	if err != nil {
		p.logger.Warn("Failed to get leave type", zap.Error(err))
		return false, false, nil, nil, err
	}
	if leaveType == nil {
		p.logger.Warn("Leave type not found", zap.String("leave_type_id", leave.LeaveTypeID.String()))
		return false, false, nil, nil, nil
	}

	return true, leaveType.IsPaid, &leave.LeaveTypeID, &leave.LeaveRequestID, nil
}
