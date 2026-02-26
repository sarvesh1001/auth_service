package service

import (
	"context"
	"fmt"
	"time"

	"auth-service/internal/hr/leave/models"
	"auth-service/internal/hr/leave/repository"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// =====================================
// INTERFACE
// =====================================

type LeaveRequestService interface {
	RequestLeave(ctx context.Context, req *models.LeaveRequestCreate) (*models.LeaveRequest, error)
	ApproveLeave(ctx context.Context, requestID uuid.UUID, approvedBy uuid.UUID) (*models.LeaveRequest, error)
	RejectLeave(ctx context.Context, requestID uuid.UUID, rejectedBy uuid.UUID, reason string) (*models.LeaveRequest, error)
	CancelLeave(ctx context.Context, requestID uuid.UUID, cancelledBy uuid.UUID) (*models.LeaveRequest, error)
	GetPendingRequests(ctx context.Context, companyID uuid.UUID, approverID uuid.UUID) ([]*models.LeaveRequest, error)
	UpdateLeaveRequest(ctx context.Context, requestID uuid.UUID, update *models.LeaveRequestUpdate) error
}

// =====================================
// SERVICE
// =====================================

type leaveRequestService struct {
	repo           repository.LeaveRepository
	balanceService LeaveBalanceService
	logger         *zap.Logger
}

func NewLeaveRequestService(
	repo repository.LeaveRepository,
	balanceService LeaveBalanceService,
	logger *zap.Logger,
) LeaveRequestService {
	return &leaveRequestService{
		repo:           repo,
		balanceService: balanceService,
		logger:         logger,
	}
}

// =====================================
// REQUEST LEAVE
// =====================================

func (s *leaveRequestService) RequestLeave(
	ctx context.Context,
	req *models.LeaveRequestCreate,
) (*models.LeaveRequest, error) {

	valid, message, err := s.repo.ValidateLeaveRequest(
		ctx,
		req,
		nil,
	)
	if err != nil {
		s.logger.Error("Leave validation failed", zap.Error(err))
		return nil, err
	}
	if !valid {
		return nil, fmt.Errorf(message)
	}

	leaveType, err := s.repo.GetLeaveTypeByID(ctx, req.LeaveTypeID)
	if err != nil {
		return nil, err
	}
	if leaveType == nil {
		return nil, fmt.Errorf("leave type not found")
	}

	request := &models.LeaveRequest{
		LeaveRequestID: uuid.New(),
		CompanyID:      req.CompanyID,
		UserID:         req.UserID,
		LeaveTypeID:    req.LeaveTypeID,
		StartDate:      req.StartDate,
		EndDate:        req.EndDate,
		TotalDays:      req.TotalDays,
		Status:         "pending",
		RequestedBy:    req.RequestedBy,
		RequestedAt:    time.Now().UTC(),
	}

	if !leaveType.RequiresApproval {
		request.Status = "approved"
		request.ApprovedBy = &req.RequestedBy
		now := time.Now().UTC()
		request.ApprovedAt = &now
	}

	if err := s.repo.CreateLeaveRequest(ctx, request); err != nil {
		return nil, err
	}

	if request.Status == "approved" {
		if err := s.processApproval(ctx, request, *request.ApprovedBy); err != nil {
			s.logger.Error("Auto approval failed", zap.Error(err))
		}
	}

	return request, nil
}

// =====================================
// APPROVE
// =====================================

func (s *leaveRequestService) ApproveLeave(
	ctx context.Context,
	requestID uuid.UUID,
	approvedBy uuid.UUID,
) (*models.LeaveRequest, error) {

	request, err := s.repo.GetLeaveRequestByID(ctx, requestID)
	if err != nil {
		return nil, err
	}
	if request == nil {
		return nil, fmt.Errorf("leave request not found")
	}
	if request.Status != "pending" {
		return nil, fmt.Errorf("leave request is not pending")
	}

	// ✅ FIX: pass companyID as well
	balance, err := s.balanceService.GetBalanceAsOf(
		ctx,
		request.CompanyID,
		request.UserID,
		request.LeaveTypeID,
		request.StartDate,
	)
	if err != nil {
		return nil, err
	}

	if balance.Balance < float64(request.TotalDays) {
		return nil, fmt.Errorf(
			"insufficient leave balance: available=%.2f, required=%d",
			balance.Balance,
			request.TotalDays,
		)
	}

	if err := s.processApproval(ctx, request, approvedBy); err != nil {
		return nil, err
	}

	return s.repo.GetLeaveRequestByID(ctx, requestID)
}

// =====================================
// REJECT
// =====================================

func (s *leaveRequestService) RejectLeave(
	ctx context.Context,
	requestID uuid.UUID,
	rejectedBy uuid.UUID,
	reason string,
) (*models.LeaveRequest, error) {

	update := &models.LeaveRequestUpdate{
		Status:     stringPtr("rejected"),
		ApprovedBy: &rejectedBy,
		ApprovedAt: timePtr(time.Now().UTC()),
	}

	if err := s.repo.UpdateLeaveRequest(ctx, requestID, update); err != nil {
		return nil, err
	}

	s.logger.Info("Leave rejected",
		zap.String("request_id", requestID.String()),
		zap.String("reason", reason),
	)

	return s.repo.GetLeaveRequestByID(ctx, requestID)
}

// =====================================
// CANCEL
// =====================================

func (s *leaveRequestService) CancelLeave(
	ctx context.Context,
	requestID uuid.UUID,
	cancelledBy uuid.UUID,
) (*models.LeaveRequest, error) {

	if err := s.repo.CancelLeaveRequest(ctx, requestID); err != nil {
		return nil, err
	}

	return s.repo.GetLeaveRequestByID(ctx, requestID)
}

// =====================================
// READ
// =====================================

func (s *leaveRequestService) GetPendingRequests(
	ctx context.Context,
	companyID uuid.UUID,
	approverID uuid.UUID,
) ([]*models.LeaveRequest, error) {
	return s.repo.GetPendingLeaveRequests(ctx, companyID, approverID)
}

func (s *leaveRequestService) UpdateLeaveRequest(
	ctx context.Context,
	requestID uuid.UUID,
	update *models.LeaveRequestUpdate,
) error {
	return s.repo.UpdateLeaveRequest(ctx, requestID, update)
}

// =====================================
// INTERNAL
// =====================================

func (s *leaveRequestService) processApproval(
	ctx context.Context,
	request *models.LeaveRequest,
	approvedBy uuid.UUID,
) error {

	return s.repo.ProcessLeaveRequest(
		ctx,
		request.LeaveRequestID,
		true,
		approvedBy,
	)
}

// =====================================
// HELPERS
// =====================================

func stringPtr(v string) *string     { return &v }
func timePtr(t time.Time) *time.Time { return &t }
