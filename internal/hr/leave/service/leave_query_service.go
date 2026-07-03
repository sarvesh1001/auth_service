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

type LeaveQueryService interface {
	GetLeaveBalance(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		asOfDate time.Time,
	) ([]*models.LeaveBalance, error)

	GetLeaveBalanceByType(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		leaveTypeID uuid.UUID,
		asOfDate time.Time,
	) (*models.LeaveBalance, error)

	IsUserOnLeave(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		date time.Time,
	) (bool, *models.LeaveRequest, error)

	// GetApprovedLeaveForDate returns the approved leave request for a user on a specific date, if any.
	GetApprovedLeaveForDate(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		date time.Time,
	) (*models.LeaveRequest, error)

	GetUserLeaveHistory(
		ctx context.Context,
		userID uuid.UUID,
		startDate, endDate time.Time,
	) ([]*models.LeaveRequest, error)

	GetLeaveTransactionHistory(
		ctx context.Context,
		userID uuid.UUID,
		startDate, endDate time.Time,
	) ([]*models.LeaveTransaction, error)

	GetLeaveTypeByID(
		ctx context.Context,
		companyID uuid.UUID,
		leaveTypeID uuid.UUID,
	) (*models.LeaveType, error)

	GetLeaveForecast(
		ctx context.Context,
		userID uuid.UUID,
		months int,
	) ([]*models.LeaveBalance, error)

	GetLeaveUtilizationReport(
		ctx context.Context,
		companyID uuid.UUID,
		startDate, endDate time.Time,
	) ([]*models.LeaveBalance, error)

	CheckLeaveAvailability(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		leaveTypeID uuid.UUID,
		days int,
		startDate time.Time,
	) (bool, float64, error)
}

type leaveQueryService struct {
	repo   repository.LeaveRepository
	logger *zap.Logger
}

func NewLeaveQueryService(
	repo repository.LeaveRepository,
	logger *zap.Logger,
) LeaveQueryService {
	return &leaveQueryService{
		repo:   repo,
		logger: logger.Named("leave_query_service"),
	}
}

// =====================================================
// BALANCE
// =====================================================

func (s *leaveQueryService) GetLeaveBalance(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	asOfDate time.Time,
) ([]*models.LeaveBalance, error) {

	positionID, _, err := s.repo.GetUserPositionContext(ctx, companyID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve user position: %w", err)
	}

	balances, err := s.repo.GetLeaveBalancesByUser(
		ctx,
		userID,
		positionID,
		asOfDate,
	)
	if err != nil {
		s.logger.Error("Failed to get leave balances",
			zap.String("user_id", userID.String()),
			zap.Time("as_of", asOfDate),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to get leave balances: %w", err)
	}

	return balances, nil
}

func (s *leaveQueryService) GetLeaveBalanceByType(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	leaveTypeID uuid.UUID,
	asOfDate time.Time,
) (*models.LeaveBalance, error) {

	positionID, _, err := s.repo.GetUserPositionContext(ctx, companyID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve user position: %w", err)
	}

	balance, err := s.repo.CalculateLeaveBalance(
		ctx,
		userID,
		leaveTypeID,
		asOfDate,
		positionID,
	)
	if err != nil {
		s.logger.Error("Failed to calculate leave balance",
			zap.String("user_id", userID.String()),
			zap.String("leave_type_id", leaveTypeID.String()),
			zap.Time("as_of", asOfDate),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to calculate leave balance: %w", err)
	}

	return balance, nil
}

// =====================================================
// STATUS / HISTORY
// =====================================================

func (s *leaveQueryService) IsUserOnLeave(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	date time.Time,
) (bool, *models.LeaveRequest, error) {

	start := date.AddDate(0, 0, -1)
	end := date.AddDate(0, 0, 1)

	requests, err := s.repo.GetLeaveRequestsByUser(ctx, userID, start, end)
	if err != nil {
		return false, nil, fmt.Errorf("failed to check leave status: %w", err)
	}

	for _, r := range requests {
		if r.Status == "approved" &&
			!date.Before(r.StartDate) &&
			!date.After(r.EndDate) {
			return true, r, nil
		}
	}

	return false, nil, nil
}

// GetApprovedLeaveForDate returns the approved leave request for a user on a specific date, if any.
func (s *leaveQueryService) GetApprovedLeaveForDate(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	date time.Time,
) (*models.LeaveRequest, error) {
	// Query requests for the exact day (or range that includes the date)
	start := date.Truncate(24 * time.Hour)
	end := start.Add(24 * time.Hour).Add(-time.Second)

	requests, err := s.repo.GetLeaveRequestsByUser(ctx, userID, start, end)
	if err != nil {
		return nil, fmt.Errorf("failed to get leave requests: %w", err)
	}

	for _, r := range requests {
		if r.Status == "approved" &&
			!date.Before(r.StartDate) &&
			!date.After(r.EndDate) {
			// Ensure it belongs to the company (optional check)
			if r.CompanyID == companyID {
				return r, nil
			}
		}
	}
	return nil, nil
}

func (s *leaveQueryService) GetUserLeaveHistory(
	ctx context.Context,
	userID uuid.UUID,
	startDate, endDate time.Time,
) ([]*models.LeaveRequest, error) {

	return s.repo.GetLeaveRequestsByUser(ctx, userID, startDate, endDate)
}

func (s *leaveQueryService) GetLeaveTransactionHistory(
	ctx context.Context,
	userID uuid.UUID,
	startDate, endDate time.Time,
) ([]*models.LeaveTransaction, error) {

	return s.repo.GetLeaveTransactionHistory(ctx, userID, startDate, endDate)
}

// =====================================================
// REPORTS
// =====================================================

func (s *leaveQueryService) GetLeaveForecast(
	ctx context.Context,
	userID uuid.UUID,
	months int,
) ([]*models.LeaveBalance, error) {

	return s.repo.GetLeaveForecast(ctx, userID, months)
}

func (s *leaveQueryService) GetLeaveUtilizationReport(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) ([]*models.LeaveBalance, error) {

	return s.repo.GetLeaveUtilizationReport(ctx, companyID, startDate, endDate)
}

// =====================================================
// AVAILABILITY
// =====================================================

func (s *leaveQueryService) CheckLeaveAvailability(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	leaveTypeID uuid.UUID,
	days int,
	startDate time.Time,
) (bool, float64, error) {

	positionID, _, err := s.repo.GetUserPositionContext(ctx, companyID, userID)
	if err != nil {
		return false, 0, fmt.Errorf("failed to resolve user position: %w", err)
	}

	return s.repo.CheckLeaveAvailability(
		ctx,
		userID,
		leaveTypeID,
		days,
		startDate,
		positionID,
	)
}

func (s *leaveQueryService) GetLeaveTypeByID(
	ctx context.Context,
	companyID uuid.UUID,
	leaveTypeID uuid.UUID,
) (*models.LeaveType, error) {

	leaveType, err := s.repo.GetLeaveTypeByID(ctx, leaveTypeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get leave type: %w", err)
	}

	// Safety: ensure leave type belongs to company
	if leaveType.CompanyID != companyID {
		return nil, fmt.Errorf("leave type does not belong to company")
	}

	return leaveType, nil
}
