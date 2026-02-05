// internal/hr/leave/service/leave_query_service.go
package service

import (
	"auth-service/internal/hr/leave/models"
	"auth-service/internal/hr/leave/repository"
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type LeaveQueryService interface {
	GetLeaveBalance(ctx context.Context, userID uuid.UUID, asOfDate time.Time) ([]*models.LeaveBalance, error)
	GetLeaveBalanceByType(ctx context.Context, userID, leaveTypeID uuid.UUID, asOfDate time.Time) (*models.LeaveBalance, error)
	IsUserOnLeave(ctx context.Context, companyID, userID uuid.UUID, date time.Time) (bool, *models.LeaveRequest, error)
	GetUserLeaveHistory(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*models.LeaveRequest, error)
	GetLeaveTransactionHistory(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*models.LeaveTransaction, error)
	GetLeaveForecast(ctx context.Context, userID uuid.UUID, months int) ([]*models.LeaveBalance, error)
	GetLeaveUtilizationReport(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]*models.LeaveBalance, error)
	CheckLeaveAvailability(ctx context.Context, userID, leaveTypeID uuid.UUID, days int, startDate time.Time) (bool, int, error)
}

type leaveQueryService struct {
	repo   repository.LeaveRepository
	logger *zap.Logger
}

func NewLeaveQueryService(repo repository.LeaveRepository, logger *zap.Logger) LeaveQueryService {
	return &leaveQueryService{
		repo:   repo,
		logger: logger,
	}
}

func (s *leaveQueryService) GetLeaveBalance(ctx context.Context, userID uuid.UUID, asOfDate time.Time) ([]*models.LeaveBalance, error) {
	// Get all leave types the user has entitlements for
	entitlements, err := s.repo.GetLeaveEntitlementsByUser(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get entitlements for balance",
			zap.String("user_id", userID.String()),
			zap.Error(err))
		return nil, fmt.Errorf("failed to get entitlements: %w", err)
	}

	// Group entitlements by leave type and get current balance
	balances := make([]*models.LeaveBalance, 0)
	processedTypes := make(map[uuid.UUID]bool)

	for _, entitlement := range entitlements {
		if processedTypes[entitlement.LeaveTypeID] {
			continue
		}

		// Check if entitlement is valid for the asOfDate
		if entitlement.EffectiveFrom.After(asOfDate) ||
			(entitlement.EffectiveTo != nil && entitlement.EffectiveTo.Before(asOfDate)) {
			continue
		}

		balance, err := s.repo.CalculateLeaveBalance(ctx, userID, entitlement.LeaveTypeID, asOfDate)
		if err != nil {
			s.logger.Warn("Failed to calculate balance for leave type",
				zap.String("user_id", userID.String()),
				zap.String("leave_type_id", entitlement.LeaveTypeID.String()),
				zap.Error(err))
			continue
		}

		balances = append(balances, balance)
		processedTypes[entitlement.LeaveTypeID] = true
	}

	s.logger.Debug("Retrieved leave balances",
		zap.String("user_id", userID.String()),
		zap.Time("as_of_date", asOfDate),
		zap.Int("balance_count", len(balances)))

	return balances, nil
}

func (s *leaveQueryService) GetLeaveBalanceByType(ctx context.Context, userID, leaveTypeID uuid.UUID, asOfDate time.Time) (*models.LeaveBalance, error) {
	balance, err := s.repo.CalculateLeaveBalance(ctx, userID, leaveTypeID, asOfDate)
	if err != nil {
		s.logger.Error("Failed to calculate leave balance by type",
			zap.String("user_id", userID.String()),
			zap.String("leave_type_id", leaveTypeID.String()),
			zap.Time("as_of_date", asOfDate),
			zap.Error(err))
		return nil, fmt.Errorf("failed to calculate leave balance: %w", err)
	}

	return balance, nil
}

func (s *leaveQueryService) IsUserOnLeave(ctx context.Context, companyID, userID uuid.UUID, date time.Time) (bool, *models.LeaveRequest, error) {
	// Get leave requests for this user that include the specified date
	// We'll check a small date range around the specified date
	startDate := date.AddDate(0, 0, -1)
	endDate := date.AddDate(0, 0, 1)

	requests, err := s.repo.GetLeaveRequestsByUser(ctx, userID, startDate, endDate)
	if err != nil {
		s.logger.Error("Failed to get leave requests for date check",
			zap.String("user_id", userID.String()),
			zap.Time("date", date),
			zap.Error(err))
		return false, nil, fmt.Errorf("failed to check leave status: %w", err)
	}

	// Check if any approved leave request includes the date
	for _, request := range requests {
		if request.Status == "approved" &&
			(request.StartDate.Equal(date) || request.StartDate.Before(date)) &&
			(request.EndDate.Equal(date) || request.EndDate.After(date)) {

			s.logger.Debug("User is on leave",
				zap.String("user_id", userID.String()),
				zap.Time("date", date),
				zap.String("leave_request_id", request.LeaveRequestID.String()))

			return true, request, nil
		}
	}

	s.logger.Debug("User is not on leave",
		zap.String("user_id", userID.String()),
		zap.Time("date", date))

	return false, nil, nil
}

func (s *leaveQueryService) GetUserLeaveHistory(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*models.LeaveRequest, error) {
	requests, err := s.repo.GetLeaveRequestsByUser(ctx, userID, startDate, endDate)
	if err != nil {
		s.logger.Error("Failed to get user leave history",
			zap.String("user_id", userID.String()),
			zap.Time("start_date", startDate),
			zap.Time("end_date", endDate),
			zap.Error(err))
		return nil, fmt.Errorf("failed to get leave history: %w", err)
	}

	s.logger.Debug("Retrieved user leave history",
		zap.String("user_id", userID.String()),
		zap.Int("request_count", len(requests)))

	return requests, nil
}

func (s *leaveQueryService) GetLeaveTransactionHistory(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*models.LeaveTransaction, error) {
	transactions, err := s.repo.GetLeaveTransactionHistory(ctx, userID, startDate, endDate)
	if err != nil {
		s.logger.Error("Failed to get leave transaction history",
			zap.String("user_id", userID.String()),
			zap.Time("start_date", startDate),
			zap.Time("end_date", endDate),
			zap.Error(err))
		return nil, fmt.Errorf("failed to get transaction history: %w", err)
	}

	s.logger.Debug("Retrieved leave transaction history",
		zap.String("user_id", userID.String()),
		zap.Int("transaction_count", len(transactions)))

	return transactions, nil
}

func (s *leaveQueryService) GetLeaveForecast(ctx context.Context, userID uuid.UUID, months int) ([]*models.LeaveBalance, error) {
	forecasts, err := s.repo.GetLeaveForecast(ctx, userID, months)
	if err != nil {
		s.logger.Error("Failed to get leave forecast",
			zap.String("user_id", userID.String()),
			zap.Int("months", months),
			zap.Error(err))
		return nil, fmt.Errorf("failed to get leave forecast: %w", err)
	}

	s.logger.Debug("Generated leave forecast",
		zap.String("user_id", userID.String()),
		zap.Int("months", months),
		zap.Int("forecast_count", len(forecasts)))

	return forecasts, nil
}

func (s *leaveQueryService) GetLeaveUtilizationReport(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]*models.LeaveBalance, error) {
	report, err := s.repo.GetLeaveUtilizationReport(ctx, companyID, startDate, endDate)
	if err != nil {
		s.logger.Error("Failed to get leave utilization report",
			zap.String("company_id", companyID.String()),
			zap.Time("start_date", startDate),
			zap.Time("end_date", endDate),
			zap.Error(err))
		return nil, fmt.Errorf("failed to get utilization report: %w", err)
	}

	s.logger.Info("Generated leave utilization report",
		zap.String("company_id", companyID.String()),
		zap.Int("employee_count", len(report)))

	return report, nil
}

func (s *leaveQueryService) CheckLeaveAvailability(ctx context.Context, userID, leaveTypeID uuid.UUID, days int, startDate time.Time) (bool, int, error) {
	available, availableDays, err := s.repo.CheckLeaveAvailability(ctx, userID, leaveTypeID, days, startDate)
	if err != nil {
		s.logger.Error("Failed to check leave availability",
			zap.String("user_id", userID.String()),
			zap.String("leave_type_id", leaveTypeID.String()),
			zap.Int("requested_days", days),
			zap.Error(err))
		return false, 0, fmt.Errorf("failed to check leave availability: %w", err)
	}

	s.logger.Debug("Checked leave availability",
		zap.String("user_id", userID.String()),
		zap.String("leave_type_id", leaveTypeID.String()),
		zap.Int("requested_days", days),
		zap.Int("available_days", availableDays),
		zap.Bool("is_available", available))

	return available, availableDays, nil
}
