package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/hr/leave/models"
	"auth-service/internal/hr/leave/repository"
	hrRepo "auth-service/internal/hr/repository"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/locationctx"
)

type LeaveQueryService interface {
	// Balance — P3 validates the target user
	GetLeaveBalance(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, asOfDate time.Time, actorType string, actorID uuid.UUID, metadata map[string]interface{}) ([]*models.LeaveBalance, error)
	GetLeaveBalanceByType(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, leaveTypeID uuid.UUID, asOfDate time.Time, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.LeaveBalance, error)
	// In LeaveQueryService interface:
	GetCompanyLedger(
		ctx context.Context,
		companyID uuid.UUID,
		locationID *uuid.UUID,
		filter models.LeaveLedgerFilter,
	) ([]*models.LeaveLedgerEntry, int64, error)
	// Internal scheduling resolver — no request ctx, no P3
	IsUserOnLeave(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, date time.Time) (bool, *models.LeaveRequest, error)
	GetApprovedLeaveForDate(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, date time.Time) (*models.LeaveRequest, error)

	// History — P3 validates the target user (signature now takes companyID)
	GetUserLeaveHistory(ctx context.Context, companyID, userID uuid.UUID, startDate, endDate time.Time) ([]*models.LeaveRequest, error)
	GetLeaveTransactionHistory(ctx context.Context, companyID, userID uuid.UUID, startDate, endDate time.Time) ([]*models.LeaveTransaction, error)

	GetLeaveTypeByID(ctx context.Context, companyID uuid.UUID, leaveTypeID uuid.UUID) (*models.LeaveType, error)
	GetLeaveForecast(ctx context.Context, userID uuid.UUID, months int) ([]*models.LeaveBalance, error)

	// GetLeaveUtilizationReport — location filter applies when locationID != nil.
	GetLeaveUtilizationReport(
		ctx context.Context,
		companyID uuid.UUID,
		locationID *uuid.UUID,
		startDate, endDate time.Time,
	) ([]*models.LeaveBalance, error)

	CheckLeaveAvailability(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, leaveTypeID uuid.UUID, days int, startDate time.Time) (bool, float64, error)
}

type leaveQueryService struct {
	repo         repository.LeaveRepository
	employeeRepo hrRepo.EmployeeRepository // 👈 new — for P3
	auditService *audit.AuditService
}

func NewLeaveQueryService(
	repo repository.LeaveRepository,
	employeeRepo hrRepo.EmployeeRepository, // 👈 new
	auditService *audit.AuditService,
) LeaveQueryService {
	return &leaveQueryService{
		repo:         repo,
		employeeRepo: employeeRepo,
		auditService: auditService,
	}
}

// ensureEmployeeInScope verifies that the target employee is within the
// request's current location scope.
//
//   - ScopeAll      → pass
//   - ScopeLocation → target must be at that location
//   - missing ctx   → error (route not wrapped → wiring bug)
func (s *leaveQueryService) ensureEmployeeInScope(
	ctx context.Context,
	companyID, userID uuid.UUID,
) error {
	locCtx, err := locationctx.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("location context missing: %w", err)
	}
	if locCtx.Mode == locationctx.ScopeAll {
		return nil
	}
	empLoc, err := s.employeeRepo.GetEmploymentLocationID(ctx, companyID, userID)
	if err != nil {
		return err
	}
	if empLoc == nil {
		return ErrEmployeeHasNoLocation
	}
	if *empLoc != *locCtx.LocationID {
		return ErrEmployeeOutsideScope
	}
	return nil
}

// ============================================================================
// BALANCE (P3 validates target)
// ============================================================================

func (s *leaveQueryService) GetLeaveBalance(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	asOfDate time.Time,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) ([]*models.LeaveBalance, error) {
	// 👇 P3 — row-level authorization
	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}

	positionID, _, err := s.repo.GetUserPositionContext(ctx, companyID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve user position: %w", err)
	}
	balances, err := s.repo.GetLeaveBalancesByUser(ctx, userID, positionID, asOfDate)
	if err != nil {
		return nil, err
	}

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMeta(metadata, map[string]interface{}{
		"user_id": userID.String(),
		"as_of":   asOfDate,
		"count":   len(balances),
		"ip":      ip,
	})
	_ = s.auditService.LogAction(
		ctx, nil, &companyID, "leave", "query.balance", "leave_balance",
		nil, actorType, &actorID, nil, nil, auditMeta,
	)
	return balances, nil
}

func (s *leaveQueryService) GetLeaveBalanceByType(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	leaveTypeID uuid.UUID,
	asOfDate time.Time,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*models.LeaveBalance, error) {
	// 👇 P3 — row-level authorization
	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}

	positionID, _, err := s.repo.GetUserPositionContext(ctx, companyID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve user position: %w", err)
	}
	balance, err := s.repo.CalculateLeaveBalance(ctx, userID, leaveTypeID, asOfDate, positionID)
	if err != nil {
		return nil, err
	}

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMeta(metadata, map[string]interface{}{
		"user_id":    userID.String(),
		"leave_type": leaveTypeID.String(),
		"as_of":      asOfDate,
		"balance":    balance.Balance,
		"ip":         ip,
	})
	_ = s.auditService.LogAction(
		ctx, nil, &companyID, "leave", "query.balance_by_type", "leave_balance",
		nil, actorType, &actorID, nil, nil, auditMeta,
	)
	return balance, nil
}

// ============================================================================
// INTERNAL (no P3 — called by scheduler resolver without request ctx)
// ============================================================================

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
		return false, nil, err
	}
	for _, r := range requests {
		if r.Status == "approved" && !date.Before(r.StartDate) && !date.After(r.EndDate) {
			return true, r, nil
		}
	}
	return false, nil, nil
}

func (s *leaveQueryService) GetApprovedLeaveForDate(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	date time.Time,
) (*models.LeaveRequest, error) {
	start := date.Truncate(24 * time.Hour)
	end := start.Add(24 * time.Hour).Add(-time.Second)
	requests, err := s.repo.GetLeaveRequestsByUser(ctx, userID, start, end)
	if err != nil {
		return nil, err
	}
	for _, r := range requests {
		if r.Status == "approved" && !date.Before(r.StartDate) &&
			!date.After(r.EndDate) && r.CompanyID == companyID {
			return r, nil
		}
	}
	return nil, nil
}

// ============================================================================
// HISTORY (P3 validates target; signature changed to accept companyID)
// ============================================================================

func (s *leaveQueryService) GetUserLeaveHistory(
	ctx context.Context,
	companyID, userID uuid.UUID,
	startDate, endDate time.Time,
) ([]*models.LeaveRequest, error) {
	// 👇 P3 — row-level authorization
	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}
	return s.repo.GetLeaveRequestsByUser(ctx, userID, startDate, endDate)
}

func (s *leaveQueryService) GetLeaveTransactionHistory(
	ctx context.Context,
	companyID, userID uuid.UUID,
	startDate, endDate time.Time,
) ([]*models.LeaveTransaction, error) {
	// 👇 P3 — row-level authorization
	if err := s.ensureEmployeeInScope(ctx, companyID, userID); err != nil {
		return nil, err
	}
	return s.repo.GetLeaveTransactionHistory(ctx, userID, startDate, endDate)
}

// ============================================================================
// LEAVE TYPE / FORECAST / UTILIZATION / AVAILABILITY
// ============================================================================

func (s *leaveQueryService) GetLeaveTypeByID(
	ctx context.Context,
	companyID uuid.UUID,
	leaveTypeID uuid.UUID,
) (*models.LeaveType, error) {
	lt, err := s.repo.GetLeaveTypeByID(ctx, leaveTypeID)
	if err != nil {
		return nil, err
	}
	if lt.CompanyID != companyID {
		return nil, fmt.Errorf("leave type does not belong to company")
	}
	return lt, nil
}

func (s *leaveQueryService) GetLeaveForecast(
	ctx context.Context,
	userID uuid.UUID,
	months int,
) ([]*models.LeaveBalance, error) {
	return s.repo.GetLeaveForecast(ctx, userID, months)
}

// GetLeaveUtilizationReport — location filter applied when locationID != nil.
func (s *leaveQueryService) GetLeaveUtilizationReport(
	ctx context.Context,
	companyID uuid.UUID,
	locationID *uuid.UUID,
	startDate, endDate time.Time,
) ([]*models.LeaveBalance, error) {
	return s.repo.GetLeaveUtilizationReport(ctx, companyID, locationID, startDate, endDate)
}

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
	return s.repo.CheckLeaveAvailability(ctx, userID, leaveTypeID, days, startDate, positionID)
}
func (s *leaveQueryService) GetCompanyLedger(
	ctx context.Context,
	companyID uuid.UUID,
	locationID *uuid.UUID,
	filter models.LeaveLedgerFilter,
) ([]*models.LeaveLedgerEntry, int64, error) {
	// Force caller scope — never trust the filter's CompanyID/LocationID.
	filter.CompanyID = companyID
	filter.LocationID = locationID

	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.PageSize < 1 {
		filter.PageSize = 50
	}
	if filter.PageSize > 500 {
		filter.PageSize = 500
	}

	return s.repo.GetCompanyLedger(ctx, filter)
}
