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

type LeavePolicyService interface {
	CreateLeaveType(ctx context.Context, companyID uuid.UUID, req *models.LeaveTypeCreate) (*models.LeaveType, error)
	UpdateLeaveType(ctx context.Context, leaveTypeID uuid.UUID, update *models.LeaveTypeUpdate) error
	AssignEntitlementToUser(ctx context.Context, entitlement *models.LeaveEntitlementCreate) (*models.LeaveEntitlement, error)
	GetLeaveTypesByCompany(ctx context.Context, companyID uuid.UUID) ([]*models.LeaveType, error)
	DeleteLeaveType(ctx context.Context, leaveTypeID uuid.UUID) error
}

type leavePolicyService struct {
	repo   repository.LeaveRepository
	logger *zap.Logger
}

func NewLeavePolicyService(
	repo repository.LeaveRepository,
	logger *zap.Logger,
) LeavePolicyService {
	return &leavePolicyService{
		repo:   repo,
		logger: logger,
	}
}

func (s *leavePolicyService) CreateLeaveType(
	ctx context.Context,
	companyID uuid.UUID,
	req *models.LeaveTypeCreate,
) (*models.LeaveType, error) {

	existing, err := s.repo.GetLeaveTypeByCode(ctx, companyID, req.Code)
	if err != nil {
		s.logger.Error("Failed to check existing leave type",
			zap.String("company_id", companyID.String()),
			zap.String("code", req.Code),
			zap.Error(err))
		return nil, fmt.Errorf("failed to check leave type: %w", err)
	}

	if existing != nil {
		return nil, fmt.Errorf("leave type with code %s already exists", req.Code)
	}

	validAccrualMethods := map[string]bool{
		"none":      true,
		"monthly":   true,
		"yearly":    true,
		"quarterly": true,
	}
	if !validAccrualMethods[req.AccrualMethod] {
		return nil, fmt.Errorf("invalid accrual method: %s", req.AccrualMethod)
	}

	leaveType := &models.LeaveType{
		LeaveTypeID:       uuid.New(),
		CompanyID:         companyID,
		Code:              req.Code,
		Name:              req.Name,
		IsPaid:            req.IsPaid,
		RequiresApproval:  req.RequiresApproval,
		AccrualMethod:     req.AccrualMethod,
		CarryForwardLimit: req.CarryForwardLimit,
		CreatedAt:         time.Now().UTC(),
	}

	if err := s.repo.CreateLeaveType(ctx, leaveType); err != nil {
		s.logger.Error("Failed to create leave type",
			zap.String("company_id", companyID.String()),
			zap.String("code", req.Code),
			zap.Error(err))
		return nil, fmt.Errorf("failed to create leave type: %w", err)
	}

	return leaveType, nil
}

func (s *leavePolicyService) UpdateLeaveType(
	ctx context.Context,
	leaveTypeID uuid.UUID,
	update *models.LeaveTypeUpdate,
) error {

	existing, err := s.repo.GetLeaveTypeByID(ctx, leaveTypeID)
	if err != nil {
		s.logger.Error("Failed to get leave type for update",
			zap.String("leave_type_id", leaveTypeID.String()),
			zap.Error(err))
		return fmt.Errorf("failed to get leave type: %w", err)
	}

	if existing == nil {
		return fmt.Errorf("leave type not found")
	}

	if update.AccrualMethod != nil {
		validAccrualMethods := map[string]bool{
			"none":      true,
			"monthly":   true,
			"yearly":    true,
			"quarterly": true,
		}
		if !validAccrualMethods[*update.AccrualMethod] {
			return fmt.Errorf("invalid accrual method: %s", *update.AccrualMethod)
		}
	}

	if err := s.repo.UpdateLeaveType(ctx, leaveTypeID, update); err != nil {
		s.logger.Error("Failed to update leave type",
			zap.String("leave_type_id", leaveTypeID.String()),
			zap.Error(err))
		return fmt.Errorf("failed to update leave type: %w", err)
	}

	return nil
}

func (s *leavePolicyService) AssignEntitlementToUser(
	ctx context.Context,
	req *models.LeaveEntitlementCreate,
) (*models.LeaveEntitlement, error) {

	if req.EffectiveFrom.IsZero() {
		return nil, fmt.Errorf("effective from date is required")
	}

	if req.EffectiveTo != nil && req.EffectiveTo.Before(req.EffectiveFrom) {
		return nil, fmt.Errorf("effective to date must be after effective from date")
	}

	if req.TotalDays <= 0 {
		return nil, fmt.Errorf("total days must be greater than 0")
	}

	existingEntitlements, err := s.repo.GetLeaveEntitlementsByUser(
		ctx,
		req.UserID,
		nil, // manual entitlement (not position-bound)
	)
	if err != nil {
		s.logger.Error("Failed to get existing entitlements",
			zap.String("user_id", req.UserID.String()),
			zap.String("leave_type_id", req.LeaveTypeID.String()),
			zap.Error(err))
		return nil, fmt.Errorf("failed to check existing entitlements: %w", err)
	}

	for _, e := range existingEntitlements {
		if e.LeaveTypeID == req.LeaveTypeID {
			if req.EffectiveTo == nil || e.EffectiveTo == nil ||
				(req.EffectiveFrom.Before(*e.EffectiveTo) &&
					req.EffectiveTo.After(e.EffectiveFrom)) {
				return nil, fmt.Errorf(
					"user already has an active entitlement for this leave type during the specified period",
				)
			}
		}
	}

	entitlement := &models.LeaveEntitlement{
		EntitlementID: uuid.New(),
		CompanyID:     req.CompanyID,
		UserID:        req.UserID,
		LeaveTypeID:   req.LeaveTypeID,
		TotalDays:     req.TotalDays,
		EffectiveFrom: req.EffectiveFrom,
		EffectiveTo:   req.EffectiveTo,
		CreatedAt:     time.Now().UTC(),
	}

	if err := s.repo.CreateLeaveEntitlement(ctx, entitlement); err != nil {
		s.logger.Error("Failed to create leave entitlement",
			zap.String("user_id", req.UserID.String()),
			zap.String("leave_type_id", req.LeaveTypeID.String()),
			zap.Error(err))
		return nil, fmt.Errorf("failed to create leave entitlement: %w", err)
	}

	return entitlement, nil
}

func (s *leavePolicyService) GetLeaveTypesByCompany(
	ctx context.Context,
	companyID uuid.UUID,
) ([]*models.LeaveType, error) {
	return s.repo.GetLeaveTypesByCompany(ctx, companyID)
}

func (s *leavePolicyService) DeleteLeaveType(
	ctx context.Context,
	leaveTypeID uuid.UUID,
) error {

	// ✅ FIX: Properly check if this leave type is used in any entitlement
	inUse, err := s.repo.IsLeaveTypeInUse(ctx, leaveTypeID)
	if err != nil {
		return fmt.Errorf("failed to check leave type usage: %w", err)
	}

	if inUse {
		return fmt.Errorf("cannot delete leave type: it is being used in existing entitlements")
	}

	return s.repo.DeleteLeaveType(ctx, leaveTypeID)
}
