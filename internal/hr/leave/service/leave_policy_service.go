package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/hr/leave/models"
	"auth-service/internal/hr/leave/repository"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
)

type LeavePolicyService interface {
	CreateLeaveType(ctx context.Context, companyID uuid.UUID, req *models.LeaveTypeCreate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.LeaveType, error)
	UpdateLeaveType(ctx context.Context, leaveTypeID uuid.UUID, update *models.LeaveTypeUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	AssignEntitlementToUser(ctx context.Context, req *models.LeaveEntitlementCreate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.LeaveEntitlement, error)
	GetLeaveTypesByCompany(ctx context.Context, companyID uuid.UUID) ([]*models.LeaveType, error)
	DeleteLeaveType(ctx context.Context, leaveTypeID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
}

type leavePolicyService struct {
	repo             repository.LeaveRepository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
}

func NewLeavePolicyService(
	repo repository.LeaveRepository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
) LeavePolicyService {
	return &leavePolicyService{
		repo:             repo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
	}
}

func (s *leavePolicyService) CreateLeaveType(
	ctx context.Context,
	companyID uuid.UUID,
	req *models.LeaveTypeCreate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*models.LeaveType, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("create_lt-%s-%s", companyID.String(), req.Code)
	}
	var cached *models.LeaveType
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	existing, err := s.repo.GetLeaveTypeByCode(ctx, companyID, req.Code)
	if err != nil {
		return nil, fmt.Errorf("failed to check leave type: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("leave type with code %s already exists", req.Code)
	}
	validAccrual := map[string]bool{"none": true, "monthly": true, "yearly": true, "quarterly": true}
	if !validAccrual[req.AccrualMethod] {
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
		return nil, err
	}

	afterJSON, _ := json.Marshal(leaveType)
	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMeta(metadata, map[string]interface{}{
		"leave_type_id": leaveType.LeaveTypeID.String(),
		"company_id":    companyID.String(),
		"code":          req.Code,
		"ip":            ip,
	})
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&companyID,
		"leave",
		"leave_type.create",
		"leave_type",
		&leaveType.LeaveTypeID,
		actorType,
		&actorID,
		[]byte("{}"),
		afterJSON,
		auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, leaveType)

	return leaveType, nil
}

func (s *leavePolicyService) UpdateLeaveType(
	ctx context.Context,
	leaveTypeID uuid.UUID,
	update *models.LeaveTypeUpdate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("update_lt-%s", leaveTypeID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	existing, err := s.repo.GetLeaveTypeByID(ctx, leaveTypeID)
	if err != nil {
		return fmt.Errorf("failed to get leave type: %w", err)
	}
	if existing == nil {
		return fmt.Errorf("leave type not found")
	}
	beforeJSON, _ := json.Marshal(existing)

	if update.AccrualMethod != nil {
		valid := map[string]bool{"none": true, "monthly": true, "yearly": true, "quarterly": true}
		if !valid[*update.AccrualMethod] {
			return fmt.Errorf("invalid accrual method")
		}
	}
	if err := s.repo.UpdateLeaveType(ctx, leaveTypeID, update); err != nil {
		return err
	}

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMeta(metadata, map[string]interface{}{
		"leave_type_id": leaveTypeID.String(),
		"ip":            ip,
	})
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&existing.CompanyID,
		"leave",
		"leave_type.update",
		"leave_type",
		&leaveTypeID,
		actorType,
		&actorID,
		beforeJSON,
		nil,
		auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)

	return nil
}

func (s *leavePolicyService) AssignEntitlementToUser(
	ctx context.Context,
	req *models.LeaveEntitlementCreate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*models.LeaveEntitlement, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("assign_ent-%s-%s", req.UserID.String(), req.LeaveTypeID.String())
	}
	var cached *models.LeaveEntitlement
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	if req.EffectiveFrom.IsZero() {
		return nil, fmt.Errorf("effective from date is required")
	}
	if req.EffectiveTo != nil && req.EffectiveTo.Before(req.EffectiveFrom) {
		return nil, fmt.Errorf("effective to must be after effective from")
	}
	if req.TotalDays <= 0 {
		return nil, fmt.Errorf("total days must be > 0")
	}

	positionID, workCenterCode, err := s.repo.GetUserPositionContext(ctx, req.CompanyID, req.UserID)
	if err != nil {
		// log but continue
	}
	entitlement := &models.LeaveEntitlement{
		EntitlementID:  uuid.New(),
		CompanyID:      req.CompanyID,
		UserID:         req.UserID,
		LeaveTypeID:    req.LeaveTypeID,
		TotalDays:      req.TotalDays,
		EffectiveFrom:  req.EffectiveFrom,
		EffectiveTo:    req.EffectiveTo,
		PositionID:     positionID,
		WorkCenterCode: workCenterCode,
		Source:         "manual",
		CreatedAt:      time.Now().UTC(),
	}
	if err := s.repo.CreateLeaveEntitlement(ctx, entitlement); err != nil {
		return nil, err
	}

	afterJSON, _ := json.Marshal(entitlement)
	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMeta(metadata, map[string]interface{}{
		"entitlement_id": entitlement.EntitlementID.String(),
		"user_id":        req.UserID.String(),
		"leave_type":     req.LeaveTypeID.String(),
		"ip":             ip,
	})
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&req.CompanyID,
		"leave",
		"entitlement.assign",
		"leave_entitlement",
		&entitlement.EntitlementID,
		actorType,
		&actorID,
		[]byte("{}"),
		afterJSON,
		auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, entitlement)

	return entitlement, nil
}

func (s *leavePolicyService) GetLeaveTypesByCompany(ctx context.Context, companyID uuid.UUID) ([]*models.LeaveType, error) {
	return s.repo.GetLeaveTypesByCompany(ctx, companyID)
}

func (s *leavePolicyService) DeleteLeaveType(
	ctx context.Context,
	leaveTypeID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("delete_lt-%s", leaveTypeID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	leaveType, err := s.repo.GetLeaveTypeByID(ctx, leaveTypeID)
	if err != nil {
		return err
	}
	beforeJSON, _ := json.Marshal(leaveType)

	inUse, err := s.repo.IsLeaveTypeInUse(ctx, leaveTypeID)
	if err != nil {
		return fmt.Errorf("failed to check usage: %w", err)
	}
	if inUse {
		return fmt.Errorf("cannot delete leave type in use")
	}

	if err := s.repo.DeleteLeaveType(ctx, leaveTypeID); err != nil {
		return err
	}

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMeta(metadata, map[string]interface{}{
		"leave_type_id": leaveTypeID.String(),
		"ip":            ip,
	})
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&leaveType.CompanyID,
		"leave",
		"leave_type.delete",
		"leave_type",
		&leaveTypeID,
		actorType,
		&actorID,
		beforeJSON,
		[]byte("{}"),
		auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)

	return nil
}
