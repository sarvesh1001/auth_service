package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/hr/leave/models"
	"auth-service/internal/hr/leave/repository"
	hrRepo "auth-service/internal/hr/repository"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/locationctx"
)

type LeaveRequestService interface {
	RequestLeave(ctx context.Context, req *models.LeaveRequestCreate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.LeaveRequest, error)
	ApproveLeave(ctx context.Context, requestID uuid.UUID, approvedBy uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.LeaveRequest, error)
	RejectLeave(ctx context.Context, requestID uuid.UUID, rejectedBy uuid.UUID, reason string, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.LeaveRequest, error)
	CancelLeave(ctx context.Context, requestID uuid.UUID, cancelledBy uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.LeaveRequest, error)

	// GetPendingRequests — location filter applies when locationID != nil.
	GetPendingRequests(
		ctx context.Context,
		companyID uuid.UUID,
		approverID uuid.UUID,
		locationID *uuid.UUID,
	) ([]*models.LeaveRequest, error)

	UpdateLeaveRequest(ctx context.Context, requestID uuid.UUID, update *models.LeaveRequestUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
}

type leaveRequestService struct {
	repo             repository.LeaveRepository
	employeeRepo     hrRepo.EmployeeRepository // 👈 new — for location lookup
	balanceService   LeaveBalanceService
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
}

func NewLeaveRequestService(
	repo repository.LeaveRepository,
	employeeRepo hrRepo.EmployeeRepository, // 👈 new
	balanceService LeaveBalanceService,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
) LeaveRequestService {
	return &leaveRequestService{
		repo:             repo,
		employeeRepo:     employeeRepo,
		balanceService:   balanceService,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
	}
}

// ensureEmployeeInScope — see hr/service for the equivalent helper.
//
// Rules:
//   - ScopeAll      → pass
//   - ScopeLocation → target.employment_location_id must match scope
//   - missing ctx   → error (route not wrapped → wiring bug)
func (s *leaveRequestService) ensureEmployeeInScope(
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

func (s *leaveRequestService) RequestLeave(
	ctx context.Context,
	req *models.LeaveRequestCreate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*models.LeaveRequest, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("request_leave-%s", uuid.New().String())
	}
	var cached *models.LeaveRequest
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	// 👇 Row-level authorization — target employee must be in scope.
	if err := s.ensureEmployeeInScope(ctx, req.CompanyID, req.UserID); err != nil {
		return nil, err
	}

	valid, message, err := s.repo.ValidateLeaveRequest(ctx, req, nil)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, fmt.Errorf("%s", message)
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
			// Non-fatal — the request is created; the approval ledger entry
			// can be reconciled later. Log via audit metadata below.
		}
	}

	afterJSON, _ := json.Marshal(request)
	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMeta(metadata, map[string]interface{}{
		"request_id": request.LeaveRequestID.String(),
		"user_id":    req.UserID.String(),
		"status":     request.Status,
		"ip":         ip,
	})
	_ = s.auditService.LogAction(
		ctx, nil, &req.CompanyID, "leave", "request.create", "leave_request",
		&request.LeaveRequestID, actorType, &actorID, []byte("{}"), afterJSON, auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, request)

	return request, nil
}

func (s *leaveRequestService) ApproveLeave(
	ctx context.Context,
	requestID uuid.UUID,
	approvedBy uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*models.LeaveRequest, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("approve_leave-%s", requestID.String())
	}
	var cached *models.LeaveRequest
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

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

	// 👇 Row-level authorization — target employee must be in scope.
	if err := s.ensureEmployeeInScope(ctx, request.CompanyID, request.UserID); err != nil {
		return nil, err
	}

	balance, err := s.balanceService.GetBalanceAsOf(ctx, request.CompanyID, request.UserID, request.LeaveTypeID, request.StartDate, actorType, actorID, metadata)
	if err != nil {
		return nil, err
	}
	if balance.Balance < float64(request.TotalDays) {
		return nil, fmt.Errorf("insufficient balance: available=%.2f, required=%d", balance.Balance, request.TotalDays)
	}

	beforeJSON, _ := json.Marshal(request)
	if err := s.processApproval(ctx, request, approvedBy); err != nil {
		return nil, err
	}
	updated, _ := s.repo.GetLeaveRequestByID(ctx, requestID)
	afterJSON, _ := json.Marshal(updated)

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMeta(metadata, map[string]interface{}{
		"request_id":  requestID.String(),
		"approved_by": approvedBy.String(),
		"ip":          ip,
	})
	_ = s.auditService.LogAction(
		ctx, nil, &request.CompanyID, "leave", "request.approve", "leave_request",
		&requestID, actorType, &actorID, beforeJSON, afterJSON, auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, updated)

	return updated, nil
}

func (s *leaveRequestService) RejectLeave(
	ctx context.Context,
	requestID uuid.UUID,
	rejectedBy uuid.UUID,
	reason string,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*models.LeaveRequest, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("reject_leave-%s", requestID.String())
	}
	var cached *models.LeaveRequest
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	request, err := s.repo.GetLeaveRequestByID(ctx, requestID)
	if err != nil {
		return nil, err
	}
	if request == nil {
		return nil, fmt.Errorf("request not found")
	}

	// 👇 Row-level authorization — target employee must be in scope.
	if err := s.ensureEmployeeInScope(ctx, request.CompanyID, request.UserID); err != nil {
		return nil, err
	}

	beforeJSON, _ := json.Marshal(request)

	update := &models.LeaveRequestUpdate{
		Status:     stringPtr("rejected"),
		ApprovedBy: &rejectedBy,
		ApprovedAt: timePtr(time.Now().UTC()),
	}
	if err := s.repo.UpdateLeaveRequest(ctx, requestID, update); err != nil {
		return nil, err
	}
	updated, _ := s.repo.GetLeaveRequestByID(ctx, requestID)
	afterJSON, _ := json.Marshal(updated)

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMeta(metadata, map[string]interface{}{
		"request_id": requestID.String(),
		"reason":     reason,
		"ip":         ip,
	})
	_ = s.auditService.LogAction(
		ctx, nil, &request.CompanyID, "leave", "request.reject", "leave_request",
		&requestID, actorType, &actorID, beforeJSON, afterJSON, auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, updated)

	return updated, nil
}

func (s *leaveRequestService) CancelLeave(
	ctx context.Context,
	requestID uuid.UUID,
	cancelledBy uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*models.LeaveRequest, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("cancel_leave-%s", requestID.String())
	}
	var cached *models.LeaveRequest
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}

	request, err := s.repo.GetLeaveRequestByID(ctx, requestID)
	if err != nil {
		return nil, err
	}
	if request == nil {
		return nil, fmt.Errorf("request not found")
	}

	// 👇 Row-level authorization — target employee must be in scope.
	if err := s.ensureEmployeeInScope(ctx, request.CompanyID, request.UserID); err != nil {
		return nil, err
	}

	beforeJSON, _ := json.Marshal(request)

	if err := s.repo.CancelLeaveRequest(ctx, requestID); err != nil {
		return nil, err
	}
	updated, _ := s.repo.GetLeaveRequestByID(ctx, requestID)
	afterJSON, _ := json.Marshal(updated)

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMeta(metadata, map[string]interface{}{
		"request_id":   requestID.String(),
		"cancelled_by": cancelledBy.String(),
		"ip":           ip,
	})
	_ = s.auditService.LogAction(
		ctx, nil, &request.CompanyID, "leave", "request.cancel", "leave_request",
		&requestID, actorType, &actorID, beforeJSON, afterJSON, auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, updated)

	return updated, nil
}

// GetPendingRequests — location filter applies when locationID != nil.
func (s *leaveRequestService) GetPendingRequests(
	ctx context.Context,
	companyID uuid.UUID,
	approverID uuid.UUID,
	locationID *uuid.UUID,
) ([]*models.LeaveRequest, error) {
	return s.repo.GetPendingLeaveRequests(ctx, companyID, approverID, locationID)
}

func (s *leaveRequestService) UpdateLeaveRequest(
	ctx context.Context,
	requestID uuid.UUID,
	update *models.LeaveRequestUpdate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("update_req-%s", requestID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	request, err := s.repo.GetLeaveRequestByID(ctx, requestID)
	if err != nil {
		return err
	}

	// 👇 Row-level authorization — target employee must be in scope.
	if err := s.ensureEmployeeInScope(ctx, request.CompanyID, request.UserID); err != nil {
		return err
	}

	beforeJSON, _ := json.Marshal(request)

	if err := s.repo.UpdateLeaveRequest(ctx, requestID, update); err != nil {
		return err
	}

	ip, _ := ctx.Value("ip_address").(string)
	auditMeta := mergeMeta(metadata, map[string]interface{}{
		"request_id": requestID.String(),
		"ip":         ip,
	})
	_ = s.auditService.LogAction(
		ctx, nil, &request.CompanyID, "leave", "request.update", "leave_request",
		&requestID, actorType, &actorID, beforeJSON, nil, auditMeta,
	)

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)

	return nil
}

func (s *leaveRequestService) processApproval(ctx context.Context, request *models.LeaveRequest, approvedBy uuid.UUID) error {
	return s.repo.ProcessLeaveRequest(ctx, request.LeaveRequestID, true, approvedBy)
}

func stringPtr(v string) *string     { return &v }
func timePtr(t time.Time) *time.Time { return &t }
