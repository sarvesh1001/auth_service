package handler

import (
	"auth-service/internal/hr/leave/models"
	"auth-service/internal/hr/leave/service"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type LeaveAdminHandler struct {
	policyService       service.LeavePolicyService
	policyConfigService service.LeavePolicyConfigService // ✅ ADD
	accrualService      service.LeaveAccrualService
	logger              *zap.Logger
}

func NewLeaveAdminHandler(
	policyService service.LeavePolicyService,
	policyConfigService service.LeavePolicyConfigService, // ✅ ADD
	accrualService service.LeaveAccrualService,
	logger *zap.Logger,
) *LeaveAdminHandler {
	return &LeaveAdminHandler{
		policyService:       policyService,
		policyConfigService: policyConfigService,
		accrualService:      accrualService,
		logger:              logger,
	}
}

type CreateLeaveTypeRequest struct {
	Code              string `json:"code"`
	Name              string `json:"name"`
	IsPaid            bool   `json:"is_paid"`
	RequiresApproval  bool   `json:"requires_approval"`
	AccrualMethod     string `json:"accrual_method"`
	CarryForwardLimit *int   `json:"carry_forward_limit,omitempty"`
}

type UpdateLeaveTypeRequest struct {
	Name              *string `json:"name,omitempty"`
	IsPaid            *bool   `json:"is_paid,omitempty"`
	RequiresApproval  *bool   `json:"requires_approval,omitempty"`
	AccrualMethod     *string `json:"accrual_method,omitempty"`
	CarryForwardLimit *int    `json:"carry_forward_limit,omitempty"`
}

type CreateEntitlementRequest struct {
	UserID        uuid.UUID  `json:"user_id"`
	LeaveTypeID   uuid.UUID  `json:"leave_type_id"`
	TotalDays     int        `json:"total_days"`
	EffectiveFrom time.Time  `json:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty"`
}

type ProcessAccrualsRequest struct {
	AccrualDate time.Time `json:"accrual_date"`
}

func (h *LeaveAdminHandler) CreateLeaveType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "leave:policy:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req CreateLeaveTypeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Code == "" {
		h.respondWithError(w, http.StatusBadRequest, "leave type code is required")
		return
	}

	if req.Name == "" {
		h.respondWithError(w, http.StatusBadRequest, "leave type name is required")
		return
	}

	if req.AccrualMethod == "" {
		h.respondWithError(w, http.StatusBadRequest, "accrual method is required")
		return
	}

	createReq := &models.LeaveTypeCreate{
		CompanyID:         companyID,
		Code:              req.Code,
		Name:              req.Name,
		IsPaid:            req.IsPaid,
		RequiresApproval:  req.RequiresApproval,
		AccrualMethod:     req.AccrualMethod,
		CarryForwardLimit: req.CarryForwardLimit,
	}

	leaveType, err := h.policyService.CreateLeaveType(ctx, companyID, createReq)
	if err != nil {
		h.logger.Error("Failed to create leave type",
			zap.String("company_id", companyID.String()),
			zap.String("code", req.Code),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to create leave type")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    leaveType,
		"message": "Leave type created successfully",
	})
}

func (h *LeaveAdminHandler) UpdateLeaveType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	leaveTypeIDStr := chi.URLParam(r, "leaveTypeID")
	leaveTypeID, err := uuid.Parse(leaveTypeIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid leave type ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "leave:policy:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req UpdateLeaveTypeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	update := &models.LeaveTypeUpdate{
		Name:              req.Name,
		IsPaid:            req.IsPaid,
		RequiresApproval:  req.RequiresApproval,
		AccrualMethod:     req.AccrualMethod,
		CarryForwardLimit: req.CarryForwardLimit,
	}

	if err := h.policyService.UpdateLeaveType(ctx, leaveTypeID, update); err != nil {
		h.logger.Error("Failed to update leave type",
			zap.String("leave_type_id", leaveTypeID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to update leave type")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Leave type updated successfully",
	})
}

func (h *LeaveAdminHandler) GetLeaveType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	leaveTypeIDStr := chi.URLParam(r, "leaveTypeID")
	leaveTypeID, err := uuid.Parse(leaveTypeIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid leave type ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "leave:policy:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Get all leave types and filter by ID
	leaveTypes, err := h.policyService.GetLeaveTypesByCompany(ctx, companyID)
	if err != nil {
		h.logger.Error("Failed to get leave types",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve leave types")
		return
	}

	var leaveType *models.LeaveType
	for _, lt := range leaveTypes {
		if lt.LeaveTypeID == leaveTypeID {
			leaveType = lt
			break
		}
	}

	if leaveType == nil {
		h.respondWithError(w, http.StatusNotFound, "leave type not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    leaveType,
	})
}

func (h *LeaveAdminHandler) ListLeaveTypes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "leave:policy:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	leaveTypes, err := h.policyService.GetLeaveTypesByCompany(ctx, companyID)
	if err != nil {
		h.logger.Error("Failed to list leave types",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list leave types")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"leave_types":  leaveTypes,
			"total_count":  len(leaveTypes),
			"company_id":   companyID,
			"current_date": time.Now().UTC(),
		},
	})
}

func (h *LeaveAdminHandler) DeleteLeaveType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	leaveTypeIDStr := chi.URLParam(r, "leaveTypeID")
	leaveTypeID, err := uuid.Parse(leaveTypeIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid leave type ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "leave:policy:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if err := h.policyService.DeleteLeaveType(ctx, leaveTypeID); err != nil {
		h.logger.Error("Failed to delete leave type",
			zap.String("leave_type_id", leaveTypeID.String()),
			zap.Error(err))
		if err.Error() == "cannot delete leave type: it is being used in existing entitlements" {
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		} else {
			h.respondWithError(w, http.StatusInternalServerError, "failed to delete leave type")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Leave type deleted successfully",
	})
}

func (h *LeaveAdminHandler) CreateEntitlement(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "leave:entitlement:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req CreateEntitlementRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.UserID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "user ID is required")
		return
	}

	if req.LeaveTypeID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "leave type ID is required")
		return
	}

	if req.TotalDays <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "total days must be greater than 0")
		return
	}

	if req.EffectiveFrom.IsZero() {
		h.respondWithError(w, http.StatusBadRequest, "effective from date is required")
		return
	}

	entitlementReq := &models.LeaveEntitlementCreate{
		CompanyID:     companyID,
		UserID:        req.UserID,
		LeaveTypeID:   req.LeaveTypeID,
		TotalDays:     req.TotalDays,
		EffectiveFrom: req.EffectiveFrom,
		EffectiveTo:   req.EffectiveTo,
	}

	entitlement, err := h.policyService.AssignEntitlementToUser(ctx, entitlementReq)
	if err != nil {
		h.logger.Error("Failed to create leave entitlement",
			zap.String("user_id", req.UserID.String()),
			zap.String("leave_type_id", req.LeaveTypeID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to create entitlement")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    entitlement,
		"message": "Leave entitlement created successfully",
	})
}

func (h *LeaveAdminHandler) ProcessMonthlyAccruals(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "leave:accrual:process") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req ProcessAccrualsRequest

	// Try decoding body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AccrualDate.IsZero() {
		// If no body or empty date → use current month
		now := time.Now().UTC()
		req.AccrualDate = now
	}

	// ✅ ENTERPRISE FIX: Normalize to first day of month UTC
	normalized := time.Date(
		req.AccrualDate.Year(),
		req.AccrualDate.Month(),
		1,
		0, 0, 0, 0,
		time.UTC,
	)

	processed, err := h.accrualService.AccrueMonthlyLeave(ctx, companyID, normalized)
	if err != nil {
		h.logger.Error("Failed to process monthly accruals",
			zap.String("company_id", companyID.String()),
			zap.Time("accrual_date", normalized),
			zap.Error(err),
		)

		h.respondWithError(w, http.StatusInternalServerError, "failed to process accruals")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"processed_count": processed,
			"accrual_month":   normalized,
			"company_id":      companyID,
		},
		"message": "Monthly accruals processed successfully",
	})
}

func (h *LeaveAdminHandler) GetAccrualsByDate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	dateStr := r.URL.Query().Get("date")
	var date time.Time
	if dateStr == "" {
		date = time.Now().UTC()
	} else {
		date, err = time.Parse("2006-01-02", dateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid date format, use YYYY-MM-DD")
			return
		}
	}

	if !h.hasPermission(ctx, companyID, "leave:accrual:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	accruals, err := h.accrualService.GetAccrualsByDate(ctx, companyID, date)
	if err != nil {
		h.logger.Error("Failed to get accruals by date",
			zap.String("company_id", companyID.String()),
			zap.Time("date", date),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve accruals")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"accruals":    accruals,
			"date":        date,
			"total_count": len(accruals),
		},
	})
}

func (h *LeaveAdminHandler) RecalculateEntitlement(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	entitlementIDStr := chi.URLParam(r, "entitlementID")
	entitlementID, err := uuid.Parse(entitlementIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entitlement ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "leave:entitlement:recalculate") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	balance, err := h.accrualService.RecalculateEntitlement(ctx, entitlementID)
	if err != nil {
		h.logger.Error("Failed to recalculate entitlement",
			zap.String("entitlement_id", entitlementID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to recalculate entitlement")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    balance,
		"message": "Entitlement recalculated successfully",
	})
}

// Helper methods
func (h *LeaveAdminHandler) hasPermission(ctx interface{}, companyID uuid.UUID, permission string) bool {
	// TODO: Implement actual permission checking
	return true
}

func (h *LeaveAdminHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *LeaveAdminHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

type CreateLeavePolicyRequest struct {
	PolicyName              string     `json:"policy_name"`
	AppliesToType           string     `json:"applies_to_type"` // company | position | work_center
	AppliesToPositionID     *uuid.UUID `json:"applies_to_position_id,omitempty"`
	AppliesToWorkCenterCode *string    `json:"applies_to_work_center_code,omitempty"`
	Priority                int        `json:"priority"`
	EffectiveFrom           time.Time  `json:"effective_from"`
	EffectiveTo             *time.Time `json:"effective_to,omitempty"`
}

type AddPolicyRuleRequest struct {
	LeaveTypeID       uuid.UUID `json:"leave_type_id"`
	TotalDays         int       `json:"total_days"`
	AccrualMethod     string    `json:"accrual_method"`
	CarryForwardLimit *int      `json:"carry_forward_limit,omitempty"`
}

func (h *LeaveAdminHandler) CreateLeavePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID := uuid.MustParse(chi.URLParam(r, "companyID"))

	var req CreateLeavePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	policy := &models.LeavePolicy{
		CompanyID:               companyID,
		PolicyName:              req.PolicyName,
		AppliesToType:           req.AppliesToType,
		AppliesToPositionID:     req.AppliesToPositionID,
		AppliesToWorkCenterCode: req.AppliesToWorkCenterCode,
		Priority:                req.Priority,
		EffectiveFrom:           req.EffectiveFrom,
		EffectiveTo:             req.EffectiveTo,
	}

	created, err := h.policyConfigService.CreatePolicy(ctx, policy)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    created,
	})
}
func (h *LeaveAdminHandler) DeactivateLeavePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	policyID := uuid.MustParse(chi.URLParam(r, "policyID"))

	if err := h.policyConfigService.DeactivatePolicy(ctx, policyID); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Policy deactivated",
	})
}
func (h *LeaveAdminHandler) GetLeavePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	policyID := uuid.MustParse(chi.URLParam(r, "policyID"))

	policy, err := h.policyConfigService.GetPolicy(ctx, policyID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    policy,
	})
}
func (h *LeaveAdminHandler) ListActiveLeavePolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID := uuid.MustParse(chi.URLParam(r, "companyID"))

	asOf := time.Now().UTC()
	policies, err := h.policyConfigService.ListActivePolicies(ctx, companyID, asOf)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    policies,
	})
}

func (h *LeaveAdminHandler) AddPolicyRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	policyID := uuid.MustParse(chi.URLParam(r, "policyID"))

	var req AddPolicyRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	accrualMethod := req.AccrualMethod

	rule := &models.LeavePolicyRule{
		PolicyID:          policyID,
		LeaveTypeID:       req.LeaveTypeID,
		TotalDays:         req.TotalDays,
		AccrualMethod:     &accrualMethod, // ✅ FIX
		CarryForwardLimit: req.CarryForwardLimit,
	}

	created, err := h.policyConfigService.AddPolicyRule(ctx, rule)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    created,
	})
}
func (h *LeaveAdminHandler) GetPolicyRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	policyID := uuid.MustParse(chi.URLParam(r, "policyID"))

	rules, err := h.policyConfigService.GetPolicyRules(ctx, policyID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    rules,
	})
}
func (h *LeaveAdminHandler) DeletePolicyRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyRuleIDStr := chi.URLParam(r, "policyRuleID")
	policyRuleID, err := uuid.Parse(policyRuleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid policy_rule_id")
		return
	}

	if err := h.policyConfigService.RemovePolicyRule(ctx, policyRuleID); err != nil {
		h.logger.Error("Failed to delete policy rule",
			zap.String("policy_rule_id", policyRuleID.String()),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, "failed to delete policy rule")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Policy rule deleted successfully",
	})
}
func (h *LeaveAdminHandler) UpdateLeavePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyIDStr := chi.URLParam(r, "policyID")
	policyID, err := uuid.Parse(policyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid policy ID")
		return
	}

	var req UpdateLeavePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	update := &models.LeavePolicyUpdate{
		PolicyName:              req.PolicyName,
		AppliesToType:           req.AppliesToType,
		AppliesToPositionID:     req.AppliesToPositionID,
		AppliesToWorkCenterCode: req.AppliesToWorkCenterCode,
		Priority:                req.Priority,
		EffectiveFrom:           req.EffectiveFrom,
		EffectiveTo:             req.EffectiveTo,
		IsActive:                req.IsActive,
	}

	err = h.policyConfigService.UpdatePolicy(ctx, policyID, update)
	if err != nil {
		h.logger.Error("Failed to update leave policy",
			zap.String("policy_id", policyID.String()),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Leave policy updated successfully",
	})
}

type UpdateLeavePolicyRequest struct {
	PolicyName              *string    `json:"policy_name,omitempty"`
	AppliesToType           *string    `json:"applies_to_type,omitempty"`
	AppliesToPositionID     *uuid.UUID `json:"applies_to_position_id,omitempty"`
	AppliesToWorkCenterCode *string    `json:"applies_to_work_center_code,omitempty"`
	Priority                *int       `json:"priority,omitempty"`
	EffectiveFrom           *time.Time `json:"effective_from,omitempty"`
	EffectiveTo             *time.Time `json:"effective_to,omitempty"`
	IsActive                *bool      `json:"is_active,omitempty"`
}
type UpdatePolicyRuleRequest struct {
	TotalDays         *int    `json:"total_days,omitempty"`
	AccrualMethod     *string `json:"accrual_method,omitempty"`
	CarryForwardLimit *int    `json:"carry_forward_limit,omitempty"`
}

func (h *LeaveAdminHandler) UpdatePolicyRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	policyRuleIDStr := chi.URLParam(r, "policyRuleID")
	policyRuleID, err := uuid.Parse(policyRuleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid policy_rule_id")
		return
	}

	if !h.hasPermission(ctx, companyID, "leave:policy:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req UpdatePolicyRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	update := &models.LeavePolicyRuleUpdate{
		TotalDays:         req.TotalDays,
		AccrualMethod:     req.AccrualMethod,
		CarryForwardLimit: req.CarryForwardLimit,
	}

	if err := h.policyConfigService.UpdatePolicyRule(
		ctx,
		companyID,
		policyRuleID,
		update,
	); err != nil {
		h.logger.Error("Failed to update policy rule",
			zap.String("company_id", companyID.String()),
			zap.String("policy_rule_id", policyRuleID.String()),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Policy rule updated successfully",
	})
}
