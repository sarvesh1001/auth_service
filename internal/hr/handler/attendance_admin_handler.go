package handler

import (
	"auth-service/internal/hr/models/attendance"
	"auth-service/internal/hr/service"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type AttendanceAdminHandler struct {
	adminService service.AttendanceAdminService
	queryService service.AttendanceQueryService
	auditService *service.AuditService
	logger       *zap.Logger
}

func NewAttendanceAdminHandler(
	adminService service.AttendanceAdminService,
	queryService service.AttendanceQueryService,
	auditService *service.AuditService,
	logger *zap.Logger,
) *AttendanceAdminHandler {
	return &AttendanceAdminHandler{
		adminService: adminService,
		queryService: queryService,
		auditService: auditService,
		logger:       logger,
	}
}

type PolicyRequest struct {
	PolicyCode     string                 `json:"policy_code"`
	PolicyType     string                 `json:"policy_type"`
	PositionID     *uuid.UUID             `json:"position_id,omitempty"`
	WorkCenterCode *string                `json:"work_center_code,omitempty"`
	Rules          attendance.PolicyRules `json:"rules"`
	IsActive       bool                   `json:"is_active"`
	Description    *string                `json:"description,omitempty"`
}

type AssignPolicyRequest struct {
	UserID        uuid.UUID  `json:"user_id"`
	PolicyID      uuid.UUID  `json:"policy_id"`
	EffectiveFrom time.Time  `json:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty"`
}

type CompanyRulesRequest struct {
	AllowedSourceTypes    []string `json:"allowed_source_types"`
	AllowMultipleCheckins bool     `json:"allow_multiple_checkins"`
	Timezone              string   `json:"timezone"`
}

type DepartmentRulesRequest struct {
	DepartmentID       uuid.UUID `json:"department_id"`
	AllowedSourceTypes []string  `json:"allowed_source_types"`
	AllowedEventTypes  []string  `json:"allowed_event_types"`
	RequireLocation    bool      `json:"require_location"`
	RequireDevice      bool      `json:"require_device"`
}

type RFIDAssignmentRequest struct {
	UserID    uuid.UUID `json:"user_id"`
	RFIDTag   string    `json:"rfid_tag"`
	Assigner  uuid.UUID `json:"assigner"`
	ValidFrom time.Time `json:"valid_from"`
	ValidTo   time.Time `json:"valid_to,omitempty"`
}

func (h *AttendanceAdminHandler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req PolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.PositionID != nil && req.WorkCenterCode != nil && *req.WorkCenterCode != "" {
		h.respondWithError(w, http.StatusBadRequest,
			"policy can be assigned to either position or work center, not both")
		return
	}

	if req.PositionID == nil && (req.WorkCenterCode == nil || *req.WorkCenterCode == "") {
		h.respondWithError(w, http.StatusBadRequest,
			"either position_id or work_center_code is required")
		return
	}

	if req.PolicyCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "policy code is required")
		return
	}

	if req.PolicyType == "" {
		h.respondWithError(w, http.StatusBadRequest, "policy type is required")
		return
	}

	policy := &attendance.AttendancePolicy{
		PolicyID:       uuid.New(),
		CompanyID:      companyID,
		PositionID:     req.PositionID,
		WorkCenterCode: req.WorkCenterCode,
		PolicyCode:     req.PolicyCode,
		PolicyType:     req.PolicyType,
		Rules:          req.Rules,
		IsActive:       req.IsActive,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}

	metadata := map[string]interface{}{
		"ip_address":     r.RemoteAddr,
		"user_agent":     r.UserAgent(),
		"endpoint":       r.URL.Path,
		"request_method": r.Method,
	}

	createdPolicy, err := h.adminService.CreateAttendancePolicy(ctx, policy, actorType, actorID, metadata)
	if err != nil {
		h.logger.Error("Failed to create attendance policy",
			zap.String("policy_code", req.PolicyCode),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to create policy")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    createdPolicy,
		"message": "Policy created successfully",
	})
}

func (h *AttendanceAdminHandler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	policyIDStr := chi.URLParam(r, "policyID")
	policyID, err := uuid.Parse(policyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid policy ID")
		return
	}

	policy, err := h.queryService.GetAttendancePolicyByID(ctx, policyID)
	if err != nil {
		h.logger.Error("Failed to get attendance policy",
			zap.String("policy_id", policyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve policy")
		return
	}

	if policy == nil {
		h.respondWithError(w, http.StatusNotFound, "policy not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    policy,
	})
}

func (h *AttendanceAdminHandler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	activeOnly := true
	if r.URL.Query().Get("include_inactive") == "true" {
		activeOnly = false
	}

	positionIDStr := r.URL.Query().Get("position_id")
	workCenterCode := r.URL.Query().Get("work_center_code")

	policies, err := h.queryService.GetAttendancePoliciesByCompany(ctx, companyID, activeOnly)
	if err != nil {
		h.logger.Error("Failed to list attendance policies",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list policies")
		return
	}

	var filteredPolicies []*attendance.AttendancePolicy
	for _, policy := range policies {
		if positionIDStr != "" {
			if policy.PositionID == nil {
				continue
			}
			positionID, err := uuid.Parse(positionIDStr)
			if err != nil || *policy.PositionID != positionID {
				continue
			}
		}
		if workCenterCode != "" {
			if policy.WorkCenterCode == nil || *policy.WorkCenterCode != workCenterCode {
				continue
			}
		}
		filteredPolicies = append(filteredPolicies, policy)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"policies":         filteredPolicies,
			"total_count":      len(filteredPolicies),
			"company_id":       companyID,
			"active_only":      activeOnly,
			"position_id":      positionIDStr,
			"work_center_code": workCenterCode,
			"current_date":     time.Now().UTC(),
		},
	})
}

func (h *AttendanceAdminHandler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	policyIDStr := chi.URLParam(r, "policyID")
	policyID, err := uuid.Parse(policyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid policy ID")
		return
	}

	existingPolicy, err := h.queryService.GetAttendancePolicyByID(ctx, policyID)
	if err != nil {
		h.logger.Error("Failed to get existing policy",
			zap.String("policy_id", policyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve policy")
		return
	}

	if existingPolicy == nil {
		h.respondWithError(w, http.StatusNotFound, "policy not found")
		return
	}

	var req PolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.PositionID != nil && req.WorkCenterCode != nil && *req.WorkCenterCode != "" {
		h.respondWithError(w, http.StatusBadRequest,
			"policy can be assigned to either position or work center, not both")
		return
	}

	if req.PositionID == nil && (req.WorkCenterCode == nil || *req.WorkCenterCode == "") {
		h.respondWithError(w, http.StatusBadRequest,
			"either position_id or work_center_code is required")
		return
	}

	existingPolicy.PolicyCode = req.PolicyCode
	existingPolicy.PolicyType = req.PolicyType
	existingPolicy.PositionID = req.PositionID
	existingPolicy.WorkCenterCode = req.WorkCenterCode
	existingPolicy.Rules = req.Rules
	existingPolicy.IsActive = req.IsActive
	existingPolicy.UpdatedAt = time.Now().UTC()

	if err := h.adminService.UpdateAttendancePolicy(ctx, existingPolicy); err != nil {
		h.logger.Error("Failed to update attendance policy",
			zap.String("policy_id", policyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to update policy")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    existingPolicy,
		"message": "Policy updated successfully",
	})
}

func (h *AttendanceAdminHandler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	policyIDStr := chi.URLParam(r, "policyID")
	policyID, err := uuid.Parse(policyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid policy ID")
		return
	}

	if err := h.adminService.DeleteAttendancePolicy(ctx, policyID); err != nil {
		h.logger.Error("Failed to delete attendance policy",
			zap.String("policy_id", policyID.String()),
			zap.Error(err))
		if strings.Contains(err.Error(), "cannot delete policy assigned to users") {
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		} else {
			h.respondWithError(w, http.StatusInternalServerError, "failed to delete policy")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Policy deleted successfully",
	})
}

func (h *AttendanceAdminHandler) AssignPolicyToUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req AssignPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.UserID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "user ID is required")
		return
	}

	if req.PolicyID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "policy ID is required")
		return
	}

	if req.EffectiveFrom.IsZero() {
		req.EffectiveFrom = time.Now().UTC()
	}

	userPolicy := &attendance.UserAttendancePolicy{
		UserID:        req.UserID,
		PolicyID:      req.PolicyID,
		EffectiveFrom: req.EffectiveFrom,
		EffectiveTo:   req.EffectiveTo,
		CreatedAt:     time.Now().UTC(),
	}

	metadata := map[string]interface{}{
		"ip_address":     r.RemoteAddr,
		"user_agent":     r.UserAgent(),
		"endpoint":       r.URL.Path,
		"request_method": r.Method,
	}

	if err := h.adminService.AssignUserAttendancePolicy(ctx, userPolicy, actorType, actorID, metadata); err != nil {
		h.logger.Error("Failed to assign policy to user",
			zap.String("user_id", req.UserID.String()),
			zap.String("policy_id", req.PolicyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to assign policy")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Policy assigned successfully",
		"data": map[string]interface{}{
			"user_id":        req.UserID,
			"policy_id":      req.PolicyID,
			"effective_from": req.EffectiveFrom,
			"assigned_by":    actorID,
		},
	})
}

func (h *AttendanceAdminHandler) GetCompanyRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// ---- companyID from URL ----
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	// ---- fetch rules ----
	rules, err := h.adminService.GetCompanyAttendanceRules(ctx, companyID)
	if err != nil {
		h.logger.Error(
			"Failed to get company attendance rules",
			zap.String("company_id", companyID.String()),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve company rules")
		return
	}

	// ---- response ----
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    rules,
	})
}

func (h *AttendanceAdminHandler) UpdateCompanyRules(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// ---- companyID from URL ----
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// ---- actor info ----
	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// ---- admin-only ----
	if actorType != "admin" {
		h.respondWithError(w, http.StatusForbidden, "only admins can update company attendance rules")
		return
	}

	// ---- decode request ----
	var req CompanyRulesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Timezone == "" {
		req.Timezone = "UTC"
	}

	// ---- build rules ----
	rules := &attendance.CompanyAttendanceRules{
		CompanyID:             companyID,
		AllowedSourceTypes:    req.AllowedSourceTypes,
		AllowMultipleCheckins: req.AllowMultipleCheckins,
		Timezone:              req.Timezone,
	}

	// ---- update ----
	if err := h.adminService.UpdateCompanyAttendanceRules(ctx, rules, actorID); err != nil {
		h.logger.Error(
			"Failed to update company attendance rules",
			zap.String("company_id", companyID.String()),
			zap.String("actor_id", actorID.String()),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, "Failed to update company rules")
		return
	}

	// ---- response ----
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    rules,
		"message": "Company attendance rules updated successfully",
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

func (h *AttendanceAdminHandler) GetResolvedRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// ---- companyID from URL ----
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	// ---- optional user ----
	userIDStr := r.URL.Query().Get("user_id")
	var userID uuid.UUID
	if userIDStr != "" {
		userID, err = uuid.Parse(userIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid user ID")
			return
		}
	}

	// ---- optional work center ----
	workCenterCode := r.URL.Query().Get("work_center_code")

	// ---- date ----
	dateStr := r.URL.Query().Get("date")
	var date time.Time
	if dateStr == "" {
		date = time.Now()
	} else {
		date, err = time.Parse("2006-01-02", dateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid date format, use YYYY-MM-DD")
			return
		}
	}

	// ---- optional position ----
	positionIDStr := r.URL.Query().Get("position_id")
	var positionID *uuid.UUID
	if positionIDStr != "" {
		parsedID, err := uuid.Parse(positionIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid position ID")
			return
		}
		positionID = &parsedID
	}

	// ---- resolve rules ----
	rules, err := h.adminService.ResolveAttendanceRules(
		ctx,
		userID,
		companyID,
		workCenterCode,
		positionID,
		date,
	)
	if err != nil {
		h.logger.Error(
			"Failed to resolve attendance rules",
			zap.String("company_id", companyID.String()),
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, "failed to resolve attendance rules")
		return
	}

	// ---- response ----
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    rules,
	})
}

func (h *AttendanceAdminHandler) getActorInfo(ctx context.Context) (string, uuid.UUID, error) {
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		return "", uuid.Nil, err
	}
	actorType := getSessionTypeFromContext(ctx)
	return actorType, actorID, nil
}

func getUserIDFromContext(ctx context.Context) (uuid.UUID, error) {
	rawUserID := ctx.Value("user_id")
	if rawUserID == nil {
		return uuid.Nil, errors.New("user_id not found in context")
	}
	switch v := rawUserID.(type) {
	case uuid.UUID:
		return v, nil
	case string:
		return uuid.Parse(v)
	default:
		return uuid.Nil, errors.New("invalid user_id type in context")
	}
}

func getSessionTypeFromContext(ctx context.Context) string {
	sessionType, ok := ctx.Value("session_type").(string)
	if !ok {
		return "user"
	}
	return sessionType
}

func (h *AttendanceAdminHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *AttendanceAdminHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
