package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/service/admin"
	"auth-service/internal/attendance/service/query"
	"auth-service/internal/infrastructure/audit"
)

// AttendanceAdminHandler handles attendance policy, rules, and assignment endpoints.
type AttendanceAdminHandler struct {
	adminService admin.AdminService
	queryService query.QueryService
	auditService *audit.AuditService
	logger       *zap.Logger
}

// NewAttendanceAdminHandler creates a new handler instance.
func NewAttendanceAdminHandler(
	adminService admin.AdminService,
	queryService query.QueryService,
	auditService *audit.AuditService,
	logger *zap.Logger,
) *AttendanceAdminHandler {
	return &AttendanceAdminHandler{
		adminService: adminService,
		queryService: queryService,
		auditService: auditService,
		logger:       logger,
	}
}

// ---- Request/Response DTOs ----

type PolicyRequest struct {
	PolicyCode     string             `json:"policy_code"`
	PolicyType     string             `json:"policy_type"`
	PositionID     *uuid.UUID         `json:"position_id,omitempty"`
	WorkCenterCode *string            `json:"work_center_code,omitempty"`
	Rules          models.PolicyRules `json:"rules"`
	IsActive       bool               `json:"is_active"`
	Description    *string            `json:"description,omitempty"`
}

// AssignPolicyRequest now supports polymorphic subjects.
type AssignPolicyRequest struct {
	// Legacy employee assignment (backward compatible)
	UserID        uuid.UUID  `json:"user_id,omitempty"`
	PolicyID      uuid.UUID  `json:"policy_id"`
	EffectiveFrom time.Time  `json:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty"`

	// NEW: Polymorphic subject fields (for students, teachers, etc.)
	SubjectType string     `json:"subject_type,omitempty"` // "employee", "student", "teacher", etc.
	SubjectID   *uuid.UUID `json:"subject_id,omitempty"`   // ID of the subject
}

type CompanyRulesRequest struct {
	AllowedSourceTypes    []string `json:"allowed_source_types"`
	AllowMultipleCheckins bool     `json:"allow_multiple_checkins"`
	Timezone              string   `json:"timezone"`
}

// ---- Handlers ----

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

	// Validate assignment
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

	policy := &models.AttendancePolicy{
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

	// Apply filters
	var filteredPolicies []*models.AttendancePolicy
	for _, policy := range policies {
		if positionIDStr != "" {
			if policy.PositionID == nil {
				continue
			}
			posID, err := uuid.Parse(positionIDStr)
			if err != nil || *policy.PositionID != posID {
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

// AssignPolicyToUser handles both legacy employee assignments and polymorphic subject assignments.
func (h *AttendanceAdminHandler) AssignPolicyToUser(w http.ResponseWriter, r *http.Request) {
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

	var req AssignPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.PolicyID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "policy_id is required")
		return
	}
	if req.EffectiveFrom.IsZero() {
		req.EffectiveFrom = time.Now().UTC()
	}

	// Determine which assignment method to use
	// Case 1: Polymorphic assignment (subject_type and subject_id provided)
	if req.SubjectType != "" && req.SubjectID != nil && *req.SubjectID != uuid.Nil {
		// Use the new polymorphic method
		err = h.adminService.AssignPolicyToSubject(
			ctx,
			req.SubjectType,
			*req.SubjectID,
			req.PolicyID,
			req.EffectiveFrom,
			req.EffectiveTo,
			&actorID,
		)
		if err != nil {
			h.logger.Error("Failed to assign policy to subject",
				zap.String("subject_type", req.SubjectType),
				zap.String("subject_id", req.SubjectID.String()),
				zap.String("policy_id", req.PolicyID.String()),
				zap.Error(err))
			h.respondWithError(w, http.StatusInternalServerError, "failed to assign policy")
			return
		}

		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "Policy assigned to subject successfully",
			"data": map[string]interface{}{
				"subject_type":   req.SubjectType,
				"subject_id":     req.SubjectID,
				"policy_id":      req.PolicyID,
				"effective_from": req.EffectiveFrom,
				"assigned_by":    actorID,
			},
		})
		return
	}

	// Case 2: Legacy employee assignment (user_id provided)
	if req.UserID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "either user_id or (subject_type + subject_id) is required")
		return
	}

	userPolicy := &models.UserAttendancePolicy{
		UserID:        req.UserID,
		PolicyID:      req.PolicyID,
		EffectiveFrom: req.EffectiveFrom,
		EffectiveTo:   req.EffectiveTo,
		CreatedAt:     time.Now().UTC(),
		// The service will populate SubjectType='employee' and SubjectID=userID
	}

	metadata := map[string]interface{}{
		"ip_address":     r.RemoteAddr,
		"user_agent":     r.UserAgent(),
		"endpoint":       r.URL.Path,
		"request_method": r.Method,
		"company_id":     companyID,
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
		"message": "Policy assigned to user successfully",
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

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	rules, err := h.adminService.GetCompanyAttendanceRules(ctx, companyID)
	if err != nil {
		h.logger.Error("Failed to get company attendance rules",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve company rules")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    rules,
	})
}

func (h *AttendanceAdminHandler) UpdateCompanyRules(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	if actorType != "admin" {
		h.respondWithError(w, http.StatusForbidden, "only admins can update company attendance rules")
		return
	}

	var req CompanyRulesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Timezone == "" {
		req.Timezone = "UTC"
	}

	rules := &models.CompanyAttendanceRules{
		CompanyID:             companyID,
		AllowedSourceTypes:    req.AllowedSourceTypes,
		AllowMultipleCheckins: req.AllowMultipleCheckins,
		Timezone:              req.Timezone,
	}

	if err := h.adminService.UpdateCompanyAttendanceRules(ctx, rules, actorID); err != nil {
		h.logger.Error("Failed to update company attendance rules",
			zap.String("company_id", companyID.String()),
			zap.String("actor_id", actorID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to update company rules")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    rules,
		"message": "Company attendance rules updated successfully",
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

// ---------------------------------------------------------------------
// CHANGED: GetResolvedRules now accepts subject_type query param
// ---------------------------------------------------------------------
func (h *AttendanceAdminHandler) GetResolvedRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userIDStr := r.URL.Query().Get("user_id")
	var userID uuid.UUID
	if userIDStr != "" {
		userID, err = uuid.Parse(userIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid user ID")
			return
		}
	}
	workCenterCode := r.URL.Query().Get("work_center_code")
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

	subjectType := r.URL.Query().Get("subject_type")
	if subjectType == "" {
		subjectType = "employee"
	}

	rules, err := h.adminService.ResolveAttendanceRules(ctx, userID, companyID, subjectType, workCenterCode, positionID, date)
	if err != nil {
		h.logger.Error("Failed to resolve attendance rules",
			zap.String("company_id", companyID.String()),
			zap.String("user_id", userID.String()),
			zap.String("subject_type", subjectType),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to resolve attendance rules")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    rules,
	})
}

// ---- Helper functions ----

func (h *AttendanceAdminHandler) getActorInfo(ctx context.Context) (string, uuid.UUID, error) {
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		return "", uuid.Nil, err
	}
	actorType := getSessionTypeFromContext(ctx)
	return actorType, actorID, nil
}

// getCompanyIDFromContext extracts the company UUID from the context.
func getCompanyIDFromContext(ctx context.Context) (uuid.UUID, error) {
	if v := ctx.Value("company_id"); v != nil {
		if id, ok := v.(uuid.UUID); ok {
			return id, nil
		}
		return uuid.Nil, errors.New("invalid company_id type")
	}
	return uuid.Nil, errors.New("company_id not found in context")
}

// getUserIDFromContext extracts the user UUID from context.
func getUserIDFromContext(ctx context.Context) (uuid.UUID, error) {
	if v := ctx.Value("current_user_id"); v != nil {
		if id, ok := v.(uuid.UUID); ok {
			return id, nil
		}
	}
	if v := ctx.Value("user_id"); v != nil {
		switch raw := v.(type) {
		case uuid.UUID:
			return raw, nil
		case string:
			return uuid.Parse(raw)
		default:
			return uuid.Nil, errors.New("invalid user_id type")
		}
	}
	return uuid.Nil, errors.New("user not authenticated")
}

func getSessionTypeFromContext(ctx context.Context) string {
	if v := ctx.Value("session_type"); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return "user"
}

// ---- Response helpers ----

func (h *AttendanceAdminHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *AttendanceAdminHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
