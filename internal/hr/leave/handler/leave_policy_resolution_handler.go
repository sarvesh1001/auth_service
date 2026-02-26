package handler

import (
	"auth-service/internal/hr/leave/service"
	"auth-service/internal/util"
	"encoding/json"
	"math" // ✅ ADD THIS
	"net/http"
	"strconv" // ✅ ADD THIS
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type LeavePolicyResolutionHandler struct {
	policyResolutionService service.LeavePolicyResolutionService
	logger                  *zap.Logger
}

func NewLeavePolicyResolutionHandler(
	policyResolutionService service.LeavePolicyResolutionService,
	logger *zap.Logger,
) *LeavePolicyResolutionHandler {
	return &LeavePolicyResolutionHandler{
		policyResolutionService: policyResolutionService,
		logger:                  logger.Named("leave_policy_resolution_handler"),
	}
}

// ResolveSingleUser - POST /companies/{companyID}/leave/admin/policies/resolve/user/{userID}
type ResolveSingleUserRequest struct {
	AsOf   *time.Time `json:"as_of,omitempty"`
	Reason string     `json:"reason"`
}

func (h *LeavePolicyResolutionHandler) ResolveSingleUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	var req ResolveSingleUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	asOf := time.Now().UTC()
	if req.AsOf != nil {
		asOf = *req.AsOf
	}

	reason := req.Reason
	if reason == "" {
		reason = "manual resolution triggered by admin"
	}

	h.logger.Info("Resolving leave entitlements for single user",
		util.String("company_id", companyID.String()),
		util.String("user_id", userID.String()),
		util.Time("as_of", asOf),
		util.String("reason", reason),
	)

	if err := h.policyResolutionService.ResolveUserLeaveEntitlements(
		ctx,
		companyID,
		userID,
		asOf,
		reason,
	); err != nil {
		h.logger.Error("Failed to resolve leave entitlements for user",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.ErrorField(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, "failed to resolve leave entitlements")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Leave entitlements resolved successfully",
		"data": map[string]interface{}{
			"company_id": companyID,
			"user_id":    userID,
			"as_of":      asOf,
			"reason":     reason,
		},
	})
}

// ResolveBatchUsers - POST /companies/{companyID}/leave/admin/policies/resolve/batch
type ResolveBatchRequest struct {
	UserIDs []uuid.UUID `json:"user_ids"`
	AsOf    *time.Time  `json:"as_of,omitempty"`
	Reason  string      `json:"reason"`
}

func (h *LeavePolicyResolutionHandler) ResolveBatchUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	var req ResolveBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.UserIDs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one user ID is required")
		return
	}

	asOf := time.Now().UTC()
	if req.AsOf != nil {
		asOf = *req.AsOf
	}

	reason := req.Reason
	if reason == "" {
		reason = "batch resolution triggered by admin"
	}

	h.logger.Info("Resolving leave entitlements for batch users",
		util.String("company_id", companyID.String()),
		util.Int("user_count", len(req.UserIDs)),
		util.Time("as_of", asOf),
		util.String("reason", reason),
	)

	result, err := h.policyResolutionService.ResolveBatchLeaveEntitlements(
		ctx,
		companyID,
		req.UserIDs,
		asOf,
		reason,
	)
	if err != nil {
		h.logger.Error("Failed to resolve batch leave entitlements",
			util.String("company_id", companyID.String()),
			util.ErrorField(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, "failed to resolve batch leave entitlements")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Batch leave entitlements resolved successfully",
		"data":    result,
	})
}

// GetEffectivePolicies - GET /companies/{companyID}/leave/admin/policies/effective/{userID}
func (h *LeavePolicyResolutionHandler) GetEffectivePolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	// Parse optional as_of parameter
	asOfStr := r.URL.Query().Get("as_of")
	asOf := time.Now().UTC()
	if asOfStr != "" {
		parsedAsOf, err := time.Parse("2006-01-02", asOfStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid as_of format, use YYYY-MM-DD")
			return
		}
		asOf = parsedAsOf
	}

	h.logger.Debug("Getting effective policies for user",
		util.String("company_id", companyID.String()),
		util.String("user_id", userID.String()),
		util.Time("as_of", asOf),
	)

	policies, err := h.policyResolutionService.GetUserEffectivePolicies(
		ctx,
		companyID,
		userID,
		asOf,
	)
	if err != nil {
		h.logger.Error("Failed to get effective policies",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.ErrorField(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, "failed to get effective policies")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"policies":   policies,
			"company_id": companyID,
			"user_id":    userID,
			"as_of":      asOf,
			"count":      len(policies),
		},
	})
}

// Internal handler for automation events

// ResolveOnboarding - POST /internal/leave/resolve/onboarding
type OnboardingRequest struct {
	CompanyID uuid.UUID `json:"company_id"`
	UserID    uuid.UUID `json:"user_id"`
	JoinedAt  time.Time `json:"joined_at"`
}

func (h *LeavePolicyResolutionHandler) ResolveOnboarding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req OnboardingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.CompanyID == uuid.Nil || req.UserID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "company_id and user_id are required")
		return
	}

	if req.JoinedAt.IsZero() {
		req.JoinedAt = time.Now().UTC()
	}

	h.logger.Info("Resolving leave entitlements for onboarding",
		util.String("company_id", req.CompanyID.String()),
		util.String("user_id", req.UserID.String()),
		util.Time("joined_at", req.JoinedAt),
	)

	if err := h.policyResolutionService.ResolveUserLeaveEntitlements(
		ctx,
		req.CompanyID,
		req.UserID,
		req.JoinedAt,
		"employee onboarding",
	); err != nil {
		h.logger.Error("Failed to resolve leave entitlements for onboarding",
			util.String("company_id", req.CompanyID.String()),
			util.String("user_id", req.UserID.String()),
			util.ErrorField(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, "failed to resolve leave entitlements for onboarding")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Leave entitlements resolved for onboarding",
	})
}

// ResolvePositionChange - POST /internal/leave/resolve/position-change
type PositionChangeRequest struct {
	CompanyID uuid.UUID `json:"company_id"`
	UserID    uuid.UUID `json:"user_id"`
	ChangedAt time.Time `json:"changed_at"`
}

func (h *LeavePolicyResolutionHandler) ResolvePositionChange(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req PositionChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.CompanyID == uuid.Nil || req.UserID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "company_id and user_id are required")
		return
	}

	if req.ChangedAt.IsZero() {
		req.ChangedAt = time.Now().UTC()
	}

	h.logger.Info("Resolving leave entitlements for position change",
		util.String("company_id", req.CompanyID.String()),
		util.String("user_id", req.UserID.String()),
		util.Time("changed_at", req.ChangedAt),
	)

	if err := h.policyResolutionService.ResolveUserLeaveEntitlements(
		ctx,
		req.CompanyID,
		req.UserID,
		req.ChangedAt,
		"position change",
	); err != nil {
		h.logger.Error("Failed to resolve leave entitlements for position change",
			util.String("company_id", req.CompanyID.String()),
			util.String("user_id", req.UserID.String()),
			util.ErrorField(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, "failed to resolve leave entitlements for position change")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Leave entitlements resolved for position change",
	})
}

// ListEntitlements - GET /companies/{companyID}/leave/admin/entitlements
// Update ListEntitlements in handler/leave_policy_resolution.go
func (h *LeavePolicyResolutionHandler) ListEntitlements(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	// Parse query parameters
	var userID *uuid.UUID
	userIDStr := r.URL.Query().Get("user_id")
	if userIDStr != "" {
		uid, err := uuid.Parse(userIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid user ID format")
			return
		}
		userID = &uid
	}

	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	}

	pageSize, err := strconv.Atoi(r.URL.Query().Get("page_size"))
	if err != nil || pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	entitlements, total, err := h.policyResolutionService.GetLeaveEntitlements(
		ctx, companyID, userID, page, pageSize,
	)
	if err != nil {
		h.logger.Error("Failed to list leave entitlements",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list leave entitlements")
		return
	}

	// Enrich with leave type info if needed
	enrichedEntitlements := make([]map[string]interface{}, len(entitlements))
	for i, entitlement := range entitlements {
		enriched := map[string]interface{}{
			"entitlement_id": entitlement.EntitlementID,
			"company_id":     entitlement.CompanyID,
			"user_id":        entitlement.UserID,
			"leave_type_id":  entitlement.LeaveTypeID,
			"total_days":     entitlement.TotalDays,
			"effective_from": entitlement.EffectiveFrom,
			"effective_to":   entitlement.EffectiveTo,
			"source":         entitlement.Source,
			"policy_id":      entitlement.PolicyID,
			"created_at":     entitlement.CreatedAt,
			"updated_at":     entitlement.UpdatedAt,
		}
		enrichedEntitlements[i] = enriched
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"entitlements": enrichedEntitlements,
			"pagination": map[string]interface{}{
				"page":        page,
				"page_size":   pageSize,
				"total":       total,
				"total_pages": int(math.Ceil(float64(total) / float64(pageSize))),
			},
			"company_id": companyID,
			"user_id":    userID,
		},
	})
}

func (h *LeavePolicyResolutionHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *LeavePolicyResolutionHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
