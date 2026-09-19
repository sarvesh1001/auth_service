package handler

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"auth-service/internal/hr/leave/service"
	"auth-service/internal/locationctx"
)

type LeavePolicyResolutionHandler struct {
	policyResolutionService service.LeavePolicyResolutionService
}

func NewLeavePolicyResolutionHandler(
	policyResolutionService service.LeavePolicyResolutionService,
) *LeavePolicyResolutionHandler {
	return &LeavePolicyResolutionHandler{
		policyResolutionService: policyResolutionService,
	}
}

// ----- helpers -----

func (h *LeavePolicyResolutionHandler) getActor(ctx context.Context) (actorType string, actorID uuid.UUID, err error) {
	actorID, err = getUserIDFromContext(ctx)
	if err != nil {
		return "", uuid.Nil, err
	}
	actorType = "admin"
	return actorType, actorID, nil
}

func (h *LeavePolicyResolutionHandler) getMetadata(ctx context.Context) map[string]interface{} {
	meta := make(map[string]interface{})
	if ip, ok := ctx.Value("ip_address").(string); ok {
		meta["ip_address"] = ip
	}
	return meta
}

// ----- request types -----

type ResolveSingleUserRequest struct {
	AsOf   *time.Time `json:"as_of,omitempty"`
	Reason string     `json:"reason"`
}

type ResolveBatchRequest struct {
	UserIDs []uuid.UUID `json:"user_ids"`
	AsOf    *time.Time  `json:"as_of,omitempty"`
	Reason  string      `json:"reason"`
}

type OnboardingRequest struct {
	CompanyID uuid.UUID `json:"company_id"`
	UserID    uuid.UUID `json:"user_id"`
	JoinedAt  time.Time `json:"joined_at"`
}

type PositionChangeRequest struct {
	CompanyID uuid.UUID `json:"company_id"`
	UserID    uuid.UUID `json:"user_id"`
	ChangedAt time.Time `json:"changed_at"`
}

// ----- handlers -----

// ResolveSingleUser - POST /companies/{companyID}/leave/admin/policies/resolve/user/{userID}
func (h *LeavePolicyResolutionHandler) ResolveSingleUser(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

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

	actorType, actorID, err := h.getActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	metadata := h.getMetadata(ctx)

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

	if err := h.policyResolutionService.ResolveUserLeaveEntitlements(
		ctx, companyID, userID, asOf, reason, actorType, actorID, metadata,
	); err != nil {
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
func (h *LeavePolicyResolutionHandler) ResolveBatchUsers(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	actorType, actorID, err := h.getActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	metadata := h.getMetadata(ctx)

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

	result, err := h.policyResolutionService.ResolveBatchLeaveEntitlements(
		ctx, companyID, req.UserIDs, asOf, reason, actorType, actorID, metadata,
	)
	if err != nil {
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
	ctx := injectCommonContext(r.Context(), r)

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

	asOfStr := r.URL.Query().Get("as_of")
	asOf := time.Now().UTC()
	if asOfStr != "" {
		parsed, err := time.Parse("2006-01-02", asOfStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid as_of format, use YYYY-MM-DD")
			return
		}
		asOf = parsed
	}

	policies, err := h.policyResolutionService.GetUserEffectivePolicies(ctx, companyID, userID, asOf)
	if err != nil {
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

// ResolveOnboarding - POST /internal/leave/resolve/onboarding
func (h *LeavePolicyResolutionHandler) ResolveOnboarding(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

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

	actorType := "system"
	actorID := uuid.Nil
	metadata := h.getMetadata(ctx)

	if err := h.policyResolutionService.ResolveUserLeaveEntitlements(
		ctx, req.CompanyID, req.UserID, req.JoinedAt, "employee onboarding", actorType, actorID, metadata,
	); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "failed to resolve leave entitlements for onboarding")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Leave entitlements resolved for onboarding",
	})
}

// ResolvePositionChange - POST /internal/leave/resolve/position-change
func (h *LeavePolicyResolutionHandler) ResolvePositionChange(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

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

	actorType := "system"
	actorID := uuid.Nil
	metadata := h.getMetadata(ctx)

	if err := h.policyResolutionService.ResolveUserLeaveEntitlements(
		ctx, req.CompanyID, req.UserID, req.ChangedAt, "position change", actorType, actorID, metadata,
	); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "failed to resolve leave entitlements for position change")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Leave entitlements resolved for position change",
	})
}

// ListEntitlements - GET /companies/{companyID}/leave/admin/entitlements
//
// Reads the request's location scope and passes it to the service.
// nil = company-wide (X-Location-ID: ALL).
func (h *LeavePolicyResolutionHandler) ListEntitlements(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	var userID *uuid.UUID
	if v := r.URL.Query().Get("user_id"); v != "" {
		uid, err := uuid.Parse(v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid user ID format")
			return
		}
		userID = &uid
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	// 👇 Location scope filter.
	locFilter := locationctx.Filter(ctx)

	entitlements, total, err := h.policyResolutionService.GetLeaveEntitlements(
		ctx, companyID, userID, locFilter, page, pageSize)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "failed to list leave entitlements")
		return
	}

	enriched := make([]map[string]interface{}, len(entitlements))
	for i, e := range entitlements {
		enriched[i] = map[string]interface{}{
			"entitlement_id": e.EntitlementID,
			"company_id":     e.CompanyID,
			"user_id":        e.UserID,
			"leave_type_id":  e.LeaveTypeID,
			"total_days":     e.TotalDays,
			"effective_from": e.EffectiveFrom,
			"effective_to":   e.EffectiveTo,
			"source":         e.Source,
			"policy_id":      e.PolicyID,
			"created_at":     e.CreatedAt,
			"updated_at":     e.UpdatedAt,
		}
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"entitlements": enriched,
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

// ----- response helpers -----

func (h *LeavePolicyResolutionHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *LeavePolicyResolutionHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
