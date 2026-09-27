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

type ResolveAllUsersRequest struct {
	AsOf   *time.Time `json:"as_of,omitempty"`
	Reason string     `json:"reason"`
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

// ResolveSingleUser — unchanged. Synchronous, one user, small blast radius.
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

// ResolveBatchUsers — ASYNC. Enqueues one resolve_user job per user and
// returns 202 Accepted immediately. The resolver worker does the work.
//
// Batch size is capped at 1000 — anything larger is an ops problem, not a
// UI action. Over-cap returns 400.
func (h *LeavePolicyResolutionHandler) ResolveBatchUsers(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	// Auth check still runs — the audit log should record who queued it.
	if _, _, err := h.getActor(ctx); err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
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
	const maxBatch = 1000
	if len(req.UserIDs) > maxBatch {
		h.respondWithError(w, http.StatusBadRequest, "batch size exceeds limit")
		return
	}

	reason := req.Reason
	if reason == "" {
		reason = "batch resolution triggered by admin"
	}

	if err := h.policyResolutionService.EnqueueUserResolutionJobs(
		ctx, companyID, req.UserIDs, reason,
	); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "failed to enqueue resolution jobs")
		return
	}

	h.respondWithJSON(w, http.StatusAccepted, map[string]interface{}{
		"success": true,
		"message": "Resolution queued",
		"data": map[string]interface{}{
			"company_id": companyID,
			"enqueued":   len(req.UserIDs),
			"reason":     reason,
		},
	})
}

// GetEffectivePolicies — unchanged.
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

// ResolveOnboarding — unchanged. One user, called on hire event.
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

// ResolvePositionChange — unchanged. One user, called on position edit.
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

// ListEntitlements — unchanged.
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

// ResolveAllUsers — ASYNC. Enqueues a single resolve_company job. The
// worker fans out in chunks of 100 internally.
func (h *LeavePolicyResolutionHandler) ResolveAllUsers(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if _, _, err := h.getActor(ctx); err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req ResolveAllUsersRequest
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	reason := req.Reason
	if reason == "" {
		reason = "initial backfill"
	}

	if err := h.policyResolutionService.EnqueueCompanyResolution(
		ctx, companyID, reason,
	); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "failed to enqueue company resolution")
		return
	}

	h.respondWithJSON(w, http.StatusAccepted, map[string]interface{}{
		"success": true,
		"message": "Company-wide resolution queued",
		"data": map[string]interface{}{
			"company_id": companyID,
			"reason":     reason,
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