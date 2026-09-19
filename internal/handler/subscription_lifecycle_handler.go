// internal/handler/subscription_lifecycle_handler.go
package handler

import (
	"context"
	"net/http"

	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/service"
)

// SubscriptionLifecycleHandler handles lifecycle management endpoints.
type SubscriptionLifecycleHandler struct {
	lifecycleService *service.SubscriptionLifecycleService
	idempotencyStore idempotency.Store
}

// NewSubscriptionLifecycleHandler creates a new SubscriptionLifecycleHandler.
func NewSubscriptionLifecycleHandler(
	lifecycleService *service.SubscriptionLifecycleService,
	idempotencyStore idempotency.Store,
) *SubscriptionLifecycleHandler {
	return &SubscriptionLifecycleHandler{
		lifecycleService: lifecycleService,
		idempotencyStore: idempotencyStore,
	}
}

// ---------- Helpers ----------

func (h *SubscriptionLifecycleHandler) getIdempotencyKey(r *http.Request) string {
	return r.Header.Get("Idempotency-Key")
}

func (h *SubscriptionLifecycleHandler) injectIdempotencyKey(ctx context.Context, r *http.Request) context.Context {
	key := h.getIdempotencyKey(r)
	if key != "" {
		return context.WithValue(ctx, "idempotency_key", key)
	}
	return ctx
}

func (h *SubscriptionLifecycleHandler) injectClientIP(ctx context.Context, r *http.Request) context.Context {
	ip := getClientIP(r)
	return context.WithValue(ctx, "ip_address", ip)
}

// ---------- Endpoints ----------

// ExpireLapsedSubscriptions POST /api/v1/admin/subscriptions/expire-lapsed
// Manually triggers the expiration of lapsed subscriptions.
func (h *SubscriptionLifecycleHandler) ExpireLapsedSubscriptions(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	if err := h.lifecycleService.ExpireLapsedSubscriptions(ctx); err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(nil, "Lapsed subscription expiration completed"))
}

// ExpireTrials POST /api/v1/admin/subscriptions/expire-trials
// Manually triggers the expiration of expired trials.
func (h *SubscriptionLifecycleHandler) ExpireTrials(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	if err := h.lifecycleService.ExpireTrials(ctx); err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(nil, "Trial expiration completed"))
}
