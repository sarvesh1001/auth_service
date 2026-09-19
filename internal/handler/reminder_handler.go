// internal/handler/reminder_handler.go
package handler

import (
	"context"
	"net/http"
	"strconv"

	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/service"
)

// ReminderHandler handles reminder-related endpoints.
type ReminderHandler struct {
	reminderService  *service.ReminderService
	idempotencyStore idempotency.Store
}

// NewReminderHandler creates a new ReminderHandler.
func NewReminderHandler(
	reminderService *service.ReminderService,
	idempotencyStore idempotency.Store,
) *ReminderHandler {
	return &ReminderHandler{
		reminderService:  reminderService,
		idempotencyStore: idempotencyStore,
	}
}

// ---------- Helpers ----------

func (h *ReminderHandler) getIdempotencyKey(r *http.Request) string {
	return r.Header.Get("Idempotency-Key")
}

func (h *ReminderHandler) injectIdempotencyKey(ctx context.Context, r *http.Request) context.Context {
	key := h.getIdempotencyKey(r)
	if key != "" {
		return context.WithValue(ctx, "idempotency_key", key)
	}
	return ctx
}

func (h *ReminderHandler) injectClientIP(ctx context.Context, r *http.Request) context.Context {
	ip := getClientIP(r)
	return context.WithValue(ctx, "ip_address", ip)
}

// ---------- Endpoints ----------

// ProcessReminders POST /api/v1/admin/reminders/process
// Manually triggers the reminder processing job.
func (h *ReminderHandler) ProcessReminders(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	if err := h.reminderService.ProcessPendingReminders(ctx); err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(nil, "Reminder processing completed"))
}

// GetPendingReminders GET /api/v1/admin/reminders/pending
// Lists pending reminders (not yet sent) with pagination.
func (h *ReminderHandler) GetPendingReminders(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}

	reminders, total, err := h.reminderService.ListPendingReminders(ctx, limit, offset)
	if err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}

	respondJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"reminders": reminders,
		"total":     total,
		"limit":     limit,
		"offset":    offset,
	}, "Pending reminders retrieved"))
}
