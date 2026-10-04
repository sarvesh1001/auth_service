// internal/hr/handler/reminder_handler.go
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	hrEmployee "auth-service/internal/hr/models/employee"
	hrrepo "auth-service/internal/hr/repository"
	hrservice "auth-service/internal/hr/service"
	"auth-service/internal/locationctx"
	"auth-service/internal/util"
)

type ReminderHandler struct {
	reminderService *hrservice.ReminderService
	logger          *zap.Logger
}

func NewReminderHandler(
	reminderService *hrservice.ReminderService,
	logger *zap.Logger,
) *ReminderHandler {
	if logger == nil {
		logger = zap.L()
	}
	return &ReminderHandler{
		reminderService: reminderService,
		logger:          logger.Named("reminder_handler"),
	}
}

// ============================================================================
// Location scope helper
// ============================================================================
//
// The frontend's axios interceptor attaches X-Location-ID on every request.
// LocationValidationMiddleware parses it into locationctx:
//   - "ALL" (or unset)      → Filter(ctx) == nil  → no location filter
//   - a specific UUID       → Filter(ctx) == &uuid → filter to that location
//
// Reminders fall into two buckets:
//   - location_id = <uuid>  → visible only to HR users scoped to that location
//   - location_id IS NULL   → company-wide; visible in every scope
//
// `resolveLocationScope` returns the locationIDs slice the repository
// expects:
//   - nil       → no filter (ALL scope)
//   - []uuid{}  → filter to that location set
func (h *ReminderHandler) resolveLocationScope(ctx context.Context) []uuid.UUID {
	loc := locationctx.Filter(ctx)
	if loc == nil {
		return nil
	}
	return []uuid.UUID{*loc}
}

// GET /companies/{companyID}/hr/reminders
//
// Query params: status, severity, type, type_prefix, since, page, page_size.
// Location scope is applied server-side from X-Location-ID — the client
// never sends a location filter, it just needs to set the header (which
// the axios interceptor already does).
func (h *ReminderHandler) ListReminders(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	recipientID, err := h.currentUserID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 30
	}

	// Location scope from X-Location-ID (resolved by middleware).
	locationIDs := h.resolveLocationScope(ctx)

	filters := hrrepo.ReminderFilters{
		LocationIDs: locationIDs, // nil = ALL scope
		Status:      strings.TrimSpace(r.URL.Query().Get("status")),
		Severity:    strings.TrimSpace(r.URL.Query().Get("severity")),
		Type:        strings.TrimSpace(r.URL.Query().Get("type")),
		TypePrefix:  strings.TrimSpace(r.URL.Query().Get("type_prefix")),
	}
	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		if t, perr := time.Parse(time.RFC3339, sinceStr); perr == nil {
			filters.Since = &t
		}
	}

	feed, err := h.reminderService.List(ctx, recipientID, filters, page, pageSize)
	if err != nil {
		h.logger.Error("ListReminders failed",
			util.String("company_id", companyID.String()),
			util.String("recipient_id", recipientID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to load reminders")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"unread_count": feed.UnreadCount,
			"groups":       groupRemindersByDay(feed.Items),
			"items":        feed.Items,
		},
		"meta": map[string]interface{}{
			"page":        feed.Page,
			"page_size":   feed.PageSize,
			"total_count": feed.TotalCount,
		},
	})
}

// GET /companies/{companyID}/hr/reminders/count
//
// The badge count uses the same location scope as the feed, so an HR user
// viewing Mumbai sees only Mumbai unread counts — not the company total.
func (h *ReminderHandler) GetReminderCounts(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	recipientID, err := h.currentUserID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Location scope from X-Location-ID.
	locationIDs := h.resolveLocationScope(ctx)

	counts, err := h.reminderService.Counts(ctx, recipientID, locationIDs)
	if err != nil {
		h.logger.Error("GetReminderCounts failed",
			util.String("recipient_id", recipientID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to load counts")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    counts,
	})
}

// POST /companies/{companyID}/hr/reminders/{reminderID}/read
//
// No location filter — the caller already owns the reminder_id. Marking a
// reminder read must succeed even if the user's location scope has since
// changed (they saw the row, they're dismissing it).
func (h *ReminderHandler) MarkReminderRead(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	recipientID, err := h.currentUserID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	reminderID, err := uuid.Parse(chi.URLParam(r, "reminderID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid reminder ID")
		return
	}

	if err := h.reminderService.MarkRead(ctx, recipientID, reminderID); err != nil {
		h.logger.Error("MarkReminderRead failed",
			util.String("reminder_id", reminderID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to mark reminder read")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Reminder marked as read",
	})
}

// POST /companies/{companyID}/hr/reminders/read-all
//
// No location filter — this is a recipient-scoped bulk flip.
func (h *ReminderHandler) MarkAllRemindersRead(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	recipientID, err := h.currentUserID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	n, err := h.reminderService.MarkAllRead(ctx, recipientID)
	if err != nil {
		h.logger.Error("MarkAllRemindersRead failed",
			util.String("recipient_id", recipientID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to mark all read")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "All reminders marked as read",
		"data": map[string]interface{}{
			"affected_count": n,
		},
	})
}

// POST /companies/{companyID}/hr/reminders/{reminderID}/dismiss
//
// No location filter — same rationale as MarkReminderRead.
func (h *ReminderHandler) DismissReminder(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	recipientID, err := h.currentUserID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	reminderID, err := uuid.Parse(chi.URLParam(r, "reminderID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid reminder ID")
		return
	}

	if err := h.reminderService.Dismiss(ctx, recipientID, reminderID); err != nil {
		h.logger.Error("DismissReminder failed",
			util.String("reminder_id", reminderID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to dismiss reminder")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Reminder dismissed",
	})
}

// ============================================================================
// Helpers
// ============================================================================

func (h *ReminderHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

func (h *ReminderHandler) respondWithError(w http.ResponseWriter, statusCode int, message string) {
	h.respondWithJSON(w, statusCode, map[string]interface{}{
		"success": false, "error": message, "code": statusCode,
	})
}

func (h *ReminderHandler) currentUserID(ctx context.Context) (uuid.UUID, error) {
	str, ok := ctx.Value("user_id").(string)
	if !ok || str == "" {
		return uuid.Nil, errMissingUserID
	}
	return uuid.Parse(str)
}

// ============================================================================
// Day-grouping for the mobile feed
// ============================================================================

type reminderGroup struct {
	Label string                 `json:"label"`
	Date  string                 `json:"date"`
	Items []*hrEmployee.Reminder `json:"items"`
}

func groupRemindersByDay(items []*hrEmployee.Reminder) []reminderGroup {
	if len(items) == 0 {
		return []reminderGroup{}
	}

	today := time.Now().UTC().Truncate(24 * time.Hour)
	buckets := map[string]*reminderGroup{}
	order := []string{}

	for _, it := range items {
		day := it.CreatedAt.UTC().Truncate(24 * time.Hour)
		key := day.Format("2006-01-02")
		bucket, ok := buckets[key]
		if !ok {
			bucket = &reminderGroup{
				Label: labelForDay(day, today),
				Date:  key,
				Items: []*hrEmployee.Reminder{},
			}
			buckets[key] = bucket
			order = append(order, key)
		}
		bucket.Items = append(bucket.Items, it)
	}

	out := make([]reminderGroup, 0, len(order))
	for _, k := range order {
		out = append(out, *buckets[k])
	}
	return out
}

func labelForDay(day, today time.Time) string {
	diff := int(today.Sub(day).Hours() / 24)
	switch {
	case diff <= 0:
		return "Today"
	case diff == 1:
		return "Yesterday"
	case diff < 7:
		return "This week"
	case diff < 30:
		return "This month"
	default:
		return "Older"
	}
}

var errMissingUserID = errors.New("user_id missing from context")
