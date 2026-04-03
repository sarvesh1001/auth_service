package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/service"
)

type NotificationHandler struct {
	notificationService service.NotificationService
	logger              *zap.Logger
}

func NewNotificationHandler(notificationService service.NotificationService, logger *zap.Logger) *NotificationHandler {
	return &NotificationHandler{
		notificationService: notificationService,
		logger:              logger.Named("notification_handler"),
	}
}

// Create handles POST /api/v1/companies/{companyID}/notifications
func (h *NotificationHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "notification:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateNotificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Set company ID from URL (override if provided in body)
	req.CompanyID = companyID
	req.CreatedBy = &userID

	// Optional idempotency key from header
	idempotencyKey := r.Header.Get("Idempotency-Key")

	notification, err := h.notificationService.Create(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to create notification",
			zap.String("title", req.Title),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    notification,
		"message": "Notification created successfully",
	})
}

// GetByID handles GET /api/v1/companies/{companyID}/notifications/{notificationID}
func (h *NotificationHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	notificationIDStr := chi.URLParam(r, "notificationID")
	notificationID, err := uuid.Parse(notificationIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid notification ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "notification:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	notification, err := h.notificationService.GetByID(ctx, notificationID)
	if err != nil {
		h.logger.Error("Failed to get notification",
			zap.String("notification_id", notificationID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    notification,
	})
}

// Update handles PUT /api/v1/companies/{companyID}/notifications/{notificationID}
func (h *NotificationHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	notificationIDStr := chi.URLParam(r, "notificationID")
	notificationID, err := uuid.Parse(notificationIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid notification ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "notification:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateNotificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.NotificationID = notificationID
	req.UpdatedBy = &userID

	notification, err := h.notificationService.Update(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update notification",
			zap.String("notification_id", notificationID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    notification,
		"message": "Notification updated successfully",
	})
}

// Delete handles DELETE /api/v1/companies/{companyID}/notifications/{notificationID}
func (h *NotificationHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	notificationIDStr := chi.URLParam(r, "notificationID")
	notificationID, err := uuid.Parse(notificationIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid notification ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "notification:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Optional: who deleted? Could be from context
	userID, _ := getUserIDFromContext(ctx)
	err = h.notificationService.Delete(ctx, notificationID, &userID)
	if err != nil {
		h.logger.Error("Failed to delete notification",
			zap.String("notification_id", notificationID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Notification deleted successfully",
	})
}

// ListUserNotifications handles GET /api/v1/companies/{companyID}/notifications
func (h *NotificationHandler) ListUserNotifications(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "notification:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Build request
	req := service.ListUserNotificationsRequest{
		UserID: userID,
	}

	// Parse types
	if typesParam := r.URL.Query().Get("types"); typesParam != "" {
		for _, t := range strings.Split(typesParam, ",") {
			req.Types = append(req.Types, models.NotificationType(t))
		}
	}
	// Parse priorities
	if prioritiesParam := r.URL.Query().Get("priorities"); prioritiesParam != "" {
		for _, p := range strings.Split(prioritiesParam, ",") {
			req.Priorities = append(req.Priorities, models.NotificationPriority(p))
		}
	}
	// Parse read status
	if readStatusParam := r.URL.Query().Get("read_status"); readStatusParam != "" {
		readStatus, err := strconv.ParseBool(readStatusParam)
		if err == nil {
			req.ReadStatus = &readStatus
		}
	}
	// Pagination
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	req.Limit = limit
	req.Offset = offset

	// Sorting
	req.SortField = r.URL.Query().Get("sort_field")
	if req.SortField == "" {
		req.SortField = "created_at"
	}
	req.SortDirection = r.URL.Query().Get("sort_direction")
	if req.SortDirection == "" {
		req.SortDirection = "DESC"
	}

	notifications, total, err := h.notificationService.ListUserNotifications(ctx, req)
	if err != nil {
		h.logger.Error("Failed to list user notifications",
			zap.String("user_id", userID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list notifications")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"notifications": notifications,
			"total":         total,
			"limit":         limit,
			"offset":        offset,
		},
	})
}

// MarkAsRead handles POST /api/v1/companies/{companyID}/notifications/{notificationID}/read
func (h *NotificationHandler) MarkAsRead(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	notificationIDStr := chi.URLParam(r, "notificationID")
	notificationID, err := uuid.Parse(notificationIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid notification ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "notification:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.notificationService.MarkAsRead(ctx, notificationID, userID)
	if err != nil {
		h.logger.Error("Failed to mark notification as read",
			zap.String("notification_id", notificationID.String()),
			zap.String("user_id", userID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Notification marked as read",
	})
}

// MarkAllAsRead handles POST /api/v1/companies/{companyID}/notifications/read-all
func (h *NotificationHandler) MarkAllAsRead(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "notification:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.notificationService.MarkAllAsRead(ctx, userID)
	if err != nil {
		h.logger.Error("Failed to mark all notifications as read",
			zap.String("user_id", userID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to mark all as read")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "All notifications marked as read",
	})
}

// GetReadStatuses handles GET /api/v1/companies/{companyID}/notifications/read-status?ids=id1,id2
func (h *NotificationHandler) GetReadStatuses(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "notification:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idsParam := r.URL.Query().Get("ids")
	if idsParam == "" {
		h.respondWithError(w, http.StatusBadRequest, "ids query parameter required")
		return
	}

	var ids []uuid.UUID
	for _, s := range strings.Split(idsParam, ",") {
		id, err := uuid.Parse(strings.TrimSpace(s))
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid notification ID: "+s)
			return
		}
		ids = append(ids, id)
	}

	statuses, err := h.notificationService.GetReadStatuses(ctx, ids, userID)
	if err != nil {
		h.logger.Error("Failed to get read statuses",
			zap.String("user_id", userID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get read statuses")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    statuses,
	})
}

// GetCounts handles GET /api/v1/companies/{companyID}/notifications/counts
func (h *NotificationHandler) GetCounts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "notification:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	counts, err := h.notificationService.GetCounts(ctx, userID)
	if err != nil {
		h.logger.Error("Failed to get notification counts",
			zap.String("user_id", userID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get counts")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    counts,
	})
}

// GetUserNotificationSummary handles GET /api/v1/companies/{companyID}/notifications/summary
func (h *NotificationHandler) GetUserNotificationSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "notification:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	notifications, err := h.notificationService.GetUserNotificationSummary(ctx, userID)
	if err != nil {
		h.logger.Error("Failed to get notification summary",
			zap.String("user_id", userID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get summary")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    notifications,
	})
}

// AddTargets handles POST /api/v1/companies/{companyID}/notifications/{notificationID}/targets
func (h *NotificationHandler) AddTargets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	notificationIDStr := chi.URLParam(r, "notificationID")
	notificationID, err := uuid.Parse(notificationIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid notification ID")
		return
	}

	_, err = getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "notification:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var targets []service.NotificationTargetInput
	if err := json.NewDecoder(r.Body).Decode(&targets); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	err = h.notificationService.AddTargets(ctx, notificationID, targets)
	if err != nil {
		h.logger.Error("Failed to add targets to notification",
			zap.String("notification_id", notificationID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Targets added successfully",
	})
}

// RemoveTargets handles DELETE /api/v1/companies/{companyID}/notifications/{notificationID}/targets
func (h *NotificationHandler) RemoveTargets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	notificationIDStr := chi.URLParam(r, "notificationID")
	notificationID, err := uuid.Parse(notificationIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid notification ID")
		return
	}

	_, err = getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "notification:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req struct {
		TargetIDs []uuid.UUID `json:"target_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.TargetIDs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "target_ids required")
		return
	}

	err = h.notificationService.RemoveTargets(ctx, notificationID, req.TargetIDs)
	if err != nil {
		h.logger.Error("Failed to remove targets from notification",
			zap.String("notification_id", notificationID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Targets removed successfully",
	})
}

// GetTargets handles GET /api/v1/companies/{companyID}/notifications/{notificationID}/targets
func (h *NotificationHandler) GetTargets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	notificationIDStr := chi.URLParam(r, "notificationID")
	notificationID, err := uuid.Parse(notificationIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid notification ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "notification:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	targets, err := h.notificationService.GetTargets(ctx, notificationID)
	if err != nil {
		h.logger.Error("Failed to get targets for notification",
			zap.String("notification_id", notificationID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get targets")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    targets,
	})
}

// GetReadCount handles GET /api/v1/companies/{companyID}/notifications/{notificationID}/read-count
func (h *NotificationHandler) GetReadCount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	notificationIDStr := chi.URLParam(r, "notificationID")
	notificationID, err := uuid.Parse(notificationIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid notification ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "notification:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	count, err := h.notificationService.GetReadCount(ctx, notificationID)
	if err != nil {
		h.logger.Error("Failed to get read count for notification",
			zap.String("notification_id", notificationID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get read count")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]int64{"read_count": count},
	})
}

// Helper methods
func (h *NotificationHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	// Placeholder – implement actual permission check
	return true
}

func (h *NotificationHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *NotificationHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
