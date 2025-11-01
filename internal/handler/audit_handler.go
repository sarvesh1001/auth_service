package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"auth-service/internal/models"
	"auth-service/internal/service"
	"auth-service/internal/util"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AuditHandler handles HTTP requests for audit log operations
type AuditHandler struct {
	auditService *service.AuditService
	logger       *zap.Logger
}

// NewAuditHandler creates a new audit handler
func NewAuditHandler(auditService *service.AuditService, logger *zap.Logger) *AuditHandler {
	return &AuditHandler{
		auditService: auditService,
		logger:       logger,
	}
}

// RegisterRoutes registers all audit routes
func (h AuditHandler) RegisterRoutes(router chi.Router) {
	router.Route("/audit", func(r chi.Router) {
		// Query operations - require admin session
		r.Get("/admin/{adminID}", h.GetAuditByAdmin)
		r.Get("/resource/{resourceID}", h.GetAuditByResource)
		r.Get("/action/{actionType}", h.GetAuditByActionType)
		r.Get("/status/{status}", h.GetAuditByStatus)
		r.Get("/between-dates", h.GetAuditBetweenDates)
		r.Get("/search", h.SearchAuditLog)

		// Statistics
		r.Get("/stats", h.GetAuditStats)
		r.Get("/admin/{adminID}/stats", h.GetAdminStats)

		// Reporting
		r.Post("/export", h.ExportAuditLog)

		// Compliance
		r.Get("/suspicious", h.GetSuspiciousActivity)
		r.Get("/today/{adminID}", h.GetAdminActionsToday)

		// Health
		r.Get("/health", h.HealthCheck)
	})
}

// ===== QUERY OPERATIONS =====

// GetAuditByAdmin retrieves all actions by specific admin
// GET /api/v1/audit/admin/{adminID}?limit=100
func (h AuditHandler) GetAuditByAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	// Get admin ID from URL
	adminIDStr := chi.URLParam(r, "adminID")
	adminID, err := uuid.Parse(adminIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID format")
		return
	}

	// Parse limit
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 10000 {
			limit = parsed
		}
	}

	// Get audit logs
	logs, err := h.auditService.GetAuditLogByAdmin(ctx, adminID, limit)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get audit logs")
		return
	}

	if logs == nil {
		logs = []*models.AdminAuditLog{}
	}

	response := successResponse(map[string]interface{}{
		"admin_id": adminID.String(),
		"logs":     logs,
		"count":    len(logs),
	}, "Audit logs retrieved successfully")

	h.respondWithJSON(w, http.StatusOK, response)
	h.logger.Debug("Audit logs retrieved by admin via HTTP",
		util.String("admin_id", adminID.String()),
		util.Int("count", len(logs)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// GetAuditByResource retrieves all actions affecting specific resource
// GET /api/v1/audit/resource/{resourceID}?limit=100
func (h AuditHandler) GetAuditByResource(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	// Get resource ID from URL
	resourceIDStr := chi.URLParam(r, "resourceID")
	resourceID, err := uuid.Parse(resourceIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid resource ID format")
		return
	}

	// Parse limit
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 10000 {
			limit = parsed
		}
	}

	// Get audit logs
	logs, err := h.auditService.GetAuditLogByResource(ctx, resourceID, limit)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get audit logs")
		return
	}

	if logs == nil {
		logs = []*models.AdminAuditLog{}
	}

	response := successResponse(map[string]interface{}{
		"resource_id": resourceID.String(),
		"logs":        logs,
		"count":       len(logs),
	}, "Audit logs retrieved successfully")

	h.respondWithJSON(w, http.StatusOK, response)
	h.logger.Debug("Audit logs retrieved by resource via HTTP",
		util.String("resource_id", resourceID.String()),
		util.Int("count", len(logs)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// GetAuditByActionType retrieves all actions of specific type
// GET /api/v1/audit/action/{actionType}?limit=100
func (h AuditHandler) GetAuditByActionType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	// Get action type from URL
	actionType := strings.ToUpper(chi.URLParam(r, "actionType"))
	if actionType == "" {
		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("action type required"), "Action type is required")
		return
	}

	// Parse limit
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 10000 {
			limit = parsed
		}
	}

	// Get audit logs
	logs, err := h.auditService.GetAuditLogByActionType(ctx, actionType, limit)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get audit logs")
		return
	}

	if logs == nil {
		logs = []*models.AdminAuditLog{}
	}

	response := successResponse(map[string]interface{}{
		"action_type": actionType,
		"logs":        logs,
		"count":       len(logs),
	}, "Audit logs retrieved successfully")

	h.respondWithJSON(w, http.StatusOK, response)
	h.logger.Debug("Audit logs retrieved by action type via HTTP",
		util.String("action_type", actionType),
		util.Int("count", len(logs)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// GetAuditByStatus retrieves audit logs by operation status
// GET /api/v1/audit/status/{status}?limit=100
func (h AuditHandler) GetAuditByStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	// Get status from URL
	status := strings.ToUpper(chi.URLParam(r, "status"))
	if status != models.StatusSuccess && status != models.StatusFailure {
		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("invalid status"), "Status must be SUCCESS or FAILURE")
		return
	}

	// Parse limit
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 10000 {
			limit = parsed
		}
	}

	// Get audit logs
	logs, err := h.auditService.GetAuditLogByStatus(ctx, status, limit)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get audit logs")
		return
	}

	if logs == nil {
		logs = []*models.AdminAuditLog{}
	}

	response := successResponse(map[string]interface{}{
		"status": status,
		"logs":   logs,
		"count":  len(logs),
	}, "Audit logs retrieved successfully")

	h.respondWithJSON(w, http.StatusOK, response)
	h.logger.Debug("Audit logs retrieved by status via HTTP",
		util.String("status", status),
		util.Int("count", len(logs)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// GetAuditBetweenDates retrieves audit logs within date range
// GET /api/v1/audit/between-dates?start=2025-10-01&end=2025-10-30&limit=100
func (h AuditHandler) GetAuditBetweenDates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	// Parse dates
	startDateStr := r.URL.Query().Get("start")
	endDateStr := r.URL.Query().Get("end")

	if startDateStr == "" || endDateStr == "" {
		h.respondWithError(w, http.StatusBadRequest, fmt.Errorf("missing dates"), "start and end dates are required")
		return
	}

	startDate, err := time.Parse("2006-01-02", startDateStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid start date format (use YYYY-MM-DD)")
		return
	}

	endDate, err := time.Parse("2006-01-02", endDateStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid end date format (use YYYY-MM-DD)")
		return
	}

	// Parse limit
	limitStr := r.URL.Query().Get("limit")
	limit := 1000
	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 100000 {
			limit = parsed
		}
	}

	// Get audit logs
	logs, err := h.auditService.GetAuditLogBetweenDates(ctx, startDate, endDate, limit)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get audit logs")
		return
	}

	if logs == nil {
		logs = []*models.AdminAuditLog{}
	}

	response := successResponse(map[string]interface{}{
		"start_date": startDateStr,
		"end_date":   endDateStr,
		"logs":       logs,
		"count":      len(logs),
	}, "Audit logs retrieved successfully")

	h.respondWithJSON(w, http.StatusOK, response)
	h.logger.Debug("Audit logs retrieved between dates via HTTP",
		util.String("start_date", startDateStr),
		util.String("end_date", endDateStr),
		util.Int("count", len(logs)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// SearchAuditLog searches audit logs with multiple filters
// GET /api/v1/audit/search?admin_id=...&resource_id=...&action=...&status=...&limit=100
func (h AuditHandler) SearchAuditLog(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	// Build filter
	filter := &models.AuditLogFilter{}

	// Admin ID
	adminIDStr := r.URL.Query().Get("admin_id")
	if adminIDStr != "" {
		adminID, err := uuid.Parse(adminIDStr)
		if err == nil {
			filter.AdminID = &adminID
		}
	}

	// Resource ID
	resourceIDStr := r.URL.Query().Get("resource_id")
	if resourceIDStr != "" {
		resourceID, err := uuid.Parse(resourceIDStr)
		if err == nil {
			filter.ResourceID = &resourceID
		}
	}

	// Action type
	actionType := r.URL.Query().Get("action")
	if actionType != "" {
		actionType = strings.ToUpper(actionType)
		filter.ActionType = &actionType
	}

	// Status
	status := r.URL.Query().Get("status")
	if status != "" {
		status = strings.ToUpper(status)
		filter.Status = &status
	}

	// Limit
	limitStr := r.URL.Query().Get("limit")
	filter.Limit = 100
	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 10000 {
			filter.Limit = parsed
		}
	}

	// Query
	logs, err := h.auditService.QueryAuditLog(ctx, filter)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to search audit logs")
		return
	}

	if logs == nil {
		logs = []*models.AdminAuditLog{}
	}

	response := successResponse(map[string]interface{}{
		"filters": filter,
		"logs":    logs,
		"count":   len(logs),
	}, "Audit logs retrieved successfully")

	h.respondWithJSON(w, http.StatusOK, response)
	h.logger.Debug("Audit logs searched via HTTP",
		util.Int("count", len(logs)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ===== STATISTICS =====

// GetAuditStats retrieves overall audit statistics
// GET /api/v1/audit/stats
func (h AuditHandler) GetAuditStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	stats, err := h.auditService.GetAuditStats(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get stats")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(stats, "Audit statistics retrieved successfully"))
	h.logger.Debug("Audit stats retrieved via HTTP",
		util.Duration("duration", time.Since(startTime)),
	)
}

// GetAdminStats retrieves statistics for specific admin
// GET /api/v1/audit/admin/{adminID}/stats
func (h AuditHandler) GetAdminStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	// Get admin ID from URL
	adminIDStr := chi.URLParam(r, "adminID")
	adminID, err := uuid.Parse(adminIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID format")
		return
	}

	stats, err := h.auditService.GetAdminActionStats(ctx, adminID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get admin stats")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(stats, "Admin statistics retrieved successfully"))
	h.logger.Debug("Admin stats retrieved via HTTP",
		util.String("admin_id", adminID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ===== REPORTING =====

// ExportAuditLog exports audit logs in specified format
// POST /api/v1/audit/export
// Body: { start_date: "2025-10-01", end_date: "2025-10-30", format: "json" | "csv" }
func (h AuditHandler) ExportAuditLog(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	var req struct {
		StartDate string `json:"start_date"`
		EndDate   string `json:"end_date"`
		Format    string `json:"format"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Parse dates
	startDate, err := time.Parse("2006-01-02", req.StartDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid start date format (use YYYY-MM-DD)")
		return
	}

	endDate, err := time.Parse("2006-01-02", req.EndDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid end date format (use YYYY-MM-DD)")
		return
	}

	if req.Format == "" {
		req.Format = "json"
	}
	req.Format = strings.ToLower(req.Format)

	// Export
	data, err := h.auditService.ExportAuditLog(ctx, startDate, endDate, req.Format)
	if err != nil {
		statusCode := http.StatusInternalServerError
		if strings.Contains(err.Error(), "cannot exceed") {
			statusCode = http.StatusBadRequest
		}
		h.respondWithError(w, statusCode, err, "Failed to export audit log")
		return
	}

	// Set content type based on format
	contentType := "application/json"
	fileExt := "json"
	if req.Format == "csv" {
		contentType = "text/csv"
		fileExt = "csv"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="audit-logs-%s.%s"`, time.Now().Format("2006-01-02"), fileExt))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.WriteHeader(http.StatusOK)
	w.Write(data)

	h.logger.Info("Audit log exported via HTTP",
		util.String("format", req.Format),
		util.String("start_date", req.StartDate),
		util.String("end_date", req.EndDate),
		util.Int("size_bytes", len(data)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ===== COMPLIANCE =====

// GetSuspiciousActivity retrieves potentially suspicious activities (failed operations)
// GET /api/v1/audit/suspicious?limit=100
func (h AuditHandler) GetSuspiciousActivity(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	// Parse limit
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 10000 {
			limit = parsed
		}
	}

	// Get suspicious activities
	logs, err := h.auditService.GetSuspiciousActivity(ctx, limit)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get suspicious activity")
		return
	}

	if logs == nil {
		logs = []*models.AdminAuditLog{}
	}

	response := successResponse(map[string]interface{}{
		"logs":  logs,
		"count": len(logs),
	}, "Suspicious activities retrieved successfully")

	h.respondWithJSON(w, http.StatusOK, response)
	h.logger.Info("Suspicious activities retrieved via HTTP",
		util.Int("count", len(logs)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// GetAdminActionsToday retrieves actions performed by admin today
// GET /api/v1/audit/today/{adminID}
func (h AuditHandler) GetAdminActionsToday(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	// Get admin ID from URL
	adminIDStr := chi.URLParam(r, "adminID")
	adminID, err := uuid.Parse(adminIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid admin ID format")
		return
	}

	// Get actions today
	logs, err := h.auditService.GetAdminActionsToday(ctx, adminID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to get admin actions")
		return
	}

	if logs == nil {
		logs = []*models.AdminAuditLog{}
	}

	response := successResponse(map[string]interface{}{
		"admin_id": adminID.String(),
		"date":     time.Now().Format("2006-01-02"),
		"logs":     logs,
		"count":    len(logs),
	}, "Admin actions retrieved successfully")

	h.respondWithJSON(w, http.StatusOK, response)
	h.logger.Debug("Admin actions today retrieved via HTTP",
		util.String("admin_id", adminID.String()),
		util.Int("count", len(logs)),
		util.Duration("duration", time.Since(startTime)),
	)
}

// ===== HEALTH =====

// HealthCheck verifies audit service health
// GET /api/v1/audit/health
func (h AuditHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := h.auditService.HealthCheck(ctx); err != nil {
		h.respondWithError(w, http.StatusServiceUnavailable, err, "Audit service unhealthy")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]string{
		"status":  "healthy",
		"service": "audit",
	}, "Audit service is healthy"))
}

// ===== HELPER FUNCTIONS =====

// respondWithJSON sends a JSON response
func (h AuditHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", util.ErrorField(err))
	}
}

// respondWithError sends an error response
func (h AuditHandler) respondWithError(w http.ResponseWriter, statusCode int, err error, message string) {
	h.logger.Warn("Audit HTTP error response",
		util.ErrorField(err),
		util.Int("status_code", statusCode),
		util.String("message", message),
	)
	h.respondWithJSON(w, statusCode, errorResponse(err, message))
}