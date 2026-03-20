package audit

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/util"
)

// AuditHandler handles audit log related operations
type AuditHandler struct {
	auditQueryService *AuditQueryService
	logger            *zap.Logger
}

// NewAuditHandler creates a new audit handler
func NewAuditHandler(
	auditQueryService *AuditQueryService,
	logger *zap.Logger,
) *AuditHandler {
	return &AuditHandler{
		auditQueryService: auditQueryService,
		logger:            logger,
	}
}

// ============================================================================
// COMPANY AUDIT ENDPOINTS (NON-ADMIN)
// ============================================================================

// GetCompanyAuditLogs retrieves audit logs for a specific company
func (h *AuditHandler) GetCompanyAuditLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get company ID from URL
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID format")
		return
	}

	// Get current user ID from context
	currentUserID, ok := ctx.Value("current_user_id").(uuid.UUID)
	if !ok {
		h.respondWithError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	// Parse query parameters
	query := r.URL.Query()

	// Filters
	var (
		module     *string
		action     *string
		entityType *string
		entityID   *uuid.UUID
		actorType  *string
		actorID    *uuid.UUID
		startDate  *time.Time
		endDate    *time.Time
	)

	if v := query.Get("module"); v != "" {
		module = &v
	}

	if v := query.Get("action"); v != "" {
		action = &v
	}

	if v := query.Get("entity_type"); v != "" {
		entityType = &v
	}

	if v := query.Get("entity_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid entity ID format")
			return
		}
		entityID = &id
	}

	if v := query.Get("actor_type"); v != "" {
		actorType = &v
	}

	if v := query.Get("actor_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid actor ID format")
			return
		}
		actorID = &id
	}

	if v := query.Get("start_date"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid start_date format")
			return
		}
		startDate = &t
	}

	if v := query.Get("end_date"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid end_date format")
			return
		}
		endDate = &t
	}

	// Pagination
	page, err := strconv.Atoi(query.Get("page"))
	if err != nil || page < 1 {
		page = 1
	}

	pageSize, err := strconv.Atoi(query.Get("page_size"))
	if err != nil || pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	// Log request
	h.logger.Info("Fetching company audit logs",
		util.String("company_id", companyID.String()),
		util.String("requested_by", currentUserID.String()),
		zap.String("module", h.getPointerValue(module)),
		zap.String("action", h.getPointerValue(action)),
		zap.String("entity_type", h.getPointerValue(entityType)),
		zap.String("actor_type", h.getPointerValue(actorType)),
	)

	// ✅ Call service WITH ALL FILTERS
	logs, total, err := h.auditQueryService.GetCompanyAuditLogs(
		ctx,
		companyID,
		module,
		action,
		entityType,
		entityID,
		actorType,
		actorID,
		startDate,
		endDate,
		page,
		pageSize,
	)

	if err != nil {
		h.logger.Error("Failed to fetch company audit logs",
			util.String("company_id", companyID.String()),
			util.ErrorField(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, "Failed to fetch audit logs")
		return
	}

	totalPages := (total + pageSize - 1) / pageSize

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"logs": logs,
			"pagination": map[string]interface{}{
				"page":         page,
				"page_size":    pageSize,
				"total":        total,
				"total_pages":  totalPages,
				"has_next":     page < totalPages,
				"has_previous": page > 1,
			},
		},
	})
}

// GetEntityAuditHistory retrieves complete audit history for a specific entity
func (h *AuditHandler) GetEntityAuditHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get company ID from URL
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID format")
		return
	}

	// Get entity type and ID from query params
	query := r.URL.Query()
	entityType := query.Get("entity_type")
	if entityType == "" {
		h.respondWithError(w, http.StatusBadRequest, "entity_type is required")
		return
	}

	entityIDStr := query.Get("entity_id")
	if entityIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "entity_id is required")
		return
	}

	entityID, err := uuid.Parse(entityIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid entity ID format")
		return
	}

	// Limit
	limit, err := strconv.Atoi(query.Get("limit"))
	if err != nil || limit < 1 || limit > 1000 {
		limit = 100
	}

	// Get current user ID from context
	currentUserID, ok := ctx.Value("current_user_id").(uuid.UUID)
	if !ok {
		h.respondWithError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	h.logger.Info("Fetching entity audit history",
		util.String("company_id", companyID.String()),
		util.String("entity_type", entityType),
		util.String("entity_id", entityID.String()),
		util.String("requested_by", currentUserID.String()),
	)

	// Get entity audit history
	logs, err := h.auditQueryService.GetEntityAuditHistory(
		ctx,
		entityType,
		entityID,
		limit,
	)

	if err != nil {
		h.logger.Error("Failed to fetch entity audit history",
			util.String("company_id", companyID.String()),
			util.String("entity_type", entityType),
			util.String("entity_id", entityID.String()),
			util.ErrorField(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, "Failed to fetch entity audit history")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"logs": logs,
			"entity": map[string]interface{}{
				"type": entityType,
				"id":   entityID,
			},
			"total": len(logs),
		},
	})
}

// ExportCompanyAuditLogs exports audit logs for a company
func (h *AuditHandler) ExportCompanyAuditLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get company ID from URL
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID format")
		return
	}

	// Parse query parameters
	query := r.URL.Query()

	// Format (default: json)
	format := strings.ToLower(query.Get("format"))
	if format == "" {
		format = "json"
	}

	if format != "json" && format != "csv" {
		h.respondWithError(w, http.StatusBadRequest, "Unsupported format. Use 'json' or 'csv'")
		return
	}

	// Date range (required for export)
	startDateParam := query.Get("start_date")
	endDateParam := query.Get("end_date")

	if startDateParam == "" || endDateParam == "" {
		h.respondWithError(w, http.StatusBadRequest, "start_date and end_date are required for export")
		return
	}

	startDate, err := time.Parse(time.RFC3339, startDateParam)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid start_date format. Use RFC3339 format")
		return
	}

	endDate, err := time.Parse(time.RFC3339, endDateParam)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid end_date format. Use RFC3339 format")
		return
	}

	// Get current user ID from context
	currentUserID, ok := ctx.Value("current_user_id").(uuid.UUID)
	if !ok {
		h.respondWithError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	h.logger.Info("Exporting company audit logs",
		util.String("company_id", companyID.String()),
		util.String("requested_by", currentUserID.String()),
		zap.String("format", format),
		zap.Time("start_date", startDate),
		zap.Time("end_date", endDate),
	)

	// Export logs
	data, contentType, err := h.auditQueryService.ExportAuditLogs(
		ctx,
		companyID,
		startDate,
		endDate,
		format,
	)

	if err != nil {
		h.logger.Error("Failed to export audit logs",
			util.String("company_id", companyID.String()),
			util.ErrorField(err),
		)

		if strings.Contains(err.Error(), "export period cannot exceed") {
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		} else {
			h.respondWithError(w, http.StatusInternalServerError, "Failed to export audit logs")
		}
		return
	}

	// Generate filename
	filename := fmt.Sprintf("audit-logs_%s_%s_%s.%s",
		companyID.String(),
		startDate.Format("2006-01-02"),
		endDate.Format("2006-01-02"),
		format,
	)

	// Set response headers
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))

	// Write data
	if _, err := w.Write(data); err != nil {
		h.logger.Error("Failed to write export data",
			util.String("company_id", companyID.String()),
			util.ErrorField(err),
		)
	}
}

// GetCompanyAuditStats retrieves audit statistics for a company
func (h *AuditHandler) GetCompanyAuditStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get company ID from URL
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID format")
		return
	}

	// Parse query parameters
	query := r.URL.Query()

	// Date range (default: last 30 days)
	startDateParam := query.Get("start_date")
	endDateParam := query.Get("end_date")

	var startDate, endDate time.Time
	if startDateParam == "" || endDateParam == "" {
		// Default to last 30 days
		endDate = time.Now().UTC()
		startDate = endDate.AddDate(0, 0, -30)
	} else {
		startDate, err = time.Parse(time.RFC3339, startDateParam)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid start_date format. Use RFC3339 format")
			return
		}

		endDate, err = time.Parse(time.RFC3339, endDateParam)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid end_date format. Use RFC3339 format")
			return
		}
	}

	// Get current user ID from context
	currentUserID, ok := ctx.Value("current_user_id").(uuid.UUID)
	if !ok {
		h.respondWithError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	h.logger.Info("Fetching company audit stats",
		util.String("company_id", companyID.String()),
		util.String("requested_by", currentUserID.String()),
		zap.Time("start_date", startDate),
		zap.Time("end_date", endDate),
	)

	// Get statistics
	stats, err := h.auditQueryService.GetAuditStats(
		ctx,
		companyID,
		startDate,
		endDate,
	)

	if err != nil {
		h.logger.Error("Failed to fetch audit stats",
			util.String("company_id", companyID.String()),
			util.ErrorField(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, "Failed to fetch audit statistics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"stats": stats,
			"period": map[string]interface{}{
				"start_date": startDate,
				"end_date":   endDate,
			},
			"company_id": companyID,
		},
	})
}

// ============================================================================
// ADMIN AUDIT ENDPOINTS
// ============================================================================

// GetSystemAuditLogs retrieves system-wide audit logs (admin only)
func (h *AuditHandler) GetSystemAuditLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	query := r.URL.Query()

	// Company filter (optional for admin)
	var companyID *uuid.UUID
	if companyIDParam := query.Get("company_id"); companyIDParam != "" {
		parsedCompanyID, err := uuid.Parse(companyIDParam)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid company ID format")
			return
		}
		companyID = &parsedCompanyID
	}

	// Module filter
	var module *string
	if moduleParam := query.Get("module"); moduleParam != "" {
		module = &moduleParam
	}

	// Other filters...
	// Similar to GetCompanyAuditLogs but with companyID as optional

	// Pagination
	page, err := strconv.Atoi(query.Get("page"))
	if err != nil || page < 1 {
		page = 1
	}

	pageSize, err := strconv.Atoi(query.Get("page_size"))
	if err != nil || pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	// Get admin ID from context
	adminID, ok := ctx.Value("user_id").(string)
	if !ok {
		h.respondWithError(w, http.StatusUnauthorized, "Admin not authenticated")
		return
	}

	h.logger.Info("Admin fetching system audit logs",
		zap.String("admin_id", adminID),
		zap.Any("company_id", companyID),
		zap.String("module", h.getPointerValue(module)),
	)

	// TODO: Implement system-wide audit log retrieval
	// This would require a new method in the service layer
	// For now, return placeholder response

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"message": "System audit logs endpoint (admin only)",
			"filters": map[string]interface{}{
				"company_id": companyID,
				"module":     module,
				"page":       page,
				"page_size":  pageSize,
			},
		},
	})
}

// ExportSystemAuditLogs exports system-wide audit logs (admin only)
func (h *AuditHandler) ExportSystemAuditLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Similar to ExportCompanyAuditLogs but with optional company filter

	// Get admin ID from context
	adminID, ok := ctx.Value("user_id").(string)
	if !ok {
		h.respondWithError(w, http.StatusUnauthorized, "Admin not authenticated")
		return
	}

	h.logger.Info("Admin exporting system audit logs",
		zap.String("admin_id", adminID),
	)

	// TODO: Implement system-wide audit export
	// This would require a new method in the service layer

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"message": "System audit export endpoint (admin only)",
		},
	})
}

// GetSystemAuditStats retrieves system-wide audit statistics (admin only)
func (h *AuditHandler) GetSystemAuditStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get admin ID from context
	adminID, ok := ctx.Value("user_id").(string)
	if !ok {
		h.respondWithError(w, http.StatusUnauthorized, "Admin not authenticated")
		return
	}

	h.logger.Info("Admin fetching system audit stats",
		zap.String("admin_id", adminID),
	)

	// TODO: Implement system-wide audit statistics
	// This would require a new method in the service layer

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"message": "System audit stats endpoint (admin only)",
		},
	})
}

// ============================================================================
// AUDIT HEALTH CHECK
// ============================================================================

// AuditHealthCheck checks the health of the audit system
func (h *AuditHandler) AuditHealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	err := h.auditQueryService.HealthCheck(ctx)
	if err != nil {
		h.logger.Error("Audit health check failed", util.ErrorField(err))
		h.respondWithJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"success": false,
			"status":  "unhealthy",
			"service": "audit",
			"error":   err.Error(),
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"status":  "healthy",
		"service": "audit",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

// ============================================================================
// HELPER METHODS
// ============================================================================

func (h *AuditHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", util.ErrorField(err))
	}
}

func (h *AuditHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
		"message": message,
		"code":    status,
	})
}

func (h *AuditHandler) getPointerValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
