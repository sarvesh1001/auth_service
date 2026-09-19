package handler

// internal/handler/analytics.go

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

	"auth-service/internal/repository/clickhouse"
	"auth-service/internal/repository/elasticsearch"
	"auth-service/internal/service"
)

// AnalyticsHandler handles operational analytics (ClickHouse) and search (Elasticsearch) endpoints.
type AnalyticsHandler struct {
	analyticsService *service.AnalyticsService
	logger           *zap.Logger
}

// NewAnalyticsHandler creates a new AnalyticsHandler.
func NewAnalyticsHandler(svc *service.AnalyticsService, logger *zap.Logger) *AnalyticsHandler {
	return &AnalyticsHandler{
		analyticsService: svc,
		logger:           logger.Named("analytics_handler"),
	}
}

// --------------------------------------------------------------------------
// Helper methods
// --------------------------------------------------------------------------

func (h *AnalyticsHandler) parsePagination(r *http.Request) (page, limit, offset int) {
	page, _ = strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	offset = (page - 1) * limit
	return
}

func (h *AnalyticsHandler) parseDateRange(r *http.Request) (start, end *time.Time) {
	if s := r.URL.Query().Get("start_date"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			start = &t
		}
	}
	if e := r.URL.Query().Get("end_date"); e != "" {
		if t, err := time.Parse(time.RFC3339, e); err == nil {
			end = &t
		}
	}
	return
}

func (h *AnalyticsHandler) parseStringPtr(r *http.Request, key string) *string {
	if v := r.URL.Query().Get(key); v != "" {
		return &v
	}
	return nil
}

func (h *AnalyticsHandler) parseUUIDPtr(r *http.Request, key string) *uuid.UUID {
	if v := r.URL.Query().Get(key); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			return &id
		}
	}
	return nil
}

func (h *AnalyticsHandler) parseIntPtr(r *http.Request, key string) *int {
	if v := r.URL.Query().Get(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return &i
		}
	}
	return nil
}

func (h *AnalyticsHandler) parseBoolPtr(r *http.Request, key string) *bool {
	if v := r.URL.Query().Get(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return &b
		}
	}
	return nil
}

// --------------------------------------------------------------------------
// Response helpers
// --------------------------------------------------------------------------

func (h *AnalyticsHandler) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON", zap.Error(err))
	}
}

func (h *AnalyticsHandler) respondError(w http.ResponseWriter, status int, err error, msg string) {
	h.respondJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   msg,
	})
}

func (h *AnalyticsHandler) respondSuccess(w http.ResponseWriter, data interface{}, msg string) {
	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    data,
		"message": msg,
	})
}

func (h *AnalyticsHandler) respondFile(w http.ResponseWriter, data []byte, contentType, filename string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}

// --------------------------------------------------------------------------
// 1. OTP LOGS
// --------------------------------------------------------------------------

// GetOTPLogs returns paginated OTP logs with filters.
// GET /api/v1/companies/{companyID}/analytics/otp
func (h *AnalyticsHandler) GetOTPLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	if _, err := uuid.Parse(companyIDStr); err != nil {
		h.respondError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	page, limit, offset := h.parsePagination(r)
	start, end := h.parseDateRange(r)
	filter := clickhouse.OTPSearchFilter{
		UserID:    h.parseStringPtr(r, "user_id"),
		Phone:     h.parseStringPtr(r, "phone"),
		Status:    h.parseStringPtr(r, "status"),
		StartDate: start,
		EndDate:   end,
		Limit:     limit,
		Offset:    offset,
	}

	logs, total, err := h.analyticsService.ListOTPLogs(ctx, filter)
	if err != nil {
		h.logger.Error("failed to list OTP logs", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err, "Failed to fetch OTP logs")
		return
	}

	h.respondSuccess(w, map[string]interface{}{
		"logs": logs,
		"pagination": map[string]interface{}{
			"page":       page,
			"limit":      limit,
			"total":      total,
			"totalPages": (total + limit - 1) / limit,
		},
	}, "OTP logs retrieved")
}

// GetOTPStats returns aggregated OTP statistics.
// GET /api/v1/companies/{companyID}/analytics/otp/stats
func (h *AnalyticsHandler) GetOTPStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	if _, err := uuid.Parse(companyIDStr); err != nil {
		h.respondError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}
	start, end := h.parseDateRange(r)
	userID := h.parseStringPtr(r, "user_id")

	stats, err := h.analyticsService.GetOTPStats(ctx, userID, start, end)
	if err != nil {
		h.logger.Error("failed to get OTP stats", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err, "Failed to fetch OTP stats")
		return
	}
	h.respondSuccess(w, stats, "OTP stats retrieved")
}

// ExportOTPLogs exports OTP logs in JSON or CSV.
// GET /api/v1/companies/{companyID}/analytics/otp/export
func (h *AnalyticsHandler) ExportOTPLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	if _, err := uuid.Parse(companyIDStr); err != nil {
		h.respondError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}
	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" {
		h.respondError(w, http.StatusBadRequest, nil, "Unsupported format, use 'json' or 'csv'")
		return
	}
	start, end := h.parseDateRange(r)
	filter := clickhouse.OTPSearchFilter{
		UserID:    h.parseStringPtr(r, "user_id"),
		Phone:     h.parseStringPtr(r, "phone"),
		Status:    h.parseStringPtr(r, "status"),
		StartDate: start,
		EndDate:   end,
		Limit:     10000, // large export
		Offset:    0,
	}

	data, contentType, err := h.analyticsService.ExportOTPLogs(ctx, filter, format)
	if err != nil {
		h.logger.Error("failed to export OTP logs", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err, "Failed to export OTP logs")
		return
	}
	filename := fmt.Sprintf("otp_logs_%s.%s", time.Now().Format("20060102150405"), format)
	h.respondFile(w, data, contentType, filename)
}

// --------------------------------------------------------------------------
// 2. MPIN LOGS
// --------------------------------------------------------------------------

// GetMPINLogs returns paginated MPIN logs with filters.
// GET /api/v1/companies/{companyID}/analytics/mpin
func (h *AnalyticsHandler) GetMPINLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	if _, err := uuid.Parse(companyIDStr); err != nil {
		h.respondError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	page, limit, offset := h.parsePagination(r)
	start, end := h.parseDateRange(r)
	filter := clickhouse.MPINSearchFilter{
		UserID:    h.parseStringPtr(r, "user_id"),
		Status:    h.parseStringPtr(r, "status"),
		IsLocked:  h.parseBoolPtr(r, "is_locked"),
		StartDate: start,
		EndDate:   end,
		Limit:     limit,
		Offset:    offset,
	}

	logs, total, err := h.analyticsService.ListMPINLogs(ctx, filter)
	if err != nil {
		h.logger.Error("failed to list MPIN logs", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err, "Failed to fetch MPIN logs")
		return
	}

	h.respondSuccess(w, map[string]interface{}{
		"logs": logs,
		"pagination": map[string]interface{}{
			"page":       page,
			"limit":      limit,
			"total":      total,
			"totalPages": (total + limit - 1) / limit,
		},
	}, "MPIN logs retrieved")
}

// GetMPINStats returns aggregated MPIN statistics.
// GET /api/v1/companies/{companyID}/analytics/mpin/stats
func (h *AnalyticsHandler) GetMPINStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	if _, err := uuid.Parse(companyIDStr); err != nil {
		h.respondError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}
	start, end := h.parseDateRange(r)
	userID := h.parseStringPtr(r, "user_id")

	stats, err := h.analyticsService.GetMPINStats(ctx, userID, start, end)
	if err != nil {
		h.logger.Error("failed to get MPIN stats", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err, "Failed to fetch MPIN stats")
		return
	}
	h.respondSuccess(w, stats, "MPIN stats retrieved")
}

// ExportMPINLogs exports MPIN logs in JSON or CSV.
// GET /api/v1/companies/{companyID}/analytics/mpin/export
func (h *AnalyticsHandler) ExportMPINLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	if _, err := uuid.Parse(companyIDStr); err != nil {
		h.respondError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}
	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" {
		h.respondError(w, http.StatusBadRequest, nil, "Unsupported format, use 'json' or 'csv'")
		return
	}
	start, end := h.parseDateRange(r)
	filter := clickhouse.MPINSearchFilter{
		UserID:    h.parseStringPtr(r, "user_id"),
		Status:    h.parseStringPtr(r, "status"),
		IsLocked:  h.parseBoolPtr(r, "is_locked"),
		StartDate: start,
		EndDate:   end,
		Limit:     10000,
		Offset:    0,
	}

	data, contentType, err := h.analyticsService.ExportMPINLogs(ctx, filter, format)
	if err != nil {
		h.logger.Error("failed to export MPIN logs", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err, "Failed to export MPIN logs")
		return
	}
	filename := fmt.Sprintf("mpin_logs_%s.%s", time.Now().Format("20060102150405"), format)
	h.respondFile(w, data, contentType, filename)
}

// --------------------------------------------------------------------------
// 3. DEVICE LOGS
// --------------------------------------------------------------------------

// GetDeviceLogs returns paginated device logs with filters.
// GET /api/v1/companies/{companyID}/analytics/device
func (h *AnalyticsHandler) GetDeviceLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	if _, err := uuid.Parse(companyIDStr); err != nil {
		h.respondError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	page, limit, offset := h.parsePagination(r)
	start, end := h.parseDateRange(r)
	filter := clickhouse.DeviceSearchFilter{
		UserID:    h.parseStringPtr(r, "user_id"),
		DeviceID:  h.parseStringPtr(r, "device_id"),
		Action:    h.parseStringPtr(r, "action"),
		Status:    h.parseStringPtr(r, "status"),
		StartDate: start,
		EndDate:   end,
		Limit:     limit,
		Offset:    offset,
	}

	logs, total, err := h.analyticsService.ListDeviceLogs(ctx, filter)
	if err != nil {
		h.logger.Error("failed to list device logs", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err, "Failed to fetch device logs")
		return
	}

	h.respondSuccess(w, map[string]interface{}{
		"logs": logs,
		"pagination": map[string]interface{}{
			"page":       page,
			"limit":      limit,
			"total":      total,
			"totalPages": (total + limit - 1) / limit,
		},
	}, "Device logs retrieved")
}

// GetDeviceStats returns aggregated device statistics.
// GET /api/v1/companies/{companyID}/analytics/device/stats
func (h *AnalyticsHandler) GetDeviceStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	if _, err := uuid.Parse(companyIDStr); err != nil {
		h.respondError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}
	start, end := h.parseDateRange(r)
	userID := h.parseStringPtr(r, "user_id")

	stats, err := h.analyticsService.GetDeviceStats(ctx, userID, start, end)
	if err != nil {
		h.logger.Error("failed to get device stats", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err, "Failed to fetch device stats")
		return
	}
	h.respondSuccess(w, stats, "Device stats retrieved")
}

// ExportDeviceLogs exports device logs in JSON or CSV.
// GET /api/v1/companies/{companyID}/analytics/device/export
func (h *AnalyticsHandler) ExportDeviceLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	if _, err := uuid.Parse(companyIDStr); err != nil {
		h.respondError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}
	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" {
		h.respondError(w, http.StatusBadRequest, nil, "Unsupported format, use 'json' or 'csv'")
		return
	}
	start, end := h.parseDateRange(r)
	filter := clickhouse.DeviceSearchFilter{
		UserID:    h.parseStringPtr(r, "user_id"),
		DeviceID:  h.parseStringPtr(r, "device_id"),
		Action:    h.parseStringPtr(r, "action"),
		Status:    h.parseStringPtr(r, "status"),
		StartDate: start,
		EndDate:   end,
		Limit:     10000,
		Offset:    0,
	}

	data, contentType, err := h.analyticsService.ExportDeviceLogs(ctx, filter, format)
	if err != nil {
		h.logger.Error("failed to export device logs", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err, "Failed to export device logs")
		return
	}
	filename := fmt.Sprintf("device_logs_%s.%s", time.Now().Format("20060102150405"), format)
	h.respondFile(w, data, contentType, filename)
}

// --------------------------------------------------------------------------
// 4. SECURITY LOGS (ClickHouse)
// --------------------------------------------------------------------------

// GetSecurityLogs returns paginated security logs with filters.
// GET /api/v1/companies/{companyID}/analytics/security
func (h *AnalyticsHandler) GetSecurityLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	if _, err := uuid.Parse(companyIDStr); err != nil {
		h.respondError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	page, limit, offset := h.parsePagination(r)
	start, end := h.parseDateRange(r)
	filter := clickhouse.SecuritySearchFilter{
		UserID:        h.parseStringPtr(r, "user_id"),
		EventCategory: h.parseStringPtr(r, "event_category"),
		Severity:      h.parseStringPtr(r, "severity"),
		IPAddress:     h.parseStringPtr(r, "ip_address"),
		Action:        h.parseStringPtr(r, "action"),
		StartDate:     start,
		EndDate:       end,
		Limit:         limit,
		Offset:        offset,
	}

	logs, total, err := h.analyticsService.ListSecurityLogs(ctx, filter)
	if err != nil {
		h.logger.Error("failed to list security logs", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err, "Failed to fetch security logs")
		return
	}

	h.respondSuccess(w, map[string]interface{}{
		"logs": logs,
		"pagination": map[string]interface{}{
			"page":       page,
			"limit":      limit,
			"total":      total,
			"totalPages": (total + limit - 1) / limit,
		},
	}, "Security logs retrieved")
}

// GetSecurityStats returns aggregated security statistics.
// GET /api/v1/companies/{companyID}/analytics/security/stats
func (h *AnalyticsHandler) GetSecurityStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	if _, err := uuid.Parse(companyIDStr); err != nil {
		h.respondError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}
	start, end := h.parseDateRange(r)
	userID := h.parseStringPtr(r, "user_id")

	stats, err := h.analyticsService.GetSecurityStats(ctx, userID, start, end)
	if err != nil {
		h.logger.Error("failed to get security stats", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err, "Failed to fetch security stats")
		return
	}
	h.respondSuccess(w, stats, "Security stats retrieved")
}

// ExportSecurityLogs exports security logs in JSON or CSV.
// GET /api/v1/companies/{companyID}/analytics/security/export
func (h *AnalyticsHandler) ExportSecurityLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	if _, err := uuid.Parse(companyIDStr); err != nil {
		h.respondError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}
	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" {
		h.respondError(w, http.StatusBadRequest, nil, "Unsupported format, use 'json' or 'csv'")
		return
	}
	start, end := h.parseDateRange(r)
	filter := clickhouse.SecuritySearchFilter{
		UserID:        h.parseStringPtr(r, "user_id"),
		EventCategory: h.parseStringPtr(r, "event_category"),
		Severity:      h.parseStringPtr(r, "severity"),
		IPAddress:     h.parseStringPtr(r, "ip_address"),
		Action:        h.parseStringPtr(r, "action"),
		StartDate:     start,
		EndDate:       end,
		Limit:         10000,
		Offset:        0,
	}

	data, contentType, err := h.analyticsService.ExportSecurityLogs(ctx, filter, format)
	if err != nil {
		h.logger.Error("failed to export security logs", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err, "Failed to export security logs")
		return
	}
	filename := fmt.Sprintf("security_logs_%s.%s", time.Now().Format("20060102150405"), format)
	h.respondFile(w, data, contentType, filename)
}

// --------------------------------------------------------------------------
// 5. SECURITY RISK LOGS
// --------------------------------------------------------------------------

// GetSecurityRiskLogs returns paginated security risk logs with filters.
// GET /api/v1/companies/{companyID}/analytics/security-risk
func (h *AnalyticsHandler) GetSecurityRiskLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	if _, err := uuid.Parse(companyIDStr); err != nil {
		h.respondError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	page, limit, offset := h.parsePagination(r)
	start, end := h.parseDateRange(r)
	filter := clickhouse.SecurityRiskSearchFilter{
		PhoneNumber:  h.parseStringPtr(r, "phone"),
		IPAddress:    h.parseStringPtr(r, "ip_address"),
		RiskScoreMin: h.parseIntPtr(r, "risk_score_min"),
		ActionTaken:  h.parseStringPtr(r, "action_taken"),
		StartDate:    start,
		EndDate:      end,
		Limit:        limit,
		Offset:       offset,
	}

	logs, total, err := h.analyticsService.ListSecurityRiskLogs(ctx, filter)
	if err != nil {
		h.logger.Error("failed to list security risk logs", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err, "Failed to fetch security risk logs")
		return
	}

	h.respondSuccess(w, map[string]interface{}{
		"logs": logs,
		"pagination": map[string]interface{}{
			"page":       page,
			"limit":      limit,
			"total":      total,
			"totalPages": (total + limit - 1) / limit,
		},
	}, "Security risk logs retrieved")
}

// GetSecurityRiskStats returns aggregated security risk statistics.
// GET /api/v1/companies/{companyID}/analytics/security-risk/stats
func (h *AnalyticsHandler) GetSecurityRiskStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	if _, err := uuid.Parse(companyIDStr); err != nil {
		h.respondError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}
	start, end := h.parseDateRange(r)
	phone := h.parseStringPtr(r, "phone")

	stats, err := h.analyticsService.GetSecurityRiskStats(ctx, phone, start, end)
	if err != nil {
		h.logger.Error("failed to get security risk stats", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err, "Failed to fetch security risk stats")
		return
	}
	h.respondSuccess(w, stats, "Security risk stats retrieved")
}

// ExportSecurityRiskLogs exports security risk logs in JSON or CSV.
// GET /api/v1/companies/{companyID}/analytics/security-risk/export
func (h *AnalyticsHandler) ExportSecurityRiskLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	if _, err := uuid.Parse(companyIDStr); err != nil {
		h.respondError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}
	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" {
		h.respondError(w, http.StatusBadRequest, nil, "Unsupported format, use 'json' or 'csv'")
		return
	}
	start, end := h.parseDateRange(r)
	filter := clickhouse.SecurityRiskSearchFilter{
		PhoneNumber:  h.parseStringPtr(r, "phone"),
		IPAddress:    h.parseStringPtr(r, "ip_address"),
		RiskScoreMin: h.parseIntPtr(r, "risk_score_min"),
		ActionTaken:  h.parseStringPtr(r, "action_taken"),
		StartDate:    start,
		EndDate:      end,
		Limit:        10000,
		Offset:       0,
	}

	data, contentType, err := h.analyticsService.ExportSecurityRiskLogs(ctx, filter, format)
	if err != nil {
		h.logger.Error("failed to export security risk logs", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err, "Failed to export security risk logs")
		return
	}
	filename := fmt.Sprintf("security_risk_logs_%s.%s", time.Now().Format("20060102150405"), format)
	h.respondFile(w, data, contentType, filename)
}

// --------------------------------------------------------------------------
// 6. DASHBOARD
// --------------------------------------------------------------------------

// GetDashboardStats returns a combined summary for all event types.
// GET /api/v1/companies/{companyID}/analytics/dashboard
func (h *AnalyticsHandler) GetDashboardStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	if _, err := uuid.Parse(companyIDStr); err != nil {
		h.respondError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}
	start, end := h.parseDateRange(r)
	userID := h.parseStringPtr(r, "user_id")

	stats, err := h.analyticsService.GetDashboardStats(ctx, userID, start, end)
	if err != nil {
		h.logger.Error("failed to get dashboard stats", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err, "Failed to fetch dashboard stats")
		return
	}
	h.respondSuccess(w, stats, "Dashboard stats retrieved")
}

// --------------------------------------------------------------------------
// 7. ELASTICSEARCH SEARCH ENDPOINTS (Admin only)
// --------------------------------------------------------------------------

// SearchAdminLogs searches admin events in Elasticsearch.
// GET /api/v1/admin/analytics/admin/search
func (h *AnalyticsHandler) SearchAdminLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	filter := elasticsearch.AdminSearchFilter{
		AdminID:      h.parseStringPtr(r, "admin_id"),
		Action:       h.parseStringPtr(r, "action"),
		Status:       h.parseStringPtr(r, "status"),
		ErrorCode:    h.parseStringPtr(r, "error_code"),
		ResourceType: h.parseStringPtr(r, "resource_type"),
	}
	start, end := h.parseDateRange(r)
	filter.StartDate, filter.EndDate = start, end
	page, limit, offset := h.parsePagination(r)
	filter.Limit, filter.Offset = limit, offset

	logs, total, err := h.analyticsService.SearchAdminLogs(ctx, filter)
	if err != nil {
		h.logger.Error("failed to search admin logs", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err, "Failed to search admin logs")
		return
	}
	h.respondSuccess(w, map[string]interface{}{
		"logs": logs,
		"pagination": map[string]interface{}{
			"page":       page,
			"limit":      limit,
			"total":      total,
			"totalPages": (total + limit - 1) / limit,
		},
	}, "Admin logs search completed")
}

// SearchSessionLogs searches session events in Elasticsearch.
// GET /api/v1/admin/analytics/session/search
func (h *AnalyticsHandler) SearchSessionLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	filter := elasticsearch.SessionSearchFilter{
		UserID:      h.parseStringPtr(r, "user_id"),
		SessionType: h.parseStringPtr(r, "session_type"),
		Status:      h.parseStringPtr(r, "status"),
	}
	start, end := h.parseDateRange(r)
	filter.StartDate, filter.EndDate = start, end
	page, limit, offset := h.parsePagination(r)
	filter.Limit, filter.Offset = limit, offset

	logs, total, err := h.analyticsService.SearchSessionLogs(ctx, filter)
	if err != nil {
		h.logger.Error("failed to search session logs", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err, "Failed to search session logs")
		return
	}
	h.respondSuccess(w, map[string]interface{}{
		"logs": logs,
		"pagination": map[string]interface{}{
			"page":       page,
			"limit":      limit,
			"total":      total,
			"totalPages": (total + limit - 1) / limit,
		},
	}, "Session logs search completed")
}

// SearchUserLogs searches user events in Elasticsearch.
// GET /api/v1/admin/analytics/user/search
func (h *AnalyticsHandler) SearchUserLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	filter := elasticsearch.UserSearchFilter{
		UserID: h.parseStringPtr(r, "user_id"),
		Action: h.parseStringPtr(r, "action"),
		Status: h.parseStringPtr(r, "status"),
	}
	start, end := h.parseDateRange(r)
	filter.StartDate, filter.EndDate = start, end
	page, limit, offset := h.parsePagination(r)
	filter.Limit, filter.Offset = limit, offset

	logs, total, err := h.analyticsService.SearchUserLogs(ctx, filter)
	if err != nil {
		h.logger.Error("failed to search user logs", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err, "Failed to search user logs")
		return
	}
	h.respondSuccess(w, map[string]interface{}{
		"logs": logs,
		"pagination": map[string]interface{}{
			"page":       page,
			"limit":      limit,
			"total":      total,
			"totalPages": (total + limit - 1) / limit,
		},
	}, "User logs search completed")
}

// SearchSecurityLogsES searches security events in Elasticsearch.
// GET /api/v1/admin/analytics/security/search
func (h *AnalyticsHandler) SearchSecurityLogsES(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	filter := elasticsearch.SecuritySearchFilter{
		UserID:        h.parseStringPtr(r, "user_id"),
		EventCategory: h.parseStringPtr(r, "event_category"),
		Severity:      h.parseStringPtr(r, "severity"),
		Action:        h.parseStringPtr(r, "action"),
		IPAddress:     h.parseStringPtr(r, "ip_address"),
	}
	start, end := h.parseDateRange(r)
	filter.StartDate, filter.EndDate = start, end
	page, limit, offset := h.parsePagination(r)
	filter.Limit, filter.Offset = limit, offset

	logs, total, err := h.analyticsService.SearchSecurityLogsES(ctx, filter)
	if err != nil {
		h.logger.Error("failed to search security logs (ES)", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err, "Failed to search security logs")
		return
	}
	h.respondSuccess(w, map[string]interface{}{
		"logs": logs,
		"pagination": map[string]interface{}{
			"page":       page,
			"limit":      limit,
			"total":      total,
			"totalPages": (total + limit - 1) / limit,
		},
	}, "Security logs search completed")
}

// GlobalSearch performs a full-text search across all Elasticsearch indices.
// GET /api/v1/admin/analytics/search
func (h *AnalyticsHandler) GlobalSearch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query().Get("q")
	if query == "" {
		h.respondError(w, http.StatusBadRequest, nil, "Search query 'q' is required")
		return
	}
	filter := elasticsearch.GlobalSearchFilter{
		Query: query,
		Index: h.parseStringPtr(r, "index"), // optional: "admin", "session", "user", "security"
	}
	start, end := h.parseDateRange(r)
	filter.StartDate, filter.EndDate = start, end
	page, limit, offset := h.parsePagination(r)
	filter.Limit, filter.Offset = limit, offset

	results, total, err := h.analyticsService.GlobalSearch(ctx, filter)
	if err != nil {
		h.logger.Error("failed to perform global search", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err, "Failed to perform global search")
		return
	}
	h.respondSuccess(w, map[string]interface{}{
		"results": results,
		"pagination": map[string]interface{}{
			"page":       page,
			"limit":      limit,
			"total":      total,
			"totalPages": (total + limit - 1) / limit,
		},
	}, "Global search completed")
}

// --------------------------------------------------------------------------
// 8. HEALTH
// --------------------------------------------------------------------------

// HealthCheck returns the health status of the analytics subsystem.
// GET /api/v1/admin/analytics/health
func (h *AnalyticsHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := h.analyticsService.HealthCheck(ctx); err != nil {
		h.logger.Error("analytics health check failed", zap.Error(err))
		h.respondJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"success": false,
			"status":  "unhealthy",
			"error":   err.Error(),
		})
		return
	}
	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"status":  "healthy",
	})
}

// =============================================================================
// SYSTEM-WIDE LOG ENDPOINTS (no company ID) – Admin only
// =============================================================================

// GetSystemOTPLogs handles GET /admin/analytics/otp
func (h *AnalyticsHandler) GetSystemOTPLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	page, limit, offset := h.parsePagination(r)
	start, end := h.parseDateRange(r)
	filter := clickhouse.OTPSearchFilter{
		UserID:    h.parseStringPtr(r, "user_id"),
		Phone:     h.parseStringPtr(r, "phone"),
		Status:    h.parseStringPtr(r, "status"),
		StartDate: start,
		EndDate:   end,
		Limit:     limit,
		Offset:    offset,
	}

	logs, total, err := h.analyticsService.ListOTPLogs(ctx, filter)
	if err != nil {
		h.logger.Error("failed to list system OTP logs", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err, "Failed to fetch OTP logs")
		return
	}

	h.respondSuccess(w, map[string]interface{}{
		"logs": logs,
		"pagination": map[string]interface{}{
			"page":       page,
			"limit":      limit,
			"total":      total,
			"totalPages": (total + limit - 1) / limit,
		},
	}, "System OTP logs retrieved")
}

// GetSystemMPINLogs handles GET /admin/analytics/mpin
func (h *AnalyticsHandler) GetSystemMPINLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	page, limit, offset := h.parsePagination(r)
	start, end := h.parseDateRange(r)
	filter := clickhouse.MPINSearchFilter{
		UserID:    h.parseStringPtr(r, "user_id"),
		Status:    h.parseStringPtr(r, "status"),
		IsLocked:  h.parseBoolPtr(r, "is_locked"),
		StartDate: start,
		EndDate:   end,
		Limit:     limit,
		Offset:    offset,
	}

	logs, total, err := h.analyticsService.ListMPINLogs(ctx, filter)
	if err != nil {
		h.logger.Error("failed to list system MPIN logs", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err, "Failed to fetch MPIN logs")
		return
	}

	h.respondSuccess(w, map[string]interface{}{
		"logs": logs,
		"pagination": map[string]interface{}{
			"page":       page,
			"limit":      limit,
			"total":      total,
			"totalPages": (total + limit - 1) / limit,
		},
	}, "System MPIN logs retrieved")
}

// GetSystemDeviceLogs handles GET /admin/analytics/device
func (h *AnalyticsHandler) GetSystemDeviceLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	page, limit, offset := h.parsePagination(r)
	start, end := h.parseDateRange(r)
	filter := clickhouse.DeviceSearchFilter{
		UserID:    h.parseStringPtr(r, "user_id"),
		DeviceID:  h.parseStringPtr(r, "device_id"),
		Action:    h.parseStringPtr(r, "action"),
		Status:    h.parseStringPtr(r, "status"),
		StartDate: start,
		EndDate:   end,
		Limit:     limit,
		Offset:    offset,
	}

	logs, total, err := h.analyticsService.ListDeviceLogs(ctx, filter)
	if err != nil {
		h.logger.Error("failed to list system device logs", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err, "Failed to fetch device logs")
		return
	}

	h.respondSuccess(w, map[string]interface{}{
		"logs": logs,
		"pagination": map[string]interface{}{
			"page":       page,
			"limit":      limit,
			"total":      total,
			"totalPages": (total + limit - 1) / limit,
		},
	}, "System device logs retrieved")
}

// GetSystemSecurityLogs handles GET /admin/analytics/security
func (h *AnalyticsHandler) GetSystemSecurityLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	page, limit, offset := h.parsePagination(r)
	start, end := h.parseDateRange(r)
	filter := clickhouse.SecuritySearchFilter{
		UserID:        h.parseStringPtr(r, "user_id"),
		EventCategory: h.parseStringPtr(r, "event_category"),
		Severity:      h.parseStringPtr(r, "severity"),
		IPAddress:     h.parseStringPtr(r, "ip_address"),
		Action:        h.parseStringPtr(r, "action"),
		StartDate:     start,
		EndDate:       end,
		Limit:         limit,
		Offset:        offset,
	}

	logs, total, err := h.analyticsService.ListSecurityLogs(ctx, filter)
	if err != nil {
		h.logger.Error("failed to list system security logs", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err, "Failed to fetch security logs")
		return
	}

	h.respondSuccess(w, map[string]interface{}{
		"logs": logs,
		"pagination": map[string]interface{}{
			"page":       page,
			"limit":      limit,
			"total":      total,
			"totalPages": (total + limit - 1) / limit,
		},
	}, "System security logs retrieved")
}

// GetSystemSecurityRiskLogs handles GET /admin/analytics/security-risk
func (h *AnalyticsHandler) GetSystemSecurityRiskLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	page, limit, offset := h.parsePagination(r)
	start, end := h.parseDateRange(r)
	filter := clickhouse.SecurityRiskSearchFilter{
		PhoneNumber:  h.parseStringPtr(r, "phone"),
		IPAddress:    h.parseStringPtr(r, "ip_address"),
		RiskScoreMin: h.parseIntPtr(r, "risk_score_min"),
		ActionTaken:  h.parseStringPtr(r, "action_taken"),
		StartDate:    start,
		EndDate:      end,
		Limit:        limit,
		Offset:       offset,
	}

	logs, total, err := h.analyticsService.ListSecurityRiskLogs(ctx, filter)
	if err != nil {
		h.logger.Error("failed to list system security risk logs", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, err, "Failed to fetch security risk logs")
		return
	}

	h.respondSuccess(w, map[string]interface{}{
		"logs": logs,
		"pagination": map[string]interface{}{
			"page":       page,
			"limit":      limit,
			"total":      total,
			"totalPages": (total + limit - 1) / limit,
		},
	}, "System security risk logs retrieved")
}
