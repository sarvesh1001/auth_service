package handler

import (
	"auth-service/internal/hr/models/attendance"
	"auth-service/internal/hr/service"
	"auth-service/internal/util"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ============================================
// ATTENDANCE INGEST HANDLER (STRICT I/O ONLY)
// ============================================

// AttendanceIngestHandler handles attendance event ingestion
type AttendanceIngestHandler struct {
	attendanceIngestService service.AttendanceIngestService
	logger                  *zap.Logger
}

// NewAttendanceIngestHandler creates a new attendance ingest handler
func NewAttendanceIngestHandler(
	attendanceIngestService service.AttendanceIngestService,
	logger *zap.Logger,
) *AttendanceIngestHandler {
	return &AttendanceIngestHandler{
		attendanceIngestService: attendanceIngestService,
		logger:                  logger,
	}
}

// ============================================
// HTTP REQUEST DTO (ONLY HTTP CONCERNS)
// ============================================

// PunchHTTPRequest is the HTTP layer DTO for attendance punch
// ⚠️ No validation tags here. All validation is in the service.
type PunchHTTPRequest struct {
	TargetUserID uuid.UUID `json:"target_user_id"`
	EventType    string    `json:"event_type"`
	EventTime    time.Time `json:"event_time"`
	Source       struct {
		SourceType string     `json:"source_type"`
		SourceID   *uuid.UUID `json:"source_id"`
		DeviceID   *string    `json:"device_id"`
		IPAddress  *string    `json:"ip_address"`
	} `json:"source"`
	Context *attendance.EventContext `json:"context,omitempty"`
}

// ============================================
// HANDLER METHOD (THE CORE - I/O ONLY)
// ============================================

// PunchAttendance handles attendance punch ingestion
// HTTP: POST /companies/{companyId}/attendance/events/punch
func (h *AttendanceIngestHandler) PunchAttendance(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	// =====================================================
	// 1. AUTH CONTEXT
	// =====================================================

	_, ok := ctx.Value("session_type").(string)
	if !ok {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	actorIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	actorID, err := uuid.Parse(actorIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "invalid user identity")
		return
	}

	// =====================================================
	// 2. COMPANY CONTEXT (FIXED)
	// =====================================================

	companyIDStr, ok := ctx.Value("company_id").(string)
	if !ok || companyIDStr == "" {
		// 🔧 fallback for missing middleware
		companyIDStr = r.Header.Get("X-Company-ID")
	}

	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company context required")
		return
	}

	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	// =====================================================
	// 3. DECODE REQUEST
	// =====================================================

	var req PunchHTTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// =====================================================
	// 4. SELF-PUNCH ONLY (UNCHANGED)
	// =====================================================

	if req.TargetUserID != actorID {
		h.respondWithError(w, http.StatusForbidden, "cannot punch for another user")
		return
	}

	// =====================================================
	// 5. EVENT TIME
	// =====================================================

	eventTime := req.EventTime.UTC()

	// =====================================================
	// 6. IP ADDRESS (FIXED)
	// =====================================================

	clientIP := req.Source.IPAddress
	if clientIP == nil || *clientIP == "" {
		ip := h.getClientIP(r)
		clientIP = &ip
	}

	// =====================================================
	// 7. DEVICE ID (UNCHANGED)
	// =====================================================

	deviceID := req.Source.DeviceID
	if deviceID == nil {
		if headerDevice := r.Header.Get("X-Device-ID"); headerDevice != "" {
			deviceID = &headerDevice
		}
	}

	// =====================================================
	// 8. SERVICE REQUEST
	// =====================================================

	punchReq := &service.PunchRequest{
		CompanyID:    companyID,
		ActorID:      actorID,
		TargetUserID: req.TargetUserID,
		EventType:    req.EventType,
		EventTime:    eventTime,
		Source: service.PunchSource{
			SourceType: req.Source.SourceType,
			SourceID:   req.Source.SourceID,
			DeviceID:   deviceID,
			IPAddress:  clientIP,
		},
		Context: req.Context,
	}

	// =====================================================
	// 9. INGEST
	// =====================================================

	event, err := h.attendanceIngestService.IngestPunch(ctx, punchReq)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// =====================================================
	// 10. RESPONSE
	// =====================================================

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    event,
	})
}

// ============================================
// HELPER METHODS (I/O ONLY)
// ============================================

// getClientIP extracts client IP address from request
func (h *AttendanceIngestHandler) getClientIP(r *http.Request) string {
	// Check for forwarded headers (load balancer/proxy)
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}

	// Fallback to remote address
	return r.RemoteAddr
}

// respondWithJSON sends a JSON response
func (h *AttendanceIngestHandler) respondWithJSON(
	w http.ResponseWriter,
	statusCode int,
	data interface{},
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response",
			util.ErrorField(err))
	}
}

// respondWithError sends an error response
func (h *AttendanceIngestHandler) respondWithError(
	w http.ResponseWriter,
	statusCode int,
	message string,
) {
	h.respondWithJSON(w, statusCode, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
