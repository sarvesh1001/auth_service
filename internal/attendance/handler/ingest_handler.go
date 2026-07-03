package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/service/ingest"
)

// AttendanceIngestHandler handles attendance punch ingestion.
type AttendanceIngestHandler struct {
	ingestService ingest.IngestService
	logger        *zap.Logger
}

// NewAttendanceIngestHandler creates a new handler.
func NewAttendanceIngestHandler(
	ingestService ingest.IngestService,
	logger *zap.Logger,
) *AttendanceIngestHandler {
	return &AttendanceIngestHandler{
		ingestService: ingestService,
		logger:        logger,
	}
}

// PunchHTTPRequest is the common request for user/admin punches.
type PunchHTTPRequest struct {
	TargetUserID uuid.UUID  `json:"target_user_id"`
	SubjectType  string     `json:"subject_type,omitempty"` // 👈 NEW: allows "student", "employee", etc.
	EventType    string     `json:"event_type"`
	EventTime    *time.Time `json:"event_time,omitempty"`
	Source       struct {
		SourceType string     `json:"source_type"`
		SourceID   *uuid.UUID `json:"source_id"`
		DeviceID   *string    `json:"device_id"`
		IPAddress  *string    `json:"ip_address"`
	} `json:"source"`
	Context *models.EventContext `json:"context,omitempty"`
}

// PunchAttendance is the main entry point; it routes to device or user handler.
func (h *AttendanceIngestHandler) PunchAttendance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sessionType := getSessionTypeFromContext(ctx)
	if sessionType == "device" {
		h.handleDevicePunch(w, r, ctx)
		return
	}
	h.handleUserPunch(w, r, ctx)
}

// handleDevicePunch rejects device requests (use dedicated endpoint).
func (h *AttendanceIngestHandler) handleDevicePunch(w http.ResponseWriter, r *http.Request, ctx context.Context) {
	h.respondWithError(
		w,
		http.StatusBadRequest,
		"use /attendance-device/events/punch for device attendance",
	)
}

// handleUserPunch processes punches from authenticated users (including admins).
func (h *AttendanceIngestHandler) handleUserPunch(w http.ResponseWriter, r *http.Request, ctx context.Context) {
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "company context required")
		return
	}

	var req PunchHTTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.TargetUserID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "target_user_id is required")
		return
	}
	if req.EventType == "" {
		h.respondWithError(w, http.StatusBadRequest, "event_type is required")
		return
	}
	if req.Source.SourceType == "" {
		h.respondWithError(w, http.StatusBadRequest, "source_type is required")
		return
	}

	// 👇 Determine subject type – default to "employee" if not provided
	subjectType := req.SubjectType
	if subjectType == "" {
		subjectType = "employee"
	}

	ip := req.Source.IPAddress
	if ip == nil || *ip == "" {
		resolvedIP := h.getClientIP(r)
		ip = &resolvedIP
	}

	punchReq := &ingest.PunchRequest{
		CompanyID:   companyID,
		ActorID:     actorID,
		SubjectType: subjectType, // 👈 dynamic
		SubjectID:   req.TargetUserID,
		EventType:   req.EventType,
		EventTime:   req.EventTime,
		Source: ingest.PunchSource{
			SourceType: req.Source.SourceType,
			SourceID:   req.Source.SourceID,
			DeviceID:   req.Source.DeviceID,
			IPAddress:  ip,
		},
		Context: req.Context,
	}

	event, err := h.ingestService.IngestPunch(ctx, punchReq)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    event,
	})
}

// DevicePunchAttendance handles device-only punches (uses device auth context).
func (h *AttendanceIngestHandler) DevicePunchAttendance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	sessionType := getSessionTypeFromContext(ctx)
	if sessionType != "device" {
		h.respondWithError(w, http.StatusUnauthorized, "device authentication required")
		return
	}

	authCtx, ok := ctx.Value("device_auth_context").(*models.DeviceAuthContext)
	if !ok || authCtx == nil {
		h.respondWithError(w, http.StatusUnauthorized, "device authentication required")
		return
	}

	var req struct {
		EventType      string               `json:"event_type"`
		EventTime      *time.Time           `json:"event_time,omitempty"`
		DeviceUserCode string               `json:"device_user_code"`
		Context        *models.EventContext `json:"context,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.EventType == "" {
		h.respondWithError(w, http.StatusBadRequest, "event_type required")
		return
	}
	if req.DeviceUserCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "device_user_code required")
		return
	}

	ctxObj := req.Context
	if ctxObj == nil {
		ctxObj = &models.EventContext{}
	}
	if authCtx.WorkCenterID != nil && ctxObj.WorkCenterCode == nil {
		ctxObj.WorkCenterCode = authCtx.WorkCenterID
	}

	ip := h.getClientIP(r)
	deviceID := authCtx.DeviceID

	punchReq := &ingest.PunchRequest{
		CompanyID:      authCtx.CompanyID,
		EventType:      req.EventType,
		EventTime:      req.EventTime,
		DeviceUserCode: &req.DeviceUserCode,
		Source: ingest.PunchSource{
			SourceType: authCtx.SourceType,
			DeviceID:   &deviceID,
			IPAddress:  &ip,
		},
		Context: ctxObj,
	}

	event, err := h.ingestService.IngestPunch(ctx, punchReq)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    event,
	})
}

// SelfPunchAttendance allows a user to punch for themselves.
func (h *AttendanceIngestHandler) SelfPunchAttendance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	sessionType := getSessionTypeFromContext(ctx)
	if sessionType == "device" {
		h.respondWithError(w, http.StatusUnauthorized, "user authentication required")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "company context required")
		return
	}

	var req struct {
		EventType   string `json:"event_type"`
		SubjectType string `json:"subject_type,omitempty"` // 👈 NEW
		Source      struct {
			SourceType string  `json:"source_type"`
			DeviceID   *string `json:"device_id"`
			IPAddress  *string `json:"ip_address"`
		} `json:"source"`
		Context *models.EventContext `json:"context,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.EventType == "" {
		h.respondWithError(w, http.StatusBadRequest, "event_type required")
		return
	}
	if req.Source.SourceType == "" {
		h.respondWithError(w, http.StatusBadRequest, "source_type required")
		return
	}

	subjectType := req.SubjectType
	if subjectType == "" {
		subjectType = "employee" // default
	}

	ip := req.Source.IPAddress
	if ip == nil || *ip == "" {
		resolvedIP := h.getClientIP(r)
		ip = &resolvedIP
	}

	punchReq := &ingest.PunchRequest{
		CompanyID:   companyID,
		ActorID:     userID,
		SubjectType: subjectType,
		SubjectID:   userID,
		EventType:   req.EventType,
		EventTime:   nil, // server time
		Source: ingest.PunchSource{
			SourceType: req.Source.SourceType,
			DeviceID:   req.Source.DeviceID,
			IPAddress:  ip,
		},
		Context: req.Context,
	}

	event, err := h.ingestService.IngestPunch(ctx, punchReq)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    event,
	})
}

// getClientIP extracts the client IP from the request.
func (h *AttendanceIngestHandler) getClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}

// response helpers
func (h *AttendanceIngestHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *AttendanceIngestHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
