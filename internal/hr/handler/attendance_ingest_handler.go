package handler

import (
	"auth-service/internal/hr/models/attendance"
	"auth-service/internal/hr/service"
	"auth-service/internal/util"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type AttendanceIngestHandler struct {
	attendanceIngestService service.AttendanceIngestService
	logger                  *zap.Logger
}

func NewAttendanceIngestHandler(
	attendanceIngestService service.AttendanceIngestService,
	logger *zap.Logger,
) *AttendanceIngestHandler {
	return &AttendanceIngestHandler{
		attendanceIngestService: attendanceIngestService,
		logger:                  logger,
	}
}

/*
===========================
COMMON USER / ADMIN REQUEST
===========================
*/
type PunchHTTPRequest struct {
	TargetUserID uuid.UUID  `json:"target_user_id"`
	EventType    string     `json:"event_type"`
	EventTime    *time.Time `json:"event_time,omitempty"`
	Source       struct {
		SourceType string     `json:"source_type"`
		SourceID   *uuid.UUID `json:"source_id"`
		DeviceID   *string    `json:"device_id"`
		IPAddress  *string    `json:"ip_address"`
	} `json:"source"`
	Context *attendance.EventContext `json:"context,omitempty"`
}

/*
===========================
ENTRY POINT
===========================
*/
func (h *AttendanceIngestHandler) PunchAttendance(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	sessionType, ok := ctx.Value("session_type").(string)
	if !ok {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if sessionType == "device" {
		h.handleDevicePunch(w, r, ctx)
		return
	}

	h.handleUserPunch(w, r, ctx)
}

/*
===========================
DEVICE PUNCH (LEGACY PATH)
(kept for safety – DO NOT REMOVE)
===========================
*/
func (h *AttendanceIngestHandler) handleDevicePunch(
	w http.ResponseWriter,
	r *http.Request,
	ctx context.Context,
) {
	h.respondWithError(
		w,
		http.StatusBadRequest,
		"use /attendance-device/events/punch for device attendance",
	)
}

/*
===========================
USER / ADMIN PUNCH
===========================
*/
func (h *AttendanceIngestHandler) handleUserPunch(
	w http.ResponseWriter,
	r *http.Request,
	ctx context.Context,
) {
	var actorID uuid.UUID
	if v := ctx.Value("user_id"); v != nil {
		switch t := v.(type) {
		case uuid.UUID:
			actorID = t
		case string:
			parsed, err := uuid.Parse(t)
			if err != nil {
				h.respondWithError(w, http.StatusUnauthorized, "invalid user identity")
				return
			}
			actorID = parsed
		default:
			h.respondWithError(w, http.StatusUnauthorized, "invalid user context")
			return
		}
	} else {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var companyID uuid.UUID
	if v := ctx.Value("company_id"); v != nil {
		switch t := v.(type) {
		case uuid.UUID:
			companyID = t
		case string:
			parsed, err := uuid.Parse(t)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid company id")
				return
			}
			companyID = parsed
		default:
			h.respondWithError(w, http.StatusBadRequest, "invalid company context")
			return
		}
	} else {
		h.respondWithError(w, http.StatusBadRequest, "company context required")
		return
	}

	var req PunchHTTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ip := req.Source.IPAddress
	if ip == nil || *ip == "" {
		resolved := h.getClientIP(r)
		ip = &resolved
	}

	punchReq := &service.PunchRequest{
		CompanyID:    companyID,
		ActorID:      actorID,
		TargetUserID: req.TargetUserID,
		EventType:    req.EventType,
		EventTime:    req.EventTime,
		Source: service.PunchSource{
			SourceType: req.Source.SourceType,
			SourceID:   req.Source.SourceID,
			DeviceID:   req.Source.DeviceID,
			IPAddress:  ip,
		},
		Context: req.Context,
	}

	event, err := h.attendanceIngestService.IngestPunch(ctx, punchReq)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    event,
	})
}

/*
===========================
DEVICE-ONLY PUNCH (CORRECT)
===========================
*/
func (h *AttendanceIngestHandler) DevicePunchAttendance(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	// -----------------------
	// SESSION VALIDATION
	// -----------------------
	sessionType, ok := ctx.Value("session_type").(string)
	if !ok || sessionType != "device" {
		h.respondWithError(w, http.StatusUnauthorized, "device authentication required")
		return
	}

	authContext, ok := ctx.Value("device_auth_context").(*attendance.DeviceAuthContext)
	if !ok || authContext == nil {
		h.respondWithError(w, http.StatusUnauthorized, "device authentication required")
		return
	}

	// -----------------------
	// REQUEST PAYLOAD
	// -----------------------
	var req struct {
		EventType      string                   `json:"event_type"`
		EventTime      *time.Time               `json:"event_time,omitempty"`
		DeviceUserCode string                   `json:"device_user_code"`
		Context        *attendance.EventContext `json:"context,omitempty"`
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

	// -----------------------
	// CONTEXT MERGE
	// -----------------------
	ctxObj := req.Context
	if ctxObj == nil {
		ctxObj = &attendance.EventContext{}
	}

	if authContext.WorkCenterID != nil && ctxObj.WorkCenterCode == nil {
		ctxObj.WorkCenterCode = authContext.WorkCenterID
	}

	ip := h.getClientIP(r)
	deviceID := authContext.DeviceID

	// -----------------------
	// BUILD PUNCH REQUEST
	// ❌ DO NOT SET SourceID HERE
	// -----------------------
	punchReq := &service.PunchRequest{
		CompanyID:      authContext.CompanyID,
		EventType:      req.EventType,
		EventTime:      req.EventTime,
		DeviceUserCode: &req.DeviceUserCode,
		Source: service.PunchSource{
			SourceType: authContext.SourceType,
			DeviceID:   &deviceID,
			IPAddress:  &ip,
		},
		Context: ctxObj,
	}

	// -----------------------
	// INGEST
	// -----------------------
	event, err := h.attendanceIngestService.IngestPunch(ctx, punchReq)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    event,
	})
}

/*
===========================
HELPERS
===========================
*/
func (h *AttendanceIngestHandler) getClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}

func (h *AttendanceIngestHandler) respondWithJSON(
	w http.ResponseWriter,
	statusCode int,
	data interface{},
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode response", util.ErrorField(err))
	}
}

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

func (h *AttendanceIngestHandler) SelfPunchAttendance(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	// 🔥 Must be user session
	sessionType, ok := ctx.Value("session_type").(string)
	if !ok || sessionType == "device" {
		h.respondWithError(w, http.StatusUnauthorized, "user authentication required")
		return
	}

	// 🔥 Get UserID from context
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		h.respondWithError(w, http.StatusUnauthorized, "invalid user context")
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "invalid user identity")
		return
	}

	// 🔥 Get CompanyID from context
	companyID, ok := ctx.Value("company_id").(uuid.UUID)
	if !ok {
		h.respondWithError(w, http.StatusBadRequest, "company context required")
		return
	}

	// 🔥 Request Body (NO target_user_id)
	var req struct {
		EventType string `json:"event_type"`
		Source    struct {
			SourceType string  `json:"source_type"`
			DeviceID   *string `json:"device_id"`
			IPAddress  *string `json:"ip_address"`
		} `json:"source"`
		Context *attendance.EventContext `json:"context,omitempty"`
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

	// 🔥 Resolve IP
	ip := req.Source.IPAddress
	if ip == nil || *ip == "" {
		resolved := h.getClientIP(r)
		ip = &resolved
	}

	// 🔥 Build PunchRequest
	punchReq := &service.PunchRequest{
		CompanyID:    companyID,
		ActorID:      userID,
		TargetUserID: userID, // SELF
		EventType:    req.EventType,
		EventTime:    nil, // 🔥 FORCE SERVER TIME
		Source: service.PunchSource{
			SourceType: req.Source.SourceType,
			DeviceID:   req.Source.DeviceID,
			IPAddress:  ip,
		},
		Context: req.Context,
	}

	event, err := h.attendanceIngestService.IngestPunch(ctx, punchReq)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    event,
	})
}
