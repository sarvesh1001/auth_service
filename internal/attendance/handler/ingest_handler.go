package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/service/ingest"
	"auth-service/internal/attendance/service/resolver"
)

type AttendanceIngestHandler struct {
	ingestService ingest.IngestService
	logger        *zap.Logger
}

func NewAttendanceIngestHandler(
	ingestService ingest.IngestService,
	logger *zap.Logger,
) *AttendanceIngestHandler {
	return &AttendanceIngestHandler{
		ingestService: ingestService,
		logger:        logger,
	}
}

type PunchHTTPRequest struct {
	TargetUserID uuid.UUID  `json:"target_user_id"`
	SubjectType  string     `json:"subject_type,omitempty"`
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

func (h *AttendanceIngestHandler) PunchAttendance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sessionType := getSessionTypeFromContext(ctx)
	if sessionType == "device" {
		h.handleDevicePunch(w, r, ctx)
		return
	}
	h.handleUserPunch(w, r, ctx)
}

func (h *AttendanceIngestHandler) handleDevicePunch(w http.ResponseWriter, r *http.Request, ctx context.Context) {
	h.respondWithError(
		w,
		http.StatusBadRequest,
		"use /attendance-device/events/punch for device attendance",
	)
}

func (h *AttendanceIngestHandler) mapIngestError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, resolver.ErrSubjectOutsideScope):
		h.respondWithError(w, http.StatusForbidden,
			"subject belongs to a different location than your current scope")
		return true
	case errors.Is(err, resolver.ErrSubjectHasNoLocation):
		h.respondWithError(w, http.StatusBadRequest,
			"target subject has no employment location assigned")
		return true
	}
	return false
}

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
	subjectType := req.SubjectType
	if subjectType == "" {
		subjectType = "employee"
	}
	ip := req.Source.IPAddress
	if ip == nil || *ip == "" {
		resolvedIP := clientIP(r)
		ip = &resolvedIP
	}
	punchReq := &ingest.PunchRequest{
		CompanyID:   companyID,
		ActorID:     actorID,
		SubjectType: subjectType,
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
		if h.mapIngestError(w, err) {
			return
		}
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    event,
	})
}

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
	ip := clientIP(r)
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
		if h.mapIngestError(w, err) {
			return
		}
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    event,
	})
}

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
		SubjectType string `json:"subject_type,omitempty"`
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
		subjectType = "employee"
	}
	ip := req.Source.IPAddress
	if ip == nil || *ip == "" {
		resolvedIP := clientIP(r)
		ip = &resolvedIP
	}
	punchReq := &ingest.PunchRequest{
		CompanyID:   companyID,
		ActorID:     userID,
		SubjectType: subjectType,
		SubjectID:   userID,
		EventType:   req.EventType,
		EventTime:   nil,
		Source: ingest.PunchSource{
			SourceType: req.Source.SourceType,
			DeviceID:   req.Source.DeviceID,
			IPAddress:  ip,
		},
		Context: req.Context,
	}
	event, err := h.ingestService.IngestPunch(ctx, punchReq)
	if err != nil {
		if h.mapIngestError(w, err) {
			return
		}
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    event,
	})
}

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