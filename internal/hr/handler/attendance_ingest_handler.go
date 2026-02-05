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

// ============================================
// HTTP REQUEST DTO
// ============================================

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

// ============================================
// HANDLER
// ============================================

func (h *AttendanceIngestHandler) PunchAttendance(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	// --------------------------------------------------
	// 1️⃣ AUTH CONTEXT (SAFE)
	// --------------------------------------------------

	sessionType, ok := ctx.Value("session_type").(string)
	if !ok || sessionType == "" {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var actorID uuid.UUID
	if sessionType != "device" {
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
	}

	// --------------------------------------------------
	// 2️⃣ COMPANY CONTEXT (UUID SAFE)
	// --------------------------------------------------

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
		hdr := r.Header.Get("X-Company-ID")
		if hdr == "" {
			h.respondWithError(w, http.StatusBadRequest, "company context required")
			return
		}
		parsed, err := uuid.Parse(hdr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid company id")
			return
		}
		companyID = parsed
	}

	// --------------------------------------------------
	// 3️⃣ DECODE REQUEST
	// --------------------------------------------------

	var req PunchHTTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// --------------------------------------------------
	// 4️⃣ IP RESOLUTION
	// --------------------------------------------------

	ip := req.Source.IPAddress
	if ip == nil || *ip == "" {
		resolved := h.getClientIP(r)
		ip = &resolved
	}

	// --------------------------------------------------
	// 5️⃣ DEVICE HEADER FALLBACK
	// --------------------------------------------------

	deviceID := req.Source.DeviceID
	if deviceID == nil {
		if d := r.Header.Get("X-Device-ID"); d != "" {
			deviceID = &d
		}
	}

	// --------------------------------------------------
	// 6️⃣ BUILD SERVICE REQUEST
	// --------------------------------------------------

	punchReq := &service.PunchRequest{
		CompanyID:    companyID,
		TargetUserID: req.TargetUserID,
		EventType:    req.EventType,
		EventTime:    req.EventTime,
		Source: service.PunchSource{
			SourceType: req.Source.SourceType,
			SourceID:   req.Source.SourceID,
			DeviceID:   deviceID,
			IPAddress:  ip,
		},
		Context: req.Context,
	}

	if sessionType != "device" {
		punchReq.ActorID = actorID
	}

	// --------------------------------------------------
	// 7️⃣ INGEST
	// --------------------------------------------------

	event, err := h.attendanceIngestService.IngestPunch(ctx, punchReq)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// --------------------------------------------------
	// 8️⃣ RESPONSE
	// --------------------------------------------------

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    event,
	})
}

// ============================================
// HELPERS
// ============================================

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
