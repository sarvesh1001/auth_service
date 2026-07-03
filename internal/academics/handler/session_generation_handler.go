package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/service"
)

// SessionGenerationHandler handles manual triggering of academic session generation.
type SessionGenerationHandler struct {
	sessionGenSvc service.SessionGenerationService
	logger        *zap.Logger
}

// NewSessionGenerationHandler creates a new handler.
func NewSessionGenerationHandler(sessionGenSvc service.SessionGenerationService, logger *zap.Logger) *SessionGenerationHandler {
	if sessionGenSvc == nil {
		logger.Warn("SessionGenerationHandler created with nil service – this will cause panics")
	} else {
		logger.Info("SessionGenerationHandler created successfully")
	}
	return &SessionGenerationHandler{
		sessionGenSvc: sessionGenSvc,
		logger:        logger.Named("session_generation_handler"),
	}
}

// GenerateSessionsRequest represents the request body for triggering session generation.
type GenerateSessionsRequest struct {
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`
}

// GenerateSessions manually triggers generation of academic sessions from active timetables.
// POST /api/v1/companies/{companyID}/academics/sessions/generate
func (h *SessionGenerationHandler) GenerateSession(w http.ResponseWriter, r *http.Request) {
	// ============================================================
	// DEFENSIVE NIL RECEIVER CHECK – prevents panic if h is nil
	// ============================================================
	if h == nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// ============================================================
	// Check if the service is nil (should not happen if initialised)
	// ============================================================
	if h.sessionGenSvc == nil {
		h.logger.Error("Session generation service is nil – cannot process request")
		h.respondWithError(w, http.StatusInternalServerError, "session generation service not available")
		return
	}

	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "academic_sessions:generate") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req GenerateSessionsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.StartDate.IsZero() || req.EndDate.IsZero() {
		h.respondWithError(w, http.StatusBadRequest, "start_date and end_date are required")
		return
	}

	if req.StartDate.After(req.EndDate) {
		h.respondWithError(w, http.StatusBadRequest, "start_date must be before end_date")
		return
	}

	// Generate a random UUID for this job – this will be used as the aggregate_id in outbox events
	jobID := uuid.New().String()

	// Log the request details
	h.logger.Info("Generating sessions",
		zap.String("company_id", companyID.String()),
		zap.Time("start_date", req.StartDate),
		zap.Time("end_date", req.EndDate),
		zap.String("job_id", jobID),
	)

	count, err := h.sessionGenSvc.GenerateSessions(ctx, req.StartDate, req.EndDate, jobID)
	if err != nil {
		h.logger.Error("Failed to generate sessions",
			zap.Time("start", req.StartDate),
			zap.Time("end", req.EndDate),
			zap.String("job_id", jobID),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.logger.Info("Session generation completed successfully",
		zap.Int("sessions_generated", count),
		zap.String("job_id", jobID),
	)

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"job_id":             jobID,
			"sessions_generated": count,
			"start_date":         req.StartDate,
			"end_date":           req.EndDate,
		},
		"message": "Session generation completed",
	})
}

// hasPermission is a placeholder – integrate with your actual RBAC.
func (h *SessionGenerationHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	// TODO: replace with real permission check
	return true
}

func (h *SessionGenerationHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

func (h *SessionGenerationHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
