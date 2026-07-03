package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
)

// AttendanceExemptionHandler handles exemption CRUD operations.
type AttendanceExemptionHandler struct {
	exemptionRepo repository.AttendanceExemptionRepository
	logger        *zap.Logger
}

// NewAttendanceExemptionHandler creates a new handler.
func NewAttendanceExemptionHandler(
	exemptionRepo repository.AttendanceExemptionRepository,
	logger *zap.Logger,
) *AttendanceExemptionHandler {
	return &AttendanceExemptionHandler{
		exemptionRepo: exemptionRepo,
		logger:        logger,
	}
}

// CreateExemptionRequest defines the payload for creating an exemption.
type CreateExemptionRequest struct {
	CompanyID   uuid.UUID  `json:"company_id"`
	SubjectType string     `json:"subject_type"`
	SubjectID   uuid.UUID  `json:"subject_id"`
	FromDate    time.Time  `json:"from_date"`
	ToDate      time.Time  `json:"to_date"`
	Reason      *string    `json:"reason"`
	ApprovedBy  *uuid.UUID `json:"approved_by"`
	CreatedBy   *uuid.UUID `json:"created_by"`
}

// CreateExemption creates a new attendance exemption.
func (h *AttendanceExemptionHandler) CreateExemption(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req CreateExemptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate
	if req.CompanyID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "company_id is required")
		return
	}
	if req.SubjectType == "" {
		h.respondWithError(w, http.StatusBadRequest, "subject_type is required")
		return
	}
	if req.SubjectID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "subject_id is required")
		return
	}
	if req.FromDate.IsZero() || req.ToDate.IsZero() {
		h.respondWithError(w, http.StatusBadRequest, "from_date and to_date are required")
		return
	}
	if req.FromDate.After(req.ToDate) {
		h.respondWithError(w, http.StatusBadRequest, "from_date must be before or equal to to_date")
		return
	}

	exemption := &models.AttendanceExemption{
		CompanyID:   req.CompanyID,
		SubjectType: req.SubjectType,
		SubjectID:   req.SubjectID,
		FromDate:    req.FromDate,
		ToDate:      req.ToDate,
		Reason:      req.Reason,
		ApprovedBy:  req.ApprovedBy,
		CreatedBy:   req.CreatedBy,
	}

	if err := h.exemptionRepo.Create(ctx, nil, exemption); err != nil {
		h.logger.Error("Failed to create exemption", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to create exemption")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    exemption,
	})
}

// UpdateExemptionRequest defines the payload for updating an exemption.
type UpdateExemptionRequest struct {
	FromDate   *time.Time `json:"from_date"`
	ToDate     *time.Time `json:"to_date"`
	Reason     *string    `json:"reason"`
	ApprovedBy *uuid.UUID `json:"approved_by"`
}

// UpdateExemption updates an existing exemption.
func (h *AttendanceExemptionHandler) UpdateExemption(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	exemptionID, err := uuid.Parse(chi.URLParam(r, "exemptionID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid exemption ID")
		return
	}

	var req UpdateExemptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Fetch existing
	existing, err := h.exemptionRepo.GetByID(ctx, nil, exemptionID)
	if err != nil {
		h.logger.Error("Failed to get exemption", zap.String("exemption_id", exemptionID.String()), zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve exemption")
		return
	}
	if existing == nil {
		h.respondWithError(w, http.StatusNotFound, "exemption not found")
		return
	}

	// Apply updates
	if req.FromDate != nil {
		existing.FromDate = *req.FromDate
	}
	if req.ToDate != nil {
		existing.ToDate = *req.ToDate
	}
	if req.Reason != nil {
		existing.Reason = req.Reason
	}
	if req.ApprovedBy != nil {
		existing.ApprovedBy = req.ApprovedBy
	}

	// Validate dates after update
	if existing.FromDate.After(existing.ToDate) {
		h.respondWithError(w, http.StatusBadRequest, "from_date must be before or equal to to_date")
		return
	}

	if err := h.exemptionRepo.Update(ctx, nil, existing); err != nil {
		h.logger.Error("Failed to update exemption", zap.String("exemption_id", exemptionID.String()), zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to update exemption")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    existing,
	})
}

// DeleteExemption deletes an exemption by ID.
func (h *AttendanceExemptionHandler) DeleteExemption(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	exemptionID, err := uuid.Parse(chi.URLParam(r, "exemptionID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid exemption ID")
		return
	}

	// Check if exists
	existing, err := h.exemptionRepo.GetByID(ctx, nil, exemptionID)
	if err != nil {
		h.logger.Error("Failed to get exemption", zap.String("exemption_id", exemptionID.String()), zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve exemption")
		return
	}
	if existing == nil {
		h.respondWithError(w, http.StatusNotFound, "exemption not found")
		return
	}

	if err := h.exemptionRepo.Delete(ctx, nil, exemptionID); err != nil {
		h.logger.Error("Failed to delete exemption", zap.String("exemption_id", exemptionID.String()), zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to delete exemption")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "exemption deleted",
	})
}

// ---- Helpers ----

func (h *AttendanceExemptionHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *AttendanceExemptionHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
