package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"auth-service/internal/hr/biometric/models"
	"auth-service/internal/hr/biometric/service"
	"auth-service/internal/middleware"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type BiometricEnrollmentHandler struct {
	enrollmentService service.BiometricEnrollmentService
	logger            *zap.Logger
}

func NewBiometricEnrollmentHandler(
	enrollmentService service.BiometricEnrollmentService,
	logger *zap.Logger,
) *BiometricEnrollmentHandler {
	return &BiometricEnrollmentHandler{
		enrollmentService: enrollmentService,
		logger:            logger,
	}
}

// ---------------------------------------------------------------------
// Helper: get company ID from context (must be present after auth)
// ---------------------------------------------------------------------
func getCompanyIDFromContext(r *http.Request) (uuid.UUID, error) {
	rawCompanyID := r.Context().Value("company_id")
	if rawCompanyID == nil {
		return uuid.Nil, errors.New("company_id not found in context")
	}
	switch v := rawCompanyID.(type) {
	case uuid.UUID:
		return v, nil
	case string:
		return uuid.Parse(v)
	default:
		return uuid.Nil, errors.New("invalid company_id type in context")
	}
}

// ---------------------------------------------------------------------
// EnrollFace
// ---------------------------------------------------------------------
func (h *BiometricEnrollmentHandler) EnrollFace(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1. Get company from context (single source of truth)
	companyID, err := getCompanyIDFromContext(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// 2. Actor info
	actorID := middleware.GetUserIDFromContext(ctx)
	if actorID == uuid.Nil {
		h.respondWithError(w, http.StatusUnauthorized, "user not authenticated")
		return
	}
	// actorType is not used by enrollment service but can be logged if needed
	// actorType := middleware.GetSessionTypeFromContext(ctx)

	// 3. Parse request body
	var input models.EnrollFaceInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// 4. Enforce company ownership
	input.CompanyID = companyID
	input.CreatedBy = actorID

	// 5. Call service
	embedding, err := h.enrollmentService.EnrollFace(ctx, &input)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, embedding)
}

// ---------------------------------------------------------------------
// ReEnrollFace
// ---------------------------------------------------------------------
func (h *BiometricEnrollmentHandler) ReEnrollFace(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	actorID := middleware.GetUserIDFromContext(ctx)
	if actorID == uuid.Nil {
		h.respondWithError(w, http.StatusUnauthorized, "user not authenticated")
		return
	}

	var input models.EnrollFaceInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	input.CompanyID = companyID
	input.CreatedBy = actorID

	embedding, err := h.enrollmentService.ReEnrollFace(ctx, &input)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, embedding)
}

// ---------------------------------------------------------------------
// DeactivateFace
// ---------------------------------------------------------------------
type deactivateRequest struct {
	UserID uuid.UUID `json:"user_id"`
	Reason string    `json:"reason"`
}

func (h *BiometricEnrollmentHandler) DeactivateFace(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	actorID := middleware.GetUserIDFromContext(ctx)
	if actorID == uuid.Nil {
		h.respondWithError(w, http.StatusUnauthorized, "user not authenticated")
		return
	}

	var req deactivateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if req.UserID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "user_id is required")
		return
	}

	err = h.enrollmentService.DeactivateFace(ctx, companyID, req.UserID, actorID, req.Reason)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Face embedding deactivated successfully",
	})
}

// ---------------------------------------------------------------------
// GetFaceEmbedding (by user)
// ---------------------------------------------------------------------
func (h *BiometricEnrollmentHandler) GetFaceEmbedding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	embedding, err := h.enrollmentService.GetFaceEmbedding(ctx, companyID, userID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if embedding == nil {
		h.respondWithError(w, http.StatusNotFound, "Face embedding not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, embedding)
}

// ---------------------------------------------------------------------
// ListActiveFaceEmbeddings (all for company)
// ---------------------------------------------------------------------
func (h *BiometricEnrollmentHandler) ListActiveFaceEmbeddings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	embeddings, err := h.enrollmentService.GetActiveFaceEmbeddingsByCompany(ctx, companyID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, embeddings)
}

// ---------------------------------------------------------------------
// RotateModelVersion
// ---------------------------------------------------------------------
type rotateRequest struct {
	EmbeddingID uuid.UUID `json:"embedding_id"`
	NewVersion  string    `json:"new_version"`
}

type activateRequest struct {
	UserID uuid.UUID `json:"user_id"`
	Reason string    `json:"reason"`
}

// ---------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------
func (h *BiometricEnrollmentHandler) respondWithJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		h.logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

func (h *BiometricEnrollmentHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

func (h *BiometricEnrollmentHandler) ActivateFace(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	actorID := middleware.GetUserIDFromContext(ctx)
	if actorID == uuid.Nil {
		h.respondWithError(w, http.StatusUnauthorized, "user not authenticated")
		return
	}

	var req activateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if req.UserID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "user_id is required")
		return
	}

	err = h.enrollmentService.ActivateFace(ctx, companyID, req.UserID, actorID, req.Reason)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Face embedding activated successfully",
	})
}
func (h *BiometricEnrollmentHandler) RotateModelVersion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	actorID := middleware.GetUserIDFromContext(ctx)
	if actorID == uuid.Nil {
		h.respondWithError(w, http.StatusUnauthorized, "user not authenticated")
		return
	}

	var req rotateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if req.EmbeddingID == uuid.Nil || req.NewVersion == "" {
		h.respondWithError(w, http.StatusBadRequest, "embedding_id and new_version are required")
		return
	}

	err = h.enrollmentService.RotateEmbeddingModel(
		ctx,
		companyID,
		req.EmbeddingID,
		req.NewVersion,
		actorID,
	)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Model version updated successfully",
	})
}
