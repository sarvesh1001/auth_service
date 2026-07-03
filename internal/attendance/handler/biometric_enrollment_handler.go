package handler

import (
	"context"
	"encoding/json"
	"net/http"

	"auth-service/internal/attendance/biometric/models"
	"auth-service/internal/attendance/biometric/service"

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

// getActorIDFromContext returns the actor UUID based on session type.
// For device sessions, it returns uuid.Nil (system actor).
// For admin/user sessions, it returns the user's UUID.
// If no valid actor is found, it returns uuid.Nil and false.
func getActorIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	sessionType, _ := ctx.Value("session_type").(string)
	if sessionType == "device" {
		// Device is authenticated; we treat it as a system actor.
		return uuid.Nil, true
	}
	// Admin or user: require user_id
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		return uuid.Nil, false
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, false
	}
	return userID, true
}

// isDeviceTrusted checks if the request comes from a trusted device.
func isDeviceTrusted(ctx context.Context) bool {
	trusted, ok := ctx.Value("is_trusted_device").(bool)
	return ok && trusted
}

// ---------------------------------------------------------------------
// EnrollFace – supports device & admin
// ---------------------------------------------------------------------
type enrollFaceRequest struct {
	SubjectType     string    `json:"subject_type"`
	SubjectID       uuid.UUID `json:"subject_id"`
	EmbeddingVector []float64 `json:"embedding_vector"`
	ModelVersion    string    `json:"model_version"`
}

func (h *BiometricEnrollmentHandler) EnrollFace(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Determine actor and validate device trust if needed
	actorID, ok := getActorIDFromContext(ctx)
	if !ok {
		h.respondWithError(w, http.StatusUnauthorized, "user not authenticated")
		return
	}
	// If device session, ensure device is trusted
	if sessionType, _ := ctx.Value("session_type").(string); sessionType == "device" {
		if !isDeviceTrusted(ctx) {
			h.respondWithError(w, http.StatusForbidden, "device not trusted")
			return
		}
	}

	var req enrollFaceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if req.SubjectType == "" || req.SubjectID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "subject_type and subject_id are required")
		return
	}
	if len(req.EmbeddingVector) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "embedding_vector cannot be empty")
		return
	}
	if req.ModelVersion == "" {
		h.respondWithError(w, http.StatusBadRequest, "model_version is required")
		return
	}

	input := &models.EnrollFaceInput{
		CompanyID:       companyID,
		SubjectType:     req.SubjectType,
		SubjectID:       req.SubjectID,
		EmbeddingVector: req.EmbeddingVector,
		ModelVersion:    req.ModelVersion,
		CreatedBy:       actorID,
	}

	embedding, err := h.enrollmentService.EnrollFace(ctx, input)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, embedding)
}

// ---------------------------------------------------------------------
// ReEnrollFace – same logic
// ---------------------------------------------------------------------
func (h *BiometricEnrollmentHandler) ReEnrollFace(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	actorID, ok := getActorIDFromContext(ctx)
	if !ok {
		h.respondWithError(w, http.StatusUnauthorized, "user not authenticated")
		return
	}
	if sessionType, _ := ctx.Value("session_type").(string); sessionType == "device" {
		if !isDeviceTrusted(ctx) {
			h.respondWithError(w, http.StatusForbidden, "device not trusted")
			return
		}
	}

	var req enrollFaceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if req.SubjectType == "" || req.SubjectID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "subject_type and subject_id are required")
		return
	}

	input := &models.EnrollFaceInput{
		CompanyID:       companyID,
		SubjectType:     req.SubjectType,
		SubjectID:       req.SubjectID,
		EmbeddingVector: req.EmbeddingVector,
		ModelVersion:    req.ModelVersion,
		CreatedBy:       actorID,
	}

	embedding, err := h.enrollmentService.ReEnrollFace(ctx, input)
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
	SubjectType string    `json:"subject_type"`
	SubjectID   uuid.UUID `json:"subject_id"`
	Reason      string    `json:"reason"`
}

func (h *BiometricEnrollmentHandler) DeactivateFace(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	actorID, ok := getActorIDFromContext(ctx)
	if !ok {
		h.respondWithError(w, http.StatusUnauthorized, "user not authenticated")
		return
	}
	if sessionType, _ := ctx.Value("session_type").(string); sessionType == "device" {
		if !isDeviceTrusted(ctx) {
			h.respondWithError(w, http.StatusForbidden, "device not trusted")
			return
		}
	}

	var req deactivateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if req.SubjectType == "" || req.SubjectID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "subject_type and subject_id are required")
		return
	}

	err = h.enrollmentService.DeactivateFace(ctx, companyID, req.SubjectID, req.SubjectType, actorID, req.Reason)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]string{"message": "Face embedding deactivated"})
}

// ---------------------------------------------------------------------
// ActivateFace
// ---------------------------------------------------------------------
type activateRequest struct {
	SubjectType string    `json:"subject_type"`
	SubjectID   uuid.UUID `json:"subject_id"`
	Reason      string    `json:"reason"`
}

func (h *BiometricEnrollmentHandler) ActivateFace(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	actorID, ok := getActorIDFromContext(ctx)
	if !ok {
		h.respondWithError(w, http.StatusUnauthorized, "user not authenticated")
		return
	}
	if sessionType, _ := ctx.Value("session_type").(string); sessionType == "device" {
		if !isDeviceTrusted(ctx) {
			h.respondWithError(w, http.StatusForbidden, "device not trusted")
			return
		}
	}

	var req activateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if req.SubjectType == "" || req.SubjectID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "subject_type and subject_id are required")
		return
	}

	err = h.enrollmentService.ActivateFace(ctx, companyID, req.SubjectID, req.SubjectType, actorID, req.Reason)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]string{"message": "Face embedding activated"})
}

// ---------------------------------------------------------------------
// GetFaceEmbedding – requires admin/user (GET, no actor needed)
// ---------------------------------------------------------------------
func (h *BiometricEnrollmentHandler) GetFaceEmbedding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	subjectType := chi.URLParam(r, "subjectType")
	subjectIDStr := chi.URLParam(r, "subjectID")
	subjectID, err := uuid.Parse(subjectIDStr)
	if err != nil || subjectType == "" {
		h.respondWithError(w, http.StatusBadRequest, "valid subject_type and subject_id required")
		return
	}

	embedding, err := h.enrollmentService.GetFaceEmbedding(ctx, companyID, subjectID, subjectType)
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
// ListActiveFaceEmbeddings – admin/user only
// ---------------------------------------------------------------------
func (h *BiometricEnrollmentHandler) ListActiveFaceEmbeddings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
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
// RotateEmbeddingModel – admin only (requires user)
// ---------------------------------------------------------------------
type rotateRequest struct {
	EmbeddingID uuid.UUID `json:"embedding_id"`
	NewVersion  string    `json:"new_version"`
}

func (h *BiometricEnrollmentHandler) RotateEmbeddingModel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	actorID, ok := getActorIDFromContext(ctx)
	if !ok {
		h.respondWithError(w, http.StatusUnauthorized, "user not authenticated")
		return
	}
	// Restrict to admin/user (device not allowed for model rotation)
	if sessionType, _ := ctx.Value("session_type").(string); sessionType == "device" {
		h.respondWithError(w, http.StatusForbidden, "device not allowed to rotate models")
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

	err = h.enrollmentService.RotateEmbeddingModel(ctx, companyID, req.EmbeddingID, req.NewVersion, actorID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]string{"message": "Model version updated"})
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
