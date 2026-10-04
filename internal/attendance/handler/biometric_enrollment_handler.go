package handler

import (
	"auth-service/internal/attendance/biometric/models"
	"auth-service/internal/attendance/biometric/service"
	"encoding/json"
	"net/http"

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
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "user not authenticated")
		return
	}
	if getSessionTypeFromContext(ctx) == "device" && !isTrustedDevice(ctx) {
		h.respondWithError(w, http.StatusForbidden, "device not trusted")
		return
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

func (h *BiometricEnrollmentHandler) ReEnrollFace(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "user not authenticated")
		return
	}
	if getSessionTypeFromContext(ctx) == "device" && !isTrustedDevice(ctx) {
		h.respondWithError(w, http.StatusForbidden, "device not trusted")
		return
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
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "user not authenticated")
		return
	}
	if getSessionTypeFromContext(ctx) == "device" && !isTrustedDevice(ctx) {
		h.respondWithError(w, http.StatusForbidden, "device not trusted")
		return
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
	if err := h.enrollmentService.DeactivateFace(ctx, companyID, req.SubjectID, req.SubjectType, actorID, req.Reason); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]string{"message": "Face embedding deactivated"})
}

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
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "user not authenticated")
		return
	}
	if getSessionTypeFromContext(ctx) == "device" && !isTrustedDevice(ctx) {
		h.respondWithError(w, http.StatusForbidden, "device not trusted")
		return
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
	if err := h.enrollmentService.ActivateFace(ctx, companyID, req.SubjectID, req.SubjectType, actorID, req.Reason); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]string{"message": "Face embedding activated"})
}

func (h *BiometricEnrollmentHandler) GetFaceEmbedding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	subjectType := chi.URLParam(r, "subjectType")
	subjectID, err := uuid.Parse(chi.URLParam(r, "subjectID"))
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
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "user not authenticated")
		return
	}
	if getSessionTypeFromContext(ctx) == "device" {
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
	if err := h.enrollmentService.RotateEmbeddingModel(ctx, companyID, req.EmbeddingID, req.NewVersion, actorID); err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]string{"message": "Model version updated"})
}

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
