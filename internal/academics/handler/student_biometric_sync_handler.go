package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/service"
)

// StudentBiometricSyncHandler handles HTTP requests for student face embedding sync and CRUD.
type StudentBiometricSyncHandler struct {
	syncService service.StudentBiometricSyncService
	logger      *zap.Logger
}

// NewStudentBiometricSyncHandler creates a new handler instance.
func NewStudentBiometricSyncHandler(
	syncService service.StudentBiometricSyncService,
	logger *zap.Logger,
) *StudentBiometricSyncHandler {
	return &StudentBiometricSyncHandler{
		syncService: syncService,
		logger:      logger.Named("student_biometric_sync_handler"),
	}
}

// ---------------------------------------------------------------------
// Request DTOs (sync)
// ---------------------------------------------------------------------

type syncEmbeddingsRequest struct {
	DeviceID     string `json:"device_id"`
	ModelVersion string `json:"model_version"`
}

// ---------------------------------------------------------------------
// Sync Handlers (Device‑authenticated – no user ID required)
// ---------------------------------------------------------------------

// SyncEmbeddings decides full or incremental sync based on device sync state.
// POST /api/v1/companies/{companyID}/academics/biometric-device/sync
func (h *StudentBiometricSyncHandler) SyncEmbeddings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	var req syncEmbeddingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.DeviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "device_id is required")
		return
	}
	if req.ModelVersion == "" {
		h.respondWithError(w, http.StatusBadRequest, "model_version is required")
		return
	}

	input := &service.StudentSyncEmbeddingsInput{
		CompanyID:    companyID,
		DeviceID:     req.DeviceID,
		ModelVersion: req.ModelVersion,
	}

	resp, err := h.syncService.SyncEmbeddings(ctx, input)
	if err != nil {
		h.logger.Error("failed to sync embeddings", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// FullSync forces a full sync for a device.
// POST /api/v1/companies/{companyID}/academics/biometric-device/full/{deviceID}
func (h *StudentBiometricSyncHandler) FullSync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "device_id is required")
		return
	}
	modelVersion := r.URL.Query().Get("model_version")
	if modelVersion == "" {
		h.respondWithError(w, http.StatusBadRequest, "model_version query parameter is required")
		return
	}

	resp, err := h.syncService.FullSync(ctx, companyID, deviceID, modelVersion)
	if err != nil {
		h.logger.Error("failed to perform full sync", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ForceResync resets the sync state for a device (forces next sync to be full).
// POST /api/v1/companies/{companyID}/academics/biometric-device/reset/{deviceID}
func (h *StudentBiometricSyncHandler) ForceResync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	err = h.syncService.ForceDeviceResync(ctx, companyID, deviceID)
	if err != nil {
		h.logger.Error("failed to reset device sync", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Device sync state reset successfully",
	})
}

// ---------------------------------------------------------------------
// Student Face Embedding CRUD Handlers (User‑authenticated)
// ---------------------------------------------------------------------
// hasPermission is a placeholder – replace with actual RBAC check using permission mask.
func (h *StudentBiometricSyncHandler) hasPermission(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, permission string) bool {
	// TODO: implement real RBAC check (e.g., check permission mask from JWT)
	return true
}

// CreateStudentFaceEmbedding creates a new face embedding.
// POST /api/v1/companies/{companyID}/academics/face-embeddings
func (h *StudentBiometricSyncHandler) CreateStudentFaceEmbedding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	// Use existing academic permission for biometric management
	if !h.hasPermission(ctx, companyID, userID, "academics.attendance.manage_exemptions") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateStudentFaceEmbeddingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Ensure the company ID in the URL matches the request (security)
	if req.CompanyID != companyID {
		h.respondWithError(w, http.StatusBadRequest, "company_id in body must match URL")
		return
	}

	// Set CreatedBy from authenticated user if not provided
	if req.CreatedBy == nil {
		req.CreatedBy = &userID
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	resp, err := h.syncService.CreateStudentFaceEmbedding(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to create face embedding", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateStudentFaceEmbedding updates an existing face embedding.
// PUT /api/v1/companies/{companyID}/academics/face-embeddings/{embeddingID}
func (h *StudentBiometricSyncHandler) UpdateStudentFaceEmbedding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	embeddingIDStr := chi.URLParam(r, "embeddingID")
	embeddingID, err := uuid.Parse(embeddingIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid embedding ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "academics.attendance.manage_exemptions") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateStudentFaceEmbeddingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.EmbeddingID = embeddingID
	if req.UpdatedBy == nil {
		req.UpdatedBy = &userID
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	resp, err := h.syncService.UpdateStudentFaceEmbedding(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to update face embedding", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DeleteStudentFaceEmbedding soft-deletes a face embedding.
// DELETE /api/v1/companies/{companyID}/academics/face-embeddings/{embeddingID}
func (h *StudentBiometricSyncHandler) DeleteStudentFaceEmbedding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	embeddingIDStr := chi.URLParam(r, "embeddingID")
	embeddingID, err := uuid.Parse(embeddingIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid embedding ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "academics.attendance.manage_exemptions") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	err = h.syncService.DeleteStudentFaceEmbedding(ctx, embeddingID, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to delete face embedding", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Face embedding deleted successfully",
	})
}

// GetStudentFaceEmbedding retrieves a face embedding by ID.
// GET /api/v1/companies/{companyID}/academics/face-embeddings/{embeddingID}
func (h *StudentBiometricSyncHandler) GetStudentFaceEmbedding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	embeddingIDStr := chi.URLParam(r, "embeddingID")
	embeddingID, err := uuid.Parse(embeddingIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid embedding ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	// Use read permission from academics
	if !h.hasPermission(ctx, companyID, userID, "academics.attendance.read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	resp, err := h.syncService.GetStudentFaceEmbedding(ctx, embeddingID)
	if err != nil {
		h.logger.Error("failed to get face embedding", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if resp == nil {
		h.respondWithError(w, http.StatusNotFound, "embedding not found")
		return
	}
	// Ensure embedding belongs to the company from URL (security)
	if resp.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "embedding does not belong to this company")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetActiveStudentFaceEmbeddingByStudent returns the active embedding for a student.
// GET /api/v1/companies/{companyID}/academics/face-embeddings/students/{studentID}/active
func (h *StudentBiometricSyncHandler) GetActiveStudentFaceEmbeddingByStudent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	studentIDStr := chi.URLParam(r, "studentID")
	studentID, err := uuid.Parse(studentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "academics.attendance.read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	resp, err := h.syncService.GetActiveStudentFaceEmbeddingByStudent(ctx, studentID)
	if err != nil {
		h.logger.Error("failed to get active embedding", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if resp == nil {
		// No active embedding is not an error
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"data":    nil,
		})
		return
	}
	// Security: ensure the embedding's company matches the URL
	if resp.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "embedding does not belong to this company")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ListStudentFaceEmbeddings lists face embeddings with filters and pagination.
// GET /api/v1/companies/{companyID}/academics/face-embeddings
// Query params: student_id, model_version, is_active, limit, offset
func (h *StudentBiometricSyncHandler) ListStudentFaceEmbeddings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "academics.attendance.read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Parse query parameters
	req := service.ListStudentFaceEmbeddingsRequest{
		CompanyID: &companyID, // enforce company filter from URL
	}
	if studentIDStr := r.URL.Query().Get("student_id"); studentIDStr != "" {
		studentID, err := uuid.Parse(studentIDStr)
		if err == nil {
			req.StudentID = &studentID
		}
	}
	if modelVersion := r.URL.Query().Get("model_version"); modelVersion != "" {
		req.ModelVersion = &modelVersion
	}
	if isActiveStr := r.URL.Query().Get("is_active"); isActiveStr != "" {
		isActive, err := strconv.ParseBool(isActiveStr)
		if err == nil {
			req.IsActive = &isActive
		}
	}
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err == nil && limit > 0 {
			req.Limit = limit
		}
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		offset, err := strconv.Atoi(offsetStr)
		if err == nil && offset >= 0 {
			req.Offset = offset
		}
	}

	embeddings, total, err := h.syncService.ListStudentFaceEmbeddings(ctx, req)
	if err != nil {
		h.logger.Error("failed to list face embeddings", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    embeddings,
		"total":   total,
		"limit":   req.Limit,
		"offset":  req.Offset,
	})
}

// DeactivateEmbeddingsForStudent deactivates all face embeddings for a student.
// POST /api/v1/companies/{companyID}/academics/face-embeddings/students/{studentID}/deactivate
func (h *StudentBiometricSyncHandler) DeactivateEmbeddingsForStudent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	studentIDStr := chi.URLParam(r, "studentID")
	studentID, err := uuid.Parse(studentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "academics.attendance.manage_exemptions") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	err = h.syncService.DeactivateEmbeddingsForStudent(ctx, studentID, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to deactivate embeddings for student", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "All face embeddings deactivated for student",
	})
}

// ---------------------------------------------------------------------
// Response Helpers
// ---------------------------------------------------------------------

func (h *StudentBiometricSyncHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *StudentBiometricSyncHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
