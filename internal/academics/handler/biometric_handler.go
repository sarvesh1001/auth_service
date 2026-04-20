package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/service"
)

// BiometricHandler handles biometric device integration:
// - Webhook for device punches
// - Student biometric mapping management
type BiometricHandler struct {
	biometricSvc        service.BiometricService
	studentBiometricSvc service.StudentBiometricService
	logger              *zap.Logger
}

// NewBiometricHandler creates a new handler.
func NewBiometricHandler(
	biometricSvc service.BiometricService,
	studentBiometricSvc service.StudentBiometricService,
	logger *zap.Logger,
) *BiometricHandler {
	return &BiometricHandler{
		biometricSvc:        biometricSvc,
		studentBiometricSvc: studentBiometricSvc,
		logger:              logger.Named("biometric_handler"),
	}
}

// ----------------------------------------------------------------------------
// Biometric Punch Webhook
// ----------------------------------------------------------------------------

// BiometricPunchRequest mirrors service.BiometricPunchRequest
type BiometricPunchRequest struct {
	DeviceID       string    `json:"device_id"`
	DeviceUserCode string    `json:"device_user_code"`
	PunchTime      time.Time `json:"punch_time"`
}

// ProcessPunch receives a punch from a biometric device and marks period attendance.
// POST /api/v1/companies/{companyID}/academics/biometric/punch
func (h *BiometricHandler) ProcessPunch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	// Optional: verify device authentication via API key or header
	// (not shown – implement as needed)

	var req BiometricPunchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.DeviceID == "" || req.DeviceUserCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "device_id and device_user_code are required")
		return
	}

	if req.PunchTime.IsZero() {
		req.PunchTime = time.Now().UTC()
	}

	svcReq := service.BiometricPunchRequest{
		DeviceID:       req.DeviceID,
		DeviceUserCode: req.DeviceUserCode,
		PunchTime:      req.PunchTime,
		CompanyID:      companyID,
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	attendance, err := h.biometricSvc.ProcessPunch(ctx, svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to process biometric punch",
			zap.String("device_id", req.DeviceID),
			zap.String("user_code", req.DeviceUserCode),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    attendance,
		"message": "Biometric punch processed successfully",
	})
}

// ----------------------------------------------------------------------------
// Student Biometric Mapping CRUD
// ----------------------------------------------------------------------------

// CreateMappingRequest represents the request body for creating a mapping.
type CreateMappingRequest struct {
	StudentID      uuid.UUID `json:"student_id"`
	DeviceID       string    `json:"device_id"`
	DeviceUserCode string    `json:"device_user_code"`
}

// CreateMapping links a student to a biometric device user code.
// POST /api/v1/companies/{companyID}/academics/biometric/mappings
func (h *BiometricHandler) CreateMapping(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "attendance:manage_biometric_mappings") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req CreateMappingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.StudentID == uuid.Nil || req.DeviceID == "" || req.DeviceUserCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "student_id, device_id, and device_user_code are required")
		return
	}

	svcReq := service.CreateBiometricMappingRequest{
		StudentID:      req.StudentID,
		CompanyID:      companyID,
		DeviceID:       req.DeviceID,
		DeviceUserCode: req.DeviceUserCode,
		EnrolledBy:     &userID,
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	mapping, err := h.studentBiometricSvc.CreateMapping(ctx, svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to create biometric mapping",
			zap.String("student_id", req.StudentID.String()),
			zap.String("device_id", req.DeviceID),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    mapping,
		"message": "Biometric mapping created",
	})
}

// GetMappingByID retrieves a mapping by its ID.
// GET /api/v1/companies/{companyID}/academics/biometric/mappings/{mappingID}
func (h *BiometricHandler) GetMappingByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	mappingIDStr := chi.URLParam(r, "mappingID")
	mappingID, err := uuid.Parse(mappingIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid mapping ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "attendance:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	mapping, err := h.studentBiometricSvc.GetMappingByID(ctx, mappingID)
	if err != nil {
		h.logger.Error("Failed to get biometric mapping",
			zap.String("mapping_id", mappingID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    mapping,
	})
}

// ListMappings returns a paginated list of biometric mappings.
// GET /api/v1/companies/{companyID}/academics/biometric/mappings
func (h *BiometricHandler) ListMappings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "attendance:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	filter := service.BiometricMappingFilter{
		CompanyID: &companyID,
	}

	if studentIDStr := r.URL.Query().Get("student_id"); studentIDStr != "" {
		if sid, err := uuid.Parse(studentIDStr); err == nil {
			filter.StudentID = &sid
		}
	}
	if deviceID := r.URL.Query().Get("device_id"); deviceID != "" {
		filter.DeviceID = &deviceID
	}
	if userCode := r.URL.Query().Get("device_user_code"); userCode != "" {
		filter.DeviceUserCode = &userCode
	}
	if isActiveStr := r.URL.Query().Get("is_active"); isActiveStr != "" {
		if active, err := strconv.ParseBool(isActiveStr); err == nil {
			filter.IsActive = &active
		}
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}

	mappings, total, err := h.studentBiometricSvc.ListMappings(ctx, filter, limit, offset)
	if err != nil {
		h.logger.Error("Failed to list biometric mappings",
			zap.Any("filter", filter),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list mappings")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"mappings": mappings,
			"total":    total,
			"limit":    limit,
			"offset":   offset,
		},
	})
}

// UpdateMappingRequest represents the request body for updating a mapping.
type UpdateMappingRequest struct {
	DeviceID       string `json:"device_id"`
	DeviceUserCode string `json:"device_user_code"`
	IsActive       bool   `json:"is_active"`
}

// UpdateMapping updates an existing mapping.
// PUT /api/v1/companies/{companyID}/academics/biometric/mappings/{mappingID}
func (h *BiometricHandler) UpdateMapping(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	mappingIDStr := chi.URLParam(r, "mappingID")
	mappingID, err := uuid.Parse(mappingIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid mapping ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "attendance:manage_biometric_mappings") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req UpdateMappingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.DeviceID == "" || req.DeviceUserCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "device_id and device_user_code are required")
		return
	}

	svcReq := service.UpdateBiometricMappingRequest{
		MappingID:      mappingID,
		DeviceID:       req.DeviceID,
		DeviceUserCode: req.DeviceUserCode,
		IsActive:       req.IsActive,
		EnrolledBy:     &userID,
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	mapping, err := h.studentBiometricSvc.UpdateMapping(ctx, svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to update biometric mapping",
			zap.String("mapping_id", mappingID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    mapping,
		"message": "Biometric mapping updated",
	})
}

// DeleteMapping deletes a mapping permanently.
// DELETE /api/v1/companies/{companyID}/academics/biometric/mappings/{mappingID}
func (h *BiometricHandler) DeleteMapping(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	mappingIDStr := chi.URLParam(r, "mappingID")
	mappingID, err := uuid.Parse(mappingIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid mapping ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "attendance:manage_biometric_mappings") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.studentBiometricSvc.DeleteMapping(ctx, mappingID, nil)
	if err != nil {
		h.logger.Error("Failed to delete biometric mapping",
			zap.String("mapping_id", mappingID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Biometric mapping deleted",
	})
}

// DeactivateStudentMappings deactivates all active mappings for a student.
// POST /api/v1/companies/{companyID}/academics/biometric/students/{studentID}/deactivate
func (h *BiometricHandler) DeactivateStudentMappings(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "attendance:manage_biometric_mappings") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.studentBiometricSvc.DeactivateByStudent(ctx, studentID, nil)
	if err != nil {
		h.logger.Error("Failed to deactivate biometric mappings for student",
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "All biometric mappings deactivated for student",
	})
}

// ----------------------------------------------------------------------------
// Helpers (shared with other handlers)
// ----------------------------------------------------------------------------

// hasPermission is a placeholder – integrate with your actual RBAC.
func (h *BiometricHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	// TODO: replace with real permission check
	return true
}

// getUserIDFromContext extracts the user ID from the request context.
// Adapt this to your actual authentication middleware.

func (h *BiometricHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

func (h *BiometricHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
