package handler

import (
	"auth-service/internal/hr/models/attendance"
	"auth-service/internal/hr/service"
	"auth-service/internal/middleware"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type AttendanceDeviceEnrollmentHandler struct {
	enrollmentService service.AttendanceDeviceEnrollmentService
	logger            *zap.Logger
}

func NewAttendanceDeviceEnrollmentHandler(
	enrollmentService service.AttendanceDeviceEnrollmentService,
	logger *zap.Logger,
) *AttendanceDeviceEnrollmentHandler {
	return &AttendanceDeviceEnrollmentHandler{
		enrollmentService: enrollmentService,
		logger:            logger,
	}
}

// ==========================
// ENROLL USER TO DEVICE
// ==========================
func (h *AttendanceDeviceEnrollmentHandler) EnrollUser(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	// Company
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Actor
	actorID := middleware.GetUserIDFromContext(ctx)
	var enrolledBy *uuid.UUID
	if actorID != uuid.Nil {
		enrolledBy = &actorID
	}

	// Device ID
	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	// Payload
	var req attendance.DeviceEnrollmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	// Validation
	if req.UserID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "user_id is required")
		return
	}
	if req.DeviceUserCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "device_user_code is required")
		return
	}
	if req.SourceType == "" {
		h.respondWithError(w, http.StatusBadRequest, "source_type is required")
		return
	}

	// Service call
	err = h.enrollmentService.EnrollUser(
		ctx,
		companyID,
		req.UserID,
		deviceID,
		req.SourceType,
		req.DeviceUserCode,
		enrolledBy,
	)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"message": "User enrolled successfully",
	})
}

// ==========================
// REVOKE ENROLLMENT
// ==========================
func (h *AttendanceDeviceEnrollmentHandler) RevokeEnrollment(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	// Company
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Actor
	actorID := middleware.GetUserIDFromContext(ctx)
	var revokedBy *uuid.UUID
	if actorID != uuid.Nil {
		revokedBy = &actorID
	}

	// Device ID
	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	// Payload
	var req attendance.DeviceEnrollmentRevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	// Validation
	if req.DeviceUserCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "device_user_code is required")
		return
	}
	if req.SourceType == "" {
		h.respondWithError(w, http.StatusBadRequest, "source_type is required")
		return
	}

	// Service call
	err = h.enrollmentService.RevokeEnrollment(
		ctx,
		companyID,
		deviceID,
		req.SourceType,
		req.DeviceUserCode,
		req.Reason,
		revokedBy,
	)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Enrollment revoked successfully",
	})
}

// ==========================
// LIST DEVICE ENROLLMENTS
// ==========================
func (h *AttendanceDeviceEnrollmentHandler) GetDeviceEnrollments(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	result, err := h.enrollmentService.GetEnrollmentsByDevice(
		ctx,
		companyID,
		deviceID,
	)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}

// ==========================
// RESPONSE HELPERS
// ==========================
func (h *AttendanceDeviceEnrollmentHandler) respondWithJSON(
	w http.ResponseWriter,
	status int,
	payload interface{},
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		h.logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

func (h *AttendanceDeviceEnrollmentHandler) respondWithError(
	w http.ResponseWriter,
	status int,
	message string,
) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

// ==========================
// UNREVOKE ENROLLMENT
// ==========================
func (h *AttendanceDeviceEnrollmentHandler) UnrevokeEnrollment(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	// Company
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Actor
	actorID := middleware.GetUserIDFromContext(ctx)
	var actedBy *uuid.UUID
	if actorID != uuid.Nil {
		actedBy = &actorID
	}

	// Device ID
	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	// Payload
	var req attendance.DeviceEnrollmentRevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	// Validation
	if req.DeviceUserCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "device_user_code is required")
		return
	}
	if req.SourceType == "" {
		h.respondWithError(w, http.StatusBadRequest, "source_type is required")
		return
	}
	if req.Reason == "" {
		h.respondWithError(w, http.StatusBadRequest, "reason is required")
		return
	}

	// Service call
	enrollment, err := h.enrollmentService.UnrevokeEnrollment(
		ctx,
		companyID,
		deviceID,
		req.SourceType,
		req.DeviceUserCode,
		req.Reason,
		actedBy,
	)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":    "Enrollment unreverted successfully",
		"enrollment": enrollment,
	})
}

// ==========================
// LIST REVOKED DEVICE ENROLLMENTS
// ==========================
func (h *AttendanceDeviceEnrollmentHandler) GetRevokedDeviceEnrollments(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	// Company
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Device ID
	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	result, err := h.enrollmentService.GetRevokedEnrollmentsByDevice(
		ctx,
		companyID,
		deviceID,
	)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, result)
}
