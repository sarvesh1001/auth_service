package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/service/enrollment"
)

// AttendanceDeviceEnrollmentHandler handles device enrollment endpoints.
type AttendanceDeviceEnrollmentHandler struct {
	enrollmentService enrollment.EnrollmentService
	logger            *zap.Logger
}

// NewAttendanceDeviceEnrollmentHandler creates a new handler.
func NewAttendanceDeviceEnrollmentHandler(
	enrollmentService enrollment.EnrollmentService,
	logger *zap.Logger,
) *AttendanceDeviceEnrollmentHandler {
	return &AttendanceDeviceEnrollmentHandler{
		enrollmentService: enrollmentService,
		logger:            logger,
	}
}

// enrollmentRequest represents the body for enrolling a user.
// SubjectType is optional; defaults to "employee" if omitted.
type enrollmentRequest struct {
	UserID         uuid.UUID `json:"user_id"`
	DeviceUserCode string    `json:"device_user_code"`
	SourceType     string    `json:"source_type"`
	SubjectType    string    `json:"subject_type,omitempty"`
}

// revokeRequest represents the body for revoking an enrollment.
type revokeRequest struct {
	DeviceUserCode string `json:"device_user_code"`
	SourceType     string `json:"source_type"`
	Reason         string `json:"reason"`
}

// EnrollUser enrolls a user to a device.
func (h *AttendanceDeviceEnrollmentHandler) EnrollUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var enrolledBy *uuid.UUID
	if actorID != uuid.Nil {
		enrolledBy = &actorID
	}

	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	var req enrollmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

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

	// Use provided subject_type, default to "employee" for backward compatibility.
	subjectType := req.SubjectType
	if subjectType == "" {
		subjectType = "employee"
	}
	// Optional: validate against allowed types (employee, student, teacher, etc.)
	// if !isValidSubjectType(subjectType) { ... }

	err = h.enrollmentService.EnrollSubject(
		ctx,
		companyID,
		subjectType,
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

// RevokeEnrollment revokes an enrollment.
func (h *AttendanceDeviceEnrollmentHandler) RevokeEnrollment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var revokedBy *uuid.UUID
	if actorID != uuid.Nil {
		revokedBy = &actorID
	}

	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	var req revokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request payload")
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

// UnrevokeEnrollment restores a previously revoked enrollment.
func (h *AttendanceDeviceEnrollmentHandler) UnrevokeEnrollment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var actedBy *uuid.UUID
	if actorID != uuid.Nil {
		actedBy = &actorID
	}

	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "device_id is required")
		return
	}

	var req revokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request payload")
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
	if req.Reason == "" {
		h.respondWithError(w, http.StatusBadRequest, "reason is required")
		return
	}

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
		"message":    "Enrollment unrevoked successfully",
		"enrollment": enrollment,
	})
}

// GetDeviceEnrollments lists active enrollments for a device.
func (h *AttendanceDeviceEnrollmentHandler) GetDeviceEnrollments(w http.ResponseWriter, r *http.Request) {
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

	enrollments, err := h.enrollmentService.GetEnrollmentsByDevice(ctx, companyID, deviceID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, enrollments)
}

// GetRevokedDeviceEnrollments lists revoked enrollments for a device.
func (h *AttendanceDeviceEnrollmentHandler) GetRevokedDeviceEnrollments(w http.ResponseWriter, r *http.Request) {
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

	enrollments, err := h.enrollmentService.GetRevokedEnrollmentsByDevice(ctx, companyID, deviceID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, enrollments)
}

// Helper response methods
func (h *AttendanceDeviceEnrollmentHandler) respondWithJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (h *AttendanceDeviceEnrollmentHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
