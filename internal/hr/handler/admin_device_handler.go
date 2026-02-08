package handler

import (
	"auth-service/internal/hr/models/attendance"
	"auth-service/internal/hr/repository"
	"auth-service/internal/hr/service"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type DeviceHandler struct {
	deviceService       service.AttendanceDeviceService
	attendanceSourceSvc service.AttendanceSourceAdminService
	auditService        *service.AuditService
	logger              *zap.Logger
}

func NewDeviceHandler(
	deviceService service.AttendanceDeviceService,
	attendanceSourceSvc service.AttendanceSourceAdminService,
	auditService *service.AuditService,
	logger *zap.Logger,
) *DeviceHandler {
	return &DeviceHandler{
		deviceService:       deviceService,
		attendanceSourceSvc: attendanceSourceSvc,
		auditService:        auditService,
		logger:              logger,
	}
}

type DeviceRequest struct {
	SourceType     string                 `json:"source_type"`
	DeviceCode     string                 `json:"device_code"`
	DeviceName     *string                `json:"device_name,omitempty"`
	Manufacturer   *string                `json:"manufacturer,omitempty"`
	Model          *string                `json:"model,omitempty"`
	WorkCenterCode *string                `json:"work_center_code,omitempty"`
	LocationID     *uuid.UUID             `json:"location_id,omitempty"`
	IPAddress      *string                `json:"ip_address,omitempty"`
	MacAddress     *string                `json:"mac_address,omitempty"`
	IsActive       *bool                  `json:"is_active,omitempty"`
	InstalledAt    *time.Time             `json:"installed_at,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

type DeviceResponse struct {
	DeviceID       string                 `json:"device_id"`
	CompanyID      uuid.UUID              `json:"company_id"`
	SourceType     string                 `json:"source_type"`
	DeviceCode     string                 `json:"device_code"`
	DeviceName     *string                `json:"device_name,omitempty"`
	Manufacturer   *string                `json:"manufacturer,omitempty"`
	Model          *string                `json:"model,omitempty"`
	WorkCenterCode *string                `json:"work_center_code,omitempty"`
	LocationID     *uuid.UUID             `json:"location_id,omitempty"`
	IPAddress      *string                `json:"ip_address,omitempty"`
	MacAddress     *string                `json:"mac_address,omitempty"`
	IsActive       bool                   `json:"is_active"`
	IsTrusted      bool                   `json:"is_trusted"`
	LastSeenAt     *time.Time             `json:"last_seen_at,omitempty"`
	InstalledAt    *time.Time             `json:"installed_at,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
}

type DeviceListResponse struct {
	Devices    []DeviceResponse `json:"devices"`
	Total      int              `json:"total"`
	Page       int              `json:"page"`
	PageSize   int              `json:"page_size"`
	TotalPages int              `json:"total_pages"`
}

func (h *DeviceHandler) panicRecovery(w http.ResponseWriter, method string) {
	if r := recover(); r != nil {
		h.logger.Error("panic recovered in DeviceHandler",
			zap.Any("panic", r),
			zap.String("method", method),
			zap.Stack("stack"),
		)
		h.respondWithError(w, http.StatusInternalServerError, "Internal server error")
	}
}

func (h *DeviceHandler) CreateDevice(w http.ResponseWriter, r *http.Request) {
	defer h.panicRecovery(w, "CreateDevice")
	startTime := time.Now()
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	if actorType != "admin" {
		h.respondWithError(w, http.StatusForbidden, "only admins can manage devices")
		return
	}

	var req DeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// ------------------------------
	// VALIDATION
	// ------------------------------

	if req.SourceType == "" {
		h.respondWithError(w, http.StatusBadRequest, "Source type is required")
		return
	}

	if req.DeviceCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "Device code is required")
		return
	}

	if req.SourceType == "rfid" {
		h.respondWithError(w, http.StatusBadRequest, "rfid devices are not supported")
		return
	}

	if req.SourceType == "biometric" || req.SourceType == "kiosk" || req.SourceType == "classroom" {
		if req.WorkCenterCode == nil || *req.WorkCenterCode == "" {
			h.respondWithError(
				w,
				http.StatusBadRequest,
				"work_center_code is required for device source",
			)
			return
		}
	}

	// ------------------------------
	// 🔥 ENSURE ATTENDANCE SOURCE EXISTS (HYBRID CORE)
	// ------------------------------

	_, err = h.attendanceSourceSvc.CreateSource(
		ctx,
		companyID,
		req.SourceType,
		"",       // default name
		&actorID, // admin actor
	)
	if err != nil {
		// Ignore "already exists" → expected in hybrid model
		if !strings.Contains(err.Error(), "already exists") {
			h.respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	// ------------------------------
	// DEVICE CREATION
	// ------------------------------

	deviceID := uuid.New().String()

	metadata := map[string]interface{}{
		"ip_address":     r.RemoteAddr,
		"user_agent":     r.UserAgent(),
		"endpoint":       r.URL.Path,
		"request_method": r.Method,
		"device_id":      deviceID,
		"device_code":    req.DeviceCode,
		"source_type":    req.SourceType,
	}

	if req.DeviceName != nil {
		metadata["device_name"] = *req.DeviceName
	}

	device := &attendance.AttendanceDevice{
		DeviceID:       deviceID,
		CompanyID:      companyID,
		SourceType:     req.SourceType,
		DeviceCode:     req.DeviceCode,
		DeviceName:     req.DeviceName,
		Manufacturer:   req.Manufacturer,
		Model:          req.Model,
		WorkCenterCode: req.WorkCenterCode,
		LocationID:     req.LocationID,
		IPAddress:      req.IPAddress,
		MacAddress:     req.MacAddress,
		Metadata:       req.Metadata,
		IsTrusted:      false,
	}

	if req.IsActive != nil {
		device.IsActive = *req.IsActive
	} else {
		device.IsActive = true
	}

	if req.InstalledAt != nil {
		device.InstalledAt = req.InstalledAt
	}

	afterState, _ := json.Marshal(device)

	if err := h.deviceService.RegisterDevice(ctx, device); err != nil {
		statusCode := http.StatusInternalServerError
		if strings.Contains(err.Error(), "already exists") {
			statusCode = http.StatusConflict
		} else if strings.Contains(err.Error(), "validation failed") {
			statusCode = http.StatusBadRequest
		}

		h.logger.Error(
			"Failed to register device",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err),
		)

		h.respondWithError(w, statusCode, err.Error())
		return
	}

	// ------------------------------
	// AUDIT
	// ------------------------------

	if h.auditService != nil {
		_ = h.auditService.LogAction(
			ctx,
			&companyID,
			"device",
			"create",
			"device",
			nil,
			actorType,
			&actorID,
			nil,
			afterState,
			metadata,
		)
	}

	// ------------------------------
	// RESPONSE
	// ------------------------------

	response := h.buildDeviceResponse(device)

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    response,
		"message": "Device registered successfully",
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

func (h *DeviceHandler) GetDevice(w http.ResponseWriter, r *http.Request) {
	defer h.panicRecovery(w, "GetDevice")
	startTime := time.Now()
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "Device ID is required")
		return
	}

	device, err := h.deviceService.GetDevice(ctx, companyID, deviceID)
	if err != nil {
		if errors.Is(err, repository.ErrDeviceNotFound) {
			h.respondWithError(w, http.StatusNotFound, "Device not found")
			return
		}
		h.logger.Error("Failed to get device",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve device")
		return
	}

	if device == nil {
		h.respondWithError(w, http.StatusNotFound, "Device not found")
		return
	}

	response := h.buildDeviceResponse(device)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    response,
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

func (h *DeviceHandler) UpdateDevice(w http.ResponseWriter, r *http.Request) {
	defer h.panicRecovery(w, "UpdateDevice")
	startTime := time.Now()
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "Device ID is required")
		return
	}

	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	if actorType != "admin" {
		h.respondWithError(w, http.StatusForbidden, "only admins can manage devices")
		return
	}

	existingDevice, err := h.deviceService.GetDevice(ctx, companyID, deviceID)
	if err != nil {
		if errors.Is(err, repository.ErrDeviceNotFound) {
			h.respondWithError(w, http.StatusNotFound, "Device not found")
			return
		}
		h.logger.Error("Failed to get existing device",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve device")
		return
	}

	if existingDevice == nil {
		h.respondWithError(w, http.StatusNotFound, "Device not found")
		return
	}

	var req DeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.SourceType == "" && req.DeviceCode == "" && req.DeviceName == nil &&
		req.Manufacturer == nil && req.Model == nil && req.WorkCenterCode == nil &&
		req.LocationID == nil && req.IPAddress == nil && req.MacAddress == nil &&
		req.IsActive == nil && req.InstalledAt == nil && req.Metadata == nil {
		h.respondWithError(w, http.StatusBadRequest, "No update fields provided")
		return
	}

	if req.SourceType != "" && req.SourceType != existingDevice.SourceType {
		h.respondWithError(w, http.StatusBadRequest, "source_type cannot be changed")
		return
	}

	if req.SourceType == "rfid" {
		h.respondWithError(w, http.StatusBadRequest, "rfid devices are not supported")
		return
	}

	if req.WorkCenterCode != nil && (existingDevice.SourceType == "biometric" || existingDevice.SourceType == "kiosk" || existingDevice.SourceType == "classroom") {
		if *req.WorkCenterCode == "" {
			h.respondWithError(w, http.StatusBadRequest, "work_center_code is required for device source")
			return
		}
	}

	metadata := map[string]interface{}{
		"ip_address":     r.RemoteAddr,
		"user_agent":     r.UserAgent(),
		"endpoint":       r.URL.Path,
		"request_method": r.Method,
		"device_id":      deviceID,
	}

	device := &attendance.AttendanceDevice{
		DeviceID:       deviceID,
		CompanyID:      companyID,
		SourceType:     existingDevice.SourceType,
		DeviceCode:     req.DeviceCode,
		DeviceName:     req.DeviceName,
		Manufacturer:   req.Manufacturer,
		Model:          req.Model,
		WorkCenterCode: req.WorkCenterCode,
		LocationID:     req.LocationID,
		IPAddress:      req.IPAddress,
		MacAddress:     req.MacAddress,
		Metadata:       req.Metadata,
	}

	if req.DeviceCode == "" {
		device.DeviceCode = existingDevice.DeviceCode
	}
	if req.DeviceName == nil {
		device.DeviceName = existingDevice.DeviceName
	}
	if req.Manufacturer == nil {
		device.Manufacturer = existingDevice.Manufacturer
	}
	if req.Model == nil {
		device.Model = existingDevice.Model
	}
	if req.WorkCenterCode == nil {
		device.WorkCenterCode = existingDevice.WorkCenterCode
	}
	if req.LocationID == nil {
		device.LocationID = existingDevice.LocationID
	}
	if req.IPAddress == nil {
		device.IPAddress = existingDevice.IPAddress
	}
	if req.MacAddress == nil {
		device.MacAddress = existingDevice.MacAddress
	}
	if req.Metadata == nil {
		device.Metadata = existingDevice.Metadata
	}
	if req.IsActive != nil {
		device.IsActive = *req.IsActive
	} else {
		device.IsActive = existingDevice.IsActive
	}
	device.IsTrusted = existingDevice.IsTrusted
	if req.InstalledAt != nil {
		device.InstalledAt = req.InstalledAt
	} else {
		device.InstalledAt = existingDevice.InstalledAt
	}

	beforeState, _ := json.Marshal(existingDevice)
	afterState, _ := json.Marshal(device)

	if err := h.deviceService.UpdateDevice(ctx, device); err != nil {
		statusCode := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			statusCode = http.StatusNotFound
		}
		h.logger.Error("Failed to update device",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err))
		h.respondWithError(w, statusCode, err.Error())
		return
	}

	entityUUID := uuid.Nil
	err = h.auditService.LogAction(
		ctx,
		&companyID,
		"device",
		"update",
		"device",
		&entityUUID,
		actorType,
		&actorID,
		beforeState,
		afterState,
		metadata,
	)
	if err != nil {
		h.logger.Warn("Failed to create audit log",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err))
	}

	updatedDevice, err := h.deviceService.GetDevice(ctx, companyID, deviceID)
	if err != nil {
		h.logger.Error("Failed to get updated device",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get updated device")
		return
	}

	if updatedDevice == nil {
		h.respondWithError(w, http.StatusNotFound, "Device not found after update")
		return
	}

	response := h.buildDeviceResponse(updatedDevice)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    response,
		"message": "Device updated successfully",
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

func (h *DeviceHandler) DeleteDevice(w http.ResponseWriter, r *http.Request) {
	defer h.panicRecovery(w, "DeleteDevice")
	startTime := time.Now()
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "Device ID is required")
		return
	}

	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	if actorType != "admin" {
		h.respondWithError(w, http.StatusForbidden, "only admins can manage devices")
		return
	}

	existingDevice, err := h.deviceService.GetDevice(ctx, companyID, deviceID)
	if err != nil {
		if errors.Is(err, repository.ErrDeviceNotFound) || strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Device not found")
			return
		}
		h.logger.Error("Failed to get device for deletion",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve device")
		return
	}

	if existingDevice == nil {
		h.respondWithError(w, http.StatusNotFound, "Device not found")
		return
	}

	metadata := map[string]interface{}{
		"ip_address":     r.RemoteAddr,
		"user_agent":     r.UserAgent(),
		"endpoint":       r.URL.Path,
		"request_method": r.Method,
		"device_id":      deviceID,
		"device_code":    existingDevice.DeviceCode,
		"source_type":    existingDevice.SourceType,
	}

	beforeState, _ := json.Marshal(existingDevice)

	if err := h.deviceService.DeleteDevice(ctx, companyID, deviceID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Device not found")
		} else {
			h.logger.Error("Failed to delete device",
				zap.String("company_id", companyID.String()),
				zap.String("device_id", deviceID),
				zap.Error(err))
			h.respondWithError(w, http.StatusInternalServerError, "Failed to delete device")
		}
		return
	}

	entityUUID := uuid.Nil
	err = h.auditService.LogAction(
		ctx,
		&companyID,
		"device",
		"delete",
		"device",
		&entityUUID,
		actorType,
		&actorID,
		beforeState,
		nil,
		metadata,
	)
	if err != nil {
		h.logger.Warn("Failed to create audit log",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err))
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Device deleted successfully",
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

func (h *DeviceHandler) ListDevices(w http.ResponseWriter, r *http.Request) {
	defer h.panicRecovery(w, "ListDevices")
	startTime := time.Now()
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	filters := make(map[string]interface{})
	if sourceType := r.URL.Query().Get("source_type"); sourceType != "" {
		filters["source_type"] = sourceType
	}
	if workCenterCode := r.URL.Query().Get("work_center_code"); workCenterCode != "" {
		filters["work_center_code"] = workCenterCode
	}
	if locationIDStr := r.URL.Query().Get("location_id"); locationIDStr != "" {
		if locationID, err := uuid.Parse(locationIDStr); err == nil {
			filters["location_id"] = locationID
		}
	}
	if isActive := r.URL.Query().Get("is_active"); isActive != "" {
		if active, err := strconv.ParseBool(isActive); err == nil {
			filters["is_active"] = active
		}
	}
	if isTrusted := r.URL.Query().Get("is_trusted"); isTrusted != "" {
		if trusted, err := strconv.ParseBool(isTrusted); err == nil {
			filters["is_trusted"] = trusted
		}
	}
	if includeInactive := r.URL.Query().Get("include_inactive"); includeInactive != "" {
		if include, err := strconv.ParseBool(includeInactive); err == nil && include {
			filters["include_inactive"] = true
		}
	}

	filter := service.DeviceFilter{
		Page:     page,
		PageSize: pageSize,
	}

	if val, ok := filters["source_type"]; ok {
		strVal := val.(string)
		filter.SourceType = &strVal
	}
	if val, ok := filters["work_center_code"]; ok {
		strVal := val.(string)
		filter.WorkCenterCode = &strVal
	}
	if val, ok := filters["location_id"]; ok {
		uuidVal := val.(uuid.UUID)
		filter.LocationID = &uuidVal
	}
	if val, ok := filters["is_active"]; ok {
		boolVal := val.(bool)
		filter.IsActive = &boolVal
	}
	if val, ok := filters["is_trusted"]; ok {
		boolVal := val.(bool)
		filter.IsTrusted = &boolVal
	}
	if val, ok := filters["include_inactive"]; ok {
		filter.IncludeInactive = val.(bool)
	}

	devices, err := h.deviceService.ListDevices(ctx, companyID, filter)
	if err != nil {
		h.logger.Error("Failed to list devices",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to list devices")
		return
	}

	deviceResponses := make([]DeviceResponse, len(devices))
	for i, d := range devices {
		deviceResponses[i] = h.buildDeviceResponse(d)
	}

	total := len(devices)
	totalPages := (total + pageSize - 1) / pageSize

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"devices": deviceResponses,
		},
		"meta": map[string]interface{}{
			"page":         page,
			"page_size":    pageSize,
			"total_count":  total,
			"total_pages":  totalPages,
			"has_next":     page < totalPages,
			"has_previous": page > 1,
			"filters":      filters,
			"duration":     time.Since(startTime).String(),
		},
	})
}

func (h *DeviceHandler) ActivateDevice(w http.ResponseWriter, r *http.Request) {
	defer h.panicRecovery(w, "ActivateDevice")
	startTime := time.Now()
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "Device ID is required")
		return
	}

	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	if actorType != "admin" {
		h.respondWithError(w, http.StatusForbidden, "only admins can manage devices")
		return
	}

	existingDevice, err := h.deviceService.GetDevice(ctx, companyID, deviceID)
	if err != nil {
		if errors.Is(err, repository.ErrDeviceNotFound) || strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Device not found")
			return
		}
		h.logger.Error("Failed to get device for activation",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve device")
		return
	}

	if existingDevice == nil {
		h.respondWithError(w, http.StatusNotFound, "Device not found")
		return
	}

	metadata := map[string]interface{}{
		"ip_address":     r.RemoteAddr,
		"user_agent":     r.UserAgent(),
		"endpoint":       r.URL.Path,
		"request_method": r.Method,
		"device_id":      deviceID,
		"device_code":    existingDevice.DeviceCode,
	}

	beforeState, _ := json.Marshal(existingDevice)

	if err := h.deviceService.ActivateDevice(ctx, companyID, deviceID); err != nil {
		statusCode := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			statusCode = http.StatusNotFound
		} else if strings.Contains(err.Error(), "already active") {
			statusCode = http.StatusBadRequest
		}
		h.logger.Error("Failed to activate device",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err))
		h.respondWithError(w, statusCode, err.Error())
		return
	}

	updatedDevice, err := h.deviceService.GetDevice(ctx, companyID, deviceID)
	if err != nil {
		h.logger.Error("Failed to get updated device after activation",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get updated device")
		return
	}

	if updatedDevice == nil {
		h.respondWithError(w, http.StatusNotFound, "Device not found after activation")
		return
	}

	afterState, _ := json.Marshal(updatedDevice)
	entityUUID := uuid.Nil
	err = h.auditService.LogAction(
		ctx,
		&companyID,
		"device",
		"activate",
		"device",
		&entityUUID,
		actorType,
		&actorID,
		beforeState,
		afterState,
		metadata,
	)
	if err != nil {
		h.logger.Warn("Failed to create audit log",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err))
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Device activated successfully",
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

func (h *DeviceHandler) DeactivateDevice(w http.ResponseWriter, r *http.Request) {
	defer h.panicRecovery(w, "DeactivateDevice")
	startTime := time.Now()
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "Device ID is required")
		return
	}

	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	if actorType != "admin" {
		h.respondWithError(w, http.StatusForbidden, "only admins can manage devices")
		return
	}

	existingDevice, err := h.deviceService.GetDevice(ctx, companyID, deviceID)
	if err != nil {
		if errors.Is(err, repository.ErrDeviceNotFound) || strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Device not found")
			return
		}
		h.logger.Error("Failed to get device for deactivation",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve device")
		return
	}

	if existingDevice == nil {
		h.respondWithError(w, http.StatusNotFound, "Device not found")
		return
	}

	metadata := map[string]interface{}{
		"ip_address":     r.RemoteAddr,
		"user_agent":     r.UserAgent(),
		"endpoint":       r.URL.Path,
		"request_method": r.Method,
		"device_id":      deviceID,
		"device_code":    existingDevice.DeviceCode,
	}

	beforeState, _ := json.Marshal(existingDevice)

	if err := h.deviceService.DeactivateDevice(ctx, companyID, deviceID); err != nil {
		statusCode := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			statusCode = http.StatusNotFound
		} else if strings.Contains(err.Error(), "already inactive") {
			statusCode = http.StatusBadRequest
		}
		h.logger.Error("Failed to deactivate device",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err))
		h.respondWithError(w, statusCode, err.Error())
		return
	}

	updatedDevice, err := h.deviceService.GetDevice(ctx, companyID, deviceID)
	if err != nil {
		h.logger.Error("Failed to get updated device after deactivation",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get updated device")
		return
	}

	if updatedDevice == nil {
		h.respondWithError(w, http.StatusNotFound, "Device not found after deactivation")
		return
	}

	afterState, _ := json.Marshal(updatedDevice)
	entityUUID := uuid.Nil
	err = h.auditService.LogAction(
		ctx,
		&companyID,
		"device",
		"deactivate",
		"device",
		&entityUUID,
		actorType,
		&actorID,
		beforeState,
		afterState,
		metadata,
	)
	if err != nil {
		h.logger.Warn("Failed to create audit log",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err))
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Device deactivated successfully",
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

func (h *DeviceHandler) MarkAsTrusted(w http.ResponseWriter, r *http.Request) {
	defer h.panicRecovery(w, "MarkAsTrusted")
	startTime := time.Now()
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "Device ID is required")
		return
	}

	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	if actorType != "admin" {
		h.respondWithError(w, http.StatusForbidden, "only admins can manage devices")
		return
	}

	existingDevice, err := h.deviceService.GetDevice(ctx, companyID, deviceID)
	if err != nil {
		if errors.Is(err, repository.ErrDeviceNotFound) || strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Device not found")
			return
		}
		h.logger.Error("Failed to get device for marking as trusted",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve device")
		return
	}

	if existingDevice == nil {
		h.respondWithError(w, http.StatusNotFound, "Device not found")
		return
	}

	metadata := map[string]interface{}{
		"ip_address":     r.RemoteAddr,
		"user_agent":     r.UserAgent(),
		"endpoint":       r.URL.Path,
		"request_method": r.Method,
		"device_id":      deviceID,
		"device_code":    existingDevice.DeviceCode,
	}

	beforeState, _ := json.Marshal(existingDevice)

	if err := h.deviceService.MarkAsTrusted(ctx, companyID, deviceID); err != nil {
		statusCode := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			statusCode = http.StatusNotFound
		} else if strings.Contains(err.Error(), "already trusted") {
			statusCode = http.StatusBadRequest
		}
		h.logger.Error("Failed to mark device as trusted",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err))
		h.respondWithError(w, statusCode, err.Error())
		return
	}

	updatedDevice, err := h.deviceService.GetDevice(ctx, companyID, deviceID)
	if err != nil {
		h.logger.Error("Failed to get updated device after marking as trusted",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get updated device")
		return
	}

	if updatedDevice == nil {
		h.respondWithError(w, http.StatusNotFound, "Device not found after marking as trusted")
		return
	}

	afterState, _ := json.Marshal(updatedDevice)
	entityUUID := uuid.Nil
	err = h.auditService.LogAction(
		ctx,
		&companyID,
		"device",
		"mark_trusted",
		"device",
		&entityUUID,
		actorType,
		&actorID,
		beforeState,
		afterState,
		metadata,
	)
	if err != nil {
		h.logger.Warn("Failed to create audit log",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err))
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Device marked as trusted successfully",
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

func (h *DeviceHandler) RevokeTrust(w http.ResponseWriter, r *http.Request) {
	defer h.panicRecovery(w, "RevokeTrust")
	startTime := time.Now()
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "Device ID is required")
		return
	}

	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	if actorType != "admin" {
		h.respondWithError(w, http.StatusForbidden, "only admins can manage devices")
		return
	}

	existingDevice, err := h.deviceService.GetDevice(ctx, companyID, deviceID)
	if err != nil {
		if errors.Is(err, repository.ErrDeviceNotFound) || strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Device not found")
			return
		}
		h.logger.Error("Failed to get device for revoking trust",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve device")
		return
	}

	if existingDevice == nil {
		h.respondWithError(w, http.StatusNotFound, "Device not found")
		return
	}

	metadata := map[string]interface{}{
		"ip_address":     r.RemoteAddr,
		"user_agent":     r.UserAgent(),
		"endpoint":       r.URL.Path,
		"request_method": r.Method,
		"device_id":      deviceID,
		"device_code":    existingDevice.DeviceCode,
	}

	beforeState, _ := json.Marshal(existingDevice)

	if err := h.deviceService.RevokeTrust(ctx, companyID, deviceID); err != nil {
		statusCode := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			statusCode = http.StatusNotFound
		} else if strings.Contains(err.Error(), "already not trusted") {
			statusCode = http.StatusBadRequest
		}
		h.logger.Error("Failed to revoke device trust",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err))
		h.respondWithError(w, statusCode, err.Error())
		return
	}

	updatedDevice, err := h.deviceService.GetDevice(ctx, companyID, deviceID)
	if err != nil {
		h.logger.Error("Failed to get updated device after revoking trust",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get updated device")
		return
	}

	if updatedDevice == nil {
		h.respondWithError(w, http.StatusNotFound, "Device not found after revoking trust")
		return
	}

	afterState, _ := json.Marshal(updatedDevice)
	entityUUID := uuid.Nil
	err = h.auditService.LogAction(
		ctx,
		&companyID,
		"device",
		"revoke_trust",
		"device",
		&entityUUID,
		actorType,
		&actorID,
		beforeState,
		afterState,
		metadata,
	)
	if err != nil {
		h.logger.Warn("Failed to create audit log",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err))
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Device trust revoked successfully",
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

func (h *DeviceHandler) GetDeviceStatistics(w http.ResponseWriter, r *http.Request) {
	defer h.panicRecovery(w, "GetDeviceStatistics")
	startTime := time.Now()
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	stats, err := h.deviceService.GetDeviceStatistics(ctx, companyID)
	if err != nil {
		h.logger.Error("Failed to get device statistics",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to get device statistics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    stats,
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

func (h *DeviceHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	defer h.panicRecovery(w, "HealthCheck")
	_ = r.Context()
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"message":   "Device service is healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (h *DeviceHandler) getActorInfo(ctx context.Context) (string, uuid.UUID, error) {
	sessionType, ok := ctx.Value("session_type").(string)
	if !ok {
		return "", uuid.Nil, fmt.Errorf("session type not found in context")
	}

	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		return "", uuid.Nil, fmt.Errorf("user ID not found in context")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return "", uuid.Nil, fmt.Errorf("invalid user ID in context: %v", err)
	}

	actorType := "user"
	if sessionType == "admin" {
		actorType = "admin"
	}

	return actorType, userID, nil
}

func (h *DeviceHandler) buildDeviceResponse(device *attendance.AttendanceDevice) DeviceResponse {
	if device == nil {
		return DeviceResponse{}
	}

	var deviceNamePtr *string
	if device.DeviceName != nil && *device.DeviceName != "" {
		deviceNamePtr = device.DeviceName
	}

	return DeviceResponse{
		DeviceID:       device.DeviceID,
		CompanyID:      device.CompanyID,
		SourceType:     device.SourceType,
		DeviceCode:     device.DeviceCode,
		DeviceName:     deviceNamePtr,
		Manufacturer:   device.Manufacturer,
		Model:          device.Model,
		WorkCenterCode: device.WorkCenterCode,
		LocationID:     device.LocationID,
		IPAddress:      device.IPAddress,
		MacAddress:     device.MacAddress,
		IsActive:       device.IsActive,
		IsTrusted:      device.IsTrusted,
		LastSeenAt:     device.LastSeenAt,
		InstalledAt:    device.InstalledAt,
		Metadata:       device.Metadata,
		CreatedAt:      device.CreatedAt,
	}
}

func (h *DeviceHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

func (h *DeviceHandler) respondWithError(w http.ResponseWriter, statusCode int, message string) {
	h.respondWithJSON(w, statusCode, map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    statusCode,
	})
}
