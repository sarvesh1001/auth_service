package handler

import (
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

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/attendance/service/device"
	"auth-service/internal/attendance/service/source"
	"auth-service/internal/infrastructure/audit"
)

type DeviceHandler struct {
	deviceService       device.DeviceService
	attendanceSourceSvc source.SourceAdminService
	auditService        *audit.AuditService
	logger              *zap.Logger
}

func NewDeviceHandler(
	deviceService device.DeviceService,
	attendanceSourceSvc source.SourceAdminService,
	auditService *audit.AuditService,
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
	GeofenceID     *uuid.UUID             `json:"geofence_id,omitempty"`
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
	GeofenceID     *uuid.UUID             `json:"geofence_id,omitempty"`
	IPAddress      *string                `json:"ip_address,omitempty"`
	MacAddress     *string                `json:"mac_address,omitempty"`
	IsActive       bool                   `json:"is_active"`
	IsTrusted      bool                   `json:"is_trusted"`
	LastSeenAt     *time.Time             `json:"last_seen_at,omitempty"`
	InstalledAt    *time.Time             `json:"installed_at,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
}

// deviceUUID parses a device_id string into a UUID for audit purposes.
// Device IDs are generated as UUID strings (see CreateDevice), so parse
// failures are logged and returned as uuid.Nil rather than aborting.
func (h *DeviceHandler) deviceUUID(deviceID string, logger *zap.Logger) uuid.UUID {
	id, err := uuid.Parse(deviceID)
	if err != nil {
		if logger != nil {
			logger.Warn("device_id is not a UUID; audit will use uuid.Nil",
				zap.String("device_id", deviceID),
				zap.Error(err))
		}
		return uuid.Nil
	}
	return id
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
	ctxCompany, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if !assertPathCompany(w, ctxCompany, companyID, h.logger) {
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
			h.respondWithError(w, http.StatusBadRequest, "work_center_code is required for device source")
			return
		}
	}
	_, err = h.attendanceSourceSvc.CreateSource(
		ctx,
		companyID,
		req.SourceType,
		"",
		&actorID,
	)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	deviceID := uuid.New().String()
	metadata := map[string]interface{}{
		"ip_address":     clientIP(r),
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
	dev := &models.AttendanceDevice{
		DeviceID:       deviceID,
		CompanyID:      companyID,
		SourceType:     req.SourceType,
		DeviceCode:     req.DeviceCode,
		DeviceName:     req.DeviceName,
		Manufacturer:   req.Manufacturer,
		Model:          req.Model,
		WorkCenterCode: req.WorkCenterCode,
		GeofenceID:     req.GeofenceID,
		IPAddress:      req.IPAddress,
		MacAddress:     req.MacAddress,
		Metadata:       req.Metadata,
		IsTrusted:      false,
	}
	if req.IsActive != nil {
		dev.IsActive = *req.IsActive
	} else {
		dev.IsActive = true
	}
	if req.InstalledAt != nil {
		dev.InstalledAt = req.InstalledAt
	}
	afterState, _ := json.Marshal(dev)
	if err := h.deviceService.RegisterDevice(ctx, dev); err != nil {
		statusCode := http.StatusInternalServerError
		if strings.Contains(err.Error(), "already exists") {
			statusCode = http.StatusConflict
		} else if strings.Contains(err.Error(), "validation failed") {
			statusCode = http.StatusBadRequest
		}
		h.logger.Error("Failed to register device",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err),
		)
		h.respondWithError(w, statusCode, err.Error())
		return
	}
	if h.auditService != nil {
		entityUUID := h.deviceUUID(deviceID, h.logger)
		_ = h.auditService.LogAction(
			ctx, nil, &companyID, "device", "create", "device",
			&entityUUID, actorType, &actorID, nil, afterState, metadata,
		)
	}
	response := h.buildDeviceResponse(dev)
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
	ctxCompany, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if !assertPathCompany(w, ctxCompany, companyID, h.logger) {
		return
	}
	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "Device ID is required")
		return
	}
	dev, err := h.deviceService.GetDevice(ctx, companyID, deviceID)
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
	if dev == nil {
		h.respondWithError(w, http.StatusNotFound, "Device not found")
		return
	}
	response := h.buildDeviceResponse(dev)
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
	ctxCompany, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if !assertPathCompany(w, ctxCompany, companyID, h.logger) {
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
		req.GeofenceID == nil && req.IPAddress == nil && req.MacAddress == nil &&
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
		"ip_address":     clientIP(r),
		"user_agent":     r.UserAgent(),
		"endpoint":       r.URL.Path,
		"request_method": r.Method,
		"device_id":      deviceID,
	}
	dev := &models.AttendanceDevice{
		DeviceID:       deviceID,
		CompanyID:      companyID,
		SourceType:     existingDevice.SourceType,
		DeviceCode:     req.DeviceCode,
		DeviceName:     req.DeviceName,
		Manufacturer:   req.Manufacturer,
		Model:          req.Model,
		WorkCenterCode: req.WorkCenterCode,
		GeofenceID:     req.GeofenceID,
		IPAddress:      req.IPAddress,
		MacAddress:     req.MacAddress,
		Metadata:       req.Metadata,
	}
	if req.DeviceCode == "" {
		dev.DeviceCode = existingDevice.DeviceCode
	}
	if req.DeviceName == nil {
		dev.DeviceName = existingDevice.DeviceName
	}
	if req.Manufacturer == nil {
		dev.Manufacturer = existingDevice.Manufacturer
	}
	if req.Model == nil {
		dev.Model = existingDevice.Model
	}
	if req.WorkCenterCode == nil {
		dev.WorkCenterCode = existingDevice.WorkCenterCode
	}
	if req.GeofenceID == nil {
		dev.GeofenceID = existingDevice.GeofenceID
	}
	if req.IPAddress == nil {
		dev.IPAddress = existingDevice.IPAddress
	}
	if req.MacAddress == nil {
		dev.MacAddress = existingDevice.MacAddress
	}
	if req.Metadata == nil {
		dev.Metadata = existingDevice.Metadata
	}
	if req.IsActive != nil {
		dev.IsActive = *req.IsActive
	} else {
		dev.IsActive = existingDevice.IsActive
	}
	dev.IsTrusted = existingDevice.IsTrusted
	if req.InstalledAt != nil {
		dev.InstalledAt = req.InstalledAt
	} else {
		dev.InstalledAt = existingDevice.InstalledAt
	}
	beforeState, _ := json.Marshal(existingDevice)
	afterState, _ := json.Marshal(dev)
	if err := h.deviceService.UpdateDevice(ctx, dev); err != nil {
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
	if h.auditService != nil {
		entityUUID := h.deviceUUID(deviceID, h.logger)
		_ = h.auditService.LogAction(
			ctx, nil, &companyID, "device", "update", "device",
			&entityUUID, actorType, &actorID, beforeState, afterState, metadata,
		)
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
	ctxCompany, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if !assertPathCompany(w, ctxCompany, companyID, h.logger) {
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
		"ip_address":     clientIP(r),
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
	if h.auditService != nil {
		entityUUID := h.deviceUUID(deviceID, h.logger)
		_ = h.auditService.LogAction(
			ctx, nil, &companyID, "device", "delete", "device",
			&entityUUID, actorType, &actorID, beforeState, nil, metadata,
		)
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
	ctxCompany, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if !assertPathCompany(w, ctxCompany, companyID, h.logger) {
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
	filter := device.DeviceFilter{
		Page:     page,
		PageSize: pageSize,
	}
	if sourceType := r.URL.Query().Get("source_type"); sourceType != "" {
		filter.SourceType = &sourceType
	}
	if workCenterCode := r.URL.Query().Get("work_center_code"); workCenterCode != "" {
		filter.WorkCenterCode = &workCenterCode
	}
	if geofenceIDStr := r.URL.Query().Get("geofence_id"); geofenceIDStr != "" {
		if gfID, err := uuid.Parse(geofenceIDStr); err == nil {
			filter.GeofenceID = &gfID
		}
	}
	if isActive := r.URL.Query().Get("is_active"); isActive != "" {
		if active, err := strconv.ParseBool(isActive); err == nil {
			filter.IsActive = &active
		}
	}
	if isTrusted := r.URL.Query().Get("is_trusted"); isTrusted != "" {
		if trusted, err := strconv.ParseBool(isTrusted); err == nil {
			filter.IsTrusted = &trusted
		}
	}
	if includeInactive := r.URL.Query().Get("include_inactive"); includeInactive != "" {
		if include, err := strconv.ParseBool(includeInactive); err == nil {
			filter.IncludeInactive = include
		}
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
	ctxCompany, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if !assertPathCompany(w, ctxCompany, companyID, h.logger) {
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
		"ip_address":     clientIP(r),
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
	if h.auditService != nil {
		entityUUID := h.deviceUUID(deviceID, h.logger)
		_ = h.auditService.LogAction(
			ctx, nil, &companyID, "device", "activate", "device",
			&entityUUID, actorType, &actorID, beforeState, afterState, metadata,
		)
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
	ctxCompany, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if !assertPathCompany(w, ctxCompany, companyID, h.logger) {
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
		"ip_address":     clientIP(r),
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
	if h.auditService != nil {
		entityUUID := h.deviceUUID(deviceID, h.logger)
		_ = h.auditService.LogAction(
			ctx, nil, &companyID, "device", "deactivate", "device",
			&entityUUID, actorType, &actorID, beforeState, afterState, metadata,
		)
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
	ctxCompany, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if !assertPathCompany(w, ctxCompany, companyID, h.logger) {
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
		"ip_address":     clientIP(r),
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
	if h.auditService != nil {
		entityUUID := h.deviceUUID(deviceID, h.logger)
		_ = h.auditService.LogAction(
			ctx, nil, &companyID, "device", "mark_trusted", "device",
			&entityUUID, actorType, &actorID, beforeState, afterState, metadata,
		)
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
	ctxCompany, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if !assertPathCompany(w, ctxCompany, companyID, h.logger) {
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
		"ip_address":     clientIP(r),
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
	if h.auditService != nil {
		entityUUID := h.deviceUUID(deviceID, h.logger)
		_ = h.auditService.LogAction(
			ctx, nil, &companyID, "device", "revoke_trust", "device",
			&entityUUID, actorType, &actorID, beforeState, afterState, metadata,
		)
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
	ctxCompany, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if !assertPathCompany(w, ctxCompany, companyID, h.logger) {
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
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		return "", uuid.Nil, err
	}
	actorType := "user"
	if sessionType == "admin" {
		actorType = "admin"
	}
	return actorType, userID, nil
}

func (h *DeviceHandler) buildDeviceResponse(dev *models.AttendanceDevice) DeviceResponse {
	if dev == nil {
		return DeviceResponse{}
	}
	var deviceNamePtr *string
	if dev.DeviceName != nil && *dev.DeviceName != "" {
		deviceNamePtr = dev.DeviceName
	}
	return DeviceResponse{
		DeviceID:       dev.DeviceID,
		CompanyID:      dev.CompanyID,
		SourceType:     dev.SourceType,
		DeviceCode:     dev.DeviceCode,
		DeviceName:     deviceNamePtr,
		Manufacturer:   dev.Manufacturer,
		Model:          dev.Model,
		WorkCenterCode: dev.WorkCenterCode,
		GeofenceID:     dev.GeofenceID,
		IPAddress:      dev.IPAddress,
		MacAddress:     dev.MacAddress,
		IsActive:       dev.IsActive,
		IsTrusted:      dev.IsTrusted,
		LastSeenAt:     dev.LastSeenAt,
		InstalledAt:    dev.InstalledAt,
		Metadata:       dev.Metadata,
		CreatedAt:      dev.CreatedAt,
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