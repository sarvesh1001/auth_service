package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	customErrors "auth-service/internal/errors"
	"auth-service/internal/models"
	"auth-service/internal/service"
	"auth-service/internal/util" // ← NEW
)

// LocationHandler handles location-related endpoints.
type LocationHandler struct {
	locationService *service.LocationService
}

// NewLocationHandler creates a new LocationHandler.
func NewLocationHandler(locationService *service.LocationService) *LocationHandler {
	return &LocationHandler{locationService: locationService}
}

// ---------- Location CRUD ----------

// CreateLocation POST /api/v1/companies/{companyID}/locations
func (h *LocationHandler) CreateLocation(w http.ResponseWriter, r *http.Request) {
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	var req models.CreateLocationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	req.CompanyID = companyID

	// ── NEW: timezone validation at the boundary.
	//   nil       → inherit company.default_timezone
	//   ""        → also treated as "inherit" (nil)
	//   valid IANA → set
	//   anything else → 400
	if req.Timezone != nil && strings.TrimSpace(*req.Timezone) != "" {
		if err := util.ValidateTimezone(*req.Timezone); err != nil {
			respondError(w, http.StatusBadRequest, "timezone: "+err.Error())
			return
		}
	}

	loc, err := h.locationService.CreateLocation(r.Context(), &req)
	if err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusCreated, successResponse(loc, "Location created"))
}

// GetLocation GET /api/v1/companies/{companyID}/locations/{locationID}
func (h *LocationHandler) GetLocation(w http.ResponseWriter, r *http.Request) {
	locationIDStr := chi.URLParam(r, "locationID")
	locationID, err := uuid.Parse(locationIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid location ID")
		return
	}
	loc, err := h.locationService.GetLocation(r.Context(), locationID)
	if err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(loc, "Location retrieved"))
}

// UpdateLocation PUT /api/v1/companies/{companyID}/locations/{locationID}
func (h *LocationHandler) UpdateLocation(w http.ResponseWriter, r *http.Request) {
	locationIDStr := chi.URLParam(r, "locationID")
	locationID, err := uuid.Parse(locationIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid location ID")
		return
	}
	var req models.UpdateLocationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// ── NEW: timezone validation.
	//   nil       → preserve current tz
	//   ""        → clear (revert to inheriting company default)
	//   valid IANA → set
	//   anything else → 400
	if req.Timezone != nil && strings.TrimSpace(*req.Timezone) != "" {
		if err := util.ValidateTimezone(*req.Timezone); err != nil {
			respondError(w, http.StatusBadRequest, "timezone: "+err.Error())
			return
		}
	}

	loc, err := h.locationService.UpdateLocation(r.Context(), locationID, &req)
	if err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(loc, "Location updated"))
}

// DeleteLocation DELETE /api/v1/companies/{companyID}/locations/{locationID}
func (h *LocationHandler) DeleteLocation(w http.ResponseWriter, r *http.Request) {
	locationIDStr := chi.URLParam(r, "locationID")
	locationID, err := uuid.Parse(locationIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid location ID")
		return
	}
	if err := h.locationService.DeleteLocation(r.Context(), locationID); err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(nil, "Location deleted"))
}

// ListLocations GET /api/v1/companies/{companyID}/locations
func (h *LocationHandler) ListLocations(w http.ResponseWriter, r *http.Request) {
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page <= 0 {
		page = 1
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	offset := (page - 1) * limit
	locations, total, err := h.locationService.ListLocations(r.Context(), companyID, limit, offset)
	if err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"locations": locations,
		"total":     total,
		"page":      page,
		"limit":     limit,
	}, "Locations retrieved"))
}

// ---------- Employee Location Access ----------

// GetEmployeeLocationsWithAccess GET /api/v1/companies/{companyID}/employees/{userID}/locations
func (h *LocationHandler) GetEmployeeLocationsWithAccess(w http.ResponseWriter, r *http.Request) {
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}
	locations, err := h.locationService.GetEmployeeLocationsWithAccess(r.Context(), companyID, userID)
	if err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(locations, "Employee locations retrieved"))
}

// UpdateEmployeeLocations PUT /api/v1/companies/{companyID}/employees/{userID}/locations
func (h *LocationHandler) UpdateEmployeeLocations(w http.ResponseWriter, r *http.Request) {
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}
	var req models.EmployeeLocationUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	req.CompanyID = companyID
	req.UserID = userID

	if err := h.locationService.UpdateEmployeeLocations(r.Context(), &req); err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(nil, "Employee locations updated"))
}

// GetEmployeeLocationHistory GET /api/v1/companies/{companyID}/employees/{userID}/locations/history
func (h *LocationHandler) GetEmployeeLocationHistory(w http.ResponseWriter, r *http.Request) {
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}
	history, err := h.locationService.GetLocationHistory(r.Context(), companyID, userID)
	if err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(history, "Location history retrieved"))
}

// AddLocationAccess POST /api/v1/companies/{companyID}/employees/{userID}/locations/access
func (h *LocationHandler) AddLocationAccess(w http.ResponseWriter, r *http.Request) {
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}
	var req struct {
		LocationID  uuid.UUID `json:"location_id"`
		AccessLevel string    `json:"access_level"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	// Get the current user from context (e.g., admin who grants access)
	grantedBy, err := getUserIDFromContext(r.Context())
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	if err := h.locationService.AddLocationAccess(r.Context(), companyID, userID, req.LocationID, req.AccessLevel, grantedBy); err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusCreated, successResponse(nil, "Location access granted"))
}

// RemoveLocationAccess DELETE /api/v1/companies/{companyID}/employees/{userID}/locations/access/{locationID}
func (h *LocationHandler) RemoveLocationAccess(w http.ResponseWriter, r *http.Request) {
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}
	locationIDStr := chi.URLParam(r, "locationID")
	locationID, err := uuid.Parse(locationIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid location ID")
		return
	}
	if err := h.locationService.RemoveLocationAccess(r.Context(), companyID, userID, locationID); err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}
	respondJSON(w, http.StatusOK, successResponse(nil, "Location access revoked"))
}

// -----------------------------------------------------------------------------
// Helper functions (package-level)
// -----------------------------------------------------------------------------

// respondJSON writes a JSON response with the given status code and payload.
func respondJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}

// respondError writes a JSON error response.
func respondError(w http.ResponseWriter, statusCode int, message string) {
	respondJSON(w, statusCode, errorResponse(nil, message))
}

// mapServiceError converts service-layer errors to HTTP status and message.
func mapServiceError(err error) (int, string) {
	if err == nil {
		return http.StatusOK, ""
	}
	switch {
	case errors.Is(err, customErrors.ErrNotFound):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, customErrors.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, customErrors.ErrDuplicate):
		return http.StatusConflict, err.Error()
	case errors.Is(err, customErrors.ErrConflict):
		return http.StatusConflict, err.Error()
	case errors.Is(err, customErrors.ErrPermissionDenied):
		return http.StatusForbidden, err.Error()
	case errors.Is(err, customErrors.ErrUnauthorized):
		return http.StatusUnauthorized, err.Error()
	case errors.Is(err, customErrors.ErrInternal):
		return http.StatusInternalServerError, "internal server error"
	default:
		errMsg := err.Error()
		if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "does not exist") {
			return http.StatusNotFound, errMsg
		}
		if strings.Contains(errMsg, "permission") || strings.Contains(errMsg, "Permission") {
			return http.StatusForbidden, errMsg
		}
		if strings.Contains(errMsg, "invalid") || strings.Contains(errMsg, "Invalid") {
			return http.StatusBadRequest, errMsg
		}
		if strings.Contains(errMsg, "duplicate") || strings.Contains(errMsg, "already exists") {
			return http.StatusConflict, errMsg
		}
		return http.StatusInternalServerError, "internal server error"
	}
}

// getUserIDFromContext extracts the user UUID from the request context.
func getUserIDFromContext(ctx context.Context) (uuid.UUID, error) {
	raw := ctx.Value("user_id")
	if raw == nil {
		return uuid.Nil, customErrors.ErrUnauthorized
	}
	switch v := raw.(type) {
	case uuid.UUID:
		return v, nil
	case string:
		return uuid.Parse(v)
	default:
		return uuid.Nil, customErrors.ErrInvalidInput
	}
}

// GetMyLocations GET /api/v1/companies/{companyID}/me/locations
//
// Self‑service endpoint. Returns the locations the *currently authenticated*
// user can access, along with their primary location and scope.
//
// IMPORTANT: This route must be registered OUTSIDE LocationValidationMiddleware,
// otherwise the client can never discover a valid X-Location-ID.
func (h *LocationHandler) GetMyLocations(w http.ResponseWriter, r *http.Request) {
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	result, err := h.locationService.GetMyLocations(r.Context(), companyID, userID)
	if err != nil {
		status, msg := mapServiceError(err)
		respondError(w, status, msg)
		return
	}

	respondJSON(w, http.StatusOK, successResponse(result, "Your locations retrieved"))
}
