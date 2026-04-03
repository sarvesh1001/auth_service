package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/repository"
	"auth-service/internal/academics/service"
)

type TransportHandler struct {
	transportService service.TransportService
	logger           *zap.Logger
}

func NewTransportHandler(transportService service.TransportService, logger *zap.Logger) *TransportHandler {
	return &TransportHandler{
		transportService: transportService,
		logger:           logger.Named("transport_handler"),
	}
}

// ---------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------

func (h *TransportHandler) CreateRoute(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "transport:route:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateTransportRouteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.CompanyID = companyID
	req.CreatedBy = &userID
	req.UpdatedBy = &userID

	idempotencyKey := r.Header.Get("Idempotency-Key")

	route, err := h.transportService.CreateRoute(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to create transport route",
			zap.String("company_id", companyID.String()),
			zap.String("route_name", req.RouteName),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    route,
		"message": "Transport route created successfully",
	})
}

func (h *TransportHandler) GetRouteByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	routeIDStr := chi.URLParam(r, "routeID")
	routeID, err := uuid.Parse(routeIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid route ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "transport:route:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	route, err := h.transportService.GetRouteByID(ctx, routeID)
	if err != nil {
		h.logger.Error("Failed to get route",
			zap.String("route_id", routeID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    route,
	})
}

func (h *TransportHandler) UpdateRoute(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	routeIDStr := chi.URLParam(r, "routeID")
	routeID, err := uuid.Parse(routeIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid route ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "transport:route:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateTransportRouteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.RouteID = routeID
	req.UpdatedBy = &userID

	route, err := h.transportService.UpdateRoute(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update route",
			zap.String("route_id", routeID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    route,
		"message": "Transport route updated successfully",
	})
}

func (h *TransportHandler) DeleteRoute(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	routeIDStr := chi.URLParam(r, "routeID")
	routeID, err := uuid.Parse(routeIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid route ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "transport:route:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.transportService.DeleteRoute(ctx, routeID, &userID)
	if err != nil {
		h.logger.Error("Failed to delete route",
			zap.String("route_id", routeID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Transport route deleted successfully",
	})
}

// ---------------------------------------------------------------------
// Stops (under routes)
// ---------------------------------------------------------------------

func (h *TransportHandler) CreateStop(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	routeIDStr := chi.URLParam(r, "routeID")
	routeID, err := uuid.Parse(routeIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid route ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "transport:stop:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateTransportStopRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.RouteID = routeID
	req.CreatedBy = &userID
	req.UpdatedBy = &userID

	idempotencyKey := r.Header.Get("Idempotency-Key")

	stop, err := h.transportService.CreateStop(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to create transport stop",
			zap.String("route_id", routeID.String()),
			zap.String("stop_name", req.StopName),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    stop,
		"message": "Transport stop created successfully",
	})
}

func (h *TransportHandler) GetStopByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	stopIDStr := chi.URLParam(r, "stopID")
	stopID, err := uuid.Parse(stopIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid stop ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "transport:stop:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	stop, err := h.transportService.GetStopByID(ctx, stopID)
	if err != nil {
		h.logger.Error("Failed to get stop",
			zap.String("stop_id", stopID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    stop,
	})
}

func (h *TransportHandler) UpdateStop(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	stopIDStr := chi.URLParam(r, "stopID")
	stopID, err := uuid.Parse(stopIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid stop ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "transport:stop:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateTransportStopRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.StopID = stopID
	req.UpdatedBy = &userID

	stop, err := h.transportService.UpdateStop(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update stop",
			zap.String("stop_id", stopID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    stop,
		"message": "Transport stop updated successfully",
	})
}

func (h *TransportHandler) DeleteStop(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	stopIDStr := chi.URLParam(r, "stopID")
	stopID, err := uuid.Parse(stopIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid stop ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "transport:stop:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.transportService.DeleteStop(ctx, stopID)
	if err != nil {
		h.logger.Error("Failed to delete stop",
			zap.String("stop_id", stopID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Transport stop deleted successfully",
	})
}

// ---------------------------------------------------------------------
// Vehicles
// ---------------------------------------------------------------------

func (h *TransportHandler) CreateVehicle(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "transport:vehicle:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateTransportVehicleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.CompanyID = companyID
	req.CreatedBy = &userID
	req.UpdatedBy = &userID

	idempotencyKey := r.Header.Get("Idempotency-Key")

	vehicle, err := h.transportService.CreateVehicle(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to create transport vehicle",
			zap.String("company_id", companyID.String()),
			zap.String("vehicle_no", req.VehicleNo),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    vehicle,
		"message": "Transport vehicle created successfully",
	})
}

func (h *TransportHandler) GetVehicleByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	vehicleIDStr := chi.URLParam(r, "vehicleID")
	vehicleID, err := uuid.Parse(vehicleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid vehicle ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "transport:vehicle:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	vehicle, err := h.transportService.GetVehicleByID(ctx, vehicleID)
	if err != nil {
		h.logger.Error("Failed to get vehicle",
			zap.String("vehicle_id", vehicleID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    vehicle,
	})
}

func (h *TransportHandler) UpdateVehicle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	vehicleIDStr := chi.URLParam(r, "vehicleID")
	vehicleID, err := uuid.Parse(vehicleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid vehicle ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "transport:vehicle:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateTransportVehicleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.VehicleID = vehicleID
	req.UpdatedBy = &userID

	vehicle, err := h.transportService.UpdateVehicle(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update vehicle",
			zap.String("vehicle_id", vehicleID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    vehicle,
		"message": "Transport vehicle updated successfully",
	})
}

func (h *TransportHandler) DeleteVehicle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	vehicleIDStr := chi.URLParam(r, "vehicleID")
	vehicleID, err := uuid.Parse(vehicleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid vehicle ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "transport:vehicle:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.transportService.DeleteVehicle(ctx, vehicleID, &userID)
	if err != nil {
		h.logger.Error("Failed to delete vehicle",
			zap.String("vehicle_id", vehicleID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Transport vehicle deleted successfully",
	})
}

// ---------------------------------------------------------------------
// Driver Assignments
// ---------------------------------------------------------------------

func (h *TransportHandler) CreateDriverAssignment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	vehicleIDStr := chi.URLParam(r, "vehicleID")
	vehicleID, err := uuid.Parse(vehicleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid vehicle ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "transport:driver:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateDriverAssignmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.VehicleID = vehicleID
	req.CreatedBy = &userID
	req.UpdatedBy = &userID

	idempotencyKey := r.Header.Get("Idempotency-Key")

	assignment, err := h.transportService.CreateDriverAssignment(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to create driver assignment",
			zap.String("vehicle_id", vehicleID.String()),
			zap.String("driver_name", req.DriverName),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    assignment,
		"message": "Driver assignment created successfully",
	})
}

func (h *TransportHandler) GetDriverAssignmentByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	assignmentIDStr := chi.URLParam(r, "assignmentID")
	assignmentID, err := uuid.Parse(assignmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid assignment ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "transport:driver:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	assignment, err := h.transportService.GetDriverAssignmentByID(ctx, assignmentID)
	if err != nil {
		h.logger.Error("Failed to get driver assignment",
			zap.String("assignment_id", assignmentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    assignment,
	})
}

func (h *TransportHandler) UpdateDriverAssignment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	assignmentIDStr := chi.URLParam(r, "assignmentID")
	assignmentID, err := uuid.Parse(assignmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid assignment ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "transport:driver:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateDriverAssignmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.AssignmentID = assignmentID
	req.UpdatedBy = &userID

	assignment, err := h.transportService.UpdateDriverAssignment(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update driver assignment",
			zap.String("assignment_id", assignmentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    assignment,
		"message": "Driver assignment updated successfully",
	})
}

func (h *TransportHandler) DeleteDriverAssignment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	assignmentIDStr := chi.URLParam(r, "assignmentID")
	assignmentID, err := uuid.Parse(assignmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid assignment ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "transport:driver:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.transportService.DeleteDriverAssignment(ctx, assignmentID)
	if err != nil {
		h.logger.Error("Failed to delete driver assignment",
			zap.String("assignment_id", assignmentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Driver assignment deleted successfully",
	})
}

// ---------------------------------------------------------------------
// Student Assignments
// ---------------------------------------------------------------------

func (h *TransportHandler) CreateStudentAssignment(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "transport:student_assignment:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateStudentAssignmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.CreatedBy = &userID
	req.UpdatedBy = &userID

	idempotencyKey := r.Header.Get("Idempotency-Key")

	assignment, err := h.transportService.CreateStudentAssignment(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to create student transport assignment",
			zap.String("student_id", req.StudentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    assignment,
		"message": "Student transport assignment created successfully",
	})
}

func (h *TransportHandler) GetStudentAssignmentByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	assignmentIDStr := chi.URLParam(r, "assignmentID")
	assignmentID, err := uuid.Parse(assignmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid assignment ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "transport:student_assignment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	assignment, err := h.transportService.GetStudentAssignmentByID(ctx, assignmentID)
	if err != nil {
		h.logger.Error("Failed to get student assignment",
			zap.String("assignment_id", assignmentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    assignment,
	})
}

func (h *TransportHandler) UpdateStudentAssignment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	assignmentIDStr := chi.URLParam(r, "assignmentID")
	assignmentID, err := uuid.Parse(assignmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid assignment ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "transport:student_assignment:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateStudentAssignmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.AssignmentID = assignmentID
	req.UpdatedBy = &userID

	assignment, err := h.transportService.UpdateStudentAssignment(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update student assignment",
			zap.String("assignment_id", assignmentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    assignment,
		"message": "Student transport assignment updated successfully",
	})
}

func (h *TransportHandler) DeleteStudentAssignment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	assignmentIDStr := chi.URLParam(r, "assignmentID")
	assignmentID, err := uuid.Parse(assignmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid assignment ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "transport:student_assignment:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.transportService.DeleteStudentAssignment(ctx, assignmentID)
	if err != nil {
		h.logger.Error("Failed to delete student assignment",
			zap.String("assignment_id", assignmentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Student transport assignment deleted successfully",
	})
}

// ---------------------------------------------------------------------
// Helper methods
// ---------------------------------------------------------------------

func (h *TransportHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	// Placeholder – implement actual permission check
	return true
}

func (h *TransportHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *TransportHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

// ListRoutes handles GET /api/v1/companies/{companyID}/transport/routes
func (h *TransportHandler) ListRoutes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "transport:route:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	filter := repository.TransportRouteFilter{
		CompanyID: companyID,
	}
	// Remove name filter – field does not exist
	if active := r.URL.Query().Get("is_active"); active != "" {
		isActive := active == "true"
		filter.IsActive = &isActive
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	sortField := r.URL.Query().Get("sort_field")
	if sortField == "" {
		sortField = "created_at"
	}
	sortDir := r.URL.Query().Get("sort_direction")
	if sortDir == "" {
		sortDir = "DESC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDir}

	routes, err := h.transportService.ListRoutes(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list routes", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list routes")
		return
	}

	count, _ := h.transportService.CountRoutes(ctx, filter)

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"routes": routes,
			"total":  count,
			"limit":  limit,
			"offset": offset,
		},
	})
}

// ListStops handles GET /api/v1/companies/{companyID}/transport/stops
func (h *TransportHandler) ListStops(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "transport:stop:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	filter := repository.TransportStopFilter{}
	if routeIDStr := r.URL.Query().Get("route_id"); routeIDStr != "" {
		if routeID, err := uuid.Parse(routeIDStr); err == nil {
			filter.RouteID = routeID // direct value, not pointer
		}
	}
	// Remove name filter – field does not exist

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	sortField := r.URL.Query().Get("sort_field")
	if sortField == "" {
		sortField = "stop_order"
	}
	sortDir := r.URL.Query().Get("sort_direction")
	if sortDir == "" {
		sortDir = "ASC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDir}

	stops, err := h.transportService.ListStops(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list stops", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list stops")
		return
	}

	count, _ := h.transportService.CountStops(ctx, filter)

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"stops":  stops,
			"total":  count,
			"limit":  limit,
			"offset": offset,
		},
	})
}

// ListVehicles handles GET /api/v1/companies/{companyID}/transport/vehicles
func (h *TransportHandler) ListVehicles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "transport:vehicle:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	filter := repository.TransportVehicleFilter{
		CompanyID: companyID,
	}
	// Remove vehicle_no and vehicle_type – fields do not exist
	if active := r.URL.Query().Get("is_active"); active != "" {
		isActive := active == "true"
		filter.IsActive = &isActive
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	sortField := r.URL.Query().Get("sort_field")
	if sortField == "" {
		sortField = "created_at"
	}
	sortDir := r.URL.Query().Get("sort_direction")
	if sortDir == "" {
		sortDir = "DESC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDir}

	vehicles, err := h.transportService.ListVehicles(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list vehicles", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list vehicles")
		return
	}

	count, _ := h.transportService.CountVehicles(ctx, filter)

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"vehicles": vehicles,
			"total":    count,
			"limit":    limit,
			"offset":   offset,
		},
	})
}

// ListDriverAssignments handles GET /api/v1/companies/{companyID}/transport/driver-assignments
func (h *TransportHandler) ListDriverAssignments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "transport:driver:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	filter := repository.TransportDriverAssignmentFilter{}
	if vehicleIDStr := r.URL.Query().Get("vehicle_id"); vehicleIDStr != "" {
		if vehicleID, err := uuid.Parse(vehicleIDStr); err == nil {
			filter.VehicleID = vehicleID // direct value, not pointer
		}
	}
	if active := r.URL.Query().Get("is_active"); active != "" {
		isActive := active == "true"
		filter.IsActive = &isActive
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	sortField := r.URL.Query().Get("sort_field")
	if sortField == "" {
		sortField = "assignment_date"
	}
	sortDir := r.URL.Query().Get("sort_direction")
	if sortDir == "" {
		sortDir = "DESC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDir}

	assignments, err := h.transportService.ListDriverAssignments(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list driver assignments", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list driver assignments")
		return
	}

	count, _ := h.transportService.CountDriverAssignments(ctx, filter)

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"assignments": assignments,
			"total":       count,
			"limit":       limit,
			"offset":      offset,
		},
	})
}

// ListStudentAssignments handles GET /api/v1/companies/{companyID}/transport/student-assignments
func (h *TransportHandler) ListStudentAssignments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "transport:student_assignment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	filter := repository.StudentTransportAssignmentFilter{}
	if studentIDStr := r.URL.Query().Get("student_id"); studentIDStr != "" {
		if studentID, err := uuid.Parse(studentIDStr); err == nil {
			filter.StudentID = studentID // direct value
		}
	}
	if routeIDStr := r.URL.Query().Get("route_id"); routeIDStr != "" {
		if routeID, err := uuid.Parse(routeIDStr); err == nil {
			filter.RouteID = routeID // direct value
		}
	}
	if active := r.URL.Query().Get("is_active"); active != "" {
		isActive := active == "true"
		filter.IsActive = &isActive
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	sortField := r.URL.Query().Get("sort_field")
	if sortField == "" {
		sortField = "effective_from"
	}
	sortDir := r.URL.Query().Get("sort_direction")
	if sortDir == "" {
		sortDir = "DESC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDir}

	assignments, err := h.transportService.ListStudentAssignments(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list student assignments", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list student assignments")
		return
	}

	count, _ := h.transportService.CountStudentAssignments(ctx, filter)

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"assignments": assignments,
			"total":       count,
			"limit":       limit,
			"offset":      offset,
		},
	})
}
