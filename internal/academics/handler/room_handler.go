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

type RoomHandler struct {
	roomService service.RoomService
	logger      *zap.Logger
}

func NewRoomHandler(roomService service.RoomService, logger *zap.Logger) *RoomHandler {
	return &RoomHandler{
		roomService: roomService,
		logger:      logger.Named("room_handler"),
	}
}

// Create handles POST /api/v1/companies/{companyID}/rooms
func (h *RoomHandler) Create(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "room:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateRoomRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Set company ID from URL
	req.CompanyID = companyID

	// Set created/updated by from authenticated user
	req.CreatedBy = &userID
	req.UpdatedBy = &userID

	// Get idempotency key from header if present
	idempotencyKey := r.Header.Get("Idempotency-Key")

	room, err := h.roomService.Create(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to create room",
			zap.String("company_id", companyID.String()),
			zap.String("room_code", req.RoomCode),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    room,
		"message": "Room created successfully",
	})
}

// BulkCreate handles POST /api/v1/companies/{companyID}/rooms/bulk
func (h *RoomHandler) BulkCreate(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "room:bulk_create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var reqs []service.CreateRoomRequest
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(reqs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "empty batch")
		return
	}

	// Set metadata
	for i := range reqs {
		reqs[i].CompanyID = companyID
		reqs[i].CreatedBy = &userID
		reqs[i].UpdatedBy = &userID
	}

	// ✅ FIX: get idempotency key
	idempotencyKey := r.Header.Get("X-Idempotency-Key")

	rooms, err := h.roomService.BulkCreate(ctx, reqs, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to bulk create rooms",
			zap.Int("batch_size", len(reqs)),
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    rooms,
		"message": "Rooms created successfully",
	})
}

// GetByID handles GET /api/v1/companies/{companyID}/rooms/{roomID}
func (h *RoomHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	roomIDStr := chi.URLParam(r, "roomID")
	roomID, err := uuid.Parse(roomIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid room ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "room:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	room, err := h.roomService.GetByID(ctx, roomID)
	if err != nil {
		h.logger.Error("Failed to get room",
			zap.String("room_id", roomID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    room,
	})
}

// GetByCode handles GET /api/v1/companies/{companyID}/rooms/by-code/{code}
func (h *RoomHandler) GetByCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	code := chi.URLParam(r, "code")
	if code == "" {
		h.respondWithError(w, http.StatusBadRequest, "room code is required")
		return
	}

	if !h.hasPermission(ctx, companyID, "room:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	room, err := h.roomService.GetByCode(ctx, companyID, code)
	if err != nil {
		h.logger.Error("Failed to get room by code",
			zap.String("company_id", companyID.String()),
			zap.String("code", code),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    room,
	})
}

// List handles GET /api/v1/companies/{companyID}/rooms with query params
func (h *RoomHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "room:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Build filter
	filter := repository.RoomFilter{
		CompanyID: companyID, // directly assign uuid.UUID (not pointer)
	}
	if building := r.URL.Query().Get("building"); building != "" {
		filter.Building = building // string, not pointer
	}
	if isActiveStr := r.URL.Query().Get("is_active"); isActiveStr != "" {
		isActive, err := strconv.ParseBool(isActiveStr)
		if err == nil {
			filter.IsActive = &isActive // assuming IsActive is *bool
		}
	}
	if roomCode := r.URL.Query().Get("room_code"); roomCode != "" {
		filter.RoomCode = roomCode // string, not pointer
	}
	if search := r.URL.Query().Get("search"); search != "" {
		filter.Search = search // string, not pointer
	}

	// Pagination
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	// Sorting
	sortField := r.URL.Query().Get("sort_field")
	if sortField == "" {
		sortField = "created_at"
	}
	sortDirection := r.URL.Query().Get("sort_direction")
	if sortDirection == "" {
		sortDirection = "DESC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDirection}

	rooms, err := h.roomService.List(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list rooms",
			zap.Any("filter", filter),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list rooms")
		return
	}

	count, err := h.roomService.Count(ctx, filter)
	if err != nil {
		h.logger.Error("Failed to count rooms", zap.Error(err))
		// non-fatal
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"rooms":  rooms,
			"total":  count,
			"limit":  limit,
			"offset": offset,
		},
	})
}

// Update handles PUT /api/v1/companies/{companyID}/rooms/{roomID}
func (h *RoomHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	roomIDStr := chi.URLParam(r, "roomID")
	roomID, err := uuid.Parse(roomIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid room ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "room:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateRoomRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.RoomID = roomID
	req.UpdatedBy = &userID

	// ✅ FIX
	idempotencyKey := r.Header.Get("X-Idempotency-Key")

	room, err := h.roomService.Update(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to update room",
			zap.String("room_id", roomID.String()),
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    room,
		"message": "Room updated successfully",
	})
}

// Delete handles DELETE /api/v1/companies/{companyID}/rooms/{roomID}
func (h *RoomHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	roomIDStr := chi.URLParam(r, "roomID")
	roomID, err := uuid.Parse(roomIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid room ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "room:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// ✅ FIX
	idempotencyKey := r.Header.Get("X-Idempotency-Key")

	err = h.roomService.Delete(ctx, roomID, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to delete room",
			zap.String("room_id", roomID.String()),
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Room deleted successfully",
	})
}

// Activate handles PATCH /api/v1/companies/{companyID}/rooms/{roomID}/activate
func (h *RoomHandler) Activate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	roomIDStr := chi.URLParam(r, "roomID")
	roomID, err := uuid.Parse(roomIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid room ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "room:activate") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// ✅ FIX: idempotency key
	idempotencyKey := r.Header.Get("X-Idempotency-Key")

	err = h.roomService.Activate(ctx, roomID, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to activate room",
			zap.String("room_id", roomID.String()),
			zap.String("company_id", companyID.String()),
			zap.String("idempotency_key", idempotencyKey),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Room activated successfully",
	})
}

// Deactivate handles PATCH /api/v1/companies/{companyID}/rooms/{roomID}/deactivate
func (h *RoomHandler) Deactivate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	roomIDStr := chi.URLParam(r, "roomID")
	roomID, err := uuid.Parse(roomIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid room ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "room:deactivate") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// ✅ FIX: idempotency key
	idempotencyKey := r.Header.Get("X-Idempotency-Key")

	err = h.roomService.Deactivate(ctx, roomID, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to deactivate room",
			zap.String("room_id", roomID.String()),
			zap.String("company_id", companyID.String()),
			zap.String("idempotency_key", idempotencyKey),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Room deactivated successfully",
	})
}

// ListByBuilding handles GET /api/v1/companies/{companyID}/rooms/by-building/{building}
func (h *RoomHandler) ListByBuilding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	building := chi.URLParam(r, "building")
	if building == "" {
		h.respondWithError(w, http.StatusBadRequest, "building name is required")
		return
	}

	if !h.hasPermission(ctx, companyID, "room:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	rooms, err := h.roomService.ListByBuilding(ctx, companyID, building)
	if err != nil {
		h.logger.Error("Failed to list rooms by building",
			zap.String("company_id", companyID.String()),
			zap.String("building", building),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list rooms")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    rooms,
	})
}

// Helper methods
func (h *RoomHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	// Placeholder – implement actual permission check
	return true
}

func (h *RoomHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *RoomHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
