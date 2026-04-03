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

	"auth-service/internal/academics/repository"
	"auth-service/internal/academics/service"
)

// TimetableHandler handles timetable-related endpoints.
type TimetableHandler struct {
	timetableService service.TimetableService
	logger           *zap.Logger
}

// NewTimetableHandler creates a new TimetableHandler.
func NewTimetableHandler(timetableService service.TimetableService, logger *zap.Logger) *TimetableHandler {
	return &TimetableHandler{
		timetableService: timetableService,
		logger:           logger.Named("timetable_handler"),
	}
}

// ---------------------- Timetable CRUD --------------------------------------

// CreateTimetable handles POST /api/v1/companies/{companyID}/timetables
func (h *TimetableHandler) CreateTimetable(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "timetable:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateTimetableRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate required fields
	if req.AcademicYearID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "academic_year_id is required")
		return
	}
	if req.TermID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "term_id is required")
		return
	}
	if req.SectionID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "section_id is required")
		return
	}
	if req.EffectiveFrom.IsZero() {
		h.respondWithError(w, http.StatusBadRequest, "effective_from is required")
		return
	}

	req.CreatedBy = &userID
	req.UpdatedBy = &userID

	idempotencyKey := r.Header.Get("Idempotency-Key") // optional

	timetable, err := h.timetableService.CreateTimetable(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to create timetable",
			zap.String("section_id", req.SectionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    timetable,
		"message": "Timetable created successfully",
	})
}

// GetTimetable handles GET /api/v1/companies/{companyID}/timetables/{timetableID}
func (h *TimetableHandler) GetTimetable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	timetableIDStr := chi.URLParam(r, "timetableID")
	timetableID, err := uuid.Parse(timetableIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid timetable ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "timetable:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	timetable, err := h.timetableService.GetTimetableByID(ctx, timetableID)
	if err != nil {
		h.logger.Error("Failed to get timetable",
			zap.String("timetable_id", timetableID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    timetable,
	})
}

// ListTimetables handles GET /api/v1/companies/{companyID}/timetables
func (h *TimetableHandler) ListTimetables(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "timetable:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Build filter
	filter := repository.TimetableFilter{}
	if academicYearIDStr := r.URL.Query().Get("academic_year_id"); academicYearIDStr != "" {
		if ayID, err := uuid.Parse(academicYearIDStr); err == nil {
			filter.AcademicYearID = &ayID
		}
	}
	if termIDStr := r.URL.Query().Get("term_id"); termIDStr != "" {
		if termID, err := uuid.Parse(termIDStr); err == nil {
			filter.TermID = &termID
		}
	}
	if sectionIDStr := r.URL.Query().Get("section_id"); sectionIDStr != "" {
		if secID, err := uuid.Parse(sectionIDStr); err == nil {
			filter.SectionID = &secID
		}
	}
	if isActiveStr := r.URL.Query().Get("is_active"); isActiveStr != "" {
		isActive, _ := strconv.ParseBool(isActiveStr)
		filter.IsActive = &isActive
	}
	if effectiveFrom := r.URL.Query().Get("effective_from"); effectiveFrom != "" {
		if t, err := time.Parse(time.RFC3339, effectiveFrom); err == nil {
			filter.EffectiveFrom = &t
		}
	}
	if effectiveTo := r.URL.Query().Get("effective_to"); effectiveTo != "" {
		if t, err := time.Parse(time.RFC3339, effectiveTo); err == nil {
			filter.EffectiveTo = &t
		}
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

	timetables, err := h.timetableService.ListTimetables(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list timetables",
			zap.Any("filter", filter),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list timetables")
		return
	}

	// Note: Count method not in interface, but we can skip total for now.
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"timetables": timetables,
			"limit":      limit,
			"offset":     offset,
		},
	})
}

// UpdateTimetable handles PUT /api/v1/companies/{companyID}/timetables/{timetableID}
func (h *TimetableHandler) UpdateTimetable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	timetableIDStr := chi.URLParam(r, "timetableID")
	timetableID, err := uuid.Parse(timetableIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid timetable ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "timetable:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateTimetableRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.TimetableID = timetableID
	req.UpdatedBy = &userID

	timetable, err := h.timetableService.UpdateTimetable(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update timetable",
			zap.String("timetable_id", timetableID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    timetable,
		"message": "Timetable updated successfully",
	})
}

// DeleteTimetable handles DELETE /api/v1/companies/{companyID}/timetables/{timetableID}
func (h *TimetableHandler) DeleteTimetable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	timetableIDStr := chi.URLParam(r, "timetableID")
	timetableID, err := uuid.Parse(timetableIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid timetable ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "timetable:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.timetableService.DeleteTimetable(ctx, timetableID, &userID)
	if err != nil {
		h.logger.Error("Failed to delete timetable",
			zap.String("timetable_id", timetableID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Timetable deleted successfully",
	})
}

// GetActiveTimetableForSection handles GET /api/v1/companies/{companyID}/timetables/active?term_id=...&section_id=...
func (h *TimetableHandler) GetActiveTimetableForSection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	termIDStr := r.URL.Query().Get("term_id")
	if termIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "term_id query param is required")
		return
	}
	termID, err := uuid.Parse(termIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid term_id")
		return
	}

	sectionIDStr := r.URL.Query().Get("section_id")
	if sectionIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "section_id query param is required")
		return
	}
	sectionID, err := uuid.Parse(sectionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid section_id")
		return
	}

	if !h.hasPermission(ctx, companyID, "timetable:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	timetable, err := h.timetableService.GetActiveTimetableForSection(ctx, termID, sectionID)
	if err != nil {
		h.logger.Error("Failed to get active timetable",
			zap.String("term_id", termID.String()),
			zap.String("section_id", sectionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    timetable,
	})
}

// ---------------------- Slot Operations ------------------------------------

// AddSlot handles POST /api/v1/companies/{companyID}/timetables/{timetableID}/slots
func (h *TimetableHandler) AddSlot(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	timetableIDStr := chi.URLParam(r, "timetableID")
	timetableID, err := uuid.Parse(timetableIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid timetable ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "timetable:manage_slots") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.AddSlotRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.TimetableID = timetableID
	req.CreatedBy = &userID

	slot, err := h.timetableService.AddSlot(ctx, req)
	if err != nil {
		h.logger.Error("Failed to add slot",
			zap.String("timetable_id", timetableID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    slot,
		"message": "Slot added successfully",
	})
}

// UpdateSlot handles PUT /api/v1/companies/{companyID}/slots/{slotID}
func (h *TimetableHandler) UpdateSlot(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	slotIDStr := chi.URLParam(r, "slotID")
	slotID, err := uuid.Parse(slotIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid slot ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "timetable:manage_slots") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateSlotRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.SlotID = slotID
	req.UpdatedBy = &userID

	slot, err := h.timetableService.UpdateSlot(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update slot",
			zap.String("slot_id", slotID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    slot,
		"message": "Slot updated successfully",
	})
}

// RemoveSlot handles DELETE /api/v1/companies/{companyID}/slots/{slotID}
func (h *TimetableHandler) RemoveSlot(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	slotIDStr := chi.URLParam(r, "slotID")
	slotID, err := uuid.Parse(slotIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid slot ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "timetable:manage_slots") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.timetableService.RemoveSlot(ctx, slotID, &userID)
	if err != nil {
		h.logger.Error("Failed to remove slot",
			zap.String("slot_id", slotID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Slot removed successfully",
	})
}

// GetSlotsForTimetable handles GET /api/v1/companies/{companyID}/timetables/{timetableID}/slots
func (h *TimetableHandler) GetSlotsForTimetable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	timetableIDStr := chi.URLParam(r, "timetableID")
	timetableID, err := uuid.Parse(timetableIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid timetable ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "timetable:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	slots, err := h.timetableService.GetSlotsForTimetable(ctx, timetableID)
	if err != nil {
		h.logger.Error("Failed to get slots for timetable",
			zap.String("timetable_id", timetableID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get slots")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    slots,
	})
}

// ---------------------- Entry Operations ------------------------------------

// AddEntry handles POST /api/v1/companies/{companyID}/slots/{slotID}/entries
func (h *TimetableHandler) AddEntry(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	slotIDStr := chi.URLParam(r, "slotID")
	slotID, err := uuid.Parse(slotIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid slot ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "timetable:manage_entries") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.AddEntryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.SlotID = slotID
	req.CreatedBy = &userID

	entry, err := h.timetableService.AddEntry(ctx, req)
	if err != nil {
		h.logger.Error("Failed to add entry",
			zap.String("slot_id", slotID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    entry,
		"message": "Entry added successfully",
	})
}

// UpdateEntry handles PUT /api/v1/companies/{companyID}/entries/{entryID}
func (h *TimetableHandler) UpdateEntry(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	entryIDStr := chi.URLParam(r, "entryID")
	entryID, err := uuid.Parse(entryIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entry ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "timetable:manage_entries") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateEntryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.EntryID = entryID
	req.UpdatedBy = &userID

	entry, err := h.timetableService.UpdateEntry(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update entry",
			zap.String("entry_id", entryID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    entry,
		"message": "Entry updated successfully",
	})
}

// RemoveEntry handles DELETE /api/v1/companies/{companyID}/entries/{entryID}
func (h *TimetableHandler) RemoveEntry(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	entryIDStr := chi.URLParam(r, "entryID")
	entryID, err := uuid.Parse(entryIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entry ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "timetable:manage_entries") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.timetableService.RemoveEntry(ctx, entryID, &userID)
	if err != nil {
		h.logger.Error("Failed to remove entry",
			zap.String("entry_id", entryID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Entry removed successfully",
	})
}

// GetEntriesForSlot handles GET /api/v1/companies/{companyID}/slots/{slotID}/entries
func (h *TimetableHandler) GetEntriesForSlot(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	slotIDStr := chi.URLParam(r, "slotID")
	slotID, err := uuid.Parse(slotIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid slot ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "timetable:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	entries, err := h.timetableService.GetEntriesForSlot(ctx, slotID)
	if err != nil {
		h.logger.Error("Failed to get entries for slot",
			zap.String("slot_id", slotID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get entries")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    entries,
	})
}

// ---------------------- Change Tracking -------------------------------------

// AddChange handles POST /api/v1/companies/{companyID}/entries/{entryID}/changes
func (h *TimetableHandler) AddChange(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	entryIDStr := chi.URLParam(r, "entryID")
	entryID, err := uuid.Parse(entryIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entry ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "timetable:manage_changes") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.AddChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.EntryID = entryID
	req.CreatedBy = &userID

	change, err := h.timetableService.AddChange(ctx, req)
	if err != nil {
		h.logger.Error("Failed to add change",
			zap.String("entry_id", entryID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    change,
		"message": "Change recorded successfully",
	})
}

// GetChangesForEntry handles GET /api/v1/companies/{companyID}/entries/{entryID}/changes
func (h *TimetableHandler) GetChangesForEntry(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	entryIDStr := chi.URLParam(r, "entryID")
	entryID, err := uuid.Parse(entryIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entry ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "timetable:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	changes, err := h.timetableService.GetChangesForEntry(ctx, entryID)
	if err != nil {
		h.logger.Error("Failed to get changes for entry",
			zap.String("entry_id", entryID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get changes")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    changes,
	})
}

// ---------------------- Helper Methods -------------------------------------

func (h *TimetableHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	// Placeholder – implement actual permission check
	return true
}

func (h *TimetableHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *TimetableHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
