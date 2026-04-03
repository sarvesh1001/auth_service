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

// TermHandler handles term-related endpoints.
type TermHandler struct {
	termService service.TermService
	logger      *zap.Logger
}

// NewTermHandler creates a new TermHandler.
func NewTermHandler(termService service.TermService, logger *zap.Logger) *TermHandler {
	return &TermHandler{
		termService: termService,
		logger:      logger.Named("term_handler"),
	}
}

// ---------------------- Request/Response Types -----------------------------

// CreateTermRequest is the HTTP request body for creating a term.
type CreateTermRequest struct {
	Name      string `json:"name"`
	StartDate string `json:"start_date"` // ISO 8601 date
	EndDate   string `json:"end_date"`
	IsCurrent bool   `json:"is_current"`
}

// UpdateTermRequest is the HTTP request body for updating a term.
type UpdateTermRequest struct {
	Name      string `json:"name"`
	StartDate string `json:"start_date"`
	EndDate   string `json:"end_date"`
	IsCurrent bool   `json:"is_current"`
}

// ---------------------- Handlers --------------------------------------------

// Create handles POST /api/v1/companies/{companyID}/academic-years/{academicYearID}/terms
// (or simply /api/v1/companies/{companyID}/terms with academic_year_id in body)
// We'll assume academic_year_id is in the URL for clarity.
func (h *TermHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearIDStr := chi.URLParam(r, "academicYearID")
	academicYearID, err := uuid.Parse(academicYearIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "term:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req CreateTermRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Parse dates
	startDate, err := time.Parse("2006-01-02", req.StartDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid start_date format (use YYYY-MM-DD)")
		return
	}
	endDate, err := time.Parse("2006-01-02", req.EndDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid end_date format (use YYYY-MM-DD)")
		return
	}

	// Build service request
	createReq := service.CreateTermRequest{
		AcademicYearID: academicYearID,
		Name:           req.Name,
		StartDate:      startDate,
		EndDate:        endDate,
		IsCurrent:      req.IsCurrent,
		CreatedBy:      &userID,
		UpdatedBy:      &userID,
	}

	term, err := h.termService.Create(ctx, createReq)
	if err != nil {
		h.logger.Error("Failed to create term",
			zap.String("academic_year_id", academicYearID.String()),
			zap.String("name", req.Name),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    term,
		"message": "Term created successfully",
	})
}

// BulkCreate handles POST /api/v1/companies/{companyID}/academic-years/{academicYearID}/terms/bulk
func (h *TermHandler) BulkCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearIDStr := chi.URLParam(r, "academicYearID")
	academicYearID, err := uuid.Parse(academicYearIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "term:bulk_create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var reqs []CreateTermRequest
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(reqs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "empty batch")
		return
	}

	// Convert to service requests
	createReqs := make([]service.CreateTermRequest, len(reqs))
	for i, r := range reqs {
		startDate, err := time.Parse("2006-01-02", r.StartDate)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid start_date format for term "+r.Name)
			return
		}
		endDate, err := time.Parse("2006-01-02", r.EndDate)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid end_date format for term "+r.Name)
			return
		}
		createReqs[i] = service.CreateTermRequest{
			AcademicYearID: academicYearID,
			Name:           r.Name,
			StartDate:      startDate,
			EndDate:        endDate,
			IsCurrent:      r.IsCurrent,
			CreatedBy:      &userID,
			UpdatedBy:      &userID,
		}
	}

	terms, err := h.termService.BulkCreate(ctx, createReqs)
	if err != nil {
		h.logger.Error("Failed to bulk create terms",
			zap.Int("count", len(reqs)),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    terms,
		"message": "Terms created successfully",
	})
}

// GetByID handles GET /api/v1/companies/{companyID}/terms/{termID}
func (h *TermHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	termIDStr := chi.URLParam(r, "termID")
	termID, err := uuid.Parse(termIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid term ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "term:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	term, err := h.termService.GetByID(ctx, termID)
	if err != nil {
		h.logger.Error("Failed to get term",
			zap.String("term_id", termID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    term,
	})
}

// GetCurrent handles GET /api/v1/companies/{companyID}/academic-years/{academicYearID}/current-term
func (h *TermHandler) GetCurrent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearIDStr := chi.URLParam(r, "academicYearID")
	academicYearID, err := uuid.Parse(academicYearIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "term:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	term, err := h.termService.GetCurrent(ctx, academicYearID)
	if err != nil {
		h.logger.Error("Failed to get current term",
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    term,
	})
}

// List handles GET /api/v1/companies/{companyID}/terms with query params
func (h *TermHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "term:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Build filter – only use fields that exist in TermFilter
	filter := repository.TermFilter{}
	if academicYearIDStr := r.URL.Query().Get("academic_year_id"); academicYearIDStr != "" {
		if ayID, err := uuid.Parse(academicYearIDStr); err == nil {
			filter.AcademicYearID = ayID // direct assignment (value, not pointer)
		}
	}
	if isCurrentStr := r.URL.Query().Get("is_current"); isCurrentStr != "" {
		isCurrent, _ := strconv.ParseBool(isCurrentStr)
		filter.IsCurrent = &isCurrent // pointer field
	}
	// Note: name and date-range filters were removed because they don't exist in TermFilter.
	// If your TermFilter has them under different names (e.g., StartDateFrom, StartDateTo),
	// you can add them back here.

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
		sortField = "start_date"
	}
	sortDirection := r.URL.Query().Get("sort_direction")
	if sortDirection == "" {
		sortDirection = "ASC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDirection}

	terms, err := h.termService.List(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list terms",
			zap.Any("filter", filter),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list terms")
		return
	}

	count, err := h.termService.Count(ctx, filter)
	if err != nil {
		h.logger.Error("Failed to count terms", zap.Error(err))
		// non-fatal
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"terms":  terms,
			"total":  count,
			"limit":  limit,
			"offset": offset,
		},
	})
}

// Update handles PUT /api/v1/companies/{companyID}/terms/{termID}
func (h *TermHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	termIDStr := chi.URLParam(r, "termID")
	termID, err := uuid.Parse(termIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid term ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "term:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req UpdateTermRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Parse dates
	startDate, err := time.Parse("2006-01-02", req.StartDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid start_date format (use YYYY-MM-DD)")
		return
	}
	endDate, err := time.Parse("2006-01-02", req.EndDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid end_date format (use YYYY-MM-DD)")
		return
	}

	updateReq := service.UpdateTermRequest{
		TermID:    termID,
		Name:      req.Name,
		StartDate: startDate,
		EndDate:   endDate,
		IsCurrent: req.IsCurrent,
		UpdatedBy: &userID,
	}

	term, err := h.termService.Update(ctx, updateReq)
	if err != nil {
		h.logger.Error("Failed to update term",
			zap.String("term_id", termID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    term,
		"message": "Term updated successfully",
	})
}

// SetCurrent handles PATCH /api/v1/companies/{companyID}/terms/{termID}/set-current
func (h *TermHandler) SetCurrent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	termIDStr := chi.URLParam(r, "termID")
	termID, err := uuid.Parse(termIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid term ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "term:set_current") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// The academic year ID is derived from the term; we can get it from the term first,
	// but the service requires academicYearID. Let's fetch the term to get its academic year.
	term, err := h.termService.GetByID(ctx, termID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "term not found")
		return
	}

	err = h.termService.SetCurrent(ctx, term.AcademicYearID, termID, &userID)
	if err != nil {
		h.logger.Error("Failed to set current term",
			zap.String("term_id", termID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Term set as current successfully",
	})
}

// Delete handles DELETE /api/v1/companies/{companyID}/terms/{termID}
func (h *TermHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	termIDStr := chi.URLParam(r, "termID")
	termID, err := uuid.Parse(termIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid term ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "term:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.termService.Delete(ctx, termID, &userID)
	if err != nil {
		h.logger.Error("Failed to delete term",
			zap.String("term_id", termID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Term deleted successfully",
	})
}

// ---------------------- Helper Methods -------------------------------------

func (h *TermHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	// Placeholder – implement actual permission check
	return true
}

func (h *TermHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *TermHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
