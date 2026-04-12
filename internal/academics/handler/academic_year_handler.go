// FILE: ./handler/academic_year_handler.go

package handler

import (
	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/academics/service"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type AcademicYearHandler struct {
	academicYearService service.AcademicYearService
	logger              *zap.Logger
}

func NewAcademicYearHandler(academicYearService service.AcademicYearService, logger *zap.Logger) *AcademicYearHandler {
	return &AcademicYearHandler{
		academicYearService: academicYearService,
		logger:              logger.Named("academic_year_handler"),
	}
}

// ---------------------------------------------------------------------
// Local request DTOs (no created_by/updated_by – taken from token)
// ---------------------------------------------------------------------

type createAcademicYearRequest struct {
	Name      string    `json:"name"`
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`
	IsCurrent bool      `json:"is_current"`
}

type updateAcademicYearRequest struct {
	Name      string    `json:"name"`
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`
	IsCurrent bool      `json:"is_current"`
}

type updateDatesRequest struct {
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`
}

type setCurrentRequest struct {
	// empty – no fields needed
}

type validateOverlapRequest struct {
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`
}

// ---------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------

func (h *AcademicYearHandler) Create(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "academic_year:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req createAcademicYearRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	serviceReq := service.CreateAcademicYearRequest{
		CompanyID: companyID,
		Name:      req.Name,
		StartDate: req.StartDate,
		EndDate:   req.EndDate,
		IsCurrent: req.IsCurrent,
		CreatedBy: &userID,
		UpdatedBy: &userID,
	}

	ay, err := h.academicYearService.Create(ctx, serviceReq)
	if err != nil {
		h.logger.Error("failed to create academic year", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    ay,
		"message": "Academic year created successfully",
	})
}

func (h *AcademicYearHandler) BulkCreate(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "academic_year:bulk_create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var reqs []createAcademicYearRequest
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	serviceReqs := make([]service.CreateAcademicYearRequest, len(reqs))
	for i, r := range reqs {
		serviceReqs[i] = service.CreateAcademicYearRequest{
			CompanyID: companyID,
			Name:      r.Name,
			StartDate: r.StartDate,
			EndDate:   r.EndDate,
			IsCurrent: r.IsCurrent,
			CreatedBy: &userID,
			UpdatedBy: &userID,
		}
	}

	years, err := h.academicYearService.BulkCreate(ctx, serviceReqs)
	if err != nil {
		h.logger.Error("failed to bulk create academic years", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    years,
		"message": "Academic years created successfully",
	})
}

func (h *AcademicYearHandler) Upsert(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "academic_year:upsert") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req createAcademicYearRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	serviceReq := service.CreateAcademicYearRequest{
		CompanyID: companyID,
		Name:      req.Name,
		StartDate: req.StartDate,
		EndDate:   req.EndDate,
		IsCurrent: req.IsCurrent,
		CreatedBy: &userID,
		UpdatedBy: &userID,
	}

	ay, err := h.academicYearService.Upsert(ctx, serviceReq)
	if err != nil {
		h.logger.Error("failed to upsert academic year", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    ay,
		"message": "Academic year upserted successfully",
	})
}

func (h *AcademicYearHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "academic_year:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	ay, err := h.academicYearService.GetByID(ctx, id)
	if err != nil {
		h.logger.Error("failed to get academic year", zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	if ay.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "academic year does not belong to this company")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    ay,
	})
}

func (h *AcademicYearHandler) GetByName(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		h.respondWithError(w, http.StatusBadRequest, "name query parameter is required")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "academic_year:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	ay, err := h.academicYearService.GetByName(ctx, companyID, name)
	if err != nil {
		h.logger.Error("failed to get academic year by name", zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    ay,
	})
}

func (h *AcademicYearHandler) GetCurrent(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "academic_year:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	ay, err := h.academicYearService.GetCurrent(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get current academic year", zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    ay,
	})
}

func (h *AcademicYearHandler) List(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "academic_year:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	query := r.URL.Query()
	filter := repository.AcademicYearFilter{
		CompanyID: companyID,
	}
	if isCurrentStr := query.Get("is_current"); isCurrentStr != "" {
		isCurrent, _ := strconv.ParseBool(isCurrentStr)
		filter.IsCurrent = &isCurrent
	}

	pagination := repository.Pagination{
		Limit:  10,
		Offset: 0,
	}
	if limitStr := query.Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 {
			pagination.Limit = limit
		}
	}
	if offsetStr := query.Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			pagination.Offset = offset
		}
	}

	sort := repository.Sort{
		Field:     query.Get("sort_field"),
		Direction: query.Get("sort_order"),
	}
	if sort.Field == "" {
		sort.Field = "start_date"
		sort.Direction = "asc"
	}

	years, err := h.academicYearService.List(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list academic years", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve academic years")
		return
	}

	// In-memory filtering for name, start_after, end_before
	nameFilter := query.Get("name")
	startAfterStr := query.Get("start_after")
	endBeforeStr := query.Get("end_before")

	filtered := make([]*models.AcademicYear, 0, len(years))
	for _, y := range years {
		if nameFilter != "" && y.Name != nameFilter {
			continue
		}
		if startAfterStr != "" {
			if t, err := time.Parse("2006-01-02", startAfterStr); err == nil && !y.StartDate.After(t) {
				continue
			}
		}
		if endBeforeStr != "" {
			if t, err := time.Parse("2006-01-02", endBeforeStr); err == nil && !y.EndDate.Before(t) {
				continue
			}
		}
		filtered = append(filtered, y)
	}

	start := pagination.Offset
	end := start + pagination.Limit
	if start > len(filtered) {
		start = len(filtered)
	}
	if end > len(filtered) {
		end = len(filtered)
	}
	paged := filtered[start:end]
	total := len(filtered)

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":  paged,
			"total":  total,
			"limit":  pagination.Limit,
			"offset": pagination.Offset,
		},
	})
}

func (h *AcademicYearHandler) ListByCompany(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "academic_year:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	years, err := h.academicYearService.ListByCompany(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to list academic years by company", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve academic years")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    years,
	})
}

func (h *AcademicYearHandler) Count(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "academic_year:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	query := r.URL.Query()
	filter := repository.AcademicYearFilter{
		CompanyID: companyID,
	}
	if isCurrentStr := query.Get("is_current"); isCurrentStr != "" {
		isCurrent, _ := strconv.ParseBool(isCurrentStr)
		filter.IsCurrent = &isCurrent
	}

	count, err := h.academicYearService.Count(ctx, filter)
	if err != nil {
		h.logger.Error("failed to count academic years", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to count academic years")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]interface{}{"count": count},
	})
}

func (h *AcademicYearHandler) Exists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		h.respondWithError(w, http.StatusBadRequest, "name query parameter is required")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "academic_year:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	exists, err := h.academicYearService.Exists(ctx, companyID, name)
	if err != nil {
		h.logger.Error("failed to check existence", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]interface{}{"exists": exists},
	})
}

func (h *AcademicYearHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "academic_year:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateAcademicYearRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	serviceReq := service.UpdateAcademicYearRequest{
		AcademicYearID: id,
		Name:           req.Name,
		StartDate:      req.StartDate,
		EndDate:        req.EndDate,
		IsCurrent:      req.IsCurrent,
		UpdatedBy:      &userID,
	}

	ay, err := h.academicYearService.Update(ctx, serviceReq)
	if err != nil {
		h.logger.Error("failed to update academic year", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if ay.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "academic year does not belong to this company")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    ay,
		"message": "Academic year updated successfully",
	})
}

func (h *AcademicYearHandler) UpdateDates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "academic_year:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateDatesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.StartDate.IsZero() || req.EndDate.IsZero() {
		h.respondWithError(w, http.StatusBadRequest, "start_date and end_date are required")
		return
	}
	if req.StartDate.After(req.EndDate) || req.StartDate.Equal(req.EndDate) {
		h.respondWithError(w, http.StatusBadRequest, "start_date must be before end_date")
		return
	}

	err = h.academicYearService.UpdateDates(ctx, id, req.StartDate, req.EndDate, &userID)
	if err != nil {
		h.logger.Error("failed to update academic year dates", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Academic year dates updated successfully",
	})
}

func (h *AcademicYearHandler) SetCurrent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "academic_year:set_current") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Body is ignored; we only use token
	var _ setCurrentRequest
	_ = json.NewDecoder(r.Body).Decode(&struct{}{})

	err = h.academicYearService.SetCurrent(ctx, companyID, id, &userID)
	if err != nil {
		h.logger.Error("failed to set current academic year", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Academic year set as current successfully",
	})
}

func (h *AcademicYearHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "academic_year:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.academicYearService.Delete(ctx, id, &userID)
	if err != nil {
		h.logger.Error("failed to delete academic year", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Academic year deleted successfully",
	})
}

func (h *AcademicYearHandler) ValidateOverlap(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "academic_year:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req validateOverlapRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.StartDate.IsZero() || req.EndDate.IsZero() {
		h.respondWithError(w, http.StatusBadRequest, "start_date and end_date are required")
		return
	}
	if req.StartDate.After(req.EndDate) || req.StartDate.Equal(req.EndDate) {
		h.respondWithError(w, http.StatusBadRequest, "start_date must be before end_date")
		return
	}

	err = h.academicYearService.ValidateOverlap(ctx, companyID, req.StartDate, req.EndDate)
	if err != nil {
		h.respondWithError(w, http.StatusConflict, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "No overlap detected",
	})
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

func (h *AcademicYearHandler) hasPermission(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, permission string) bool {
	// TODO: Implement actual permission check using auth service or context claims.
	return true
}

func (h *AcademicYearHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *AcademicYearHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

// getUserIDFromContext extracts the user ID from the request context.
// Assumes the auth middleware has set the "user_id" key.
func getUserIDFromContext(ctx context.Context) (uuid.UUID, error) {
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		return uuid.Nil, fmt.Errorf("user ID not found in context")
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid user ID in context: %v", err)
	}
	return userID, nil
}
