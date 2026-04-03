package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/service"
)

// SectionHandler handles HTTP requests for sections.
type SectionHandler struct {
	sectionService service.SectionService
	logger         *zap.Logger
}

// NewSectionHandler creates a new SectionHandler.
func NewSectionHandler(sectionService service.SectionService, logger *zap.Logger) *SectionHandler {
	return &SectionHandler{
		sectionService: sectionService,
		logger:         logger.Named("section_handler"),
	}
}

// Create handles POST /api/v1/companies/{companyID}/sections
func (h *SectionHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "section:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateSectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Set audit fields
	req.CreatedBy = &userID
	req.UpdatedBy = &userID

	section, err := h.sectionService.Create(ctx, req)
	if err != nil {
		h.logger.Error("Failed to create section",
			zap.String("course_id", req.CourseID.String()),
			zap.String("term_id", req.TermID.String()),
			zap.String("name", req.Name),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    section,
		"message": "Section created successfully",
	})
}

// BulkCreate handles POST /api/v1/companies/{companyID}/sections/bulk
func (h *SectionHandler) BulkCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "section:bulk_create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var reqs []service.CreateSectionRequest
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(reqs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "empty batch")
		return
	}

	// Set audit fields for each request
	for i := range reqs {
		reqs[i].CreatedBy = &userID
		reqs[i].UpdatedBy = &userID
	}

	sections, err := h.sectionService.BulkCreate(ctx, reqs)
	if err != nil {
		h.logger.Error("Failed to bulk create sections",
			zap.Int("batch_size", len(reqs)),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    sections,
		"message": "Sections created successfully",
	})
}

// Upsert handles POST /api/v1/companies/{companyID}/sections/upsert
func (h *SectionHandler) Upsert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "section:upsert") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateSectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.CreatedBy = &userID
	req.UpdatedBy = &userID

	section, err := h.sectionService.Upsert(ctx, req)
	if err != nil {
		h.logger.Error("Failed to upsert section",
			zap.String("course_id", req.CourseID.String()),
			zap.String("term_id", req.TermID.String()),
			zap.String("name", req.Name),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    section,
		"message": "Section upserted successfully",
	})
}

// GetByID handles GET /api/v1/companies/{companyID}/sections/{sectionID}
func (h *SectionHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	sectionID, err := h.parseSectionID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, "section:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	section, err := h.sectionService.GetByID(ctx, sectionID)
	if err != nil {
		h.logger.Error("Failed to get section",
			zap.String("section_id", sectionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    section,
	})
}

// ListByCourse handles GET /api/v1/companies/{companyID}/courses/{courseID}/sections
func (h *SectionHandler) ListByCourse(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	courseIDStr := chi.URLParam(r, "courseID")
	courseID, err := uuid.Parse(courseIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid course ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "section:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	sections, err := h.sectionService.ListByCourse(ctx, courseID)
	if err != nil {
		h.logger.Error("Failed to list sections by course",
			zap.String("course_id", courseID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list sections")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    sections,
	})
}

// ListByTerm handles GET /api/v1/companies/{companyID}/terms/{termID}/sections
func (h *SectionHandler) ListByTerm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	termIDStr := chi.URLParam(r, "termID")
	termID, err := uuid.Parse(termIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid term ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "section:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	sections, err := h.sectionService.ListByTerm(ctx, termID)
	if err != nil {
		h.logger.Error("Failed to list sections by term",
			zap.String("term_id", termID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list sections")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    sections,
	})
}

// Update handles PUT /api/v1/companies/{companyID}/sections/{sectionID}
func (h *SectionHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	sectionID, err := h.parseSectionID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "section:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateSectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.SectionID = sectionID
	req.UpdatedBy = &userID

	section, err := h.sectionService.Update(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update section",
			zap.String("section_id", sectionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    section,
		"message": "Section updated successfully",
	})
}

// UpdateCapacity handles PATCH /api/v1/companies/{companyID}/sections/{sectionID}/capacity
func (h *SectionHandler) UpdateCapacity(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	sectionID, err := h.parseSectionID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "section:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req struct {
		Capacity int `json:"capacity"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Capacity < 0 {
		h.respondWithError(w, http.StatusBadRequest, "capacity cannot be negative")
		return
	}

	err = h.sectionService.UpdateCapacity(ctx, sectionID, req.Capacity, &userID)
	if err != nil {
		h.logger.Error("Failed to update capacity",
			zap.String("section_id", sectionID.String()),
			zap.Int("capacity", req.Capacity),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Section capacity updated successfully",
	})
}

// Activate handles PATCH /api/v1/companies/{companyID}/sections/{sectionID}/activate
func (h *SectionHandler) Activate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	sectionID, err := h.parseSectionID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "section:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.sectionService.Activate(ctx, sectionID, &userID)
	if err != nil {
		h.logger.Error("Failed to activate section",
			zap.String("section_id", sectionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Section activated successfully",
	})
}

// Deactivate handles PATCH /api/v1/companies/{companyID}/sections/{sectionID}/deactivate
func (h *SectionHandler) Deactivate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	sectionID, err := h.parseSectionID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "section:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.sectionService.Deactivate(ctx, sectionID, &userID)
	if err != nil {
		h.logger.Error("Failed to deactivate section",
			zap.String("section_id", sectionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Section deactivated successfully",
	})
}

// Delete handles DELETE /api/v1/companies/{companyID}/sections/{sectionID}
func (h *SectionHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	sectionID, err := h.parseSectionID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "section:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.sectionService.Delete(ctx, sectionID, &userID)
	if err != nil {
		h.logger.Error("Failed to delete section",
			zap.String("section_id", sectionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Section deleted successfully",
	})
}

// ValidateCapacity handles GET /api/v1/companies/{companyID}/sections/{sectionID}/validate-capacity
func (h *SectionHandler) ValidateCapacity(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	sectionID, err := h.parseSectionID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, "section:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.sectionService.ValidateCapacity(ctx, sectionID)
	if err != nil {
		h.logger.Error("Capacity validation failed",
			zap.String("section_id", sectionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Section capacity is valid",
	})
}

// Helper methods

func (h *SectionHandler) parseCompanyID(r *http.Request) (uuid.UUID, error) {
	companyIDStr := chi.URLParam(r, "companyID")
	if companyIDStr == "" {
		return uuid.Nil, fmt.Errorf("company ID is required")
	}
	return uuid.Parse(companyIDStr)
}

func (h *SectionHandler) parseSectionID(r *http.Request) (uuid.UUID, error) {
	sectionIDStr := chi.URLParam(r, "sectionID")
	if sectionIDStr == "" {
		return uuid.Nil, fmt.Errorf("section ID is required")
	}
	return uuid.Parse(sectionIDStr)
}

func (h *SectionHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	// Placeholder – implement actual permission check
	return true
}

func (h *SectionHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *SectionHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
