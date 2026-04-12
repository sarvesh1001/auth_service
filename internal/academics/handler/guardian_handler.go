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

type GuardianHandler struct {
	guardianService service.GuardianService
	logger          *zap.Logger
}

func NewGuardianHandler(guardianService service.GuardianService, logger *zap.Logger) *GuardianHandler {
	return &GuardianHandler{
		guardianService: guardianService,
		logger:          logger.Named("guardian_handler"),
	}
}

// Create handles POST /api/v1/companies/{companyID}/guardians
func (h *GuardianHandler) Create(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "guardian:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateGuardianRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate required fields
	if req.StudentID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "student_id is required")
		return
	}
	if req.GuardianName == "" {
		h.respondWithError(w, http.StatusBadRequest, "guardian_name is required")
		return
	}
	if req.Relation == "" {
		h.respondWithError(w, http.StatusBadRequest, "relation is required")
		return
	}

	req.CreatedBy = &userID
	req.UpdatedBy = &userID

	// --- FIX: Inject idempotency key into context, not as argument ---
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey != "" {
		ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)
	}
	guardian, err := h.guardianService.Create(ctx, req) // only 2 args now
	if err != nil {
		h.logger.Error("Failed to create guardian",
			zap.String("student_id", req.StudentID.String()),
			zap.String("guardian_name", req.GuardianName),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    guardian,
		"message": "Guardian created successfully",
	})
}

// BulkCreate handles POST /api/v1/companies/{companyID}/guardians/bulk
func (h *GuardianHandler) BulkCreate(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "guardian:bulk_create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var reqs []service.CreateGuardianRequest
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(reqs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "empty batch")
		return
	}

	// Set CreatedBy/UpdatedBy for each
	for i := range reqs {
		reqs[i].CreatedBy = &userID
		reqs[i].UpdatedBy = &userID
	}

	guardians, err := h.guardianService.BulkCreate(ctx, reqs)
	if err != nil {
		h.logger.Error("Failed to bulk create guardians",
			zap.Int("batch_size", len(reqs)),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    guardians,
		"message": "Guardians created successfully",
	})
}

// GetByID handles GET /api/v1/companies/{companyID}/guardians/{guardianID}
func (h *GuardianHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	guardianIDStr := chi.URLParam(r, "guardianID")
	guardianID, err := uuid.Parse(guardianIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid guardian ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "guardian:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	guardian, err := h.guardianService.GetByID(ctx, guardianID)
	if err != nil {
		h.logger.Error("Failed to get guardian",
			zap.String("guardian_id", guardianID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    guardian,
	})
}

// GetByStudentID handles GET /api/v1/companies/{companyID}/students/{studentID}/guardians
func (h *GuardianHandler) GetByStudentID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	studentIDStr := chi.URLParam(r, "studentID")
	studentID, err := uuid.Parse(studentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "guardian:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	guardians, err := h.guardianService.GetByStudentID(ctx, studentID)
	if err != nil {
		h.logger.Error("Failed to get guardians by student",
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve guardians")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    guardians,
	})
}

// GetPrimaryGuardian handles GET /api/v1/companies/{companyID}/students/{studentID}/guardians/primary
func (h *GuardianHandler) GetPrimaryGuardian(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	studentIDStr := chi.URLParam(r, "studentID")
	studentID, err := uuid.Parse(studentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "guardian:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	guardian, err := h.guardianService.GetPrimaryGuardian(ctx, studentID)
	if err != nil {
		h.logger.Error("Failed to get primary guardian",
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    guardian,
	})
}

// List handles GET /api/v1/companies/{companyID}/guardians with query params
func (h *GuardianHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "guardian:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Parse filter
	filter := service.GuardianFilter{}
	if studentIDStr := r.URL.Query().Get("student_id"); studentIDStr != "" {
		studentID, err := uuid.Parse(studentIDStr)
		if err == nil {
			filter.StudentID = studentID
		}
	}
	if isPrimaryStr := r.URL.Query().Get("is_primary"); isPrimaryStr != "" {
		isPrimary, err := strconv.ParseBool(isPrimaryStr)
		if err == nil {
			filter.IsPrimary = &isPrimary
		}
	}
	if relation := r.URL.Query().Get("relation"); relation != "" {
		filter.Relation = relation
	}
	if search := r.URL.Query().Get("search"); search != "" {
		filter.Search = search
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

	guardians, err := h.guardianService.List(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list guardians",
			zap.Any("filter", filter),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list guardians")
		return
	}

	count, err := h.guardianService.Count(ctx, filter)
	if err != nil {
		h.logger.Error("Failed to count guardians", zap.Error(err))
		// Non-fatal, we can still return guardians without total
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"guardians": guardians,
			"total":     count,
			"limit":     limit,
			"offset":    offset,
		},
	})
}

// Update handles PUT /api/v1/companies/{companyID}/guardians/{guardianID}
func (h *GuardianHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	guardianIDStr := chi.URLParam(r, "guardianID")
	guardianID, err := uuid.Parse(guardianIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid guardian ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "guardian:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateGuardianRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.GuardianID = guardianID
	req.UpdatedBy = &userID

	guardian, err := h.guardianService.Update(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update guardian",
			zap.String("guardian_id", guardianID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    guardian,
		"message": "Guardian updated successfully",
	})
}

// Delete handles DELETE /api/v1/companies/{companyID}/guardians/{guardianID}
func (h *GuardianHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	guardianIDStr := chi.URLParam(r, "guardianID")
	guardianID, err := uuid.Parse(guardianIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid guardian ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "guardian:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.guardianService.Delete(ctx, guardianID, &userID)
	if err != nil {
		h.logger.Error("Failed to delete guardian",
			zap.String("guardian_id", guardianID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Guardian deleted successfully",
	})
}

// SetPrimary handles PATCH /api/v1/companies/{companyID}/students/{studentID}/guardians/{guardianID}/primary
func (h *GuardianHandler) SetPrimary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	studentIDStr := chi.URLParam(r, "studentID")
	studentID, err := uuid.Parse(studentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	guardianIDStr := chi.URLParam(r, "guardianID")
	guardianID, err := uuid.Parse(guardianIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid guardian ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "guardian:set_primary") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.guardianService.SetPrimary(ctx, studentID, guardianID, &userID)
	if err != nil {
		h.logger.Error("Failed to set primary guardian",
			zap.String("student_id", studentID.String()),
			zap.String("guardian_id", guardianID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Primary guardian set successfully",
	})
}

// Exists is a helper endpoint to check if a guardian exists for a student with given name and relation
// GET /api/v1/companies/{companyID}/students/{studentID}/guardians/exists?name=...&relation=...
func (h *GuardianHandler) Exists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	studentIDStr := chi.URLParam(r, "studentID")
	studentID, err := uuid.Parse(studentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "guardian:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	guardianName := r.URL.Query().Get("name")
	relation := r.URL.Query().Get("relation")
	if guardianName == "" || relation == "" {
		h.respondWithError(w, http.StatusBadRequest, "name and relation query parameters are required")
		return
	}

	exists, err := h.guardianService.Exists(ctx, studentID, guardianName, relation)
	if err != nil {
		h.logger.Error("Failed to check guardian existence",
			zap.String("student_id", studentID.String()),
			zap.String("guardian_name", guardianName),
			zap.String("relation", relation),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check guardian existence")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"exists": exists,
		},
	})
}

// Helper methods
func (h *GuardianHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	// Placeholder – implement actual permission check
	return true
}

func (h *GuardianHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *GuardianHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
