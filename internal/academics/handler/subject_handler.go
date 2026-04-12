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

type SubjectHandler struct {
	subjectService service.SubjectService
	logger         *zap.Logger
}

func NewSubjectHandler(subjectService service.SubjectService, logger *zap.Logger) *SubjectHandler {
	return &SubjectHandler{
		subjectService: subjectService,
		logger:         logger.Named("subject_handler"),
	}
}

type CreateSubjectRequest struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Credits     int    `json:"credits,omitempty"`
	IsActive    bool   `json:"is_active,omitempty"`
}

type UpdateSubjectRequest struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Credits     int    `json:"credits,omitempty"`
	IsActive    bool   `json:"is_active,omitempty"`
}

func (h *SubjectHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "subject:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req CreateSubjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Code == "" || req.Name == "" {
		h.respondWithError(w, http.StatusBadRequest, "code and name are required")
		return
	}

	// ✅ FIX: read idempotency key from context (set by middleware)
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	createReq := service.CreateSubjectRequest{
		CompanyID:   companyID,
		Code:        req.Code,
		Name:        req.Name,
		Description: req.Description,
		Credits:     req.Credits,
		IsActive:    req.IsActive,
		CreatedBy:   &userID,
		UpdatedBy:   &userID,
	}

	subject, err := h.subjectService.Create(ctx, createReq, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to create subject",
			zap.String("company_id", companyID.String()),
			zap.String("code", req.Code),
			zap.String("idempotency_key", idempotencyKey),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    subject,
		"message": "Subject created successfully",
	})
}

func (h *SubjectHandler) BulkCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "subject:bulk_create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var reqs []CreateSubjectRequest
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(reqs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "empty batch")
		return
	}

	// ✅ FIX: read idempotency key from context
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	createReqs := make([]service.CreateSubjectRequest, len(reqs))
	for i, r := range reqs {
		if r.Code == "" || r.Name == "" {
			h.respondWithError(w, http.StatusBadRequest, "code and name required for all subjects")
			return
		}
		createReqs[i] = service.CreateSubjectRequest{
			CompanyID:   companyID,
			Code:        r.Code,
			Name:        r.Name,
			Description: r.Description,
			Credits:     r.Credits,
			IsActive:    r.IsActive,
			CreatedBy:   &userID,
			UpdatedBy:   &userID,
		}
	}

	subjects, err := h.subjectService.BulkCreate(ctx, createReqs, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to bulk create subjects",
			zap.Int("count", len(reqs)),
			zap.String("idempotency_key", idempotencyKey),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    subjects,
		"message": "Subjects created successfully",
	})
}

func (h *SubjectHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	subjectIDStr := chi.URLParam(r, "subjectID")
	subjectID, err := uuid.Parse(subjectIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subject ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "subject:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	subject, err := h.subjectService.GetByID(ctx, subjectID)
	if err != nil {
		h.logger.Error("Failed to get subject",
			zap.String("subject_id", subjectID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    subject,
	})
}

func (h *SubjectHandler) GetByCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	code := chi.URLParam(r, "code")
	if code == "" {
		h.respondWithError(w, http.StatusBadRequest, "code is required")
		return
	}

	if !h.hasPermission(ctx, companyID, "subject:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	subject, err := h.subjectService.GetByCode(ctx, companyID, code)
	if err != nil {
		h.logger.Error("Failed to get subject by code",
			zap.String("company_id", companyID.String()),
			zap.String("code", code),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    subject,
	})
}

func (h *SubjectHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "subject:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	filter := repository.SubjectFilter{
		CompanyID: companyID,
	}
	if status := r.URL.Query().Get("is_active"); status != "" {
		active := status == "true"
		filter.IsActive = &active
	}
	if search := r.URL.Query().Get("search"); search != "" {
		filter.Search = search
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
	sortDirection := r.URL.Query().Get("sort_direction")
	if sortDirection == "" {
		sortDirection = "DESC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDirection}

	subjects, err := h.subjectService.List(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list subjects",
			zap.Any("filter", filter),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list subjects")
		return
	}

	count, err := h.subjectService.Count(ctx, filter)
	if err != nil {
		h.logger.Error("Failed to count subjects", zap.Error(err))
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"subjects": subjects,
			"total":    count,
			"limit":    limit,
			"offset":   offset,
		},
	})
}

func (h *SubjectHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	subjectID, err := uuid.Parse(chi.URLParam(r, "subjectID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subject ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "subject:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req UpdateSubjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Code == "" || req.Name == "" {
		h.respondWithError(w, http.StatusBadRequest, "code and name are required")
		return
	}

	// ✅ FIX: read idempotency key from context
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	updateReq := service.UpdateSubjectRequest{
		SubjectID:   subjectID,
		Code:        req.Code,
		Name:        req.Name,
		Description: req.Description,
		Credits:     req.Credits,
		IsActive:    req.IsActive,
		UpdatedBy:   &userID,
	}

	subject, err := h.subjectService.Update(ctx, updateReq, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to update subject",
			zap.String("subject_id", subjectID.String()),
			zap.String("idempotency_key", idempotencyKey),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    subject,
		"message": "Subject updated successfully",
	})
}

func (h *SubjectHandler) Activate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	subjectID, err := uuid.Parse(chi.URLParam(r, "subjectID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subject ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "subject:activate") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// ✅ FIX: read idempotency key from context
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	err = h.subjectService.Activate(ctx, subjectID, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to activate subject",
			zap.String("subject_id", subjectID.String()),
			zap.String("idempotency_key", idempotencyKey),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Subject activated",
	})
}

func (h *SubjectHandler) Deactivate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	subjectID, err := uuid.Parse(chi.URLParam(r, "subjectID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subject ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "subject:deactivate") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// ✅ FIX: read idempotency key from context
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	err = h.subjectService.Deactivate(ctx, subjectID, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to deactivate subject",
			zap.String("subject_id", subjectID.String()),
			zap.String("idempotency_key", idempotencyKey),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Subject deactivated",
	})
}

func (h *SubjectHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	subjectID, err := uuid.Parse(chi.URLParam(r, "subjectID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subject ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "subject:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// ✅ FIX: read idempotency key from context
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	err = h.subjectService.Delete(ctx, subjectID, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to delete subject",
			zap.String("subject_id", subjectID.String()),
			zap.String("idempotency_key", idempotencyKey),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Subject deleted",
	})
}

func (h *SubjectHandler) ValidateCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		h.respondWithError(w, http.StatusBadRequest, "code query param is required")
		return
	}

	if !h.hasPermission(ctx, companyID, "subject:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.subjectService.ValidateUniqueCode(ctx, companyID, code)
	if err != nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"valid":   false,
			"message": err.Error(),
		})
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"valid":   true,
	})
}

// hasPermission is a placeholder – real permission checks are done via middleware
func (h *SubjectHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	return true
}

func (h *SubjectHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *SubjectHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
