package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	subErrors "auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/models"
	"auth-service/internal/subscription/models/enums"
	"auth-service/internal/subscription/repository"
	"auth-service/internal/subscription/service"
)

// BenefitHandler handles HTTP requests for benefits.
type BenefitHandler struct {
	benefitService service.BenefitService
	*BaseHandler
}

// NewBenefitHandler creates a new BenefitHandler.
func NewBenefitHandler(benefitService service.BenefitService, logger *zap.Logger) *BenefitHandler {
	return &BenefitHandler{
		benefitService: benefitService,
		BaseHandler:    &BaseHandler{logger: logger.Named("benefit_handler")},
	}
}

// ----- Request/Response structures -------------------------------------------

type createBenefitRequest struct {
	PlanItemID         string       `json:"plan_item_id"`
	BenefitType        string       `json:"benefit_type"`
	BenefitDescription *string      `json:"benefit_description,omitempty"`
	Value              models.JSONB `json:"value"`
}

type updateBenefitRequest struct {
	BenefitType        *string       `json:"benefit_type,omitempty"`
	BenefitDescription *string       `json:"benefit_description,omitempty"`
	Value              *models.JSONB `json:"value,omitempty"`
}

type replaceBenefitsRequest struct {
	Benefits []createBenefitRequest `json:"benefits"`
}

type copyBenefitsRequest struct {
	SourcePlanItemID string `json:"source_plan_item_id"`
	TargetPlanItemID string `json:"target_plan_item_id"`
}

type benefitResponse struct {
	BenefitID          string       `json:"benefit_id"`
	PlanItemID         string       `json:"plan_item_id"`
	BenefitType        string       `json:"benefit_type"`
	BenefitDescription *string      `json:"benefit_description,omitempty"`
	Value              models.JSONB `json:"value"`
	CreatedAt          string       `json:"created_at"`
	UpdatedAt          string       `json:"updated_at"`
}

type listBenefitsResponse struct {
	Benefits []benefitResponse `json:"benefits"`
	Total    int64             `json:"total"`
	Limit    int               `json:"limit"`
	Offset   int               `json:"offset"`
}

// ----- Helpers --------------------------------------------------------------

func (h *BenefitHandler) toBenefitResponse(benefit *models.Benefit) benefitResponse {
	return benefitResponse{
		BenefitID:          benefit.BenefitID.String(),
		PlanItemID:         benefit.PlanItemID.String(),
		BenefitType:        string(benefit.BenefitType),
		BenefitDescription: benefit.BenefitDescription,
		Value:              benefit.Value,
		CreatedAt:          benefit.CreatedAt.Format(time.RFC3339),
		UpdatedAt:          benefit.UpdatedAt.Format(time.RFC3339),
	}
}

func (h *BenefitHandler) parseBenefitType(s string) (enums.BenefitType, error) {
	bt := enums.BenefitType(s)
	if !bt.IsValid() {
		return "", errors.New("invalid benefit_type")
	}
	return bt, nil
}

// ----- Handlers -------------------------------------------------------------

// CreateBenefit creates a new benefit.
func (h *BenefitHandler) CreateBenefit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Optional: verify authentication
	_, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req createBenefitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate required fields
	if req.PlanItemID == "" || req.BenefitType == "" {
		h.respondWithError(w, http.StatusBadRequest, "plan_item_id and benefit_type are required")
		return
	}

	planItemID, err := uuid.Parse(req.PlanItemID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan_item_id")
		return
	}

	benefitType, err := h.parseBenefitType(req.BenefitType)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid benefit_type")
		return
	}

	benefit := &models.Benefit{
		BenefitID:          uuid.New(),
		PlanItemID:         planItemID,
		BenefitType:        benefitType,
		BenefitDescription: req.BenefitDescription,
		Value:              req.Value,
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.benefitService.Create(ctx, benefit); err != nil {
		h.logger.Error("failed to create benefit", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toBenefitResponse(benefit)
	location := fmt.Sprintf("/benefits/%s", benefit.BenefitID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetBenefit retrieves a benefit by ID.
func (h *BenefitHandler) GetBenefit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	benefitID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid benefit ID")
		return
	}

	benefit, err := h.benefitService.GetByID(ctx, benefitID)
	if err != nil {
		h.logger.Error("failed to get benefit", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toBenefitResponse(benefit)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateBenefit updates an existing benefit.
func (h *BenefitHandler) UpdateBenefit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	benefitID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid benefit ID")
		return
	}

	_, err = h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req updateBenefitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Fetch existing benefit
	existing, err := h.benefitService.GetByID(ctx, benefitID)
	if err != nil {
		h.logger.Error("failed to get benefit for update", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	// Apply updates
	if req.BenefitType != nil {
		bt, err := h.parseBenefitType(*req.BenefitType)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid benefit_type")
			return
		}
		existing.BenefitType = bt
	}
	if req.BenefitDescription != nil {
		existing.BenefitDescription = req.BenefitDescription
	}
	if req.Value != nil {
		existing.Value = *req.Value
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.benefitService.Update(ctx, existing); err != nil {
		h.logger.Error("failed to update benefit", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toBenefitResponse(existing)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DeleteBenefit deletes a benefit.
func (h *BenefitHandler) DeleteBenefit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	benefitID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid benefit ID")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.benefitService.Delete(ctx, benefitID); err != nil {
		h.logger.Error("failed to delete benefit", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "benefit deleted successfully",
	})
}

// ListBenefits lists benefits with filters and pagination.
func (h *BenefitHandler) ListBenefits(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	filter := repository.BenefitFilter{}

	if planItemIDStr := r.URL.Query().Get("plan_item_id"); planItemIDStr != "" {
		if id, err := uuid.Parse(planItemIDStr); err == nil {
			filter.PlanItemID = &id
		}
	}
	if benefitTypeStr := r.URL.Query().Get("benefit_type"); benefitTypeStr != "" {
		if bt, err := h.parseBenefitType(benefitTypeStr); err == nil {
			filter.BenefitType = &bt
		}
	}

	limit, offset := h.parsePagination(r)
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	sortField := r.URL.Query().Get("sort_field")
	sortDir := r.URL.Query().Get("sort_dir")
	if sortField == "" {
		sortField = "created_at"
	}
	if sortDir == "" {
		sortDir = "DESC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDir}

	benefits, total, err := h.benefitService.List(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list benefits", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list benefits")
		return
	}

	responses := make([]benefitResponse, len(benefits))
	for i, b := range benefits {
		responses[i] = h.toBenefitResponse(b)
	}

	resp := listBenefitsResponse{
		Benefits: responses,
		Total:    total,
		Limit:    limit,
		Offset:   offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// SearchBenefits searches benefits by query.
func (h *BenefitHandler) SearchBenefits(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	query := r.URL.Query().Get("q")
	if query == "" {
		h.respondWithError(w, http.StatusBadRequest, "q query parameter is required")
		return
	}

	planItemIDStr := r.URL.Query().Get("plan_item_id")
	if planItemIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "plan_item_id query parameter is required")
		return
	}
	planItemID, err := uuid.Parse(planItemIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan_item_id")
		return
	}

	limit, offset := h.parsePagination(r)

	benefits, total, err := h.benefitService.Search(ctx, planItemID, query, limit, offset)
	if err != nil {
		h.logger.Error("failed to search benefits", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to search benefits")
		return
	}

	responses := make([]benefitResponse, len(benefits))
	for i, b := range benefits {
		responses[i] = h.toBenefitResponse(b)
	}

	resp := listBenefitsResponse{
		Benefits: responses,
		Total:    total,
		Limit:    limit,
		Offset:   offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetBenefitsByPlanItem retrieves all benefits for a plan item.
func (h *BenefitHandler) GetBenefitsByPlanItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	planItemID, err := h.parseUUIDParam(r, "planItemId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan_item_id")
		return
	}

	benefits, err := h.benefitService.GetByPlanItem(ctx, planItemID)
	if err != nil {
		h.logger.Error("failed to get benefits by plan item", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get benefits")
		return
	}

	responses := make([]benefitResponse, len(benefits))
	for i, b := range benefits {
		responses[i] = h.toBenefitResponse(b)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// GetBenefitsByType retrieves all benefits of a given type.
func (h *BenefitHandler) GetBenefitsByType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	benefitTypeStr := r.URL.Query().Get("type")
	if benefitTypeStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "type query parameter is required")
		return
	}
	benefitType, err := h.parseBenefitType(benefitTypeStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid benefit_type")
		return
	}

	benefits, err := h.benefitService.GetByType(ctx, benefitType)
	if err != nil {
		h.logger.Error("failed to get benefits by type", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get benefits")
		return
	}

	responses := make([]benefitResponse, len(benefits))
	for i, b := range benefits {
		responses[i] = h.toBenefitResponse(b)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// ReplaceBenefitsByPlanItem replaces all benefits for a plan item with a new set.
func (h *BenefitHandler) ReplaceBenefitsByPlanItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	planItemID, err := h.parseUUIDParam(r, "planItemId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan_item_id")
		return
	}

	_, err = h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req replaceBenefitsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Benefits) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "benefits list cannot be empty")
		return
	}

	benefits := make([]*models.Benefit, len(req.Benefits))
	for i, bReq := range req.Benefits {
		if bReq.BenefitType == "" {
			h.respondWithError(w, http.StatusBadRequest, "benefit_type is required for each benefit")
			return
		}
		bt, err := h.parseBenefitType(bReq.BenefitType)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid benefit_type in list")
			return
		}
		benefits[i] = &models.Benefit{
			BenefitID:          uuid.New(),
			PlanItemID:         planItemID, // all belong to the same plan item
			BenefitType:        bt,
			BenefitDescription: bReq.BenefitDescription,
			Value:              bReq.Value,
		}
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.benefitService.ReplaceByPlanItem(ctx, planItemID, benefits); err != nil {
		h.logger.Error("failed to replace benefits", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	// Return the new benefits (optional, we can fetch them)
	newBenefits, err := h.benefitService.GetByPlanItem(ctx, planItemID)
	if err != nil {
		// Still return success but without data
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "benefits replaced successfully",
		})
		return
	}
	responses := make([]benefitResponse, len(newBenefits))
	for i, b := range newBenefits {
		responses[i] = h.toBenefitResponse(b)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// DeleteBenefitsByPlanItem deletes all benefits for a plan item.
func (h *BenefitHandler) DeleteBenefitsByPlanItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	planItemID, err := h.parseUUIDParam(r, "planItemId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan_item_id")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.benefitService.DeleteByPlanItem(ctx, planItemID); err != nil {
		h.logger.Error("failed to delete benefits by plan item", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "all benefits for plan item deleted",
	})
}

// CopyBenefitsToPlanItem copies benefits from one plan item to another.
func (h *BenefitHandler) CopyBenefitsToPlanItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req copyBenefitsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.SourcePlanItemID == "" || req.TargetPlanItemID == "" {
		h.respondWithError(w, http.StatusBadRequest, "source_plan_item_id and target_plan_item_id are required")
		return
	}

	sourceID, err := uuid.Parse(req.SourcePlanItemID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid source_plan_item_id")
		return
	}
	targetID, err := uuid.Parse(req.TargetPlanItemID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid target_plan_item_id")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.benefitService.CopyToPlanItem(ctx, sourceID, targetID); err != nil {
		h.logger.Error("failed to copy benefits", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	// Return the new benefits (optional)
	newBenefits, err := h.benefitService.GetByPlanItem(ctx, targetID)
	if err != nil {
		// Still return success without data
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "benefits copied successfully",
		})
		return
	}
	responses := make([]benefitResponse, len(newBenefits))
	for i, b := range newBenefits {
		responses[i] = h.toBenefitResponse(b)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// BenefitExists checks if a benefit exists (HEAD or GET with query param).
func (h *BenefitHandler) BenefitExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	benefitID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid benefit ID")
		return
	}

	exists, err := h.benefitService.Exists(ctx, benefitID)
	if err != nil {
		h.logger.Error("failed to check benefit existence", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}

	if !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// ExistsByType checks if a benefit of a given type exists for a plan item.
// This is a separate endpoint: GET /benefits/exists-by-type?plan_item_id=...&benefit_type=...
func (h *BenefitHandler) ExistsByType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	planItemIDStr := r.URL.Query().Get("plan_item_id")
	if planItemIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "plan_item_id query parameter is required")
		return
	}
	planItemID, err := uuid.Parse(planItemIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan_item_id")
		return
	}

	benefitTypeStr := r.URL.Query().Get("benefit_type")
	if benefitTypeStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "benefit_type query parameter is required")
		return
	}
	benefitType, err := h.parseBenefitType(benefitTypeStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid benefit_type")
		return
	}

	exists, err := h.benefitService.ExistsByType(ctx, planItemID, benefitType)
	if err != nil {
		h.logger.Error("failed to check benefit existence by type", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}

	if !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// ----- Error mapping ---------------------------------------------------------

func (h *BenefitHandler) mapServiceError(err error) (status int, message string) {
	switch {
	case errors.Is(err, subErrors.ErrNotFound):
		return http.StatusNotFound, "benefit not found"
	case errors.Is(err, subErrors.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, subErrors.ErrDuplicate):
		return http.StatusConflict, "benefit already exists"
	default:
		return h.BaseHandler.mapServiceError(err)
	}
}
