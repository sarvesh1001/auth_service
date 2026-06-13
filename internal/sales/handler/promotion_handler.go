package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/sales/models/discount"
	"auth-service/internal/sales/service"
)

// PromotionHandler handles HTTP requests for promotion management.
type PromotionHandler struct {
	promotionService service.PromotionService
	*BaseHandler
}

// NewPromotionHandler creates a new PromotionHandler.
func NewPromotionHandler(promotionService service.PromotionService, logger *zap.Logger) *PromotionHandler {
	return &PromotionHandler{
		promotionService: promotionService,
		BaseHandler:      &BaseHandler{logger: logger.Named("promotion_handler")},
	}
}

// ---------- Request/Response Types ----------

type createPromotionRequest struct {
	Name         string  `json:"name"`
	Description  *string `json:"description,omitempty"`
	StartDate    string  `json:"start_date"`
	EndDate      string  `json:"end_date"`
	IsActive     bool    `json:"is_active"`
	Priority     *int    `json:"priority,omitempty"`
	StackingType string  `json:"stacking_type,omitempty"` // NEW
}

type createPromotionResponse struct {
	PromotionID  string  `json:"promotion_id"`
	CompanyID    string  `json:"company_id"`
	Name         string  `json:"name"`
	Description  *string `json:"description,omitempty"`
	StartDate    string  `json:"start_date"`
	EndDate      string  `json:"end_date"`
	IsActive     bool    `json:"is_active"`
	Priority     *int    `json:"priority,omitempty"`
	StackingType string  `json:"stacking_type,omitempty"` // NEW
	CreatedAt    string  `json:"created_at"`
	UpdatedAt    string  `json:"updated_at"`
}

type updatePromotionRequest struct {
	Name         *string `json:"name,omitempty"`
	Description  *string `json:"description,omitempty"`
	StartDate    *string `json:"start_date,omitempty"`
	EndDate      *string `json:"end_date,omitempty"`
	IsActive     *bool   `json:"is_active,omitempty"`
	Priority     *int    `json:"priority,omitempty"`
	StackingType *string `json:"stacking_type,omitempty"` // NEW
}

type createPromotionRuleRequest struct {
	PromotionID   string                 `json:"promotion_id"`
	RuleType      string                 `json:"rule_type"`
	RuleConfig    map[string]interface{} `json:"rule_config"`
	DiscountType  string                 `json:"discount_type"` // "percentage" or "fixed_amount"
	DiscountValue string                 `json:"discount_value"`
	MaxDiscount   *string                `json:"max_discount,omitempty"`
}

type updatePromotionRuleRequest struct {
	RuleType      *string                `json:"rule_type,omitempty"`
	RuleConfig    map[string]interface{} `json:"rule_config,omitempty"`
	DiscountType  *string                `json:"discount_type,omitempty"`
	DiscountValue *string                `json:"discount_value,omitempty"`
	MaxDiscount   *string                `json:"max_discount,omitempty"`
}

type listPromotionsResponse struct {
	Promotions []promotionSummary `json:"promotions"`
	Total      int64              `json:"total"`
	Limit      int                `json:"limit"`
	Offset     int                `json:"offset"`
}

type promotionSummary struct {
	PromotionID  string `json:"promotion_id"`
	Name         string `json:"name"`
	StartDate    string `json:"start_date"`
	EndDate      string `json:"end_date"`
	IsActive     bool   `json:"is_active"`
	Priority     *int   `json:"priority,omitempty"`
	StackingType string `json:"stacking_type,omitempty"` // NEW
}

type evaluatePromotionRequest struct {
	PromotionID string  `json:"promotion_id"`
	CustomerID  *string `json:"customer_id,omitempty"`
	OrderAmount string  `json:"order_amount"`
	At          string  `json:"at"`
}

type promotionApplyRequest struct {
	EntityType  string `json:"entity_type"` // order, quote, invoice
	EntityID    string `json:"entity_id"`
	PromotionID string `json:"promotion_id"`
}

type applyPromotionResponse struct {
	PromotionID    string `json:"promotion_id"`
	DiscountAmount string `json:"discount_amount"`
}

type recordUsageRequest struct {
	PromotionID    string  `json:"promotion_id"`
	EntityType     string  `json:"entity_type"`
	EntityID       string  `json:"entity_id"`
	CustomerID     *string `json:"customer_id,omitempty"`
	DiscountAmount string  `json:"discount_amount"`
	UsedAt         string  `json:"used_at"`
}

// ---------- Promotion CRUD ----------

// CreatePromotion handles POST /promotions
func (h *PromotionHandler) CreatePromotion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req createPromotionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		h.respondWithError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.StartDate == "" || req.EndDate == "" {
		h.respondWithError(w, http.StatusBadRequest, "start_date and end_date are required")
		return
	}
	startDate, err := time.Parse(time.RFC3339, req.StartDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid start_date format (use RFC3339)")
		return
	}
	endDate, err := time.Parse(time.RFC3339, req.EndDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid end_date format (use RFC3339)")
		return
	}
	if endDate.Before(startDate) {
		h.respondWithError(w, http.StatusBadRequest, "end_date must be after start_date")
		return
	}

	// Validate stacking_type
	allowedStacking := map[string]bool{"stackable": true, "exclusive": true, "none": true}
	if req.StackingType != "" && !allowedStacking[req.StackingType] {
		h.respondWithError(w, http.StatusBadRequest, "stacking_type must be 'stackable', 'exclusive', or 'none'")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "promotion:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	svcReq := service.CreatePromotionRequest{
		CompanyID:    companyID,
		Name:         req.Name,
		Description:  req.Description,
		StartDate:    startDate,
		EndDate:      endDate,
		IsActive:     req.IsActive,
		Priority:     req.Priority,
		StackingType: req.StackingType, // NEW
		CreatedBy:    &userID,
	}

	promotion, err := h.promotionService.CreatePromotion(ctx, &svcReq)
	if err != nil {
		h.logger.Error("failed to create promotion", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.promotionToResponse(promotion)
	location := fmt.Sprintf("/promotions/%s", promotion.PromotionID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdatePromotion handles PUT /promotions/{id}
func (h *PromotionHandler) UpdatePromotion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	promotionID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "promotion:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updatePromotionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	svcReq := service.UpdatePromotionRequest{
		Name:        req.Name,
		Description: req.Description,
		IsActive:    req.IsActive,
		Priority:    req.Priority,
		UpdatedBy:   &userID,
	}
	if req.StartDate != nil {
		start, err := time.Parse(time.RFC3339, *req.StartDate)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid start_date format")
			return
		}
		svcReq.StartDate = &start
	}
	if req.EndDate != nil {
		end, err := time.Parse(time.RFC3339, *req.EndDate)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid end_date format")
			return
		}
		svcReq.EndDate = &end
	}
	// NEW: handle stacking_type update
	if req.StackingType != nil {
		allowed := map[string]bool{"stackable": true, "exclusive": true, "none": true}
		if !allowed[*req.StackingType] {
			h.respondWithError(w, http.StatusBadRequest, "stacking_type must be 'stackable', 'exclusive', or 'none'")
			return
		}
		svcReq.StackingType = req.StackingType
	}

	promotion, err := h.promotionService.UpdatePromotion(ctx, companyID, promotionID, &svcReq)
	if err != nil {
		h.logger.Error("failed to update promotion", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.promotionToResponse(promotion)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DeletePromotion handles DELETE /promotions/{id}
func (h *PromotionHandler) DeletePromotion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	promotionID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "promotion:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.promotionService.DeletePromotion(ctx, companyID, promotionID, userID)
	if err != nil {
		h.logger.Error("failed to delete promotion", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "promotion deleted successfully",
	})
}

// GetPromotionByID handles GET /promotions/{id}
func (h *PromotionHandler) GetPromotionByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	promotionID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	promotion, err := h.promotionService.GetPromotionByID(ctx, companyID, promotionID)
	if err != nil {
		h.logger.Error("failed to get promotion", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.promotionToResponse(promotion)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetPromotionByCode handles GET /promotions/by-code?code=...
func (h *PromotionHandler) GetPromotionByCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		h.respondWithError(w, http.StatusBadRequest, "code query parameter is required")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	promotion, err := h.promotionService.GetPromotionByCode(ctx, companyID, code)
	if err != nil {
		h.logger.Error("failed to get promotion by code", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.promotionToResponse(promotion)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetPromotionByName handles GET /promotions/by-name?name=...
func (h *PromotionHandler) GetPromotionByName(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		h.respondWithError(w, http.StatusBadRequest, "name query parameter is required")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	promotion, err := h.promotionService.GetPromotionByName(ctx, companyID, name)
	if err != nil {
		h.logger.Error("failed to get promotion by name", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.promotionToResponse(promotion)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ListPromotions handles GET /promotions
func (h *PromotionHandler) ListPromotions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	filter := service.PromotionListFilter{
		CompanyID: companyID,
	}
	if activeStr := r.URL.Query().Get("active"); activeStr != "" {
		active, err := strconv.ParseBool(activeStr)
		if err == nil {
			filter.IsActive = &active
		}
	}
	if name := r.URL.Query().Get("name"); name != "" {
		filter.Name = &name
	}

	limit := 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	offset := 0
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}
	pagination := service.Pagination{Limit: limit, Offset: offset}

	sort := service.Sort{
		Field:     r.URL.Query().Get("sort_field"),
		Direction: r.URL.Query().Get("sort_dir"),
	}
	if sort.Field == "" {
		sort.Field = "created_at"
	}
	if sort.Direction == "" {
		sort.Direction = "DESC"
	}

	promotions, total, err := h.promotionService.ListPromotions(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list promotions", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list promotions")
		return
	}

	summaries := make([]promotionSummary, len(promotions))
	for i, p := range promotions {
		summaries[i] = promotionSummary{
			PromotionID:  p.PromotionID.String(),
			Name:         p.Name,
			StartDate:    p.StartDate.Format(time.RFC3339),
			EndDate:      p.EndDate.Format(time.RFC3339),
			IsActive:     p.IsActive,
			Priority:     p.Priority,
			StackingType: p.StackingType, // NEW
		}
	}

	resp := listPromotionsResponse{
		Promotions: summaries,
		Total:      total,
		Limit:      limit,
		Offset:     offset,
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// SearchPromotions handles GET /promotions/search
func (h *PromotionHandler) SearchPromotions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	query := r.URL.Query().Get("q")
	if query == "" {
		h.respondWithError(w, http.StatusBadRequest, "q query parameter is required")
		return
	}

	limit := 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	offset := 0
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	promotions, total, err := h.promotionService.SearchPromotions(ctx, companyID, query, limit, offset)
	if err != nil {
		h.logger.Error("failed to search promotions", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to search promotions")
		return
	}

	summaries := make([]promotionSummary, len(promotions))
	for i, p := range promotions {
		summaries[i] = promotionSummary{
			PromotionID:  p.PromotionID.String(),
			Name:         p.Name,
			StartDate:    p.StartDate.Format(time.RFC3339),
			EndDate:      p.EndDate.Format(time.RFC3339),
			IsActive:     p.IsActive,
			Priority:     p.Priority,
			StackingType: p.StackingType, // NEW
		}
	}

	resp := listPromotionsResponse{
		Promotions: summaries,
		Total:      total,
		Limit:      limit,
		Offset:     offset,
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetActivePromotions handles GET /promotions/active
func (h *PromotionHandler) GetActivePromotions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	atStr := r.URL.Query().Get("at")
	at := time.Now()
	if atStr != "" {
		parsed, err := time.Parse(time.RFC3339, atStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid at format (use RFC3339)")
			return
		}
		at = parsed
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	promotions, err := h.promotionService.GetActivePromotions(ctx, companyID, at)
	if err != nil {
		h.logger.Error("failed to get active promotions", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get active promotions")
		return
	}

	summaries := make([]promotionSummary, len(promotions))
	for i, p := range promotions {
		summaries[i] = promotionSummary{
			PromotionID:  p.PromotionID.String(),
			Name:         p.Name,
			StartDate:    p.StartDate.Format(time.RFC3339),
			EndDate:      p.EndDate.Format(time.RFC3339),
			IsActive:     p.IsActive,
			Priority:     p.Priority,
			StackingType: p.StackingType, // NEW
		}
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

// ActivatePromotion handles POST /promotions/{id}/activate
func (h *PromotionHandler) ActivatePromotion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	promotionID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "promotion:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.promotionService.ActivatePromotion(ctx, companyID, promotionID, userID)
	if err != nil {
		h.logger.Error("failed to activate promotion", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "promotion activated",
	})
}

// DeactivatePromotion handles POST /promotions/{id}/deactivate
func (h *PromotionHandler) DeactivatePromotion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	promotionID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "promotion:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.promotionService.DeactivatePromotion(ctx, companyID, promotionID, userID)
	if err != nil {
		h.logger.Error("failed to deactivate promotion", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "promotion deactivated",
	})
}

// ExpirePromotion handles POST /promotions/{id}/expire
func (h *PromotionHandler) ExpirePromotion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	promotionID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "promotion:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.promotionService.ExpirePromotion(ctx, companyID, promotionID, userID)
	if err != nil {
		h.logger.Error("failed to expire promotion", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "promotion expired",
	})
}

// ---------- Promotion Rules ----------

// CreatePromotionRule handles POST /promotions/rules
func (h *PromotionHandler) CreatePromotionRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req createPromotionRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.PromotionID == "" {
		h.respondWithError(w, http.StatusBadRequest, "promotion_id is required")
		return
	}
	promotionID, err := uuid.Parse(req.PromotionID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion_id")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "promotion:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	discountValue, err := decimal.NewFromString(req.DiscountValue)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid discount_value")
		return
	}
	var maxDiscount *decimal.Decimal
	if req.MaxDiscount != nil && *req.MaxDiscount != "" {
		md, err := decimal.NewFromString(*req.MaxDiscount)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid max_discount")
			return
		}
		maxDiscount = &md
	}

	svcReq := service.CreatePromotionRuleRequest{
		PromotionID:   promotionID,
		RuleType:      req.RuleType,
		RuleConfig:    req.RuleConfig,
		DiscountType:  discount.DiscountType(req.DiscountType),
		DiscountValue: discountValue,
		MaxDiscount:   maxDiscount,
	}

	rule, err := h.promotionService.CreatePromotionRule(ctx, &svcReq)
	if err != nil {
		h.logger.Error("failed to create promotion rule", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := map[string]interface{}{
		"rule_id":        rule.RuleID.String(),
		"promotion_id":   rule.PromotionID.String(),
		"rule_type":      rule.RuleType,
		"rule_config":    rule.RuleConfig,
		"discount_type":  string(rule.DiscountType),
		"discount_value": rule.DiscountValue.String(),
	}
	if rule.MaxDiscount != nil {
		resp["max_discount"] = rule.MaxDiscount.String()
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdatePromotionRule handles PUT /promotions/rules/{ruleId}
func (h *PromotionHandler) UpdatePromotionRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ruleID, err := h.parseUUIDParam(r, "ruleId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid rule ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "promotion:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updatePromotionRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	svcReq := service.UpdatePromotionRuleRequest{
		RuleType:   req.RuleType,
		RuleConfig: req.RuleConfig,
	}
	if req.DiscountType != nil {
		dt := discount.DiscountType(*req.DiscountType)
		svcReq.DiscountType = &dt
	}
	if req.DiscountValue != nil {
		val, err := decimal.NewFromString(*req.DiscountValue)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid discount_value")
			return
		}
		svcReq.DiscountValue = &val
	}
	if req.MaxDiscount != nil {
		md, err := decimal.NewFromString(*req.MaxDiscount)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid max_discount")
			return
		}
		svcReq.MaxDiscount = &md
	}

	rule, err := h.promotionService.UpdatePromotionRule(ctx, companyID, ruleID, &svcReq)
	if err != nil {
		h.logger.Error("failed to update promotion rule", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := map[string]interface{}{
		"rule_id":        rule.RuleID.String(),
		"promotion_id":   rule.PromotionID.String(),
		"rule_type":      rule.RuleType,
		"rule_config":    rule.RuleConfig,
		"discount_type":  string(rule.DiscountType),
		"discount_value": rule.DiscountValue.String(),
	}
	if rule.MaxDiscount != nil {
		resp["max_discount"] = rule.MaxDiscount.String()
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DeletePromotionRule handles DELETE /promotions/rules/{ruleId}
func (h *PromotionHandler) DeletePromotionRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ruleID, err := h.parseUUIDParam(r, "ruleId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid rule ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "promotion:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.promotionService.DeletePromotionRule(ctx, companyID, ruleID, userID)
	if err != nil {
		h.logger.Error("failed to delete promotion rule", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "promotion rule deleted",
	})
}

// GetPromotionRuleByID handles GET /promotions/rules/{ruleId}
func (h *PromotionHandler) GetPromotionRuleByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ruleID, err := h.parseUUIDParam(r, "ruleId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid rule ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	rule, err := h.promotionService.GetPromotionRuleByID(ctx, companyID, ruleID)
	if err != nil {
		h.logger.Error("failed to get promotion rule", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := map[string]interface{}{
		"rule_id":        rule.RuleID.String(),
		"promotion_id":   rule.PromotionID.String(),
		"rule_type":      rule.RuleType,
		"rule_config":    rule.RuleConfig,
		"discount_type":  string(rule.DiscountType),
		"discount_value": rule.DiscountValue.String(),
	}
	if rule.MaxDiscount != nil {
		resp["max_discount"] = rule.MaxDiscount.String()
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetPromotionRules handles GET /promotions/{id}/rules
func (h *PromotionHandler) GetPromotionRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	promotionID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	rules, err := h.promotionService.GetPromotionRules(ctx, companyID, promotionID)
	if err != nil {
		h.logger.Error("failed to get promotion rules", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	response := make([]map[string]interface{}, len(rules))
	for i, rule := range rules {
		item := map[string]interface{}{
			"rule_id":        rule.RuleID.String(),
			"promotion_id":   rule.PromotionID.String(),
			"rule_type":      rule.RuleType,
			"rule_config":    rule.RuleConfig,
			"discount_type":  string(rule.DiscountType),
			"discount_value": rule.DiscountValue.String(),
		}
		if rule.MaxDiscount != nil {
			item["max_discount"] = rule.MaxDiscount.String()
		}
		response[i] = item
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    response,
	})
}

// ---------- Validation & Evaluation ----------

// ValidatePromotion handles POST /promotions/validate
func (h *PromotionHandler) ValidatePromotion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req struct {
		PromotionID string   `json:"promotion_id"`
		CustomerID  *string  `json:"customer_id,omitempty"`
		ProductIDs  []string `json:"product_ids"`
		OrderAmount string   `json:"order_amount"`
		At          string   `json:"at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	promotionID, err := uuid.Parse(req.PromotionID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion_id")
		return
	}

	var customerID *uuid.UUID
	if req.CustomerID != nil && *req.CustomerID != "" {
		parsed, err := uuid.Parse(*req.CustomerID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
			return
		}
		customerID = &parsed
	}

	productIDs := make([]uuid.UUID, len(req.ProductIDs))
	for i, idStr := range req.ProductIDs {
		pid, err := uuid.Parse(idStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid product_id")
			return
		}
		productIDs[i] = pid
	}

	orderAmount, err := decimal.NewFromString(req.OrderAmount)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order_amount")
		return
	}

	at := time.Now()
	if req.At != "" {
		at, err = time.Parse(time.RFC3339, req.At)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid at format (use RFC3339)")
			return
		}
	}

	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.promotionService.ValidatePromotion(ctx, companyID, promotionID, customerID, productIDs, orderAmount, at)
	if err != nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"data":    map[string]interface{}{"valid": false, "error": err.Error()},
		})
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]interface{}{"valid": true},
	})
}

type evaluatePromotionResponse struct {
	Applicable     bool    `json:"is_applicable"`
	DiscountAmount string  `json:"discount_amount"`
	Reason         *string `json:"reason,omitempty"`
}

// EvaluatePromotion handles POST /promotions/evaluate
func (h *PromotionHandler) EvaluatePromotion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req evaluatePromotionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	promotionID, err := uuid.Parse(req.PromotionID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion_id")
		return
	}

	var customerID *uuid.UUID
	if req.CustomerID != nil && *req.CustomerID != "" {
		parsed, err := uuid.Parse(*req.CustomerID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
			return
		}
		customerID = &parsed
	}

	orderAmount, err := decimal.NewFromString(req.OrderAmount)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order_amount")
		return
	}

	at, err := time.Parse(time.RFC3339, req.At)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid at format (use RFC3339)")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	evalReq := &service.EvaluatePromotionRequest{
		CompanyID:   companyID,
		PromotionID: promotionID,
		CustomerID:  customerID,
		OrderAmount: orderAmount,
		At:          at,
	}
	result, err := h.promotionService.EvaluatePromotion(ctx, evalReq)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := evaluatePromotionResponse{
		Applicable:     result.Applicable,
		DiscountAmount: result.DiscountAmount.String(),
		Reason:         &result.Reason,
	}
	if result.Reason == "" {
		resp.Reason = nil
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// CalculatePromotionDiscount handles POST /promotions/{id}/calculate-discount
func (h *PromotionHandler) CalculatePromotionDiscount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	promotionID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req struct {
		Subtotal   string   `json:"subtotal"`
		ProductIDs []string `json:"product_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	subtotal, err := decimal.NewFromString(req.Subtotal)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subtotal")
		return
	}
	productIDs := make([]uuid.UUID, len(req.ProductIDs))
	for i, idStr := range req.ProductIDs {
		pid, err := uuid.Parse(idStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid product_id")
			return
		}
		productIDs[i] = pid
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	discount, err := h.promotionService.CalculatePromotionDiscount(ctx, promotionID, subtotal, productIDs)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]interface{}{"discount_amount": discount.String()},
	})
}

// ---------- Apply/Remove to Entities ----------

// ApplyPromotionToOrder handles POST /promotions/apply-to-order
func (h *PromotionHandler) ApplyPromotionToOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req promotionApplyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	orderID, err := uuid.Parse(req.EntityID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id (order ID)")
		return
	}
	promotionID, err := uuid.Parse(req.PromotionID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion_id")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "promotion:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	promotion, discountAmount, err := h.promotionService.ApplyPromotionToOrder(ctx, companyID, orderID, promotionID, userID)
	if err != nil {
		h.logger.Error("failed to apply promotion to order", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := applyPromotionResponse{
		PromotionID:    promotion.PromotionID.String(),
		DiscountAmount: discountAmount.String(),
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ApplyPromotionToQuote handles POST /promotions/apply-to-quote
func (h *PromotionHandler) ApplyPromotionToQuote(w http.ResponseWriter, r *http.Request) {
	h.applyPromotionToEntity(w, r, "quote")
}

// ApplyPromotionToInvoice handles POST /promotions/apply-to-invoice
func (h *PromotionHandler) ApplyPromotionToInvoice(w http.ResponseWriter, r *http.Request) {
	h.applyPromotionToEntity(w, r, "invoice")
}

func (h *PromotionHandler) applyPromotionToEntity(w http.ResponseWriter, r *http.Request, entityType string) {
	ctx := r.Context()

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req promotionApplyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	entityID, err := uuid.Parse(req.EntityID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}
	promotionID, err := uuid.Parse(req.PromotionID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion_id")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "promotion:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	var promotion *discount.Promotion
	var discountAmount decimal.Decimal
	switch entityType {
	case "quote":
		promotion, discountAmount, err = h.promotionService.ApplyPromotionToQuote(ctx, companyID, entityID, promotionID, userID)
	case "invoice":
		promotion, discountAmount, err = h.promotionService.ApplyPromotionToInvoice(ctx, companyID, entityID, promotionID, userID)
	default:
		h.respondWithError(w, http.StatusBadRequest, "unsupported entity type")
		return
	}
	if err != nil {
		h.logger.Error("failed to apply promotion to "+entityType, zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := applyPromotionResponse{
		PromotionID:    promotion.PromotionID.String(),
		DiscountAmount: discountAmount.String(),
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// RemovePromotionFromOrder handles DELETE /promotions/remove-from-order
func (h *PromotionHandler) RemovePromotionFromOrder(w http.ResponseWriter, r *http.Request) {
	h.removePromotionFromEntity(w, r, "order")
}

// RemovePromotionFromQuote handles DELETE /promotions/remove-from-quote
func (h *PromotionHandler) RemovePromotionFromQuote(w http.ResponseWriter, r *http.Request) {
	h.removePromotionFromEntity(w, r, "quote")
}

// RemovePromotionFromInvoice handles DELETE /promotions/remove-from-invoice
func (h *PromotionHandler) RemovePromotionFromInvoice(w http.ResponseWriter, r *http.Request) {
	h.removePromotionFromEntity(w, r, "invoice")
}

func (h *PromotionHandler) removePromotionFromEntity(w http.ResponseWriter, r *http.Request, entityType string) {
	ctx := r.Context()

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req struct {
		EntityID    string `json:"entity_id"`
		PromotionID string `json:"promotion_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	entityID, err := uuid.Parse(req.EntityID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}
	promotionID, err := uuid.Parse(req.PromotionID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion_id")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "promotion:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	switch entityType {
	case "order":
		err = h.promotionService.RemovePromotionFromOrder(ctx, companyID, entityID, promotionID, userID)
	case "quote":
		err = h.promotionService.RemovePromotionFromQuote(ctx, companyID, entityID, promotionID, userID)
	case "invoice":
		err = h.promotionService.RemovePromotionFromInvoice(ctx, companyID, entityID, promotionID, userID)
	default:
		h.respondWithError(w, http.StatusBadRequest, "unsupported entity type")
		return
	}
	if err != nil {
		h.logger.Error("failed to remove promotion from "+entityType, zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("promotion removed from %s", entityType),
	})
}

// ClearPromotions handles DELETE /promotions/clear
func (h *PromotionHandler) ClearPromotions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req struct {
		EntityType string `json:"entity_type"`
		EntityID   string `json:"entity_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	entityID, err := uuid.Parse(req.EntityID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "promotion:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.promotionService.ClearPromotions(ctx, companyID, req.EntityType, entityID, userID)
	if err != nil {
		h.logger.Error("failed to clear promotions", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "promotions cleared",
	})
}

// RecordPromotionUsage handles POST /promotions/record-usage
func (h *PromotionHandler) RecordPromotionUsage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req recordUsageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	promotionID, err := uuid.Parse(req.PromotionID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion_id")
		return
	}
	entityID, err := uuid.Parse(req.EntityID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}
	var customerID *uuid.UUID
	if req.CustomerID != nil && *req.CustomerID != "" {
		parsed, err := uuid.Parse(*req.CustomerID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
			return
		}
		customerID = &parsed
	}
	discountAmount, err := decimal.NewFromString(req.DiscountAmount)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid discount_amount")
		return
	}
	usedAt, err := time.Parse(time.RFC3339, req.UsedAt)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid used_at format (use RFC3339)")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "promotion:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	usageReq := &service.RecordPromotionUsageRequest{
		CompanyID:      companyID,
		PromotionID:    promotionID,
		EntityType:     req.EntityType,
		EntityID:       entityID,
		CustomerID:     customerID,
		DiscountAmount: discountAmount,
		UsedAt:         usedAt,
	}
	err = h.promotionService.RecordPromotionUsage(ctx, usageReq)
	if err != nil {
		h.logger.Error("failed to record promotion usage", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "usage recorded",
	})
}

// GetPromotionUsageCount handles GET /promotions/{id}/usage-count
func (h *PromotionHandler) GetPromotionUsageCount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	promotionID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	count, err := h.promotionService.GetPromotionUsageCount(ctx, companyID, promotionID)
	if err != nil {
		h.logger.Error("failed to get usage count", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]interface{}{"usage_count": count},
	})
}

// GetCustomerPromotionUsageCount handles GET /promotions/customer-usage-count
func (h *PromotionHandler) GetCustomerPromotionUsageCount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	promotionIDStr := r.URL.Query().Get("promotion_id")
	if promotionIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "promotion_id query parameter is required")
		return
	}
	promotionID, err := uuid.Parse(promotionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion_id")
		return
	}
	customerIDStr := r.URL.Query().Get("customer_id")
	if customerIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "customer_id query parameter is required")
		return
	}
	customerID, err := uuid.Parse(customerIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	count, err := h.promotionService.GetCustomerPromotionUsageCount(ctx, companyID, promotionID, customerID)
	if err != nil {
		h.logger.Error("failed to get customer usage count", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]interface{}{"usage_count": count},
	})
}

// GetPromotionUsageHistory handles GET /promotions/{id}/usage-history
func (h *PromotionHandler) GetPromotionUsageHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	promotionID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	limit := 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	offset := 0
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}
	sort := service.Sort{
		Field:     r.URL.Query().Get("sort_field"),
		Direction: r.URL.Query().Get("sort_dir"),
	}
	if sort.Field == "" {
		sort.Field = "used_at"
	}
	if sort.Direction == "" {
		sort.Direction = "DESC"
	}
	pagination := service.Pagination{Limit: limit, Offset: offset}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	usages, total, err := h.promotionService.GetPromotionUsageHistory(ctx, companyID, promotionID, pagination, sort)
	if err != nil {
		h.logger.Error("failed to get usage history", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	response := make([]map[string]interface{}, len(usages))
	for i, u := range usages {
		response[i] = map[string]interface{}{
			"application_id": u.ApplicationID.String(),
			"order_id":       u.OrderID,
			"invoice_id":     u.InvoiceID,
			"discount_type":  u.DiscountType,
			"discount_id":    u.DiscountID,
			"discount_name":  u.DiscountName,
			"amount":         u.Amount.String(),
			"created_at":     u.CreatedAt.Format(time.RFC3339),
		}
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"usages": response,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		},
	})
}

// CanStackPromotion handles GET /promotions/can-stack
func (h *PromotionHandler) CanStackPromotion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	firstIDStr := r.URL.Query().Get("first_promotion_id")
	if firstIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "first_promotion_id query parameter is required")
		return
	}
	firstID, err := uuid.Parse(firstIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid first_promotion_id")
		return
	}
	secondIDStr := r.URL.Query().Get("second_promotion_id")
	if secondIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "second_promotion_id query parameter is required")
		return
	}
	secondID, err := uuid.Parse(secondIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid second_promotion_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	canStack, err := h.promotionService.CanStackPromotion(ctx, companyID, firstID, secondID)
	if err != nil {
		h.logger.Error("failed to check stacking", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]interface{}{"can_stack": canStack},
	})
}

// ValidatePromotionStacking handles POST /promotions/validate-stacking
func (h *PromotionHandler) ValidatePromotionStacking(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req struct {
		PromotionIDs []string `json:"promotion_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	promotionIDs := make([]uuid.UUID, len(req.PromotionIDs))
	for i, idStr := range req.PromotionIDs {
		pid, err := uuid.Parse(idStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid promotion_id")
			return
		}
		promotionIDs[i] = pid
	}

	if !h.hasPermission(ctx, companyID, userID, "promotion:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.promotionService.ValidatePromotionStacking(ctx, companyID, promotionIDs)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "stacking valid",
	})
}

// GetStackablePromotions handles GET /promotions/{id}/stackable
func (h *PromotionHandler) GetStackablePromotions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	promotionID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	stackableIDs, err := h.promotionService.GetStackablePromotions(ctx, companyID, promotionID)
	if err != nil {
		h.logger.Error("failed to get stackable promotions", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	idStrs := make([]string, len(stackableIDs))
	for i, id := range stackableIDs {
		idStrs[i] = id.String()
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]interface{}{"stackable_promotion_ids": idStrs},
	})
}

// GetTopPromotions handles GET /promotions/top
func (h *PromotionHandler) GetTopPromotions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	limit := 10
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	var from, to *time.Time
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			from = &t
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			to = &t
		}
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	promotions, err := h.promotionService.GetTopPromotions(ctx, companyID, limit, from, to)
	if err != nil {
		h.logger.Error("failed to get top promotions", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get top promotions")
		return
	}

	summaries := make([]promotionSummary, len(promotions))
	for i, p := range promotions {
		summaries[i] = promotionSummary{
			PromotionID:  p.PromotionID.String(),
			Name:         p.Name,
			StartDate:    p.StartDate.Format(time.RFC3339),
			EndDate:      p.EndDate.Format(time.RFC3339),
			IsActive:     p.IsActive,
			Priority:     p.Priority,
			StackingType: p.StackingType,
		}
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

// GetMostUsedPromotions handles GET /promotions/most-used
func (h *PromotionHandler) GetMostUsedPromotions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	limit := 10
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	var from, to *time.Time
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			from = &t
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			to = &t
		}
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	promotions, err := h.promotionService.GetMostUsedPromotions(ctx, companyID, limit, from, to)
	if err != nil {
		h.logger.Error("failed to get most used promotions", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get most used promotions")
		return
	}

	summaries := make([]promotionSummary, len(promotions))
	for i, p := range promotions {
		summaries[i] = promotionSummary{
			PromotionID:  p.PromotionID.String(),
			Name:         p.Name,
			StartDate:    p.StartDate.Format(time.RFC3339),
			EndDate:      p.EndDate.Format(time.RFC3339),
			IsActive:     p.IsActive,
			Priority:     p.Priority,
			StackingType: p.StackingType,
		}
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

// GetHighestRevenuePromotions handles GET /promotions/highest-revenue
func (h *PromotionHandler) GetHighestRevenuePromotions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	limit := 10
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	var from, to *time.Time
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			from = &t
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			to = &t
		}
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	promotions, err := h.promotionService.GetHighestRevenuePromotions(ctx, companyID, limit, from, to)
	if err != nil {
		h.logger.Error("failed to get highest revenue promotions", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get highest revenue promotions")
		return
	}

	summaries := make([]promotionSummary, len(promotions))
	for i, p := range promotions {
		summaries[i] = promotionSummary{
			PromotionID:  p.PromotionID.String(),
			Name:         p.Name,
			StartDate:    p.StartDate.Format(time.RFC3339),
			EndDate:      p.EndDate.Format(time.RFC3339),
			IsActive:     p.IsActive,
			Priority:     p.Priority,
			StackingType: p.StackingType,
		}
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

// GetTotalPromotionDiscountAmount handles GET /promotions/total-discount-amount
func (h *PromotionHandler) GetTotalPromotionDiscountAmount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var from, to *time.Time
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			from = &t
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			to = &t
		}
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	total, err := h.promotionService.GetTotalPromotionDiscountAmount(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get total discount amount", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get total discount amount")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]interface{}{"total_discount_amount": total.String()},
	})
}

// GetPromotionConversionImpact handles GET /promotions/{id}/conversion-impact
func (h *PromotionHandler) GetPromotionConversionImpact(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	promotionID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var from, to *time.Time
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			from = &t
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			to = &t
		}
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	impact, err := h.promotionService.GetPromotionConversionImpact(ctx, companyID, promotionID, from, to)
	if err != nil {
		h.logger.Error("failed to get conversion impact", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]interface{}{"conversion_impact": impact.String()},
	})
}

// GetPromotionRedemptionRate handles GET /promotions/{id}/redemption-rate
func (h *PromotionHandler) GetPromotionRedemptionRate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	promotionID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var from, to *time.Time
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			from = &t
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			to = &t
		}
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	rate, err := h.promotionService.GetPromotionRedemptionRate(ctx, companyID, promotionID, from, to)
	if err != nil {
		h.logger.Error("failed to get redemption rate", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]interface{}{"redemption_rate": rate.String()},
	})
}

// PromotionExists handles GET /promotions/{id}/exists
func (h *PromotionHandler) PromotionExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	promotionID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	exists, err := h.promotionService.PromotionExists(ctx, companyID, promotionID)
	if err != nil {
		h.logger.Error("failed to check promotion exists", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]interface{}{"exists": exists},
	})
}

// PromotionCodeExists handles GET /promotions/code-exists
func (h *PromotionHandler) PromotionCodeExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		h.respondWithError(w, http.StatusBadRequest, "code query parameter is required")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	exists, err := h.promotionService.PromotionCodeExists(ctx, companyID, code)
	if err != nil {
		h.logger.Error("failed to check code exists", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]interface{}{"exists": exists},
	})
}

// PromotionRuleExists handles GET /promotions/rules/{ruleId}/exists
func (h *PromotionHandler) PromotionRuleExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ruleID, err := h.parseUUIDParam(r, "ruleId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid rule ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	exists, err := h.promotionService.PromotionRuleExists(ctx, companyID, ruleID)
	if err != nil {
		h.logger.Error("failed to check rule exists", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]interface{}{"exists": exists},
	})
}

// IsPromotionExpired handles GET /promotions/{id}/expired
func (h *PromotionHandler) IsPromotionExpired(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	promotionID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	atStr := r.URL.Query().Get("at")
	at := time.Now()
	if atStr != "" {
		parsed, err := time.Parse(time.RFC3339, atStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid at format")
			return
		}
		at = parsed
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	expired, err := h.promotionService.IsPromotionExpired(ctx, companyID, promotionID, at)
	if err != nil {
		h.logger.Error("failed to check expired", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]interface{}{"expired": expired},
	})
}

// IsPromotionUsageLimitReached handles GET /promotions/{id}/usage-limit-reached
func (h *PromotionHandler) IsPromotionUsageLimitReached(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	promotionID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	reached, err := h.promotionService.IsPromotionUsageLimitReached(ctx, companyID, promotionID)
	if err != nil {
		h.logger.Error("failed to check usage limit", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]interface{}{"usage_limit_reached": reached},
	})
}

// IsCustomerPromotionUsageLimitReached handles GET /promotions/customer-usage-limit-reached
func (h *PromotionHandler) IsCustomerPromotionUsageLimitReached(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	promotionIDStr := r.URL.Query().Get("promotion_id")
	if promotionIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "promotion_id query parameter is required")
		return
	}
	promotionID, err := uuid.Parse(promotionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid promotion_id")
		return
	}
	customerIDStr := r.URL.Query().Get("customer_id")
	if customerIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "customer_id query parameter is required")
		return
	}
	customerID, err := uuid.Parse(customerIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "promotion:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	reached, err := h.promotionService.IsCustomerPromotionUsageLimitReached(ctx, companyID, promotionID, customerID)
	if err != nil {
		h.logger.Error("failed to check customer usage limit", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]interface{}{"usage_limit_reached": reached},
	})
}

// ---------- Helper to convert promotion model to response ----------
func (h *PromotionHandler) promotionToResponse(p *discount.Promotion) createPromotionResponse {
	resp := createPromotionResponse{
		PromotionID:  p.PromotionID.String(),
		CompanyID:    p.CompanyID.String(),
		Name:         p.Name,
		Description:  p.Description,
		StartDate:    p.StartDate.Format(time.RFC3339),
		EndDate:      p.EndDate.Format(time.RFC3339),
		IsActive:     p.IsActive,
		Priority:     p.Priority,
		StackingType: p.StackingType, // NEW
		CreatedAt:    p.CreatedAt.Format(time.RFC3339),
		UpdatedAt:    p.UpdatedAt.Format(time.RFC3339),
	}
	return resp
}
