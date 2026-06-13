// file: internal/sales/handler/coupon_handler.go
package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"
	"gorm.io/datatypes"

	"auth-service/internal/sales/models/discount"
	"auth-service/internal/sales/models/enums"
	"auth-service/internal/sales/service"
)

// CouponHandler handles HTTP requests for coupon management.
type CouponHandler struct {
	couponService service.CouponService
	*BaseHandler
}

// NewCouponHandler creates a new CouponHandler.
func NewCouponHandler(couponService service.CouponService, logger *zap.Logger) *CouponHandler {
	return &CouponHandler{
		couponService: couponService,
		BaseHandler:   &BaseHandler{logger: logger.Named("coupon_handler")},
	}
}

// injectIdempotencyKey adds the idempotency key from the request header into the context.
func (h *CouponHandler) injectIdempotencyKey(ctx context.Context, r *http.Request) context.Context {
	key := h.getIdempotencyKey(r)
	if key != "" {
		return context.WithValue(ctx, "idempotency_key", key)
	}
	return ctx
}

// ---------- Request/Response Types ----------

type createCouponRequest struct {
	Code              string  `json:"code"`
	DiscountType      string  `json:"discount_type"`
	DiscountValue     string  `json:"discount_value"`
	MaxDiscountAmount *string `json:"max_discount_amount,omitempty"`
	StartDate         string  `json:"start_date"`
	EndDate           string  `json:"end_date"`
	UsageLimit        *int    `json:"usage_limit,omitempty"`
	PerUserLimit      *int    `json:"per_user_limit,omitempty"`
	MinOrderAmount    *string `json:"min_order_amount,omitempty"`
	ApplicableItems   *string `json:"applicable_items,omitempty"`
	StackingType      string  `json:"stacking_type,omitempty"` // NEW
}

type createCouponResponse struct {
	CouponID          string  `json:"coupon_id"`
	CompanyID         string  `json:"company_id"`
	Code              string  `json:"code"`
	DiscountType      string  `json:"discount_type"`
	DiscountValue     string  `json:"discount_value"`
	MaxDiscountAmount *string `json:"max_discount_amount,omitempty"`
	StartDate         string  `json:"start_date"`
	EndDate           string  `json:"end_date"`
	UsageLimit        *int    `json:"usage_limit,omitempty"`
	PerUserLimit      *int    `json:"per_user_limit,omitempty"`
	MinOrderAmount    *string `json:"min_order_amount,omitempty"`
	ApplicableItems   *string `json:"applicable_items,omitempty"`
	StackingType      string  `json:"stacking_type,omitempty"` // NEW
	IsActive          bool    `json:"is_active"`
	CreatedAt         string  `json:"created_at"`
	UpdatedAt         string  `json:"updated_at"`
}

type updateCouponRequest struct {
	DiscountType      *string `json:"discount_type,omitempty"`
	DiscountValue     *string `json:"discount_value,omitempty"`
	MaxDiscountAmount *string `json:"max_discount_amount,omitempty"`
	StartDate         *string `json:"start_date,omitempty"`
	EndDate           *string `json:"end_date,omitempty"`
	UsageLimit        *int    `json:"usage_limit,omitempty"`
	PerUserLimit      *int    `json:"per_user_limit,omitempty"`
	MinOrderAmount    *string `json:"min_order_amount,omitempty"`
	ApplicableItems   *string `json:"applicable_items,omitempty"`
	StackingType      *string `json:"stacking_type,omitempty"` // NEW
}

type validateCouponRequest struct {
	CouponCode  string   `json:"coupon_code"`
	CustomerID  *string  `json:"customer_id,omitempty"`
	OrderAmount string   `json:"order_amount"`
	ProductIDs  []string `json:"product_ids,omitempty"`
	At          string   `json:"at"`
}

type calculateDiscountRequest struct {
	Subtotal string `json:"subtotal"`
}

type calculateDiscountForProductsRequest struct {
	Subtotal   string   `json:"subtotal"`
	ProductIDs []string `json:"product_ids"`
}

type applyCouponToEntityRequest struct {
	EntityID   string `json:"entity_id"`
	CouponCode string `json:"coupon_code"`
}

type removeCouponFromEntityRequest struct {
	EntityID   string `json:"entity_id"`
	CouponCode string `json:"coupon_code"`
}

type recordCouponUsageRequest struct {
	CouponID       string  `json:"coupon_id"`
	OrderID        string  `json:"order_id"`
	CustomerID     *string `json:"customer_id,omitempty"`
	DiscountAmount string  `json:"discount_amount"`
	UsedAt         string  `json:"used_at"`
}

type couponSummary struct {
	CouponID      string  `json:"coupon_id"`
	Code          string  `json:"code"`
	DiscountType  string  `json:"discount_type"`
	DiscountValue string  `json:"discount_value"`
	IsActive      bool    `json:"is_active"`
	StartDate     string  `json:"start_date"`
	EndDate       string  `json:"end_date"`
	UsageCount    int64   `json:"usage_count,omitempty"`
	TotalDiscount *string `json:"total_discount,omitempty"`
}

type listCouponsResponse struct {
	Coupons []couponSummary `json:"coupons"`
	Total   int64           `json:"total"`
	Limit   int             `json:"limit"`
	Offset  int             `json:"offset"`
}

type couponUsageHistoryResponse struct {
	UsageID        string `json:"usage_id"`
	CouponID       string `json:"coupon_id"`
	CustomerID     string `json:"customer_id"`
	OrderID        string `json:"order_id"`
	DiscountAmount string `json:"discount_amount"`
	UsedAt         string `json:"used_at"`
}

// ---------- Handler Methods ----------

// CreateCoupon handles POST /coupons
// CreateCoupon handles POST /coupons
func (h *CouponHandler) CreateCoupon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ctx = h.injectIdempotencyKey(ctx, r)

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

	var req createCouponRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Code == "" {
		h.respondWithError(w, http.StatusBadRequest, "code is required")
		return
	}
	if req.DiscountType == "" {
		h.respondWithError(w, http.StatusBadRequest, "discount_type is required")
		return
	}
	discountValue, err := decimal.NewFromString(req.DiscountValue)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid discount_value")
		return
	}
	startDate, err := time.Parse(time.RFC3339, req.StartDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid start_date (RFC3339)")
		return
	}
	endDate, err := time.Parse(time.RFC3339, req.EndDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid end_date (RFC3339)")
		return
	}
	var maxDiscountAmount *decimal.Decimal
	if req.MaxDiscountAmount != nil && *req.MaxDiscountAmount != "" {
		val, err := decimal.NewFromString(*req.MaxDiscountAmount)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid max_discount_amount")
			return
		}
		maxDiscountAmount = &val
	}
	var minOrderAmount *decimal.Decimal
	if req.MinOrderAmount != nil && *req.MinOrderAmount != "" {
		val, err := decimal.NewFromString(*req.MinOrderAmount)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid min_order_amount")
			return
		}
		minOrderAmount = &val
	}
	var applicableItems datatypes.JSON
	if req.ApplicableItems != nil && *req.ApplicableItems != "" {
		applicableItems = datatypes.JSON(*req.ApplicableItems)
	}

	// --- Validate stacking_type ---
	allowedStacking := map[string]bool{"stackable": true, "exclusive": true, "none": true}
	if req.StackingType != "" && !allowedStacking[req.StackingType] {
		h.respondWithError(w, http.StatusBadRequest, "stacking_type must be 'stackable', 'exclusive', or 'none'")
		return
	}
	// ------------------------------

	if !h.hasPermission(ctx, companyID, userID, "coupon:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	svcReq := &service.CreateCouponRequest{
		CompanyID:         companyID,
		Code:              req.Code,
		DiscountType:      enums.DiscountType(req.DiscountType),
		DiscountValue:     discountValue,
		MaxDiscountAmount: maxDiscountAmount,
		StartDate:         startDate,
		EndDate:           endDate,
		UsageLimit:        req.UsageLimit,
		PerUserLimit:      req.PerUserLimit,
		MinOrderAmount:    minOrderAmount,
		ApplicableItems:   applicableItems,
		StackingType:      req.StackingType, // may be empty – service will default
		CreatedBy:         &userID,
	}

	coupon, err := h.couponService.CreateCoupon(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to create coupon", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.couponToResponse(coupon)
	location := fmt.Sprintf("/coupons/%s", coupon.CouponID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateCoupon handles PUT /coupons/{id}
// UpdateCoupon handles PUT /coupons/{id}
func (h *CouponHandler) UpdateCoupon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ctx = h.injectIdempotencyKey(ctx, r)

	couponID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid coupon ID")
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

	if !h.hasPermission(ctx, companyID, userID, "coupon:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateCouponRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// --- Validate stacking_type if provided ---
	allowedStacking := map[string]bool{"stackable": true, "exclusive": true, "none": true}
	if req.StackingType != nil && *req.StackingType != "" && !allowedStacking[*req.StackingType] {
		h.respondWithError(w, http.StatusBadRequest, "stacking_type must be 'stackable', 'exclusive', or 'none'")
		return
	}
	// -----------------------------------------

	svcReq := &service.UpdateCouponRequest{UpdatedBy: &userID}
	if req.DiscountType != nil {
		dt := enums.DiscountType(*req.DiscountType)
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
	if req.MaxDiscountAmount != nil {
		if *req.MaxDiscountAmount == "" {
			svcReq.MaxDiscountAmount = nil
		} else {
			val, err := decimal.NewFromString(*req.MaxDiscountAmount)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid max_discount_amount")
				return
			}
			svcReq.MaxDiscountAmount = &val
		}
	}
	if req.StartDate != nil {
		start, err := time.Parse(time.RFC3339, *req.StartDate)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid start_date")
			return
		}
		svcReq.StartDate = &start
	}
	if req.EndDate != nil {
		end, err := time.Parse(time.RFC3339, *req.EndDate)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid end_date")
			return
		}
		svcReq.EndDate = &end
	}
	if req.UsageLimit != nil {
		svcReq.UsageLimit = req.UsageLimit
	}
	if req.PerUserLimit != nil {
		svcReq.PerUserLimit = req.PerUserLimit
	}
	if req.MinOrderAmount != nil {
		if *req.MinOrderAmount == "" {
			svcReq.MinOrderAmount = nil
		} else {
			val, err := decimal.NewFromString(*req.MinOrderAmount)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid min_order_amount")
				return
			}
			svcReq.MinOrderAmount = &val
		}
	}
	if req.ApplicableItems != nil {
		if *req.ApplicableItems == "" {
			svcReq.ApplicableItems = nil
		} else {
			svcReq.ApplicableItems = datatypes.JSON(*req.ApplicableItems)
		}
	}
	if req.StackingType != nil {
		svcReq.StackingType = req.StackingType
	}

	coupon, err := h.couponService.UpdateCoupon(ctx, companyID, couponID, svcReq)
	if err != nil {
		h.logger.Error("failed to update coupon", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.couponToResponse(coupon)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DeleteCoupon handles DELETE /coupons/{id}
func (h *CouponHandler) DeleteCoupon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ctx = h.injectIdempotencyKey(ctx, r)

	couponID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid coupon ID")
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

	if !h.hasPermission(ctx, companyID, userID, "coupon:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.couponService.DeleteCoupon(ctx, companyID, couponID, userID)
	if err != nil {
		h.logger.Error("failed to delete coupon", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "coupon deleted successfully",
	})
}

// GetCouponByID handles GET /coupons/{id}
func (h *CouponHandler) GetCouponByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	couponID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid coupon ID")
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

	if !h.hasPermission(ctx, companyID, userID, "coupon:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	coupon, err := h.couponService.GetCouponByID(ctx, companyID, couponID)
	if err != nil {
		h.logger.Error("failed to get coupon", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.couponToResponse(coupon)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetCouponByCode handles GET /coupons/by-code
func (h *CouponHandler) GetCouponByCode(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "coupon:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	coupon, err := h.couponService.GetCouponByCode(ctx, companyID, code)
	if err != nil {
		h.logger.Error("failed to get coupon by code", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.couponToResponse(coupon)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ListCoupons handles GET /coupons
func (h *CouponHandler) ListCoupons(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "coupon:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	filter := service.CouponListFilter{
		CompanyID: companyID,
	}
	if activeStr := r.URL.Query().Get("active"); activeStr != "" {
		active, err := strconv.ParseBool(activeStr)
		if err == nil {
			filter.IsActive = &active
		}
	}
	if code := r.URL.Query().Get("code"); code != "" {
		filter.Code = &code
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

	coupons, total, err := h.couponService.ListCoupons(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list coupons", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list coupons")
		return
	}

	summaries := make([]couponSummary, len(coupons))
	for i, c := range coupons {
		summaries[i] = couponSummary{
			CouponID:      c.CouponID.String(),
			Code:          c.Code,
			DiscountType:  string(c.DiscountType),
			DiscountValue: c.DiscountValue.String(),
			IsActive:      c.IsActive,
			StartDate:     c.StartDate.Format(time.RFC3339),
			EndDate:       c.EndDate.Format(time.RFC3339),
		}
	}

	resp := listCouponsResponse{
		Coupons: summaries,
		Total:   total,
		Limit:   limit,
		Offset:  offset,
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// SearchCoupons handles GET /coupons/search
func (h *CouponHandler) SearchCoupons(w http.ResponseWriter, r *http.Request) {
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
	if !h.hasPermission(ctx, companyID, userID, "coupon:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	coupons, total, err := h.couponService.SearchCoupons(ctx, companyID, query, limit, offset)
	if err != nil {
		h.logger.Error("failed to search coupons", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to search coupons")
		return
	}

	summaries := make([]couponSummary, len(coupons))
	for i, c := range coupons {
		summaries[i] = couponSummary{
			CouponID:      c.CouponID.String(),
			Code:          c.Code,
			DiscountType:  string(c.DiscountType),
			DiscountValue: c.DiscountValue.String(),
			IsActive:      c.IsActive,
			StartDate:     c.StartDate.Format(time.RFC3339),
			EndDate:       c.EndDate.Format(time.RFC3339),
		}
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"coupons": summaries,
			"total":   total,
			"limit":   limit,
			"offset":  offset,
		},
	})
}

// GetActiveCoupons handles GET /coupons/active
func (h *CouponHandler) GetActiveCoupons(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	atStr := r.URL.Query().Get("at")
	var at time.Time
	if atStr == "" {
		at = time.Now()
	} else {
		at, err = time.Parse(time.RFC3339, atStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid at timestamp")
			return
		}
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "coupon:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	coupons, err := h.couponService.GetActiveCoupons(ctx, companyID, at)
	if err != nil {
		h.logger.Error("failed to get active coupons", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get active coupons")
		return
	}

	summaries := make([]couponSummary, len(coupons))
	for i, c := range coupons {
		summaries[i] = couponSummary{
			CouponID:      c.CouponID.String(),
			Code:          c.Code,
			DiscountType:  string(c.DiscountType),
			DiscountValue: c.DiscountValue.String(),
			IsActive:      c.IsActive,
			StartDate:     c.StartDate.Format(time.RFC3339),
			EndDate:       c.EndDate.Format(time.RFC3339),
		}
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

// ActivateCoupon handles POST /coupons/{id}/activate
func (h *CouponHandler) ActivateCoupon(w http.ResponseWriter, r *http.Request) {
	h.updateCouponActivation(w, r, true)
}

// DeactivateCoupon handles POST /coupons/{id}/deactivate
func (h *CouponHandler) DeactivateCoupon(w http.ResponseWriter, r *http.Request) {
	h.updateCouponActivation(w, r, false)
}

func (h *CouponHandler) updateCouponActivation(w http.ResponseWriter, r *http.Request, activate bool) {
	ctx := r.Context()
	ctx = h.injectIdempotencyKey(ctx, r)

	couponID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid coupon ID")
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

	if !h.hasPermission(ctx, companyID, userID, "coupon:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if activate {
		err = h.couponService.ActivateCoupon(ctx, companyID, couponID, userID)
	} else {
		err = h.couponService.DeactivateCoupon(ctx, companyID, couponID, userID)
	}
	if err != nil {
		h.logger.Error("failed to update coupon activation", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	msg := "deactivated"
	if activate {
		msg = "activated"
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("coupon %s", msg),
	})
}

// ExpireCoupon handles POST /coupons/{id}/expire
func (h *CouponHandler) ExpireCoupon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ctx = h.injectIdempotencyKey(ctx, r)

	couponID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid coupon ID")
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

	if !h.hasPermission(ctx, companyID, userID, "coupon:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.couponService.ExpireCoupon(ctx, companyID, couponID, userID)
	if err != nil {
		h.logger.Error("failed to expire coupon", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "coupon expired",
	})
}

// ValidateCoupon handles POST /coupons/validate
func (h *CouponHandler) ValidateCoupon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req validateCouponRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
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
	productIDs := make([]uuid.UUID, len(req.ProductIDs))
	for i, pid := range req.ProductIDs {
		parsed, err := uuid.Parse(pid)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid product_id in list")
			return
		}
		productIDs[i] = parsed
	}
	at, err := time.Parse(time.RFC3339, req.At)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid at timestamp")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "coupon:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.couponService.ValidateCoupon(ctx, companyID, req.CouponCode, customerID, orderAmount, productIDs, at)
	if err != nil {
		h.logger.Error("coupon validation failed", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "coupon is valid",
	})
}

// CalculateDiscount handles POST /coupons/{id}/calculate-discount
func (h *CouponHandler) CalculateDiscount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	couponID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid coupon ID")
		return
	}

	var req calculateDiscountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	subtotal, err := decimal.NewFromString(req.Subtotal)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subtotal")
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
	if !h.hasPermission(ctx, companyID, userID, "coupon:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	discountAmount, err := h.couponService.CalculateDiscount(ctx, companyID, couponID, subtotal)
	if err != nil {
		h.logger.Error("failed to calculate discount", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]string{
			"discount_amount": discountAmount.String(),
		},
	})
}

func (h *CouponHandler) CalculateDiscountForProducts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	couponID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid coupon ID")
		return
	}

	var req calculateDiscountForProductsRequest
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
	for i, pid := range req.ProductIDs {
		parsed, err := uuid.Parse(pid)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid product_id in list")
			return
		}
		productIDs[i] = parsed
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
	if !h.hasPermission(ctx, companyID, userID, "coupon:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	discountAmount, err := h.couponService.CalculateDiscountForProducts(ctx, companyID, couponID, subtotal, productIDs)
	if err != nil {
		h.logger.Error("failed to calculate discount for products", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]string{
			"discount_amount": discountAmount.String(),
		},
	})
}

// ApplyCouponToOrder handles POST /coupons/apply-to-order
func (h *CouponHandler) ApplyCouponToOrder(w http.ResponseWriter, r *http.Request) {
	h.applyCouponToEntity(w, r, "order")
}

// ApplyCouponToQuote handles POST /coupons/apply-to-quote
func (h *CouponHandler) ApplyCouponToQuote(w http.ResponseWriter, r *http.Request) {
	h.applyCouponToEntity(w, r, "quote")
}

// ApplyCouponToInvoice handles POST /coupons/apply-to-invoice
func (h *CouponHandler) ApplyCouponToInvoice(w http.ResponseWriter, r *http.Request) {
	h.applyCouponToEntity(w, r, "invoice")
}

func (h *CouponHandler) applyCouponToEntity(w http.ResponseWriter, r *http.Request, entityType string) {
	ctx := r.Context()
	ctx = h.injectIdempotencyKey(ctx, r)

	var req applyCouponToEntityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	entityID, err := uuid.Parse(req.EntityID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "coupon:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var coupon *discount.Coupon
	var discountAmount decimal.Decimal
	switch entityType {
	case "order":
		coupon, discountAmount, err = h.couponService.ApplyCouponToOrder(ctx, companyID, entityID, req.CouponCode, userID)
	case "quote":
		coupon, discountAmount, err = h.couponService.ApplyCouponToQuote(ctx, companyID, entityID, req.CouponCode, userID)
	case "invoice":
		coupon, discountAmount, err = h.couponService.ApplyCouponToInvoice(ctx, companyID, entityID, req.CouponCode, userID)
	default:
		h.respondWithError(w, http.StatusBadRequest, "invalid entity type")
		return
	}
	if err != nil {
		h.logger.Error("failed to apply coupon to entity", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := map[string]interface{}{
		"coupon":          h.couponToResponse(coupon),
		"discount_amount": discountAmount.String(),
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// RemoveCouponFromOrder handles DELETE /coupons/remove-from-order
func (h *CouponHandler) RemoveCouponFromOrder(w http.ResponseWriter, r *http.Request) {
	h.removeCouponFromEntity(w, r, "order")
}

// RemoveCouponFromQuote handles DELETE /coupons/remove-from-quote
func (h *CouponHandler) RemoveCouponFromQuote(w http.ResponseWriter, r *http.Request) {
	h.removeCouponFromEntity(w, r, "quote")
}

// RemoveCouponFromInvoice handles DELETE /coupons/remove-from-invoice
func (h *CouponHandler) RemoveCouponFromInvoice(w http.ResponseWriter, r *http.Request) {
	h.removeCouponFromEntity(w, r, "invoice")
}

func (h *CouponHandler) removeCouponFromEntity(w http.ResponseWriter, r *http.Request, entityType string) {
	ctx := r.Context()
	ctx = h.injectIdempotencyKey(ctx, r)

	var req removeCouponFromEntityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	entityID, err := uuid.Parse(req.EntityID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "coupon:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	switch entityType {
	case "order":
		err = h.couponService.RemoveCouponFromOrder(ctx, companyID, entityID, req.CouponCode, userID)
	case "quote":
		err = h.couponService.RemoveCouponFromQuote(ctx, companyID, entityID, req.CouponCode, userID)
	case "invoice":
		err = h.couponService.RemoveCouponFromInvoice(ctx, companyID, entityID, req.CouponCode, userID)
	default:
		h.respondWithError(w, http.StatusBadRequest, "invalid entity type")
		return
	}
	if err != nil {
		h.logger.Error("failed to remove coupon from entity", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "coupon removed",
	})
}

// RecordCouponUsage handles POST /coupons/record-usage
func (h *CouponHandler) RecordCouponUsage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ctx = h.injectIdempotencyKey(ctx, r)

	var req recordCouponUsageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	couponID, err := uuid.Parse(req.CouponID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid coupon_id")
		return
	}
	orderID, err := uuid.Parse(req.OrderID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid order_id")
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
		h.respondWithError(w, http.StatusBadRequest, "invalid used_at")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "coupon:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	svcReq := &service.RecordCouponUsageRequest{
		CompanyID:      companyID,
		CouponID:       couponID,
		OrderID:        orderID,
		CustomerID:     customerID,
		DiscountAmount: discountAmount,
		UsedAt:         usedAt,
	}
	err = h.couponService.RecordCouponUsage(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to record coupon usage", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "usage recorded",
	})
}

// GetCouponUsageCount handles GET /coupons/{id}/usage-count
func (h *CouponHandler) GetCouponUsageCount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	couponID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid coupon ID")
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
	if !h.hasPermission(ctx, companyID, userID, "coupon:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	count, err := h.couponService.GetCouponUsageCount(ctx, companyID, couponID)
	if err != nil {
		h.logger.Error("failed to get coupon usage count", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]int64{
			"usage_count": count,
		},
	})
}

// GetCustomerCouponUsageCount handles GET /coupons/customer-usage
func (h *CouponHandler) GetCustomerCouponUsageCount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	couponIDStr := r.URL.Query().Get("coupon_id")
	if couponIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "coupon_id query parameter is required")
		return
	}
	couponID, err := uuid.Parse(couponIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid coupon_id")
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
	if !h.hasPermission(ctx, companyID, userID, "coupon:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	count, err := h.couponService.GetCustomerCouponUsageCount(ctx, companyID, couponID, customerID)
	if err != nil {
		h.logger.Error("failed to get customer coupon usage count", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]int64{
			"usage_count": count,
		},
	})
}

// GetCouponUsageHistory handles GET /coupons/{id}/usage-history
func (h *CouponHandler) GetCouponUsageHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	couponID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid coupon ID")
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
	pagination := service.Pagination{Limit: limit, Offset: offset}
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

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "coupon:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	usages, total, err := h.couponService.GetCouponUsageHistory(ctx, companyID, couponID, pagination, sort)
	if err != nil {
		h.logger.Error("failed to get coupon usage history", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	items := make([]couponUsageHistoryResponse, len(usages))
	for i, u := range usages {
		items[i] = couponUsageHistoryResponse{
			UsageID:        u.UsageID.String(),
			CouponID:       u.CouponID.String(),
			CustomerID:     u.CustomerID.String(),
			OrderID:        u.OrderID.String(),
			DiscountAmount: u.DiscountAmount.String(),
			UsedAt:         u.UsedAt.Format(time.RFC3339),
		}
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"usages": items,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		},
	})
}

// GetTopCoupons handles GET /coupons/top
func (h *CouponHandler) GetTopCoupons(w http.ResponseWriter, r *http.Request) {
	h.getTopCouponsByMetric(w, r, "usage")
}

// GetMostUsedCoupons handles GET /coupons/most-used
func (h *CouponHandler) GetMostUsedCoupons(w http.ResponseWriter, r *http.Request) {
	h.getTopCouponsByMetric(w, r, "usage")
}

// GetHighestDiscountCoupons handles GET /coupons/highest-discount
func (h *CouponHandler) GetHighestDiscountCoupons(w http.ResponseWriter, r *http.Request) {
	h.getTopCouponsByMetric(w, r, "discount")
}

func (h *CouponHandler) getTopCouponsByMetric(w http.ResponseWriter, r *http.Request, metric string) {
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
	if !h.hasPermission(ctx, companyID, userID, "coupon:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var coupons []*discount.Coupon
	switch metric {
	case "usage":
		coupons, err = h.couponService.GetMostUsedCoupons(ctx, companyID, limit, from, to)
	case "discount":
		coupons, err = h.couponService.GetHighestDiscountCoupons(ctx, companyID, limit, from, to)
	default:
		coupons, err = h.couponService.GetTopCoupons(ctx, companyID, limit, from, to)
	}
	if err != nil {
		h.logger.Error("failed to get top coupons", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	summaries := make([]couponSummary, len(coupons))
	for i, c := range coupons {
		summaries[i] = couponSummary{
			CouponID:      c.CouponID.String(),
			Code:          c.Code,
			DiscountType:  string(c.DiscountType),
			DiscountValue: c.DiscountValue.String(),
			IsActive:      c.IsActive,
			StartDate:     c.StartDate.Format(time.RFC3339),
			EndDate:       c.EndDate.Format(time.RFC3339),
		}
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

// GetTotalCouponDiscountAmount handles GET /coupons/total-discount-amount
func (h *CouponHandler) GetTotalCouponDiscountAmount(w http.ResponseWriter, r *http.Request) {
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
	if !h.hasPermission(ctx, companyID, userID, "coupon:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	amount, err := h.couponService.GetTotalCouponDiscountAmount(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get total coupon discount amount", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]string{
			"total_discount_amount": amount.String(),
		},
	})
}

// GetCouponRedemptionRate handles GET /coupons/{id}/redemption-rate
func (h *CouponHandler) GetCouponRedemptionRate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	couponID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid coupon ID")
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
	if !h.hasPermission(ctx, companyID, userID, "coupon:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	rate, err := h.couponService.GetCouponRedemptionRate(ctx, companyID, couponID, from, to)
	if err != nil {
		h.logger.Error("failed to get coupon redemption rate", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]string{
			"redemption_rate": rate.String(),
		},
	})
}

// CouponExists handles GET /coupons/{id}/exists
func (h *CouponHandler) CouponExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	couponID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid coupon ID")
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
	if !h.hasPermission(ctx, companyID, userID, "coupon:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	exists, err := h.couponService.CouponExists(ctx, companyID, couponID)
	if err != nil {
		h.logger.Error("failed to check coupon existence", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"exists": exists},
	})
}

// CouponCodeExists handles GET /coupons/code-exists
func (h *CouponHandler) CouponCodeExists(w http.ResponseWriter, r *http.Request) {
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
	if !h.hasPermission(ctx, companyID, userID, "coupon:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	exists, err := h.couponService.CouponCodeExists(ctx, companyID, code)
	if err != nil {
		h.logger.Error("failed to check coupon code existence", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"exists": exists},
	})
}

// IsCouponExpired handles GET /coupons/{id}/expired
func (h *CouponHandler) IsCouponExpired(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	couponID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid coupon ID")
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
		at, err = time.Parse(time.RFC3339, atStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid at timestamp")
			return
		}
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "coupon:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	expired, err := h.couponService.IsCouponExpired(ctx, companyID, couponID, at)
	if err != nil {
		h.logger.Error("failed to check coupon expired", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"expired": expired},
	})
}

// IsCouponUsageLimitReached handles GET /coupons/{id}/usage-limit-reached
func (h *CouponHandler) IsCouponUsageLimitReached(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	couponID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid coupon ID")
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
	if !h.hasPermission(ctx, companyID, userID, "coupon:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	reached, err := h.couponService.IsCouponUsageLimitReached(ctx, companyID, couponID)
	if err != nil {
		h.logger.Error("failed to check usage limit", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"reached": reached},
	})
}

// IsCustomerUsageLimitReached handles GET /coupons/customer-usage-limit-reached
func (h *CouponHandler) IsCustomerUsageLimitReached(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	couponIDStr := r.URL.Query().Get("coupon_id")
	if couponIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "coupon_id query parameter is required")
		return
	}
	couponID, err := uuid.Parse(couponIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid coupon_id")
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
	if !h.hasPermission(ctx, companyID, userID, "coupon:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	reached, err := h.couponService.IsCustomerUsageLimitReached(ctx, companyID, couponID, customerID)
	if err != nil {
		h.logger.Error("failed to check customer usage limit", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"reached": reached},
	})
}

// ---------- Helper to convert coupon model to response ----------
func (h *CouponHandler) couponToResponse(c *discount.Coupon) createCouponResponse {
	resp := createCouponResponse{
		CouponID:      c.CouponID.String(),
		CompanyID:     c.CompanyID.String(),
		Code:          c.Code,
		DiscountType:  string(c.DiscountType),
		DiscountValue: c.DiscountValue.String(),
		StartDate:     c.StartDate.Format(time.RFC3339),
		EndDate:       c.EndDate.Format(time.RFC3339),
		UsageLimit:    c.UsageLimit,
		PerUserLimit:  c.PerUserLimit,
		IsActive:      c.IsActive,
		StackingType:  c.StackingType, // NEW
		CreatedAt:     c.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     c.UpdatedAt.Format(time.RFC3339),
	}
	if c.MaxDiscountAmount != nil {
		s := c.MaxDiscountAmount.String()
		resp.MaxDiscountAmount = &s
	}
	if c.MinOrderAmount != nil {
		s := c.MinOrderAmount.String()
		resp.MinOrderAmount = &s
	}
	if c.ApplicableItems != nil && len(c.ApplicableItems) > 0 {
		s := string(c.ApplicableItems)
		resp.ApplicableItems = &s
	}
	return resp
}
