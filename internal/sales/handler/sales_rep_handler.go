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

	"auth-service/internal/sales/models"
	"auth-service/internal/sales/service"
)

// SalesRepHandler handles HTTP requests for sales representative operations.
type SalesRepHandler struct {
	salesRepService service.SalesRepService
	*BaseHandler
}

// NewSalesRepHandler creates a new SalesRepHandler.
func NewSalesRepHandler(salesRepService service.SalesRepService, logger *zap.Logger) *SalesRepHandler {
	return &SalesRepHandler{
		salesRepService: salesRepService,
		BaseHandler:     &BaseHandler{logger: logger.Named("sales_rep_handler")},
	}
}

// injectIdempotencyKey reads the Idempotency-Key header and injects it into the context.
// This follows the pattern used in the payment handler.
func (h *SalesRepHandler) injectIdempotencyKey(ctx context.Context, r *http.Request) context.Context {
	key := h.getIdempotencyKey(r)
	if key != "" {
		return context.WithValue(ctx, "idempotency_key", key)
	}
	return ctx
}

// ----------------------------------------------------------------------------
// Request/Response types
// ----------------------------------------------------------------------------

type createSalesRepRequest struct {
	UserID string  `json:"user_id"`
	Code   string  `json:"code"`
	Name   string  `json:"name"`
	Email  *string `json:"email,omitempty"`
	Phone  *string `json:"phone,omitempty"`
}

type updateSalesRepRequest struct {
	Name     *string `json:"name,omitempty"`
	Email    *string `json:"email,omitempty"`
	Phone    *string `json:"phone,omitempty"`
	IsActive *bool   `json:"is_active,omitempty"`
}

type salesRepSummary struct {
	SalesRepID string  `json:"sales_rep_id"`
	Code       string  `json:"code"`
	Name       string  `json:"name"`
	Email      *string `json:"email,omitempty"`
	Phone      *string `json:"phone,omitempty"`
	IsActive   bool    `json:"is_active"`
}

type listSalesRepsResponse struct {
	SalesReps []salesRepSummary `json:"sales_reps"`
	Total     int64             `json:"total"`
	Limit     int               `json:"limit"`
	Offset    int               `json:"offset"`
}

type assignEntityRequest struct {
	EntityID string `json:"entity_id"`
}

type setCommissionPlanRequest struct {
	CommissionPlanID string `json:"commission_plan_id"`
}

type setSalesTargetRequest struct {
	TargetAmount string `json:"target_amount"`
	PeriodStart  string `json:"period_start"`
	PeriodEnd    string `json:"period_end"`
}

type salesTargetResponse struct {
	TargetID     string `json:"target_id"`
	SalesRepID   string `json:"sales_rep_id"`
	PeriodStart  string `json:"period_start"`
	PeriodEnd    string `json:"period_end"`
	TargetAmount string `json:"target_amount"`
	Currency     string `json:"currency"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

type commissionResponse struct {
	CommissionAmount string `json:"commission_amount"`
}

type revenueResponse struct {
	Revenue string `json:"revenue"`
}

type averageDealSizeResponse struct {
	AverageDealSize string `json:"average_deal_size"`
}

type conversionRateResponse struct {
	ConversionRate string `json:"conversion_rate"`
}

type topSalesRepsResponse struct {
	SalesReps []salesRepSummary `json:"sales_reps"`
}

type leaderboardEntry struct {
	SalesRepID   string `json:"sales_rep_id"`
	Code         string `json:"code"`
	Name         string `json:"name"`
	TotalRevenue string `json:"total_revenue"`
	TotalOrders  int    `json:"total_orders"`
	AverageDeal  string `json:"average_deal"`
}

type leaderboardResponse struct {
	Entries []leaderboardEntry `json:"entries"`
}

// ----------------------------------------------------------------------------
// Helper methods (pagination, sorting, mapping)
// ----------------------------------------------------------------------------

func (h *SalesRepHandler) parsePagination(r *http.Request) (limit, offset int) {
	limit = 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	offset = 0
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}
	return
}

func (h *SalesRepHandler) parseSort(r *http.Request) service.Sort {
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
	return sort
}

func (h *SalesRepHandler) parseTimeRange(r *http.Request) (from, to *time.Time) {
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
			from = &t
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			to = &t
		}
	}
	return
}

func (h *SalesRepHandler) salesRepToSummary(rep *models.SalesRep) salesRepSummary {
	summary := salesRepSummary{
		SalesRepID: rep.SalesRepID.String(),
		Code:       rep.Code,
		Name:       rep.Name,
		IsActive:   rep.IsActive,
	}
	if rep.Email != nil {
		summary.Email = rep.Email
	}
	if rep.Phone != nil {
		summary.Phone = rep.Phone
	}
	return summary
}

func (h *SalesRepHandler) salesRepToResponse(rep *models.SalesRep) createSalesRepResponse {
	resp := createSalesRepResponse{
		SalesRepID: rep.SalesRepID.String(),
		CompanyID:  rep.CompanyID.String(),
		UserID:     rep.UserID.String(),
		Code:       rep.Code,
		Name:       rep.Name,
		IsActive:   rep.IsActive,
		CreatedAt:  rep.CreatedAt.Format(time.RFC3339),
		UpdatedAt:  rep.UpdatedAt.Format(time.RFC3339),
	}
	if rep.Email != nil {
		resp.Email = rep.Email
	}
	if rep.Phone != nil {
		resp.Phone = rep.Phone
	}
	return resp
}

// ----------------------------------------------------------------------------
// Mutating handlers (with idempotency injection)
// ----------------------------------------------------------------------------

// CreateSalesRep handles POST /sales-reps
func (h *SalesRepHandler) CreateSalesRep(w http.ResponseWriter, r *http.Request) {
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

	var req createSalesRepRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.UserID == "" {
		h.respondWithError(w, http.StatusBadRequest, "user_id is required")
		return
	}
	userUUID, err := uuid.Parse(req.UserID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user_id")
		return
	}
	if req.Code == "" {
		h.respondWithError(w, http.StatusBadRequest, "code is required")
		return
	}
	if req.Name == "" {
		h.respondWithError(w, http.StatusBadRequest, "name is required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "sales_rep:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Inject idempotency key from header into context (similar to payment handler)
	ctx = h.injectIdempotencyKey(ctx, r)

	svcReq := &service.CreateSalesRepRequest{
		CompanyID: companyID,
		UserID:    userUUID,
		Code:      req.Code,
		Name:      req.Name,
		Email:     req.Email,
		Phone:     req.Phone,
		CreatedBy: &userID,
	}

	rep, err := h.salesRepService.CreateSalesRep(ctx, svcReq) // idempotency key is read from ctx
	if err != nil {
		h.logger.Error("failed to create sales rep", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.salesRepToResponse(rep)
	location := fmt.Sprintf("/sales-reps/%s", rep.SalesRepID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateSalesRep handles PUT /sales-reps/{id}
func (h *SalesRepHandler) UpdateSalesRep(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	salesRepID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
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
	if !h.hasPermission(ctx, companyID, userID, "sales_rep:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateSalesRepRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ctx = h.injectIdempotencyKey(ctx, r)

	svcReq := &service.UpdateSalesRepRequest{
		Name:      req.Name,
		Email:     req.Email,
		Phone:     req.Phone,
		IsActive:  req.IsActive,
		UpdatedBy: &userID,
	}

	rep, err := h.salesRepService.UpdateSalesRep(ctx, companyID, salesRepID, svcReq)
	if err != nil {
		h.logger.Error("failed to update sales rep", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.salesRepToResponse(rep)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DeleteSalesRep handles DELETE /sales-reps/{id}
func (h *SalesRepHandler) DeleteSalesRep(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	salesRepID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
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
	if !h.hasPermission(ctx, companyID, userID, "sales_rep:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	ctx = h.injectIdempotencyKey(ctx, r)

	err = h.salesRepService.DeleteSalesRep(ctx, companyID, salesRepID, userID)
	if err != nil {
		h.logger.Error("failed to delete sales rep", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "sales rep deleted successfully",
	})
}

// ActivateSalesRep handles POST /sales-reps/{id}/activate
func (h *SalesRepHandler) ActivateSalesRep(w http.ResponseWriter, r *http.Request) {
	h.updateActivation(w, r, true)
}

// DeactivateSalesRep handles POST /sales-reps/{id}/deactivate
func (h *SalesRepHandler) DeactivateSalesRep(w http.ResponseWriter, r *http.Request) {
	h.updateActivation(w, r, false)
}

func (h *SalesRepHandler) updateActivation(w http.ResponseWriter, r *http.Request, activate bool) {
	ctx := r.Context()
	salesRepID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
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
	if !h.hasPermission(ctx, companyID, userID, "sales_rep:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	ctx = h.injectIdempotencyKey(ctx, r)

	if activate {
		err = h.salesRepService.ActivateSalesRep(ctx, companyID, salesRepID, userID)
	} else {
		err = h.salesRepService.DeactivateSalesRep(ctx, companyID, salesRepID, userID)
	}
	if err != nil {
		h.logger.Error("failed to update activation status", zap.Error(err))
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
		"message": fmt.Sprintf("sales rep %s", msg),
	})
}

// AssignOrder handles POST /sales-reps/{id}/assign-order
func (h *SalesRepHandler) AssignOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	salesRepID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
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
	if !h.hasPermission(ctx, companyID, userID, "sales_rep:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req assignEntityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	orderID, err := uuid.Parse(req.EntityID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}

	ctx = h.injectIdempotencyKey(ctx, r)

	err = h.salesRepService.AssignOrder(ctx, companyID, salesRepID, orderID, userID)
	if err != nil {
		h.logger.Error("failed to assign order", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "order assigned",
	})
}

// RemoveOrderAssignment handles DELETE /sales-reps/{id}/assign-order
func (h *SalesRepHandler) RemoveOrderAssignment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	salesRepID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
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
	if !h.hasPermission(ctx, companyID, userID, "sales_rep:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req assignEntityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	orderID, err := uuid.Parse(req.EntityID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}

	ctx = h.injectIdempotencyKey(ctx, r)

	err = h.salesRepService.RemoveOrderAssignment(ctx, companyID, salesRepID, orderID, userID)
	if err != nil {
		h.logger.Error("failed to remove order assignment", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "order assignment removed",
	})
}

// AssignQuote handles POST /sales-reps/{id}/assign-quote
func (h *SalesRepHandler) AssignQuote(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	salesRepID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
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
	if !h.hasPermission(ctx, companyID, userID, "sales_rep:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req assignEntityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	quoteID, err := uuid.Parse(req.EntityID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}

	ctx = h.injectIdempotencyKey(ctx, r)

	err = h.salesRepService.AssignQuote(ctx, companyID, salesRepID, quoteID, userID)
	if err != nil {
		h.logger.Error("failed to assign quote", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "quote assigned",
	})
}

// RemoveQuoteAssignment handles DELETE /sales-reps/{id}/assign-quote
func (h *SalesRepHandler) RemoveQuoteAssignment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	salesRepID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
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
	if !h.hasPermission(ctx, companyID, userID, "sales_rep:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req assignEntityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	quoteID, err := uuid.Parse(req.EntityID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}

	ctx = h.injectIdempotencyKey(ctx, r)

	err = h.salesRepService.RemoveQuoteAssignment(ctx, companyID, salesRepID, quoteID, userID)
	if err != nil {
		h.logger.Error("failed to remove quote assignment", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "quote assignment removed",
	})
}

// AssignInvoice handles POST /sales-reps/{id}/assign-invoice
func (h *SalesRepHandler) AssignInvoice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	salesRepID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
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
	if !h.hasPermission(ctx, companyID, userID, "sales_rep:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req assignEntityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	invoiceID, err := uuid.Parse(req.EntityID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}

	ctx = h.injectIdempotencyKey(ctx, r)

	err = h.salesRepService.AssignInvoice(ctx, companyID, salesRepID, invoiceID, userID)
	if err != nil {
		h.logger.Error("failed to assign invoice", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "invoice assigned",
	})
}

// RemoveInvoiceAssignment handles DELETE /sales-reps/{id}/assign-invoice
func (h *SalesRepHandler) RemoveInvoiceAssignment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	salesRepID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
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
	if !h.hasPermission(ctx, companyID, userID, "sales_rep:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req assignEntityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	invoiceID, err := uuid.Parse(req.EntityID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}

	ctx = h.injectIdempotencyKey(ctx, r)

	err = h.salesRepService.RemoveInvoiceAssignment(ctx, companyID, salesRepID, invoiceID, userID)
	if err != nil {
		h.logger.Error("failed to remove invoice assignment", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "invoice assignment removed",
	})
}

// SetCommissionPlan handles POST /sales-reps/{id}/commission-plan
func (h *SalesRepHandler) SetCommissionPlan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	salesRepID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
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
	if !h.hasPermission(ctx, companyID, userID, "sales_rep:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req setCommissionPlanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	planID, err := uuid.Parse(req.CommissionPlanID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid commission_plan_id")
		return
	}

	ctx = h.injectIdempotencyKey(ctx, r)

	err = h.salesRepService.SetCommissionPlan(ctx, companyID, salesRepID, planID, userID)
	if err != nil {
		h.logger.Error("failed to set commission plan", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "commission plan set",
	})
}

// SetSalesTarget handles POST /sales-reps/{id}/target
func (h *SalesRepHandler) SetSalesTarget(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	salesRepID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
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
	if !h.hasPermission(ctx, companyID, userID, "sales_rep:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req setSalesTargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	targetAmount, err := decimal.NewFromString(req.TargetAmount)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid target_amount")
		return
	}
	periodStart, err := time.Parse(time.RFC3339, req.PeriodStart)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid period_start")
		return
	}
	periodEnd, err := time.Parse(time.RFC3339, req.PeriodEnd)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid period_end")
		return
	}

	ctx = h.injectIdempotencyKey(ctx, r)

	svcReq := &service.SetSalesTargetRequest{
		TargetAmount: targetAmount,
		PeriodStart:  periodStart,
		PeriodEnd:    periodEnd,
	}

	err = h.salesRepService.SetSalesTarget(ctx, companyID, salesRepID, svcReq, userID)
	if err != nil {
		h.logger.Error("failed to set sales target", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "sales target set",
	})
}

// ----------------------------------------------------------------------------
// Read‑only handlers (no idempotency injection needed)
// ----------------------------------------------------------------------------

// GetSalesRepByID handles GET /sales-reps/{id}
func (h *SalesRepHandler) GetSalesRepByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	salesRepID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
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
	if !h.hasPermission(ctx, companyID, userID, "sales_rep:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	rep, err := h.salesRepService.GetSalesRepByID(ctx, companyID, salesRepID)
	if err != nil {
		h.logger.Error("failed to get sales rep", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := h.salesRepToResponse(rep)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetSalesRepByUserID handles GET /sales-reps/by-user
func (h *SalesRepHandler) GetSalesRepByUserID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userIDStr := r.URL.Query().Get("user_id")
	if userIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "user_id query parameter is required")
		return
	}
	userUUID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user_id")
		return
	}
	authUserID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, authUserID, "sales_rep:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	rep, err := h.salesRepService.GetSalesRepByUserID(ctx, companyID, userUUID)
	if err != nil {
		h.logger.Error("failed to get sales rep by user ID", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := h.salesRepToResponse(rep)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetSalesRepByCode handles GET /sales-reps/by-code
func (h *SalesRepHandler) GetSalesRepByCode(w http.ResponseWriter, r *http.Request) {
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
	authUserID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, authUserID, "sales_rep:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	rep, err := h.salesRepService.GetSalesRepByCode(ctx, companyID, code)
	if err != nil {
		h.logger.Error("failed to get sales rep by code", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := h.salesRepToResponse(rep)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ListSalesReps handles GET /sales-reps
func (h *SalesRepHandler) ListSalesReps(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	authUserID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, authUserID, "sales_rep:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	filter := service.SalesRepListFilter{
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
	if name := r.URL.Query().Get("name"); name != "" {
		filter.Name = &name
	}
	if userIDStr := r.URL.Query().Get("user_id"); userIDStr != "" {
		if uID, err := uuid.Parse(userIDStr); err == nil {
			filter.UserID = &uID
		}
	}
	limit, offset := h.parsePagination(r)
	pagination := service.Pagination{Limit: limit, Offset: offset}
	sort := h.parseSort(r)

	reps, total, err := h.salesRepService.ListSalesReps(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list sales reps", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list sales reps")
		return
	}

	summaries := make([]salesRepSummary, len(reps))
	for i, r := range reps {
		summaries[i] = h.salesRepToSummary(r)
	}
	resp := listSalesRepsResponse{
		SalesReps: summaries,
		Total:     total,
		Limit:     limit,
		Offset:    offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// SearchSalesReps handles GET /sales-reps/search
func (h *SalesRepHandler) SearchSalesReps(w http.ResponseWriter, r *http.Request) {
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
	limit, offset := h.parsePagination(r)
	authUserID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, authUserID, "sales_rep:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	reps, total, err := h.salesRepService.SearchSalesReps(ctx, companyID, query, limit, offset)
	if err != nil {
		h.logger.Error("failed to search sales reps", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to search sales reps")
		return
	}

	summaries := make([]salesRepSummary, len(reps))
	for i, r := range reps {
		summaries[i] = h.salesRepToSummary(r)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"sales_reps": summaries,
			"total":      total,
			"limit":      limit,
			"offset":     offset,
		},
	})
}

// GetActiveSalesReps handles GET /sales-reps/active
func (h *SalesRepHandler) GetActiveSalesReps(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	authUserID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, authUserID, "sales_rep:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	reps, err := h.salesRepService.GetActiveSalesReps(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get active sales reps", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get active sales reps")
		return
	}

	summaries := make([]salesRepSummary, len(reps))
	for i, r := range reps {
		summaries[i] = h.salesRepToSummary(r)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

// GetAssignedOrders handles GET /sales-reps/{id}/assigned-orders
func (h *SalesRepHandler) GetAssignedOrders(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	salesRepID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	authUserID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, authUserID, "sales_rep:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	limit, offset := h.parsePagination(r)
	pagination := service.Pagination{Limit: limit, Offset: offset}
	sort := h.parseSort(r)

	orders, total, err := h.salesRepService.GetAssignedOrders(ctx, companyID, salesRepID, pagination, sort)
	if err != nil {
		h.logger.Error("failed to get assigned orders", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"orders": orders,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		},
	})
}

// GetAssignedQuotes handles GET /sales-reps/{id}/assigned-quotes
func (h *SalesRepHandler) GetAssignedQuotes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	salesRepID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	authUserID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, authUserID, "sales_rep:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	limit, offset := h.parsePagination(r)
	pagination := service.Pagination{Limit: limit, Offset: offset}
	sort := h.parseSort(r)

	quotes, total, err := h.salesRepService.GetAssignedQuotes(ctx, companyID, salesRepID, pagination, sort)
	if err != nil {
		h.logger.Error("failed to get assigned quotes", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"quotes": quotes,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		},
	})
}

// GetAssignedInvoices handles GET /sales-reps/{id}/assigned-invoices
func (h *SalesRepHandler) GetAssignedInvoices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	salesRepID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	authUserID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, authUserID, "sales_rep:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	limit, offset := h.parsePagination(r)
	pagination := service.Pagination{Limit: limit, Offset: offset}
	sort := h.parseSort(r)

	invoices, total, err := h.salesRepService.GetAssignedInvoices(ctx, companyID, salesRepID, pagination, sort)
	if err != nil {
		h.logger.Error("failed to get assigned invoices", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"invoices": invoices,
			"total":    total,
			"limit":    limit,
			"offset":   offset,
		},
	})
}

// CalculateCommission handles GET /sales-reps/{id}/commission
func (h *SalesRepHandler) CalculateCommission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	salesRepID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	authUserID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, authUserID, "sales_rep:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	from, to := h.parseTimeRange(r)
	amount, err := h.salesRepService.CalculateCommission(ctx, companyID, salesRepID, from, to)
	if err != nil {
		h.logger.Error("failed to calculate commission", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": commissionResponse{
			CommissionAmount: amount.String(),
		},
	})
}

// GetEarnedCommission is an alias for CalculateCommission
func (h *SalesRepHandler) GetEarnedCommission(w http.ResponseWriter, r *http.Request) {
	h.CalculateCommission(w, r)
}

// GetSalesRevenue handles GET /sales-reps/{id}/revenue
func (h *SalesRepHandler) GetSalesRevenue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	salesRepID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	authUserID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, authUserID, "sales_rep:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	from, to := h.parseTimeRange(r)
	revenue, err := h.salesRepService.GetSalesRevenue(ctx, companyID, salesRepID, from, to)
	if err != nil {
		h.logger.Error("failed to get sales revenue", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": revenueResponse{
			Revenue: revenue.String(),
		},
	})
}

// GetCollectedRevenue handles GET /sales-reps/{id}/collected-revenue
func (h *SalesRepHandler) GetCollectedRevenue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	salesRepID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	authUserID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, authUserID, "sales_rep:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	from, to := h.parseTimeRange(r)
	revenue, err := h.salesRepService.GetCollectedRevenue(ctx, companyID, salesRepID, from, to)
	if err != nil {
		h.logger.Error("failed to get collected revenue", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": revenueResponse{
			Revenue: revenue.String(),
		},
	})
}

// GetAverageDealSize handles GET /sales-reps/{id}/average-deal-size
func (h *SalesRepHandler) GetAverageDealSize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	salesRepID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	authUserID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, authUserID, "sales_rep:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	from, to := h.parseTimeRange(r)
	avg, err := h.salesRepService.GetAverageDealSize(ctx, companyID, salesRepID, from, to)
	if err != nil {
		h.logger.Error("failed to get average deal size", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": averageDealSizeResponse{
			AverageDealSize: avg.String(),
		},
	})
}

// GetConversionRate handles GET /sales-reps/{id}/conversion-rate
func (h *SalesRepHandler) GetConversionRate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	salesRepID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	authUserID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, authUserID, "sales_rep:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	from, to := h.parseTimeRange(r)
	rate, err := h.salesRepService.GetConversionRate(ctx, companyID, salesRepID, from, to)
	if err != nil {
		h.logger.Error("failed to get conversion rate", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": conversionRateResponse{
			ConversionRate: rate.String(),
		},
	})
}

// GetTopSalesReps handles GET /sales-reps/top
func (h *SalesRepHandler) GetTopSalesReps(w http.ResponseWriter, r *http.Request) {
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
	from, to := h.parseTimeRange(r)
	authUserID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, authUserID, "sales_rep:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	reps, err := h.salesRepService.GetTopSalesReps(ctx, companyID, limit, from, to)
	if err != nil {
		h.logger.Error("failed to get top sales reps", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	summaries := make([]salesRepSummary, len(reps))
	for i, r := range reps {
		summaries[i] = h.salesRepToSummary(r)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": topSalesRepsResponse{
			SalesReps: summaries,
		},
	})
}

// GetSalesRepLeaderboard handles GET /sales-reps/leaderboard
func (h *SalesRepHandler) GetSalesRepLeaderboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	from, to := h.parseTimeRange(r)
	authUserID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, authUserID, "sales_rep:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	entries, err := h.salesRepService.GetSalesRepLeaderboard(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get leaderboard", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	respEntries := make([]leaderboardEntry, len(entries))
	for i, e := range entries {
		respEntries[i] = leaderboardEntry{
			SalesRepID:   e.SalesRepID.String(),
			Code:         e.Code,
			Name:         e.Name,
			TotalRevenue: e.TotalRevenue.String(),
			TotalOrders:  e.TotalOrders,
			AverageDeal:  e.AverageDeal.String(),
		}
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": leaderboardResponse{
			Entries: respEntries,
		},
	})
}

// GetSalesTarget handles GET /sales-reps/{id}/target
func (h *SalesRepHandler) GetSalesTarget(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	salesRepID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	periodStartStr := r.URL.Query().Get("period_start")
	if periodStartStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "period_start query parameter is required")
		return
	}
	periodStart, err := time.Parse(time.RFC3339, periodStartStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid period_start")
		return
	}
	periodEndStr := r.URL.Query().Get("period_end")
	if periodEndStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "period_end query parameter is required")
		return
	}
	periodEnd, err := time.Parse(time.RFC3339, periodEndStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid period_end")
		return
	}
	authUserID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, authUserID, "sales_rep:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	target, err := h.salesRepService.GetSalesTarget(ctx, companyID, salesRepID, periodStart, periodEnd)
	if err != nil {
		h.logger.Error("failed to get sales target", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := salesTargetResponse{
		TargetID:     target.TargetID.String(),
		SalesRepID:   target.SalesRepID.String(),
		PeriodStart:  target.PeriodStart.Format(time.RFC3339),
		PeriodEnd:    target.PeriodEnd.Format(time.RFC3339),
		TargetAmount: target.TargetAmount.String(),
		Currency:     target.Currency,
		CreatedAt:    target.CreatedAt.Format(time.RFC3339),
		UpdatedAt:    target.UpdatedAt.Format(time.RFC3339),
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// SalesRepExists handles GET /sales-reps/{id}/exists
func (h *SalesRepHandler) SalesRepExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	salesRepID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid sales rep ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	authUserID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, authUserID, "sales_rep:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	exists, err := h.salesRepService.SalesRepExists(ctx, companyID, salesRepID)
	if err != nil {
		h.logger.Error("failed to check existence", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"exists": exists},
	})
}

// SalesRepCodeExists handles GET /sales-reps/exists?code=...
func (h *SalesRepHandler) SalesRepCodeExists(w http.ResponseWriter, r *http.Request) {
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
	authUserID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, authUserID, "sales_rep:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	exists, err := h.salesRepService.SalesRepCodeExists(ctx, companyID, code)
	if err != nil {
		h.logger.Error("failed to check code existence", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"exists": exists},
	})
}

// UserAlreadyLinked handles GET /sales-reps/user-linked?user_id=...
func (h *SalesRepHandler) UserAlreadyLinked(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userIDStr := r.URL.Query().Get("user_id")
	if userIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "user_id query parameter is required")
		return
	}
	userUUID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user_id")
		return
	}
	authUserID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, authUserID, "sales_rep:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	linked, err := h.salesRepService.UserAlreadyLinked(ctx, companyID, userUUID)
	if err != nil {
		h.logger.Error("failed to check user linked", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"linked": linked},
	})
}

// ----------------------------------------------------------------------------
// Unimplemented endpoints (customer assignment not supported)
// ----------------------------------------------------------------------------

func (h *SalesRepHandler) AssignCustomer(w http.ResponseWriter, r *http.Request) {
	h.respondWithError(w, http.StatusNotImplemented, "customer assignment not supported")
}

func (h *SalesRepHandler) RemoveCustomerAssignment(w http.ResponseWriter, r *http.Request) {
	h.respondWithError(w, http.StatusNotImplemented, "customer assignment removal not supported")
}

func (h *SalesRepHandler) GetAssignedCustomers(w http.ResponseWriter, r *http.Request) {
	h.respondWithError(w, http.StatusNotImplemented, "customer assignment not supported")
}

func (h *SalesRepHandler) GetCustomerSalesRep(w http.ResponseWriter, r *http.Request) {
	h.respondWithError(w, http.StatusNotImplemented, "customer sales rep not supported")
}

type createSalesRepResponse struct {
	SalesRepID string  `json:"sales_rep_id"`
	CompanyID  string  `json:"company_id"`
	UserID     string  `json:"user_id"`
	Code       string  `json:"code"`
	Name       string  `json:"name"`
	Email      *string `json:"email,omitempty"`
	Phone      *string `json:"phone,omitempty"`
	IsActive   bool    `json:"is_active"`
	CreatedAt  string  `json:"created_at"`
	UpdatedAt  string  `json:"updated_at"`
}
