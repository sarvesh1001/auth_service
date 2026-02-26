package handler

import (
	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/service"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// PayrollAdjustmentHandler handles HTTP requests for payroll adjustments.
type PayrollAdjustmentHandler struct {
	adjustmentService service.PayrollAdjustmentService
	logger            *zap.Logger
}

// NewPayrollAdjustmentHandler creates a new adjustment handler.
func NewPayrollAdjustmentHandler(
	adjustmentService service.PayrollAdjustmentService,
	logger *zap.Logger,
) *PayrollAdjustmentHandler {
	return &PayrollAdjustmentHandler{
		adjustmentService: adjustmentService,
		logger:            logger,
	}
}

// ---------------------------------------------------------------------
// Request / Response Types
// ---------------------------------------------------------------------

type createPayrollAdjustmentRequest struct {
	UserID          string  `json:"user_id"`
	ComponentCode   string  `json:"component_code"`
	Amount          float64 `json:"amount"`
	AdjustmentType  string  `json:"adjustment_type"`
	Reason          string  `json:"reason,omitempty"`
	ApplicableMonth string  `json:"applicable_month"` // e.g. "2024-01"
}

type updatePayrollAdjustmentRequest struct {
	Amount *float64 `json:"amount,omitempty"`
	Reason *string  `json:"reason,omitempty"`
}

// ---------------------------------------------------------------------
// List Adjustments (GET /companies/{companyID}/payroll/adjustments)
// ---------------------------------------------------------------------
func (h *PayrollAdjustmentHandler) ListAdjustments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	// Parse query filters
	filter := models.PayrollAdjustmentFilter{
		CompanyID: companyID,
	}

	if userIDStr := r.URL.Query().Get("user_id"); userIDStr != "" {
		uid, err := uuid.Parse(userIDStr)
		if err == nil {
			filter.UserID = &uid
		}
	}
	if compCode := r.URL.Query().Get("component_code"); compCode != "" {
		filter.ComponentCode = &compCode
	}
	if adjType := r.URL.Query().Get("adjustment_type"); adjType != "" {
		filter.AdjustmentType = &adjType
	}
	if from := r.URL.Query().Get("from_month"); from != "" {
		if t, err := time.Parse("2006-01", from); err == nil {
			filter.FromMonth = &t
		}
	}
	if to := r.URL.Query().Get("to_month"); to != "" {
		if t, err := time.Parse("2006-01", to); err == nil {
			filter.ToMonth = &t
		}
	}
	if page := r.URL.Query().Get("page"); page != "" {
		if p, err := strconv.Atoi(page); err == nil && p > 0 {
			filter.Page = p
		}
	}
	if size := r.URL.Query().Get("page_size"); size != "" {
		if s, err := strconv.Atoi(size); err == nil && s > 0 {
			filter.PageSize = s
		}
	}

	adjustments, total, err := h.adjustmentService.List(ctx, filter)
	if err != nil {
		h.logger.Error("failed to list payroll adjustments", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    adjustments,
		"total":   total,
	})
}

// ---------------------------------------------------------------------
// Create Adjustment (POST /companies/{companyID}/payroll/adjustments)
// ---------------------------------------------------------------------
func (h *PayrollAdjustmentHandler) CreateAdjustment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req createPayrollAdjustmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Basic validation
	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user_id")
		return
	}
	req.ComponentCode = strings.TrimSpace(req.ComponentCode)
	if req.ComponentCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "component_code is required")
		return
	}
	if req.Amount == 0 {
		h.respondWithError(w, http.StatusBadRequest, "amount cannot be zero")
		return
	}
	if req.AdjustmentType == "" {
		h.respondWithError(w, http.StatusBadRequest, "adjustment_type is required")
		return
	}
	applicableMonth, err := time.Parse("2006-01", req.ApplicableMonth)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid applicable_month, expected format YYYY-MM")
		return
	}

	input := &models.CreatePayrollAdjustmentInput{
		CompanyID:       companyID,
		UserID:          userID,
		ComponentCode:   req.ComponentCode,
		Amount:          req.Amount,
		AdjustmentType:  req.AdjustmentType,
		Reason:          req.Reason,
		ApplicableMonth: applicableMonth,
		CreatedBy:       actorID,
	}

	adjustment, err := h.adjustmentService.Create(ctx, input)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    adjustment,
	})
}

// ---------------------------------------------------------------------
// Bulk Create Adjustments (POST /companies/{companyID}/payroll/adjustments/bulk)
// ---------------------------------------------------------------------
func (h *PayrollAdjustmentHandler) BulkCreateAdjustments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var reqs []createPayrollAdjustmentRequest
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body, expected array")
		return
	}

	if len(reqs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one adjustment required")
		return
	}

	inputs := make([]*models.CreatePayrollAdjustmentInput, 0, len(reqs))
	for i, r := range reqs {
		userID, err := uuid.Parse(r.UserID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid user_id at index "+strconv.Itoa(i))
			return
		}
		r.ComponentCode = strings.TrimSpace(r.ComponentCode)
		if r.ComponentCode == "" {
			h.respondWithError(w, http.StatusBadRequest, "component_code required at index "+strconv.Itoa(i))
			return
		}
		if r.Amount == 0 {
			h.respondWithError(w, http.StatusBadRequest, "amount cannot be zero at index "+strconv.Itoa(i))
			return
		}
		if r.AdjustmentType == "" {
			h.respondWithError(w, http.StatusBadRequest, "adjustment_type required at index "+strconv.Itoa(i))
			return
		}
		applicableMonth, err := time.Parse("2006-01", r.ApplicableMonth)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid applicable_month at index "+strconv.Itoa(i)+", expected YYYY-MM")
			return
		}

		inputs = append(inputs, &models.CreatePayrollAdjustmentInput{
			CompanyID:       companyID,
			UserID:          userID,
			ComponentCode:   r.ComponentCode,
			Amount:          r.Amount,
			AdjustmentType:  r.AdjustmentType,
			Reason:          r.Reason,
			ApplicableMonth: applicableMonth,
			CreatedBy:       actorID,
		})
	}

	if err := h.adjustmentService.BulkCreate(ctx, inputs); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": "bulk adjustments created successfully",
	})
}

// ---------------------------------------------------------------------
// Get Adjustment (GET /companies/{companyID}/payroll/adjustments/{adjustmentID})
// ---------------------------------------------------------------------
func (h *PayrollAdjustmentHandler) GetAdjustment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	adjustmentID, err := uuid.Parse(chi.URLParam(r, "adjustmentID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid adjustment id")
		return
	}

	// Optional: verify company ID matches (service layer may already enforce)
	adjustment, err := h.adjustmentService.Get(ctx, adjustmentID)
	if err != nil {
		h.logger.Error("failed to get payroll adjustment", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if adjustment == nil {
		h.respondWithError(w, http.StatusNotFound, "adjustment not found")
		return
	}
	if adjustment.CompanyID != companyID {
		h.respondWithError(w, http.StatusNotFound, "adjustment not found in this company")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    adjustment,
	})
}

// ---------------------------------------------------------------------
// Update Adjustment (PUT /companies/{companyID}/payroll/adjustments/{adjustmentID})
// ---------------------------------------------------------------------
func (h *PayrollAdjustmentHandler) UpdateAdjustment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	adjustmentID, err := uuid.Parse(chi.URLParam(r, "adjustmentID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid adjustment id")
		return
	}

	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Verify existence and company ownership before update
	existing, err := h.adjustmentService.Get(ctx, adjustmentID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if existing == nil {
		h.respondWithError(w, http.StatusNotFound, "adjustment not found")
		return
	}
	if existing.CompanyID != companyID {
		h.respondWithError(w, http.StatusNotFound, "adjustment not found in this company")
		return
	}

	var req updatePayrollAdjustmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// At least one field must be provided
	if req.Amount == nil && req.Reason == nil {
		h.respondWithError(w, http.StatusBadRequest, "no fields to update")
		return
	}

	input := &models.UpdatePayrollAdjustmentInput{
		AdjustmentID: adjustmentID,
		Amount:       req.Amount,
		Reason:       req.Reason,
		UpdatedBy:    actorID,
	}

	updated, err := h.adjustmentService.Update(ctx, input)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    updated,
	})
}

// ---------------------------------------------------------------------
// Delete Adjustment (DELETE /companies/{companyID}/payroll/adjustments/{adjustmentID})
// ---------------------------------------------------------------------
func (h *PayrollAdjustmentHandler) DeleteAdjustment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	adjustmentID, err := uuid.Parse(chi.URLParam(r, "adjustmentID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid adjustment id")
		return
	}

	actorID, err := h.getAdminActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Verify ownership before deletion
	existing, err := h.adjustmentService.Get(ctx, adjustmentID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if existing == nil {
		h.respondWithError(w, http.StatusNotFound, "adjustment not found")
		return
	}
	if existing.CompanyID != companyID {
		h.respondWithError(w, http.StatusNotFound, "adjustment not found in this company")
		return
	}

	if err := h.adjustmentService.Delete(ctx, adjustmentID, actorID); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "adjustment deleted successfully",
	})
}

// ---------------------------------------------------------------------
// Get Employee Adjustments for Period (GET /companies/{companyID}/employees/{userID}/payroll-adjustments)
// ---------------------------------------------------------------------
func (h *PayrollAdjustmentHandler) GetEmployeeAdjustmentsForPeriod(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	// Parse period from query params
	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	if fromStr == "" || toStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "from and to query parameters are required")
		return
	}
	from, err := time.Parse("2006-01-02", fromStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid from date, expected YYYY-MM-DD")
		return
	}
	to, err := time.Parse("2006-01-02", toStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid to date, expected YYYY-MM-DD")
		return
	}

	adjustments, err := h.adjustmentService.GetEmployeeAdjustmentsForPeriod(ctx, companyID, userID, from, to)
	if err != nil {
		h.logger.Error("failed to get employee adjustments for period", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    adjustments,
	})
}

// ---------------------------------------------------------------------
// Helper: get admin actor from context
// ---------------------------------------------------------------------
func (h *PayrollAdjustmentHandler) getAdminActor(ctx context.Context) (uuid.UUID, error) {
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok || userIDStr == "" {
		return uuid.Nil, errors.New("unauthenticated user")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, errors.New("invalid user_id in context")
	}

	return userID, nil
}

// ---------------------------------------------------------------------
// Standard JSON responses
// ---------------------------------------------------------------------
func (h *PayrollAdjustmentHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *PayrollAdjustmentHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    status,
		"time":    time.Now().UTC(),
	})
}
