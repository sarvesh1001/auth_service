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

// TrialHandler handles HTTP requests for trial operations.
type TrialHandler struct {
	trialService service.TrialService
	*BaseHandler
}

// NewTrialHandler creates a new TrialHandler.
func NewTrialHandler(trialService service.TrialService, logger *zap.Logger) *TrialHandler {
	return &TrialHandler{
		trialService: trialService,
		BaseHandler:  &BaseHandler{logger: logger.Named("trial_handler")},
	}
}

// -------- Request/Response Structs --------

type createTrialRequest struct {
	SubscriptionID  string       `json:"subscription_id"`
	TrialDays       int          `json:"trial_days"`
	FeaturesEnabled models.JSONB `json:"features_enabled,omitempty"`
	UsageConsumed   models.JSONB `json:"usage_consumed,omitempty"`
}

type updateTrialRequest struct {
	TrialDays       *int          `json:"trial_days,omitempty"`
	FeaturesEnabled *models.JSONB `json:"features_enabled,omitempty"`
	UsageConsumed   *models.JSONB `json:"usage_consumed,omitempty"`
}

type extendTrialRequest struct {
	AdditionalDays int `json:"additional_days"`
}

type trialResponse struct {
	TrialID         string       `json:"trial_id"`
	SubscriptionID  string       `json:"subscription_id"`
	StartedAt       string       `json:"started_at"`
	EndedAt         *string      `json:"ended_at,omitempty"`
	TrialDays       int          `json:"trial_days"`
	FeaturesEnabled models.JSONB `json:"features_enabled"`
	UsageConsumed   models.JSONB `json:"usage_consumed"`
	Status          string       `json:"status"`
	CreatedAt       string       `json:"created_at"`
	UpdatedAt       string       `json:"updated_at"`
}

type listTrialsResponse struct {
	Trials []trialResponse `json:"trials"`
	Total  int64           `json:"total"`
	Limit  int             `json:"limit"`
	Offset int             `json:"offset"`
}

// -------- Helpers --------

func (h *TrialHandler) toTrialResponse(trial *models.Trial) trialResponse {
	resp := trialResponse{
		TrialID:         trial.TrialID.String(),
		SubscriptionID:  trial.SubscriptionID.String(),
		StartedAt:       trial.StartedAt.Format(time.RFC3339),
		TrialDays:       trial.TrialDays,
		FeaturesEnabled: trial.FeaturesEnabled,
		UsageConsumed:   trial.UsageConsumed,
		Status:          string(trial.Status),
		CreatedAt:       trial.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       trial.UpdatedAt.Format(time.RFC3339),
	}
	if trial.EndedAt != nil {
		ended := trial.EndedAt.Format(time.RFC3339)
		resp.EndedAt = &ended
	}
	return resp
}

// -------- CRUD Operations --------

// CreateTrial handles POST /trials
// CreateTrial handles POST /trials
func (h *TrialHandler) CreateTrial(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Authentication
	_, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r) // ✅ capture companyID
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req createTrialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.SubscriptionID == "" || req.TrialDays <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "subscription_id and trial_days are required")
		return
	}

	subID, err := uuid.Parse(req.SubscriptionID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subscription_id")
		return
	}

	trial := &models.Trial{
		SubscriptionID:  subID,
		TrialDays:       req.TrialDays,
		FeaturesEnabled: req.FeaturesEnabled,
		UsageConsumed:   req.UsageConsumed,
		StartedAt:       time.Now(),
		Status:          enums.TrialActive,
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	// ✅ Pass companyID to service
	if err := h.trialService.Create(ctx, companyID, trial); err != nil {
		h.logger.Error("failed to create trial", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toTrialResponse(trial)
	location := fmt.Sprintf("/trials/%s", trial.TrialID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetTrial handles GET /trials/{id}
func (h *TrialHandler) GetTrial(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	trialID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid trial ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	trial, err := h.trialService.GetByID(ctx, companyID, trialID)
	if err != nil {
		h.logger.Error("failed to get trial", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toTrialResponse(trial)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetTrialBySubscription handles GET /trials?subscription_id={subID}
func (h *TrialHandler) GetTrialBySubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	subIDStr := r.URL.Query().Get("subscription_id")
	if subIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "subscription_id query parameter is required")
		return
	}

	subID, err := uuid.Parse(subIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subscription_id")
		return
	}

	trial, err := h.trialService.GetBySubscription(ctx, subID)
	if err != nil {
		h.logger.Error("failed to get trial by subscription", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toTrialResponse(trial)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateTrial handles PUT /trials/{id}
func (h *TrialHandler) UpdateTrial(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	trialID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid trial ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req updateTrialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	existing, err := h.trialService.GetByID(ctx, companyID, trialID)
	if err != nil {
		h.logger.Error("failed to get trial for update", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	if req.TrialDays != nil {
		existing.TrialDays = *req.TrialDays
	}
	if req.FeaturesEnabled != nil {
		existing.FeaturesEnabled = *req.FeaturesEnabled
	}
	if req.UsageConsumed != nil {
		existing.UsageConsumed = *req.UsageConsumed
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.trialService.Update(ctx, existing); err != nil {
		h.logger.Error("failed to update trial", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toTrialResponse(existing)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DeleteTrial handles DELETE /trials/{id}
func (h *TrialHandler) DeleteTrial(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	trialID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid trial ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.trialService.Delete(ctx, companyID, trialID); err != nil {
		h.logger.Error("failed to delete trial", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "trial deleted successfully",
	})
}

// -------- State Transitions --------

// StartTrial handles POST /trials/{id}/start
func (h *TrialHandler) StartTrial(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	trialID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid trial ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.trialService.Start(ctx, companyID, trialID); err != nil {
		h.logger.Error("failed to start trial", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "trial started",
	})
}

// EndTrial handles POST /trials/{id}/end
func (h *TrialHandler) EndTrial(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	trialID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid trial ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.trialService.End(ctx, companyID, trialID); err != nil {
		h.logger.Error("failed to end trial", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "trial ended",
	})
}

// ExtendTrial handles POST /trials/{id}/extend
func (h *TrialHandler) ExtendTrial(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	trialID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid trial ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req extendTrialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.AdditionalDays <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "additional_days must be positive")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.trialService.Extend(ctx, companyID, trialID, req.AdditionalDays); err != nil {
		h.logger.Error("failed to extend trial", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	updated, err := h.trialService.GetByID(ctx, companyID, trialID)
	if err != nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "trial extended",
		})
		return
	}
	resp := h.toTrialResponse(updated)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ConvertTrial handles POST /trials/{id}/convert
func (h *TrialHandler) ConvertTrial(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	trialID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid trial ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.trialService.Convert(ctx, companyID, trialID); err != nil {
		h.logger.Error("failed to convert trial", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	updated, err := h.trialService.GetByID(ctx, companyID, trialID)
	if err != nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "trial converted",
		})
		return
	}
	resp := h.toTrialResponse(updated)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// CancelTrial handles POST /trials/{id}/cancel
func (h *TrialHandler) CancelTrial(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	trialID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid trial ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.trialService.Cancel(ctx, companyID, trialID); err != nil {
		h.logger.Error("failed to cancel trial", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "trial cancelled",
	})
}

// -------- Field Updates --------

// UpdateTrialDays handles PUT /trials/{id}/days
func (h *TrialHandler) UpdateTrialDays(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	trialID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid trial ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req struct {
		TrialDays int `json:"trial_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.TrialDays <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "trial_days must be positive")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.trialService.UpdateTrialDays(ctx, companyID, trialID, req.TrialDays); err != nil {
		h.logger.Error("failed to update trial days", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	updated, err := h.trialService.GetByID(ctx, companyID, trialID)
	if err != nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "trial days updated",
		})
		return
	}
	resp := h.toTrialResponse(updated)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateStartDate handles PUT /trials/{id}/start_date
func (h *TrialHandler) UpdateStartDate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	trialID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid trial ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req struct {
		StartDate string `json:"start_date"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.StartDate == "" {
		h.respondWithError(w, http.StatusBadRequest, "start_date is required")
		return
	}
	start, err := time.Parse(time.RFC3339, req.StartDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid start_date format (RFC3339)")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.trialService.UpdateStartDate(ctx, companyID, trialID, start); err != nil {
		h.logger.Error("failed to update start date", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	updated, err := h.trialService.GetByID(ctx, companyID, trialID)
	if err != nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "start date updated",
		})
		return
	}
	resp := h.toTrialResponse(updated)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateEndDate handles PUT /trials/{id}/end_date
func (h *TrialHandler) UpdateEndDate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	trialID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid trial ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req struct {
		EndDate string `json:"end_date"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.EndDate == "" {
		h.respondWithError(w, http.StatusBadRequest, "end_date is required")
		return
	}
	end, err := time.Parse(time.RFC3339, req.EndDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid end_date format (RFC3339)")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.trialService.UpdateEndDate(ctx, companyID, trialID, end); err != nil {
		h.logger.Error("failed to update end date", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	updated, err := h.trialService.GetByID(ctx, companyID, trialID)
	if err != nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "end date updated",
		})
		return
	}
	resp := h.toTrialResponse(updated)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateUsage handles PUT /trials/{id}/usage
func (h *TrialHandler) UpdateUsage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	trialID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid trial ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req struct {
		UsageConsumed models.JSONB `json:"usage_consumed"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.trialService.UpdateUsage(ctx, companyID, trialID, req.UsageConsumed); err != nil {
		h.logger.Error("failed to update usage", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	updated, err := h.trialService.GetByID(ctx, companyID, trialID)
	if err != nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "usage updated",
		})
		return
	}
	resp := h.toTrialResponse(updated)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateFeatures handles PUT /trials/{id}/features
func (h *TrialHandler) UpdateFeatures(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	trialID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid trial ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req struct {
		FeaturesEnabled models.JSONB `json:"features_enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.trialService.UpdateFeatures(ctx, companyID, trialID, req.FeaturesEnabled); err != nil {
		h.logger.Error("failed to update features", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	updated, err := h.trialService.GetByID(ctx, companyID, trialID)
	if err != nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "features updated",
		})
		return
	}
	resp := h.toTrialResponse(updated)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// -------- Listing and Search --------

// ListTrials handles GET /trials
func (h *TrialHandler) ListTrials(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	filter := repository.TrialFilter{
		CompanyID: &companyID,
	}
	if status := r.URL.Query().Get("status"); status != "" {
		s := enums.TrialStatus(status)
		if s.IsValid() {
			filter.Status = &s
		}
	}
	if subIDStr := r.URL.Query().Get("subscription_id"); subIDStr != "" {
		if subID, err := uuid.Parse(subIDStr); err == nil {
			filter.SubscriptionID = &subID
		}
	}

	limit, offset := h.parsePagination(r)
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	sortField := r.URL.Query().Get("sort_field")
	if sortField == "" {
		sortField = "created_at"
	}
	sortDir := r.URL.Query().Get("sort_dir")
	if sortDir == "" {
		sortDir = "DESC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDir}

	trials, total, err := h.trialService.List(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list trials", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list trials")
		return
	}

	responses := make([]trialResponse, len(trials))
	for i, t := range trials {
		responses[i] = h.toTrialResponse(t)
	}

	resp := listTrialsResponse{
		Trials: responses,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// SearchTrials handles GET /trials/search?q={query}
func (h *TrialHandler) SearchTrials(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	query := r.URL.Query().Get("q")
	if query == "" {
		h.respondWithError(w, http.StatusBadRequest, "q query parameter is required")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	limit, offset := h.parsePagination(r)

	trials, total, err := h.trialService.Search(ctx, companyID, query, limit, offset)
	if err != nil {
		h.logger.Error("failed to search trials", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to search trials")
		return
	}

	responses := make([]trialResponse, len(trials))
	for i, t := range trials {
		responses[i] = h.toTrialResponse(t)
	}

	resp := listTrialsResponse{
		Trials: responses,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetActiveTrials handles GET /trials/active
func (h *TrialHandler) GetActiveTrials(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	trials, err := h.trialService.GetActive(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get active trials", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get active trials")
		return
	}

	responses := make([]trialResponse, len(trials))
	for i, t := range trials {
		responses[i] = h.toTrialResponse(t)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// GetExpiredTrials handles GET /trials/expired
func (h *TrialHandler) GetExpiredTrials(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	trials, err := h.trialService.GetExpired(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get expired trials", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get expired trials")
		return
	}

	responses := make([]trialResponse, len(trials))
	for i, t := range trials {
		responses[i] = h.toTrialResponse(t)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// GetConvertedTrials handles GET /trials/converted
func (h *TrialHandler) GetConvertedTrials(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	trials, err := h.trialService.GetConverted(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get converted trials", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get converted trials")
		return
	}

	responses := make([]trialResponse, len(trials))
	for i, t := range trials {
		responses[i] = h.toTrialResponse(t)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// GetExpiringTrials handles GET /trials/expiring?before={timestamp}
func (h *TrialHandler) GetExpiringTrials(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	beforeStr := r.URL.Query().Get("before")
	if beforeStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "before query parameter is required (RFC3339)")
		return
	}
	before, err := time.Parse(time.RFC3339, beforeStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid before timestamp")
		return
	}

	trials, err := h.trialService.GetExpiring(ctx, companyID, before)
	if err != nil {
		h.logger.Error("failed to get expiring trials", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get expiring trials")
		return
	}

	responses := make([]trialResponse, len(trials))
	for i, t := range trials {
		responses[i] = h.toTrialResponse(t)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// -------- Utility Endpoints --------

// CheckEligibility handles GET /trials/eligibility?customer_id={id}&plan_id={id}
func (h *TrialHandler) CheckEligibility(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	customerIDStr := r.URL.Query().Get("customer_id")
	planIDStr := r.URL.Query().Get("plan_id")
	if customerIDStr == "" || planIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "customer_id and plan_id query parameters are required")
		return
	}

	customerID, err := uuid.Parse(customerIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
		return
	}
	planID, err := uuid.Parse(planIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan_id")
		return
	}

	eligible, err := h.trialService.IsEligible(ctx, companyID, customerID, planID)
	if err != nil {
		h.logger.Error("failed to check eligibility", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check eligibility")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"eligible": eligible,
	})
}

// TrialExists handles HEAD /trials/{id}
func (h *TrialHandler) TrialExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	trialID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid trial ID")
		return
	}

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	exists, err := h.trialService.Exists(ctx, companyID, trialID)
	if err != nil {
		h.logger.Error("failed to check trial existence", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// -------- Error Mapping --------

// mapServiceError extends BaseHandler error mapping with trial‑specific errors.
func (h *TrialHandler) mapServiceError(err error) (status int, message string) {
	switch {
	case errors.Is(err, subErrors.ErrTrialNotFound):
		return http.StatusNotFound, "trial not found"
	case errors.Is(err, subErrors.ErrTrialAlreadyActive):
		return http.StatusConflict, "trial already active"
	case errors.Is(err, subErrors.ErrTrialExpired):
		return http.StatusBadRequest, "trial has expired"
	case errors.Is(err, subErrors.ErrTrialNotActive):
		return http.StatusBadRequest, "trial is not active"
	case errors.Is(err, subErrors.ErrInvalidStatus),
		errors.Is(err, subErrors.ErrInvalidState):
		return http.StatusBadRequest, err.Error()
	default:
		return h.BaseHandler.mapServiceError(err)
	}
}
