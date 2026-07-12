// FILE: ./handler/subscription_handler.go
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	subErrors "auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/models"
	"auth-service/internal/subscription/models/enums"
	"auth-service/internal/subscription/repository"
	"auth-service/internal/subscription/service"
)

// SubscriptionHandler handles HTTP requests for subscription management,
// including core CRUD, lifecycle operations, item management, and provisioning.
type SubscriptionHandler struct {
	subService          service.SubscriptionService
	lifecycleService    service.SubscriptionLifecycleService
	itemService         service.SubscriptionItemService
	provisioningService service.SubscriptionProvisioningService
	billingEngine       *service.BillingEngineService // <-- NEW
	*BaseHandler
}

// NewSubscriptionHandler creates a new SubscriptionHandler with all required services.
func NewSubscriptionHandler(
	subService service.SubscriptionService,
	lifecycleService service.SubscriptionLifecycleService,
	itemService service.SubscriptionItemService,
	provisioningService service.SubscriptionProvisioningService,
	billingEngine *service.BillingEngineService, // <-- NEW parameter
	logger *zap.Logger,
) *SubscriptionHandler {
	return &SubscriptionHandler{
		subService:          subService,
		lifecycleService:    lifecycleService,
		itemService:         itemService,
		provisioningService: provisioningService,
		billingEngine:       billingEngine, // <-- store it
		BaseHandler:         &BaseHandler{logger: logger.Named("subscription_handler")},
	}
}

// ---------- Request/Response DTOs ----------

type createSubscriptionRequest struct {
	CompanyID      string                 `json:"company_id"`
	CustomerID     string                 `json:"customer_id"`
	PlanID         string                 `json:"plan_id"`
	StartDate      string                 `json:"start_date"`          // RFC3339
	EndDate        *string                `json:"end_date,omitempty"`  // RFC3339
	TrialEnd       *string                `json:"trial_end,omitempty"` // RFC3339
	BillingStart   string                 `json:"billing_start"`
	AutoRenew      *bool                  `json:"auto_renew,omitempty"`
	ContractNumber *string                `json:"contract_number,omitempty"`
	SalesOrderID   *string                `json:"sales_order_id,omitempty"`
	CouponID       *string                `json:"coupon_id,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

type updateSubscriptionRequest struct {
	CustomerID     *string `json:"customer_id,omitempty"`
	PlanID         *string `json:"plan_id,omitempty"`
	StartDate      *string `json:"start_date,omitempty"`
	EndDate        *string `json:"end_date,omitempty"`
	BillingStart   *string `json:"billing_start,omitempty"`
	AutoRenew      *bool   `json:"auto_renew,omitempty"`
	ContractNumber *string `json:"contract_number,omitempty"`
	SalesOrderID   *string `json:"sales_order_id,omitempty"`
	CouponID       *string `json:"coupon_id,omitempty"`
	Version        int     `json:"version"`
}

type lifecycleRequest struct {
	Reason *string `json:"reason,omitempty"`
}

type activateRequest struct {
	ActivatedBy string `json:"activated_by"`
}

type reactivateRequest struct {
	ActivatedBy string `json:"activated_by"`
}

type suspendRequest struct {
	Reason      *string `json:"reason,omitempty"`
	SuspendedBy string  `json:"suspended_by"`
}

type pauseRequest struct {
	Reason   *string `json:"reason,omitempty"`
	PausedBy string  `json:"paused_by"`
}

type resumeRequest struct {
	ResumedBy string `json:"resumed_by"`
}

type renewRequest struct {
	RenewedBy  string  `json:"renewed_by"`
	NewEndDate *string `json:"new_end_date,omitempty"`
}

type expireRequest struct {
	ExpiredBy string `json:"expired_by"`
	EndDate   string `json:"end_date"`
}

type upgradeRequest struct {
	NewPlanID  string                 `json:"new_plan_id"`
	UpgradedBy string                 `json:"upgraded_by"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type downgradeRequest struct {
	NewPlanID    string                 `json:"new_plan_id"`
	DowngradedBy string                 `json:"downgraded_by"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

type changePlanRequest struct {
	NewPlanID string                 `json:"new_plan_id"`
	ChangedBy string                 `json:"changed_by"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

type cancelRequest struct {
	Reason      *string `json:"reason,omitempty"`
	CancelledBy string  `json:"cancelled_by"`
	Immediate   bool    `json:"immediate"`
}

// subscriptionResponse is the full subscription representation.
type subscriptionResponse struct {
	SubscriptionID     string  `json:"subscription_id"`
	CompanyID          string  `json:"company_id"`
	CustomerID         string  `json:"customer_id"`
	PlanID             string  `json:"plan_id"`
	Status             string  `json:"status"`
	StartDate          string  `json:"start_date"`
	EndDate            *string `json:"end_date,omitempty"`
	TrialEnd           *string `json:"trial_end,omitempty"`
	BillingStart       string  `json:"billing_start"`
	AutoRenew          bool    `json:"auto_renew"`
	PauseReason        *string `json:"pause_reason,omitempty"`
	CancellationReason *string `json:"cancellation_reason,omitempty"`
	CancelledAt        *string `json:"cancelled_at,omitempty"`
	ContractNumber     *string `json:"contract_number,omitempty"`
	SignedAt           *string `json:"signed_at,omitempty"`
	TermsVersion       *string `json:"terms_version,omitempty"`
	SignedDocumentKey  *string `json:"signed_document_key,omitempty"`
	CurrentInvoiceID   *string `json:"current_invoice_id,omitempty"`
	LastInvoiceID      *string `json:"last_invoice_id,omitempty"`
	NextInvoiceID      *string `json:"next_invoice_id,omitempty"`
	CouponID           *string `json:"coupon_id,omitempty"`
	Version            int     `json:"version"`
	CreatedAt          string  `json:"created_at"`
	UpdatedAt          string  `json:"updated_at"`
	DeletedAt          *string `json:"deleted_at,omitempty"`
	SalesOrderID       *string `json:"sales_order_id,omitempty"`
	ScheduleID         *string `json:"schedule_id,omitempty"`
	WorkflowID         *string `json:"workflow_id,omitempty"`
	NotificationPrefID *string `json:"notification_pref_id,omitempty"`
}

type listSubscriptionsResponse struct {
	Subscriptions []subscriptionResponse `json:"subscriptions"`
	Total         int64                  `json:"total"`
	Limit         int                    `json:"limit"`
	Offset        int                    `json:"offset"`
}

// ---------- Helper functions ----------

func (h *SubscriptionHandler) toSubscriptionResponse(sub *models.Subscription) subscriptionResponse {
	resp := subscriptionResponse{
		SubscriptionID: sub.SubscriptionID.String(),
		CompanyID:      sub.CompanyID.String(),
		CustomerID:     sub.CustomerID.String(),
		PlanID:         sub.PlanID.String(),
		Status:         string(sub.Status),
		StartDate:      sub.StartDate.Format(time.RFC3339),
		BillingStart:   sub.BillingStart.Format(time.RFC3339),
		AutoRenew:      sub.AutoRenew,
		Version:        sub.Version,
		CreatedAt:      sub.CreatedAt.Format(time.RFC3339),
		UpdatedAt:      sub.UpdatedAt.Format(time.RFC3339),
	}
	if sub.EndDate != nil {
		s := sub.EndDate.Format(time.RFC3339)
		resp.EndDate = &s
	}
	if sub.TrialEnd != nil {
		s := sub.TrialEnd.Format(time.RFC3339)
		resp.TrialEnd = &s
	}
	if sub.PauseReason != nil {
		resp.PauseReason = sub.PauseReason
	}
	if sub.CancellationReason != nil {
		resp.CancellationReason = sub.CancellationReason
	}
	if sub.CancelledAt != nil {
		s := sub.CancelledAt.Format(time.RFC3339)
		resp.CancelledAt = &s
	}
	if sub.ContractNumber != nil {
		resp.ContractNumber = sub.ContractNumber
	}
	if sub.SignedAt != nil {
		s := sub.SignedAt.Format(time.RFC3339)
		resp.SignedAt = &s
	}
	if sub.TermsVersion != nil {
		resp.TermsVersion = sub.TermsVersion
	}
	if sub.SignedDocumentKey != nil {
		resp.SignedDocumentKey = sub.SignedDocumentKey
	}
	if sub.CurrentInvoiceID != nil {
		s := sub.CurrentInvoiceID.String()
		resp.CurrentInvoiceID = &s
	}
	if sub.LastInvoiceID != nil {
		s := sub.LastInvoiceID.String()
		resp.LastInvoiceID = &s
	}
	if sub.NextInvoiceID != nil {
		s := sub.NextInvoiceID.String()
		resp.NextInvoiceID = &s
	}
	if sub.CouponID != nil {
		s := sub.CouponID.String()
		resp.CouponID = &s
	}
	if sub.DeletedAt != nil {
		s := sub.DeletedAt.Format(time.RFC3339)
		resp.DeletedAt = &s
	}
	if sub.SalesOrderID != nil {
		s := sub.SalesOrderID.String()
		resp.SalesOrderID = &s
	}
	if sub.ScheduleID != nil {
		s := sub.ScheduleID.String()
		resp.ScheduleID = &s
	}
	if sub.WorkflowID != nil {
		s := sub.WorkflowID.String()
		resp.WorkflowID = &s
	}
	if sub.NotificationPrefID != nil {
		s := sub.NotificationPrefID.String()
		resp.NotificationPrefID = &s
	}
	return resp
}

// parseTimePtr parses an RFC3339 string into a *time.Time.
func parseTimePtr(s *string) (*time.Time, error) {
	if s == nil {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// ---------- Core CRUD Handlers ----------

// CreateSubscription handles POST /subscriptions
func (h *SubscriptionHandler) CreateSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Authentication
	_, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req createSubscriptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate required fields
	if req.CompanyID == "" || req.CustomerID == "" || req.PlanID == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id, customer_id, plan_id are required")
		return
	}
	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}
	customerID, err := uuid.Parse(req.CustomerID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
		return
	}
	planID, err := uuid.Parse(req.PlanID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan_id")
		return
	}

	startDate, err := time.Parse(time.RFC3339, req.StartDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid start_date")
		return
	}
	billingStart, err := time.Parse(time.RFC3339, req.BillingStart)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid billing_start")
		return
	}

	endDate, err := parseTimePtr(req.EndDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid end_date")
		return
	}
	trialEnd, err := parseTimePtr(req.TrialEnd)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid trial_end")
		return
	}

	autoRenew := true
	if req.AutoRenew != nil {
		autoRenew = *req.AutoRenew
	}

	var salesOrderID *uuid.UUID
	if req.SalesOrderID != nil {
		id, err := uuid.Parse(*req.SalesOrderID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid sales_order_id")
			return
		}
		salesOrderID = &id
	}
	var couponID *uuid.UUID
	if req.CouponID != nil {
		id, err := uuid.Parse(*req.CouponID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid coupon_id")
			return
		}
		couponID = &id
	}

	sub := &models.Subscription{
		SubscriptionID: uuid.New(),
		CompanyID:      companyID,
		CustomerID:     customerID,
		PlanID:         planID,
		Status:         enums.SubStatusPending,
		StartDate:      startDate,
		EndDate:        endDate,
		TrialEnd:       trialEnd,
		BillingStart:   billingStart,
		AutoRenew:      autoRenew,
		ContractNumber: req.ContractNumber,
		SalesOrderID:   salesOrderID,
		CouponID:       couponID,
		Version:        1,
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.subService.Create(ctx, sub); err != nil {
		h.logger.Error("failed to create subscription", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	// Optionally provision immediately
	if err := h.provisioningService.Provision(ctx, sub); err != nil {
		h.logger.Warn("provisioning failed after creation", zap.Error(err))
		// non-fatal, but we might want to return a warning
	}

	resp := h.toSubscriptionResponse(sub)
	location := fmt.Sprintf("/subscriptions/%s", sub.SubscriptionID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetSubscription handles GET /subscriptions/{id}
func (h *SubscriptionHandler) GetSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	subID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subscription ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	sub, err := h.subService.GetByID(ctx, companyID, subID)
	if err != nil {
		h.logger.Error("failed to get subscription", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := h.toSubscriptionResponse(sub)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateSubscription handles PUT /subscriptions/{id}
func (h *SubscriptionHandler) UpdateSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	subID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subscription ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req updateSubscriptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	existing, err := h.subService.GetByID(ctx, companyID, subID)
	if err != nil {
		h.logger.Error("failed to get subscription for update", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	// Apply updates
	if req.CustomerID != nil {
		cid, err := uuid.Parse(*req.CustomerID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
			return
		}
		existing.CustomerID = cid
	}
	if req.PlanID != nil {
		pid, err := uuid.Parse(*req.PlanID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid plan_id")
			return
		}
		existing.PlanID = pid
	}
	if req.StartDate != nil {
		t, err := time.Parse(time.RFC3339, *req.StartDate)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid start_date")
			return
		}
		existing.StartDate = t
	}
	if req.EndDate != nil {
		t, err := parseTimePtr(req.EndDate)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid end_date")
			return
		}
		existing.EndDate = t
	}
	if req.BillingStart != nil {
		t, err := time.Parse(time.RFC3339, *req.BillingStart)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid billing_start")
			return
		}
		existing.BillingStart = t
	}
	if req.AutoRenew != nil {
		existing.AutoRenew = *req.AutoRenew
	}
	if req.ContractNumber != nil {
		existing.ContractNumber = req.ContractNumber
	}
	if req.SalesOrderID != nil {
		if *req.SalesOrderID == "" {
			existing.SalesOrderID = nil
		} else {
			id, err := uuid.Parse(*req.SalesOrderID)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid sales_order_id")
				return
			}
			existing.SalesOrderID = &id
		}
	}
	if req.CouponID != nil {
		if *req.CouponID == "" {
			existing.CouponID = nil
		} else {
			id, err := uuid.Parse(*req.CouponID)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid coupon_id")
				return
			}
			existing.CouponID = &id
		}
	}
	existing.Version = req.Version

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.subService.Update(ctx, existing); err != nil {
		h.logger.Error("failed to update subscription", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toSubscriptionResponse(existing)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DeleteSubscription handles DELETE /subscriptions/{id}
func (h *SubscriptionHandler) DeleteSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	subID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subscription ID")
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

	if err := h.subService.Delete(ctx, companyID, subID); err != nil {
		h.logger.Error("failed to delete subscription", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "subscription deleted",
	})
}

// ListSubscriptions handles GET /subscriptions
func (h *SubscriptionHandler) ListSubscriptions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	filter := repository.SubscriptionFilter{
		CompanyID: companyID,
	}
	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = (*enums.SubscriptionStatus)(&status)
	}
	if customerIDStr := r.URL.Query().Get("customer_id"); customerIDStr != "" {
		if cid, err := uuid.Parse(customerIDStr); err == nil {
			filter.CustomerID = &cid
		}
	}
	if planIDStr := r.URL.Query().Get("plan_id"); planIDStr != "" {
		if pid, err := uuid.Parse(planIDStr); err == nil {
			filter.PlanID = &pid
		}
	}
	if autoRenewStr := r.URL.Query().Get("auto_renew"); autoRenewStr != "" {
		if b, err := strconv.ParseBool(autoRenewStr); err == nil {
			filter.AutoRenew = &b
		}
	}
	if startDateStr := r.URL.Query().Get("start_date_from"); startDateStr != "" {
		if t, err := time.Parse(time.RFC3339, startDateStr); err == nil {
			filter.StartDateFrom = &t
		}
	}
	if endDateStr := r.URL.Query().Get("end_date_to"); endDateStr != "" {
		if t, err := time.Parse(time.RFC3339, endDateStr); err == nil {
			filter.EndDateTo = &t
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

	subs, total, err := h.subService.List(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list subscriptions", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list subscriptions")
		return
	}

	responses := make([]subscriptionResponse, len(subs))
	for i, s := range subs {
		responses[i] = h.toSubscriptionResponse(s)
	}
	resp := listSubscriptionsResponse{
		Subscriptions: responses,
		Total:         total,
		Limit:         limit,
		Offset:        offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// SearchSubscriptions handles GET /subscriptions/search?q=...
func (h *SubscriptionHandler) SearchSubscriptions(w http.ResponseWriter, r *http.Request) {
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

	subs, total, err := h.subService.Search(ctx, companyID, query, limit, offset)
	if err != nil {
		h.logger.Error("failed to search subscriptions", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to search")
		return
	}

	responses := make([]subscriptionResponse, len(subs))
	for i, s := range subs {
		responses[i] = h.toSubscriptionResponse(s)
	}
	resp := listSubscriptionsResponse{
		Subscriptions: responses,
		Total:         total,
		Limit:         limit,
		Offset:        offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetByCustomer handles GET /subscriptions/customer/{customerId}
func (h *SubscriptionHandler) GetByCustomer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	customerID, err := h.parseUUIDParam(r, "customerId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	subs, err := h.subService.GetByCustomer(ctx, companyID, customerID)
	if err != nil {
		h.logger.Error("failed to get subscriptions by customer", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to fetch")
		return
	}
	responses := make([]subscriptionResponse, len(subs))
	for i, s := range subs {
		responses[i] = h.toSubscriptionResponse(s)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// GetByPlan handles GET /subscriptions/plan/{planId}
func (h *SubscriptionHandler) GetByPlan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	planID, err := h.parseUUIDParam(r, "planId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	subs, err := h.subService.GetByPlan(ctx, companyID, planID)
	if err != nil {
		h.logger.Error("failed to get subscriptions by plan", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to fetch")
		return
	}
	responses := make([]subscriptionResponse, len(subs))
	for i, s := range subs {
		responses[i] = h.toSubscriptionResponse(s)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// GetExpiring handles GET /subscriptions/expiring?before=...
func (h *SubscriptionHandler) GetExpiring(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	beforeStr := r.URL.Query().Get("before")
	if beforeStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "before query parameter is required")
		return
	}
	before, err := time.Parse(time.RFC3339, beforeStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid before date")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	subs, err := h.subService.GetExpiring(ctx, companyID, before)
	if err != nil {
		h.logger.Error("failed to get expiring subscriptions", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to fetch")
		return
	}
	responses := make([]subscriptionResponse, len(subs))
	for i, s := range subs {
		responses[i] = h.toSubscriptionResponse(s)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// ---------- Lifecycle Handlers ----------

// ActivateSubscription handles POST /subscriptions/{id}/activate
// It now generates the initial invoice synchronously after activation.
func (h *SubscriptionHandler) ActivateSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	subID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subscription ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req activateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.ActivatedBy == "" {
		h.respondWithError(w, http.StatusBadRequest, "activated_by is required")
		return
	}
	activatedBy, err := uuid.Parse(req.ActivatedBy)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid activated_by")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	// 1. Activate the subscription (this does NOT generate an invoice internally)
	sub, err := h.lifecycleService.Activate(ctx, &service.ActivateSubscriptionRequest{
		CompanyID:      companyID,
		SubscriptionID: subID,
		ActivatedBy:    activatedBy,
	})
	if err != nil {
		h.logger.Error("failed to activate subscription", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := h.toSubscriptionResponse(sub)

	// 2. Generate the initial invoice synchronously
	if sub.EndDate == nil {
		h.logger.Error("cannot generate invoice: end_date is nil",
			zap.String("subscription_id", sub.SubscriptionID.String()))
		// Return 202 with warning (subscription is active but no invoice)
		h.respondWithJSON(w, http.StatusAccepted, map[string]interface{}{
			"success": true,
			"data":    resp,
			"warning": "subscription activated but invoice generation skipped: end_date missing",
		})
		return
	}

	_, err = h.billingEngine.GenerateInitialInvoice(ctx, companyID, sub.SubscriptionID, sub.StartDate, *sub.EndDate)
	if err != nil {
		h.logger.Error("initial invoice generation failed", zap.Error(err))
		// Return 202 Accepted – subscription is active, but invoice creation failed
		// In production, you might want to enqueue a retry instead.
		h.respondWithJSON(w, http.StatusAccepted, map[string]interface{}{
			"success": true,
			"data":    resp,
			"warning": "subscription activated but invoice generation failed; check logs",
		})
		return
	}

	// Everything succeeded
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ReactivateSubscription handles POST /subscriptions/{id}/reactivate
func (h *SubscriptionHandler) ReactivateSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	subID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subscription ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req reactivateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.ActivatedBy == "" {
		h.respondWithError(w, http.StatusBadRequest, "activated_by is required")
		return
	}
	activatedBy, err := uuid.Parse(req.ActivatedBy)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid activated_by")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	sub, err := h.lifecycleService.Reactivate(ctx, &service.ReactivateSubscriptionRequest{
		CompanyID:      companyID,
		SubscriptionID: subID,
		ActivatedBy:    activatedBy,
	})
	if err != nil {
		h.logger.Error("failed to reactivate subscription", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := h.toSubscriptionResponse(sub)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// SuspendSubscription handles POST /subscriptions/{id}/suspend
func (h *SubscriptionHandler) SuspendSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	subID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subscription ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req suspendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.SuspendedBy == "" {
		h.respondWithError(w, http.StatusBadRequest, "suspended_by is required")
		return
	}
	suspendedBy, err := uuid.Parse(req.SuspendedBy)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid suspended_by")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	sub, err := h.lifecycleService.Suspend(ctx, &service.SuspendSubscriptionRequest{
		CompanyID:      companyID,
		SubscriptionID: subID,
		Reason:         req.Reason,
		SuspendedBy:    suspendedBy,
	})
	if err != nil {
		h.logger.Error("failed to suspend subscription", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := h.toSubscriptionResponse(sub)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// PauseSubscription handles POST /subscriptions/{id}/pause
func (h *SubscriptionHandler) PauseSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	subID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subscription ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req pauseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.PausedBy == "" {
		h.respondWithError(w, http.StatusBadRequest, "paused_by is required")
		return
	}
	pausedBy, err := uuid.Parse(req.PausedBy)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid paused_by")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	sub, err := h.lifecycleService.Pause(ctx, &service.PauseSubscriptionRequest{
		CompanyID:      companyID,
		SubscriptionID: subID,
		Reason:         req.Reason,
		PausedBy:       pausedBy,
	})
	if err != nil {
		h.logger.Error("failed to pause subscription", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := h.toSubscriptionResponse(sub)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ResumeSubscription handles POST /subscriptions/{id}/resume
func (h *SubscriptionHandler) ResumeSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	subID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subscription ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req resumeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.ResumedBy == "" {
		h.respondWithError(w, http.StatusBadRequest, "resumed_by is required")
		return
	}
	resumedBy, err := uuid.Parse(req.ResumedBy)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid resumed_by")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	sub, err := h.lifecycleService.Resume(ctx, &service.ResumeSubscriptionRequest{
		CompanyID:      companyID,
		SubscriptionID: subID,
		ResumedBy:      resumedBy,
	})
	if err != nil {
		h.logger.Error("failed to resume subscription", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := h.toSubscriptionResponse(sub)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// RenewSubscription handles POST /subscriptions/{id}/renew
func (h *SubscriptionHandler) RenewSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	subID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subscription ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req renewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.RenewedBy == "" {
		h.respondWithError(w, http.StatusBadRequest, "renewed_by is required")
		return
	}
	renewedBy, err := uuid.Parse(req.RenewedBy)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid renewed_by")
		return
	}
	newEndDate, err := parseTimePtr(req.NewEndDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid new_end_date")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	sub, err := h.lifecycleService.Renew(ctx, &service.RenewSubscriptionRequest{
		CompanyID:      companyID,
		SubscriptionID: subID,
		RenewedBy:      renewedBy,
		NewEndDate:     newEndDate,
	})
	if err != nil {
		h.logger.Error("failed to renew subscription", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := h.toSubscriptionResponse(sub)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ExpireSubscription handles POST /subscriptions/{id}/expire
func (h *SubscriptionHandler) ExpireSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	subID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subscription ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req expireRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.ExpiredBy == "" {
		h.respondWithError(w, http.StatusBadRequest, "expired_by is required")
		return
	}
	expiredBy, err := uuid.Parse(req.ExpiredBy)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid expired_by")
		return
	}
	endDate, err := time.Parse(time.RFC3339, req.EndDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid end_date")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	sub, err := h.lifecycleService.Expire(ctx, &service.ExpireSubscriptionRequest{
		CompanyID:      companyID,
		SubscriptionID: subID,
		ExpiredBy:      expiredBy,
		EndDate:        endDate,
	})
	if err != nil {
		h.logger.Error("failed to expire subscription", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := h.toSubscriptionResponse(sub)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpgradeSubscription handles POST /subscriptions/{id}/upgrade

// DowngradeSubscription handles POST /subscriptions/{id}/downgrade
func (h *SubscriptionHandler) DowngradeSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	subID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subscription ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req downgradeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.NewPlanID == "" || req.DowngradedBy == "" {
		h.respondWithError(w, http.StatusBadRequest, "new_plan_id and downgraded_by are required")
		return
	}
	newPlanID, err := uuid.Parse(req.NewPlanID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid new_plan_id")
		return
	}
	downgradedBy, err := uuid.Parse(req.DowngradedBy)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid downgraded_by")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	sub, err := h.lifecycleService.Downgrade(ctx, &service.DowngradeSubscriptionRequest{
		CompanyID:      companyID,
		SubscriptionID: subID,
		NewPlanID:      newPlanID,
		DowngradedBy:   downgradedBy,
		Metadata:       req.Metadata,
	})
	if err != nil {
		h.logger.Error("failed to downgrade subscription", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := h.toSubscriptionResponse(sub)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ChangePlan handles POST /subscriptions/{id}/change-plan
func (h *SubscriptionHandler) ChangePlan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	subID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subscription ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req changePlanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.NewPlanID == "" || req.ChangedBy == "" {
		h.respondWithError(w, http.StatusBadRequest, "new_plan_id and changed_by are required")
		return
	}
	newPlanID, err := uuid.Parse(req.NewPlanID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid new_plan_id")
		return
	}
	changedBy, err := uuid.Parse(req.ChangedBy)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid changed_by")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	sub, err := h.lifecycleService.ChangePlan(ctx, &service.ChangeSubscriptionPlanRequest{
		CompanyID:      companyID,
		SubscriptionID: subID,
		NewPlanID:      newPlanID,
		ChangedBy:      changedBy,
		Metadata:       req.Metadata,
	})
	if err != nil {
		h.logger.Error("failed to change plan", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := h.toSubscriptionResponse(sub)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// CancelSubscription handles POST /subscriptions/{id}/cancel
func (h *SubscriptionHandler) CancelSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	subID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subscription ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req cancelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.CancelledBy == "" {
		h.respondWithError(w, http.StatusBadRequest, "cancelled_by is required")
		return
	}
	cancelledBy, err := uuid.Parse(req.CancelledBy)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid cancelled_by")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	sub, err := h.lifecycleService.Cancel(ctx, &service.CancelSubscriptionRequest{
		CompanyID:      companyID,
		SubscriptionID: subID,
		Reason:         req.Reason,
		CancelledBy:    cancelledBy,
		Immediate:      req.Immediate,
	})
	if err != nil {
		h.logger.Error("failed to cancel subscription", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := h.toSubscriptionResponse(sub)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ---------- Subscription Item Handlers ----------

type createItemRequest struct {
	PlanItemID string  `json:"plan_item_id"`
	AddonID    *string `json:"addon_id,omitempty"`
	Quantity   string  `json:"quantity"`
	UnitPrice  string  `json:"unit_price"`
	Currency   string  `json:"currency"`
	StartDate  string  `json:"start_date"`
}

type updateItemRequest struct {
	Quantity  *string `json:"quantity,omitempty"`
	UnitPrice *string `json:"unit_price,omitempty"`
	Currency  *string `json:"currency,omitempty"`
	Status    *string `json:"status,omitempty"` // active/inactive
}

type itemResponse struct {
	SubItemID      string  `json:"sub_item_id"`
	SubscriptionID string  `json:"subscription_id"`
	PlanItemID     string  `json:"plan_item_id"`
	AddonID        *string `json:"addon_id,omitempty"`
	Quantity       string  `json:"quantity"`
	UnitPrice      string  `json:"unit_price"`
	TotalPrice     string  `json:"total_price"`
	Currency       string  `json:"currency"`
	Status         string  `json:"status"`
	StartDate      string  `json:"start_date"`
	EndDate        *string `json:"end_date,omitempty"`
	CreatedAt      string  `json:"created_at"`
	UpdatedAt      string  `json:"updated_at"`
}

func (h *SubscriptionHandler) toItemResponse(item *models.SubscriptionItem) itemResponse {
	resp := itemResponse{
		SubItemID:      item.SubItemID.String(),
		SubscriptionID: item.SubscriptionID.String(),
		PlanItemID:     item.PlanItemID.String(),
		Quantity:       item.Quantity.String(),
		UnitPrice:      item.UnitPrice.String(),
		TotalPrice:     item.TotalPrice.String(),
		Currency:       item.Currency,
		Status:         string(item.Status),
		StartDate:      item.StartDate.Format(time.RFC3339),
		CreatedAt:      item.CreatedAt.Format(time.RFC3339),
		UpdatedAt:      item.UpdatedAt.Format(time.RFC3339),
	}
	if item.AddonID != nil {
		s := item.AddonID.String()
		resp.AddonID = &s
	}
	if item.EndDate != nil {
		s := item.EndDate.Format(time.RFC3339)
		resp.EndDate = &s
	}
	return resp
}

// GetSubscriptionItems handles GET /subscriptions/{id}/items
func (h *SubscriptionHandler) GetSubscriptionItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	subID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subscription ID")
		return
	}
	// optionally validate company, but we trust the service to check permissions via companyID from header?
	// We'll pass companyID to item service if needed, but most item methods don't require companyID.
	items, err := h.itemService.GetBySubscription(ctx, subID)
	if err != nil {
		h.logger.Error("failed to get subscription items", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to fetch items")
		return
	}
	responses := make([]itemResponse, len(items))
	for i, it := range items {
		responses[i] = h.toItemResponse(it)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responses,
	})
}

// AddSubscriptionItem handles POST /subscriptions/{id}/items
func (h *SubscriptionHandler) AddSubscriptionItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	subID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subscription ID")
		return
	}
	_, err = h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req createItemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.PlanItemID == "" || req.Quantity == "" || req.UnitPrice == "" || req.Currency == "" || req.StartDate == "" {
		h.respondWithError(w, http.StatusBadRequest, "plan_item_id, quantity, unit_price, currency, start_date are required")
		return
	}
	planItemID, err := uuid.Parse(req.PlanItemID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid plan_item_id")
		return
	}
	quantity, err := decimal.NewFromString(req.Quantity)
	if err != nil || quantity.LessThanOrEqual(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "invalid quantity")
		return
	}
	unitPrice, err := decimal.NewFromString(req.UnitPrice)
	if err != nil || unitPrice.LessThan(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "invalid unit_price")
		return
	}
	startDate, err := time.Parse(time.RFC3339, req.StartDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid start_date")
		return
	}
	var addonID *uuid.UUID
	if req.AddonID != nil {
		id, err := uuid.Parse(*req.AddonID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid addon_id")
			return
		}
		addonID = &id
	}

	item := &models.SubscriptionItem{
		SubItemID:      uuid.New(),
		SubscriptionID: subID,
		PlanItemID:     planItemID,
		AddonID:        addonID,
		Quantity:       quantity,
		UnitPrice:      unitPrice,
		Currency:       req.Currency,
		Status:         enums.ItemStatusActive,
		StartDate:      startDate,
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.itemService.AddToSubscription(ctx, subID, item); err != nil {
		h.logger.Error("failed to add item to subscription", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := h.toItemResponse(item)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateSubscriptionItem handles PUT /subscriptions/items/{itemId}
func (h *SubscriptionHandler) UpdateSubscriptionItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	itemID, err := h.parseUUIDParam(r, "itemId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid item ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req updateItemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Get existing item
	item, err := h.itemService.GetByID(ctx, companyID, itemID)
	if err != nil {
		h.logger.Error("failed to get item for update", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	if req.Quantity != nil {
		q, err := decimal.NewFromString(*req.Quantity)
		if err != nil || q.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid quantity")
			return
		}
		item.Quantity = q
	}
	if req.UnitPrice != nil {
		p, err := decimal.NewFromString(*req.UnitPrice)
		if err != nil || p.LessThan(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid unit_price")
			return
		}
		item.UnitPrice = p
	}
	if req.Currency != nil {
		if len(*req.Currency) != 3 {
			h.respondWithError(w, http.StatusBadRequest, "currency must be 3 characters")
			return
		}
		item.Currency = *req.Currency
	}
	if req.Status != nil {
		status := enums.ItemStatus(*req.Status)
		if !status.IsValid() {
			h.respondWithError(w, http.StatusBadRequest, "invalid status")
			return
		}
		item.Status = status
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.itemService.Update(ctx, item); err != nil {
		h.logger.Error("failed to update item", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := h.toItemResponse(item)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DeleteSubscriptionItem handles DELETE /subscriptions/items/{itemId}
func (h *SubscriptionHandler) DeleteSubscriptionItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	itemID, err := h.parseUUIDParam(r, "itemId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid item ID")
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

	if err := h.itemService.Delete(ctx, companyID, itemID); err != nil {
		h.logger.Error("failed to delete item", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "item deleted",
	})
}

// ---------- Provisioning Handlers (admin/internal) ----------

// ProvisionSubscription handles POST /subscriptions/{id}/provision
func (h *SubscriptionHandler) ProvisionSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	subID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subscription ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	sub, err := h.subService.GetByID(ctx, companyID, subID)
	if err != nil {
		h.logger.Error("failed to get subscription for provisioning", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.provisioningService.Provision(ctx, sub); err != nil {
		h.logger.Error("failed to provision subscription", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "subscription provisioned",
	})
}

// DeprovisionSubscription handles POST /subscriptions/{id}/deprovision
func (h *SubscriptionHandler) DeprovisionSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	subID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subscription ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	sub, err := h.subService.GetByID(ctx, companyID, subID)
	if err != nil {
		h.logger.Error("failed to get subscription for deprovisioning", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.provisioningService.Deprovision(ctx, sub); err != nil {
		h.logger.Error("failed to deprovision subscription", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "subscription deprovisioned",
	})
}

// ReprovisionSubscription handles POST /subscriptions/{id}/reprovision
func (h *SubscriptionHandler) ReprovisionSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	subID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subscription ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	sub, err := h.subService.GetByID(ctx, companyID, subID)
	if err != nil {
		h.logger.Error("failed to get subscription for reprovisioning", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	if err := h.provisioningService.Reprovision(ctx, sub); err != nil {
		h.logger.Error("failed to reprovision subscription", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "subscription reprovisioned",
	})
}

// ---------- Error Mapping ----------

func (h *SubscriptionHandler) mapServiceError(err error) (status int, message string) {
	switch {
	case errors.Is(err, subErrors.ErrNotFound),
		errors.Is(err, subErrors.ErrSubscriptionNotFound),
		errors.Is(err, subErrors.ErrPlanNotFound),
		errors.Is(err, subErrors.ErrAddonNotFound),
		errors.Is(err, subErrors.ErrTrialNotFound):
		return http.StatusNotFound, "resource not found"
	case errors.Is(err, subErrors.ErrInvalidInput),
		errors.Is(err, subErrors.ErrInvalidState),
		errors.Is(err, subErrors.ErrInvalidStatus),
		errors.Is(err, subErrors.ErrInvalidStatusTransition),
		errors.Is(err, subErrors.ErrVersionMismatch),
		errors.Is(err, subErrors.ErrSubscriptionInactive),
		errors.Is(err, subErrors.ErrSubscriptionCancelled),
		errors.Is(err, subErrors.ErrSubscriptionExpired),
		errors.Is(err, subErrors.ErrSubscriptionPaused),
		errors.Is(err, subErrors.ErrSubscriptionNotRenewable),
		errors.Is(err, subErrors.ErrPlanInactive),
		errors.Is(err, subErrors.ErrPlanNotPublished),
		errors.Is(err, subErrors.ErrAddonInactive),
		errors.Is(err, subErrors.ErrAddonAlreadyExists),
		errors.Is(err, subErrors.ErrAddonNotAttached),
		errors.Is(err, subErrors.ErrTrialAlreadyActive),
		errors.Is(err, subErrors.ErrTrialExpired),
		errors.Is(err, subErrors.ErrTrialNotActive),
		errors.Is(err, subErrors.ErrPlanHasNoItems),      // <-- NEW
		errors.Is(err, subErrors.ErrNoSubscriptionItems): // <-- NEW
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, subErrors.ErrDuplicate),
		errors.Is(err, subErrors.ErrConflict),
		errors.Is(err, subErrors.ErrConcurrentUpdate):
		return http.StatusConflict, err.Error()
	case errors.Is(err, subErrors.ErrPermissionDenied):
		return http.StatusForbidden, "permission denied"
	case errors.Is(err, subErrors.ErrUnauthorized):
		return http.StatusUnauthorized, "authentication required"
	default:
		return http.StatusInternalServerError, "internal server error"
	}
}

// UpgradeSubscription handles POST /subscriptions/{id}/upgrade
func (h *SubscriptionHandler) UpgradeSubscription(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	subID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subscription ID")
		return
	}
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req upgradeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.NewPlanID == "" || req.UpgradedBy == "" {
		h.respondWithError(w, http.StatusBadRequest, "new_plan_id and upgraded_by are required")
		return
	}
	newPlanID, err := uuid.Parse(req.NewPlanID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid new_plan_id")
		return
	}
	upgradedBy, err := uuid.Parse(req.UpgradedBy)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid upgraded_by")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	ctx = context.WithValue(ctx, "idempotency_key", idempotencyKey)

	// --- LOG: Upgrade attempt ---
	h.logger.Info("upgrade subscription request",
		zap.String("subscription_id", subID.String()),
		zap.String("new_plan_id", req.NewPlanID),
		zap.String("idempotency_key", idempotencyKey),
	)

	sub, err := h.lifecycleService.Upgrade(ctx, &service.UpgradeSubscriptionRequest{
		CompanyID:      companyID,
		SubscriptionID: subID,
		NewPlanID:      newPlanID,
		UpgradedBy:     upgradedBy,
		Metadata:       req.Metadata,
	})
	if err != nil {
		h.logger.Error("failed to upgrade subscription", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	// --- LOG: Result from lifecycle service ---
	if sub == nil {
		h.logger.Error("upgrade returned nil subscription without error")
		h.respondWithError(w, http.StatusInternalServerError, "upgrade failed: nil subscription")
		return
	}
	if sub.SubscriptionID == uuid.Nil {
		h.logger.Error("upgrade returned zero placeholder subscription",
			zap.String("subscription_id", sub.SubscriptionID.String()),
			zap.String("plan_id", sub.PlanID.String()),
			zap.String("status", string(sub.Status)),
		)
		// Still return 200 but with warning; or return error.
		// We'll return 500 to indicate an internal inconsistency.
		h.respondWithError(w, http.StatusInternalServerError, "upgrade resulted in invalid subscription")
		return
	}

	h.logger.Info("upgrade succeeded",
		zap.String("subscription_id", sub.SubscriptionID.String()),
		zap.String("new_plan_id", sub.PlanID.String()),
		zap.String("status", string(sub.Status)),
	)

	resp := h.toSubscriptionResponse(sub)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}
