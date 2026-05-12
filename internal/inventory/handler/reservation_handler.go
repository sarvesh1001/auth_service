package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models"
	"auth-service/internal/inventory/repository"
	"auth-service/internal/inventory/service"
)

type ReservationHandler struct {
	reservationSvc  service.ReservationService
	reservationRepo repository.ReservationRepository
	pgClient        *client.PostgresClient
	logger          *zap.Logger
}

func NewReservationHandler(
	reservationSvc service.ReservationService,
	reservationRepo repository.ReservationRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) *ReservationHandler {
	return &ReservationHandler{
		reservationSvc:  reservationSvc,
		reservationRepo: reservationRepo,
		pgClient:        pgClient,
		logger:          logger.Named("reservation_handler"),
	}
}

type createReservationRequest struct {
	ReservationType string     `json:"reservation_type"`
	ReferenceID     string     `json:"reference_id"`
	WarehouseID     string     `json:"warehouse_id"`
	ItemID          string     `json:"item_id"`
	BatchID         *string    `json:"batch_id,omitempty"`
	Quantity        float64    `json:"quantity"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
}

type reservationResponse struct {
	ReservationID   string     `json:"reservation_id"`
	CompanyID       string     `json:"company_id"`
	ReservationType string     `json:"reservation_type"`
	ReferenceID     string     `json:"reference_id"`
	WarehouseID     string     `json:"warehouse_id"`
	ItemID          string     `json:"item_id"`
	BatchID         *string    `json:"batch_id,omitempty"`
	Quantity        float64    `json:"quantity"`
	Status          string     `json:"status"`
	CreatedAt       time.Time  `json:"created_at"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
}

func (h *ReservationHandler) CreateReservation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseCompanyID(w, r)
	if err != nil {
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "reservation:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	var req createReservationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// ✅ Validate reservation_type against allowed values
	allowedReservationTypes := map[string]bool{
		"sales_order":    true,
		"fulfillment":    true,
		"purchase_order": true,
		"transfer":       true,
		"adjustment":     true,
	}
	if !allowedReservationTypes[req.ReservationType] {
		h.respondWithError(w, http.StatusBadRequest,
			"invalid reservation_type: must be one of sales_order, fulfillment, purchase_order, transfer, adjustment")
		return
	}

	referenceID, err := uuid.Parse(req.ReferenceID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "reference_id must be a valid UUID")
		return
	}

	warehouseID, err := uuid.Parse(req.WarehouseID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid warehouse_id")
		return
	}

	itemID, err := uuid.Parse(req.ItemID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid item_id")
		return
	}

	var batchID *uuid.UUID
	if req.BatchID != nil && *req.BatchID != "" {
		parsed, err := uuid.Parse(*req.BatchID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid batch_id")
			return
		}
		batchID = &parsed
	}

	quantity := decimal.NewFromFloat(req.Quantity)
	if quantity.IsZero() || quantity.LessThan(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "quantity must be positive")
		return
	}

	// Optional: validate expiry is in future
	if req.ExpiresAt != nil && req.ExpiresAt.Before(time.Now()) {
		h.respondWithError(w, http.StatusUnprocessableEntity, "expiry date must be in the future")
		return
	}

	tx, err := h.pgClient.BeginTx(ctx, nil)
	if err != nil {
		h.logger.Error("failed to begin transaction", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	defer tx.Rollback()

	svcReq := service.CreateReservationRequest{
		CompanyID:       companyID,
		ReservationType: req.ReservationType,
		ReferenceID:     referenceID,
		WarehouseID:     warehouseID,
		ItemID:          itemID,
		BatchID:         batchID,
		Quantity:        quantity,
		ExpiresAt:       req.ExpiresAt,
		CreatedBy:       &userID,
	}

	reservation, err := h.reservationSvc.CreateReservation(ctx, tx, svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to create reservation", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrInvalidInput):
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, inventory_errors.ErrInsufficientStock):
			h.respondWithError(w, http.StatusConflict, err.Error())
		case errors.Is(err, inventory_errors.ErrExpiryInPast):
			h.respondWithError(w, http.StatusUnprocessableEntity, err.Error())
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to create reservation")
		}
		return
	}

	if err := tx.Commit(); err != nil {
		h.logger.Error("failed to commit transaction", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    h.toReservationResponse(reservation),
		"message": "Reservation created successfully",
	})
}

func (h *ReservationHandler) FulfillReservation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseCompanyID(w, r)
	if err != nil {
		return
	}

	reservationID, err := h.parseReservationID(w, r)
	if err != nil {
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "reservation:fulfill") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	tx, err := h.pgClient.BeginTx(ctx, nil)
	if err != nil {
		h.logger.Error("failed to begin transaction", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	defer tx.Rollback()

	err = h.reservationSvc.FulfillReservation(ctx, tx, reservationID, companyID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to fulfill reservation", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrNotFound):
			h.respondWithError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, inventory_errors.ErrPermissionDenied):
			h.respondWithError(w, http.StatusForbidden, err.Error())
		default:
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	if err := tx.Commit(); err != nil {
		h.logger.Error("failed to commit transaction", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Reservation fulfilled successfully",
	})
}

func (h *ReservationHandler) CancelReservation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseCompanyID(w, r)
	if err != nil {
		return
	}

	reservationID, err := h.parseReservationID(w, r)
	if err != nil {
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "reservation:cancel") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	tx, err := h.pgClient.BeginTx(ctx, nil)
	if err != nil {
		h.logger.Error("failed to begin transaction", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	defer tx.Rollback()

	err = h.reservationSvc.CancelReservation(ctx, tx, reservationID, companyID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to cancel reservation", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrNotFound):
			h.respondWithError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, inventory_errors.ErrPermissionDenied):
			h.respondWithError(w, http.StatusForbidden, err.Error())
		default:
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	if err := tx.Commit(); err != nil {
		h.logger.Error("failed to commit transaction", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Reservation cancelled successfully",
	})
}

func (h *ReservationHandler) ExpireReservations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseCompanyID(w, r)
	if err != nil {
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "reservation:expire") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		idempotencyKey = fmt.Sprintf("expire:%s:%d", companyID.String(), time.Now().Unix())
	}

	tx, err := h.pgClient.BeginTx(ctx, nil)
	if err != nil {
		h.logger.Error("failed to begin transaction", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	defer tx.Rollback()

	count, err := h.reservationSvc.ExpireReservations(ctx, tx, companyID)
	if err != nil {
		h.logger.Error("failed to expire reservations", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to expire reservations")
		return
	}

	if err := tx.Commit(); err != nil {
		h.logger.Error("failed to commit transaction", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]int64{"expired_count": count},
		"message": "Expired reservations processed",
	})
}

func (h *ReservationHandler) ListReservations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.parseCompanyID(w, r)
	if err != nil {
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "reservation:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	filter := repository.ReservationFilter{
		CompanyID: companyID,
	}

	if rt := r.URL.Query().Get("reservation_type"); rt != "" {
		filter.ReservationType = rt
	}
	if refIDStr := r.URL.Query().Get("reference_id"); refIDStr != "" {
		refID, err := uuid.Parse(refIDStr)
		if err == nil {
			filter.ReferenceID = &refID
		}
	}
	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = status
	}

	pagination := repository.Pagination{
		Limit:  20,
		Offset: 0,
	}
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 {
			pagination.Limit = limit
		}
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			pagination.Offset = offset
		}
	}

	sort := repository.Sort{
		Field:     "created_at",
		Direction: "DESC",
	}
	if sortField := r.URL.Query().Get("sort_field"); sortField != "" {
		sort.Field = sortField
	}
	if sortDir := r.URL.Query().Get("sort_order"); sortDir != "" {
		sort.Direction = sortDir
	}

	reservations, err := h.reservationRepo.List(ctx, h.pgClient.DB, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list reservations", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list reservations")
		return
	}

	responseList := make([]reservationResponse, 0, len(reservations))
	for _, res := range reservations {
		responseList = append(responseList, h.toReservationResponse(res))
	}

	total, err := h.reservationRepo.Count(ctx, h.pgClient.DB, filter)
	if err != nil {
		h.logger.Error("failed to count reservations", zap.Error(err))
		total = int64(len(reservations))
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":  responseList,
			"total":  total,
			"limit":  pagination.Limit,
			"offset": pagination.Offset,
		},
	})
}

func (h *ReservationHandler) parseCompanyID(w http.ResponseWriter, r *http.Request) (uuid.UUID, error) {
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return uuid.Nil, err
	}
	return companyID, nil
}

func (h *ReservationHandler) parseReservationID(w http.ResponseWriter, r *http.Request) (uuid.UUID, error) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid reservation ID")
		return uuid.Nil, err
	}
	return id, nil
}

// placeholder – replace with actual permission logic
func (h *ReservationHandler) hasPermission(ctx context.Context, companyID, userID uuid.UUID, permission string) bool {
	return true
}

func (h *ReservationHandler) toReservationResponse(res *models.Reservation) reservationResponse {
	var batchIDStr *string
	if res.BatchID != nil {
		s := res.BatchID.String()
		batchIDStr = &s
	}
	quantity, _ := res.Quantity.Float64()
	return reservationResponse{
		ReservationID:   res.ReservationID.String(),
		CompanyID:       res.CompanyID.String(),
		ReservationType: res.ReservationType,
		ReferenceID:     res.ReferenceID.String(),
		WarehouseID:     res.WarehouseID.String(),
		ItemID:          res.ItemID.String(),
		BatchID:         batchIDStr,
		Quantity:        quantity,
		Status:          res.Status,
		CreatedAt:       res.CreatedAt,
		ExpiresAt:       res.ExpiresAt,
	}
}

func (h *ReservationHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *ReservationHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
