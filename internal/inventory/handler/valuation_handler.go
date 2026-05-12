package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models/enums"
	"auth-service/internal/inventory/service"
)

type ValuationHandler struct {
	valuationService service.ValuationService
	logger           *zap.Logger
}

func NewValuationHandler(valuationService service.ValuationService, logger *zap.Logger) *ValuationHandler {
	return &ValuationHandler{
		valuationService: valuationService,
		logger:           logger.Named("valuation_handler"),
	}
}

func (h *ValuationHandler) GetItemValuation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromParam(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	itemID, err := parseUUIDFromParam(r, "itemId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid item ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "valuation:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	query := r.URL.Query()
	var warehouseID *uuid.UUID
	if whStr := query.Get("warehouseId"); whStr != "" {
		whID, err := uuid.Parse(whStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid warehouseId")
			return
		}
		warehouseID = &whID
	}

	asOfDate := time.Now().UTC()
	if dateStr := query.Get("asOfDate"); dateStr != "" {
		parsed, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid asOfDate format, use YYYY-MM-DD")
			return
		}
		asOfDate = parsed
	}

	var method enums.ValuationMethod
	if methodStr := query.Get("method"); methodStr != "" {
		method = enums.ValuationMethod(methodStr)
		if !method.IsValid() {
			h.respondWithError(w, http.StatusBadRequest, "invalid valuation method")
			return
		}
	}

	req := service.ValuationRequest{
		CompanyID:   companyID,
		ItemID:      itemID,
		WarehouseID: warehouseID,
		AsOfDate:    asOfDate,
		Method:      method,
	}

	result, err := h.valuationService.GetItemValuation(ctx, req)
	if err != nil {
		h.logger.Error("failed to get item valuation", zap.Error(err))
		switch {
		case errors.Is(err, inventory_errors.ErrInvalidInput):
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, inventory_errors.ErrNotFound):
			h.respondWithError(w, http.StatusNotFound, "item not found")
		default:
			h.respondWithError(w, http.StatusInternalServerError, "failed to compute valuation")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

func (h *ValuationHandler) GetCompanyValuation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromParam(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "valuation:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	asOfDate := time.Now().UTC()
	if dateStr := r.URL.Query().Get("asOfDate"); dateStr != "" {
		parsed, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid asOfDate format, use YYYY-MM-DD")
			return
		}
		asOfDate = parsed
	}

	results, err := h.valuationService.GetCompanyValuation(ctx, companyID, asOfDate)
	if err != nil {
		h.logger.Error("failed to get company valuation", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to compute company valuation")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    results,
	})
}

func (h *ValuationHandler) GetCOGS(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromParam(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	itemID, err := parseUUIDFromParam(r, "itemId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid item ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "valuation:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	if fromStr == "" || toStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "both 'from' and 'to' query parameters are required")
		return
	}

	from, err := time.Parse("2006-01-02", fromStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid 'from' format, use YYYY-MM-DD")
		return
	}
	to, err := time.Parse("2006-01-02", toStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid 'to' format, use YYYY-MM-DD")
		return
	}
	if from.After(to) {
		h.respondWithError(w, http.StatusBadRequest, "'from' date must be before or equal to 'to' date")
		return
	}

	cogs, err := h.valuationService.GetCOGS(ctx, companyID, itemID, from, to)
	if err != nil {
		h.logger.Error("failed to get COGS", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to compute COGS")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"itemId": itemID,
			"from":   from,
			"to":     to,
			"cogs":   cogs,
		},
	})
}

func (h *ValuationHandler) CreateValuationSnapshot(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromParam(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "valuation:create_snapshot") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		idempotencyKey = fmt.Sprintf("valuation_snapshot:%s:%d", companyID, time.Now().Unix())
	}

	var req struct {
		ValuationDate time.Time `json:"valuationDate"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	valuationDate := req.ValuationDate
	if valuationDate.IsZero() {
		valuationDate = time.Now().UTC()
	}
	valuationDate = valuationDate.Truncate(24 * time.Hour)

	err = h.valuationService.CreateValuationSnapshot(ctx, companyID, valuationDate)
	if err != nil {
		h.logger.Error("failed to create valuation snapshot", zap.Error(err))
		if errors.Is(err, inventory_errors.ErrConflict) {
			h.respondWithError(w, http.StatusConflict, err.Error())
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to create snapshot")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Valuation snapshot created successfully",
		"data": map[string]interface{}{
			"companyId":     companyID,
			"valuationDate": valuationDate,
		},
	})
}

// hasPermission is a stub – replace with real permission check
func (h *ValuationHandler) hasPermission(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, permission string) bool {
	return true
}

func (h *ValuationHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *ValuationHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

func parseUUIDFromParam(r *http.Request, paramName string) (uuid.UUID, error) {
	paramStr := chi.URLParam(r, paramName)
	return uuid.Parse(paramStr)
}

// getUserIDFromContext is a stub – replace with real context extraction
