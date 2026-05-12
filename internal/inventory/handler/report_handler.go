package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models/enums"
	"auth-service/internal/inventory/service"
)

type ReportHandler struct {
	querySvc     service.InventoryQueryService
	valuationSvc service.ValuationService
	analyticsSvc service.InventoryAnalyticsService
	logger       *zap.Logger
}

func NewReportHandler(
	querySvc service.InventoryQueryService,
	valuationSvc service.ValuationService,
	analyticsSvc service.InventoryAnalyticsService,
	logger *zap.Logger,
) *ReportHandler {
	return &ReportHandler{
		querySvc:     querySvc,
		valuationSvc: valuationSvc,
		analyticsSvc: analyticsSvc,
		logger:       logger.Named("report_handler"),
	}
}

type valuationRequest struct {
	ItemID      string    `json:"itemId"`
	WarehouseID *string   `json:"warehouseId,omitempty"`
	AsOfDate    time.Time `json:"asOfDate"`
	Method      string    `json:"method"`
}

func (h *ReportHandler) GetItemValuation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromPath(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req valuationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	itemUUID, err := uuid.Parse(req.ItemID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid itemId")
		return
	}

	var warehouseUUID *uuid.UUID
	if req.WarehouseID != nil && *req.WarehouseID != "" {
		parsed, err := uuid.Parse(*req.WarehouseID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid warehouseId")
			return
		}
		warehouseUUID = &parsed
	}

	var method enums.ValuationMethod
	if req.Method != "" {
		method = enums.ValuationMethod(req.Method)
		if !method.IsValid() {
			h.respondWithError(w, http.StatusBadRequest, "invalid valuation method")
			return
		}
	}

	valuationReq := service.ValuationRequest{
		CompanyID:   companyID,
		ItemID:      itemUUID,
		WarehouseID: warehouseUUID,
		AsOfDate:    req.AsOfDate,
		Method:      method,
	}

	result, err := h.valuationSvc.GetItemValuation(ctx, valuationReq)
	if err != nil {
		h.logger.Error("failed to get item valuation", zap.Error(err))
		if errors.Is(err, inventory_errors.ErrNotFound) {
			h.respondWithError(w, http.StatusNotFound, "item not found")
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to compute valuation")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

func (h *ReportHandler) GetCompanyValuation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromPath(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	asOfDateStr := r.URL.Query().Get("asOfDate")
	var asOfDate time.Time
	if asOfDateStr == "" {
		asOfDate = time.Now().UTC()
	} else {
		// Use same YYYY-MM-DD format as all other valuation endpoints
		asOfDate, err = time.Parse("2006-01-02", asOfDateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid asOfDate format, use YYYY-MM-DD")
			return
		}
	}

	results, err := h.valuationSvc.GetCompanyValuation(ctx, companyID, asOfDate)
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

type snapshotRequest struct {
	ValuationDate time.Time `json:"valuationDate"`
}

func (h *ReportHandler) GenerateValuationSnapshot(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromPath(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	var req snapshotRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.ValuationDate.IsZero() {
		req.ValuationDate = time.Now().UTC()
	}

	err = h.valuationSvc.CreateValuationSnapshot(ctx, companyID, req.ValuationDate)
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
		"message": "Valuation snapshot generated successfully",
	})
}

func (h *ReportHandler) GetLowStockReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromPath(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	items, err := h.querySvc.GetLowStockItems(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get low stock items", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve low stock items")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    items,
	})
}

func (h *ReportHandler) GetExpiringBatches(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromPath(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	daysStr := r.URL.Query().Get("days")
	days := 30
	if daysStr != "" {
		days, err = strconv.Atoi(daysStr)
		if err != nil || days < 0 {
			h.respondWithError(w, http.StatusBadRequest, "days must be a non-negative integer")
			return
		}
	}

	batches, err := h.querySvc.GetExpiringBatches(ctx, companyID, days)
	if err != nil {
		h.logger.Error("failed to get expiring batches", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve expiring batches")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    batches,
	})
}

func (h *ReportHandler) GetStockLevelsReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromPath(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	warehouseIDStr := r.URL.Query().Get("warehouseId")
	itemIDStr := r.URL.Query().Get("itemId")

	var filter service.StockFilter
	filter.CompanyID = companyID

	if warehouseIDStr != "" {
		whID, err := uuid.Parse(warehouseIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid warehouseId")
			return
		}
		filter.WarehouseID = &whID
	}
	if itemIDStr != "" {
		itID, err := uuid.Parse(itemIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid itemId")
			return
		}
		filter.ItemID = &itID
	}

	var balances []*service.StockLevel
	if filter.WarehouseID != nil && filter.ItemID != nil {
		stock, err := h.querySvc.GetCurrentStock(ctx, companyID, *filter.WarehouseID, *filter.ItemID, nil)
		if err != nil {
			h.respondWithError(w, http.StatusInternalServerError, "failed to get stock")
			return
		}
		balances = []*service.StockLevel{stock}
	} else if filter.WarehouseID != nil {
		balances, err = h.querySvc.GetAllStockByWarehouse(ctx, companyID, *filter.WarehouseID)
		if err != nil {
			h.respondWithError(w, http.StatusInternalServerError, "failed to get warehouse stock")
			return
		}
	} else if filter.ItemID != nil {
		balances, err = h.querySvc.GetAllStockByItem(ctx, companyID, *filter.ItemID)
		if err != nil {
			h.respondWithError(w, http.StatusInternalServerError, "failed to get item stock")
			return
		}
	} else {
		h.respondWithError(w, http.StatusBadRequest, "provide at least warehouseId or itemId")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    balances,
	})
}

// Helper functions

func getCompanyIDFromPath(r *http.Request) (uuid.UUID, error) {
	companyIDStr := chi.URLParam(r, "companyID")
	if companyIDStr == "" {
		return uuid.Nil, fmt.Errorf("companyID is required")
	}
	return uuid.Parse(companyIDStr)
}

func (h *ReportHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *ReportHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
