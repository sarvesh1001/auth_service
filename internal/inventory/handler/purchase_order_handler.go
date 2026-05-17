package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/repository"
	"auth-service/internal/inventory/service"
)

type PurchaseOrderHandler struct {
	poService service.PurchaseOrderService
	logger    *zap.Logger
}

func NewPurchaseOrderHandler(poService service.PurchaseOrderService, logger *zap.Logger) *PurchaseOrderHandler {
	return &PurchaseOrderHandler{
		poService: poService,
		logger:    logger.Named("purchase_order_handler"),
	}
}

// ---------- Vendor endpoints ----------

type createVendorRequest struct {
	VendorCode      string  `json:"vendorCode"`
	VendorName      string  `json:"vendorName"`
	VendorType      *string `json:"vendorType,omitempty"`
	ContactPerson   string  `json:"contactPerson,omitempty"`
	Phone           string  `json:"phone,omitempty"`
	Email           string  `json:"email,omitempty"`
	Address         string  `json:"address,omitempty"`
	BankAccountNo   string  `json:"bankAccountNo,omitempty"`
	BankRoutingCode string  `json:"bankRoutingCode,omitempty"`
	BankName        string  `json:"bankName,omitempty"`
	IsActive        bool    `json:"isActive"`
}

func (h *PurchaseOrderHandler) CreateVendor(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req createVendorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	svcReq := service.CreateVendorRequest{
		CompanyID:       companyID,
		VendorCode:      req.VendorCode,
		VendorName:      req.VendorName,
		VendorType:      req.VendorType,
		ContactPerson:   req.ContactPerson,
		Phone:           req.Phone,
		Email:           req.Email,
		Address:         req.Address,
		BankAccountNo:   req.BankAccountNo,
		BankRoutingCode: req.BankRoutingCode,
		BankName:        req.BankName,
		IsActive:        req.IsActive,
		CreatedBy:       &userID,
	}

	idempotencyKey := getIdempotencyKey(r)
	vendor, err := h.poService.CreateVendor(ctx, svcReq, idempotencyKey)
	if err != nil {
		if errors.Is(err, inventory_errors.ErrDuplicate) {
			h.respondError(w, http.StatusConflict, err.Error())
			return
		}
		if errors.Is(err, inventory_errors.ErrInvalidInput) {
			h.respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		h.logger.Error("failed to create vendor", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to create vendor")
		return
	}

	h.respondJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    vendor,
	})
}

func (h *PurchaseOrderHandler) GetVendor(w http.ResponseWriter, r *http.Request) {
	vendorIDStr := chi.URLParam(r, "vendorId")
	vendorID, err := uuid.Parse(vendorIDStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid vendor ID")
		return
	}

	vendor, err := h.poService.GetVendor(r.Context(), vendorID)
	if err != nil {
		if errors.Is(err, inventory_errors.ErrNotFound) {
			h.respondError(w, http.StatusNotFound, "vendor not found")
			return
		}
		h.logger.Error("failed to get vendor", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to retrieve vendor")
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    vendor,
	})
}

func (h *PurchaseOrderHandler) ListVendors(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	query := r.URL.Query()
	pageRaw, _ := strconv.Atoi(query.Get("page"))
	pageSizeRaw, _ := strconv.Atoi(query.Get("pageSize"))

	page := pageRaw
	if page < 1 {
		page = 1
	}
	pageSize := pageSizeRaw
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}

	filter := repository.VendorFilter{
		CompanyID:  companyID,
		VendorCode: query.Get("vendorCode"),
		VendorName: query.Get("vendorName"),
		VendorType: query.Get("vendorType"),
		Search:     query.Get("search"),
	}
	if isActive := query.Get("isActive"); isActive != "" {
		active := isActive == "true"
		filter.IsActive = &active
	}

	vendors, total, err := h.poService.ListVendors(ctx, filter, page, pageSize)
	if err != nil {
		h.logger.Error("failed to list vendors", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to list vendors")
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":    vendors,
			"total":    total,
			"page":     page,
			"pageSize": pageSize,
		},
	})
}

type updateVendorRequest struct {
	VendorName      *string `json:"vendorName,omitempty"`
	VendorType      *string `json:"vendorType,omitempty"`
	ContactPerson   *string `json:"contactPerson,omitempty"`
	Phone           *string `json:"phone,omitempty"`
	Email           *string `json:"email,omitempty"`
	Address         *string `json:"address,omitempty"`
	BankAccountNo   *string `json:"bankAccountNo,omitempty"`
	BankRoutingCode *string `json:"bankRoutingCode,omitempty"`
	BankName        *string `json:"bankName,omitempty"`
	IsActive        *bool   `json:"isActive,omitempty"`
}

func (h *PurchaseOrderHandler) UpdateVendor(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	vendorIDStr := chi.URLParam(r, "vendorId")
	vendorID, err := uuid.Parse(vendorIDStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid vendor ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	existing, err := h.poService.GetVendor(ctx, vendorID)
	if err != nil {
		if errors.Is(err, inventory_errors.ErrNotFound) {
			h.respondError(w, http.StatusNotFound, "vendor not found")
			return
		}
		h.respondError(w, http.StatusInternalServerError, "failed to fetch vendor")
		return
	}
	if existing.CompanyID != companyID {
		h.respondError(w, http.StatusForbidden, "vendor does not belong to this company")
		return
	}

	var req updateVendorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.VendorName != nil {
		existing.VendorName = *req.VendorName
	}
	if req.VendorType != nil {
		existing.VendorType = req.VendorType
	}
	if req.ContactPerson != nil {
		existing.ContactPerson = *req.ContactPerson
	}
	if req.Phone != nil {
		existing.Phone = *req.Phone
	}
	if req.Email != nil {
		existing.Email = *req.Email
	}
	if req.Address != nil {
		existing.Address = *req.Address
	}
	if req.BankAccountNo != nil {
		existing.BankAccountNo = *req.BankAccountNo
	}
	if req.BankRoutingCode != nil {
		existing.BankRoutingCode = *req.BankRoutingCode
	}
	if req.BankName != nil {
		existing.BankName = *req.BankName
	}
	if req.IsActive != nil {
		existing.IsActive = *req.IsActive
	}
	existing.UpdatedBy = &userID

	idempotencyKey := getIdempotencyKey(r)
	if err := h.poService.UpdateVendor(ctx, existing, idempotencyKey); err != nil {
		h.logger.Error("failed to update vendor", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to update vendor")
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Vendor updated successfully",
	})
}

func (h *PurchaseOrderHandler) DeleteVendor(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	vendorIDStr := chi.URLParam(r, "vendorId")
	vendorID, err := uuid.Parse(vendorIDStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid vendor ID")
		return
	}

	existing, err := h.poService.GetVendor(ctx, vendorID)
	if err != nil {
		if errors.Is(err, inventory_errors.ErrNotFound) {
			h.respondError(w, http.StatusNotFound, "vendor not found")
			return
		}
		h.respondError(w, http.StatusInternalServerError, "failed to fetch vendor")
		return
	}
	if existing.CompanyID != companyID {
		h.respondError(w, http.StatusForbidden, "vendor does not belong to this company")
		return
	}

	idempotencyKey := getIdempotencyKey(r)
	if err := h.poService.DeleteVendor(ctx, vendorID, idempotencyKey); err != nil {
		h.logger.Error("failed to delete vendor", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to delete vendor")
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Vendor deleted successfully",
	})
}

// ---------- Purchase Order endpoints ----------

type createPurchaseOrderRequest struct {
	PONumber             string                   `json:"poNumber"`
	VendorID             string                   `json:"vendorId"`
	OrderDate            string                   `json:"orderDate"`
	ExpectedDeliveryDate *string                  `json:"expectedDeliveryDate,omitempty"`
	Items                []purchaseOrderItemInput `json:"items"`
	Notes                *string                  `json:"notes,omitempty"`
}

type purchaseOrderItemInput struct {
	ItemID          string `json:"itemId"`
	QuantityOrdered string `json:"quantityOrdered"` // decimal
	UnitCost        string `json:"unitCost"`        // decimal
}

func (h *PurchaseOrderHandler) CreatePurchaseOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req createPurchaseOrderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	vendorID, err := uuid.Parse(req.VendorID)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid vendorId")
		return
	}

	orderDate, err := time.Parse(time.RFC3339, req.OrderDate)
	if err != nil {
		orderDate, err = time.Parse("2006-01-02", req.OrderDate)
		if err != nil {
			h.respondError(w, http.StatusBadRequest, "invalid orderDate format (use YYYY-MM-DD or RFC3339)")
			return
		}
	}

	var expectedDeliveryDate *time.Time
	if req.ExpectedDeliveryDate != nil && *req.ExpectedDeliveryDate != "" {
		ed, err := time.Parse(time.RFC3339, *req.ExpectedDeliveryDate)
		if err != nil {
			ed, err = time.Parse("2006-01-02", *req.ExpectedDeliveryDate)
			if err != nil {
				h.respondError(w, http.StatusBadRequest, "invalid expectedDeliveryDate format")
				return
			}
		}
		expectedDeliveryDate = &ed
	}

	items := make([]service.PurchaseOrderItemInput, len(req.Items))
	for i, it := range req.Items {
		itemID, err := uuid.Parse(it.ItemID)
		if err != nil {
			h.respondError(w, http.StatusBadRequest, "invalid itemId in items")
			return
		}
		qty, err := decimal.NewFromString(it.QuantityOrdered)
		if err != nil {
			h.respondError(w, http.StatusBadRequest, "invalid quantityOrdered")
			return
		}
		cost, err := decimal.NewFromString(it.UnitCost)
		if err != nil {
			h.respondError(w, http.StatusBadRequest, "invalid unitCost")
			return
		}
		items[i] = service.PurchaseOrderItemInput{
			ItemID:          itemID,
			QuantityOrdered: qty,
			UnitCost:        cost,
		}
	}

	svcReq := service.CreatePurchaseOrderRequest{
		CompanyID:            companyID,
		PONumber:             req.PONumber,
		VendorID:             vendorID,
		OrderDate:            orderDate,
		ExpectedDeliveryDate: expectedDeliveryDate,
		Items:                items,
		Notes:                req.Notes,
		CreatedBy:            &userID,
	}

	idempotencyKey := getIdempotencyKey(r)
	po, err := h.poService.CreatePurchaseOrder(ctx, svcReq, idempotencyKey)
	if err != nil {
		switch {
		case errors.Is(err, inventory_errors.ErrDuplicate):
			h.respondError(w, http.StatusConflict, err.Error())
		case errors.Is(err, inventory_errors.ErrInvalidInput):
			h.respondError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, inventory_errors.ErrNotFound):
			// Vendor not found, etc.
			h.respondError(w, http.StatusNotFound, err.Error())
		default:
			h.logger.Error("failed to create purchase order", zap.Error(err))
			h.respondError(w, http.StatusInternalServerError, "failed to create purchase order")
		}
		return
	}

	h.respondJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    po,
	})
}

func (h *PurchaseOrderHandler) GetPurchaseOrder(w http.ResponseWriter, r *http.Request) {
	poIDStr := chi.URLParam(r, "purchaseOrderId")
	poID, err := uuid.Parse(poIDStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid purchase order ID")
		return
	}

	po, err := h.poService.GetPurchaseOrder(r.Context(), poID)
	if err != nil {
		if errors.Is(err, inventory_errors.ErrNotFound) {
			h.respondError(w, http.StatusNotFound, "purchase order not found")
			return
		}
		h.logger.Error("failed to get purchase order", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to retrieve purchase order")
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    po,
	})
}

func (h *PurchaseOrderHandler) ListPurchaseOrders(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	query := r.URL.Query()
	pageRaw, _ := strconv.Atoi(query.Get("page"))
	pageSizeRaw, _ := strconv.Atoi(query.Get("pageSize"))

	page := pageRaw
	if page < 1 {
		page = 1
	}
	pageSize := pageSizeRaw
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}

	filter := repository.PurchaseOrderFilter{
		CompanyID: companyID,
		Status:    query.Get("status"),
	}
	if vendorIDStr := query.Get("vendorId"); vendorIDStr != "" {
		vid, err := uuid.Parse(vendorIDStr)
		if err == nil {
			filter.VendorID = &vid
		}
	}
	if fromDateStr := query.Get("fromOrderDate"); fromDateStr != "" {
		if t, err := time.Parse("2006-01-02", fromDateStr); err == nil {
			filter.FromOrderDate = &t
		}
	}
	if toDateStr := query.Get("toOrderDate"); toDateStr != "" {
		if t, err := time.Parse("2006-01-02", toDateStr); err == nil {
			filter.ToOrderDate = &t
		}
	}

	pos, total, err := h.poService.ListPurchaseOrders(ctx, filter, page, pageSize)
	if err != nil {
		if errors.Is(err, inventory_errors.ErrInvalidStatus) {
			h.respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		h.logger.Error("failed to list purchase orders", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to list purchase orders")
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":    pos,
			"total":    total,
			"page":     page,
			"pageSize": pageSize,
		},
	})
}

type updatePOStatusRequest struct {
	Status string `json:"status"`
}

func (h *PurchaseOrderHandler) UpdatePurchaseOrderStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	poIDStr := chi.URLParam(r, "purchaseOrderId")
	poID, err := uuid.Parse(poIDStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid purchase order ID")
		return
	}

	po, err := h.poService.GetPurchaseOrder(ctx, poID)
	if err != nil {
		if errors.Is(err, inventory_errors.ErrNotFound) {
			h.respondError(w, http.StatusNotFound, "purchase order not found")
			return
		}
		h.respondError(w, http.StatusInternalServerError, "failed to fetch purchase order")
		return
	}
	if po.CompanyID != companyID {
		h.respondError(w, http.StatusForbidden, "purchase order does not belong to this company")
		return
	}

	var req updatePOStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	idempotencyKey := getIdempotencyKey(r)
	if err := h.poService.UpdatePurchaseOrderStatus(ctx, poID, req.Status, idempotencyKey); err != nil {
		if errors.Is(err, inventory_errors.ErrInvalidStatus) || errors.Is(err, inventory_errors.ErrInvalidTransition) {
			h.respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		h.logger.Error("failed to update PO status", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to update status")
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Purchase order status updated",
	})
}

type addPOItemsRequest struct {
	Items []purchaseOrderItemInput `json:"items"`
}

func (h *PurchaseOrderHandler) AddPurchaseOrderItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	poIDStr := chi.URLParam(r, "purchaseOrderId")
	poID, err := uuid.Parse(poIDStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid purchase order ID")
		return
	}

	po, err := h.poService.GetPurchaseOrder(ctx, poID)
	if err != nil {
		if errors.Is(err, inventory_errors.ErrNotFound) {
			h.respondError(w, http.StatusNotFound, "purchase order not found")
			return
		}
		h.respondError(w, http.StatusInternalServerError, "failed to fetch purchase order")
		return
	}
	if po.CompanyID != companyID {
		h.respondError(w, http.StatusForbidden, "purchase order does not belong to this company")
		return
	}

	var req addPOItemsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	items := make([]service.PurchaseOrderItemInput, len(req.Items))
	for i, it := range req.Items {
		itemID, err := uuid.Parse(it.ItemID)
		if err != nil {
			h.respondError(w, http.StatusBadRequest, "invalid itemId in items")
			return
		}
		qty, err := decimal.NewFromString(it.QuantityOrdered)
		if err != nil {
			h.respondError(w, http.StatusBadRequest, "invalid quantityOrdered")
			return
		}
		cost, err := decimal.NewFromString(it.UnitCost)
		if err != nil {
			h.respondError(w, http.StatusBadRequest, "invalid unitCost")
			return
		}
		items[i] = service.PurchaseOrderItemInput{
			ItemID:          itemID,
			QuantityOrdered: qty,
			UnitCost:        cost,
		}
	}

	idempotencyKey := getIdempotencyKey(r)
	if err := h.poService.AddPurchaseOrderItems(ctx, poID, items, idempotencyKey); err != nil {
		switch {
		case errors.Is(err, inventory_errors.ErrDuplicate):
			h.respondError(w, http.StatusConflict, err.Error())
		case errors.Is(err, inventory_errors.ErrInvalidInput):
			h.respondError(w, http.StatusBadRequest, err.Error())
		default:
			h.logger.Error("failed to add PO items", zap.Error(err))
			h.respondError(w, http.StatusInternalServerError, "failed to add items")
		}
		return
	}

	h.respondJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": "Items added to purchase order",
	})
}

func (h *PurchaseOrderHandler) GetPurchaseOrderItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	poIDStr := chi.URLParam(r, "purchaseOrderId")
	poID, err := uuid.Parse(poIDStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid purchase order ID")
		return
	}

	po, err := h.poService.GetPurchaseOrder(ctx, poID)
	if err != nil {
		if errors.Is(err, inventory_errors.ErrNotFound) {
			h.respondError(w, http.StatusNotFound, "purchase order not found")
			return
		}
		h.respondError(w, http.StatusInternalServerError, "failed to fetch purchase order")
		return
	}
	if po.CompanyID != companyID {
		h.respondError(w, http.StatusForbidden, "purchase order does not belong to this company")
		return
	}

	items, err := h.poService.GetPurchaseOrderItems(ctx, poID)
	if err != nil {
		h.logger.Error("failed to get PO items", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to retrieve items")
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    items,
	})
}

// ---------- Receiving ----------

type receivePurchaseOrderRequest struct {
	ReceiptDate string                          `json:"receiptDate"`
	Items       []receivePurchaseOrderItemInput `json:"items"`
	WarehouseID string                          `json:"warehouseId"`
}

type receivePurchaseOrderItemInput struct {
	POItemID         string `json:"poItemId"`
	QuantityReceived string `json:"quantityReceived"` // decimal
	UnitCost         string `json:"unitCost"`         // decimal
}

func (h *PurchaseOrderHandler) ReceivePurchaseOrder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseCompanyID(r)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	poIDStr := chi.URLParam(r, "purchaseOrderId")
	poID, err := uuid.Parse(poIDStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid purchase order ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req receivePurchaseOrderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	receiptDate, err := time.Parse(time.RFC3339, req.ReceiptDate)
	if err != nil {
		receiptDate, err = time.Parse("2006-01-02", req.ReceiptDate)
		if err != nil {
			h.respondError(w, http.StatusBadRequest, "invalid receiptDate format (use YYYY-MM-DD or RFC3339)")
			return
		}
	}

	warehouseID, err := uuid.Parse(req.WarehouseID)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid warehouseId")
		return
	}

	items := make([]service.ReceivePurchaseOrderItemInput, len(req.Items))
	for i, it := range req.Items {
		poItemID, err := uuid.Parse(it.POItemID)
		if err != nil {
			h.respondError(w, http.StatusBadRequest, "invalid poItemId")
			return
		}
		qty, err := decimal.NewFromString(it.QuantityReceived)
		if err != nil {
			h.respondError(w, http.StatusBadRequest, "invalid quantityReceived")
			return
		}
		cost, err := decimal.NewFromString(it.UnitCost)
		if err != nil {
			h.respondError(w, http.StatusBadRequest, "invalid unitCost")
			return
		}
		items[i] = service.ReceivePurchaseOrderItemInput{
			POItemID:         poItemID,
			QuantityReceived: qty,
			UnitCost:         cost,
		}
	}

	svcReq := service.ReceivePurchaseOrderRequest{
		CompanyID:       companyID,
		PurchaseOrderID: poID,
		ReceiptDate:     receiptDate,
		Items:           items,
		WarehouseID:     warehouseID,
		CreatedBy:       &userID,
	}

	idempotencyKey := getIdempotencyKey(r)
	receipt, err := h.poService.ReceivePurchaseOrder(ctx, svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to receive purchase order", zap.Error(err))
		if errors.Is(err, inventory_errors.ErrInvalidInput) {
			h.respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		// For warehouse not found, the service may return ErrNotFound – we should map to 404
		if errors.Is(err, inventory_errors.ErrNotFound) {
			h.respondError(w, http.StatusNotFound, err.Error())
			return
		}
		h.respondError(w, http.StatusInternalServerError, "failed to process receipt")
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    receipt,
		"message": "Purchase order received successfully",
	})
}

// ---------- Helper functions ----------

func (h *PurchaseOrderHandler) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *PurchaseOrderHandler) respondError(w http.ResponseWriter, status int, message string) {
	h.respondJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
