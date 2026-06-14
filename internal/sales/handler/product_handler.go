// file: internal/sales/handler/product_handler.go

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

	"auth-service/internal/sales/service"
)

// ProductHandler handles HTTP requests for product management.
type ProductHandler struct {
	productService service.ProductService
	*BaseHandler
}

// NewProductHandler creates a new ProductHandler.
func NewProductHandler(productService service.ProductService, logger *zap.Logger) *ProductHandler {
	return &ProductHandler{
		productService: productService,
		BaseHandler:    &BaseHandler{logger: logger.Named("commission_handler")},
	}
}

// ---------- Request/Response Types ----------

type createProductRequest struct {
	SKU             string  `json:"sku"`
	Name            string  `json:"name"`
	Description     *string `json:"description,omitempty"`
	UnitPrice       string  `json:"unit_price"`
	IsActive        bool    `json:"is_active"`
	InventoryItemID *string `json:"inventory_item_id,omitempty"`
	TaxRate         *string `json:"tax_rate,omitempty"` // NEW
}

type createProductResponse struct {
	ProductID       string  `json:"product_id"`
	CompanyID       string  `json:"company_id"`
	SKU             string  `json:"sku"`
	Name            string  `json:"name"`
	Description     *string `json:"description,omitempty"`
	UnitPrice       string  `json:"unit_price"`
	IsActive        bool    `json:"is_active"`
	InventoryItemID *string `json:"inventory_item_id,omitempty"`
	TaxRate         *string `json:"tax_rate,omitempty"` // NEW
	CreatedAt       string  `json:"created_at"`
	UpdatedAt       string  `json:"updated_at"`
}

type updateProductRequest struct {
	Name            *string `json:"name,omitempty"`
	Description     *string `json:"description,omitempty"`
	UnitPrice       *string `json:"unit_price,omitempty"`
	IsActive        *bool   `json:"is_active,omitempty"`
	InventoryItemID *string `json:"inventory_item_id,omitempty"`
	TaxRate         *string `json:"tax_rate,omitempty"` // NEW
}

type updateProductStatusRequest struct {
	IsActive bool `json:"is_active"`
}

type updateUnitPriceRequest struct {
	UnitPrice string `json:"unit_price"`
}

type linkInventoryRequest struct {
	InventoryItemID string `json:"inventory_item_id"`
}

type listProductsResponse struct {
	Products []productSummary `json:"products"`
	Total    int64            `json:"total"`
	Limit    int              `json:"limit"`
	Offset   int              `json:"offset"`
}

type productSummary struct {
	ProductID       string  `json:"product_id"`
	SKU             string  `json:"sku"`
	Name            string  `json:"name"`
	UnitPrice       string  `json:"unit_price"`
	IsActive        bool    `json:"is_active"`
	InventoryItemID *string `json:"inventory_item_id,omitempty"`
	TaxRate         *string `json:"tax_rate,omitempty"` // NEW
}

// ---------- Helper to extract company ID from header ----------
func (h *ProductHandler) getCompanyIDFromHeader(r *http.Request) (uuid.UUID, error) {
	header := r.Header.Get("X-Company-ID")
	if header == "" {
		return uuid.Nil, fmt.Errorf("X-Company-ID header is required")
	}
	companyID, err := uuid.Parse(header)
	if err != nil || companyID == uuid.Nil {
		return uuid.Nil, fmt.Errorf("invalid X-Company-ID header")
	}
	return companyID, nil
}

// ---------- Handler Methods ----------

// CreateProduct handles POST /products
func (h *ProductHandler) CreateProduct(w http.ResponseWriter, r *http.Request) {
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

	var req createProductRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validation
	if req.SKU == "" || req.Name == "" || req.UnitPrice == "" {
		h.respondWithError(w, http.StatusBadRequest, "sku, name, and unit_price are required")
		return
	}
	if len(req.SKU) > 100 {
		h.respondWithError(w, http.StatusBadRequest, "sku must be at most 100 characters")
		return
	}
	if len(req.Name) > 255 {
		h.respondWithError(w, http.StatusBadRequest, "name must be at most 255 characters")
		return
	}
	unitPrice, err := decimal.NewFromString(req.UnitPrice)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid unit_price")
		return
	}
	if unitPrice.LessThan(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "unit_price cannot be negative")
		return
	}

	var inventoryItemID *uuid.UUID
	if req.InventoryItemID != nil && *req.InventoryItemID != "" {
		parsed, err := uuid.Parse(*req.InventoryItemID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid inventory_item_id")
			return
		}
		if parsed == uuid.Nil {
			h.respondWithError(w, http.StatusBadRequest, "inventory_item_id cannot be the nil UUID")
			return
		}
		inventoryItemID = &parsed
	}

	// NEW: parse tax_rate
	var taxRate *decimal.Decimal
	if req.TaxRate != nil && *req.TaxRate != "" {
		tr, err := decimal.NewFromString(*req.TaxRate)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid tax_rate")
			return
		}
		if tr.LessThan(decimal.Zero) || tr.GreaterThan(decimal.NewFromInt(100)) {
			h.respondWithError(w, http.StatusBadRequest, "tax_rate must be between 0 and 100")
			return
		}
		taxRate = &tr
	}

	if !h.hasPermission(ctx, companyID, userID, "product:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	svcReq := service.CreateProductRequest{
		CompanyID:       companyID,
		SKU:             req.SKU,
		Name:            req.Name,
		Description:     req.Description,
		UnitPrice:       unitPrice,
		IsActive:        &req.IsActive,
		InventoryItemID: inventoryItemID,
		TaxRate:         taxRate, // NEW
		CreatedBy:       &userID,
	}

	product, err := h.productService.CreateProduct(ctx, svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to create product", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := createProductResponse{
		ProductID:   product.ProductID.String(),
		CompanyID:   product.CompanyID.String(),
		SKU:         product.SKU,
		Name:        product.Name,
		Description: product.Description,
		UnitPrice:   product.UnitPrice.String(),
		IsActive:    product.IsActive,
		CreatedAt:   product.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   product.UpdatedAt.Format(time.RFC3339),
	}
	if product.InventoryItemID != nil {
		idStr := product.InventoryItemID.String()
		resp.InventoryItemID = &idStr
	}
	if product.TaxRate != nil {
		trStr := product.TaxRate.String()
		resp.TaxRate = &trStr
	}

	location := fmt.Sprintf("/products/%s", product.ProductID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateProduct handles PUT /products/{id}
func (h *ProductHandler) UpdateProduct(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	productID, err := parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid product ID")
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

	if !h.hasPermission(ctx, companyID, userID, "product:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateProductRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var unitPrice *decimal.Decimal
	if req.UnitPrice != nil && *req.UnitPrice != "" {
		price, err := decimal.NewFromString(*req.UnitPrice)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid unit_price")
			return
		}
		if price.LessThan(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "unit_price cannot be negative")
			return
		}
		unitPrice = &price
	}

	var inventoryItemID *uuid.UUID
	if req.InventoryItemID != nil && *req.InventoryItemID != "" {
		parsed, err := uuid.Parse(*req.InventoryItemID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid inventory_item_id")
			return
		}
		inventoryItemID = &parsed
	}

	// NEW: parse tax_rate update
	var taxRate *decimal.Decimal
	if req.TaxRate != nil && *req.TaxRate != "" {
		tr, err := decimal.NewFromString(*req.TaxRate)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid tax_rate")
			return
		}
		if tr.LessThan(decimal.Zero) || tr.GreaterThan(decimal.NewFromInt(100)) {
			h.respondWithError(w, http.StatusBadRequest, "tax_rate must be between 0 and 100")
			return
		}
		taxRate = &tr
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	svcReq := service.UpdateProductRequest{
		Name:            req.Name,
		Description:     req.Description,
		UnitPrice:       unitPrice,
		IsActive:        req.IsActive,
		InventoryItemID: inventoryItemID,
		TaxRate:         taxRate, // NEW
		UpdatedBy:       &userID,
	}

	updated, err := h.productService.UpdateProduct(ctx, companyID, productID, svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to update product", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := createProductResponse{
		ProductID:   updated.ProductID.String(),
		CompanyID:   updated.CompanyID.String(),
		SKU:         updated.SKU,
		Name:        updated.Name,
		Description: updated.Description,
		UnitPrice:   updated.UnitPrice.String(),
		IsActive:    updated.IsActive,
		CreatedAt:   updated.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   updated.UpdatedAt.Format(time.RFC3339),
	}
	if updated.InventoryItemID != nil {
		idStr := updated.InventoryItemID.String()
		resp.InventoryItemID = &idStr
	}
	if updated.TaxRate != nil {
		trStr := updated.TaxRate.String()
		resp.TaxRate = &trStr
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// DeleteProduct handles DELETE /products/{id}
func (h *ProductHandler) DeleteProduct(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	productID, err := parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid product ID")
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

	if !h.hasPermission(ctx, companyID, userID, "product:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.productService.DeleteProduct(ctx, companyID, productID, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to delete product", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "product deleted successfully",
	})
}

// GetProductByID handles GET /products/{id}
func (h *ProductHandler) GetProductByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	productID, err := parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid product ID")
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

	if !h.hasPermission(ctx, companyID, userID, "product:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	product, err := h.productService.GetProductByID(ctx, companyID, productID)
	if err != nil {
		h.logger.Error("failed to get product", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := createProductResponse{
		ProductID:   product.ProductID.String(),
		CompanyID:   product.CompanyID.String(),
		SKU:         product.SKU,
		Name:        product.Name,
		Description: product.Description,
		UnitPrice:   product.UnitPrice.String(),
		IsActive:    product.IsActive,
		CreatedAt:   product.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   product.UpdatedAt.Format(time.RFC3339),
	}
	if product.InventoryItemID != nil {
		idStr := product.InventoryItemID.String()
		resp.InventoryItemID = &idStr
	}
	if product.TaxRate != nil {
		trStr := product.TaxRate.String()
		resp.TaxRate = &trStr
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetProductBySKU handles GET /products/by-sku
func (h *ProductHandler) GetProductBySKU(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	sku := r.URL.Query().Get("sku")
	if sku == "" {
		h.respondWithError(w, http.StatusBadRequest, "sku query parameter is required")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "product:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	product, err := h.productService.GetProductBySKU(ctx, companyID, sku)
	if err != nil {
		h.logger.Error("failed to get product by SKU", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := createProductResponse{
		ProductID:   product.ProductID.String(),
		CompanyID:   product.CompanyID.String(),
		SKU:         product.SKU,
		Name:        product.Name,
		Description: product.Description,
		UnitPrice:   product.UnitPrice.String(),
		IsActive:    product.IsActive,
		CreatedAt:   product.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   product.UpdatedAt.Format(time.RFC3339),
	}
	if product.InventoryItemID != nil {
		idStr := product.InventoryItemID.String()
		resp.InventoryItemID = &idStr
	}
	if product.TaxRate != nil {
		trStr := product.TaxRate.String()
		resp.TaxRate = &trStr
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ListProducts handles GET /products
func (h *ProductHandler) ListProducts(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, userID, "product:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	filter := service.ProductListFilter{
		CompanyID: companyID,
	}
	if activeStr := r.URL.Query().Get("active"); activeStr != "" {
		active, err := strconv.ParseBool(activeStr)
		if err == nil {
			filter.IsActive = &active
		}
	}
	if search := r.URL.Query().Get("search"); search != "" {
		filter.Search = &search
	}
	// NEW: tax rate filters
	if minTaxRateStr := r.URL.Query().Get("min_tax_rate"); minTaxRateStr != "" {
		minTaxRate, err := decimal.NewFromString(minTaxRateStr)
		if err == nil {
			filter.MinTaxRate = &minTaxRate
		}
	}
	if maxTaxRateStr := r.URL.Query().Get("max_tax_rate"); maxTaxRateStr != "" {
		maxTaxRate, err := decimal.NewFromString(maxTaxRateStr)
		if err == nil {
			filter.MaxTaxRate = &maxTaxRate
		}
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

	products, total, err := h.productService.ListProducts(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list products", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list products")
		return
	}

	summaries := make([]productSummary, len(products))
	for i, p := range products {
		summaries[i] = productSummary{
			ProductID: p.ProductID.String(),
			SKU:       p.SKU,
			Name:      p.Name,
			UnitPrice: p.UnitPrice.String(),
			IsActive:  p.IsActive,
		}
		if p.InventoryItemID != nil {
			idStr := p.InventoryItemID.String()
			summaries[i].InventoryItemID = &idStr
		}
		if p.TaxRate != nil {
			trStr := p.TaxRate.String()
			summaries[i].TaxRate = &trStr
		}
	}

	resp := listProductsResponse{
		Products: summaries,
		Total:    total,
		Limit:    limit,
		Offset:   offset,
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateProductStatus handles POST /products/{id}/status
func (h *ProductHandler) UpdateProductStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	productID, err := parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid product ID")
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

	if !h.hasPermission(ctx, companyID, userID, "product:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateProductStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	if req.IsActive {
		err = h.productService.ActivateProduct(ctx, companyID, productID, &userID, idempotencyKey)
	} else {
		err = h.productService.DeactivateProduct(ctx, companyID, productID, &userID, idempotencyKey)
	}
	if err != nil {
		h.logger.Error("failed to update product status", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("product %s", map[bool]string{true: "activated", false: "deactivated"}[req.IsActive]),
	})
}

// UpdateUnitPrice handles POST /products/{id}/unit-price
func (h *ProductHandler) UpdateUnitPrice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	productID, err := parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid product ID")
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

	if !h.hasPermission(ctx, companyID, userID, "product:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateUnitPriceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.UnitPrice == "" {
		h.respondWithError(w, http.StatusBadRequest, "unit_price is required")
		return
	}
	unitPrice, err := decimal.NewFromString(req.UnitPrice)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid unit_price")
		return
	}
	if unitPrice.LessThan(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "unit_price cannot be negative")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.productService.UpdateUnitPrice(ctx, companyID, productID, unitPrice, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to update unit price", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "unit price updated",
	})
}

// LinkInventoryItem handles POST /products/{id}/link-inventory
func (h *ProductHandler) LinkInventoryItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	productID, err := parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid product ID")
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

	if !h.hasPermission(ctx, companyID, userID, "product:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req linkInventoryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.InventoryItemID == "" {
		h.respondWithError(w, http.StatusBadRequest, "inventory_item_id is required")
		return
	}
	inventoryItemID, err := uuid.Parse(req.InventoryItemID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid inventory_item_id")
		return
	}
	if inventoryItemID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "inventory_item_id cannot be the nil UUID")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.productService.LinkInventoryItem(ctx, companyID, productID, inventoryItemID, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to link inventory item", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "inventory item linked",
	})
}

// UnlinkInventoryItem handles POST /products/{id}/unlink-inventory
func (h *ProductHandler) UnlinkInventoryItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	productID, err := parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid product ID")
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

	if !h.hasPermission(ctx, companyID, userID, "product:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	err = h.productService.UnlinkInventoryItem(ctx, companyID, productID, &userID, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to unlink inventory item", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "inventory item unlinked",
	})
}
