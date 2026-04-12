package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/repository"
	"auth-service/internal/academics/service"
)

type FeeHandler struct {
	feeService service.FeeService
	logger     *zap.Logger
}

func NewFeeHandler(feeService service.FeeService, logger *zap.Logger) *FeeHandler {
	return &FeeHandler{
		feeService: feeService,
		logger:     logger.Named("fee_handler"),
	}
}

// ======================= Fee Structure =======================

// CreateFeeStructure handles POST /api/v1/companies/{companyID}/fee-structures
func (h *FeeHandler) CreateFeeStructure(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "fee:structure:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateFeeStructureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.CompanyID = companyID
	req.CreatedBy = &userID
	req.UpdatedBy = &userID

	// Idempotency key from header
	idempotencyKey := r.Header.Get("Idempotency-Key")

	fs, err := h.feeService.CreateFeeStructure(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to create fee structure",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    fs,
		"message": "Fee structure created successfully",
	})
}

// GetFeeStructure handles GET /api/v1/companies/{companyID}/fee-structures/{feeStructureID}
func (h *FeeHandler) GetFeeStructure(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	feeStructureIDStr := chi.URLParam(r, "feeStructureID")
	feeStructureID, err := uuid.Parse(feeStructureIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid fee structure ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "fee:structure:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	fs, err := h.feeService.GetFeeStructureByID(ctx, feeStructureID)
	if err != nil {
		h.logger.Error("Failed to get fee structure",
			zap.String("fee_structure_id", feeStructureID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    fs,
	})
}

// ListFeeStructures handles GET /api/v1/companies/{companyID}/fee-structures
func (h *FeeHandler) ListFeeStructures(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "fee:structure:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Build filter
	filter := repository.FeeStructureFilter{}
	if academicYearIDStr := r.URL.Query().Get("academic_year_id"); academicYearIDStr != "" {
		if id, err := uuid.Parse(academicYearIDStr); err == nil {
			filter.AcademicYearID = &id
		}
	}
	if courseIDStr := r.URL.Query().Get("course_id"); courseIDStr != "" {
		if id, err := uuid.Parse(courseIDStr); err == nil {
			filter.CourseID = &id
		}
	}
	if sectionIDStr := r.URL.Query().Get("section_id"); sectionIDStr != "" {
		if id, err := uuid.Parse(sectionIDStr); err == nil {
			filter.SectionID = &id
		}
	}
	if isActiveStr := r.URL.Query().Get("is_active"); isActiveStr != "" {
		isActive, err := strconv.ParseBool(isActiveStr)
		if err == nil {
			filter.IsActive = &isActive
		}
	}
	// NOTE: Name filtering is currently disabled because repository.FeeStructureFilter does not have a Name field.
	// If name filtering is required, add a 'Name *string' field to the filter struct in repository/fee_structure.go.
	// if name := r.URL.Query().Get("name"); name != "" {
	// 	filter.Name = &name
	// }

	// Pagination
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	// Sorting
	sortField := r.URL.Query().Get("sort_field")
	if sortField == "" {
		sortField = "created_at"
	}
	sortDirection := r.URL.Query().Get("sort_direction")
	if sortDirection == "" {
		sortDirection = "DESC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDirection}

	fsList, err := h.feeService.ListFeeStructures(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list fee structures", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list fee structures")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"fee_structures": fsList,
			"limit":          limit,
			"offset":         offset,
		},
	})
}

// UpdateFeeStructure handles PUT /api/v1/companies/{companyID}/fee-structures/{feeStructureID}
func (h *FeeHandler) UpdateFeeStructure(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	feeStructureIDStr := chi.URLParam(r, "feeStructureID")
	feeStructureID, err := uuid.Parse(feeStructureIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid fee structure ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "fee:structure:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateFeeStructureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.FeeStructureID = feeStructureID
	req.UpdatedBy = &userID

	fs, err := h.feeService.UpdateFeeStructure(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update fee structure",
			zap.String("fee_structure_id", feeStructureID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    fs,
		"message": "Fee structure updated successfully",
	})
}

// DeleteFeeStructure handles DELETE /api/v1/companies/{companyID}/fee-structures/{feeStructureID}
func (h *FeeHandler) DeleteFeeStructure(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	feeStructureIDStr := chi.URLParam(r, "feeStructureID")
	feeStructureID, err := uuid.Parse(feeStructureIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid fee structure ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "fee:structure:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.feeService.DeleteFeeStructure(ctx, feeStructureID, &userID)
	if err != nil {
		h.logger.Error("Failed to delete fee structure",
			zap.String("fee_structure_id", feeStructureID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Fee structure deleted successfully",
	})
}

// ======================= Fee Structure Items =======================

// AddFeeStructureItem handles POST /api/v1/companies/{companyID}/fee-structures/{feeStructureID}/items
func (h *FeeHandler) AddFeeStructureItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	feeStructureIDStr := chi.URLParam(r, "feeStructureID")
	feeStructureID, err := uuid.Parse(feeStructureIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid fee structure ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "fee:structure:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateFeeStructureItemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.CreatedBy = &userID

	item, err := h.feeService.AddFeeStructureItem(ctx, feeStructureID, req)
	if err != nil {
		h.logger.Error("Failed to add fee structure item",
			zap.String("fee_structure_id", feeStructureID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    item,
		"message": "Fee structure item added successfully",
	})
}

// UpdateFeeStructureItem handles PUT /api/v1/companies/{companyID}/fee-structures/{feeStructureID}/items/{itemID}
func (h *FeeHandler) UpdateFeeStructureItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	feeStructureIDStr := chi.URLParam(r, "feeStructureID")
	feeStructureID, err := uuid.Parse(feeStructureIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid fee structure ID")
		return
	}

	itemIDStr := chi.URLParam(r, "itemID")
	itemID, err := uuid.Parse(itemIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid item ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "fee:structure:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateFeeStructureItemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.ItemID = itemID
	req.FeeStructureID = feeStructureID

	err = h.feeService.UpdateFeeStructureItem(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update fee structure item",
			zap.String("item_id", itemID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Fee structure item updated successfully",
	})
}

// DeleteFeeStructureItem handles DELETE /api/v1/companies/{companyID}/fee-structures/items/{itemID}
func (h *FeeHandler) DeleteFeeStructureItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	itemIDStr := chi.URLParam(r, "itemID")
	itemID, err := uuid.Parse(itemIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid item ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "fee:structure:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.feeService.DeleteFeeStructureItem(ctx, itemID)
	if err != nil {
		h.logger.Error("Failed to delete fee structure item",
			zap.String("item_id", itemID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Fee structure item deleted successfully",
	})
}

// ======================= Invoices =======================

// CreateInvoice handles POST /api/v1/companies/{companyID}/invoices
func (h *FeeHandler) CreateInvoice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "fee:invoice:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateInvoiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.CreatedBy = &userID

	inv, err := h.feeService.CreateInvoice(ctx, req)
	if err != nil {
		h.logger.Error("Failed to create invoice",
			zap.String("student_id", req.StudentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    inv,
		"message": "Invoice created successfully",
	})
}

// GetInvoice handles GET /api/v1/companies/{companyID}/invoices/{invoiceID}
func (h *FeeHandler) GetInvoice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	invoiceIDStr := chi.URLParam(r, "invoiceID")
	invoiceID, err := uuid.Parse(invoiceIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "fee:invoice:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	inv, err := h.feeService.GetInvoiceByID(ctx, invoiceID)
	if err != nil {
		h.logger.Error("Failed to get invoice",
			zap.String("invoice_id", invoiceID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    inv,
	})
}

// GetInvoiceByNumber handles GET /api/v1/companies/{companyID}/invoices/by-number/{invoiceNo}
func (h *FeeHandler) GetInvoiceByNumber(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	invoiceNo := chi.URLParam(r, "invoiceNo")
	if invoiceNo == "" {
		h.respondWithError(w, http.StatusBadRequest, "invoice number is required")
		return
	}

	if !h.hasPermission(ctx, companyID, "fee:invoice:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	inv, err := h.feeService.GetInvoiceByNumber(ctx, invoiceNo)
	if err != nil {
		h.logger.Error("Failed to get invoice by number",
			zap.String("invoice_no", invoiceNo),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    inv,
	})
}

// ListInvoices handles GET /api/v1/companies/{companyID}/invoices
func (h *FeeHandler) ListInvoices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "fee:invoice:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Build filter
	filter := repository.InvoiceFilter{}
	if studentIDStr := r.URL.Query().Get("student_id"); studentIDStr != "" {
		if id, err := uuid.Parse(studentIDStr); err == nil {
			filter.StudentID = &id
		}
	}
	if feeStructureIDStr := r.URL.Query().Get("fee_structure_id"); feeStructureIDStr != "" {
		if id, err := uuid.Parse(feeStructureIDStr); err == nil {
			filter.FeeStructureID = &id
		}
	}
	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = &status
	}
	if dueDateFrom := r.URL.Query().Get("due_date_from"); dueDateFrom != "" {
		// parse date and set filter.DueDateFrom
	}
	if dueDateTo := r.URL.Query().Get("due_date_to"); dueDateTo != "" {
		// parse date and set filter.DueDateTo
	}

	// Pagination
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	// Sorting
	sortField := r.URL.Query().Get("sort_field")
	if sortField == "" {
		sortField = "created_at"
	}
	sortDirection := r.URL.Query().Get("sort_direction")
	if sortDirection == "" {
		sortDirection = "DESC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDirection}

	invoices, err := h.feeService.ListInvoices(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list invoices", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list invoices")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"invoices": invoices,
			"limit":    limit,
			"offset":   offset,
		},
	})
}

// UpdateInvoiceStatus handles PATCH /api/v1/companies/{companyID}/invoices/{invoiceID}/status
func (h *FeeHandler) UpdateInvoiceStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	invoiceIDStr := chi.URLParam(r, "invoiceID")
	invoiceID, err := uuid.Parse(invoiceIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "fee:invoice:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Status == "" {
		h.respondWithError(w, http.StatusBadRequest, "status is required")
		return
	}

	err = h.feeService.UpdateInvoiceStatus(ctx, invoiceID, req.Status, &userID)
	if err != nil {
		h.logger.Error("Failed to update invoice status",
			zap.String("invoice_id", invoiceID.String()),
			zap.String("status", req.Status),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Invoice status updated successfully",
	})
}

// ======================= Payments =======================

// CreatePayment handles POST /api/v1/companies/{companyID}/payments
func (h *FeeHandler) CreatePayment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "fee:payment:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreatePaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.CreatedBy = &userID

	payment, err := h.feeService.CreatePayment(ctx, req)
	if err != nil {
		h.logger.Error("Failed to create payment",
			zap.String("invoice_id", req.InvoiceID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    payment,
		"message": "Payment created successfully",
	})
}

// GetPayment handles GET /api/v1/companies/{companyID}/payments/{paymentID}
func (h *FeeHandler) GetPayment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	paymentIDStr := chi.URLParam(r, "paymentID")
	paymentID, err := uuid.Parse(paymentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "fee:payment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	payment, err := h.feeService.GetPaymentByID(ctx, paymentID)
	if err != nil {
		h.logger.Error("Failed to get payment",
			zap.String("payment_id", paymentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    payment,
	})
}

// GetPaymentsByInvoice handles GET /api/v1/companies/{companyID}/invoices/{invoiceID}/payments
func (h *FeeHandler) GetPaymentsByInvoice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	invoiceIDStr := chi.URLParam(r, "invoiceID")
	invoiceID, err := uuid.Parse(invoiceIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "fee:payment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	payments, err := h.feeService.GetPaymentsByInvoice(ctx, invoiceID)
	if err != nil {
		h.logger.Error("Failed to get payments by invoice",
			zap.String("invoice_id", invoiceID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve payments")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    payments,
	})
}

// ListPayments handles GET /api/v1/companies/{companyID}/payments
func (h *FeeHandler) ListPayments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "fee:payment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Build filter
	filter := repository.PaymentFilter{}
	if studentIDStr := r.URL.Query().Get("student_id"); studentIDStr != "" {
		if id, err := uuid.Parse(studentIDStr); err == nil {
			filter.StudentID = &id
		}
	}
	if invoiceIDStr := r.URL.Query().Get("invoice_id"); invoiceIDStr != "" {
		if id, err := uuid.Parse(invoiceIDStr); err == nil {
			filter.InvoiceID = &id
		}
	}
	if paymentMode := r.URL.Query().Get("payment_mode"); paymentMode != "" {
		filter.PaymentMode = &paymentMode
	}
	if paymentDateFrom := r.URL.Query().Get("payment_date_from"); paymentDateFrom != "" {
		// parse and set
	}
	if paymentDateTo := r.URL.Query().Get("payment_date_to"); paymentDateTo != "" {
		// parse and set
	}

	// Pagination
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	// Sorting
	sortField := r.URL.Query().Get("sort_field")
	if sortField == "" {
		sortField = "payment_date"
	}
	sortDirection := r.URL.Query().Get("sort_direction")
	if sortDirection == "" {
		sortDirection = "DESC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDirection}

	payments, err := h.feeService.ListPayments(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list payments", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list payments")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"payments": payments,
			"limit":    limit,
			"offset":   offset,
		},
	})
}

// ======================= Discounts =======================

// CreateDiscount handles POST /api/v1/companies/{companyID}/discounts
func (h *FeeHandler) CreateDiscount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "fee:discount:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateDiscountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.CreatedBy = &userID

	discount, err := h.feeService.CreateDiscount(ctx, req)
	if err != nil {
		h.logger.Error("Failed to create discount",
			zap.String("student_id", req.StudentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    discount,
		"message": "Discount created successfully",
	})
}

// UpdateDiscount handles PUT /api/v1/companies/{companyID}/discounts/{discountID}
func (h *FeeHandler) UpdateDiscount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	discountIDStr := chi.URLParam(r, "discountID")
	discountID, err := uuid.Parse(discountIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid discount ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "fee:discount:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateDiscountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.DiscountID = discountID
	req.UpdatedBy = &userID

	discount, err := h.feeService.UpdateDiscount(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update discount",
			zap.String("discount_id", discountID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    discount,
		"message": "Discount updated successfully",
	})
}

// DeleteDiscount handles DELETE /api/v1/companies/{companyID}/discounts/{discountID}
func (h *FeeHandler) DeleteDiscount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	discountIDStr := chi.URLParam(r, "discountID")
	discountID, err := uuid.Parse(discountIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid discount ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "fee:discount:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.feeService.DeleteDiscount(ctx, discountID)
	if err != nil {
		h.logger.Error("Failed to delete discount",
			zap.String("discount_id", discountID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Discount deleted successfully",
	})
}

// ======================= Penalties =======================

// CreatePenalty handles POST /api/v1/companies/{companyID}/penalties
func (h *FeeHandler) CreatePenalty(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "fee:penalty:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreatePenaltyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.CreatedBy = &userID

	penalty, err := h.feeService.CreatePenalty(ctx, req)
	if err != nil {
		h.logger.Error("Failed to create penalty",
			zap.String("invoice_id", req.InvoiceID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    penalty,
		"message": "Penalty created successfully",
	})
}

// UpdatePenalty handles PUT /api/v1/companies/{companyID}/penalties/{penaltyID}
func (h *FeeHandler) UpdatePenalty(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	penaltyIDStr := chi.URLParam(r, "penaltyID")
	penaltyID, err := uuid.Parse(penaltyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid penalty ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "fee:penalty:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdatePenaltyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.PenaltyID = penaltyID

	penalty, err := h.feeService.UpdatePenalty(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update penalty",
			zap.String("penalty_id", penaltyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    penalty,
		"message": "Penalty updated successfully",
	})
}

// ======================= Receipts =======================

// GenerateReceipt handles POST /api/v1/companies/{companyID}/payments/{paymentID}/receipt
func (h *FeeHandler) GenerateReceipt(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	paymentIDStr := chi.URLParam(r, "paymentID")
	paymentID, err := uuid.Parse(paymentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "fee:receipt:generate") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req struct {
		ReceiptNo string `json:"receipt_no"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Extract idempotency key from header
	idempotencyKey := r.Header.Get("Idempotency-Key")

	receipt, err := h.feeService.GenerateReceipt(ctx, paymentID, req.ReceiptNo, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to generate receipt",
			zap.String("payment_id", paymentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    receipt,
		"message": "Receipt generated successfully",
	})
}

// GetReceiptByNumber handles GET /api/v1/companies/{companyID}/receipts/by-number/{receiptNo}
func (h *FeeHandler) GetReceiptByNumber(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	receiptNo := chi.URLParam(r, "receiptNo")
	if receiptNo == "" {
		h.respondWithError(w, http.StatusBadRequest, "receipt number is required")
		return
	}

	if !h.hasPermission(ctx, companyID, "fee:receipt:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	receipt, err := h.feeService.GetReceiptByNumber(ctx, receiptNo)
	if err != nil {
		h.logger.Error("Failed to get receipt by number",
			zap.String("receipt_no", receiptNo),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    receipt,
	})
}

// ======================= Helper Methods =======================

func (h *FeeHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	// Placeholder – implement actual permission check
	return true
}

func (h *FeeHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *FeeHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
