// file: internal/sales/handler/credit_note_handler.go
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

	"auth-service/internal/sales/models"
	"auth-service/internal/sales/models/enums"
	"auth-service/internal/sales/service"
)

type CreditNoteHandler struct {
	creditNoteService service.CreditNoteService
	*BaseHandler
}

func NewCreditNoteHandler(creditNoteService service.CreditNoteService, logger *zap.Logger) *CreditNoteHandler {
	return &CreditNoteHandler{
		creditNoteService: creditNoteService,
		BaseHandler:       &BaseHandler{logger: logger.Named("credit_note_handler")},
	}
}

// Request/Response types

type createCreditNoteRequest struct {
	CustomerID     string                        `json:"customer_id"`
	CreditNoteDate string                        `json:"credit_note_date"` // was IssueDate
	Currency       *string                       `json:"currency,omitempty"`
	Reason         *string                       `json:"reason,omitempty"`
	Notes          *string                       `json:"notes,omitempty"`
	Items          []createCreditNoteItemRequest `json:"items"`
}

type createCreditNoteItemRequest struct {
	ProductID string  `json:"product_id"`
	Quantity  string  `json:"quantity"`
	UnitPrice string  `json:"unit_price"`
	TaxRate   *string `json:"tax_rate,omitempty"`
}

type createCreditNoteFromInvoiceRequest struct {
	InvoiceID string   `json:"invoice_id"`
	Items     []string `json:"items,omitempty"` // invoice item IDs to credit (nil = full invoice)
	Reason    *string  `json:"reason,omitempty"`
	Notes     *string  `json:"notes,omitempty"`
}

type createCreditNoteFromReturnRequest struct {
	ReturnID string  `json:"return_id"`
	Reason   *string `json:"reason,omitempty"`
	Notes    *string `json:"notes,omitempty"`
}

type updateCreditNoteRequest struct {
	Reason *string `json:"reason,omitempty"`
	Notes  *string `json:"notes,omitempty"`
}

type creditNoteResponse struct {
	CreditNoteID     string  `json:"credit_note_id"`
	CompanyID        string  `json:"company_id"`
	CustomerID       string  `json:"customer_id"`
	CreditNoteNumber string  `json:"credit_note_number"`
	InvoiceID        *string `json:"invoice_id,omitempty"`
	ReturnID         *string `json:"return_id,omitempty"`
	IssueDate        string  `json:"issue_date"`
	Status           string  `json:"status"`
	Currency         string  `json:"currency"`
	Subtotal         string  `json:"subtotal"`
	TaxTotal         string  `json:"tax_total"`
	TotalAmount      string  `json:"total_amount"`
	AmountApplied    string  `json:"amount_applied"`
	RemainingAmount  string  `json:"remaining_amount"`
	Reason           *string `json:"reason,omitempty"`
	Notes            *string `json:"notes,omitempty"`
	IssuedAt         *string `json:"issued_at,omitempty"`
	VoidedAt         *string `json:"voided_at,omitempty"`
	VoidReason       *string `json:"void_reason,omitempty"`
	CreatedAt        string  `json:"created_at"`
	UpdatedAt        string  `json:"updated_at"`
	CreatedBy        *string `json:"created_by,omitempty"`
	UpdatedBy        *string `json:"updated_by,omitempty"`
}

type creditNoteItemResponse struct {
	CreditNoteItemID    string  `json:"credit_note_item_id"`
	CreditNoteID        string  `json:"credit_note_id"`
	InvoiceItemID       *string `json:"invoice_item_id,omitempty"`
	ProductID           *string `json:"product_id,omitempty"`
	ProductNameSnapshot string  `json:"product_name_snapshot"`
	Quantity            string  `json:"quantity"`
	UnitPrice           string  `json:"unit_price"`
	TaxRate             *string `json:"tax_rate,omitempty"`
	TaxAmount           string  `json:"tax_amount"`
	LineAmount          string  `json:"line_amount"`
	CreatedAt           string  `json:"created_at"`
}

type creditNoteApplicationResponse struct {
	ApplicationID string  `json:"application_id"`
	CreditNoteID  string  `json:"credit_note_id"`
	InvoiceID     string  `json:"invoice_id"`
	Amount        string  `json:"amount"`
	AppliedAt     string  `json:"applied_at"`
	AppliedBy     *string `json:"applied_by,omitempty"`
}

type addCreditNoteItemsRequest struct {
	Items []createCreditNoteItemRequest `json:"items"`
}

type replaceCreditNoteItemsRequest struct {
	Items []createCreditNoteItemRequest `json:"items"`
}

type creditNoteUpdateStatusRequest struct {
	Status string `json:"status"`
}

type voidCreditNoteRequest struct {
	Reason string `json:"reason"`
}

type applyToInvoiceRequest struct {
	InvoiceID string `json:"invoice_id"`
	Amount    string `json:"amount"`
}

type applyToInvoicesRequest struct {
	Applications []creditNoteApplicationRequest `json:"applications"`
}

type creditNoteApplicationRequest struct {
	InvoiceID string `json:"invoice_id"`
	Amount    string `json:"amount"`
}

type convertToRefundRequest struct {
	PaymentID string `json:"payment_id"`
	Reason    string `json:"reason"`
}

type listCreditNotesResponse struct {
	CreditNotes []creditNoteSummary `json:"credit_notes"`
	Total       int64               `json:"total"`
	Limit       int                 `json:"limit"`
	Offset      int                 `json:"offset"`
}

type creditNoteSummary struct {
	CreditNoteID     string `json:"credit_note_id"`
	CreditNoteNumber string `json:"credit_note_number"`
	CustomerID       string `json:"customer_id"`
	Status           string `json:"status"`
	IssueDate        string `json:"issue_date"`
	TotalAmount      string `json:"total_amount"`
	RemainingAmount  string `json:"remaining_amount"`
}

type creditNoteTotalsResponse struct {
	Subtotal        string `json:"subtotal"`
	TaxTotal        string `json:"tax_total"`
	TotalAmount     string `json:"total_amount"`
	RemainingAmount string `json:"remaining_amount"`
}

// Conversion helpers

func (h *CreditNoteHandler) toCreditNoteResponse(cn *models.CreditNote) creditNoteResponse {
	resp := creditNoteResponse{
		CreditNoteID:     cn.CreditNoteID.String(),
		CompanyID:        cn.CompanyID.String(),
		CustomerID:       cn.CustomerID.String(),
		CreditNoteNumber: cn.CreditNoteNumber,
		IssueDate:        cn.IssueDate.Format(time.RFC3339),
		Status:           string(cn.Status),
		Currency:         cn.Currency,
		Subtotal:         cn.Subtotal.String(),
		TaxTotal:         cn.TaxTotal.String(),
		TotalAmount:      cn.TotalAmount.String(),
		AmountApplied:    cn.AmountApplied.String(),
		RemainingAmount:  cn.RemainingAmount.String(),
		Reason:           cn.Reason,
		Notes:            cn.Notes,
		CreatedAt:        cn.CreatedAt.Format(time.RFC3339),
		UpdatedAt:        cn.UpdatedAt.Format(time.RFC3339),
	}
	if cn.InvoiceID != nil {
		idStr := cn.InvoiceID.String()
		resp.InvoiceID = &idStr
	}
	if cn.ReturnID != nil {
		idStr := cn.ReturnID.String()
		resp.ReturnID = &idStr
	}
	if cn.IssuedAt != nil {
		issuedStr := cn.IssuedAt.Format(time.RFC3339)
		resp.IssuedAt = &issuedStr
	}
	if cn.VoidedAt != nil {
		voidedStr := cn.VoidedAt.Format(time.RFC3339)
		resp.VoidedAt = &voidedStr
	}
	if cn.VoidReason != nil {
		resp.VoidReason = cn.VoidReason
	}
	if cn.CreatedBy != nil {
		createdStr := cn.CreatedBy.String()
		resp.CreatedBy = &createdStr
	}
	if cn.UpdatedBy != nil {
		updatedStr := cn.UpdatedBy.String()
		resp.UpdatedBy = &updatedStr
	}
	return resp
}

func (h *CreditNoteHandler) toCreditNoteItemResponse(item *models.CreditNoteItem) creditNoteItemResponse {
	resp := creditNoteItemResponse{
		CreditNoteItemID:    item.CreditNoteItemID.String(),
		CreditNoteID:        item.CreditNoteID.String(),
		ProductNameSnapshot: item.ProductNameSnapshot,
		Quantity:            item.Quantity.String(),
		UnitPrice:           item.UnitPrice.String(),
		TaxAmount:           item.TaxAmount.String(),
		LineAmount:          item.LineAmount.String(),
		CreatedAt:           item.CreatedAt.Format(time.RFC3339),
	}
	if item.InvoiceItemID != nil {
		idStr := item.InvoiceItemID.String()
		resp.InvoiceItemID = &idStr
	}
	if item.ProductID != nil {
		idStr := item.ProductID.String()
		resp.ProductID = &idStr
	}
	if item.TaxRate != nil {
		rateStr := item.TaxRate.String()
		resp.TaxRate = &rateStr
	}
	return resp
}

func (h *CreditNoteHandler) toCreditNoteApplicationResponse(app *models.CreditNoteApplication) creditNoteApplicationResponse {
	resp := creditNoteApplicationResponse{
		ApplicationID: app.ApplicationID.String(),
		CreditNoteID:  app.CreditNoteID.String(),
		InvoiceID:     app.InvoiceID.String(),
		Amount:        app.Amount.String(),
		AppliedAt:     app.AppliedAt.Format(time.RFC3339),
	}
	if app.AppliedBy != nil {
		byStr := app.AppliedBy.String()
		resp.AppliedBy = &byStr
	}
	return resp
}

// Handlers

func (h *CreditNoteHandler) CreateDraftCreditNote(w http.ResponseWriter, r *http.Request) {
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

	var req createCreditNoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.CustomerID == "" {
		h.respondWithError(w, http.StatusBadRequest, "customer_id is required")
		return
	}

	customerID, err := uuid.Parse(req.CustomerID)
	if err != nil || customerID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer_id")
		return
	}

	creditNoteDate, err := time.Parse(time.RFC3339, req.CreditNoteDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid credit_note_date (use RFC3339)")
		return
	}

	var currency *string
	if req.Currency != nil && *req.Currency != "" {
		currency = req.Currency
	}

	if len(req.Items) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one item is required")
		return
	}

	items := make([]*service.CreateCreditNoteItemRequest, len(req.Items))
	for i, it := range req.Items {
		quantity, err := decimal.NewFromString(it.Quantity)
		if err != nil || quantity.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid quantity for item")
			return
		}
		unitPrice, err := decimal.NewFromString(it.UnitPrice)
		if err != nil || unitPrice.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid unit_price for item")
			return
		}
		var taxRate *decimal.Decimal
		if it.TaxRate != nil && *it.TaxRate != "" {
			rate, err := decimal.NewFromString(*it.TaxRate)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid tax_rate")
				return
			}
			taxRate = &rate
		}
		productID, err := uuid.Parse(it.ProductID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid product_id")
			return
		}
		items[i] = &service.CreateCreditNoteItemRequest{
			ProductID: productID,
			Quantity:  quantity,
			UnitPrice: unitPrice,
			TaxRate:   taxRate,
		}
	}

	if !h.hasPermission(ctx, companyID, userID, "credit_note:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	svcReq := &service.CreateCreditNoteRequest{
		CompanyID:      companyID,
		CustomerID:     customerID,
		CreditNoteDate: creditNoteDate,
		Currency:       currency,
		Items:          items,
		Reason:         req.Reason,
		Notes:          req.Notes,
		CreatedBy:      &userID,
	}

	creditNote, err := h.creditNoteService.CreateDraftCreditNote(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to create draft credit note", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toCreditNoteResponse(creditNote)
	location := fmt.Sprintf("/credit-notes/%s", creditNote.CreditNoteID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *CreditNoteHandler) CreateFromInvoice(w http.ResponseWriter, r *http.Request) {
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

	var req createCreditNoteFromInvoiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.InvoiceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "invoice_id is required")
		return
	}

	invoiceID, err := uuid.Parse(req.InvoiceID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice_id")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit_note:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	var itemIDs []uuid.UUID
	for _, idStr := range req.Items {
		id, err := uuid.Parse(idStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid item id in items list")
			return
		}
		itemIDs = append(itemIDs, id)
	}

	svcReq := &service.CreateCreditNoteFromInvoiceRequest{
		Items:  itemIDs,
		Reason: req.Reason,
		Notes:  req.Notes,
	}
	creditNote, err := h.creditNoteService.CreateFromInvoice(ctx, companyID, invoiceID, svcReq)
	if err != nil {
		h.logger.Error("failed to create credit note from invoice", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toCreditNoteResponse(creditNote)
	location := fmt.Sprintf("/credit-notes/%s", creditNote.CreditNoteID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *CreditNoteHandler) CreateFromReturn(w http.ResponseWriter, r *http.Request) {
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

	var req createCreditNoteFromReturnRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.ReturnID == "" {
		h.respondWithError(w, http.StatusBadRequest, "return_id is required")
		return
	}

	returnID, err := uuid.Parse(req.ReturnID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid return_id")
		return
	}

	if !h.hasPermission(ctx, companyID, userID, "credit_note:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	svcReq := &service.CreateCreditNoteFromReturnRequest{
		Reason: req.Reason,
		Notes:  req.Notes,
	}
	creditNote, err := h.creditNoteService.CreateFromReturn(ctx, companyID, returnID, svcReq)
	if err != nil {
		h.logger.Error("failed to create credit note from return", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toCreditNoteResponse(creditNote)
	location := fmt.Sprintf("/credit-notes/%s", creditNote.CreditNoteID)
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *CreditNoteHandler) UpdateCreditNote(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	creditNoteID, err := parseUUIDParamCreditNote(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid credit note ID")
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

	if !h.hasPermission(ctx, companyID, userID, "credit_note:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateCreditNoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	svcReq := &service.UpdateCreditNoteRequest{
		Reason: req.Reason,
		Notes:  req.Notes,
	}

	creditNote, err := h.creditNoteService.UpdateCreditNote(ctx, companyID, creditNoteID, svcReq)
	if err != nil {
		h.logger.Error("failed to update credit note", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toCreditNoteResponse(creditNote)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *CreditNoteHandler) DeleteCreditNote(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	creditNoteID, err := parseUUIDParamCreditNote(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid credit note ID")
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

	if !h.hasPermission(ctx, companyID, userID, "credit_note:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	err = h.creditNoteService.DeleteCreditNote(ctx, companyID, creditNoteID, userID)
	if err != nil {
		h.logger.Error("failed to delete credit note", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "credit note deleted successfully",
	})
}

func (h *CreditNoteHandler) GetCreditNoteByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	creditNoteID, err := parseUUIDParamCreditNote(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid credit note ID")
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
	if !h.hasPermission(ctx, companyID, userID, "credit_note:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	creditNote, err := h.creditNoteService.GetCreditNoteByID(ctx, companyID, creditNoteID)
	if err != nil {
		h.logger.Error("failed to get credit note", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toCreditNoteResponse(creditNote)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *CreditNoteHandler) GetCreditNoteByNumber(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	creditNoteNumber := r.URL.Query().Get("number")
	if creditNoteNumber == "" {
		h.respondWithError(w, http.StatusBadRequest, "number query parameter is required")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "credit_note:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	creditNote, err := h.creditNoteService.GetCreditNoteByNumber(ctx, companyID, creditNoteNumber)
	if err != nil {
		h.logger.Error("failed to get credit note by number", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := h.toCreditNoteResponse(creditNote)
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *CreditNoteHandler) ListCreditNotes(w http.ResponseWriter, r *http.Request) {
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
	if !h.hasPermission(ctx, companyID, userID, "credit_note:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	filter := service.CreditNoteListFilter{
		CompanyID: companyID,
	}
	if statusStr := r.URL.Query().Get("status"); statusStr != "" {
		s := enums.CreditNoteStatus(statusStr)
		filter.Status = &s
	}
	if customerIDStr := r.URL.Query().Get("customer_id"); customerIDStr != "" {
		cID, err := uuid.Parse(customerIDStr)
		if err == nil {
			filter.CustomerID = &cID
		}
	}
	if fromStr := r.URL.Query().Get("from_date"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			filter.FromDate = &t
		}
	}
	if toStr := r.URL.Query().Get("to_date"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			filter.ToDate = &t
		}
	}

	limit := 20
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
			limit = l
		}
	}
	offset := 0
	if oStr := r.URL.Query().Get("offset"); oStr != "" {
		if o, err := strconv.Atoi(oStr); err == nil && o >= 0 {
			offset = o
		}
	}
	pagination := service.Pagination{Limit: limit, Offset: offset}
	sort := service.Sort{
		Field:     r.URL.Query().Get("sort_field"),
		Direction: r.URL.Query().Get("sort_dir"),
	}
	if sort.Field == "" {
		sort.Field = "issue_date"
	}
	if sort.Direction == "" {
		sort.Direction = "DESC"
	}

	creditNotes, total, err := h.creditNoteService.ListCreditNotes(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list credit notes", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list credit notes")
		return
	}

	summaries := make([]creditNoteSummary, len(creditNotes))
	for i, cn := range creditNotes {
		summaries[i] = creditNoteSummary{
			CreditNoteID:     cn.CreditNoteID.String(),
			CreditNoteNumber: cn.CreditNoteNumber,
			CustomerID:       cn.CustomerID.String(),
			Status:           string(cn.Status),
			IssueDate:        cn.IssueDate.Format(time.RFC3339),
			TotalAmount:      cn.TotalAmount.String(),
			RemainingAmount:  cn.RemainingAmount.String(),
		}
	}
	resp := listCreditNotesResponse{
		CreditNotes: summaries,
		Total:       total,
		Limit:       limit,
		Offset:      offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *CreditNoteHandler) SearchCreditNotes(w http.ResponseWriter, r *http.Request) {
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
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "credit_note:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	limit := 20
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
			limit = l
		}
	}
	offset := 0
	if oStr := r.URL.Query().Get("offset"); oStr != "" {
		if o, err := strconv.Atoi(oStr); err == nil && o >= 0 {
			offset = o
		}
	}
	creditNotes, total, err := h.creditNoteService.SearchCreditNotes(ctx, companyID, query, limit, offset)
	if err != nil {
		h.logger.Error("failed to search credit notes", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to search credit notes")
		return
	}
	summaries := make([]creditNoteSummary, len(creditNotes))
	for i, cn := range creditNotes {
		summaries[i] = creditNoteSummary{
			CreditNoteID:     cn.CreditNoteID.String(),
			CreditNoteNumber: cn.CreditNoteNumber,
			CustomerID:       cn.CustomerID.String(),
			Status:           string(cn.Status),
			IssueDate:        cn.IssueDate.Format(time.RFC3339),
			TotalAmount:      cn.TotalAmount.String(),
			RemainingAmount:  cn.RemainingAmount.String(),
		}
	}
	resp := listCreditNotesResponse{
		CreditNotes: summaries,
		Total:       total,
		Limit:       limit,
		Offset:      offset,
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *CreditNoteHandler) AddItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	creditNoteID, err := parseUUIDParamCreditNote(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid credit note ID")
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
	if !h.hasPermission(ctx, companyID, userID, "credit_note:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req addCreditNoteItemsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Items) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one item required")
		return
	}
	items := make([]*service.CreateCreditNoteItemRequest, len(req.Items))
	for i, it := range req.Items {
		quantity, err := decimal.NewFromString(it.Quantity)
		if err != nil || quantity.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid quantity")
			return
		}
		unitPrice, err := decimal.NewFromString(it.UnitPrice)
		if err != nil || unitPrice.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid unit_price")
			return
		}
		var taxRate *decimal.Decimal
		if it.TaxRate != nil && *it.TaxRate != "" {
			rate, err := decimal.NewFromString(*it.TaxRate)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid tax_rate")
				return
			}
			taxRate = &rate
		}
		productID, err := uuid.Parse(it.ProductID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid product_id")
			return
		}
		items[i] = &service.CreateCreditNoteItemRequest{
			ProductID: productID,
			Quantity:  quantity,
			UnitPrice: unitPrice,
			TaxRate:   taxRate,
		}
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	err = h.creditNoteService.AddItems(ctx, companyID, creditNoteID, items, userID)
	if err != nil {
		h.logger.Error("failed to add items", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "items added",
	})
}

func (h *CreditNoteHandler) ReplaceItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	creditNoteID, err := parseUUIDParamCreditNote(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid credit note ID")
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
	if !h.hasPermission(ctx, companyID, userID, "credit_note:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req replaceCreditNoteItemsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	items := make([]*service.CreateCreditNoteItemRequest, len(req.Items))
	for i, it := range req.Items {
		quantity, err := decimal.NewFromString(it.Quantity)
		if err != nil || quantity.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid quantity")
			return
		}
		unitPrice, err := decimal.NewFromString(it.UnitPrice)
		if err != nil || unitPrice.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid unit_price")
			return
		}
		var taxRate *decimal.Decimal
		if it.TaxRate != nil && *it.TaxRate != "" {
			rate, err := decimal.NewFromString(*it.TaxRate)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid tax_rate")
				return
			}
			taxRate = &rate
		}
		productID, err := uuid.Parse(it.ProductID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid product_id")
			return
		}
		items[i] = &service.CreateCreditNoteItemRequest{
			ProductID: productID,
			Quantity:  quantity,
			UnitPrice: unitPrice,
			TaxRate:   taxRate,
		}
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	err = h.creditNoteService.ReplaceItems(ctx, companyID, creditNoteID, items, userID)
	if err != nil {
		h.logger.Error("failed to replace items", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "items replaced",
	})
}

func (h *CreditNoteHandler) RemoveItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	creditNoteID, err := parseUUIDParamCreditNote(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid credit note ID")
		return
	}
	itemID, err := parseUUIDParamCreditNote(r, "itemId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid item ID")
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
	if !h.hasPermission(ctx, companyID, userID, "credit_note:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	err = h.creditNoteService.RemoveItem(ctx, companyID, creditNoteID, itemID, userID)
	if err != nil {
		h.logger.Error("failed to remove item", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "item removed",
	})
}

func (h *CreditNoteHandler) GetCreditNoteItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	creditNoteID, err := parseUUIDParamCreditNote(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid credit note ID")
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
	if !h.hasPermission(ctx, companyID, userID, "credit_note:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	items, err := h.creditNoteService.GetCreditNoteItems(ctx, companyID, creditNoteID)
	if err != nil {
		h.logger.Error("failed to get credit note items", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := make([]creditNoteItemResponse, len(items))
	for i, it := range items {
		resp[i] = h.toCreditNoteItemResponse(it)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *CreditNoteHandler) CalculateTotals(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	creditNoteID, err := parseUUIDParamCreditNote(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid credit note ID")
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
	if !h.hasPermission(ctx, companyID, userID, "credit_note:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	err = h.creditNoteService.CalculateTotals(ctx, companyID, creditNoteID)
	if err != nil {
		h.logger.Error("failed to calculate totals", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "totals calculated",
	})
}

func (h *CreditNoteHandler) PreviewTotals(w http.ResponseWriter, r *http.Request) {
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
	var req service.CreditNotePreviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.CustomerID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "customer_id required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "credit_note:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	// Override company ID from header
	req.CompanyID = companyID
	result, err := h.creditNoteService.PreviewTotals(ctx, &req)
	if err != nil {
		h.logger.Error("failed to preview totals", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

func (h *CreditNoteHandler) GetCreditNoteTotals(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	creditNoteID, err := parseUUIDParamCreditNote(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid credit note ID")
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
	if !h.hasPermission(ctx, companyID, userID, "credit_note:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	subtotal, taxTotal, totalAmount, remainingAmount, err := h.creditNoteService.GetCreditNoteTotals(ctx, companyID, creditNoteID)
	if err != nil {
		h.logger.Error("failed to get credit note totals", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := creditNoteTotalsResponse{
		Subtotal:        subtotal.String(),
		TaxTotal:        taxTotal.String(),
		TotalAmount:     totalAmount.String(),
		RemainingAmount: remainingAmount.String(),
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *CreditNoteHandler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	creditNoteID, err := parseUUIDParamCreditNote(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid credit note ID")
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
	if !h.hasPermission(ctx, companyID, userID, "credit_note:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req creditNoteUpdateStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	status := enums.CreditNoteStatus(req.Status)
	if !status.IsValid() {
		h.respondWithError(w, http.StatusBadRequest, "invalid status")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	err = h.creditNoteService.UpdateStatus(ctx, companyID, creditNoteID, status, userID)
	if err != nil {
		h.logger.Error("failed to update credit note status", zap.Error(err))
		statusCode, msg := h.mapServiceError(err)
		h.respondWithError(w, statusCode, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "status updated",
	})
}

func (h *CreditNoteHandler) IssueCreditNote(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	creditNoteID, err := parseUUIDParamCreditNote(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid credit note ID")
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
	if !h.hasPermission(ctx, companyID, userID, "credit_note:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	err = h.creditNoteService.IssueCreditNote(ctx, companyID, creditNoteID, userID)
	if err != nil {
		h.logger.Error("failed to issue credit note", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "credit note issued",
	})
}

func (h *CreditNoteHandler) VoidCreditNote(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	creditNoteID, err := parseUUIDParamCreditNote(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid credit note ID")
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
	if !h.hasPermission(ctx, companyID, userID, "credit_note:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req voidCreditNoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	err = h.creditNoteService.VoidCreditNote(ctx, companyID, creditNoteID, req.Reason, userID)
	if err != nil {
		h.logger.Error("failed to void credit note", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "credit note voided",
	})
}

func (h *CreditNoteHandler) MarkFullyApplied(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	creditNoteID, err := parseUUIDParamCreditNote(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid credit note ID")
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
	if !h.hasPermission(ctx, companyID, userID, "credit_note:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	err = h.creditNoteService.MarkFullyApplied(ctx, companyID, creditNoteID, userID)
	if err != nil {
		h.logger.Error("failed to mark fully applied", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "credit note marked as fully applied",
	})
}

func (h *CreditNoteHandler) ApplyToInvoice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	creditNoteID, err := parseUUIDParamCreditNote(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid credit note ID")
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
	if !h.hasPermission(ctx, companyID, userID, "credit_note:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req applyToInvoiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	invoiceID, err := uuid.Parse(req.InvoiceID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid invoice_id")
		return
	}
	amount, err := decimal.NewFromString(req.Amount)
	if err != nil || amount.LessThanOrEqual(decimal.Zero) {
		h.respondWithError(w, http.StatusBadRequest, "invalid amount")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	err = h.creditNoteService.ApplyToInvoice(ctx, companyID, creditNoteID, invoiceID, amount, userID)
	if err != nil {
		h.logger.Error("failed to apply credit note to invoice", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "credit note applied to invoice",
	})
}

func (h *CreditNoteHandler) ApplyToInvoices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	creditNoteID, err := parseUUIDParamCreditNote(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid credit note ID")
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
	if !h.hasPermission(ctx, companyID, userID, "credit_note:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req applyToInvoicesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Applications) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one application required")
		return
	}
	apps := make([]*service.CreditNoteApplicationRequest, len(req.Applications))
	for i, a := range req.Applications {
		invoiceID, err := uuid.Parse(a.InvoiceID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid invoice_id in application")
			return
		}
		amount, err := decimal.NewFromString(a.Amount)
		if err != nil || amount.LessThanOrEqual(decimal.Zero) {
			h.respondWithError(w, http.StatusBadRequest, "invalid amount in application")
			return
		}
		apps[i] = &service.CreditNoteApplicationRequest{
			InvoiceID: invoiceID,
			Amount:    amount,
		}
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	err = h.creditNoteService.ApplyToInvoices(ctx, companyID, creditNoteID, apps, userID)
	if err != nil {
		h.logger.Error("failed to apply credit note to multiple invoices", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "credit note applied to invoices",
	})
}

func (h *CreditNoteHandler) AutoApplyToOutstandingInvoices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	creditNoteID, err := parseUUIDParamCreditNote(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid credit note ID")
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
	if !h.hasPermission(ctx, companyID, userID, "credit_note:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	err = h.creditNoteService.AutoApplyToOutstandingInvoices(ctx, companyID, creditNoteID, userID)
	if err != nil {
		h.logger.Error("failed to auto-apply credit note", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "credit note auto-applied to outstanding invoices",
	})
}

func (h *CreditNoteHandler) RemoveApplication(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	creditNoteID, err := parseUUIDParamCreditNote(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid credit note ID")
		return
	}
	appID, err := parseUUIDParamCreditNote(r, "appId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid application ID")
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
	if !h.hasPermission(ctx, companyID, userID, "credit_note:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	err = h.creditNoteService.RemoveApplication(ctx, companyID, creditNoteID, appID, userID)
	if err != nil {
		h.logger.Error("failed to remove application", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "application removed",
	})
}

func (h *CreditNoteHandler) GetApplications(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	creditNoteID, err := parseUUIDParamCreditNote(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid credit note ID")
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
	if !h.hasPermission(ctx, companyID, userID, "credit_note:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	apps, err := h.creditNoteService.GetApplications(ctx, companyID, creditNoteID)
	if err != nil {
		h.logger.Error("failed to get applications", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := make([]creditNoteApplicationResponse, len(apps))
	for i, a := range apps {
		resp[i] = h.toCreditNoteApplicationResponse(a)
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *CreditNoteHandler) GetRemainingBalance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	creditNoteID, err := parseUUIDParamCreditNote(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid credit note ID")
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
	if !h.hasPermission(ctx, companyID, userID, "credit_note:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	balance, err := h.creditNoteService.GetRemainingBalance(ctx, companyID, creditNoteID)
	if err != nil {
		h.logger.Error("failed to get remaining balance", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"remaining_balance": balance.String()},
	})
}

func (h *CreditNoteHandler) IsFullyApplied(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	creditNoteID, err := parseUUIDParamCreditNote(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid credit note ID")
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
	if !h.hasPermission(ctx, companyID, userID, "credit_note:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	fullyApplied, err := h.creditNoteService.IsFullyApplied(ctx, companyID, creditNoteID)
	if err != nil {
		h.logger.Error("failed to check if fully applied", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"fully_applied": fullyApplied},
	})
}

func (h *CreditNoteHandler) GetCustomerCreditBalance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	customerID, err := parseUUIDParamCreditNote(r, "customerId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
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
	if !h.hasPermission(ctx, companyID, userID, "credit_note:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	balance, err := h.creditNoteService.GetCustomerCreditBalance(ctx, companyID, customerID)
	if err != nil {
		h.logger.Error("failed to get customer credit balance", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"credit_balance": balance.String()},
	})
}

func (h *CreditNoteHandler) GetUnusedCreditNotes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	customerID, err := parseUUIDParamCreditNote(r, "customerId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid customer ID")
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
	if !h.hasPermission(ctx, companyID, userID, "credit_note:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	creditNotes, err := h.creditNoteService.GetUnusedCreditNotes(ctx, companyID, customerID)
	if err != nil {
		h.logger.Error("failed to get unused credit notes", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	resp := make([]creditNoteSummary, len(creditNotes))
	for i, cn := range creditNotes {
		resp[i] = creditNoteSummary{
			CreditNoteID:     cn.CreditNoteID.String(),
			CreditNoteNumber: cn.CreditNoteNumber,
			CustomerID:       cn.CustomerID.String(),
			Status:           string(cn.Status),
			IssueDate:        cn.IssueDate.Format(time.RFC3339),
			TotalAmount:      cn.TotalAmount.String(),
			RemainingAmount:  cn.RemainingAmount.String(),
		}
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *CreditNoteHandler) ConvertToRefund(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	creditNoteID, err := parseUUIDParamCreditNote(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid credit note ID")
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
	if !h.hasPermission(ctx, companyID, userID, "credit_note:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var req convertToRefundRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.PaymentID == "" {
		h.respondWithError(w, http.StatusBadRequest, "payment_id is required")
		return
	}
	paymentID, err := uuid.Parse(req.PaymentID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payment_id")
		return
	}
	if req.Reason == "" {
		h.respondWithError(w, http.StatusBadRequest, "reason is required")
		return
	}
	svcReq := &service.ConvertCreditNoteToRefundRequest{
		PaymentID: paymentID,
		Reason:    req.Reason,
	}
	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}
	_ = idempotencyKey

	refund, err := h.creditNoteService.ConvertToRefund(ctx, companyID, creditNoteID, svcReq)
	if err != nil {
		h.logger.Error("failed to convert to refund", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"refund_id": refund.RefundID.String(),
			"amount":    refund.Amount.String(),
			"status":    refund.Status,
		},
	})
}

func (h *CreditNoteHandler) GetTotalCreditIssued(w http.ResponseWriter, r *http.Request) {
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
	if !h.hasPermission(ctx, companyID, userID, "credit_note:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var from, to *time.Time
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			from = &t
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			to = &t
		}
	}
	total, err := h.creditNoteService.GetTotalCreditIssued(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get total credit issued", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get total credit issued")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"total_credit_issued": total.String()},
	})
}

func (h *CreditNoteHandler) GetTotalCreditApplied(w http.ResponseWriter, r *http.Request) {
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
	if !h.hasPermission(ctx, companyID, userID, "credit_note:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	var from, to *time.Time
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			from = &t
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			to = &t
		}
	}
	total, err := h.creditNoteService.GetTotalCreditApplied(ctx, companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get total credit applied", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get total credit applied")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"total_credit_applied": total.String()},
	})
}

func (h *CreditNoteHandler) GetOutstandingCredits(w http.ResponseWriter, r *http.Request) {
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
	if !h.hasPermission(ctx, companyID, userID, "credit_note:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	outstanding, err := h.creditNoteService.GetOutstandingCredits(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get outstanding credits", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get outstanding credits")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]string{"outstanding_credits": outstanding.String()},
	})
}

func (h *CreditNoteHandler) CreditNoteExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	creditNoteID, err := parseUUIDParamCreditNote(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid credit note ID")
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
	if !h.hasPermission(ctx, companyID, userID, "credit_note:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	exists, err := h.creditNoteService.CreditNoteExists(ctx, companyID, creditNoteID)
	if err != nil {
		h.logger.Error("failed to check credit note exists", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"exists": exists},
	})
}

func (h *CreditNoteHandler) CreditNoteNumberExists(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	number := r.URL.Query().Get("number")
	if number == "" {
		h.respondWithError(w, http.StatusBadRequest, "number query parameter is required")
		return
	}
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.hasPermission(ctx, companyID, userID, "credit_note:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}
	exists, err := h.creditNoteService.CreditNoteNumberExists(ctx, companyID, number)
	if err != nil {
		h.logger.Error("failed to check credit note number exists", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]bool{"exists": exists},
	})
}
