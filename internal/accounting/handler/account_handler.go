package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/accounting/repository"
	"auth-service/internal/accounting/service"
)

// AccountHandler handles HTTP requests for chart of accounts.
type AccountHandler struct {
	accountService service.AccountService
	logger         *zap.Logger
}

// NewAccountHandler creates a new AccountHandler.
func NewAccountHandler(accountService service.AccountService, logger *zap.Logger) *AccountHandler {
	return &AccountHandler{
		accountService: accountService,
		logger:         logger.Named("account_handler"),
	}
}

// ---------- Request/Response Types ----------

type createAccountRequest struct {
	CompanyID       string  `json:"company_id"`
	AccountCode     string  `json:"account_code"`
	AccountName     string  `json:"account_name"`
	AccountType     string  `json:"account_type"`
	ParentAccountID *string `json:"parent_account_id,omitempty"`
	IsActive        bool    `json:"is_active"`
	Description     *string `json:"description,omitempty"`
}

type createAccountResponse struct {
	AccountID       string  `json:"account_id"`
	CompanyID       string  `json:"company_id"`
	AccountCode     string  `json:"account_code"`
	AccountName     string  `json:"account_name"`
	AccountType     string  `json:"account_type"`
	ParentAccountID *string `json:"parent_account_id,omitempty"`
	IsActive        bool    `json:"is_active"`
	Description     *string `json:"description,omitempty"`
	CreatedAt       string  `json:"created_at"`
}

type bulkCreateRequest struct {
	Accounts []createAccountRequest `json:"accounts"`
}

type updateAccountRequest struct {
	AccountName     string  `json:"account_name"`
	AccountType     string  `json:"account_type"`
	ParentAccountID *string `json:"parent_account_id,omitempty"`
	IsActive        bool    `json:"is_active"`
	Description     *string `json:"description,omitempty"`
}

type updateStatusRequest struct {
	IsActive bool `json:"is_active"`
}

type moveAccountRequest struct {
	ParentAccountID *string `json:"parent_account_id,omitempty"`
}

type listAccountsResponse struct {
	Accounts []accountSummary `json:"accounts"`
	Total    int64            `json:"total"`
	Page     int              `json:"page"`
	PageSize int              `json:"page_size"`
}

type accountSummary struct {
	AccountID       string  `json:"account_id"`
	AccountCode     string  `json:"account_code"`
	AccountName     string  `json:"account_name"`
	AccountType     string  `json:"account_type"`
	ParentAccountID *string `json:"parent_account_id,omitempty"`
	IsActive        bool    `json:"is_active"`
}

type accountTreeNodeResponse struct {
	Account  accountSummary             `json:"account"`
	Children []*accountTreeNodeResponse `json:"children,omitempty"`
}

// ---------- Handler Methods ----------

// CreateAccount handles POST /api/v1/accounts
func (h *AccountHandler) CreateAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	h.logger.Info("CreateAccount called")

	// 🔴 Check handler dependencies
	if h.accountService == nil {
		h.logger.Error("accountService is NIL")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// 🔍 Debug context
	rawUser := ctx.Value("user_id")
	h.logger.Info("context debug",
		zap.Any("user_id_raw", rawUser),
		zap.Bool("user_id_nil", rawUser == nil),
	)

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.logger.Error("failed to extract user_id from context", zap.Error(err))
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	h.logger.Info("user extracted", zap.String("user_id", userID.String()))

	// 🔍 Decode request
	var req createAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error("failed to decode request body", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	h.logger.Info("request parsed",
		zap.Any("request", req),
	)

	// 🔍 Parse company ID
	companyID, err := uuid.Parse(req.CompanyID)
	if err != nil || companyID == uuid.Nil {
		h.logger.Error("invalid company_id",
			zap.String("company_id", req.CompanyID),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	h.logger.Info("company parsed", zap.String("company_id", companyID.String()))

	// 🔍 Validate required fields
	if req.AccountCode == "" || req.AccountName == "" || req.AccountType == "" {
		h.logger.Warn("missing required fields",
			zap.String("account_code", req.AccountCode),
			zap.String("account_name", req.AccountName),
			zap.String("account_type", req.AccountType),
		)
		h.respondWithError(w, http.StatusBadRequest, "account_code, account_name, and account_type are required")
		return
	}

	// 🔍 Validate account type
	validTypes := map[string]bool{
		"asset": true, "liability": true, "equity": true, "revenue": true, "expense": true,
	}
	if !validTypes[req.AccountType] {
		h.logger.Warn("invalid account_type", zap.String("account_type", req.AccountType))
		h.respondWithError(w, http.StatusBadRequest, "account_type must be asset, liability, equity, revenue, or expense")
		return
	}

	// 🔍 Permission check
	if !h.hasPermission(ctx, companyID, userID, "accounting:account:write") {
		h.logger.Warn("permission denied",
			zap.String("user_id", userID.String()),
			zap.String("company_id", companyID.String()),
		)
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// 🔍 Idempotency key
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.logger.Warn("missing idempotency key")
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	h.logger.Info("idempotency key received", zap.String("key", idempotencyKey))

	// 🔍 Parent parsing
	var parentID *uuid.UUID
	if req.ParentAccountID != nil && *req.ParentAccountID != "" {
		parsed, err := uuid.Parse(*req.ParentAccountID)
		if err != nil {
			h.logger.Error("invalid parent_account_id",
				zap.String("parent_account_id", *req.ParentAccountID),
				zap.Error(err),
			)
			h.respondWithError(w, http.StatusBadRequest, "invalid parent_account_id")
			return
		}
		parentID = &parsed
	}

	// 🔍 Build service request
	svcReq := service.CreateAccountRequest{
		AccountID:       uuid.New(),
		CompanyID:       companyID,
		AccountCode:     req.AccountCode,
		AccountName:     req.AccountName,
		AccountType:     req.AccountType,
		ParentAccountID: parentID,
		IsActive:        req.IsActive,
		Description:     req.Description,
		CreatedBy:       &userID,
	}

	h.logger.Info("calling service.CreateAccount",
		zap.String("account_code", svcReq.AccountCode),
		zap.String("company_id", svcReq.CompanyID.String()),
	)

	// 🔴 SERVICE CALL
	account, err := h.accountService.CreateAccount(ctx, svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to create account", zap.Error(err))

		if err == service.ErrDuplicate {
			h.respondWithError(w, http.StatusConflict, "account code already exists")
			return
		}
		if err == service.ErrInvalidInput {
			h.respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}

		h.respondWithError(w, http.StatusInternalServerError, "failed to create account")
		return
	}

	// 🔍 Defensive nil check
	if account == nil {
		h.logger.Error("service returned NIL account without error")
		h.respondWithError(w, http.StatusInternalServerError, "invalid response from service")
		return
	}

	h.logger.Info("account created successfully",
		zap.String("account_id", account.AccountID.String()),
	)

	// 🔍 Build response
	resp := createAccountResponse{
		AccountID:   account.AccountID.String(),
		CompanyID:   account.CompanyID.String(),
		AccountCode: account.AccountCode,
		AccountName: account.AccountName,
		AccountType: account.AccountType,
		IsActive:    account.IsActive,
		Description: account.Description,
		CreatedAt:   account.CreatedAt.Format(time.RFC3339),
	}

	if account.ParentAccountID != nil {
		parentStr := account.ParentAccountID.String()
		resp.ParentAccountID = &parentStr
	}

	location := fmt.Sprintf("/api/v1/accounts/%s", account.AccountID)
	w.Header().Set("Location", location)

	h.logger.Info("response ready", zap.String("location", location))

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// BulkCreateAccounts handles POST /api/v1/accounts/bulk
func (h *AccountHandler) BulkCreateAccounts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req bulkCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Accounts) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "accounts array cannot be empty")
		return
	}

	// ✅ IMPROVEMENT: Validate all accounts belong to the same company
	firstCompanyID, err := uuid.Parse(req.Accounts[0].CompanyID)
	if err != nil || firstCompanyID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id in first account")
		return
	}
	for i, acc := range req.Accounts {
		companyID, err := uuid.Parse(acc.CompanyID)
		if err != nil || companyID == uuid.Nil {
			h.respondWithError(w, http.StatusBadRequest, fmt.Sprintf("invalid company_id in account %d", i))
			return
		}
		if companyID != firstCompanyID {
			h.respondWithError(w, http.StatusBadRequest, "all accounts must belong to the same company")
			return
		}
	}

	if !h.hasPermission(ctx, firstCompanyID, userID, "accounting:account:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	svcReqs := make([]*service.CreateAccountRequest, 0, len(req.Accounts))
	for _, accReq := range req.Accounts {
		companyID, err := uuid.Parse(accReq.CompanyID)
		if err != nil || companyID == uuid.Nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid company_id in account")
			return
		}
		if accReq.AccountCode == "" || accReq.AccountName == "" || accReq.AccountType == "" {
			h.respondWithError(w, http.StatusBadRequest, "account_code, account_name, account_type required for all accounts")
			return
		}
		validTypes := map[string]bool{"asset": true, "liability": true, "equity": true, "revenue": true, "expense": true}
		if !validTypes[accReq.AccountType] {
			h.respondWithError(w, http.StatusBadRequest, "invalid account_type: "+accReq.AccountType)
			return
		}
		var parentID *uuid.UUID
		if accReq.ParentAccountID != nil && *accReq.ParentAccountID != "" {
			parsed, err := uuid.Parse(*accReq.ParentAccountID)
			if err != nil {
				h.respondWithError(w, http.StatusBadRequest, "invalid parent_account_id")
				return
			}
			parentID = &parsed
		}
		svcReqs = append(svcReqs, &service.CreateAccountRequest{
			AccountID:       uuid.New(),
			CompanyID:       companyID,
			AccountCode:     accReq.AccountCode,
			AccountName:     accReq.AccountName,
			AccountType:     accReq.AccountType,
			ParentAccountID: parentID,
			IsActive:        accReq.IsActive,
			Description:     accReq.Description,
			CreatedBy:       &userID,
		})
	}

	bulkReq := service.BulkCreateAccountsRequest{Accounts: svcReqs}
	err = h.accountService.BulkCreateAccounts(ctx, bulkReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to bulk create accounts", zap.Error(err))
		if err == service.ErrDuplicate {
			h.respondWithError(w, http.StatusConflict, "one or more account codes already exist")
			return
		}
		if err == service.ErrInvalidInput {
			h.respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to bulk create accounts")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("%d accounts created", len(req.Accounts)),
	})
}

// UpdateAccount handles PUT /api/v1/accounts/{accountID}
func (h *AccountHandler) UpdateAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	accountID, err := parseUUIDParam(r, "accountID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid account ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Fetch existing account to get companyID for permission check
	existing, err := h.accountService.GetAccount(ctx, accountID)
	if err != nil {
		if err == service.ErrNotFound {
			h.respondWithError(w, http.StatusNotFound, "account not found")
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to fetch account")
		return
	}

	if !h.hasPermission(ctx, existing.CompanyID, userID, "accounting:account:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	var parentID *uuid.UUID
	if req.ParentAccountID != nil && *req.ParentAccountID != "" {
		parsed, err := uuid.Parse(*req.ParentAccountID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid parent_account_id")
			return
		}
		parentID = &parsed
	}

	// ✅ FIX: Add CompanyID to UpdateAccountRequest
	svcReq := service.UpdateAccountRequest{
		AccountID:       accountID,
		CompanyID:       existing.CompanyID, // REQUIRED NOW
		AccountName:     req.AccountName,
		AccountType:     req.AccountType,
		ParentAccountID: parentID,
		IsActive:        req.IsActive,
		Description:     req.Description,
		UpdatedBy:       &userID,
	}

	updated, err := h.accountService.UpdateAccount(ctx, svcReq, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to update account", zap.Error(err))
		if err == service.ErrNotFound {
			h.respondWithError(w, http.StatusNotFound, "account not found")
			return
		}
		if err == service.ErrInvalidInput {
			h.respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to update account")
		return
	}

	resp := createAccountResponse{
		AccountID:   updated.AccountID.String(),
		CompanyID:   updated.CompanyID.String(),
		AccountCode: updated.AccountCode,
		AccountName: updated.AccountName,
		AccountType: updated.AccountType,
		IsActive:    updated.IsActive,
		Description: updated.Description,
		CreatedAt:   updated.CreatedAt.Format(time.RFC3339),
	}
	if updated.ParentAccountID != nil {
		parentStr := updated.ParentAccountID.String()
		resp.ParentAccountID = &parentStr
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// UpdateAccountStatus handles PATCH /api/v1/accounts/{accountID}/status
func (h *AccountHandler) UpdateAccountStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	accountID, err := parseUUIDParam(r, "accountID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid account ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	existing, err := h.accountService.GetAccount(ctx, accountID)
	if err != nil {
		if err == service.ErrNotFound {
			h.respondWithError(w, http.StatusNotFound, "account not found")
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to fetch account")
		return
	}

	if !h.hasPermission(ctx, existing.CompanyID, userID, "accounting:account:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req updateStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	// ✅ FIX: Pass companyID as first argument
	err = h.accountService.UpdateAccountStatus(ctx,
		existing.CompanyID, // REQUIRED NOW
		accountID,
		req.IsActive,
		&userID,
		idempotencyKey,
	)
	if err != nil {
		h.logger.Error("failed to update account status", zap.Error(err))
		if err == service.ErrNotFound {
			h.respondWithError(w, http.StatusNotFound, "account not found")
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to update status")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "account status updated",
	})
}

// MoveAccount handles PATCH /api/v1/accounts/{accountID}/move
func (h *AccountHandler) MoveAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	accountID, err := parseUUIDParam(r, "accountID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid account ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	existing, err := h.accountService.GetAccount(ctx, accountID)
	if err != nil {
		if err == service.ErrNotFound {
			h.respondWithError(w, http.StatusNotFound, "account not found")
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to fetch account")
		return
	}

	if !h.hasPermission(ctx, existing.CompanyID, userID, "accounting:account:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req moveAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	var newParentID *uuid.UUID
	if req.ParentAccountID != nil && *req.ParentAccountID != "" {
		parsed, err := uuid.Parse(*req.ParentAccountID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid parent_account_id")
			return
		}
		newParentID = &parsed
	}

	// ✅ FIX: Pass companyID as first argument
	err = h.accountService.MoveAccount(ctx,
		existing.CompanyID, // REQUIRED NOW
		accountID,
		newParentID,
		&userID,
		idempotencyKey,
	)
	if err != nil {
		h.logger.Error("failed to move account", zap.Error(err))
		if err == service.ErrNotFound {
			h.respondWithError(w, http.StatusNotFound, "account not found")
			return
		}
		if err == service.ErrInvalidInput {
			h.respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to move account")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "account moved",
	})
}

// DeleteAccount handles DELETE /api/v1/accounts/{accountID}
func (h *AccountHandler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	accountID, err := parseUUIDParam(r, "accountID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid account ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	existing, err := h.accountService.GetAccount(ctx, accountID)
	if err != nil {
		if err == service.ErrNotFound {
			h.respondWithError(w, http.StatusNotFound, "account not found")
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to fetch account")
		return
	}

	if !h.hasPermission(ctx, existing.CompanyID, userID, "accounting:account:write") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "Idempotency-Key header is required")
		return
	}

	// ✅ FIX: Pass companyID as first argument
	err = h.accountService.DeleteAccount(ctx,
		existing.CompanyID, // REQUIRED NOW
		accountID,
		&userID,
		idempotencyKey,
	)
	if err != nil {
		h.logger.Error("failed to delete account", zap.Error(err))
		if err == service.ErrNotFound {
			h.respondWithError(w, http.StatusNotFound, "account not found")
			return
		}
		if err == service.ErrInvalidState {
			h.respondWithError(w, http.StatusConflict, err.Error())
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to delete account")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "account deleted",
	})
}

// GetAccount handles GET /api/v1/accounts/{accountID}
func (h *AccountHandler) GetAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	accountID, err := parseUUIDParam(r, "accountID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid account ID")
		return
	}

	account, err := h.accountService.GetAccount(ctx, accountID)
	if err != nil {
		if err == service.ErrNotFound {
			h.respondWithError(w, http.StatusNotFound, "account not found")
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to get account")
		return
	}

	// Permission check: user must have read access to the company
	if !h.hasPermission(ctx, account.CompanyID, uuid.Nil, "accounting:account:read") {
		// If we have userID from context, check with that
		if userID, err := getUserIDFromContext(ctx); err == nil {
			if !h.hasPermission(ctx, account.CompanyID, userID, "accounting:account:read") {
				h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
				return
			}
		} else {
			h.respondWithError(w, http.StatusUnauthorized, "authentication required")
			return
		}
	}

	resp := createAccountResponse{
		AccountID:   account.AccountID.String(),
		CompanyID:   account.CompanyID.String(),
		AccountCode: account.AccountCode,
		AccountName: account.AccountName,
		AccountType: account.AccountType,
		IsActive:    account.IsActive,
		Description: account.Description,
		CreatedAt:   account.CreatedAt.Format(time.RFC3339),
	}
	if account.ParentAccountID != nil {
		parentStr := account.ParentAccountID.String()
		resp.ParentAccountID = &parentStr
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetAccountByCode handles GET /api/v1/accounts/by-code?company_id={companyID}&code={code}
func (h *AccountHandler) GetAccountByCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := r.URL.Query().Get("company_id")
	code := r.URL.Query().Get("code")
	if companyIDStr == "" || code == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id and code query parameters are required")
		return
	}

	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	if !h.hasPermission(ctx, companyID, uuid.Nil, "accounting:account:read") {
		if userID, err := getUserIDFromContext(ctx); err == nil {
			if !h.hasPermission(ctx, companyID, userID, "accounting:account:read") {
				h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
				return
			}
		} else {
			h.respondWithError(w, http.StatusUnauthorized, "authentication required")
			return
		}
	}

	account, err := h.accountService.GetAccountByCode(ctx, companyID, code)
	if err != nil {
		if err == service.ErrNotFound {
			h.respondWithError(w, http.StatusNotFound, "account not found")
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to get account")
		return
	}

	resp := createAccountResponse{
		AccountID:   account.AccountID.String(),
		CompanyID:   account.CompanyID.String(),
		AccountCode: account.AccountCode,
		AccountName: account.AccountName,
		AccountType: account.AccountType,
		IsActive:    account.IsActive,
		Description: account.Description,
		CreatedAt:   account.CreatedAt.Format(time.RFC3339),
	}
	if account.ParentAccountID != nil {
		parentStr := account.ParentAccountID.String()
		resp.ParentAccountID = &parentStr
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ListAccounts handles GET /api/v1/accounts?company_id={companyID}&type={type}&active={active}&parent={parentID}&search={search}&page={page}&page_size={size}&sort_field={field}&sort_dir={dir}
func (h *AccountHandler) ListAccounts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	if !h.hasPermission(ctx, companyID, uuid.Nil, "accounting:account:read") {
		if userID, err := getUserIDFromContext(ctx); err == nil {
			if !h.hasPermission(ctx, companyID, userID, "accounting:account:read") {
				h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
				return
			}
		} else {
			h.respondWithError(w, http.StatusUnauthorized, "authentication required")
			return
		}
	}

	filter := repository.AccountFilter{CompanyID: companyID}

	if typeStr := r.URL.Query().Get("type"); typeStr != "" {
		filter.AccountType = &typeStr
	}
	if activeStr := r.URL.Query().Get("active"); activeStr != "" {
		active, err := strconv.ParseBool(activeStr)
		if err == nil {
			filter.IsActive = &active
		}
	}
	if parentStr := r.URL.Query().Get("parent"); parentStr != "" {
		if parentStr == "null" {
			nullID := uuid.Nil
			filter.ParentAccountID = &nullID
		} else {
			parentID, err := uuid.Parse(parentStr)
			if err == nil {
				filter.ParentAccountID = &parentID
			}
		}
	}
	filter.Search = r.URL.Query().Get("search")

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}

	sort := repository.Sort{
		Field:     r.URL.Query().Get("sort_field"),
		Direction: r.URL.Query().Get("sort_dir"),
	}
	if sort.Field == "" {
		sort.Field = "account_code"
	}
	if sort.Direction == "" {
		sort.Direction = "ASC"
	}

	accounts, total, err := h.accountService.ListAccounts(ctx, filter, page, pageSize, sort)
	if err != nil {
		h.logger.Error("failed to list accounts", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list accounts")
		return
	}

	summaries := make([]accountSummary, len(accounts))
	for i, acc := range accounts {
		summaries[i] = accountSummary{
			AccountID:   acc.AccountID.String(),
			AccountCode: acc.AccountCode,
			AccountName: acc.AccountName,
			AccountType: acc.AccountType,
			IsActive:    acc.IsActive,
		}
		if acc.ParentAccountID != nil {
			parentStr := acc.ParentAccountID.String()
			summaries[i].ParentAccountID = &parentStr
		}
	}

	resp := listAccountsResponse{
		Accounts: summaries,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// GetAccountTree handles GET /api/v1/accounts/tree?company_id={companyID}
func (h *AccountHandler) GetAccountTree(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := r.URL.Query().Get("company_id")
	if companyIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "company_id query parameter is required")
		return
	}
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	if !h.hasPermission(ctx, companyID, uuid.Nil, "accounting:account:read") {
		if userID, err := getUserIDFromContext(ctx); err == nil {
			if !h.hasPermission(ctx, companyID, userID, "accounting:account:read") {
				h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
				return
			}
		} else {
			h.respondWithError(w, http.StatusUnauthorized, "authentication required")
			return
		}
	}

	tree, err := h.accountService.GetAccountTree(ctx, companyID)
	if err != nil {
		h.logger.Error("failed to get account tree", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get account tree")
		return
	}

	responseTree := make([]*accountTreeNodeResponse, 0, len(tree))
	for _, node := range tree {
		responseTree = append(responseTree, convertTreeNode(node))
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    responseTree,
	})
}

// GetChildren handles GET /api/v1/accounts/{accountID}/children
func (h *AccountHandler) GetChildren(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	parentID, err := parseUUIDParam(r, "accountID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid account ID")
		return
	}

	// Fetch parent to get companyID for permission
	parent, err := h.accountService.GetAccount(ctx, parentID)
	if err != nil {
		if err == service.ErrNotFound {
			h.respondWithError(w, http.StatusNotFound, "parent account not found")
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "failed to fetch parent")
		return
	}

	if !h.hasPermission(ctx, parent.CompanyID, uuid.Nil, "accounting:account:read") {
		if userID, err := getUserIDFromContext(ctx); err == nil {
			if !h.hasPermission(ctx, parent.CompanyID, userID, "accounting:account:read") {
				h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
				return
			}
		} else {
			h.respondWithError(w, http.StatusUnauthorized, "authentication required")
			return
		}
	}

	children, err := h.accountService.GetChildren(ctx, parentID)
	if err != nil {
		h.logger.Error("failed to get children", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get children")
		return
	}

	summaries := make([]accountSummary, len(children))
	for i, child := range children {
		summaries[i] = accountSummary{
			AccountID:   child.AccountID.String(),
			AccountCode: child.AccountCode,
			AccountName: child.AccountName,
			AccountType: child.AccountType,
			IsActive:    child.IsActive,
		}
		if child.ParentAccountID != nil {
			parentStr := child.ParentAccountID.String()
			summaries[i].ParentAccountID = &parentStr
		}
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summaries,
	})
}

// HasChildren handles GET /api/v1/accounts/{accountID}/has-children
func (h *AccountHandler) HasChildren(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	accountID, err := parseUUIDParam(r, "accountID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid account ID")
		return
	}

	has, err := h.accountService.HasChildren(ctx, accountID)
	if err != nil {
		if err == service.ErrNotFound {
			h.respondWithError(w, http.StatusNotFound, "account not found")
			return
		}
		h.logger.Error("failed to check children", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check children")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]interface{}{"has_children": has},
	})
}

// CheckUsage handles GET /api/v1/accounts/{accountID}/usage
func (h *AccountHandler) CheckUsage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	accountID, err := parseUUIDParam(r, "accountID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid account ID")
		return
	}

	used, err := h.accountService.CheckAccountUsage(ctx, accountID)
	if err != nil {
		if err == service.ErrNotFound {
			h.respondWithError(w, http.StatusNotFound, "account not found")
			return
		}
		h.logger.Error("failed to check usage", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check usage")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]interface{}{"in_use": used},
	})
}

// CheckCircularReference handles GET /api/v1/accounts/{accountID}/circular?parent_id={parentID}
func (h *AccountHandler) CheckCircularReference(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	accountID, err := parseUUIDParam(r, "accountID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid account ID")
		return
	}

	parentIDStr := r.URL.Query().Get("parent_id")
	var parentID *uuid.UUID
	if parentIDStr != "" && parentIDStr != "null" {
		parsed, err := uuid.Parse(parentIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid parent_id")
			return
		}
		parentID = &parsed
	}

	circular, err := h.accountService.CheckCircularReference(ctx, accountID, parentID)
	if err != nil {
		if err == service.ErrNotFound {
			h.respondWithError(w, http.StatusNotFound, "account not found")
			return
		}
		h.logger.Error("failed to check circular reference", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check circular reference")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]interface{}{"circular": circular},
	})
}

// ---------- Helper Functions ----------

// parseUUIDParam extracts a UUID from the URL parameter.
func parseUUIDParam(r *http.Request, paramName string) (uuid.UUID, error) {
	idStr := chi.URLParam(r, paramName)
	if idStr == "" {
		return uuid.Nil, fmt.Errorf("missing %s parameter", paramName)
	}
	return uuid.Parse(idStr)
}

// hasPermission is a placeholder permission check.
func (h *AccountHandler) hasPermission(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, permission string) bool {
	// TODO: Implement real RBAC check
	return true
}

// respondWithJSON sends a JSON response.
func (h *AccountHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

// respondWithError sends a JSON error response.
func (h *AccountHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

// convertTreeNode recursively converts repository.AccountTreeNode to response format.
func convertTreeNode(node *repository.AccountTreeNode) *accountTreeNodeResponse {
	if node == nil {
		return nil
	}
	resp := &accountTreeNodeResponse{
		Account: accountSummary{
			AccountID:   node.Account.AccountID.String(),
			AccountCode: node.Account.AccountCode,
			AccountName: node.Account.AccountName,
			AccountType: node.Account.AccountType,
			IsActive:    node.Account.IsActive,
		},
	}
	if node.Account.ParentAccountID != nil {
		parentStr := node.Account.ParentAccountID.String()
		resp.Account.ParentAccountID = &parentStr
	}
	for _, child := range node.Children {
		resp.Children = append(resp.Children, convertTreeNode(child))
	}
	return resp
}
