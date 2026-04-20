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

	"auth-service/internal/accounting/service"
)

type ReportHandler struct {
	querySvc *service.AccountingQueryService
	logger   *zap.Logger
}

func NewReportHandler(querySvc *service.AccountingQueryService, logger *zap.Logger) *ReportHandler {
	return &ReportHandler{
		querySvc: querySvc,
		logger:   logger.Named("report_handler"),
	}
}

// ------------------------------
// Trial Balance
// ------------------------------
type trialBalanceRequest struct {
	FiscalYear int `json:"fiscal_year"`
	Period     int `json:"period"`
}

func (h *ReportHandler) GetTrialBalance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.checkPermission(ctx, companyID, "accounting:reports:read"); err != nil {
		h.respondWithError(w, http.StatusForbidden, err.Error())
		return
	}

	var req trialBalanceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.FiscalYear == 0 || req.Period == 0 {
		h.respondWithError(w, http.StatusBadRequest, "fiscal_year and period are required")
		return
	}

	entries, totalDebit, totalCredit, err := h.querySvc.GetTrialBalance(ctx, companyID, req.FiscalYear, req.Period)
	if err != nil {
		h.logger.Error("failed to get trial balance", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve trial balance")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"entries":      entries,
			"total_debit":  totalDebit.String(),
			"total_credit": totalCredit.String(),
		},
	})
}

// ------------------------------
// General Ledger
// ------------------------------
func (h *ReportHandler) GetGeneralLedger(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.checkPermission(ctx, companyID, "accounting:reports:read"); err != nil {
		h.respondWithError(w, http.StatusForbidden, err.Error())
		return
	}

	accountIDStr := r.URL.Query().Get("account_id")
	if accountIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "account_id query parameter is required")
		return
	}
	accountID, err := uuid.Parse(accountIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid account_id")
		return
	}

	startDate, err := h.parseDateParam(r, "start_date")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid start_date")
		return
	}
	endDate, err := h.parseDateParam(r, "end_date")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid end_date")
		return
	}

	entries, openingBalance, err := h.querySvc.GetGeneralLedger(ctx, companyID, accountID, startDate, endDate)
	if err != nil {
		h.logger.Error("failed to get general ledger", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve general ledger")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"opening_balance": openingBalance.String(),
			"entries":         entries,
		},
	})
}

// ------------------------------
// Balance Sheet
// ------------------------------
func (h *ReportHandler) GetBalanceSheet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.checkPermission(ctx, companyID, "accounting:reports:read"); err != nil {
		h.respondWithError(w, http.StatusForbidden, err.Error())
		return
	}

	asOf, err := h.parseDateParam(r, "as_of")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid as_of date")
		return
	}

	assets, liabilities, equity, totalAssets, totalLiabilities, totalEquity, err := h.querySvc.GetBalanceSheet(ctx, companyID, asOf)
	if err != nil {
		h.logger.Error("failed to get balance sheet", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve balance sheet")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"assets":            assets,
			"liabilities":       liabilities,
			"equity":            equity,
			"total_assets":      totalAssets.String(),
			"total_liabilities": totalLiabilities.String(),
			"total_equity":      totalEquity.String(),
		},
	})
}

// ------------------------------
// Income Statement
// ------------------------------
type incomeStatementRequest struct {
	FiscalYear int `json:"fiscal_year"`
	Period     int `json:"period"`
}

func (h *ReportHandler) GetIncomeStatement(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.checkPermission(ctx, companyID, "accounting:reports:read"); err != nil {
		h.respondWithError(w, http.StatusForbidden, err.Error())
		return
	}

	var req incomeStatementRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.FiscalYear == 0 || req.Period == 0 {
		h.respondWithError(w, http.StatusBadRequest, "fiscal_year and period are required")
		return
	}

	revenues, expenses, totalRevenue, totalExpense, netIncome, err := h.querySvc.GetIncomeStatement(ctx, companyID, req.FiscalYear, req.Period)
	if err != nil {
		h.logger.Error("failed to get income statement", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve income statement")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"revenues":      revenues,
			"expenses":      expenses,
			"total_revenue": totalRevenue.String(),
			"total_expense": totalExpense.String(),
			"net_income":    netIncome.String(),
		},
	})
}

// ------------------------------
// Cash Flow Statement
// ------------------------------
func (h *ReportHandler) GetCashFlowStatement(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.checkPermission(ctx, companyID, "accounting:reports:read"); err != nil {
		h.respondWithError(w, http.StatusForbidden, err.Error())
		return
	}

	startDate, err := h.parseDateParam(r, "start_date")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid start_date")
		return
	}
	endDate, err := h.parseDateParam(r, "end_date")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid end_date")
		return
	}

	operating, investing, financing, err := h.querySvc.GetCashFlowStatement(ctx, companyID, startDate, endDate)
	if err != nil {
		h.logger.Error("failed to get cash flow statement", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve cash flow statement")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"operating": operating.String(),
			"investing": investing.String(),
			"financing": financing.String(),
		},
	})
}

// ------------------------------
// Tax Summary
// ------------------------------
func (h *ReportHandler) GetTaxSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.checkPermission(ctx, companyID, "accounting:reports:read"); err != nil {
		h.respondWithError(w, http.StatusForbidden, err.Error())
		return
	}

	startDate, err := h.parseDateParam(r, "start_date")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid start_date")
		return
	}
	endDate, err := h.parseDateParam(r, "end_date")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid end_date")
		return
	}

	results, totalTax, err := h.querySvc.GetTaxSummary(ctx, companyID, startDate, endDate)
	if err != nil {
		h.logger.Error("failed to get tax summary", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve tax summary")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"breakdown": results,
			"total_tax": totalTax.String(),
		},
	})
}

// ------------------------------
// List Compliance Returns
// ------------------------------
func (h *ReportHandler) ListComplianceReturns(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.checkPermission(ctx, companyID, "accounting:reports:read"); err != nil {
		h.respondWithError(w, http.StatusForbidden, err.Error())
		return
	}

	status := r.URL.Query().Get("status")
	yearStr := r.URL.Query().Get("year")
	var year int
	if yearStr != "" {
		year, _ = strconv.Atoi(yearStr)
	}
	limit, offset := h.parsePagination(r)

	summaries, total, err := h.querySvc.ListComplianceReturns(ctx, companyID, status, year, limit, offset)
	if err != nil {
		h.logger.Error("failed to list compliance returns", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve returns")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"items":  summaries,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		},
	})
}

// ------------------------------
// Helpers (same as AcademicYearHandler)
// ------------------------------
func (h *ReportHandler) parseCompanyID(r *http.Request) (uuid.UUID, error) {
	companyIDStr := chi.URLParam(r, "companyID")
	if companyIDStr == "" {
		return uuid.Nil, fmt.Errorf("company ID is required")
	}
	return uuid.Parse(companyIDStr)
}

func (h *ReportHandler) parseDateParam(r *http.Request, param string) (time.Time, error) {
	val := r.URL.Query().Get(param)
	if val == "" {
		return time.Time{}, fmt.Errorf("missing %s", param)
	}
	return time.Parse("2006-01-02", val)
}

func (h *ReportHandler) parsePagination(r *http.Request) (limit, offset int) {
	limit = 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	offset = 0
	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	return
}

func (h *ReportHandler) checkPermission(ctx context.Context, companyID uuid.UUID, permission string) error {
	// In real implementation, fetch user from context and check RBAC.
	// For now, stub returning nil (allowed).
	return nil
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
