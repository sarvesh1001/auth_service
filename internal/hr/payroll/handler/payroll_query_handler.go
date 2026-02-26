package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/service"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// PayrollQueryHandler handles read-only payroll operations.
type PayrollQueryHandler struct {
	queryService service.PayrollQueryService
	logger       *zap.Logger
}

// NewPayrollQueryHandler creates a new payroll query handler.
func NewPayrollQueryHandler(
	queryService service.PayrollQueryService,
	logger *zap.Logger,
) *PayrollQueryHandler {
	return &PayrollQueryHandler{
		queryService: queryService,
		logger:       logger,
	}
}

// ListRuns returns a paginated list of payroll runs.
// GET /companies/{companyID}/payroll/runs
func (h *PayrollQueryHandler) ListRuns(w http.ResponseWriter, r *http.Request) {
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	// Parse query filters
	filter := models.PayrollRunFilter{
		CompanyID: companyID,
	}

	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = &status
	}
	if periodStart := r.URL.Query().Get("period_start"); periodStart != "" {
		t, err := time.Parse("2006-01-02", periodStart)
		if err == nil {
			filter.PeriodStart = &t
		}
	}
	if periodEnd := r.URL.Query().Get("period_end"); periodEnd != "" {
		t, err := time.Parse("2006-01-02", periodEnd)
		if err == nil {
			filter.PeriodEnd = &t
		}
	}
	// Pagination
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	filter.Page = page
	filter.PageSize = pageSize

	runs, total, err := h.queryService.ListRuns(r.Context(), filter)
	if err != nil {
		h.logger.Error("failed to list payroll runs", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    runs,
		"total":   total,
		"page":    page,
		"size":    pageSize,
	})
}

// GetRunSummary returns summary dashboard for a payroll run.
// GET /companies/{companyID}/payroll/runs/{runID}/summary
func (h *PayrollQueryHandler) GetRunSummary(w http.ResponseWriter, r *http.Request) {
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	runID, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid run id")
		return
	}

	summary, err := h.queryService.GetRunSummary(r.Context(), companyID, runID)
	if err != nil {
		h.logger.Error("failed to get run summary", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}

// GetRunLedgerSummary returns ledger summary for a payroll run.
// GET /companies/{companyID}/payroll/runs/{runID}/ledger-summary
func (h *PayrollQueryHandler) GetRunLedgerSummary(w http.ResponseWriter, r *http.Request) {
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	runID, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid run id")
		return
	}

	summary, err := h.queryService.GetRunLedgerSummary(r.Context(), companyID, runID)
	if err != nil {
		h.logger.Error("failed to get run ledger summary", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}

// GetRunExecutionStatus returns execution progress of a payroll run.
// GET /companies/{companyID}/payroll/runs/{runID}/execution-status
func (h *PayrollQueryHandler) GetRunExecutionStatus(w http.ResponseWriter, r *http.Request) {
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	runID, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid run id")
		return
	}

	status, err := h.queryService.GetRunExecutionStatus(r.Context(), companyID, runID)
	if err != nil {
		h.logger.Error("failed to get run execution status", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    status,
	})
}

// ListEmployeesInRun returns all payroll items for a given run.
// GET /companies/{companyID}/payroll/runs/{runID}/employees
func (h *PayrollQueryHandler) ListEmployeesInRun(w http.ResponseWriter, r *http.Request) {
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	runID, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid run id")
		return
	}

	items, err := h.queryService.ListEmployeesInRun(r.Context(), companyID, runID)
	if err != nil {
		h.logger.Error("failed to list employees in run", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    items,
	})
}

// GetEmployeePayrollDetail returns detailed payroll item for an employee.
// GET /companies/{companyID}/payroll/items/{payrollItemID}
func (h *PayrollQueryHandler) GetEmployeePayrollDetail(w http.ResponseWriter, r *http.Request) {
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	itemID, err := uuid.Parse(chi.URLParam(r, "payrollItemID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payroll item id")
		return
	}

	detail, err := h.queryService.GetEmployeePayrollDetail(r.Context(), companyID, itemID)
	if err != nil {
		h.logger.Error("failed to get payroll item detail", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    detail,
	})
}

// GetEmployeePayrollHistory returns payroll history for an employee.
// GET /companies/{companyID}/employees/{userID}/payroll-history
func (h *PayrollQueryHandler) GetEmployeePayrollHistory(w http.ResponseWriter, r *http.Request) {
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	var from, to time.Time
	if fromStr != "" {
		from, err = time.Parse("2006-01-02", fromStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid from date format, use YYYY-MM-DD")
			return
		}
	}
	if toStr != "" {
		to, err = time.Parse("2006-01-02", toStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid to date format, use YYYY-MM-DD")
			return
		}
	}

	history, err := h.queryService.GetEmployeePayrollHistory(r.Context(), companyID, userID, from, to)
	if err != nil {
		h.logger.Error("failed to get employee payroll history", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    history,
	})
}

// GetEmployeeYTD returns year-to-date summary for an employee.
// GET /companies/{companyID}/employees/{userID}/ytd
func (h *PayrollQueryHandler) GetEmployeeYTD(w http.ResponseWriter, r *http.Request) {
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	finYearStartStr := r.URL.Query().Get("financial_year_start")
	if finYearStartStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "financial_year_start is required")
		return
	}
	finYearStart, err := time.Parse("2006-01-02", finYearStartStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid financial_year_start format, use YYYY-MM-DD")
		return
	}

	ytd, err := h.queryService.GetEmployeeYTD(r.Context(), companyID, userID, finYearStart)
	if err != nil {
		h.logger.Error("failed to get employee YTD", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    ytd,
	})
}

// GetEmployeeStatutorySummary returns statutory summary for an employee.
// GET /companies/{companyID}/employees/{userID}/statutory-summary
func (h *PayrollQueryHandler) GetEmployeeStatutorySummary(w http.ResponseWriter, r *http.Request) {
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	finYearStartStr := r.URL.Query().Get("financial_year_start")
	if finYearStartStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "financial_year_start is required")
		return
	}
	finYearStart, err := time.Parse("2006-01-02", finYearStartStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid financial_year_start format, use YYYY-MM-DD")
		return
	}

	summary, err := h.queryService.GetEmployeeStatutorySummary(r.Context(), companyID, userID, finYearStart)
	if err != nil {
		h.logger.Error("failed to get employee statutory summary", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}

// GetRunStatutorySummary returns statutory totals for a payroll run.
// GET /companies/{companyID}/payroll/runs/{runID}/statutory-summary
func (h *PayrollQueryHandler) GetRunStatutorySummary(w http.ResponseWriter, r *http.Request) {
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	runID, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid run id")
		return
	}

	summary, err := h.queryService.GetRunStatutorySummary(r.Context(), companyID, runID)
	if err != nil {
		h.logger.Error("failed to get run statutory summary", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}

// GetCompanyPayrollTrend returns payroll trend over a date range.
// GET /companies/{companyID}/payroll/trends
func (h *PayrollQueryHandler) GetCompanyPayrollTrend(w http.ResponseWriter, r *http.Request) {
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}

	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	var from, to time.Time
	if fromStr != "" {
		from, err = time.Parse("2006-01-02", fromStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid from date format, use YYYY-MM-DD")
			return
		}
	}
	if toStr != "" {
		to, err = time.Parse("2006-01-02", toStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid to date format, use YYYY-MM-DD")
			return
		}
	}

	trend, err := h.queryService.GetCompanyPayrollTrend(r.Context(), companyID, from, to)
	if err != nil {
		h.logger.Error("failed to get payroll trend", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    trend,
	})
}

// GetComponentBreakdownTrend returns trend for a specific component.
// GET /companies/{companyID}/payroll/component-trend/{componentCode}
func (h *PayrollQueryHandler) GetComponentBreakdownTrend(w http.ResponseWriter, r *http.Request) {
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	componentCode := chi.URLParam(r, "componentCode")
	if componentCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "component code is required")
		return
	}

	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	var from, to time.Time
	if fromStr != "" {
		from, err = time.Parse("2006-01-02", fromStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid from date format, use YYYY-MM-DD")
			return
		}
	}
	if toStr != "" {
		to, err = time.Parse("2006-01-02", toStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid to date format, use YYYY-MM-DD")
			return
		}
	}

	trend, err := h.queryService.GetComponentBreakdownTrend(r.Context(), companyID, componentCode, from, to)
	if err != nil {
		h.logger.Error("failed to get component trend", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    trend,
	})
}

// GetEmployeePayslip returns payslip for a payroll item.
// GET /companies/{companyID}/payroll/payslips/{payrollItemID}
func (h *PayrollQueryHandler) GetEmployeePayslip(w http.ResponseWriter, r *http.Request) {
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	itemID, err := uuid.Parse(chi.URLParam(r, "payrollItemID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid payroll item id")
		return
	}

	payslip, err := h.queryService.GetEmployeePayslip(r.Context(), companyID, itemID)
	if err != nil {
		h.logger.Error("failed to get payslip", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    payslip,
	})
}

// ExportRunToCSV exports a payroll run as CSV.
// GET /companies/{companyID}/payroll/runs/{runID}/export
func (h *PayrollQueryHandler) ExportRunToCSV(w http.ResponseWriter, r *http.Request) {
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company id")
		return
	}
	runID, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid run id")
		return
	}

	csvData, err := h.queryService.ExportRunToCSV(r.Context(), companyID, runID)
	if err != nil {
		h.logger.Error("failed to export run to CSV", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=payroll_run_"+runID.String()+".csv")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(csvData)
}

// respondWithJSON writes a JSON response.
func (h *PayrollQueryHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// respondWithError writes an error response in JSON.
func (h *PayrollQueryHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    status,
		"time":    time.Now().UTC(),
	})
}
