package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/service"
	"auth-service/internal/util"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type PayrollAdminHandler struct {
	lockService service.PayrollLockService
	calcService service.PayrollCalculationService
	logger      *zap.Logger
}

func NewPayrollAdminHandler(
	lockService service.PayrollLockService,
	calcService service.PayrollCalculationService,
	logger *zap.Logger,
) *PayrollAdminHandler {
	return &PayrollAdminHandler{
		lockService: lockService,
		calcService: calcService,
		logger:      logger,
	}
}

// LockPeriodRequest represents request to lock payroll period
type LockPeriodRequest struct {
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	LockedBy    uuid.UUID `json:"locked_by"`
}

// UnlockPeriodRequest represents request to unlock payroll period
type UnlockPeriodRequest struct {
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	UnlockedBy  uuid.UUID `json:"unlocked_by"`
}

// ForceRecalculationRequest represents request to force recalculation
type ForceRecalculationRequest struct {
	UserID  uuid.UUID `json:"user_id,omitempty"` // If empty, recalculate entire run
	ActorID uuid.UUID `json:"actor_id"`
}

// TaxProfileRequest represents request to configure tax profile
type TaxProfileRequest struct {
	CountryCode string `json:"country_code"`
	Name        string `json:"name"`
	IsActive    bool   `json:"is_active"`
}

// TaxRuleRequest represents request to configure tax rule
type TaxRuleRequest struct {
	TaxProfileID    uuid.UUID `json:"tax_profile_id"`
	ComponentCode   string    `json:"component_code"`
	CalculationType string    `json:"calculation_type"`
	Value           *float64  `json:"value,omitempty"`
	Formula         *string   `json:"formula,omitempty"`
	MinAmount       *float64  `json:"min_amount,omitempty"`
	MaxAmount       *float64  `json:"max_amount,omitempty"`
}

func (h *PayrollAdminHandler) LockPeriod(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	var req LockPeriodRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate request
	if req.PeriodStart.IsZero() || req.PeriodEnd.IsZero() {
		h.respondWithError(w, http.StatusBadRequest, "Period start and end are required")
		return
	}
	if req.PeriodStart.After(req.PeriodEnd) {
		h.respondWithError(w, http.StatusBadRequest, "Period start cannot be after period end")
		return
	}
	if req.LockedBy == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "Locked by is required")
		return
	}

	// Lock period
	if err := h.lockService.LockPeriod(ctx, companyID, req.PeriodStart, req.PeriodEnd); err != nil {
		h.logger.Error("Failed to lock payroll period",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))

		status := http.StatusInternalServerError
		if err.Error() == "period is already locked" {
			status = http.StatusConflict
		}
		h.respondWithError(w, status, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Payroll period locked successfully",
	})
}

func (h *PayrollAdminHandler) UnlockPeriod(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	var req UnlockPeriodRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate request
	if req.PeriodStart.IsZero() || req.PeriodEnd.IsZero() {
		h.respondWithError(w, http.StatusBadRequest, "Period start and end are required")
		return
	}
	if req.PeriodStart.After(req.PeriodEnd) {
		h.respondWithError(w, http.StatusBadRequest, "Period start cannot be after period end")
		return
	}
	if req.UnlockedBy == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "Unlocked by is required")
		return
	}

	// Unlock period (admin override)
	if err := h.lockService.UnlockPeriod(ctx, companyID, req.PeriodStart, req.PeriodEnd); err != nil {
		h.logger.Error("Failed to unlock payroll period",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to unlock payroll period")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Payroll period unlocked successfully (admin override)",
	})
}

func (h *PayrollAdminHandler) CheckPeriodLock(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	dateStr := r.URL.Query().Get("date")
	if dateStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "Date parameter is required")
		return
	}

	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid date format, use YYYY-MM-DD")
		return
	}

	// Check if period is locked
	locked, err := h.lockService.IsPeriodLocked(ctx, companyID, date)
	if err != nil {
		h.logger.Error("Failed to check period lock",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to check period lock")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"is_locked":  locked,
			"date":       date.Format("2006-01-02"),
			"company_id": companyID.String(),
		},
	})
}

func (h *PayrollAdminHandler) ForceRecalculation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	runIDStr := chi.URLParam(r, "runID")
	runID, err := uuid.Parse(runIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid payroll run ID")
		return
	}

	var req ForceRecalculationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.ActorID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "Actor ID is required")
		return
	}

	// Force recalculation
	if req.UserID != uuid.Nil {
		// Recalculate specific employee
		if err := h.calcService.RecalculateEmployee(ctx, runID, req.UserID); err != nil {
			h.logger.Error("Failed to recalculate employee payroll",
				util.String("run_id", runID.String()),
				util.String("user_id", req.UserID.String()),
				util.String("company_id", companyID.String()),
				util.ErrorField(err))
			h.respondWithError(w, http.StatusInternalServerError, "Failed to recalculate employee payroll")
			return
		}

		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "Employee payroll recalculated successfully",
			"data": map[string]interface{}{
				"run_id":   runID.String(),
				"user_id":  req.UserID.String(),
				"actor_id": req.ActorID.String(),
			},
		})
	} else {
		// Recalculate entire run (admin only - be careful!)
		h.respondWithError(w, http.StatusNotImplemented, "Bulk recalculation not implemented. Use specific user recalculation.")
	}
}

func (h *PayrollAdminHandler) GetPayrollComponents(w http.ResponseWriter, r *http.Request) {
	_ = r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// This would typically come from a service/repository
	// For now, return standard components
	components := []map[string]interface{}{
		{
			"component_code": models.ComponentCodeBasic,
			"component_type": models.ComponentTypeEarning,
			"description":    "Basic Salary",
			"is_taxable":     true,
			"is_system":      true,
			"is_active":      true,
		},
		{
			"component_code": models.ComponentCodeHRA,
			"component_type": models.ComponentTypeEarning,
			"description":    "House Rent Allowance",
			"is_taxable":     true,
			"is_system":      false,
			"is_active":      true,
		},
		{
			"component_code": models.ComponentCodePF,
			"component_type": models.ComponentTypeDeduction,
			"description":    "Provident Fund",
			"is_taxable":     false,
			"is_system":      false,
			"is_active":      true,
		},
		{
			"component_code": models.ComponentCodeTDS,
			"component_type": models.ComponentTypeDeduction,
			"description":    "Income Tax",
			"is_taxable":     false,
			"is_system":      false,
			"is_active":      true,
		},
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"components": components,
			"company_id": companyID.String(),
		},
	})
}

func (h *PayrollAdminHandler) ValidatePeriodNotLocked(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// Get period from query params
	periodStartStr := r.URL.Query().Get("period_start")
	periodEndStr := r.URL.Query().Get("period_end")

	if periodStartStr == "" || periodEndStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "period_start and period_end parameters are required")
		return
	}

	periodStart, err := time.Parse("2006-01-02", periodStartStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid period_start format, use YYYY-MM-DD")
		return
	}

	periodEnd, err := time.Parse("2006-01-02", periodEndStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid period_end format, use YYYY-MM-DD")
		return
	}

	if periodStart.After(periodEnd) {
		h.respondWithError(w, http.StatusBadRequest, "period_start cannot be after period_end")
		return
	}

	// This would be a method in the lock service, but we can simulate it
	lockedDates := []string{}
	for d := periodStart; !d.After(periodEnd); d = d.AddDate(0, 0, 1) {
		locked, err := h.lockService.IsPeriodLocked(ctx, companyID, d)
		if err != nil {
			h.logger.Error("Failed to check period lock for date",
				util.String("company_id", companyID.String()),
				util.String("date", d.Format("2006-01-02")),
				util.ErrorField(err))
			h.respondWithError(w, http.StatusInternalServerError, "Failed to validate period")
			return
		}
		if locked {
			lockedDates = append(lockedDates, d.Format("2006-01-02"))
		}
	}

	isLocked := len(lockedDates) > 0
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"is_locked":    isLocked,
			"locked_dates": lockedDates,
			"period_start": periodStart.Format("2006-01-02"),
			"period_end":   periodEnd.Format("2006-01-02"),
			"company_id":   companyID.String(),
		},
	})
}

// Admin dashboard endpoints
func (h *PayrollAdminHandler) GetAdminDashboard(w http.ResponseWriter, r *http.Request) {
	_ = r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// This would typically fetch dashboard data from multiple services
	dashboardData := map[string]interface{}{
		"company_id":      companyID.String(),
		"current_period":  time.Now().UTC().Format("January 2006"),
		"locked_periods":  0, // Would be calculated
		"pending_runs":    0, // Would be calculated
		"completed_runs":  0, // Would be calculated
		"total_employees": 0, // Would be calculated
		"recent_activity": []map[string]interface{}{
			{
				"action": "payroll_run.created",
				"run_id": uuid.New().String(),
				"period": "December 2023",
				"status": "draft",
				"date":   time.Now().Add(-24 * time.Hour).Format("2006-01-02 15:04"),
				"actor":  "System",
			},
		},
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    dashboardData,
	})
}

// Health check endpoint for admin
func (h *PayrollAdminHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	healthStatus := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"services": map[string]string{
			"lock_service": "operational",
			"calc_service": "operational",
		},
		"version": "1.0.0",
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    healthStatus,
	})
}

// Helper methods
func (h *PayrollAdminHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *PayrollAdminHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
