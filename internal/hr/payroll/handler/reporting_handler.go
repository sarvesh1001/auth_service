package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"auth-service/internal/hr/payroll/service"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type ReportingHandler struct {
	reportingService service.ReportingService
	logger           *zap.Logger
}

func NewReportingHandler(reportingService service.ReportingService, logger *zap.Logger) *ReportingHandler {
	return &ReportingHandler{
		reportingService: reportingService,
		logger:           logger.Named("reporting_handler"),
	}
}

// ----------------------------------------------------------------------
// Request & Response Types
// ----------------------------------------------------------------------

type generateStatutoryChallanRequest struct {
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
}

func (r *generateStatutoryChallanRequest) validate() error {
	if r.PeriodStart.IsZero() {
		return errMissingField("period_start")
	}
	if r.PeriodEnd.IsZero() {
		return errMissingField("period_end")
	}
	if r.PeriodEnd.Before(r.PeriodStart) {
		return errInvalidField("period_end cannot be before period_start")
	}
	return nil
}

type statutoryChallanResponse struct {
	StatutoryCode  string  `json:"statutory_code"`
	Description    string  `json:"description"`
	EmployeeAmount float64 `json:"employee_amount"`
	EmployerAmount float64 `json:"employer_amount"`
	TotalAmount    float64 `json:"total_amount"`
}

type generatePayrollRegisterRequest struct {
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	GroupBy     string    `json:"group_by"`
}

func (r *generatePayrollRegisterRequest) validate() error {
	if r.PeriodStart.IsZero() {
		return errMissingField("period_start")
	}
	if r.PeriodEnd.IsZero() {
		return errMissingField("period_end")
	}
	if r.PeriodEnd.Before(r.PeriodStart) {
		return errInvalidField("period_end cannot be before period_start")
	}
	return nil
}

// ----------------------------------------------------------------------
// Handlers
// ----------------------------------------------------------------------

func (h *ReportingHandler) GenerateStatutoryChallan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseUUIDParam(r, "companyID")
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req generateStatutoryChallanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := req.validate(); err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	entries, err := h.reportingService.GenerateStatutoryChallan(ctx, companyID, req.PeriodStart, req.PeriodEnd)
	if err != nil {
		h.logger.Error("failed to generate statutory challan", zap.Error(err))
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := make([]statutoryChallanResponse, 0, len(entries))
	for _, e := range entries {
		resp = append(resp, statutoryChallanResponse{
			StatutoryCode:  e.StatutoryCode,
			Description:    e.Description,
			EmployeeAmount: e.EmployeeAmount,
			EmployerAmount: e.EmployerAmount,
			TotalAmount:    e.TotalAmount,
		})
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

func (h *ReportingHandler) GeneratePayrollRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseUUIDParam(r, "companyID")
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req generatePayrollRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := req.validate(); err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	groupBy := req.GroupBy
	if groupBy == "" {
		groupBy = "employee"
	}

	rows, err := h.reportingService.GeneratePayrollRegister(ctx, companyID, req.PeriodStart, req.PeriodEnd, groupBy)
	if err != nil {
		h.logger.Error("failed to generate payroll register", zap.Error(err))
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    rows,
	})
}

// ----------------------------------------------------------------------
// Helper Functions (copied here to avoid missing imports)
// ----------------------------------------------------------------------

func errMissingField(field string) error {
	return fmt.Errorf("missing required field: %s", field)
}

func errInvalidField(msg string) error {
	return fmt.Errorf("invalid field: %s", msg)
}

func respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func respondWithError(w http.ResponseWriter, status int, message string) {
	respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    status,
		"time":    time.Now().UTC(),
	})
}

func getAdminActor(ctx context.Context) (uuid.UUID, error) {
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok || userIDStr == "" {
		return uuid.Nil, errors.New("unauthenticated user")
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, errors.New("invalid user_id in context")
	}
	return userID, nil
}
