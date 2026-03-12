package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/service"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type LoanHandler struct {
	loanService service.LoanService
	logger      *zap.Logger
}

func NewLoanHandler(loanService service.LoanService, logger *zap.Logger) *LoanHandler {
	return &LoanHandler{
		loanService: loanService,
		logger:      logger.Named("loan_handler"),
	}
}

// ----------------------------------------------------------------------
// Request & Response Types
// ----------------------------------------------------------------------

type createLoanRequest struct {
	UserID          uuid.UUID `json:"user_id"`
	LoanType        string    `json:"loan_type"`
	PrincipalAmount float64   `json:"principal_amount"`
	EmiAmount       float64   `json:"emi_amount"` // optional
	InterestRate    *float64  `json:"interest_rate,omitempty"`
	InterestType    *string   `json:"interest_type,omitempty"` // "flat" or "compound"
	TotalEmis       int       `json:"total_emis"`
	DisbursedAt     time.Time `json:"disbursed_at"`
	FirstEmiDate    time.Time `json:"first_emi_date"`
	ComponentCode   string    `json:"component_code"` // optional
	MaxCTCPercent   float64   `json:"max_ctc_percent"`
}

func (r *createLoanRequest) validate() error {
	if r.UserID == uuid.Nil {
		return errors.New("user_id is required")
	}
	if r.LoanType == "" {
		return errors.New("loan_type is required")
	}
	if r.PrincipalAmount <= 0 {
		return errors.New("principal_amount must be positive")
	}
	if r.TotalEmis <= 0 {
		return errors.New("total_emis must be positive")
	}
	if r.DisbursedAt.IsZero() {
		return errors.New("disbursed_at is required")
	}
	if r.FirstEmiDate.IsZero() {
		return errors.New("first_emi_date is required")
	}
	if r.FirstEmiDate.Before(r.DisbursedAt) {
		return errors.New("first_emi_date cannot be before disbursed_at")
	}
	return nil
}

// emiPreviewRequest – MODIFIED to include interestRate and interestType
type emiPreviewRequest struct {
	UserID        uuid.UUID `json:"user_id"`
	Principal     float64   `json:"principal"`
	TotalEmis     int       `json:"total_emis"`
	InterestRate  *float64  `json:"interest_rate,omitempty"` // NEW
	InterestType  *string   `json:"interest_type,omitempty"` // NEW
	MaxCTCPercent float64   `json:"max_ctc_percent"`
}

type markEmiPaidRequest struct {
	PaidDate     time.Time  `json:"paid_date"`
	PayrollRunID *uuid.UUID `json:"payroll_run_id,omitempty"`
}

func (r *markEmiPaidRequest) validate() error {
	if r.PaidDate.IsZero() {
		return errors.New("paid_date is required")
	}
	return nil
}

type closeLoanRequest struct {
	ClosureDate time.Time `json:"closure_date"`
}

func (r *closeLoanRequest) validate() error {
	if r.ClosureDate.IsZero() {
		return errors.New("closure_date is required")
	}
	return nil
}

type manualPaymentRequest struct {
	Amount  float64   `json:"amount"`
	Penalty float64   `json:"penalty"`
	PaidAt  time.Time `json:"paid_at"`
}

// ----------------------------------------------------------------------
// Handlers
// ----------------------------------------------------------------------

// CreateLoan godoc
// POST /api/v1/companies/{companyId}/payroll/loans
func (h *LoanHandler) CreateLoan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseUUIDParam(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	actorID, err := h.getActorID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req createLoanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := req.validate(); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	loan := &models.EmployeeLoan{
		CompanyID:       companyID,
		UserID:          req.UserID,
		LoanType:        req.LoanType,
		PrincipalAmount: req.PrincipalAmount,
		EmiAmount:       req.EmiAmount,
		InterestRate:    req.InterestRate,
		InterestType:    req.InterestType,
		TotalEmis:       req.TotalEmis,
		DisbursedAt:     req.DisbursedAt,
		FirstEmiDate:    req.FirstEmiDate,
		ComponentCode:   req.ComponentCode,
		CreatedBy:       &actorID,
	}

	createdLoan, err := h.loanService.CreateLoan(ctx, loan, req.MaxCTCPercent)
	if err != nil {
		h.logger.Error("failed to create loan", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	response := map[string]interface{}{
		"success": true,
		"data":    createdLoan,
		"meta": map[string]interface{}{
			"emi_auto_calculated": req.EmiAmount <= 0,
			"ctc_cap_percent":     req.MaxCTCPercent,
		},
	}
	h.respondWithJSON(w, http.StatusCreated, response)
}

// PreviewEMI godoc – MODIFIED to accept interest fields
// POST /api/v1/companies/{companyId}/payroll/loans/preview-emi
func (h *LoanHandler) PreviewEMI(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseUUIDParam(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req emiPreviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// MODIFIED: pass interestRate and interestType to service
	result, err := h.loanService.CalculateEMI(
		ctx,
		companyID,
		req.UserID,
		req.Principal,
		req.TotalEmis,
		req.MaxCTCPercent,
		req.InterestRate,
		req.InterestType,
	)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

// GetLoan godoc (unchanged)
// GET /api/v1/companies/{companyId}/payroll/loans/{loanId}
func (h *LoanHandler) GetLoan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseUUIDParam(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	loanID, err := parseUUIDParam(r, "loanID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	loan, err := h.loanService.GetLoan(ctx, loanID)
	if err != nil {
		h.logger.Error("failed to get loan", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if loan == nil {
		h.respondWithError(w, http.StatusNotFound, "loan not found")
		return
	}
	if loan.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "loan does not belong to this company")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    loan,
	})
}

// ListUserLoans godoc (unchanged)
// GET /api/v1/companies/{companyId}/payroll/loans/user/{userId}?includeClosed=true
func (h *LoanHandler) ListUserLoans(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := parseUUIDParam(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	userID, err := parseUUIDParam(r, "userId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	includeClosed := r.URL.Query().Get("includeClosed") == "true"

	loans, err := h.loanService.ListUserLoans(ctx, companyID, userID, includeClosed)
	if err != nil {
		h.logger.Error("failed to list user loans", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    loans,
	})
}

// GetPendingEMIsForLoan godoc (unchanged)
// GET /api/v1/companies/{companyId}/payroll/loans/{loanId}/pending-emis
func (h *LoanHandler) GetPendingEMIsForLoan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	loanID, err := parseUUIDParam(r, "loanID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	emis, err := h.loanService.GetPendingEMIsForLoan(ctx, loanID)
	if err != nil {
		h.logger.Error("failed to get pending EMIs", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    emis,
	})
}

// GetPendingEMIsForPayrollRun godoc (unchanged)
// GET /api/v1/companies/{companyId}/payroll/runs/{payrollRunId}/pending-emis
func (h *LoanHandler) GetPendingEMIsForPayrollRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	payrollRunID, err := parseUUIDParam(r, "payrollRunID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	emis, err := h.loanService.GetPendingEMIsForPayrollRun(ctx, payrollRunID)
	if err != nil {
		h.logger.Error("failed to get pending EMIs for payroll run", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    emis,
	})
}

// MarkEMIAsPaid godoc (unchanged)
// POST /api/v1/companies/{companyId}/payroll/emis/{emiId}/paid
func (h *LoanHandler) MarkEMIAsPaid(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	emiID, err := parseUUIDParam(r, "emiID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	actorID, _ := h.getActorID(ctx) // optional

	var req markEmiPaidRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := req.validate(); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.loanService.MarkEMIAsPaid(ctx, emiID, req.PaidDate, req.PayrollRunID); err != nil {
		h.logger.Error("failed to mark EMI as paid", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "EMI marked as paid",
		"actor":   actorID,
	})
}

// CloseLoan godoc (unchanged)
// POST /api/v1/companies/{companyId}/payroll/loans/{loanId}/close
func (h *LoanHandler) CloseLoan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	loanID, err := parseUUIDParam(r, "loanID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	actorID, _ := h.getActorID(ctx)

	var req closeLoanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := req.validate(); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.loanService.CloseLoan(ctx, loanID, req.ClosureDate); err != nil {
		h.logger.Error("failed to close loan", zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "loan closed",
		"actor":   actorID,
	})
}

// RecordManualPayment godoc (unchanged)
// POST /api/v1/companies/{companyId}/payroll/loans/{loanId}/manual-payment
func (h *LoanHandler) RecordManualPayment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	loanID, err := parseUUIDParam(r, "loanID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	actorID, err := h.getActorID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req manualPaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	err = h.loanService.RecordManualPayment(
		ctx,
		loanID,
		req.Amount,
		req.Penalty,
		req.PaidAt,
		actorID,
	)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "manual payment recorded",
	})
}

// ListLoanPayments godoc (unchanged)
// GET /api/v1/companies/{companyId}/payroll/loans/{loanId}/payments
func (h *LoanHandler) ListLoanPayments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	loanID, err := parseUUIDParam(r, "loanID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	payments, err := h.loanService.ListLoanPayments(ctx, loanID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    payments,
	})
}

// ----------------------------------------------------------------------
// Helper functions (unchanged)
// ----------------------------------------------------------------------

func (h *LoanHandler) getActorID(ctx context.Context) (uuid.UUID, error) {
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

func (h *LoanHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *LoanHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    status,
		"time":    time.Now().UTC(),
	})
}
