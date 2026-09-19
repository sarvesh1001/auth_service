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
)

type LoanHandler struct {
	loanService service.LoanService
}

func NewLoanHandler(loanService service.LoanService) *LoanHandler {
	return &LoanHandler{
		loanService: loanService,
	}
}

// ----------------------------------------------------------------------
// Request & Response Types
// ----------------------------------------------------------------------

type createLoanRequest struct {
	UserID          uuid.UUID `json:"user_id"`
	LoanType        string    `json:"loan_type"`
	PrincipalAmount float64   `json:"principal_amount"`
	EmiAmount       float64   `json:"emi_amount"`
	InterestRate    *float64  `json:"interest_rate,omitempty"`
	InterestType    *string   `json:"interest_type,omitempty"`
	TotalEmis       int       `json:"total_emis"`
	DisbursedAt     time.Time `json:"disbursed_at"`
	FirstEmiDate    time.Time `json:"first_emi_date"`
	ComponentCode   string    `json:"component_code"`
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

type emiPreviewRequest struct {
	UserID        uuid.UUID `json:"user_id"`
	Principal     float64   `json:"principal"`
	TotalEmis     int       `json:"total_emis"`
	InterestRate  *float64  `json:"interest_rate,omitempty"`
	InterestType  *string   `json:"interest_type,omitempty"`
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
// Helpers
// ----------------------------------------------------------------------

func (h *LoanHandler) getActorID(ctx context.Context) (uuid.UUID, error) {
	if v := ctx.Value("current_user_id"); v != nil {
		if id, ok := v.(uuid.UUID); ok {
			return id, nil
		}
	}
	if v := ctx.Value("user_id"); v != nil {
		switch raw := v.(type) {
		case uuid.UUID:
			return raw, nil
		case string:
			return uuid.Parse(raw)
		default:
			return uuid.Nil, errors.New("invalid user_id type")
		}
	}
	return uuid.Nil, errors.New("user not authenticated")
}

// ----------------------------------------------------------------------
// Handlers
// ----------------------------------------------------------------------

// CreateLoan godoc
// POST /api/v1/companies/{companyId}/payroll/loans
func (h *LoanHandler) CreateLoan(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := parseUUIDParam(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
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
	}

	actorID, _ := h.getActorID(ctx)
	loan.CreatedBy = &actorID

	createdLoan, err := h.loanService.CreateLoan(ctx, loan, req.MaxCTCPercent)
	if err != nil {
		if mapPayrollLocationError(w, err) {
			return
		}
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

// PreviewEMI godoc
// POST /api/v1/companies/{companyId}/payroll/loans/preview-emi
func (h *LoanHandler) PreviewEMI(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

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
		if mapPayrollLocationError(w, err) {
			return
		}
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

// GetLoan godoc
// GET /api/v1/companies/{companyId}/payroll/loans/{loanId}
func (h *LoanHandler) GetLoan(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

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
		if mapPayrollLocationError(w, err) {
			return
		}
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

// ListUserLoans godoc
// GET /api/v1/companies/{companyId}/payroll/loans/user/{userId}?includeClosed=true
func (h *LoanHandler) ListUserLoans(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

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
		if mapPayrollLocationError(w, err) {
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    loans,
	})
}

// GetPendingEMIsForLoan godoc
// GET /api/v1/companies/{companyId}/payroll/loans/{loanId}/pending-emis
func (h *LoanHandler) GetPendingEMIsForLoan(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	loanID, err := parseUUIDParam(r, "loanID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	emis, err := h.loanService.GetPendingEMIsForLoan(ctx, loanID)
	if err != nil {
		if mapPayrollLocationError(w, err) {
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    emis,
	})
}

// GetPendingEMIsForPayrollRun godoc
// GET /api/v1/companies/{companyId}/payroll/runs/{payrollRunId}/pending-emis
func (h *LoanHandler) GetPendingEMIsForPayrollRun(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	payrollRunID, err := parseUUIDParam(r, "payrollRunID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	emis, err := h.loanService.GetPendingEMIsForPayrollRun(ctx, payrollRunID)
	if err != nil {
		if mapPayrollLocationError(w, err) {
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    emis,
	})
}

// MarkEMIAsPaid godoc
// POST /api/v1/companies/{companyId}/payroll/emis/{emiId}/paid
func (h *LoanHandler) MarkEMIAsPaid(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	emiID, err := parseUUIDParam(r, "emiID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

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
		if mapPayrollLocationError(w, err) {
			return
		}
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "EMI marked as paid",
	})
}

// CloseLoan godoc
// POST /api/v1/companies/{companyId}/payroll/loans/{loanId}/close
func (h *LoanHandler) CloseLoan(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	loanID, err := parseUUIDParam(r, "loanID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

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
		if mapPayrollLocationError(w, err) {
			return
		}
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "loan closed",
	})
}

// RecordManualPayment godoc
// POST /api/v1/companies/{companyId}/payroll/loans/{loanId}/manual-payment
func (h *LoanHandler) RecordManualPayment(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

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

	if err := h.loanService.RecordManualPayment(ctx, loanID, req.Amount, req.Penalty, req.PaidAt, actorID); err != nil {
		if mapPayrollLocationError(w, err) {
			return
		}
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "manual payment recorded",
	})
}

// ListLoanPayments godoc
// GET /api/v1/companies/{companyId}/payroll/loans/{loanId}/payments
func (h *LoanHandler) ListLoanPayments(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	loanID, err := parseUUIDParam(r, "loanID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	payments, err := h.loanService.ListLoanPayments(ctx, loanID)
	if err != nil {
		if mapPayrollLocationError(w, err) {
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    payments,
	})
}

// ----------------------------------------------------------------------
// Response helpers
// ----------------------------------------------------------------------

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
