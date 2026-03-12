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

// PayslipHandler handles HTTP requests for payslip operations.
type PayslipHandler struct {
	payslipService service.PayslipService
	logger         *zap.Logger
}

// NewPayslipHandler creates a new PayslipHandler.
func NewPayslipHandler(payslipService service.PayslipService, logger *zap.Logger) *PayslipHandler {
	return &PayslipHandler{
		payslipService: payslipService,
		logger:         logger.Named("payslip_handler"),
	}
}

type generatePayslipsRequest struct{}

type sendPayslipEmailRequest struct{}

type payslipRecordResponse struct {
	PayslipID    uuid.UUID `json:"payslip_id"`
	PayrollRunID uuid.UUID `json:"payroll_run_id"`
	UserID       uuid.UUID `json:"user_id"`
	GeneratedAt  time.Time `json:"generated_at"`
}

type listPayslipsResponse struct {
	Payslips []payslipRecordResponse `json:"payslips"`
	Total    int                     `json:"total,omitempty"`
}

// ----------------------------------------------------------------------
// Generate Payslips
// ----------------------------------------------------------------------

func (h *PayslipHandler) GeneratePayslipsForRun(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()

	companyID, err := parseUUIDParam(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	runID, err := parseUUIDParam(r, "runId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	actorID, err := h.getActorID(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req generatePayslipsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err.Error() != "EOF" {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.payslipService.GeneratePayslipsForRun(ctx, runID, actorID); err != nil {

		h.logger.Error("failed to generate payslips",
			zap.String("company_id", companyID.String()),
			zap.String("run_id", runID.String()),
			zap.Error(err),
		)

		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusAccepted, map[string]interface{}{
		"success": true,
		"message": "payslip generation started",
	})
}

// ----------------------------------------------------------------------
// Download Payslip
// ----------------------------------------------------------------------

func (h *PayslipHandler) DownloadPayslip(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()

	companyID, err := parseUUIDParam(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	runID, err := parseUUIDParam(r, "runId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	targetUserID, err := parseUUIDParam(r, "userId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	pdfData, err := h.payslipService.GetPayslip(ctx, targetUserID, runID)
	if err != nil {

		h.logger.Error("failed to get payslip",
			zap.String("company_id", companyID.String()),
			zap.String("run_id", runID.String()),
			zap.String("user_id", targetUserID.String()),
			zap.Error(err),
		)

		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	filename := fmt.Sprintf("payslip_%s_%s.pdf", runID.String()[:8], targetUserID.String()[:8])

	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pdfData)
}

// ----------------------------------------------------------------------
// Send Payslip Email
// ----------------------------------------------------------------------

func (h *PayslipHandler) SendPayslipEmail(w http.ResponseWriter, r *http.Request) {

	_ = r.Context()

	_, err := parseUUIDParam(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	runID, err := parseUUIDParam(r, "runId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	_, err = parseUUIDParam(r, "userId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req sendPayslipEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err.Error() != "EOF" {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	_ = runID

	h.respondWithError(
		w,
		http.StatusNotImplemented,
		"SendPayslipEmail requires a payslip ID endpoint (not implemented yet)",
	)
}

// ----------------------------------------------------------------------
// List Payslips
// ----------------------------------------------------------------------

func (h *PayslipHandler) ListUserPayslips(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()

	companyID, err := parseUUIDParam(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	targetUserID, err := parseUUIDParam(r, "userId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	from, err := parseTimeQuery(r, "from", time.Time{})
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	to, err := parseTimeQuery(r, "to", time.Time{})
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	records, err := h.payslipService.ListUserPayslips(ctx, companyID, targetUserID, from, to)
	if err != nil {

		h.logger.Error("failed to list payslips",
			zap.String("company_id", companyID.String()),
			zap.String("user_id", targetUserID.String()),
			zap.Error(err),
		)

		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := make([]payslipRecordResponse, 0, len(records))

	for _, r := range records {

		resp = append(resp, payslipRecordResponse{
			PayslipID:    r.PayslipID,
			PayrollRunID: r.PayrollRunID,
			UserID:       r.UserID,
			GeneratedAt:  r.GeneratedAt,
		})
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

func (h *PayslipHandler) getActorID(ctx context.Context) (uuid.UUID, error) {

	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok || userIDStr == "" {
		return uuid.Nil, errors.New("unauthenticated")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, errors.New("invalid user_id")
	}

	return userID, nil
}

func (h *PayslipHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(data)
}

func (h *PayslipHandler) respondWithError(w http.ResponseWriter, status int, message string) {

	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    status,
		"time":    time.Now().UTC(),
	})
}
