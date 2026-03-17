package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/hr/payroll/service"
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

// generatePayslipsRequest is kept for compatibility, though unused in on‑demand mode.
type generatePayslipsRequest struct{}

// sendPayslipEmailRequest is kept for compatibility.
type sendPayslipEmailRequest struct{}

// payslipSummaryResponse represents a payroll run summary for a user.
type payslipSummaryResponse struct {
	PayrollRunID uuid.UUID `json:"payroll_run_id"`
	PeriodStart  time.Time `json:"period_start"`
	PeriodEnd    time.Time `json:"period_end"`
	Status       string    `json:"status"`
	TotalGross   float64   `json:"total_gross"`
	TotalNet     float64   `json:"total_net"`
}

// listPayslipsResponse is the response for listing payslips.
type listPayslipsResponse struct {
	Payslips []payslipSummaryResponse `json:"payslips"`
	Total    int                      `json:"total,omitempty"`
}

// GeneratePayslipsForRun initiates generation of payslips for a whole payroll run.
// In on‑demand mode this is not supported; returns 501 Not Implemented.
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

	_ = companyID
	_ = runID
	_ = actorID

	// Bulk generation is not implemented in on‑demand mode.
	h.respondWithError(w, http.StatusNotImplemented, "bulk generation not supported in on‑demand mode")
}

// DownloadPayslip generates and returns a PDF payslip for a specific employee and payroll run.
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

	// Get payslip PDF – generates on the fly.
	pdfData, err := h.payslipService.GetPayslip(ctx, targetUserID, runID)
	if err != nil {
		h.logger.Error("failed to get payslip",
			zap.String("company_id", companyID.String()),
			zap.String("run_id", runID.String()),
			zap.String("user_id", targetUserID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Build filename and serve PDF.
	filename := fmt.Sprintf("payslip_%s_%s.pdf", runID.String()[:8], targetUserID.String()[:8])
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pdfData)
}

// SendPayslipEmail is a placeholder for sending a payslip by email.
// Not implemented in this version.
func (h *PayslipHandler) SendPayslipEmail(w http.ResponseWriter, r *http.Request) {
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

	logger := h.logger.With(
		zap.String("handler", "SendPayslipEmail"),
		zap.String("company_id", companyID.String()),
		zap.String("run_id", runID.String()),
		zap.String("user_id", targetUserID.String()),
	)
	logger.Debug("received send payslip email request")

	err = h.payslipService.SendPayslipEmail(ctx, companyID, runID, targetUserID)
	if err != nil {
		logger.Error("failed to send payslip email", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	logger.Info("payslip email sent successfully")
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Payslip email sent successfully",
	})
}

// ListUserPayslips returns a list of payroll runs (payslip summaries) for a given user.
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

	// Fetch summaries from the service.
	summaries, err := h.payslipService.ListUserPayslipSummaries(ctx, companyID, targetUserID, from, to)
	if err != nil {
		h.logger.Error("failed to list payslip summaries",
			zap.String("company_id", companyID.String()),
			zap.String("user_id", targetUserID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Convert to response format.
	resp := make([]payslipSummaryResponse, 0, len(summaries))
	for _, s := range summaries {
		resp = append(resp, payslipSummaryResponse{
			PayrollRunID: s.PayrollRunID,
			PeriodStart:  s.PeriodStart,
			PeriodEnd:    s.PeriodEnd,
			Status:       s.Status,
			TotalGross:   s.TotalGross,
			TotalNet:     s.TotalNet,
		})
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// getActorID extracts the actor ID from the request context.
// It assumes the context value "user_id" is a string containing a UUID.
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

// respondWithJSON writes a JSON response.
func (h *PayslipHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// respondWithError writes a JSON error response.
func (h *PayslipHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    status,
		"time":    time.Now().UTC(),
	})
}

// parseUUIDParam extracts a UUID path parameter from the request.
