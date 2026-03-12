package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"auth-service/internal/hr/payroll/service"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type BankExportHandler struct {
	bankService service.BankExportService
	logger      *zap.Logger
}

func NewBankExportHandler(
	bankService service.BankExportService,
	logger *zap.Logger,
) *BankExportHandler {
	return &BankExportHandler{
		bankService: bankService,
		logger:      logger.Named("bank_export_handler"),
	}
}

// GenerateBankFile handles POST /companies/{companyID}/payroll-runs/{runID}/bank-export?format={format}
// It returns a CSV file with the bank transfer instructions.
func (h *BankExportHandler) GenerateBankFile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse path parameters
	companyID, err := parseUUIDParam(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	payrollRunID, err := parseUUIDParam(r, "runID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Get format from query parameter
	format := r.URL.Query().Get("format")
	if format == "" {
		h.respondWithError(w, http.StatusBadRequest, "format query parameter is required")
		return
	}

	// Validate allowed formats
	allowedFormats := map[string]bool{
		"generic": true,
		"hdfc":    true,
		"icici":   true,
	}
	if !allowedFormats[format] {
		h.respondWithError(w, http.StatusBadRequest, "unsupported format; must be one of: generic, hdfc, icici")
		return
	}

	// Extract actor ID from context (assumes authenticated user)
	actorID, err := h.getActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Call the service
	data, filename, err := h.bankService.GenerateBankFile(ctx, companyID, payrollRunID, format)
	if err != nil {
		h.logger.Error("failed to generate bank file",
			zap.Error(err),
			zap.String("company_id", companyID.String()),
			zap.String("payroll_run_id", payrollRunID.String()),
			zap.String("format", format),
			zap.String("actor_id", actorID.String()),
		)

		// Map common errors to HTTP status codes
		switch {
		case strings.Contains(err.Error(), "not found"):
			h.respondWithError(w, http.StatusNotFound, err.Error())
		case strings.Contains(err.Error(), "must be approved"):
			h.respondWithError(w, http.StatusConflict, err.Error())
		default:
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	// Serve the file as an attachment
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// getActor extracts the authenticated user ID from the request context.
func (h *BankExportHandler) getActor(ctx context.Context) (uuid.UUID, error) {
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

// respondWithError sends a JSON error response.
func (h *BankExportHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    status,
		"time":    time.Now().UTC(),
	})
}

// parseUUIDParam extracts and parses a UUID path parameter.
