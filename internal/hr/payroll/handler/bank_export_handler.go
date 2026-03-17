package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"auth-service/internal/hr/payroll/models"
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

///////////////////////////////////////////////////////////////
//////////////////// CREATE BANK DETAILS //////////////////////
///////////////////////////////////////////////////////////////

func (h *BankExportHandler) CreateBankDetails(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()

	companyID, err := parseUUIDParam(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := parseUUIDParam(r, "userID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.EmployeeBankDetails

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.CompanyID = companyID
	req.UserID = userID

	err = h.bankService.CreateBankDetails(ctx, &req)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    req,
	})
}

///////////////////////////////////////////////////////////////
//////////////////// UPDATE BANK DETAILS //////////////////////
///////////////////////////////////////////////////////////////

func (h *BankExportHandler) UpdateBankDetails(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()

	bankDetailID, err := parseUUIDParam(r, "bankDetailID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req models.EmployeeBankDetails

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.BankDetailID = bankDetailID

	err = h.bankService.UpdateBankDetails(ctx, &req)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
	})
}

///////////////////////////////////////////////////////////////
//////////////////// DEACTIVATE BANK DETAILS //////////////////
///////////////////////////////////////////////////////////////

func (h *BankExportHandler) DeactivateBankDetails(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()

	bankDetailID, err := parseUUIDParam(r, "bankDetailID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	actorID, err := h.getActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	err = h.bankService.DeactivateBankDetails(ctx, bankDetailID, actorID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
	})
}

///////////////////////////////////////////////////////////////
//////////////////// GET ACTIVE BANK DETAILS //////////////////
///////////////////////////////////////////////////////////////

func (h *BankExportHandler) GetActiveBankDetails(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()

	companyID, err := parseUUIDParam(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := parseUUIDParam(r, "userID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	asOf := time.Now().UTC()

	bank, err := h.bankService.GetActiveBankDetails(ctx, companyID, userID, asOf)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    bank,
	})
}

///////////////////////////////////////////////////////////////
//////////////////// LIST USER BANK DETAILS ///////////////////
///////////////////////////////////////////////////////////////

func (h *BankExportHandler) ListUserBankDetails(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()

	companyID, err := parseUUIDParam(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, err := parseUUIDParam(r, "userID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	list, err := h.bankService.ListUserBankDetails(ctx, companyID, userID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    list,
	})
}

///////////////////////////////////////////////////////////////
//////////////////// BANK EXPORT (existing) ///////////////////
///////////////////////////////////////////////////////////////

func (h *BankExportHandler) GenerateBankFile(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()

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

	format := r.URL.Query().Get("format")

	if format == "" {
		h.respondWithError(w, http.StatusBadRequest, "format query parameter required")
		return
	}

	data, filename, err := h.bankService.GenerateBankFile(ctx, companyID, payrollRunID, format)
	if err != nil {

		h.logger.Error("failed to generate bank file",
			zap.Error(err),
			zap.String("company_id", companyID.String()),
			zap.String("payroll_run_id", payrollRunID.String()),
		)

		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

///////////////////////////////////////////////////////////////
//////////////////// COMMON HELPERS ///////////////////////////
///////////////////////////////////////////////////////////////

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

func (h *BankExportHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(data)
}

func (h *BankExportHandler) respondWithError(w http.ResponseWriter, status int, message string) {

	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    status,
		"time":    time.Now().UTC(),
	})
}
func (h *BankExportHandler) ActivateBankDetails(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()

	bankDetailID, err := parseUUIDParam(r, "bankDetailID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	actorID, err := h.getActor(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	err = h.bankService.ActivateBankDetails(ctx, bankDetailID, actorID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
	})
}
