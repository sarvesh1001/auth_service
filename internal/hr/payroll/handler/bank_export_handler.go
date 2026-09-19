package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/service"
)

type BankExportHandler struct {
	bankService service.BankExportService
}

func NewBankExportHandler(bankService service.BankExportService) *BankExportHandler {
	return &BankExportHandler{
		bankService: bankService,
	}
}

// ----- helpers -----

func (h *BankExportHandler) getActor(ctx context.Context) (uuid.UUID, error) {
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok || userIDStr == "" {
		return uuid.Nil, errors.New("unauthenticated user")
	}
	return uuid.Parse(userIDStr)
}

// ----- handlers -----

func (h *BankExportHandler) CreateBankDetails(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

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
		if mapPayrollLocationError(w, err) {
			return
		}
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    req,
	})
}

func (h *BankExportHandler) UpdateBankDetails(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

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
		if mapPayrollLocationError(w, err) {
			return
		}
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
	})
}

func (h *BankExportHandler) DeactivateBankDetails(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

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
		if mapPayrollLocationError(w, err) {
			return
		}
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
	})
}

func (h *BankExportHandler) ActivateBankDetails(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

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
		if mapPayrollLocationError(w, err) {
			return
		}
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
	})
}

func (h *BankExportHandler) GetActiveBankDetails(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

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
		if mapPayrollLocationError(w, err) {
			return
		}
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    bank,
	})
}

func (h *BankExportHandler) ListUserBankDetails(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

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
		if mapPayrollLocationError(w, err) {
			return
		}
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    list,
	})
}

func (h *BankExportHandler) GenerateBankFile(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

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
		if mapPayrollLocationError(w, err) {
			return
		}
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// ----- response helpers -----

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
