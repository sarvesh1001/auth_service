package handler

import (
	"auth-service/internal/hr/payroll/service"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type PayslipHandler struct {
	service service.PayslipService
}

func NewPayslipHandler(service service.PayslipService) *PayslipHandler {
	return &PayslipHandler{service: service}
}

func (h *PayslipHandler) GetPayslipJSON(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	itemID, _ := uuid.Parse(chi.URLParam(r, "payrollItemID"))

	payslip, err := h.service.GeneratePayslipJSON(ctx, itemID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	writeJSON(w, http.StatusOK, payslip)
}

func (h *PayslipHandler) DownloadPayslipPDF(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	itemID, _ := uuid.Parse(chi.URLParam(r, "payrollItemID"))

	pdf, err := h.service.GeneratePayslipPDF(ctx, itemID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", "attachment; filename=payslip.pdf")
	w.Write(pdf)
}
