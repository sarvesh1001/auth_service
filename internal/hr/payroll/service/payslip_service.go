package service

import (
	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/hr/payroll/repository"
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jung-kurt/gofpdf"
)

type PayslipService interface {
	GeneratePayslipJSON(ctx context.Context, payrollItemID uuid.UUID) (*models.Payslip, error)
	GeneratePayslipPDF(ctx context.Context, payrollItemID uuid.UUID) ([]byte, error)
}

type payslipService struct {
	repo repository.PayrollRepository
}

func NewPayslipService(repo repository.PayrollRepository) PayslipService {
	return &payslipService{repo: repo}
}

func (s *payslipService) GeneratePayslipJSON(
	ctx context.Context,
	payrollItemID uuid.UUID,
) (*models.Payslip, error) {

	detail, err := s.repo.GetPayrollItemDetail(ctx, payrollItemID)
	if err != nil || detail == nil {
		return nil, fmt.Errorf("payroll item not found")
	}

	run, err := s.repo.GetPayrollRunByID(ctx, detail.PayrollRunID)
	if err != nil || run == nil {
		return nil, fmt.Errorf("payroll run not found")
	}

	var earnings, deductions []models.PayslipComponent
	var totalTax float64

	for _, c := range detail.Components {
		comp := models.PayslipComponent{
			Code:        c.ComponentCode,
			Description: c.Description,
			Amount:      c.Amount,
		}

		if c.ComponentType == models.ComponentTypeEarning {
			earnings = append(earnings, comp)
		} else {
			deductions = append(deductions, comp)
			if c.IsTaxable {
				totalTax += c.Amount
			}
		}
	}

	return &models.Payslip{
		PayslipID:    uuid.New(),
		CompanyID:    run.CompanyID,
		UserID:       detail.UserID,
		PayrollRunID: run.PayrollRunID,
		PeriodStart:  run.PeriodStart,
		PeriodEnd:    run.PeriodEnd,
		Earnings:     earnings,
		Deductions:   deductions,
		GrossAmount:  detail.GrossAmount,
		TotalTax:     totalTax,
		NetAmount:    detail.NetAmount,
		GeneratedAt:  time.Now().UTC(),
	}, nil
}

func (s *payslipService) GeneratePayslipPDF(
	ctx context.Context,
	payrollItemID uuid.UUID,
) ([]byte, error) {

	payslip, err := s.GeneratePayslipJSON(ctx, payrollItemID)
	if err != nil {
		return nil, err
	}

	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()

	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(40, 10, "Payslip")
	pdf.Ln(12)

	pdf.SetFont("Arial", "", 11)
	pdf.Cell(0, 8, fmt.Sprintf("Period: %s to %s",
		payslip.PeriodStart.Format("02 Jan 2006"),
		payslip.PeriodEnd.Format("02 Jan 2006")))
	pdf.Ln(10)

	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(0, 8, "Earnings")
	pdf.Ln(8)

	pdf.SetFont("Arial", "", 10)
	for _, e := range payslip.Earnings {
		pdf.CellFormat(120, 7, e.Description, "", 0, "", false, 0, "")
		pdf.CellFormat(40, 7, fmt.Sprintf("%.2f", e.Amount), "", 1, "R", false, 0, "")
	}

	pdf.Ln(5)
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(0, 8, "Deductions")
	pdf.Ln(8)

	pdf.SetFont("Arial", "", 10)
	for _, d := range payslip.Deductions {
		pdf.CellFormat(120, 7, d.Description, "", 0, "", false, 0, "")
		pdf.CellFormat(40, 7, fmt.Sprintf("%.2f", d.Amount), "", 1, "R", false, 0, "")
	}

	pdf.Ln(8)
	pdf.SetFont("Arial", "B", 11)
	pdf.Cell(120, 7, "Net Pay")
	pdf.CellFormat(40, 7, fmt.Sprintf("%.2f", payslip.NetAmount), "", 1, "R", false, 0, "")

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
