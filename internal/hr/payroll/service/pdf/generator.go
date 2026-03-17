package pdf

import (
	"bytes"
	"fmt"

	"auth-service/internal/hr/payroll/models"

	"github.com/go-pdf/fpdf"
)

type Generator struct{}

func NewGenerator() *Generator {
	return &Generator{}
}

// GeneratePayslipPDF implements payrollsvc.PDFGenerator interface
func (g *Generator) GeneratePayslipPDF(p *models.Payslip) ([]byte, error) {

	data := convertPayslip(p)

	return GeneratePayslip(data)
}

// convertPayslip converts service Payslip model → PayslipData used by renderer
func convertPayslip(p *models.Payslip) *models.PayslipData {

	return &models.PayslipData{
		CompanyID:    p.CompanyID,
		PayrollRunID: p.PayrollRunID,
		UserID:       p.UserID,

		PeriodStart: p.PeriodStart,
		PeriodEnd:   p.PeriodEnd,

		Earnings:   p.Earnings,
		Deductions: p.Deductions,

		GrossAmount: p.GrossAmount,
		NetAmount:   p.NetAmount,

		GeneratedAt: p.GeneratedAt,
	}
}

func GeneratePayslip(data *models.PayslipData) ([]byte, error) {

	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.AddPage()

	// Header
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(190, 10, data.CompanyName)
	pdf.Ln(12)

	// Title
	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(190, 10, "Payslip")
	pdf.Ln(10)

	// Employee Details
	pdf.SetFont("Arial", "", 11)
	pdf.Cell(40, 7, "Employee Name:")
	pdf.SetFont("Arial", "B", 11)
	pdf.Cell(100, 7, data.EmployeeName)
	pdf.Ln(7)

	pdf.SetFont("Arial", "", 11)
	pdf.Cell(40, 7, "Employee ID:")
	pdf.SetFont("Arial", "B", 11)
	pdf.Cell(100, 7, data.EmployeeID)
	pdf.Ln(7)

	pdf.SetFont("Arial", "", 11)
	pdf.Cell(40, 7, "Department:")
	pdf.SetFont("Arial", "B", 11)
	pdf.Cell(100, 7, data.Department)
	pdf.Ln(7)

	pdf.SetFont("Arial", "", 11)
	pdf.Cell(40, 7, "Position:")
	pdf.SetFont("Arial", "B", 11)
	pdf.Cell(100, 7, data.Position)
	pdf.Ln(10)

	// Period
	pdf.SetFont("Arial", "", 11)
	pdf.Cell(40, 7, "Pay Period:")
	periodStr := fmt.Sprintf("%s to %s",
		data.PeriodStart.Format("02 Jan 2006"),
		data.PeriodEnd.Format("02 Jan 2006"))

	pdf.SetFont("Arial", "B", 11)
	pdf.Cell(100, 7, periodStr)
	pdf.Ln(10)

	// Earnings
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(190, 8, "Earnings")
	pdf.Ln(8)

	pdf.SetFont("Arial", "B", 11)
	pdf.Cell(100, 7, "Component")
	pdf.Cell(50, 7, "Description")
	pdf.Cell(40, 7, "Amount")
	pdf.Ln(7)

	pdf.SetFont("Arial", "", 11)

	for _, e := range data.Earnings {
		pdf.Cell(100, 7, e.Code)
		pdf.Cell(50, 7, truncate(e.Description, 30))
		pdf.CellFormat(40, 7, fmt.Sprintf("%.2f", e.Amount), "", 0, "R", false, 0, "")
		pdf.Ln(7)
	}

	pdf.Ln(5)

	// Deductions
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(190, 8, "Deductions")
	pdf.Ln(8)

	pdf.SetFont("Arial", "B", 11)
	pdf.Cell(100, 7, "Component")
	pdf.Cell(50, 7, "Description")
	pdf.Cell(40, 7, "Amount")
	pdf.Ln(7)

	pdf.SetFont("Arial", "", 11)

	for _, d := range data.Deductions {
		pdf.Cell(100, 7, d.Code)
		pdf.Cell(50, 7, truncate(d.Description, 30))
		pdf.CellFormat(40, 7, fmt.Sprintf("%.2f", d.Amount), "", 0, "R", false, 0, "")
		pdf.Ln(7)
	}

	pdf.Ln(5)

	// Totals
	pdf.SetFont("Arial", "B", 11)

	pdf.Cell(150, 7, "Gross Amount:")
	pdf.CellFormat(40, 7, fmt.Sprintf("%.2f", data.GrossAmount), "", 0, "R", false, 0, "")
	pdf.Ln(7)

	pdf.Cell(150, 7, "Net Amount:")
	pdf.CellFormat(40, 7, fmt.Sprintf("%.2f", data.NetAmount), "", 0, "R", false, 0, "")
	pdf.Ln(10)

	// Bank details
	if data.BankDetails != nil {

		pdf.SetFont("Arial", "B", 11)
		pdf.Cell(190, 7, "Bank Details")
		pdf.Ln(7)

		pdf.SetFont("Arial", "", 11)
		pdf.Cell(40, 7, "Account Holder:")
		pdf.SetFont("Arial", "B", 11)
		pdf.Cell(150, 7, data.BankDetails.AccountHolder)
		pdf.Ln(7)

		pdf.SetFont("Arial", "", 11)
		pdf.Cell(40, 7, "Account Number:")
		pdf.SetFont("Arial", "B", 11)
		pdf.Cell(150, 7, data.BankDetails.AccountNumber)
		pdf.Ln(7)

		pdf.SetFont("Arial", "", 11)
		pdf.Cell(40, 7, "IFSC Code:")
		pdf.SetFont("Arial", "B", 11)
		pdf.Cell(150, 7, data.BankDetails.IFSCCode)
		pdf.Ln(7)

		pdf.SetFont("Arial", "", 11)
		pdf.Cell(40, 7, "Bank Name:")
		pdf.SetFont("Arial", "B", 11)
		pdf.Cell(150, 7, data.BankDetails.BankName)
		pdf.Ln(10)
	}

	// Footer
	if data.FooterDeclaration != "" {

		pdf.SetY(-40)

		pdf.SetFont("Arial", "I", 10)

		pdf.MultiCell(190, 5, data.FooterDeclaration, "", "L", false)

		pdf.Ln(5)
	}

	if data.AuthorizedSignatory != "" {

		pdf.SetFont("Arial", "B", 10)

		pdf.Cell(190, 5, "Authorized Signatory: "+data.AuthorizedSignatory)
	}

	var buf bytes.Buffer

	err := pdf.Output(&buf)
	if err != nil {
		return nil, fmt.Errorf("generate PDF: %w", err)
	}

	return buf.Bytes(), nil
}

func truncate(s string, max int) string {

	if len(s) <= max {
		return s
	}

	return s[:max-3] + "..."
}
