package models

import (
	"time"

	"github.com/google/uuid"
)

type Payslip struct {
	PayslipID    uuid.UUID `json:"payslip_id"`
	CompanyID    uuid.UUID `json:"company_id"`
	UserID       uuid.UUID `json:"user_id"`
	PayrollRunID uuid.UUID `json:"payroll_run_id"`

	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`

	Earnings   []PayslipComponent `json:"earnings"`
	Deductions []PayslipComponent `json:"deductions"`

	GrossAmount float64 `json:"gross_amount"`
	TotalTax    float64 `json:"total_tax"`
	NetAmount   float64 `json:"net_amount"`

	GeneratedAt time.Time `json:"generated_at"`
}

type PayslipComponent struct {
	Code        string  `json:"code"`
	Description string  `json:"description"`
	Amount      float64 `json:"amount"`
}
