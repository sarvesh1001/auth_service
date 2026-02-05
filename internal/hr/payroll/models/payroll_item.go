package models

import (
	"time"

	"github.com/google/uuid"
)

type PayrollItem struct {
	PayrollItemID uuid.UUID `json:"payroll_item_id" db:"payroll_item_id"`
	PayrollRunID  uuid.UUID `json:"payroll_run_id" db:"payroll_run_id"`
	UserID        uuid.UUID `json:"user_id" db:"user_id"`
	PayableDays   float64   `json:"payable_days" db:"payable_days"`
	UnpaidDays    float64   `json:"unpaid_days" db:"unpaid_days"`
	GrossAmount   float64   `json:"gross_amount" db:"gross_amount"`
	NetAmount     float64   `json:"net_amount" db:"net_amount"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
}

type PayrollItemDetail struct {
	PayrollItem
	Username       string              `json:"username"`
	FullName       string              `json:"full_name"`
	EmployeeID     string              `json:"employee_id"`
	PositionTitle  *string             `json:"position_title,omitempty"`
	DepartmentName *string             `json:"department_name,omitempty"`
	Components     []PayrollLedgerItem `json:"components"`
}
