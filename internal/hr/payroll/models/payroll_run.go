package models

import (
	"time"

	"github.com/google/uuid"
)

type PayrollRun struct {
	PayrollRunID uuid.UUID  `json:"payroll_run_id" db:"payroll_run_id"`
	CompanyID    uuid.UUID  `json:"company_id" db:"company_id"`
	PeriodStart  time.Time  `json:"period_start" db:"period_start"`
	PeriodEnd    time.Time  `json:"period_end" db:"period_end"`
	Status       string     `json:"status" db:"status"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	CreatedBy    *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
}

type PayrollRunFilter struct {
	CompanyID   uuid.UUID
	Status      *string
	PeriodStart *time.Time
	PeriodEnd   *time.Time
	Page        int
	PageSize    int
}

type PayrollRunSummary struct {
	PayrollRunID    uuid.UUID `json:"payroll_run_id"`
	PeriodStart     time.Time `json:"period_start"`
	PeriodEnd       time.Time `json:"period_end"`
	Status          string    `json:"status"`
	TotalEmployees  int       `json:"total_employees"`
	TotalGross      float64   `json:"total_gross"`
	TotalNet        float64   `json:"total_net"`
	TotalDeductions float64   `json:"total_deductions"`
	CreatedAt       time.Time `json:"created_at"`
}
