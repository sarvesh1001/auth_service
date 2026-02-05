package models

import (
	"time"

	"github.com/google/uuid"
)

type PayrollSnapshot struct {
	SnapshotID   uuid.UUID `json:"snapshot_id"`
	PayrollRunID uuid.UUID `json:"payroll_run_id"`
	CompanyID    uuid.UUID `json:"company_id"`
	SnapshotType string    `json:"snapshot_type"` // draft, approved, paid
	SnapshotData []byte    `json:"snapshot_data"` // JSONB data
	CreatedAt    time.Time `json:"created_at"`
	CreatedBy    uuid.UUID `json:"created_by"`
}

type PayrollSummary struct {
	PayrollRunID    uuid.UUID `json:"payroll_run_id"`
	PeriodStart     time.Time `json:"period_start"`
	PeriodEnd       time.Time `json:"period_end"`
	TotalEmployees  int       `json:"total_employees"`
	TotalGross      float64   `json:"total_gross"`
	TotalNet        float64   `json:"total_net"`
	TotalTax        float64   `json:"total_tax"`
	TotalDeductions float64   `json:"total_deductions"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"created_at"`
}
