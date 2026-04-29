package compliance

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type ComplianceReturn struct {
	ReturnID       uuid.UUID       `db:"return_id" json:"return_id"`
	CompanyID      uuid.UUID       `db:"company_id" json:"company_id"`
	ReturnType     string          `db:"return_type" json:"return_type"`
	PeriodStart    time.Time       `db:"period_start" json:"period_start"`
	PeriodEnd      time.Time       `db:"period_end" json:"period_end"`
	DueDate        time.Time       `db:"due_date" json:"due_date"`
	FilingDate     *time.Time      `db:"filing_date" json:"filing_date,omitempty"`
	Status         string          `db:"status" json:"status"`
	TotalLiability decimal.Decimal `db:"total_liability" json:"total_liability"`
	TotalPaid      decimal.Decimal `db:"total_paid" json:"total_paid"`
	IsLocked       bool            `db:"is_locked" json:"is_locked"`
	CreatedAt      time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt      time.Time       `db:"updated_at" json:"updated_at"`
	CreatedBy      *uuid.UUID      `db:"created_by" json:"created_by,omitempty"`
	UpdatedBy      *uuid.UUID      `db:"updated_by" json:"updated_by,omitempty"`
	FiledBy        *uuid.UUID      `db:"filed_by" json:"filed_by,omitempty"`
	FiledAt        *time.Time      `db:"filed_at" json:"filed_at,omitempty"`
	DeletedAt      *time.Time      `db:"deleted_at" json:"deleted_at,omitempty"`
	AmendedFrom    *uuid.UUID      `db:"amended_from" json:"amended_from,omitempty"`
}
