package models

import (
	"time"

	"github.com/google/uuid"
)

type PayrollLedger struct {
	LedgerID      uuid.UUID `json:"ledger_id" db:"ledger_id"`
	PayrollItemID uuid.UUID `json:"payroll_item_id" db:"payroll_item_id"`
	ComponentCode string    `json:"component_code" db:"component_code"`
	Amount        float64   `json:"amount" db:"amount"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
}

type PayrollLedgerItem struct {
	ComponentCode string  `json:"component_code"`
	ComponentType string  `json:"component_type"`
	Description   string  `json:"description,omitempty"`
	Amount        float64 `json:"amount"`
	IsTaxable     bool    `json:"is_taxable"`
}

type LedgerSummary struct {
	ComponentCode string  `json:"component_code"`
	ComponentType string  `json:"component_type"`
	Description   string  `json:"description"`
	TotalAmount   float64 `json:"total_amount"`
	IsTaxable     bool    `json:"is_taxable"`
}
