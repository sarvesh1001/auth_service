package models

import (
	"time"

	"github.com/google/uuid"
)

type TaxRule struct {
	TaxRuleID       uuid.UUID `json:"tax_rule_id" db:"tax_rule_id"`
	TaxProfileID    uuid.UUID `json:"tax_profile_id" db:"tax_profile_id"`
	ComponentCode   string    `json:"component_code" db:"component_code"`
	CalculationType string    `json:"calculation_type" db:"calculation_type"`
	Value           *float64  `json:"value,omitempty" db:"value"`
	Formula         *string   `json:"formula,omitempty" db:"formula"`
	MinAmount       *float64  `json:"min_amount,omitempty" db:"min_amount"`
	MaxAmount       *float64  `json:"max_amount,omitempty" db:"max_amount"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
}

type CalculatedTax struct {
	ComponentCode string  `json:"component_code"`
	Amount        float64 `json:"amount"`
	TaxAmount     float64 `json:"tax_amount"`
	AppliedRule   string  `json:"applied_rule"`
}
