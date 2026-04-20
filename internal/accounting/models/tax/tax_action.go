// tax_action.go
package tax

import (
	"time"

	"github.com/google/uuid"
)

type TaxAction struct {
	ActionID         uuid.UUID `db:"action_id" json:"action_id"`
	TaxRuleID        uuid.UUID `db:"tax_rule_id" json:"tax_rule_id"`
	TaxRateID        uuid.UUID `db:"tax_rate_id" json:"tax_rate_id"`
	ActionType       string    `db:"action_type" json:"action_type"`             // apply_tax, exempt, reverse_charge
	CalculationBasis string    `db:"calculation_basis" json:"calculation_basis"` // line_amount, taxable_value
	CreatedAt        time.Time `db:"created_at" json:"created_at"`
}
