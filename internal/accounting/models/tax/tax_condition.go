package tax

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type TaxCondition struct {
	ConditionID  uuid.UUID        `db:"condition_id" json:"condition_id"`
	TaxRuleID    uuid.UUID        `db:"tax_rule_id" json:"tax_rule_id"`
	FieldName    string           `db:"field_name" json:"field_name"`
	Operator     string           `db:"operator" json:"operator"`
	ValueText    *string          `db:"value_text" json:"value_text,omitempty"`
	ValueNumeric *decimal.Decimal `db:"value_numeric" json:"value_numeric,omitempty"` // changed to decimal
	CreatedAt    time.Time        `db:"created_at" json:"created_at"`
}
