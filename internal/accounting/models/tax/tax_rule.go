package tax

import (
	"time"

	"github.com/google/uuid"
)

type TaxRule struct {
	TaxRuleID uuid.UUID  `db:"tax_rule_id" json:"tax_rule_id"`
	CompanyID uuid.UUID  `db:"company_id" json:"company_id"`
	RuleName  string     `db:"rule_name" json:"rule_name"`
	AppliesTo string     `db:"applies_to" json:"applies_to"` // sales, purchase, both
	Priority  int        `db:"priority" json:"priority"`
	IsActive  bool       `db:"is_active" json:"is_active"`
	CreatedAt time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt time.Time  `db:"updated_at" json:"updated_at"`
	CreatedBy *uuid.UUID `db:"created_by" json:"created_by,omitempty"`
	UpdatedBy *uuid.UUID `db:"updated_by" json:"updated_by,omitempty"`
	DeletedAt *time.Time `db:"deleted_at" json:"deleted_at,omitempty"`
}

type TaxRuleVersion struct {
	VersionID uuid.UUID  `db:"version_id" json:"version_id"`
	TaxRuleID uuid.UUID  `db:"tax_rule_id" json:"tax_rule_id"`
	Version   int        `db:"version" json:"version"`
	RuleJSON  []byte     `db:"rule_json" json:"rule_json"` // JSONB
	IsCurrent bool       `db:"is_current" json:"is_current"`
	CreatedAt time.Time  `db:"created_at" json:"created_at"`
	CreatedBy *uuid.UUID `db:"created_by" json:"created_by,omitempty"`
}
