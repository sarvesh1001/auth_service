package events

import "time"

// Tax event types
const (
	EventTaxCalculated         = "tax.calculated"
	EventTaxTransactionCreated = "tax.transaction.created"
	EventTaxRateChanged        = "tax.rate.changed"
	EventTaxRuleApplied        = "tax.rule.applied"
	EventTaxProfileCreated     = "tax.profile.created"
	EventTaxProfileUpdated     = "tax.profile.updated"
	EventTaxRateCreated        = "tax.rate.created"
	EventTaxRateUpdated        = "tax.rate.updated"
	EventTaxRuleCreated        = "tax.rule.created"
	EventTaxRuleUpdated        = "tax.rule.updated"
)

// TaxCalculatedPayload carries the result of tax calculation
type TaxCalculatedPayload struct {
	TransactionID   string    `json:"transaction_id"`
	TransactionType string    `json:"transaction_type"`
	CompanyID       string    `json:"company_id"`
	TaxableAmount   string    `json:"taxable_amount"`
	TaxAmount       string    `json:"tax_amount"`
	Currency        string    `json:"currency"`
	ExchangeRate    string    `json:"exchange_rate"`
	BaseAmount      string    `json:"base_amount"`
	TransactionDate time.Time `json:"transaction_date"`
	TaxRateID       string    `json:"tax_rate_id,omitempty"`
	TaxRuleID       string    `json:"tax_rule_id,omitempty"`
}

// TaxTransactionPayload for storing tax transaction
type TaxTransactionPayload struct {
	TaxTransactionID string    `json:"tax_transaction_id"`
	CompanyID        string    `json:"company_id"`
	TransactionType  string    `json:"transaction_type"`
	TransactionID    string    `json:"transaction_id"`
	TaxableAmount    string    `json:"taxable_amount"`
	TaxAmount        string    `json:"tax_amount"`
	TransactionDate  time.Time `json:"transaction_date"`
}

type TaxProfilePayload struct {
	ProfileID    string `json:"profile_id"`
	CompanyID    string `json:"company_id"`
	TaxRegime    string `json:"tax_regime"`
	Jurisdiction string `json:"jurisdiction"`
	IsActive     bool   `json:"is_active"`
}

type TaxRatePayload struct {
	RateID         string     `json:"rate_id"`
	CompanyID      string     `json:"company_id"`
	TaxName        string     `json:"tax_name"`
	RatePercentage string     `json:"rate_percentage"`
	EffectiveFrom  time.Time  `json:"effective_from"`
	EffectiveTo    *time.Time `json:"effective_to,omitempty"`
	IsActive       bool       `json:"is_active"`
}

type TaxRulePayload struct {
	RuleID    string `json:"rule_id"`
	CompanyID string `json:"company_id"`
	RuleName  string `json:"rule_name"`
	AppliesTo string `json:"applies_to"`
	Priority  int    `json:"priority"`
	IsActive  bool   `json:"is_active"`
	Version   int    `json:"version"`
}
