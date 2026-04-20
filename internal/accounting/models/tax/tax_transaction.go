package tax

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type TaxTransaction struct {
	TaxTransactionID   uuid.UUID       `db:"tax_transaction_id" json:"tax_transaction_id"`
	CompanyID          uuid.UUID       `db:"company_id" json:"company_id"`
	TransactionType    string          `db:"transaction_type" json:"transaction_type"` // invoice, payment, journal
	TransactionID      uuid.UUID       `db:"transaction_id" json:"transaction_id"`
	TaxRuleID          *uuid.UUID      `db:"tax_rule_id" json:"tax_rule_id,omitempty"`
	TaxRateID          *uuid.UUID      `db:"tax_rate_id" json:"tax_rate_id,omitempty"`
	TaxableAmount      decimal.Decimal `db:"taxable_amount" json:"taxable_amount"`
	TaxAmount          decimal.Decimal `db:"tax_amount" json:"tax_amount"`
	Currency           string          `db:"currency" json:"currency"`
	ExchangeRate       decimal.Decimal `db:"exchange_rate" json:"exchange_rate"`
	BaseCurrencyAmount decimal.Decimal `db:"base_currency_amount" json:"base_currency_amount"` // generated column
	TransactionDate    time.Time       `db:"transaction_date" json:"transaction_date"`
	CreatedAt          time.Time       `db:"created_at" json:"created_at"`
}
