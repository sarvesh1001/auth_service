package analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type Cashflow struct {
	CashflowID  uuid.UUID       `db:"cashflow_id" json:"cashflow_id"`
	CompanyID   uuid.UUID       `db:"company_id" json:"company_id"`
	Date        time.Time       `db:"date" json:"date"`
	Inflow      decimal.Decimal `db:"inflow" json:"inflow"`
	Outflow     decimal.Decimal `db:"outflow" json:"outflow"`
	NetCashflow decimal.Decimal `db:"net_cashflow" json:"net_cashflow"` // generated
	CreatedAt   time.Time       `db:"created_at" json:"created_at"`
}
