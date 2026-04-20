package analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type AccountSnapshot struct {
	SnapshotID   uuid.UUID       `db:"snapshot_id" json:"snapshot_id"`
	CompanyID    uuid.UUID       `db:"company_id" json:"company_id"`
	AccountID    uuid.UUID       `db:"account_id" json:"account_id"`
	SnapshotDate time.Time       `db:"snapshot_date" json:"snapshot_date"`
	Balance      decimal.Decimal `db:"balance" json:"balance"`
	FiscalYear   *int            `db:"fiscal_year" json:"fiscal_year,omitempty"`
	Period       *int            `db:"period" json:"period,omitempty"`
	CreatedAt    time.Time       `db:"created_at" json:"created_at"`
}
