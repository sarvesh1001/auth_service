package analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type DailyAccountSummary struct {
	SummaryID        uuid.UUID       `db:"summary_id" json:"summary_id"`
	CompanyID        uuid.UUID       `db:"company_id" json:"company_id"`
	AccountID        uuid.UUID       `db:"account_id" json:"account_id"`
	Date             time.Time       `db:"date" json:"date"`
	TotalDebit       decimal.Decimal `db:"total_debit" json:"total_debit"`
	TotalCredit      decimal.Decimal `db:"total_credit" json:"total_credit"`
	NetMovement      decimal.Decimal `db:"net_movement" json:"net_movement"` // generated
	TransactionCount int             `db:"transaction_count" json:"transaction_count"`
	CreatedAt        time.Time       `db:"created_at" json:"created_at"`
}
