package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// PaymentAllocationFact records the allocation of a payment amount to a specific invoice.
// Used for analytics (e.g., time from payment to allocation, total allocated per day).
type PaymentAllocationFact struct {
	CompanyID       uuid.UUID       `db:"company_id"`
	PaymentID       uuid.UUID       `db:"payment_id"`
	InvoiceID       uuid.UUID       `db:"invoice_id"`
	AllocatedAmount decimal.Decimal `db:"allocated_amount"`
	AllocatedAt     time.Time       `db:"allocated_at"`
}
