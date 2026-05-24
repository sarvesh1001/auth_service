// FILE: internal/sales/models/sales_analytics/invoice_aging_snapshot.go

package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type InvoiceAgingSnapshot struct {
	SnapshotID       int64           `gorm:"primaryKey;autoIncrement" json:"snapshotId"`
	CompanyID        uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_invoice_aging_snapshot_company_date" json:"companyId"`
	SnapshotDate     time.Time       `gorm:"type:date;not null;uniqueIndex:idx_invoice_aging_snapshot_company_date" json:"snapshotDate"`
	Bucket0_30Days   decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"bucket0_30Days"`
	Bucket31_60Days  decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"bucket31_60Days"`
	Bucket61_90Days  decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"bucket61_90Days"`
	BucketOver90Days decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"bucketOver90Days"`
	TotalOutstanding decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"totalOutstanding"`
	CreatedAt        time.Time       `gorm:"default:now()" json:"createdAt"`
}

func (InvoiceAgingSnapshot) TableName() string {
	return "sales_analytics.invoice_aging_snapshot"
}
