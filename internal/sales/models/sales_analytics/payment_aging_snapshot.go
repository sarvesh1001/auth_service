package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type PaymentAgingSnapshot struct {
	SnapshotID       int64           `gorm:"primaryKey;autoIncrement" json:"snapshotId"`
	CompanyID        uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_payment_aging_company_date,priority:1" json:"companyId"`
	SnapshotDate     time.Time       `gorm:"type:date;not null;uniqueIndex:idx_payment_aging_company_date,priority:2" json:"snapshotDate"`
	Bucket0_30Days   decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"bucket0_30Days"`
	Bucket31_60Days  decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"bucket31_60Days"`
	Bucket61_90Days  decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"bucket61_90Days"`
	BucketOver90Days decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"bucketOver90Days"`
	TotalUnallocated decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"totalUnallocated"`
	CreatedAt        time.Time       `gorm:"default:now()" json:"createdAt"`
}

func (PaymentAgingSnapshot) TableName() string {
	return "sales_analytics.payment_aging_snapshot"
}
