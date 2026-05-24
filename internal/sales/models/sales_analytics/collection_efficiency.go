package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type CollectionEfficiency struct {
	ID                   int64            `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID            uuid.UUID        `gorm:"type:uuid;not null;uniqueIndex:idx_collection_efficiency_company_date,priority:1" json:"companyId"`
	Date                 time.Time        `gorm:"type:date;not null;uniqueIndex:idx_collection_efficiency_company_date,priority:2" json:"date"`
	DaysSalesOutstanding *decimal.Decimal `gorm:"type:numeric(10,2)" json:"daysSalesOutstanding,omitempty"`
	CollectionRate       *decimal.Decimal `gorm:"type:numeric(5,2)" json:"collectionRate,omitempty"`
	TotalReceivables     decimal.Decimal  `gorm:"type:numeric(14,4);default:0" json:"totalReceivables"`
	CollectedAmount      decimal.Decimal  `gorm:"type:numeric(14,4);default:0" json:"collectedAmount"`
	UpdatedAt            time.Time        `gorm:"default:now()" json:"updatedAt"`
}

func (CollectionEfficiency) TableName() string {
	return "sales_analytics.collection_efficiency"
}
