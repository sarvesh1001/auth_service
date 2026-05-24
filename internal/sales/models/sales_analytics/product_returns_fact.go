// file: internal/sales/models/sales_analytics/product_returns_fact.go
package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// ProductReturnsFact stores pre-aggregated return metrics per product per day.
type ProductReturnsFact struct {
	ID               int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID        uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_product_returns_company_product_date,priority:1" json:"companyId"`
	ProductID        uuid.UUID       `gorm:"type:uuid;not null;uniqueIndex:idx_product_returns_company_product_date,priority:2" json:"productId"`
	Date             time.Time       `gorm:"type:date;not null;uniqueIndex:idx_product_returns_company_product_date,priority:3" json:"date"`
	QuantityReturned decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"quantityReturned"`
	RefundAmount     decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"refundAmount"`
	UpdatedAt        time.Time       `gorm:"default:now()" json:"updatedAt"`
}

// TableName specifies the table name for GORM.
func (ProductReturnsFact) TableName() string {
	return "sales_analytics.product_returns_fact"
}
