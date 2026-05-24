package sales_analytics

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// ProductSalesFact stores daily product-level sales for analytics (fact table).
type ProductSalesFact struct {
	ID              int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID       uuid.UUID       `gorm:"type:uuid;not null;index:idx_product_sales_company_date" json:"companyId"`
	ProductID       uuid.UUID       `gorm:"type:uuid;not null" json:"productId"`
	Date            time.Time       `gorm:"type:date;not null;index:idx_product_sales_company_date" json:"date"`
	QuantitySold    decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"quantitySold"`
	Revenue         decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"revenue"`
	DiscountApplied decimal.Decimal `gorm:"type:numeric(14,4);default:0" json:"discountApplied"`
	UpdatedAt       time.Time       `gorm:"default:now()" json:"updatedAt"`
}

func (ProductSalesFact) TableName() string {
	return "sales_analytics.product_sales_fact"
}
