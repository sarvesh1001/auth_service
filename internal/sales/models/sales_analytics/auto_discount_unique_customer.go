package sales_analytics

import (
	"time"

	"github.com/google/uuid"
)

// AutoDiscountUniqueCustomer tracks unique customers per automatic discount per day.
// This is a bridge table used to deduplicate customers for daily metrics.
type AutoDiscountUniqueCustomer struct {
	CompanyID      uuid.UUID `gorm:"type:uuid;not null;primaryKey" json:"companyId"`
	AutoDiscountID uuid.UUID `gorm:"type:uuid;not null;primaryKey" json:"autoDiscountId"`
	Date           time.Time `gorm:"type:date;not null;primaryKey" json:"date"`
	CustomerID     uuid.UUID `gorm:"type:uuid;not null;primaryKey" json:"customerId"`
}

// TableName specifies the table name for GORM.
func (AutoDiscountUniqueCustomer) TableName() string {
	return "sales_analytics.auto_discount_unique_customers"
}
