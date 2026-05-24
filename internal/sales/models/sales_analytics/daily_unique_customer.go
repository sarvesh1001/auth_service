package sales_analytics

import (
	"time"

	"github.com/google/uuid"
)

// DailyUniqueCustomer tracks which customers made a purchase on a given day.
// It prevents double‑counting unique customers in the daily_sales aggregate.
type DailyUniqueCustomer struct {
	CompanyID  uuid.UUID `gorm:"type:uuid;primaryKey"`
	Date       time.Time `gorm:"type:date;primaryKey"`
	CustomerID uuid.UUID `gorm:"type:uuid;primaryKey"`
}

// TableName returns the full table name including schema.
func (DailyUniqueCustomer) TableName() string {
	return "sales_analytics.daily_unique_customers"
}
