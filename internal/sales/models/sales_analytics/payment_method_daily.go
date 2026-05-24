package sales_analytics

import (
	"auth-service/internal/sales/models/enums"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type PaymentMethodDaily struct {
	ID            int64               `gorm:"primaryKey;autoIncrement" json:"id"`
	CompanyID     uuid.UUID           `gorm:"type:uuid;not null;uniqueIndex:idx_payment_method_daily_company_date_method,priority:1" json:"companyId"`
	Date          time.Time           `gorm:"type:date;not null;uniqueIndex:idx_payment_method_daily_company_date_method,priority:2" json:"date"`
	PaymentMethod enums.PaymentMethod `gorm:"type:sales.payment_method;not null;uniqueIndex:idx_payment_method_daily_company_date_method,priority:3" json:"paymentMethod"`
	PaymentCount  int                 `gorm:"default:0" json:"paymentCount"`
	TotalAmount   decimal.Decimal     `gorm:"type:numeric(14,4);default:0" json:"totalAmount"`
	AverageAmount decimal.Decimal     `gorm:"->" json:"averageAmount"`
	UpdatedAt     time.Time           `gorm:"default:now()" json:"updatedAt"`
}

func (PaymentMethodDaily) TableName() string {
	return "sales_analytics.payment_method_daily"
}
