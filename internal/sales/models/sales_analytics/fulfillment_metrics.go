// file: internal/sales/models/sales_analytics/fulfillment_metrics.go
package sales_analytics

import (
	"time"

	"github.com/google/uuid"
)

// FulfillmentMetrics tracks shipping and delivery performance per order.
type FulfillmentMetrics struct {
	ID                      int64      `gorm:"primaryKey;autoIncrement" json:"id"`
	OrderID                 uuid.UUID  `gorm:"type:uuid;not null;uniqueIndex" json:"orderId"`
	CompanyID               uuid.UUID  `gorm:"type:uuid;not null" json:"companyId"`
	ConfirmedAt             *time.Time `gorm:"type:timestamptz" json:"confirmedAt,omitempty"`
	ShippedAt               *time.Time `gorm:"type:timestamptz" json:"shippedAt,omitempty"`
	DeliveredAt             *time.Time `gorm:"type:timestamptz" json:"deliveredAt,omitempty"`
	ConfirmationToShipHours float64    `gorm:"->" json:"confirmationToShipHours"` // generated
	ShipToDeliveryHours     float64    `gorm:"->" json:"shipToDeliveryHours"`     // generated
	Carrier                 *string    `gorm:"type:varchar(100)" json:"carrier,omitempty"`
	TrackingNumber          *string    `gorm:"type:varchar(100)" json:"trackingNumber,omitempty"`
	ShippingAddressRegion   *string    `gorm:"type:varchar(100)" json:"shippingAddressRegion,omitempty"`
	CreatedAt               time.Time  `gorm:"default:now()" json:"createdAt"`
}

func (FulfillmentMetrics) TableName() string {
	return "sales_analytics.fulfillment_metrics"
}
