package enums

type OrderStatus string

const (
	OrderStatusDraft      OrderStatus = "draft"
	OrderStatusConfirmed  OrderStatus = "confirmed"
	OrderStatusProcessing OrderStatus = "processing"
	OrderStatusShipped    OrderStatus = "shipped"
	OrderStatusDelivered  OrderStatus = "delivered"
	OrderStatusCancelled  OrderStatus = "cancelled"
	OrderStatusRefunded   OrderStatus = "refunded"
)

func (s OrderStatus) IsValid() bool {
	switch s {
	case OrderStatusDraft, OrderStatusConfirmed, OrderStatusProcessing,
		OrderStatusShipped, OrderStatusDelivered, OrderStatusCancelled, OrderStatusRefunded:
		return true
	}
	return false
}

func (s OrderStatus) String() string { return string(s) }
