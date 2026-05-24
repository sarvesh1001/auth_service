// file: internal/sales/events/sales_events.go
package events

const (
	// TopicSalesEvents is the Kafka topic for all sales domain events.
	TopicSalesEvents = "sales-events"
)

// ----------------------------------------------------------------------------
// Customer Events
// ----------------------------------------------------------------------------
const (
	EventCustomerCreated            = "sales.customer.created"
	EventCustomerUpdated            = "sales.customer.updated"
	EventCustomerDeleted            = "sales.customer.deleted"
	EventCustomerActivated          = "sales.customer.activated"
	EventCustomerDeactivated        = "sales.customer.deactivated"
	EventCustomerCreditLimitUpdated = "sales.customer.credit_limit_updated"
)

type CustomerPayload struct {
	CustomerID   string `json:"customer_id"`
	CompanyID    string `json:"company_id"`
	CustomerCode string `json:"customer_code"`
	Name         string `json:"name"`
	IsActive     bool   `json:"is_active"`
	CreditLimit  string `json:"credit_limit,omitempty"`
}

// ----------------------------------------------------------------------------
// Product Events
// ----------------------------------------------------------------------------
const (
	EventProductCreated           = "sales.product.created"
	EventProductUpdated           = "sales.product.updated"
	EventProductDeleted           = "sales.product.deleted"
	EventProductActivated         = "sales.product.activated"
	EventProductDeactivated       = "sales.product.deactivated"
	EventProductPriceChanged      = "sales.product.price_changed"
	EventProductInventoryLinked   = "sales.product.inventory_linked"
	EventProductInventoryUnlinked = "sales.product.inventory_unlinked"
)

type ProductPayload struct {
	ProductID       string `json:"product_id"`
	CompanyID       string `json:"company_id"`
	SKU             string `json:"sku"`
	Name            string `json:"name"`
	UnitPrice       string `json:"unit_price"`
	IsActive        bool   `json:"is_active"`
	InventoryItemID string `json:"inventory_item_id,omitempty"`
}

// ----------------------------------------------------------------------------
// Order Events (EXTENDED for analytics)
// ----------------------------------------------------------------------------
const (
	EventOrderCreated             = "sales.order.created"
	EventOrderUpdated             = "sales.order.updated"
	EventOrderConfirmed           = "sales.order.confirmed"
	EventOrderProcessing          = "sales.order.processing"
	EventOrderShipped             = "sales.order.shipped"
	EventOrderDelivered           = "sales.order.delivered"
	EventOrderCancelled           = "sales.order.cancelled"
	EventOrderRefunded            = "sales.order.refunded"
	EventAutomaticDiscountApplied = "sales.automatic_discount.applied"
	EventStackingRuleUsed         = "sales.stacking_rule.used"
)

type OrderItemPayload struct {
	OrderItemID   string `json:"order_item_id,omitempty"` // NEW – for linking to order_item_analytics
	ProductID     string `json:"product_id"`
	Quantity      string `json:"quantity"`
	UnitPrice     string `json:"unit_price"`
	DiscountTotal string `json:"discount_total"`
	TaxTotal      string `json:"tax_total"`
}

type OrderPayload struct {
	OrderID     string             `json:"order_id"`
	CompanyID   string             `json:"company_id"`
	CustomerID  string             `json:"customer_id"`
	OrderNumber string             `json:"order_number"`
	Status      string             `json:"status"`
	GrandTotal  string             `json:"grand_total"`
	OrderDate   string             `json:"order_date"`
	Items       []OrderItemPayload `json:"items"`

	// Extended fields for analytics & reporting
	SalesRepID         string `json:"sales_rep_id,omitempty"`
	CancellationReason string `json:"cancellation_reason,omitempty"`
	CancelledBy        string `json:"cancelled_by,omitempty"`
	StatusBeforeCancel string `json:"status_before_cancel,omitempty"`
	Carrier            string `json:"carrier,omitempty"`
	TrackingNumber     string `json:"tracking_number,omitempty"`
	ShippingRegion     string `json:"shipping_region,omitempty"`
}

// ----------------------------------------------------------------------------
// Invoice Events (EXTENDED)
// ----------------------------------------------------------------------------
const (
	EventInvoiceCreated   = "sales.invoice.created"
	EventInvoiceUpdated   = "sales.invoice.updated"
	EventInvoiceIssued    = "sales.invoice.issued"
	EventInvoicePaid      = "sales.invoice.paid"
	EventInvoiceOverdue   = "sales.invoice.overdue"
	EventInvoiceCancelled = "sales.invoice.cancelled"
	EventInvoiceCredited  = "sales.invoice.credited"
)

type InvoicePayload struct {
	InvoiceID            string `json:"invoice_id"`
	CompanyID            string `json:"company_id"`
	CustomerID           string `json:"customer_id"`
	OrderID              string `json:"order_id,omitempty"`
	InvoiceNumber        string `json:"invoice_number"`
	Status               string `json:"status"`
	GrandTotal           string `json:"grand_total"`
	AmountDue            string `json:"amount_due"`
	DueDate              string `json:"due_date"`
	InvoiceDate          string `json:"invoice_date"`
	PaymentTermID        string `json:"payment_term_id,omitempty"`
	EarlyDiscountPercent string `json:"early_discount_percent,omitempty"`
	EarlyDiscountDays    int    `json:"early_discount_days,omitempty"`
}

// ----------------------------------------------------------------------------
// Payment Events (EXTENDED with Allocations)
// ----------------------------------------------------------------------------
const (
	EventPaymentCreated           = "sales.payment.created"
	EventPaymentUpdated           = "sales.payment.updated"
	EventPaymentProcessing        = "sales.payment.processing"
	EventPaymentCompleted         = "sales.payment.completed"
	EventPaymentFailed            = "sales.payment.failed"
	EventPaymentRefunded          = "sales.payment.refunded"
	EventPaymentPartiallyRefunded = "sales.payment.partially_refunded"
)

type PaymentAllocation struct {
	InvoiceID       string `json:"invoice_id"`
	Amount          string `json:"amount"`
	IsEarlyDiscount bool   `json:"is_early_discount"`
	DiscountAmount  string `json:"discount_amount,omitempty"`
}

type PaymentPayload struct {
	PaymentID     string              `json:"payment_id"`
	RefundID      string              `json:"refund_id,omitempty"` // add this
	CompanyID     string              `json:"company_id"`
	PaymentNumber string              `json:"payment_number"`
	Amount        string              `json:"amount"`
	PaymentMethod string              `json:"payment_method"`
	Status        string              `json:"status"`
	PaymentDate   string              `json:"payment_date"`
	Allocations   []PaymentAllocation `json:"allocations,omitempty"`
}

// ----------------------------------------------------------------------------
// Return Events
// ----------------------------------------------------------------------------
const (
	EventReturnCreated   = "sales.return.created"
	EventReturnApproved  = "sales.return.approved"
	EventReturnCompleted = "sales.return.completed"
	EventReturnRejected  = "sales.return.rejected"
)

type ReturnItemPayload struct {
	ProductID    string `json:"product_id"`
	Quantity     string `json:"quantity"`
	RefundAmount string `json:"refund_amount"`
}

type ReturnPayload struct {
	ReturnID     string              `json:"return_id"`
	CompanyID    string              `json:"company_id"`
	OrderID      string              `json:"order_id"`
	CustomerID   string              `json:"customer_id"`
	ReturnNumber string              `json:"return_number"`
	Status       string              `json:"status"`
	TotalRefund  string              `json:"total_refund"`
	ReturnDate   string              `json:"return_date"`
	Items        []ReturnItemPayload `json:"items"`
}

// ----------------------------------------------------------------------------
// Quote Events (EXTENDED for analytics)
// ----------------------------------------------------------------------------
const (
	EventQuoteCreated   = "sales.quote.created"
	EventQuoteUpdated   = "sales.quote.updated"
	EventQuoteSent      = "sales.quote.sent"
	EventQuoteAccepted  = "sales.quote.accepted"
	EventQuoteRejected  = "sales.quote.rejected"
	EventQuoteExpired   = "sales.quote.expired"
	EventQuoteConverted = "sales.quote.converted"
)

// QuoteItemPayload contains line‑item details for a quote (snapshot at quote time).
type QuoteItemPayload struct {
	QuoteItemID   string `json:"quote_item_id,omitempty"`
	ProductID     string `json:"product_id"`
	Quantity      string `json:"quantity"`
	UnitPrice     string `json:"unit_price"`
	DiscountTotal string `json:"discount_total"`
	TaxTotal      string `json:"tax_total"`
}

// QuotePayload is the payload for all quote events.
type QuotePayload struct {
	QuoteID     string `json:"quote_id"`
	CompanyID   string `json:"company_id"`
	CustomerID  string `json:"customer_id"`
	QuoteNumber string `json:"quote_number"`
	Revision    int    `json:"revision"`
	Status      string `json:"status"`
	GrandTotal  string `json:"grand_total"`
	ExpiryDate  string `json:"expiry_date,omitempty"`

	// Extended fields for analytics
	QuoteDate        string             `json:"quote_date,omitempty"`         // RFC3339 date when quote was created
	ConvertedOrderID string             `json:"converted_order_id,omitempty"` // order ID when quote is converted
	Items            []QuoteItemPayload `json:"items,omitempty"`              // line items (for created/converted events)
}

// ----------------------------------------------------------------------------
// Coupon Events
// ----------------------------------------------------------------------------
const (
	EventCouponCreated = "sales.coupon.created"
	EventCouponUpdated = "sales.coupon.updated"
	EventCouponDeleted = "sales.coupon.deleted"
	EventCouponApplied = "sales.coupon.applied"
)

type CouponPayload struct {
	CouponID      string `json:"coupon_id"`
	CompanyID     string `json:"company_id"`
	Code          string `json:"code"`
	DiscountType  string `json:"discount_type"`
	DiscountValue string `json:"discount_value"`
	IsActive      bool   `json:"is_active"`
}

// ----------------------------------------------------------------------------
// Promotion Events
// ----------------------------------------------------------------------------
const (
	EventPromotionCreated = "sales.promotion.created"
	EventPromotionUpdated = "sales.promotion.updated"
	EventPromotionDeleted = "sales.promotion.deleted"
	EventPromotionApplied = "sales.promotion.applied"
)

type PromotionPayload struct {
	PromotionID string `json:"promotion_id"`
	CompanyID   string `json:"company_id"`
	Name        string `json:"name"`
	IsActive    bool   `json:"is_active"`
	StartDate   string `json:"start_date"`
	EndDate     string `json:"end_date"`
}

// ----------------------------------------------------------------------------
// Payment Term Events
// ----------------------------------------------------------------------------
const (
	EventPaymentTermCreated     = "sales.payment_term.created"
	EventPaymentTermUpdated     = "sales.payment_term.updated"
	EventPaymentTermDeleted     = "sales.payment_term.deleted"
	EventPaymentTermActivated   = "sales.payment_term.activated"
	EventPaymentTermDeactivated = "sales.payment_term.deactivated"
)

type PaymentTermPayload struct {
	TermID          string `json:"term_id"`
	CompanyID       string `json:"company_id"`
	Code            string `json:"code"`
	TermName        string `json:"term_name"`
	DueDays         int    `json:"due_days"`
	DiscountPercent string `json:"discount_percent"`
	DiscountDays    int    `json:"discount_days"`
	IsActive        bool   `json:"is_active"`
}

const (
	EventCouponActivated   = "sales.coupon.activated"   // new
	EventCouponDeactivated = "sales.coupon.deactivated" // new
	EventReturnUpdated     = "sales.return.updated"
	EventReturnDeleted     = "sales.return.deleted"
)

type CouponAppliedPayload struct {
	CouponID       string  `json:"coupon_id"`
	CompanyID      string  `json:"company_id"`
	Code           string  `json:"code"`
	DiscountAmount string  `json:"discount_amount"`
	OrderSubtotal  string  `json:"order_subtotal"` // base amount before discount
	EntityType     string  `json:"entity_type"`    // "order" or "invoice"
	EntityID       string  `json:"entity_id"`
	CustomerID     *string `json:"customer_id,omitempty"`
	UsedAt         string  `json:"used_at"` // RFC3339
}

const (
	EventSalesRepCreated     = "sales.sales_rep.created"
	EventSalesRepUpdated     = "sales.sales_rep.updated"
	EventSalesRepDeleted     = "sales.sales_rep.deleted"
	EventSalesRepActivated   = "sales.sales_rep.activated"
	EventSalesRepDeactivated = "sales.sales_rep.deactivated"
	EventSalesRepAssigned    = "sales.sales_rep.assigned"
	EventSalesRepUnassigned  = "sales.sales_rep.unassigned"
)
