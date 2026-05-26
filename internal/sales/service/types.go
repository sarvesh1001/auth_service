// file: internal/sales/service/types.go
package service

import (
	"encoding/json"
	"fmt"
	"time"

	"auth-service/internal/sales/models"
	"auth-service/internal/sales/models/discount"
	"auth-service/internal/sales/models/enums"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"gorm.io/datatypes"
)

// ================================
// Shared types (Pagination, Sort)
// ================================

type Pagination struct {
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

type Sort struct {
	Field     string `json:"field"`
	Direction string `json:"direction"` // ASC, DESC
}

// ================================
// Customer DTOs
// ================================

type CreateCustomerRequest struct {
	CompanyID      uuid.UUID        `json:"companyId"`
	CustomerCode   string           `json:"customerCode"`
	Name           string           `json:"name"`
	Email          *string          `json:"email,omitempty"`
	Phone          *string          `json:"phone,omitempty"`
	TaxID          *string          `json:"taxId,omitempty"`
	BillingAddress *string          `json:"billingAddress,omitempty"`
	ShippingAddr   *string          `json:"shippingAddress,omitempty"`
	CreditLimit    *decimal.Decimal `json:"creditLimit,omitempty"`
	PaymentTermID  *uuid.UUID       `json:"paymentTermId,omitempty"`
	CreatedBy      *uuid.UUID       `json:"createdBy,omitempty"`
}

type UpdateCustomerRequest struct {
	Name           *string    `json:"name,omitempty"`
	Email          *string    `json:"email,omitempty"`
	Phone          *string    `json:"phone,omitempty"`
	TaxID          *string    `json:"taxId,omitempty"`
	BillingAddress *string    `json:"billingAddress,omitempty"`
	ShippingAddr   *string    `json:"shippingAddress,omitempty"`
	IsActive       *bool      `json:"isActive,omitempty"`
	UpdatedBy      *uuid.UUID `json:"updatedBy,omitempty"`
}

type CustomerListFilter struct {
	CompanyID              uuid.UUID   `json:"companyId"`
	IsActive               *bool       `json:"isActive,omitempty"`
	CustomerIDs            []uuid.UUID `json:"customerIds,omitempty"`
	CustomerCode           *string     `json:"customerCode,omitempty"`
	Name                   *string     `json:"name,omitempty"`
	HasOutstandingInvoices *bool       `json:"hasOutstandingInvoices,omitempty"`
	PaymentTermID          *uuid.UUID  `json:"paymentTermId,omitempty"`
	CreatedFrom            *time.Time  `json:"createdFrom,omitempty"`
	CreatedTo              *time.Time  `json:"createdTo,omitempty"`
	UpdatedFrom            *time.Time  `json:"updatedFrom,omitempty"`
	UpdatedTo              *time.Time  `json:"updatedTo,omitempty"`
}

// ================================
// Product DTOs
// ================================

type CreateProductRequest struct {
	CompanyID       uuid.UUID       `json:"companyId"`
	SKU             string          `json:"sku"`
	Name            string          `json:"name"`
	Description     *string         `json:"description,omitempty"`
	UnitPrice       decimal.Decimal `json:"unitPrice"`
	InventoryItemID *uuid.UUID      `json:"inventoryItemId,omitempty"`
	IsActive        *bool           `json:"isActive,omitempty"`
	CreatedBy       *uuid.UUID      `json:"createdBy,omitempty"`
}

type UpdateProductRequest struct {
	Name            *string          `json:"name,omitempty"`
	Description     *string          `json:"description,omitempty"`
	UnitPrice       *decimal.Decimal `json:"unitPrice,omitempty"`
	InventoryItemID *uuid.UUID       `json:"inventoryItemId,omitempty"`
	IsActive        *bool            `json:"isActive,omitempty"`
	UpdatedBy       *uuid.UUID       `json:"updatedBy,omitempty"`
}

type ProductListFilter struct {
	CompanyID       uuid.UUID        `json:"companyId"`
	IsActive        *bool            `json:"isActive,omitempty"`
	InventoryLinked *bool            `json:"inventoryLinked,omitempty"` // true = has inventory_item_id, false = no link
	MinPrice        *decimal.Decimal `json:"minPrice,omitempty"`
	MaxPrice        *decimal.Decimal `json:"maxPrice,omitempty"`
	Search          *string          `json:"search,omitempty"` // searches SKU, Name
}

// ================================
// Payment Term DTOs
// ================================

type CreatePaymentTermRequest struct {
	CompanyID       uuid.UUID       `json:"companyId"`
	Code            string          `json:"code"`
	TermName        string          `json:"termName"`
	Description     *string         `json:"description,omitempty"`
	DueDays         int             `json:"dueDays"`
	DiscountPercent decimal.Decimal `json:"discountPercent"`
	DiscountDays    int             `json:"discountDays"`
	IsActive        *bool           `json:"isActive,omitempty"`
	CreatedBy       *uuid.UUID      `json:"createdBy,omitempty"`
}

type UpdatePaymentTermRequest struct {
	TermName        *string          `json:"termName,omitempty"`
	Description     *string          `json:"description,omitempty"`
	DueDays         *int             `json:"dueDays,omitempty"`
	DiscountPercent *decimal.Decimal `json:"discountPercent,omitempty"`
	DiscountDays    *int             `json:"discountDays,omitempty"`
	IsActive        *bool            `json:"isActive,omitempty"`
	UpdatedBy       *uuid.UUID       `json:"updatedBy,omitempty"`
}

type PaymentTermListFilter struct {
	CompanyID  uuid.UUID `json:"companyId"`
	IsActive   *bool     `json:"isActive,omitempty"`
	MinDueDays *int      `json:"minDueDays,omitempty"`
	MaxDueDays *int      `json:"maxDueDays,omitempty"`
	Search     *string   `json:"search,omitempty"`
}

// ================================
// Order DTOs (for OrderService)
// ================================

type CreateOrderRequest struct {
	CompanyID       uuid.UUID
	CustomerID      uuid.UUID
	OrderNumber     string
	ExternalRef     *string
	OrderDate       time.Time
	Currency        string
	Notes           *string
	ShippingAddress models.JSONB
	BillingAddress  models.JSONB
	SalesRepID      *uuid.UUID
	Items           []*CreateOrderItemRequest
	CouponCodes     []string
	CreatedBy       *uuid.UUID
}

type UpdateOrderRequest struct {
	ExternalRef     *string
	OrderDate       *time.Time
	Currency        *string
	Notes           *string
	ShippingAddress *models.JSONB
	BillingAddress  *models.JSONB
	SalesRepID      *uuid.UUID
	UpdatedBy       *uuid.UUID
}

type CreateOrderItemRequest struct {
	ProductID      uuid.UUID
	Quantity       decimal.Decimal
	UnitPrice      *decimal.Decimal
	DiscountAmount *decimal.Decimal
	Metadata       models.JSONB
}

type OrderListFilter struct {
	CompanyID    uuid.UUID
	CustomerID   *uuid.UUID
	Status       *enums.OrderStatus
	SalesRepID   *uuid.UUID
	FromDate     *time.Time
	ToDate       *time.Time
	MinTotal     *decimal.Decimal
	MaxTotal     *decimal.Decimal
	Search       *string
	CreditHold   *bool                    // NEW: filter by credit hold status
	CreditStatus *enums.CreditCheckStatus // NEW: filter by credit check status
}

type OrderPricingPreviewResult struct {
	Subtotal          decimal.Decimal
	DiscountTotal     decimal.Decimal
	TaxTotal          decimal.Decimal
	GrandTotal        decimal.Decimal
	AppliedCoupons    []*discount.Coupon
	AppliedPromotions []*discount.Promotion
}

// ---------------------------------------------------------------------
// Request / Result DTOs (used by PricingService)
// ---------------------------------------------------------------------

type PricingLineInput struct {
	ProductID uuid.UUID
	Quantity  decimal.Decimal
	UnitPrice *decimal.Decimal
}

type CalculateOrderPricingRequest struct {
	CompanyID    uuid.UUID
	CustomerID   *uuid.UUID
	Lines        []PricingLineInput
	CouponCodes  []string
	CalculateTax bool
	At           time.Time
}

type CalculateQuotePricingRequest struct {
	CompanyID    uuid.UUID
	CustomerID   *uuid.UUID
	Lines        []PricingLineInput
	CouponCodes  []string
	CalculateTax bool
	At           time.Time
}

type CalculateInvoicePricingRequest struct {
	CompanyID    uuid.UUID
	CustomerID   *uuid.UUID
	Lines        []PricingLineInput
	CouponCodes  []string
	CalculateTax bool
	At           time.Time
}

type PricingCalculationResult struct {
	Subtotal          decimal.Decimal
	DiscountTotal     decimal.Decimal
	TaxTotal          decimal.Decimal
	GrandTotal        decimal.Decimal
	LineResults       []*PricingLineResult
	AppliedCoupons    []*discount.Coupon
	AppliedPromotions []*discount.Promotion
}

type PricingLineResult struct {
	ProductID       uuid.UUID
	Quantity        decimal.Decimal
	BasePrice       decimal.Decimal
	DiscountAmount  decimal.Decimal
	TaxAmount       decimal.Decimal
	FinalLineAmount decimal.Decimal
}

// DiscountCalculationResult is used by both PricingService and DiscountEngineService.
// It includes fields for automatic discounts (which may be unused by PricingService).
type DiscountCalculationResult struct {
	DiscountTotal     decimal.Decimal
	AppliedCoupons    []*discount.Coupon
	AppliedPromotions []*discount.Promotion
	AppliedAutomatic  []*AutomaticDiscount
}

type PricingValidationRequest struct {
	CompanyID    uuid.UUID
	CustomerID   *uuid.UUID
	Lines        []PricingLineInput
	CouponIDs    []uuid.UUID
	PromotionIDs []uuid.UUID
}

type OrderPricingPreviewRequest struct {
	CompanyID   uuid.UUID
	CustomerID  *uuid.UUID
	Items       []*CreateOrderItemRequest
	CouponCodes []string
	At          *time.Time
}

type QuotePricingPreviewRequest struct {
	CompanyID   uuid.UUID
	CustomerID  *uuid.UUID
	Items       []*CreateQuoteItemRequest
	CouponCodes []string
	At          *time.Time
}

type InvoicePricingPreviewRequest struct {
	CompanyID   uuid.UUID
	CustomerID  *uuid.UUID
	Items       []*CreateOrderItemRequest // reuse same item structure
	CouponCodes []string
	At          *time.Time
}

type PricingPreviewResult struct {
	Subtotal          decimal.Decimal
	DiscountTotal     decimal.Decimal
	TaxTotal          decimal.Decimal
	GrandTotal        decimal.Decimal
	AppliedCoupons    []*discount.Coupon
	AppliedPromotions []*discount.Promotion
}

type CreateInvoiceFromOrderRequest struct {
	Notes     *string
	CreatedBy uuid.UUID
}

type CreateInvoiceFromQuoteRequest struct {
	Notes     *string
	CreatedBy uuid.UUID
}

// ================================
// Discount Engine DTOs
// ================================

type EvaluateOrderDiscountsRequest struct {
	CompanyID uuid.UUID
	OrderID   uuid.UUID
	At        time.Time
}

type EvaluateQuoteDiscountsRequest struct {
	CompanyID uuid.UUID
	QuoteID   uuid.UUID
	At        time.Time
}

type EvaluateInvoiceDiscountsRequest struct {
	CompanyID uuid.UUID
	InvoiceID uuid.UUID
	At        time.Time
}

type DiscountEvaluationResult struct {
	Subtotal          decimal.Decimal
	DiscountTotal     decimal.Decimal
	TaxTotal          decimal.Decimal
	GrandTotal        decimal.Decimal
	AppliedCoupons    []*discount.Coupon
	AppliedPromotions []*discount.Promotion
	AppliedAutomatic  []*AutomaticDiscount
	LineResults       []*DiscountLineResult
}

type DiscountLineResult struct {
	ProductID       uuid.UUID
	Quantity        decimal.Decimal
	BasePrice       decimal.Decimal
	DiscountAmount  decimal.Decimal
	TaxAmount       decimal.Decimal
	FinalLineAmount decimal.Decimal
}

type BestDiscountCombinationRequest struct {
	CompanyID         uuid.UUID
	CustomerID        *uuid.UUID
	ProductIDs        []uuid.UUID
	OrderAmount       decimal.Decimal
	At                time.Time
	IncludeCoupons    bool
	IncludePromotions bool
	IncludeAutomatic  bool
	MaxCombinations   int
}

type DiscountCombinationResult struct {
	DiscountTotal     decimal.Decimal
	AppliedCoupons    []*discount.Coupon
	AppliedPromotions []*discount.Promotion
	AppliedAutomatic  []*discount.AutomaticDiscount // not []*AutomaticDiscount
}

type CombinedDiscountCalculationRequest struct {
	CompanyID    uuid.UUID
	CustomerID   *uuid.UUID
	ProductIDs   []uuid.UUID
	OrderAmount  decimal.Decimal
	CouponIDs    []uuid.UUID
	PromotionIDs []uuid.UUID
	AutomaticIDs []uuid.UUID
	At           time.Time
}

type DiscountApplicationResult struct {
	DiscountTotal     decimal.Decimal
	AppliedCoupons    []*discount.Coupon
	AppliedPromotions []*discount.Promotion
	AppliedAutomatic  []*AutomaticDiscount
}

type DiscountEligibilityRequest struct {
	CompanyID    uuid.UUID
	DiscountID   uuid.UUID
	DiscountType string // "coupon", "promotion", "automatic"
	CustomerID   *uuid.UUID
	ProductIDs   []uuid.UUID
	OrderAmount  decimal.Decimal
	At           time.Time
}

type AutomaticDiscount = discount.AutomaticDiscount

// ================================
// Coupon DTOs
// ================================

type CreateCouponRequest struct {
	CompanyID         uuid.UUID          `json:"companyId"`
	Code              string             `json:"code"`
	DiscountType      enums.DiscountType `json:"discountType"`
	DiscountValue     decimal.Decimal    `json:"discountValue"`
	MaxDiscountAmount *decimal.Decimal   `json:"maxDiscountAmount,omitempty"`
	StartDate         time.Time          `json:"startDate"`
	EndDate           time.Time          `json:"endDate"`
	UsageLimit        *int               `json:"usageLimit,omitempty"`
	PerUserLimit      *int               `json:"perUserLimit,omitempty"`
	MinOrderAmount    *decimal.Decimal   `json:"minOrderAmount,omitempty"`
	ApplicableItems   datatypes.JSON     `json:"applicableItems,omitempty"`
	CreatedBy         *uuid.UUID         `json:"createdBy,omitempty"`
	IdempotencyKey    string             `json:"idempotencyKey"`
}

type UpdateCouponRequest struct {
	Code              *string             `json:"code,omitempty"`
	DiscountType      *enums.DiscountType `json:"discountType,omitempty"`
	DiscountValue     *decimal.Decimal    `json:"discountValue,omitempty"`
	MaxDiscountAmount *decimal.Decimal    `json:"maxDiscountAmount,omitempty"`
	StartDate         *time.Time          `json:"startDate,omitempty"`
	EndDate           *time.Time          `json:"endDate,omitempty"`
	UsageLimit        *int                `json:"usageLimit,omitempty"`
	PerUserLimit      *int                `json:"perUserLimit,omitempty"`
	MinOrderAmount    *decimal.Decimal    `json:"minOrderAmount,omitempty"`
	ApplicableItems   datatypes.JSON      `json:"applicableItems,omitempty"`
	UpdatedBy         *uuid.UUID          `json:"updatedBy,omitempty"`
	IdempotencyKey    string              `json:"idempotencyKey"`
}

type CouponListFilter struct {
	CompanyID   uuid.UUID  `json:"companyId"`
	Code        *string    `json:"code,omitempty"`
	IsActive    *bool      `json:"isActive,omitempty"`
	CreatedFrom *time.Time `json:"createdFrom,omitempty"`
	CreatedTo   *time.Time `json:"createdTo,omitempty"`
}

type RecordCouponUsageRequest struct {
	CompanyID      uuid.UUID       `json:"companyId"`
	CouponID       uuid.UUID       `json:"couponId"`
	OrderID        uuid.UUID       `json:"orderId"`
	CustomerID     *uuid.UUID      `json:"customerId,omitempty"`
	DiscountAmount decimal.Decimal `json:"discountAmount"`
	UsedAt         time.Time       `json:"usedAt"`
}

var ErrNotSupported = fmt.Errorf("operation not supported by current data model")

type CreatePromotionRequest struct {
	CompanyID   uuid.UUID  `json:"companyId"`
	Name        string     `json:"name"`
	Description *string    `json:"description,omitempty"`
	StartDate   time.Time  `json:"startDate"`
	EndDate     time.Time  `json:"endDate"`
	IsActive    bool       `json:"isActive"`
	Priority    *int       `json:"priority,omitempty"`
	CreatedBy   *uuid.UUID `json:"createdBy,omitempty"`
}

type UpdatePromotionRequest struct {
	Name        *string    `json:"name,omitempty"`
	Description *string    `json:"description,omitempty"`
	StartDate   *time.Time `json:"startDate,omitempty"`
	EndDate     *time.Time `json:"endDate,omitempty"`
	IsActive    *bool      `json:"isActive,omitempty"`
	Priority    *int       `json:"priority,omitempty"`
	UpdatedBy   *uuid.UUID `json:"updatedBy,omitempty"`
}

type PromotionListFilter struct {
	CompanyID    uuid.UUID   `json:"companyId"`
	IsActive     *bool       `json:"isActive,omitempty"`
	Name         *string     `json:"name,omitempty"`
	PromotionIDs []uuid.UUID `json:"promotionIds,omitempty"`
}

type CreatePromotionRuleRequest struct {
	CompanyID     uuid.UUID              `json:"companyId"`
	PromotionID   uuid.UUID              `json:"promotionId"`
	RuleType      string                 `json:"ruleType"`
	RuleConfig    map[string]interface{} `json:"ruleConfig"`
	DiscountType  discount.DiscountType  `json:"discountType"`
	DiscountValue decimal.Decimal        `json:"discountValue"`
	MaxDiscount   *decimal.Decimal       `json:"maxDiscount,omitempty"`
}

type UpdatePromotionRuleRequest struct {
	RuleType      *string                `json:"ruleType,omitempty"`
	RuleConfig    map[string]interface{} `json:"ruleConfig,omitempty"`
	DiscountType  *discount.DiscountType `json:"discountType,omitempty"`
	DiscountValue *decimal.Decimal       `json:"discountValue,omitempty"`
	MaxDiscount   *decimal.Decimal       `json:"maxDiscount,omitempty"`
}

type EvaluatePromotionRequest struct {
	CompanyID   uuid.UUID            `json:"companyId"`
	PromotionID uuid.UUID            `json:"promotionId"`
	CustomerID  *uuid.UUID           `json:"customerId,omitempty"`
	Items       []PromotionItemInput `json:"items"`
	OrderAmount decimal.Decimal      `json:"orderAmount"`
	At          time.Time            `json:"at"`
}

type PromotionItemInput struct {
	ProductID uuid.UUID       `json:"productId"`
	Quantity  decimal.Decimal `json:"quantity"`
	UnitPrice decimal.Decimal `json:"unitPrice"`
}

type PromotionEvaluationResult struct {
	Applicable     bool            `json:"applicable"`
	DiscountAmount decimal.Decimal `json:"discountAmount"`
	Reason         string          `json:"reason,omitempty"`
}

type PromotionRuleEvaluationResult struct {
	ApplicableRules []*discount.PromotionRule `json:"applicableRules"`
	DiscountAmount  decimal.Decimal           `json:"discountAmount"`
}

type PromotionApplicationResult struct {
	AppliedPromotions []*discount.Promotion `json:"appliedPromotions"`
	TotalDiscount     decimal.Decimal       `json:"totalDiscount"`
}

type PromotionItemCalculationInput struct {
	ProductID  uuid.UUID       `json:"productId"`
	Quantity   decimal.Decimal `json:"quantity"`
	UnitPrice  decimal.Decimal `json:"unitPrice"`
	CategoryID *uuid.UUID      `json:"categoryId,omitempty"`
}

type RecordPromotionUsageRequest struct {
	CompanyID      uuid.UUID       `json:"companyId"`
	PromotionID    uuid.UUID       `json:"promotionId"`
	EntityType     string          `json:"entityType"`
	EntityID       uuid.UUID       `json:"entityId"`
	CustomerID     *uuid.UUID      `json:"customerId,omitempty"`
	DiscountAmount decimal.Decimal `json:"discountAmount"`
	UsedAt         time.Time       `json:"usedAt"`
}

type CreateSalesRepRequest struct {
	CompanyID uuid.UUID  `json:"companyId"`
	UserID    uuid.UUID  `json:"userId"`
	Code      string     `json:"code"`
	Name      string     `json:"name"`
	Email     *string    `json:"email,omitempty"`
	Phone     *string    `json:"phone,omitempty"`
	CreatedBy *uuid.UUID `json:"createdBy,omitempty"`
}

type UpdateSalesRepRequest struct {
	Name      *string    `json:"name,omitempty"`
	Email     *string    `json:"email,omitempty"`
	Phone     *string    `json:"phone,omitempty"`
	IsActive  *bool      `json:"isActive,omitempty"`
	UpdatedBy *uuid.UUID `json:"updatedBy,omitempty"`
}

type SalesRepListFilter struct {
	CompanyID   uuid.UUID   `json:"companyId"`
	IsActive    *bool       `json:"isActive,omitempty"`
	SalesRepIDs []uuid.UUID `json:"salesRepIds,omitempty"`
	Code        *string     `json:"code,omitempty"`
	Name        *string     `json:"name,omitempty"`
	UserID      *uuid.UUID  `json:"userId,omitempty"`
}

type SetSalesTargetRequest struct {
	TargetAmount decimal.Decimal `json:"targetAmount"`
	PeriodStart  time.Time       `json:"periodStart"`
	PeriodEnd    time.Time       `json:"periodEnd"`
}

type SalesRepLeaderboardEntry struct {
	SalesRepID   uuid.UUID       `json:"salesRepId"`
	Code         string          `json:"code"`
	Name         string          `json:"name"`
	TotalRevenue decimal.Decimal `json:"totalRevenue"`
	TotalOrders  int             `json:"totalOrders"`
	AverageDeal  decimal.Decimal `json:"averageDeal"`
}

// CreditCheckResult holds the outcome of a credit eligibility check.
type CreditCheckResult struct {
	Eligible         bool            `json:"eligible"`
	Reason           string          `json:"reason,omitempty"`
	CurrentBalance   decimal.Decimal `json:"currentBalance"`
	CreditLimit      decimal.Decimal `json:"creditLimit"`
	AvailableCredit  decimal.Decimal `json:"availableCredit"`
	RequestedAmount  decimal.Decimal `json:"requestedAmount"`
	OutstandingCount int             `json:"outstandingCount"`
}

// CreateCreditCheckHistoryRequest is used to manually log a credit check.
type CreateCreditCheckHistoryRequest struct {
	CompanyID           uuid.UUID
	CustomerID          uuid.UUID
	ActionType          string
	PreviousLimit       *decimal.Decimal
	NewLimit            *decimal.Decimal
	PreviousOutstanding *decimal.Decimal
	NewOutstanding      *decimal.Decimal
	Reason              *string
	ApprovedBy          *uuid.UUID
	CreatedBy           *uuid.UUID
}

// CreditReviewResult summarises the automatic credit review.
type CreditReviewResult struct {
	CustomerID          uuid.UUID       `json:"customerId"`
	PreviousLimit       decimal.Decimal `json:"previousLimit"`
	RecommendedLimit    decimal.Decimal `json:"recommendedLimit"`
	CurrentOutstanding  decimal.Decimal `json:"currentOutstanding"`
	PaymentHistoryScore decimal.Decimal `json:"paymentHistoryScore"`
	ActionTaken         string          `json:"actionTaken"` // "increase", "decrease", "maintain", "suspend"
	Reason              string          `json:"reason"`
}

type CreateCreditNoteRequest struct {
	CompanyID      uuid.UUID
	CustomerID     uuid.UUID
	CreditNoteDate time.Time
	Currency       *string
	Items          []*CreateCreditNoteItemRequest
	Reason         *string
	Notes          *string
	CreatedBy      *uuid.UUID
}

type CreateCreditNoteItemRequest struct {
	ProductID     uuid.UUID
	Quantity      decimal.Decimal
	UnitPrice     decimal.Decimal
	TaxRate       *decimal.Decimal
	InvoiceItemID *uuid.UUID
}

type CreateCreditNoteFromInvoiceRequest struct {
	Items  []uuid.UUID // invoice item IDs to credit (nil = full invoice)
	Reason *string
	Notes  *string
}

type CreateCreditNoteFromReturnRequest struct {
	Reason *string
	Notes  *string
}

type UpdateCreditNoteRequest struct {
	Reason *string
	Notes  *string
}

type CreditNoteListFilter struct {
	CompanyID  uuid.UUID
	CustomerID *uuid.UUID
	Status     *enums.CreditNoteStatus
	FromDate   *time.Time
	ToDate     *time.Time
	InvoiceID  *uuid.UUID
	ReturnID   *uuid.UUID
}

type CreditNotePreviewRequest struct {
	CompanyID  uuid.UUID
	CustomerID uuid.UUID
	Items      []*CreateCreditNoteItemRequest
}

type CreditNotePreviewResult struct {
	Subtotal    decimal.Decimal
	TaxTotal    decimal.Decimal
	TotalAmount decimal.Decimal
}

type CreditNoteApplicationRequest struct {
	InvoiceID uuid.UUID
	Amount    decimal.Decimal
}

type ConvertCreditNoteToRefundRequest struct {
	PaymentID uuid.UUID // original payment to refund against
	Reason    string
}

type CreateInvoiceRequest struct {
	CompanyID     uuid.UUID
	CustomerID    uuid.UUID
	OrderID       *uuid.UUID
	InvoiceNumber string
	ExternalRef   *string
	InvoiceDate   time.Time
	DueDate       time.Time
	Currency      string
	Notes         *string
	Items         []CreateInvoiceItemRequest
	CreatedBy     *uuid.UUID
}

type CreateInvoiceItemRequest struct {
	ProductID uuid.UUID
	Quantity  decimal.Decimal
	UnitPrice *decimal.Decimal // override default product price
	Discount  *decimal.Decimal
	Metadata  models.JSONB
}

type UpdateInvoiceRequest struct {
	DueDate   *time.Time
	Currency  *string
	Notes     *string
	UpdatedBy *uuid.UUID
}

type InvoiceListFilter struct {
	CompanyID  uuid.UUID
	CustomerID *uuid.UUID
	OrderID    *uuid.UUID
	Status     *enums.InvoiceStatus
	FromDate   *time.Time
	ToDate     *time.Time
	MinTotal   *decimal.Decimal
	MaxTotal   *decimal.Decimal
}

type InvoicePricingPreviewResult struct {
	Subtotal      decimal.Decimal
	DiscountTotal decimal.Decimal
	TaxTotal      decimal.Decimal
	GrandTotal    decimal.Decimal
	LineDetails   []InvoicePricingLineDetail
}

type InvoicePricingLineDetail struct {
	ProductID      uuid.UUID
	Quantity       decimal.Decimal
	UnitPrice      decimal.Decimal
	DiscountAmount decimal.Decimal
	TaxAmount      decimal.Decimal
	LineTotal      decimal.Decimal
}

type RegisterInvoicePaymentRequest struct {
	CompanyID   uuid.UUID
	InvoiceID   uuid.UUID
	PaymentID   uuid.UUID
	Amount      decimal.Decimal
	AllocatedBy *uuid.UUID
}

type InvoicePayment struct {
	PaymentID   uuid.UUID
	Amount      decimal.Decimal
	AllocatedAt time.Time
}

type CreatePaymentRequest struct {
	CompanyID       uuid.UUID
	PaymentNumber   string
	ExternalRef     *string
	PaymentDate     time.Time
	Amount          decimal.Decimal
	PaymentMethod   enums.PaymentMethod
	Reference       *string
	GatewayResponse models.JSONB
	CreatedBy       *uuid.UUID
}

type UpdatePaymentRequest struct {
	ExternalRef     *string
	PaymentDate     *time.Time
	Amount          *decimal.Decimal
	PaymentMethod   *enums.PaymentMethod
	Reference       *string
	GatewayResponse models.JSONB
	UpdatedBy       *uuid.UUID
}

type PaymentListFilter struct {
	CompanyID     uuid.UUID
	CustomerID    *uuid.UUID
	InvoiceID     *uuid.UUID
	Status        *enums.PaymentStatus
	PaymentMethod *enums.PaymentMethod
	FromDate      *time.Time
	ToDate        *time.Time
	MinAmount     *decimal.Decimal
	MaxAmount     *decimal.Decimal
}

type PaymentAllocationRequest struct {
	InvoiceID uuid.UUID
	Amount    decimal.Decimal
}

type RegisterCashPaymentRequest struct {
	CompanyID   uuid.UUID
	CustomerID  uuid.UUID
	Amount      decimal.Decimal
	PaymentDate time.Time
	Reference   *string
	Allocations []PaymentAllocationRequest
	CreatedBy   uuid.UUID
}

type RegisterCardPaymentRequest struct {
	CompanyID       uuid.UUID
	CustomerID      uuid.UUID
	Amount          decimal.Decimal
	PaymentDate     time.Time
	CardLast4       string
	CardBrand       string
	GatewayTxID     string
	GatewayResponse models.JSONB
	Allocations     []PaymentAllocationRequest
	CreatedBy       uuid.UUID
}

type RegisterBankTransferPaymentRequest struct {
	CompanyID       uuid.UUID
	CustomerID      uuid.UUID
	Amount          decimal.Decimal
	PaymentDate     time.Time
	ReferenceNumber string
	BankName        *string
	Allocations     []PaymentAllocationRequest
	CreatedBy       uuid.UUID
}

type RegisterChequePaymentRequest struct {
	CompanyID    uuid.UUID
	CustomerID   uuid.UUID
	Amount       decimal.Decimal
	PaymentDate  time.Time
	ChequeNumber string
	BankName     *string
	Allocations  []PaymentAllocationRequest
	CreatedBy    uuid.UUID
}

type RegisterWalletPaymentRequest struct {
	CompanyID      uuid.UUID
	CustomerID     uuid.UUID
	Amount         decimal.Decimal
	PaymentDate    time.Time
	WalletProvider string
	WalletTxID     string
	Allocations    []PaymentAllocationRequest
	CreatedBy      uuid.UUID
}

type ProcessGatewayPaymentRequest struct {
	CompanyID      uuid.UUID
	CustomerID     uuid.UUID
	Amount         decimal.Decimal
	PaymentMethod  enums.PaymentMethod
	GatewayName    string
	GatewayToken   string
	IdempotencyKey string
	Allocations    []PaymentAllocationRequest
	CreatedBy      uuid.UUID
}

type ProcessGatewayWebhookRequest struct {
	CompanyID   uuid.UUID
	GatewayName string
	GatewayTxID string
	Status      string
	RawPayload  []byte
	Signature   string
}

type CreateRefundRequest struct {
	CompanyID  uuid.UUID
	PaymentID  uuid.UUID
	Amount     decimal.Decimal
	Reason     string
	RefundedBy uuid.UUID
}

type ProcessGatewayRefundRequest struct {
	CompanyID   uuid.UUID
	PaymentID   uuid.UUID
	Amount      decimal.Decimal
	Reason      string
	GatewayName string
	RefundedBy  uuid.UUID
}

type CreateQuoteRequest struct {
	CompanyID   uuid.UUID
	CustomerID  uuid.UUID
	QuoteNumber string
	QuoteDate   time.Time
	ExpiryDate  *time.Time
	Currency    string
	Notes       *string
	Items       []*CreateQuoteItemRequest
	CouponCodes []string
	SalesRepID  *uuid.UUID
	CreatedBy   *uuid.UUID
}

type UpdateQuoteRequest struct {
	ExpiryDate *time.Time
	Currency   *string
	Notes      *string
	SalesRepID *uuid.UUID
	UpdatedBy  *uuid.UUID
}

type CreateQuoteItemRequest struct {
	ProductID      uuid.UUID
	Quantity       decimal.Decimal
	UnitPrice      *decimal.Decimal
	DiscountAmount *decimal.Decimal
	Metadata       models.JSONB
}

type QuoteListFilter struct {
	CompanyID  uuid.UUID
	CustomerID *uuid.UUID
	Status     *enums.QuoteStatus
	SalesRepID *uuid.UUID
	FromDate   *time.Time
	ToDate     *time.Time
	MinTotal   *decimal.Decimal
	MaxTotal   *decimal.Decimal
	Search     *string
}

type QuotePricingPreviewResult struct {
	Subtotal          decimal.Decimal
	DiscountTotal     decimal.Decimal
	TaxTotal          decimal.Decimal
	GrandTotal        decimal.Decimal
	AppliedCoupons    []*discount.Coupon
	AppliedPromotions []*discount.Promotion
}

type CreateQuoteRevisionRequest struct {
	Items       []*CreateQuoteItemRequest
	CouponCodes []string
	Notes       *string
	ExpiryDate  *time.Time
	UpdatedBy   *uuid.UUID
}

type ConvertQuoteToOrderRequest struct {
	OrderDate       time.Time
	ShippingAddress models.JSONB
	BillingAddress  models.JSONB
	Notes           *string
	UpdatedBy       *uuid.UUID
}

type CreateReturnRequest struct {
	CompanyID  uuid.UUID
	OrderID    *uuid.UUID
	InvoiceID  *uuid.UUID
	ReturnDate time.Time
	Reason     *string
	Items      []*CreateReturnItemRequest
	CreatedBy  uuid.UUID
}

type CreateReturnFromOrderRequest struct {
	ReturnDate time.Time
	Reason     *string
	Items      []*CreateReturnItemRequest
	CreatedBy  uuid.UUID
}

type CreateReturnFromInvoiceRequest struct {
	ReturnDate time.Time
	Reason     *string
	Items      []*CreateReturnItemRequest
	CreatedBy  uuid.UUID
}

type UpdateReturnRequest struct {
	ReturnDate *time.Time
	Reason     *string
	UpdatedBy  uuid.UUID
}

type CreateReturnItemRequest struct {
	OrderItemID *uuid.UUID
	ProductID   uuid.UUID
	Quantity    decimal.Decimal
	Reason      *string
}

type ReturnListFilter struct {
	CompanyID      uuid.UUID
	OrderID        *uuid.UUID
	InvoiceID      *uuid.UUID
	ReturnIDs      []uuid.UUID
	Statuses       []enums.ReturnStatus
	ReturnNumber   string
	MinRefundTotal *decimal.Decimal
	MaxRefundTotal *decimal.Decimal
	ReturnDateFrom *time.Time
	ReturnDateTo   *time.Time
	ApprovedFrom   *time.Time
	ApprovedTo     *time.Time
	CompletedFrom  *time.Time
	CompletedTo    *time.Time
	CreatedFrom    *time.Time
	CreatedTo      *time.Time
	UpdatedFrom    *time.Time
	UpdatedTo      *time.Time
}

type ReturnRefundPreviewRequest struct {
	CompanyID uuid.UUID
	OrderID   *uuid.UUID
	InvoiceID *uuid.UUID
	Items     []*CreateReturnItemRequest
}

type ReturnRefundPreviewResult struct {
	Subtotal           decimal.Decimal
	TaxRefund          decimal.Decimal
	DiscountAdjustment decimal.Decimal
	TotalRefund        decimal.Decimal
}

type GenerateCreditNoteRequest struct {
	IssuedBy uuid.UUID
}

type ProcessReturnRefundRequest struct {
	CompanyID  uuid.UUID
	ReturnID   uuid.UUID
	Amount     decimal.Decimal
	Reason     string
	RefundedBy uuid.UUID
}

// AnalyticsGranularity defines the time grouping for trends.
type AnalyticsGranularity string

const (
	GranularityDaily   AnalyticsGranularity = "daily"
	GranularityWeekly  AnalyticsGranularity = "weekly"
	GranularityMonthly AnalyticsGranularity = "monthly"
	GranularityYearly  AnalyticsGranularity = "yearly"
)

// SalesDashboardSummary contains high‑level sales KPIs.
type SalesDashboardSummary struct {
	Revenue                decimal.Decimal       `json:"revenue"`
	Orders                 int                   `json:"orders"`
	AverageOrderValue      decimal.Decimal       `json:"averageOrderValue"`
	ConversionRate         decimal.Decimal       `json:"conversionRate"`
	OutstandingReceivables decimal.Decimal       `json:"outstandingReceivables"`
	TopSellingProduct      *TopSellingProductRow `json:"topSellingProduct,omitempty"`
	TotalDiscounts         decimal.Decimal       `json:"totalDiscounts"`
	TotalTax               decimal.Decimal       `json:"totalTax"`
	UniqueCustomers        int                   `json:"uniqueCustomers"`
	PeriodStart            time.Time             `json:"periodStart"`
	PeriodEnd              time.Time             `json:"periodEnd"`
}

// TodaySalesSummary represents sales for the current calendar day.
type TodaySalesSummary struct {
	Date                     time.Time       `json:"date"`
	Revenue                  decimal.Decimal `json:"revenue"`
	OrdersCount              int             `json:"ordersCount"`
	AverageOrderValue        decimal.Decimal `json:"averageOrderValue"`
	InvoicesIssuedCount      int             `json:"invoicesIssuedCount"`
	InvoicesIssuedValue      decimal.Decimal `json:"invoicesIssuedValue"`
	PaymentsReceivedCount    int             `json:"paymentsReceivedCount"`
	PaymentsReceivedValue    decimal.Decimal `json:"paymentsReceivedValue"`
	UniqueCustomers          int             `json:"uniqueCustomers"`
	TopSellingProductName    string          `json:"topSellingProductName,omitempty"`
	TopSellingProductRevenue decimal.Decimal `json:"topSellingProductRevenue,omitempty"`
}

// RealtimeSalesSnapshot shows the current state of sales activity.
type RealtimeSalesSnapshot struct {
	LastHourRevenue      decimal.Decimal `json:"lastHourRevenue"`
	LastHourOrders       int             `json:"lastHourOrders"`
	TodayRevenue         decimal.Decimal `json:"todayRevenue"`
	TodayOrders          int             `json:"todayOrders"`
	PendingOrders        int             `json:"pendingOrders"`
	OverdueInvoicesCount int             `json:"overdueInvoicesCount"`
	OverdueInvoicesValue decimal.Decimal `json:"overdueInvoicesValue"`
	ActiveQuotesCount    int             `json:"activeQuotesCount"`
}

// RevenueSummary aggregates revenue metrics for a period.
type RevenueSummary struct {
	TotalRevenue        decimal.Decimal `json:"totalRevenue"`
	RevenueFromOrders   decimal.Decimal `json:"revenueFromOrders"`
	RevenueFromInvoices decimal.Decimal `json:"revenueFromInvoices"`
	CollectedRevenue    decimal.Decimal `json:"collectedRevenue"`
	RefundedAmount      decimal.Decimal `json:"refundedAmount"`
	NetRevenue          decimal.Decimal `json:"netRevenue"`
	PeriodStart         time.Time       `json:"periodStart"`
	PeriodEnd           time.Time       `json:"periodEnd"`
}

// RevenueTrendPoint is a single point in a revenue time series.
type RevenueTrendPoint struct {
	Date    time.Time       `json:"date"`
	Revenue decimal.Decimal `json:"revenue"`
}

// CustomerRevenueSummary summarises revenue per customer.
type CustomerRevenueSummary struct {
	CustomerID   uuid.UUID       `json:"customerId"`
	CustomerName string          `json:"customerName"`
	TotalRevenue decimal.Decimal `json:"totalRevenue"`
	OrderCount   int             `json:"orderCount"`
	AverageValue decimal.Decimal `json:"averageValue"`
}

// ProductRevenueSummary shows revenue and quantity sold per product.
type ProductRevenueSummary struct {
	ProductID    uuid.UUID       `json:"productId"`
	ProductName  string          `json:"productName"`
	SKU          string          `json:"sku"`
	QuantitySold decimal.Decimal `json:"quantitySold"`
	Revenue      decimal.Decimal `json:"revenue"`
}

// CategoryRevenueSummary groups revenue by product category.
type CategoryRevenueSummary struct {
	CategoryName string          `json:"categoryName"`
	Revenue      decimal.Decimal `json:"revenue"`
	Percentage   decimal.Decimal `json:"percentage"`
}

// SalesRepRevenueSummary shows revenue attributed to a sales representative.
type SalesRepRevenueSummary struct {
	SalesRepID   uuid.UUID       `json:"salesRepId"`
	SalesRepName string          `json:"salesRepName"`
	Revenue      decimal.Decimal `json:"revenue"`
	OrdersCount  int             `json:"ordersCount"`
}

// PaymentMethodRevenueSummary aggregates payments by method.
type PaymentMethodRevenueSummary struct {
	PaymentMethod string          `json:"paymentMethod"`
	TotalAmount   decimal.Decimal `json:"totalAmount"`
	Count         int             `json:"count"`
}

// TopCustomerRow contains data for customer ranking.
type TopCustomerRow struct {
	CustomerID   uuid.UUID       `json:"customerId"`
	CustomerName string          `json:"customerName"`
	TotalSpent   decimal.Decimal `json:"totalSpent"`
	OrderCount   int             `json:"orderCount"`
	LastOrder    time.Time       `json:"lastOrder,omitempty"`
}

// CustomerSalesSummary provides a full sales profile for one customer.
type CustomerSalesSummary struct {
	CustomerID         uuid.UUID       `json:"customerId"`
	CustomerName       string          `json:"customerName"`
	TotalOrders        int             `json:"totalOrders"`
	TotalRevenue       decimal.Decimal `json:"totalRevenue"`
	TotalInvoices      int             `json:"totalInvoices"`
	TotalPayments      decimal.Decimal `json:"totalPayments"`
	OutstandingBalance decimal.Decimal `json:"outstandingBalance"`
	AverageOrderValue  decimal.Decimal `json:"averageOrderValue"`
	LifetimeValue      decimal.Decimal `json:"lifetimeValue"`
	FirstOrderDate     *time.Time      `json:"firstOrderDate,omitempty"`
	LastOrderDate      *time.Time      `json:"lastOrderDate,omitempty"`
}

// CustomerOutstandingBalanceRow shows the amount a customer owes.
type CustomerOutstandingBalanceRow struct {
	CustomerID        uuid.UUID       `json:"customerId"`
	CustomerName      string          `json:"customerName"`
	OutstandingAmount decimal.Decimal `json:"outstandingAmount"`
	OverdueAmount     decimal.Decimal `json:"overdueAmount"`
}

// CustomerOverdueSummary details overdue invoices for a customer.
type CustomerOverdueSummary struct {
	CustomerID    uuid.UUID       `json:"customerId"`
	CustomerName  string          `json:"customerName"`
	OverdueAmount decimal.Decimal `json:"overdueAmount"`
	OverdueDays   int             `json:"overdueDays"`
}

// OrderSummary provides aggregated order statistics.
type OrderSummary struct {
	TotalOrders       int             `json:"totalOrders"`
	TotalRevenue      decimal.Decimal `json:"totalRevenue"`
	AverageOrderValue decimal.Decimal `json:"averageOrderValue"`
	CompletedOrders   int             `json:"completedOrders"`
	CancelledOrders   int             `json:"cancelledOrders"`
	RefundedOrders    int             `json:"refundedOrders"`
	PendingOrders     int             `json:"pendingOrders"`
	PeriodStart       time.Time       `json:"periodStart"`
	PeriodEnd         time.Time       `json:"periodEnd"`
}

// OrderStatusSummary counts orders by status.
type OrderStatusSummary struct {
	Status string          `json:"status"`
	Count  int             `json:"count"`
	Value  decimal.Decimal `json:"value"`
}

// AverageOrderValuePoint is a time‑bucketed AOV.
type AverageOrderValuePoint struct {
	Date time.Time       `json:"date"`
	AOV  decimal.Decimal `json:"aov"`
}

// OrderConversionFunnel tracks quote → order conversion.
type OrderConversionFunnel struct {
	TotalVisits     int             `json:"totalVisits"`
	QuotesCreated   int             `json:"quotesCreated"`
	OrdersCreated   int             `json:"ordersCreated"`
	OrdersCompleted int             `json:"ordersCompleted"`
	ConversionRate  decimal.Decimal `json:"conversionRate"`
}

// QuoteSummary aggregates quote statistics.
type QuoteSummary struct {
	TotalQuotes               int             `json:"totalQuotes"`
	TotalValue                decimal.Decimal `json:"totalValue"`
	ConvertedQuotes           int             `json:"convertedQuotes"`
	ConvertedValue            decimal.Decimal `json:"convertedValue"`
	ExpiredQuotes             int             `json:"expiredQuotes"`
	AverageConversionTimeDays decimal.Decimal `json:"averageConversionTimeDays"`
}

// QuoteConversionMetrics analyses what drives quote conversions.
type QuoteConversionMetrics struct {
	ConversionRate          decimal.Decimal `json:"conversionRate"`
	AverageConversionDays   decimal.Decimal `json:"averageConversionDays"`
	QuotesWithCoupon        int             `json:"quotesWithCoupon"`
	QuotesWithoutCoupon     int             `json:"quotesWithoutCoupon"`
	ConversionWithCoupon    decimal.Decimal `json:"conversionWithCoupon"`
	ConversionWithoutCoupon decimal.Decimal `json:"conversionWithoutCoupon"`
}

// InvoiceSummary provides invoice KPIs for a period.
type InvoiceSummary struct {
	TotalIssued       int             `json:"totalIssued"`
	TotalIssuedValue  decimal.Decimal `json:"totalIssuedValue"`
	TotalPaid         int             `json:"totalPaid"`
	TotalPaidValue    decimal.Decimal `json:"totalPaidValue"`
	TotalOverdue      int             `json:"totalOverdue"`
	TotalOverdueValue decimal.Decimal `json:"totalOverdueValue"`
	TotalCancelled    int             `json:"totalCancelled"`
	PeriodStart       time.Time       `json:"periodStart"`
	PeriodEnd         time.Time       `json:"periodEnd"`
}

// OutstandingReceivablesSummary shows the state of uncollected revenue.
type OutstandingReceivablesSummary struct {
	TotalReceivables   decimal.Decimal `json:"totalReceivables"`
	CurrentReceivables decimal.Decimal `json:"currentReceivables"`
	OverdueReceivables decimal.Decimal `json:"overdueReceivables"`
	Overdue30Days      decimal.Decimal `json:"overdue30Days"`
	Overdue60Days      decimal.Decimal `json:"overdue60Days"`
	Overdue90Days      decimal.Decimal `json:"overdue90Days"`
	OverdueOver90Days  decimal.Decimal `json:"overdueOver90Days"`
}

// InvoiceAgingBucket groups overdue invoices by age.
type InvoiceAgingBucket struct {
	BucketName string          `json:"bucketName"`
	Amount     decimal.Decimal `json:"amount"`
	Count      int             `json:"count"`
}

// CollectionTrendPoint tracks collection efficiency over time.
type CollectionTrendPoint struct {
	Date           time.Time       `json:"date"`
	Collected      decimal.Decimal `json:"collected"`
	Outstanding    decimal.Decimal `json:"outstanding"`
	CollectionRate decimal.Decimal `json:"collectionRate"`
}

// PaymentSummary aggregates payments and refunds.
type PaymentSummary struct {
	TotalPayments  decimal.Decimal `json:"totalPayments"`
	TotalRefunds   decimal.Decimal `json:"totalRefunds"`
	NetCollections decimal.Decimal `json:"netCollections"`
	PaymentCount   int             `json:"paymentCount"`
	AveragePayment decimal.Decimal `json:"averagePayment"`
	FailedPayments int             `json:"failedPayments"`
	PeriodStart    time.Time       `json:"periodStart"`
	PeriodEnd      time.Time       `json:"periodEnd"`
}

// PaymentMethodBreakdownRow shows per‑method payment stats.
type PaymentMethodBreakdownRow struct {
	PaymentMethod string          `json:"paymentMethod"`
	TotalAmount   decimal.Decimal `json:"totalAmount"`
	Count         int             `json:"count"`
	Percentage    decimal.Decimal `json:"percentage"`
}

// FailedPaymentAnalytics provides insight into failed payments.
type FailedPaymentAnalytics struct {
	TotalFailed       int             `json:"totalFailed"`
	TotalFailedAmount decimal.Decimal `json:"totalFailedAmount"`
	ByReason          map[string]int  `json:"byReason"`
	ByMethod          map[string]int  `json:"byMethod"`
}

// RefundSummary aggregates refunds and credit notes.
type RefundSummary struct {
	TotalRefunds        decimal.Decimal `json:"totalRefunds"`
	RefundCount         int             `json:"refundCount"`
	AverageRefundAmount decimal.Decimal `json:"averageRefundAmount"`
	FullRefunds         int             `json:"fullRefunds"`
	PartialRefunds      int             `json:"partialRefunds"`
	CreditNotesIssued   decimal.Decimal `json:"creditNotesIssued"`
}

// TopSellingProductRow ranks products by revenue.
type TopSellingProductRow struct {
	ProductID    uuid.UUID       `json:"productId"`
	ProductName  string          `json:"productName"`
	QuantitySold decimal.Decimal `json:"quantitySold"`
	Revenue      decimal.Decimal `json:"revenue"`
}

// LeastSellingProductRow ranks products by lowest revenue.
type LeastSellingProductRow struct {
	ProductID    uuid.UUID       `json:"productId"`
	ProductName  string          `json:"productName"`
	QuantitySold decimal.Decimal `json:"quantitySold"`
	Revenue      decimal.Decimal `json:"revenue"`
}

// ProductSalesTrendPoint shows sales over time for a single product.
type ProductSalesTrendPoint struct {
	Date         time.Time       `json:"date"`
	QuantitySold decimal.Decimal `json:"quantitySold"`
	Revenue      decimal.Decimal `json:"revenue"`
}

// MostReturnedProductRow identifies frequently returned products.
type MostReturnedProductRow struct {
	ProductID    uuid.UUID       `json:"productId"`
	ProductName  string          `json:"productName"`
	ReturnCount  int             `json:"returnCount"`
	ReturnAmount decimal.Decimal `json:"returnAmount"`
}

// ReturnSummary provides high‑level return metrics.
type ReturnSummary struct {
	TotalReturns          int             `json:"totalReturns"`
	ApprovedReturns       int             `json:"approvedReturns"`
	CompletedReturns      int             `json:"completedReturns"`
	RejectedReturns       int             `json:"rejectedReturns"`
	TotalRefundAmount     decimal.Decimal `json:"totalRefundAmount"`
	TotalCreditNoteAmount decimal.Decimal `json:"totalCreditNoteAmount"`
	ReturnRate            decimal.Decimal `json:"returnRate"`
}

// ReturnRateTrendPoint shows the return rate over time.
type ReturnRateTrendPoint struct {
	Date       time.Time       `json:"date"`
	ReturnRate decimal.Decimal `json:"returnRate"`
}

// RefundLiabilitySummary shows future refund obligations.
type RefundLiabilitySummary struct {
	PendingRefunds         decimal.Decimal `json:"pendingRefunds"`
	ApprovedRefunds        decimal.Decimal `json:"approvedRefunds"`
	CompletedRefunds       decimal.Decimal `json:"completedRefunds"`
	OutstandingCreditNotes decimal.Decimal `json:"outstandingCreditNotes"`
	TotalLiability         decimal.Decimal `json:"totalLiability"`
}

// DiscountSummary aggregates all discount usage.
type DiscountSummary struct {
	TotalDiscountAmount    decimal.Decimal `json:"totalDiscountAmount"`
	TotalCouponDiscount    decimal.Decimal `json:"totalCouponDiscount"`
	TotalPromotionDiscount decimal.Decimal `json:"totalPromotionDiscount"`
	TotalAutoDiscount      decimal.Decimal `json:"totalAutoDiscount"`
	AverageDiscountRate    decimal.Decimal `json:"averageDiscountRate"`
	UniqueCouponsUsed      int             `json:"uniqueCouponsUsed"`
	UniquePromotionsUsed   int             `json:"uniquePromotionsUsed"`
}

// CouponPerformanceRow shows how a coupon performed.
type CouponPerformanceRow struct {
	CouponID        uuid.UUID       `json:"couponId"`
	CouponCode      string          `json:"couponCode"`
	TimesUsed       int             `json:"timesUsed"`
	TotalDiscount   decimal.Decimal `json:"totalDiscount"`
	AverageDiscount decimal.Decimal `json:"averageDiscount"`
	UniqueCustomers int             `json:"uniqueCustomers"`
}

// PromotionPerformanceRow shows how a promotion performed.
type PromotionPerformanceRow struct {
	PromotionID     uuid.UUID       `json:"promotionId"`
	PromotionName   string          `json:"promotionName"`
	TimesUsed       int             `json:"timesUsed"`
	TotalDiscount   decimal.Decimal `json:"totalDiscount"`
	AverageDiscount decimal.Decimal `json:"averageDiscount"`
	UniqueCustomers int             `json:"uniqueCustomers"`
}

// DiscountRevenueImpact quantifies the effect of discounts on revenue.
type DiscountRevenueImpact struct {
	GrossRevenue       decimal.Decimal `json:"grossRevenue"`
	DiscountAmount     decimal.Decimal `json:"discountAmount"`
	NetRevenue         decimal.Decimal `json:"netRevenue"`
	DiscountPercentage decimal.Decimal `json:"discountPercentage"`
	IncrementalRevenue decimal.Decimal `json:"incrementalRevenue"`
}

// TaxSummary aggregates tax collected.
type TaxSummary struct {
	TotalTaxableAmount decimal.Decimal `json:"totalTaxableAmount"`
	TotalTaxAmount     decimal.Decimal `json:"totalTaxAmount"`
	EffectiveTaxRate   decimal.Decimal `json:"effectiveTaxRate"`
}

// TaxRateBreakdownRow shows tax collected per rate.
type TaxRateBreakdownRow struct {
	TaxRateName   string          `json:"taxRateName"`
	TaxPercentage decimal.Decimal `json:"taxPercentage"`
	TaxableAmount decimal.Decimal `json:"taxableAmount"`
	TaxAmount     decimal.Decimal `json:"taxAmount"`
}

// JurisdictionTaxBreakdownRow shows tax collected per jurisdiction.
type JurisdictionTaxBreakdownRow struct {
	Jurisdiction  string          `json:"jurisdiction"`
	TaxableAmount decimal.Decimal `json:"taxableAmount"`
	TaxAmount     decimal.Decimal `json:"taxAmount"`
}

// ProductTaxBreakdownRow shows tax collected per product.
type ProductTaxBreakdownRow struct {
	ProductID     uuid.UUID       `json:"productId"`
	ProductName   string          `json:"productName"`
	TaxableAmount decimal.Decimal `json:"taxableAmount"`
	TaxAmount     decimal.Decimal `json:"taxAmount"`
}

// CollectedTaxTrendPoint shows tax collected over time.
type CollectedTaxTrendPoint struct {
	Date         time.Time       `json:"date"`
	TaxCollected decimal.Decimal `json:"taxCollected"`
}

// TaxAuditReportRow is a single line in a tax audit.
type TaxAuditReportRow struct {
	EntityType    string          `json:"entityType"`
	EntityID      uuid.UUID       `json:"entityId"`
	TaxableAmount decimal.Decimal `json:"taxableAmount"`
	TaxAmount     decimal.Decimal `json:"taxAmount"`
	TaxRate       decimal.Decimal `json:"taxRate"`
	CreatedAt     time.Time       `json:"createdAt"`
}

// SalesRepPerformanceSummary provides commission and sales data for a rep.
type SalesRepPerformanceSummary struct {
	SalesRepID         uuid.UUID       `json:"salesRepId"`
	Name               string          `json:"name"`
	TotalRevenue       decimal.Decimal `json:"totalRevenue"`
	TotalOrders        int             `json:"totalOrders"`
	AverageOrderValue  decimal.Decimal `json:"averageOrderValue"`
	TotalCommission    decimal.Decimal `json:"totalCommission"`
	TargetAmount       decimal.Decimal `json:"targetAmount"`
	AchievementPercent decimal.Decimal `json:"achievementPercent"`
}

// SalesLeaderboardRow ranks sales representatives.
type SalesLeaderboardRow struct {
	Rank        int             `json:"rank"`
	SalesRepID  uuid.UUID       `json:"salesRepId"`
	Name        string          `json:"name"`
	Revenue     decimal.Decimal `json:"revenue"`
	OrdersCount int             `json:"ordersCount"`
	Commission  decimal.Decimal `json:"commission"`
}

// CommissionSummary aggregates commission data.
type CommissionSummary struct {
	TotalEarned           decimal.Decimal `json:"totalEarned"`
	TotalPaid             decimal.Decimal `json:"totalPaid"`
	TotalPending          decimal.Decimal `json:"totalPending"`
	TotalApproved         decimal.Decimal `json:"totalApproved"`
	AverageCommissionRate decimal.Decimal `json:"averageCommissionRate"`
	PeriodStart           time.Time       `json:"periodStart"`
	PeriodEnd             time.Time       `json:"periodEnd"`
}

// CreditRiskSummary provides a company‑wide view of credit risk.
type CreditRiskSummary struct {
	TotalCreditLimit        decimal.Decimal `json:"totalCreditLimit"`
	TotalOutstanding        decimal.Decimal `json:"totalOutstanding"`
	TotalAvailableCredit    decimal.Decimal `json:"totalAvailableCredit"`
	AverageUtilization      decimal.Decimal `json:"averageUtilization"`
	CustomersExceedingLimit int             `json:"customersExceedingLimit"`
	CustomersNearLimit      int             `json:"customersNearLimit"`
	OrdersOnCreditHold      int             `json:"ordersOnCreditHold"`
}

// CustomerCreditUtilizationRow shows utilisation per customer.
type CustomerCreditUtilizationRow struct {
	CustomerID     uuid.UUID       `json:"customerId"`
	CustomerName   string          `json:"customerName"`
	CreditLimit    decimal.Decimal `json:"creditLimit"`
	Outstanding    decimal.Decimal `json:"outstanding"`
	UtilizationPct decimal.Decimal `json:"utilizationPct"`
}

// CustomerCreditExposureRow shows customers that exceeded their limit.
type CustomerCreditExposureRow struct {
	CustomerID   uuid.UUID       `json:"customerId"`
	CustomerName string          `json:"customerName"`
	CreditLimit  decimal.Decimal `json:"creditLimit"`
	Outstanding  decimal.Decimal `json:"outstanding"`
	ExceedAmount decimal.Decimal `json:"exceedAmount"`
}

// SalesReportRequest defines parameters for the sales report.
type SalesReportRequest struct {
	CompanyID      uuid.UUID
	From           *time.Time
	To             *time.Time
	Granularity    AnalyticsGranularity
	IncludeDetails bool
}

// SalesReportResult is the output of a sales report.
type SalesReportResult struct {
	Summary      *SalesDashboardSummary
	Trend        []*RevenueTrendPoint
	TopCustomers []*TopCustomerRow
	TopProducts  []*TopSellingProductRow
}

// TaxReportRequest defines parameters for the tax report.
type TaxReportRequest struct {
	CompanyID   uuid.UUID
	From        *time.Time
	To          *time.Time
	Granularity AnalyticsGranularity
}

// TaxReportResult is the output of a tax report.
type TaxReportResult struct {
	Summary        *TaxSummary
	ByRate         []*TaxRateBreakdownRow
	ByJurisdiction []*JurisdictionTaxBreakdownRow
	Trend          []*CollectedTaxTrendPoint
}

// ReceivablesReportRequest defines parameters for the receivables report.
type ReceivablesReportRequest struct {
	CompanyID uuid.UUID
	AsOf      time.Time
}

// ReceivablesReportResult is the output of a receivables report.
type ReceivablesReportResult struct {
	TotalOutstanding decimal.Decimal
	AgingBuckets     []*InvoiceAgingBucket
	ByCustomer       []*CustomerOutstandingBalanceRow
}

// CustomerStatementResult shows a customer's financial activity.
type CustomerStatementResult struct {
	CustomerID     uuid.UUID
	CustomerName   string
	PeriodStart    time.Time
	PeriodEnd      time.Time
	OpeningBalance decimal.Decimal
	Invoices       []*models.Invoice
	Payments       []*models.Payment
	CreditNotes    []*models.CreditNote
	ClosingBalance decimal.Decimal
}

// SalesAuditEntry represents a single audit log entry.
type SalesAuditEntry struct {
	EntityType  string          `json:"entityType"`
	EntityID    uuid.UUID       `json:"entityId"`
	Action      string          `json:"action"`
	Changes     json.RawMessage `json:"changes"`
	PerformedBy uuid.UUID       `json:"performedBy"`
	PerformedAt time.Time       `json:"performedAt"`
}

type CreateCommissionPlanRequest struct {
	CompanyID     uuid.UUID             `json:"company_id"`
	Code          string                `json:"code"`
	Name          string                `json:"name"`
	Description   *string               `json:"description,omitempty"`
	EffectiveFrom time.Time             `json:"effective_from"`
	EffectiveTo   *time.Time            `json:"effective_to,omitempty"`
	IsActive      bool                  `json:"is_active"`
	CreatedBy     *uuid.UUID            `json:"created_by,omitempty"`
	Rules         []CommissionRuleInput `json:"rules"`
}

type UpdateCommissionPlanRequest struct {
	Name          *string    `json:"name,omitempty"`
	Description   *string    `json:"description,omitempty"`
	EffectiveFrom *time.Time `json:"effective_from,omitempty"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty"`
	IsActive      *bool      `json:"is_active,omitempty"`
	UpdatedBy     *uuid.UUID `json:"updated_by,omitempty"`
}

type CommissionPlanListFilter struct {
	CompanyID uuid.UUID
	IsActive  *bool
	Code      *string
	Name      *string
	Effective *time.Time // return plans effective at this time
}

type CreateCommissionRuleRequest struct {
	CompanyID    uuid.UUID                `json:"company_id"`
	PlanID       uuid.UUID                `json:"plan_id"`
	RuleType     enums.CommissionRuleType `json:"rule_type"`
	AppliesTo    enums.CommissionBaseType `json:"applies_to"`
	ProductID    *uuid.UUID               `json:"product_id,omitempty"`
	TierMin      *decimal.Decimal         `json:"tier_min,omitempty"`
	TierMax      *decimal.Decimal         `json:"tier_max,omitempty"`
	Rate         decimal.Decimal          `json:"rate"`
	IsPercentage bool                     `json:"is_percentage"`
	Priority     int                      `json:"priority"`
	CreatedBy    *uuid.UUID               `json:"created_by,omitempty"`
}

type UpdateCommissionRuleRequest struct {
	RuleType     *enums.CommissionRuleType `json:"rule_type,omitempty"`
	AppliesTo    *enums.CommissionBaseType `json:"applies_to,omitempty"`
	ProductID    *uuid.UUID                `json:"product_id,omitempty"`
	TierMin      *decimal.Decimal          `json:"tier_min,omitempty"`
	TierMax      *decimal.Decimal          `json:"tier_max,omitempty"`
	Rate         *decimal.Decimal          `json:"rate,omitempty"`
	IsPercentage *bool                     `json:"is_percentage,omitempty"`
	Priority     *int                      `json:"priority,omitempty"`
	UpdatedBy    *uuid.UUID                `json:"updated_by,omitempty"`
}

type CommissionPreviewRequest struct {
	CompanyID     uuid.UUID                     `json:"company_id"`
	SalesRepID    uuid.UUID                     `json:"sales_rep_id"`
	ReferenceType enums.CommissionReferenceType `json:"reference_type"`
	ReferenceID   uuid.UUID                     `json:"reference_id"`
	CalculationAt time.Time                     `json:"calculation_at"`
}

type CommissionPreviewResult struct {
	BaseAmount       decimal.Decimal `json:"base_amount"`
	ApplicableRate   decimal.Decimal `json:"applicable_rate"`
	CommissionAmount decimal.Decimal `json:"commission_amount"`
	RuleID           *uuid.UUID      `json:"rule_id,omitempty"`
}

type CreateSalesCommissionRequest struct {
	CompanyID        uuid.UUID                     `json:"company_id"`
	SalesRepID       uuid.UUID                     `json:"sales_rep_id"`
	ReferenceType    enums.CommissionReferenceType `json:"reference_type"`
	ReferenceID      uuid.UUID                     `json:"reference_id"`
	CommissionBase   decimal.Decimal               `json:"commission_base"`
	CommissionRate   decimal.Decimal               `json:"commission_rate"`
	CommissionAmount decimal.Decimal               `json:"commission_amount"`
	EarnedAt         time.Time                     `json:"earned_at"`
	Status           enums.CommissionStatus        `json:"status"`
	CreatedBy        *uuid.UUID                    `json:"created_by,omitempty"`
}

type UpdateSalesCommissionRequest struct {
	Status       *enums.CommissionStatus `json:"status,omitempty"`
	PaidAt       *time.Time              `json:"paid_at,omitempty"`
	ApprovedAt   *time.Time              `json:"approved_at,omitempty"`
	RejectedAt   *time.Time              `json:"rejected_at,omitempty"`
	RejectReason *string                 `json:"reject_reason,omitempty"`
	UpdatedBy    *uuid.UUID              `json:"updated_by,omitempty"`
}

type SalesCommissionListFilter struct {
	CompanyID     uuid.UUID
	SalesRepID    *uuid.UUID
	ReferenceType *enums.CommissionReferenceType
	ReferenceID   *uuid.UUID
	Status        *enums.CommissionStatus
	EarnedFrom    *time.Time
	EarnedTo      *time.Time
}

type SalesRepCommissionSummary struct {
	SalesRepID    uuid.UUID       `json:"sales_rep_id"`
	TotalEarned   decimal.Decimal `json:"total_earned"`
	TotalApproved decimal.Decimal `json:"total_approved"`
	TotalPaid     decimal.Decimal `json:"total_paid"`
	PendingCount  int             `json:"pending_count"`
	ApprovedCount int             `json:"approved_count"`
	PaidCount     int             `json:"paid_count"`
	RejectedCount int             `json:"rejected_count"`
}

// CommissionTrendPoint is re‑exported from repository – same struct

type CommissionRuleInput struct {
	RuleType     enums.CommissionRuleType `json:"rule_type"`
	AppliesTo    enums.CommissionBaseType `json:"applies_to"`
	ProductID    *uuid.UUID               `json:"product_id,omitempty"`
	TierMin      *decimal.Decimal         `json:"tier_min,omitempty"`
	TierMax      *decimal.Decimal         `json:"tier_max,omitempty"`
	Rate         decimal.Decimal          `json:"rate"`
	IsPercentage bool                     `json:"is_percentage"`
	Priority     int                      `json:"priority"`
}

type CommissionCalculationValidationRequest struct {
	CompanyID        uuid.UUID                     `json:"company_id"`
	SalesRepID       uuid.UUID                     `json:"sales_rep_id"`
	ReferenceType    enums.CommissionReferenceType `json:"reference_type"`
	ReferenceID      uuid.UUID                     `json:"reference_id"`
	CalculatedAmount decimal.Decimal               `json:"calculated_amount"`
}

type CalculateOrderTaxRequest struct {
	CompanyID      uuid.UUID
	OrderID        uuid.UUID
	LineItems      []*LineItemInput
	CustomerID     *uuid.UUID
	BillingAddress *AddressInput
}

type CalculateQuoteTaxRequest struct {
	CompanyID      uuid.UUID
	QuoteID        uuid.UUID
	LineItems      []*LineItemInput
	CustomerID     *uuid.UUID
	BillingAddress *AddressInput
}

type CalculateInvoiceTaxRequest struct {
	CompanyID      uuid.UUID
	InvoiceID      uuid.UUID
	LineItems      []*LineItemInput
	CustomerID     *uuid.UUID
	BillingAddress *AddressInput
}

type CalculateReturnTaxRequest struct {
	CompanyID      uuid.UUID
	ReturnID       uuid.UUID
	LineItems      []*LineItemInput
	CustomerID     *uuid.UUID
	BillingAddress *AddressInput
}

type CalculateLineTaxRequest struct {
	CompanyID      uuid.UUID
	ProductID      uuid.UUID
	LineAmount     decimal.Decimal
	TaxableAmount  decimal.Decimal
	CustomerID     *uuid.UUID
	BillingCountry string
	BillingState   *string
}

type TaxPreviewRequest struct {
	CompanyID      uuid.UUID
	LineItems      []*LineItemInput
	CustomerID     *uuid.UUID
	BillingAddress *AddressInput
}

type CreateTaxSnapshotRequest struct {
	CompanyID     uuid.UUID
	EntityType    string
	EntityID      uuid.UUID
	LineID        *uuid.UUID
	TaxRateID     *uuid.UUID
	TaxName       *string
	TaxPercentage *decimal.Decimal
	TaxableAmount decimal.Decimal
	TaxAmount     decimal.Decimal
}

type LineItemInput struct {
	ProductID     uuid.UUID
	Quantity      decimal.Decimal
	UnitPrice     decimal.Decimal
	LineAmount    decimal.Decimal // = quantity * unitPrice - discount + tax? Usually taxable before tax
	TaxableAmount decimal.Decimal // amount subject to tax (may be same as LineAmount)
}

type AddressInput struct {
	CountryCode string
	StateCode   string
	PostalCode  string
}

type TaxCalculationResult struct {
	TotalTax            decimal.Decimal
	LineTaxes           []TaxLineDetail
	TaxesByJurisdiction map[string]decimal.Decimal // tax name -> total tax amount for this rate
	ApplicableRates     map[string]decimal.Decimal // tax name -> taxable amount for this rate
	ExemptionsApplied   bool
}

type TaxLineDetail struct {
	ProductID     uuid.UUID
	LineAmount    decimal.Decimal
	TaxableAmount decimal.Decimal
	TaxAmount     decimal.Decimal
	TaxRateName   string
}

type TaxPreviewResult struct {
	TotalTax            decimal.Decimal
	LineTaxes           []TaxLineDetail
	TaxesByJurisdiction map[string]decimal.Decimal
	ApplicableRates     map[string]decimal.Decimal
	ExemptionsApplied   bool
}

type TaxLineResult struct {
	TaxAmount      decimal.Decimal
	ApplicableRate decimal.Decimal
	Details        interface{} // optional breakdown
}

type TaxBreakdownLine struct {
	TaxName       *string
	TaxPercentage *decimal.Decimal
	TaxableAmount decimal.Decimal
	TaxAmount     decimal.Decimal
}
