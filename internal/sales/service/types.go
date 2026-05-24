// file: internal/sales/service/types.go
package service

import (
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
	CompanyID  uuid.UUID
	CustomerID *uuid.UUID
	Status     *enums.OrderStatus
	SalesRepID *uuid.UUID
	FromDate   *time.Time
	ToDate     *time.Time
	MinTotal   *decimal.Decimal
	MaxTotal   *decimal.Decimal
	Search     *string
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
