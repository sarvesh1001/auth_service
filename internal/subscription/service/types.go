package service

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"

	"auth-service/internal/subscription/models"
)

// -------------------- Request DTOs --------------------

type CreateSubscriptionRequest struct {
	CompanyID    uuid.UUID
	CustomerID   uuid.UUID
	PlanID       uuid.UUID
	AddonIDs     []uuid.UUID
	CouponID     *uuid.UUID
	StartDate    *time.Time
	Currency     string
	SalesOrderID *uuid.UUID
	CreatedBy    uuid.UUID
}

type CreateTrialCheckoutRequest struct {
	CompanyID  uuid.UUID
	CustomerID uuid.UUID
	PlanID     uuid.UUID
	TrialDays  *int
	AddonIDs   []uuid.UUID
	CreatedBy  uuid.UUID
}

type CheckoutPreviewRequest struct {
	CompanyID  uuid.UUID
	CustomerID uuid.UUID
	PlanID     uuid.UUID
	AddonIDs   []uuid.UUID
	CouponID   *uuid.UUID
	StartDate  *time.Time
	Currency   string
}

type CheckoutValidationRequest struct {
	CompanyID  uuid.UUID
	CustomerID uuid.UUID
	PlanID     uuid.UUID
	AddonIDs   []uuid.UUID
	CouponID   *uuid.UUID
}

type CheckoutPricingRequest struct {
	CompanyID uuid.UUID
	PlanID    uuid.UUID
	AddonIDs  []uuid.UUID
	CouponID  *uuid.UUID
	Currency  string
}

type AddAddonRequest struct {
	CompanyID      uuid.UUID
	SubscriptionID uuid.UUID
	AddonID        uuid.UUID
	Quantity       int
	CreatedBy      uuid.UUID
}

type RemoveAddonRequest struct {
	CompanyID      uuid.UUID
	SubscriptionID uuid.UUID
	AddonID        uuid.UUID
	RemovedBy      uuid.UUID
}

type ApplyCouponRequest struct {
	CompanyID      uuid.UUID
	SubscriptionID uuid.UUID
	CouponID       uuid.UUID
	AppliedBy      uuid.UUID
}

// -------------------- Result DTOs --------------------

type CheckoutResult struct {
	Subscription *models.Subscription
	InvoiceID    *uuid.UUID
	TrialID      *uuid.UUID
	TimelineID   *uuid.UUID
	TotalAmount  decimal.Decimal
}

type CheckoutPricingResult struct {
	BaseAmount      decimal.Decimal
	AddonAmount     decimal.Decimal
	DiscountAmount  decimal.Decimal
	TaxAmount       decimal.Decimal
	ProrationAmount decimal.Decimal
	GrandTotal      decimal.Decimal
}

type CheckoutPreview struct {
	Plan    *models.Plan
	Items   []*models.PlanItem
	Addons  []*models.Addon
	Pricing *CheckoutPricingResult
}

type CouponResult struct {
	Valid    bool
	Discount decimal.Decimal
	Message  string
}

type CheckoutQuote struct {
	Pricing   *CheckoutPricingResult
	ExpiresAt time.Time
}
type PlanVersionComparison struct {
	LeftVersion  *models.PlanVersion
	RightVersion *models.PlanVersion

	PlanChanged          bool
	ItemsChanged         bool
	BenefitsChanged      bool
	EntitlementsChanged  bool
	BillingPolicyChanged bool
	RenewalPolicyChanged bool
	PausePolicyChanged   bool
	ProrationChanged     bool

	Changes []PlanChange
}

type PlanChange struct {
	Entity string
	Field  string
	Old    any
	New    any
}

type ClonePlanRequest struct {
	Name              string
	Code              string // not used in this version; can be used for plan name uniqueness
	CreateNewVersion  bool   // not used; versioning is separate
	CloneItems        bool
	CloneBenefits     bool
	CloneEntitlements bool
	ClonePolicies     bool
	CreatedBy         uuid.UUID
}

type PlanClonePreview struct {
	Items          int
	Benefits       int
	Entitlements   int
	Policies       int
	EstimatedSteps int
}
