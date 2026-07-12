// internal/subscription/events/events.go
package events

// ----------------------------------------------------------------------------
// Topics
// ----------------------------------------------------------------------------

const (
	TopicSubscriptionEvents = "subscription-events"
	TopicPlanItemEvents     = TopicSubscriptionEvents
)

// ----------------------------------------------------------------------------
// Subscription lifecycle events
// ----------------------------------------------------------------------------

const (
	EventSubscriptionCreated    = "subscription.created"
	EventSubscriptionActivated  = "subscription.activated"
	EventSubscriptionPaused     = "subscription.paused"
	EventSubscriptionResumed    = "subscription.resumed"
	EventSubscriptionRenewed    = "subscription.renewed"
	EventSubscriptionExpired    = "subscription.expired"
	EventSubscriptionCancelled  = "subscription.cancelled"
	EventSubscriptionUpgraded   = "subscription.upgraded"
	EventSubscriptionDowngraded = "subscription.downgraded"
	EventSubscriptionChanged    = "subscription.changed"

	// New subscription lifecycle events
	EventSubscriptionUpdated           = "subscription.updated"
	EventSubscriptionDeleted           = "subscription.deleted"
	EventSubscriptionCustomerAssigned  = "subscription.customer_assigned"
	EventSubscriptionPlanAssigned      = "subscription.plan_assigned"
	EventSubscriptionSalesOrderUpdated = "subscription.sales_order_updated"
	EventSubscriptionAutoRenewUpdated  = "subscription.auto_renew_updated"
	EventSubscriptionCouponUpdated     = "subscription.coupon_updated"
)

// SubscriptionPayload carries the core subscription data for events.
type SubscriptionPayload struct {
	SubscriptionID string `json:"subscription_id"`
	CompanyID      string `json:"company_id"`
	CustomerID     string `json:"customer_id"`
	PlanID         string `json:"plan_id"`
	Status         string `json:"status"`
	StartDate      string `json:"start_date"`
	EndDate        string `json:"end_date,omitempty"`
	TrialEnd       string `json:"trial_end,omitempty"`
	AutoRenew      bool   `json:"auto_renew"`
	Currency       string `json:"currency"`
	TotalAmount    string `json:"total_amount,omitempty"`
	ContractNumber string `json:"contract_number,omitempty"`
	CouponID       string `json:"coupon_id,omitempty"`
	SalesOrderID   string `json:"sales_order_id,omitempty"`
	Version        int    `json:"version"`
}

// SubscriptionDeletedPayload for deletion events.
type SubscriptionDeletedPayload struct {
	SubscriptionID string `json:"subscription_id"`
	CompanyID      string `json:"company_id"`
	DeletedAt      string `json:"deleted_at"`
}

// SubscriptionAssignmentPayload for customer/plan assignment.
type SubscriptionAssignmentPayload struct {
	SubscriptionID string `json:"subscription_id"`
	CompanyID      string `json:"company_id"`
	CustomerID     string `json:"customer_id,omitempty"`
	OldCustomerID  string `json:"old_customer_id,omitempty"`
	PlanID         string `json:"plan_id,omitempty"`
	OldPlanID      string `json:"old_plan_id,omitempty"`
	AssignedAt     string `json:"assigned_at"`
}

// SubscriptionSalesOrderPayload for sales order updates.
type SubscriptionSalesOrderPayload struct {
	SubscriptionID string `json:"subscription_id"`
	CompanyID      string `json:"company_id"`
	SalesOrderID   string `json:"sales_order_id"`
	UpdatedAt      string `json:"updated_at"`
}

// SubscriptionAutoRenewPayload for auto‑renew toggles.
type SubscriptionAutoRenewPayload struct {
	SubscriptionID string `json:"subscription_id"`
	CompanyID      string `json:"company_id"`
	AutoRenew      bool   `json:"auto_renew"`
	UpdatedAt      string `json:"updated_at"`
}

// SubscriptionCouponPayload for coupon updates.
type SubscriptionCouponPayload struct {
	SubscriptionID string  `json:"subscription_id"`
	CompanyID      string  `json:"company_id"`
	CouponID       *string `json:"coupon_id,omitempty"`
	UpdatedAt      string  `json:"updated_at"`
}

// ----------------------------------------------------------------------------
// Trial events
// ----------------------------------------------------------------------------

const (
	EventTrialStarted   = "subscription.trial.started"
	EventTrialEnded     = "subscription.trial.ended"
	EventTrialConverted = "subscription.trial.converted"
	EventTrialCancelled = "subscription.trial.cancelled"
)

type TrialPayload struct {
	TrialID        string `json:"trial_id"`
	SubscriptionID string `json:"subscription_id"`
	CompanyID      string `json:"company_id"`
	StartedAt      string `json:"started_at"`
	EndedAt        string `json:"ended_at,omitempty"`
	TrialDays      int    `json:"trial_days"`
	Status         string `json:"status"`
}

// ----------------------------------------------------------------------------
// Plan events (CRUD & lifecycle)
// ----------------------------------------------------------------------------

const (
	EventPlanCreated      = "subscription.plan.created"
	EventPlanUpdated      = "subscription.plan.updated"
	EventPlanDeleted      = "subscription.plan.deleted"
	EventPlanActivated    = "subscription.plan.activated"
	EventPlanDeactivated  = "subscription.plan.deactivated"
	EventPlanArchived     = "subscription.plan.archived"
	EventPlanRestored     = "subscription.plan.restored"
	EventPlanPriceUpdated = "subscription.plan.price_updated"

	// Cloning events
	EventPlanCloned             = "subscription.plan.cloned"
	EventPlanItemsCloned        = "subscription.plan.items.cloned"
	EventPlanBenefitsCloned     = "subscription.plan.benefits.cloned"
	EventPlanEntitlementsCloned = "subscription.plan.entitlements.cloned"
	EventBillingPolicyCloned    = "subscription.plan.billing_policy.cloned"
	EventRenewalPolicyCloned    = "subscription.plan.renewal_policy.cloned"
	EventPausePolicyCloned      = "subscription.plan.pause_policy.cloned"
	EventProrationPolicyCloned  = "subscription.plan.proration_policy.cloned"
)

type PlanPayload struct {
	PlanID            string `json:"plan_id"`
	CompanyID         string `json:"company_id"`
	Name              string `json:"name"`
	PlanType          string `json:"plan_type"`
	BillingPolicyID   string `json:"billing_policy_id"`
	RenewalPolicyID   string `json:"renewal_policy_id"`
	PausePolicyID     string `json:"pause_policy_id"`
	ProrationPolicyID string `json:"proration_policy_id"`
	DurationDays      int    `json:"duration_days"`
	IsActive          bool   `json:"is_active"`
	Version           int    `json:"version"`
}

// ----------------------------------------------------------------------------
// Plan version events
// ----------------------------------------------------------------------------

const (
	EventPlanVersionCreated     = "subscription.plan_version.created"
	EventPlanVersionPublished   = "subscription.plan_version.published"
	EventPlanVersionUnpublished = "subscription.plan_version.unpublished"
	EventPlanVersionRestored    = "subscription.plan_version.restored"
	EventPlanVersionArchived    = "subscription.plan_version.archived"
	EventPlanVersionCloned      = "subscription.plan_version.cloned"
	EventPlanVersionRollback    = "subscription.plan_version.rollback"
)

type PlanVersionPayload struct {
	VersionID     string `json:"version_id"`
	PlanID        string `json:"plan_id"`
	CompanyID     string `json:"company_id"`
	VersionNumber int    `json:"version_number"`
	IsPublished   bool   `json:"is_published"`
}

// ----------------------------------------------------------------------------
// Subscription provisioning events
// ----------------------------------------------------------------------------

const (
	EventSubscriptionProvisioned    = "subscription.provisioned"
	EventSubscriptionDeprovisioned  = "subscription.deprovisioned"
	EventSubscriptionReprovisioned  = "subscription.reprovisioned"
	EventSubscriptionItemsCreated   = "subscription.items.created"
	EventSubscriptionItemsRefreshed = "subscription.items.refreshed"
	EventSubscriptionItemsRemoved   = "subscription.items.removed"
)

// ----------------------------------------------------------------------------
// Subscription Item events (new)
// ----------------------------------------------------------------------------

const (
	EventSubscriptionItemCreated         = "subscription.item.created"
	EventSubscriptionItemUpdated         = "subscription.item.updated"
	EventSubscriptionItemDeleted         = "subscription.item.deleted"
	EventSubscriptionItemActivated       = "subscription.item.activated"
	EventSubscriptionItemDeactivated     = "subscription.item.deactivated"
	EventSubscriptionItemRestored        = "subscription.item.restored"
	EventSubscriptionItemReplaced        = "subscription.item.replaced"
	EventSubscriptionItemQuantityUpdated = "subscription.item.quantity_updated"
	EventSubscriptionItemPriceUpdated    = "subscription.item.price_updated"
)

// SubscriptionItemPayload carries the core subscription item data for events.
type SubscriptionItemPayload struct {
	SubItemID      string                 `json:"sub_item_id"`
	SubscriptionID string                 `json:"subscription_id"`
	PlanItemID     string                 `json:"plan_item_id"`
	AddonID        string                 `json:"addon_id,omitempty"`
	Quantity       string                 `json:"quantity"`
	UnitPrice      string                 `json:"unit_price"`
	TotalPrice     string                 `json:"total_price"`
	Currency       string                 `json:"currency"`
	Status         string                 `json:"status"`
	StartDate      string                 `json:"start_date"`
	EndDate        string                 `json:"end_date,omitempty"`
	ProductID      string                 `json:"product_id,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// ----------------------------------------------------------------------------
// Plan Item events (new)
// ----------------------------------------------------------------------------

const (
	EventPlanItemCreated      = "plan_item.created"
	EventPlanItemUpdated      = "plan_item.updated"
	EventPlanItemDeleted      = "plan_item.deleted"
	EventPlanItemActivated    = "plan_item.activated"
	EventPlanItemDeactivated  = "plan_item.deactivated"
	EventPlanItemRestored     = "plan_item.restored"
	EventPlanItemPriceUpdated = "plan_item.price_updated"
)

// PlanItemPayload carries the core plan item data for events.

// ----------------------------------------------------------------------------
// Addon events
// ----------------------------------------------------------------------------

const (
	EventAddonCreated              = "addon.created"
	EventAddonUpdated              = "addon.updated"
	EventAddonDeleted              = "addon.deleted"
	EventAddonActivated            = "addon.activated"
	EventAddonDeactivated          = "addon.deactivated"
	EventAddonRestored             = "addon.restored"
	EventAddonPriceUpdated         = "addon.price_updated"
	EventAddonBillingPolicyUpdated = "addon.billing_policy_updated"
)

type AddonPayload struct {
	AddonID         string  `json:"addon_id"`
	CompanyID       string  `json:"company_id"`
	Name            string  `json:"name"`
	Description     *string `json:"description,omitempty"`
	BillingPolicyID string  `json:"billing_policy_id"`
	Price           string  `json:"price"`
	Currency        string  `json:"currency"`
	IsActive        bool    `json:"is_active"`
	Version         int     `json:"version"`
	CreatedAt       string  `json:"created_at"`
	UpdatedAt       string  `json:"updated_at"`
}

// ----------------------------------------------------------------------------
// Benefit events
// ----------------------------------------------------------------------------

const (
	EventBenefitCreated     = "subscription.benefit.created"
	EventBenefitUpdated     = "subscription.benefit.updated"
	EventBenefitDeleted     = "subscription.benefit.deleted"
	EventBenefitBulkCreated = "subscription.benefit.bulk_created"
	EventBenefitCopied      = "subscription.benefit.copied"
)

type BenefitPayload struct {
	BenefitID          string                 `json:"benefit_id"`
	CompanyID          string                 `json:"company_id"`
	PlanItemID         string                 `json:"plan_item_id"`
	BenefitType        string                 `json:"benefit_type"`
	BenefitDescription *string                `json:"benefit_description,omitempty"`
	Value              map[string]interface{} `json:"value"`
	CreatedAt          string                 `json:"created_at"`
	UpdatedAt          string                 `json:"updated_at"`
}

// ----------------------------------------------------------------------------
// Billing policy events
// ----------------------------------------------------------------------------

const (
	EventBillingPolicyCreated     = "billing_policy.created"
	EventBillingPolicyUpdated     = "billing_policy.updated"
	EventBillingPolicyDeleted     = "billing_policy.deleted"
	EventBillingPolicyActivated   = "billing_policy.activated"
	EventBillingPolicyDeactivated = "billing_policy.deactivated"
	EventBillingPolicyRestored    = "billing_policy.restored"
)

type BillingPolicyPayload struct {
	BillingPolicyID string `json:"billing_policy_id"`
	CompanyID       string `json:"company_id"`
	Name            string `json:"name"`
	FrequencyID     int16  `json:"frequency_id"`
	BillingInterval int    `json:"billing_interval"`
	ModelID         int16  `json:"model_id"`
	AdvanceDays     int    `json:"advance_days"`
	IsActive        bool   `json:"is_active"`
}

// ----------------------------------------------------------------------------
// Renewal policy events
// ----------------------------------------------------------------------------

const (
	EventRenewalPolicyCreated     = "renewal_policy.created"
	EventRenewalPolicyUpdated     = "renewal_policy.updated"
	EventRenewalPolicyDeleted     = "renewal_policy.deleted"
	EventRenewalPolicyActivated   = "renewal_policy.activated"
	EventRenewalPolicyDeactivated = "renewal_policy.deactivated"
	EventRenewalPolicyRestored    = "renewal_policy.restored"
)

type RenewalPolicyPayload struct {
	RenewalPolicyID string  `json:"renewal_policy_id"`
	CompanyID       string  `json:"company_id"`
	Name            string  `json:"name"`
	AutoRenew       bool    `json:"auto_renew"`
	GraceDays       int     `json:"grace_days"`
	LateFeePercent  float64 `json:"late_fee_percent"`
	NoticeDays      int     `json:"notice_days"`
	IsActive        bool    `json:"is_active"`
}

// ----------------------------------------------------------------------------
// Pause policy events
// ----------------------------------------------------------------------------

const (
	EventPausePolicyCreated     = "pause_policy.created"
	EventPausePolicyUpdated     = "pause_policy.updated"
	EventPausePolicyDeleted     = "pause_policy.deleted"
	EventPausePolicyActivated   = "pause_policy.activated"
	EventPausePolicyDeactivated = "pause_policy.deactivated"
	EventPausePolicyRestored    = "pause_policy.restored"
)

type PausePolicyPayload struct {
	PausePolicyID  string   `json:"pause_policy_id"`
	CompanyID      string   `json:"company_id"`
	Name           string   `json:"name"`
	MaxPauseDays   int      `json:"max_pause_days"`
	AllowedReasons []string `json:"allowed_reasons"`
	FreezeDays     int      `json:"freeze_days"`
	IsActive       bool     `json:"is_active"`
	CreatedAt      string   `json:"created_at"`
	UpdatedAt      string   `json:"updated_at"`
}

// ----------------------------------------------------------------------------
// Proration policy events
// ----------------------------------------------------------------------------

const (
	EventProrationPolicyCreated     = "proration_policy.created"
	EventProrationPolicyUpdated     = "proration_policy.updated"
	EventProrationPolicyDeleted     = "proration_policy.deleted"
	EventProrationPolicyActivated   = "proration_policy.activated"
	EventProrationPolicyDeactivated = "proration_policy.deactivated"
	EventProrationPolicyRestored    = "proration_policy.restored"
)

type ProrationPolicyPayload struct {
	ProrationPolicyID string `json:"proration_policy_id"`
	CompanyID         string `json:"company_id"`
	Name              string `json:"name"`
	UpgradeType       string `json:"upgrade_type"`
	DowngradeType     string `json:"downgrade_type"`
	IsActive          bool   `json:"is_active"`
}

// ----------------------------------------------------------------------------
// Feature registry events
// ----------------------------------------------------------------------------

const (
	EventFeatureCreated     = "feature.created"
	EventFeatureUpdated     = "feature.updated"
	EventFeatureDeleted     = "feature.deleted"
	EventFeatureActivated   = "feature.activated"
	EventFeatureDeactivated = "feature.deactivated"
	EventFeatureRestored    = "feature.restored"
)

type FeaturePayload struct {
	FeatureKey      string   `json:"feature_key"`
	Module          string   `json:"module"`
	FeatureGroup    string   `json:"feature_group,omitempty"`
	PermissionScope string   `json:"permission_scope,omitempty"`
	Description     string   `json:"description,omitempty"`
	DefaultLimit    string   `json:"default_limit,omitempty"`
	DependsOn       []string `json:"depends_on,omitempty"`
	IsActive        bool     `json:"is_active"`
	Version         int      `json:"version"`
	CreatedAt       string   `json:"created_at"`
	UpdatedAt       string   `json:"updated_at"`
}

// ----------------------------------------------------------------------------
// Entitlement events
// ----------------------------------------------------------------------------

const (
	EventEntitlementCreated           = "entitlement.created"
	EventEntitlementUpdated           = "entitlement.updated"
	EventEntitlementDeleted           = "entitlement.deleted"
	EventEntitlementBulkCreated       = "entitlement.bulk_created"
	EventEntitlementReplaced          = "entitlement.replaced"
	EventEntitlementDeletedByPlanItem = "entitlement.deleted_by_plan_item"
	EventEntitlementCopied            = "entitlement.copied"
	EventEntitlementGranted           = "entitlement.granted"
	EventEntitlementRevoked           = "entitlement.revoked"
	EventEntitlementRefreshed         = "entitlement.refreshed"
)

type EntitlementPayload struct {
	EntitlementID string `json:"entitlement_id"`
	PlanItemID    string `json:"plan_item_id"`
	FeatureKey    string `json:"feature_key"`
	LimitValue    string `json:"limit_value,omitempty"`
	LimitPeriod   string `json:"limit_period,omitempty"`
	IsEnabled     bool   `json:"is_enabled"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

type EntitlementBulkPayload struct {
	EntitlementIDs []string `json:"entitlement_ids"`
	PlanItemID     string   `json:"plan_item_id"`
	Count          int      `json:"count"`
}

type EntitlementReplacePayload struct {
	PlanItemID     string   `json:"plan_item_id"`
	EntitlementIDs []string `json:"entitlement_ids"`
}

type EntitlementDeleteByPlanItemPayload struct {
	PlanItemID string `json:"plan_item_id"`
}

type EntitlementCopyPayload struct {
	SourcePlanItemID string `json:"source_plan_item_id"`
	TargetPlanItemID string `json:"target_plan_item_id"`
	Count            int    `json:"count"`
}

type EntitlementGrantPayload struct {
	SubscriptionID string `json:"subscription_id"`
}

type EntitlementRevokePayload struct {
	SubscriptionID string `json:"subscription_id"`
}

type EntitlementRefreshPayload struct {
	SubscriptionID string `json:"subscription_id"`
}

// PlanItemPayload carries the core plan item data for events.
type PlanItemPayload struct {
	PlanItemID      string                 `json:"plan_item_id"`
	PlanID          string                 `json:"plan_id"`
	CompanyID       string                 `json:"company_id"` // ✅ NEW: required for scoping
	ItemType        string                 `json:"item_type"`
	Name            string                 `json:"name"`
	Description     *string                `json:"description,omitempty"`
	FeatureKey      *string                `json:"feature_key,omitempty"`
	BillingPolicyID *string                `json:"billing_policy_id,omitempty"`
	Price           string                 `json:"price"`
	Currency        string                 `json:"currency"`
	TaxRate         *string                `json:"tax_rate,omitempty"`   // ✅ NEW: decimal as string
	ProductID       *string                `json:"product_id,omitempty"` // ✅ NEW: for linking
	EffectiveFrom   string                 `json:"effective_from"`
	EffectiveTo     string                 `json:"effective_to,omitempty"`
	IsMandatory     bool                   `json:"is_mandatory"`
	IsActive        bool                   `json:"is_active"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"` // ✅ NEW: extra attributes
}
