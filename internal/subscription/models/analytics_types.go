// FILE: models/analytics_types.go

package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"

	"auth-service/internal/subscription/models/enums"
)

// -------------------------------------------------------------------------
// Subscription KPIs
// -------------------------------------------------------------------------

type SubscriptionMetrics struct {
	Total     int64 `json:"total"`
	Active    int64 `json:"active"`
	Paused    int64 `json:"paused"`
	Expired   int64 `json:"expired"`
	Cancelled int64 `json:"cancelled"`
	Trial     int64 `json:"trial"`
	Pending   int64 `json:"pending"`
}

type SubscriptionStatusMetric struct {
	Status enums.SubscriptionStatus `json:"status"`
	Count  int64                    `json:"count"`
}

type SubscriptionGrowthMetric struct {
	Period           time.Time `json:"period"`
	NewSubscriptions int64     `json:"newSubscriptions"`
	ActiveAtPeriod   int64     `json:"activeAtPeriod"`
}

// -------------------------------------------------------------------------
// Revenue
// -------------------------------------------------------------------------

type RevenueMetrics struct {
	TotalRevenue                  decimal.Decimal `json:"totalRevenue"`
	ActiveSubscriptions           int64           `json:"activeSubscriptions"`
	ActiveCustomers               int64           `json:"activeCustomers"`
	AverageRevenuePerSubscription decimal.Decimal `json:"averageRevenuePerSubscription"`
	AverageQuantity               decimal.Decimal `json:"averageQuantity"`
}

type RevenueTrendMetric struct {
	Period            time.Time       `json:"period"`
	Revenue           decimal.Decimal `json:"revenue"`
	SubscriptionCount int64           `json:"subscriptionCount"`
}

// -------------------------------------------------------------------------
// Churn / Retention
// -------------------------------------------------------------------------

type ChurnMetrics struct {
	ChurnedSubscriptions int64           `json:"churnedSubscriptions"`
	ChurnedCustomers     int64           `json:"churnedCustomers"`
	LostRevenue          decimal.Decimal `json:"lostRevenue"`
	ChurnRate            decimal.Decimal `json:"churnRate"` // percentage
}

type RetentionMetrics struct {
	TotalActive          int64           `json:"totalActive"`
	RenewedSubscriptions int64           `json:"renewedSubscriptions"`
	RetentionRate        decimal.Decimal `json:"retentionRate"` // percentage
}

// -------------------------------------------------------------------------
// Trials
// -------------------------------------------------------------------------

type TrialMetrics struct {
	TrialsStarted            int64           `json:"trialsStarted"`
	TrialsConverted          int64           `json:"trialsConverted"`
	TrialsExpired            int64           `json:"trialsExpired"`
	AverageTrialDurationDays float64         `json:"averageTrialDurationDays"`
	ConversionRate           decimal.Decimal `json:"conversionRate"` // percentage
}

// -------------------------------------------------------------------------
// Renewals
// -------------------------------------------------------------------------

type RenewalMetrics struct {
	RenewedSubscriptions int64           `json:"renewedSubscriptions"`
	RenewalRate          decimal.Decimal `json:"renewalRate"` // percentage
}

type SubscriptionRenewalMetric struct {
	SubscriptionID uuid.UUID `json:"subscriptionId"`
	CustomerID     uuid.UUID `json:"customerId"`
	EndDate        time.Time `json:"endDate"`
}

// -------------------------------------------------------------------------
// Usage
// -------------------------------------------------------------------------

type UsageMetrics struct {
	TotalUsageEvents             int64           `json:"totalUsageEvents"`
	TotalQuantityUsed            decimal.Decimal `json:"totalQuantityUsed"`
	DistinctFeaturesUsed         int64           `json:"distinctFeaturesUsed"`
	ActiveSubscriptionsWithUsage int64           `json:"activeSubscriptionsWithUsage"`
}

type FeatureUsageMetric struct {
	FeatureKey        string          `json:"featureKey"`
	UsageCount        int64           `json:"usageCount"`
	TotalQuantity     decimal.Decimal `json:"totalQuantity"`
	SubscriptionCount int64           `json:"subscriptionCount"`
}

type PlanAnalyticsMetric struct {
	PlanID            uuid.UUID       `json:"planId"`
	PlanName          string          `json:"planName"`
	SubscriptionCount int64           `json:"subscriptionCount"`
	TotalRevenue      decimal.Decimal `json:"totalRevenue"`
	CustomerCount     int64           `json:"customerCount"`
}

type AddonAnalyticsMetric struct {
	AddonID           uuid.UUID       `json:"addonId"`
	AddonName         string          `json:"addonName"`
	UsageCount        int64           `json:"usageCount"`
	TotalRevenue      decimal.Decimal `json:"totalRevenue"`
	SubscriptionCount int64           `json:"subscriptionCount"`
}

// -------------------------------------------------------------------------
// Customer
// -------------------------------------------------------------------------

type CustomerAnalyticsMetric struct {
	CustomerID           uuid.UUID       `json:"customerId"`
	SubscriptionCount    int64           `json:"subscriptionCount"`
	TotalSpent           decimal.Decimal `json:"totalSpent"`
	LastSubscriptionDate *time.Time      `json:"lastSubscriptionDate,omitempty"`
}

// -------------------------------------------------------------------------
// Dashboard
// -------------------------------------------------------------------------

type SubscriptionDashboard struct {
	SubscriptionMetrics *SubscriptionMetrics         `json:"subscriptionMetrics,omitempty"`
	RevenueMetrics      *RevenueMetrics              `json:"revenueMetrics,omitempty"`
	MRR                 decimal.Decimal              `json:"mrr"`
	ARR                 decimal.Decimal              `json:"arr"`
	ChurnMetrics        *ChurnMetrics                `json:"churnMetrics,omitempty"`
	TrialMetrics        *TrialMetrics                `json:"trialMetrics,omitempty"`
	TopFeatures         []*FeatureUsageMetric        `json:"topFeatures,omitempty"`
	TopPlans            []*PlanAnalyticsMetric       `json:"topPlans,omitempty"`
	UpcomingRenewals    []*SubscriptionRenewalMetric `json:"upcomingRenewals,omitempty"`
}
type SubscriptionFact struct {
	FactID         uuid.UUID        `json:"factId"`
	CompanyID      uuid.UUID        `json:"companyId"`
	SubscriptionID uuid.UUID        `json:"subscriptionId"`
	EventDate      time.Time        `json:"eventDate"`
	EventType      string           `json:"eventType"`
	PlanID         *uuid.UUID       `json:"planId,omitempty"`
	CustomerID     *uuid.UUID       `json:"customerId,omitempty"`
	OldStatusID    *int16           `json:"oldStatusId,omitempty"`
	NewStatusID    *int16           `json:"newStatusId,omitempty"`
	MRRChange      *decimal.Decimal `json:"mrrChange,omitempty"`
	Metadata       JSONB            `json:"metadata,omitempty"`
	CreatedAt      time.Time        `json:"createdAt"`
}

type UsageFact struct {
	FactID             uuid.UUID       `json:"factId"`
	CompanyID          uuid.UUID       `json:"companyId"`
	SubscriptionItemID uuid.UUID       `json:"subscriptionItemId"`
	FeatureKey         string          `json:"featureKey"`
	Quantity           decimal.Decimal `json:"quantity"`
	UsageDate          time.Time       `json:"usageDate"`
	CreatedAt          time.Time       `json:"createdAt"`
}

// file: internal/subscription/models/analytics_types.go (append)

// AddonUsageFact represents a usage record for an addon.
type AddonUsageFact struct {
	FactID         uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"factId"`
	CompanyID      uuid.UUID       `gorm:"type:uuid;not null" json:"companyId"`
	AddonID        uuid.UUID       `gorm:"type:uuid;not null" json:"addonId"`
	SubscriptionID uuid.UUID       `gorm:"type:uuid;not null" json:"subscriptionId"`
	Quantity       decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"quantity"`
	UsageDate      time.Time       `gorm:"type:date;not null" json:"usageDate"`
	CreatedAt      time.Time       `gorm:"default:now()" json:"createdAt"`
}

// DailyAddonMetrics stores aggregated metrics per addon per day.
type DailyAddonMetrics struct {
	CompanyID   uuid.UUID       `gorm:"type:uuid;primaryKey" json:"companyId"`
	AddonID     uuid.UUID       `gorm:"type:uuid;primaryKey" json:"addonId"`
	Date        time.Time       `gorm:"type:date;primaryKey" json:"date"`
	ActiveCount int             `gorm:"not null;default:0" json:"activeCount"`
	NewCount    int             `gorm:"not null;default:0" json:"newCount"`
	Revenue     decimal.Decimal `gorm:"type:numeric(14,2);not null;default:0" json:"revenue"`
	MRR         decimal.Decimal `gorm:"type:numeric(14,2);not null;default:0" json:"mrr"`
	ARR         decimal.Decimal `gorm:"type:numeric(14,2);not null;default:0" json:"arr"`
	UpdatedAt   time.Time       `gorm:"default:now()" json:"updatedAt"`
}

// DailyAddonMetricsDelta represents incremental changes to daily addon metrics.
type DailyAddonMetricsDelta struct {
	ActiveCount int             `json:"activeCount"` // change in number of subscriptions with this addon active
	NewCount    int             `json:"newCount"`    // new subscriptions that attached this addon
	Revenue     decimal.Decimal `json:"revenue"`     // total revenue change
	MRR         decimal.Decimal `json:"mrr"`         // monthly recurring revenue change
	ARR         decimal.Decimal `json:"arr"`         // annualised MRR change
}
type BenefitUsageFact struct {
	FactID         uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"factId"`
	CompanyID      uuid.UUID       `gorm:"type:uuid;not null" json:"companyId"`
	BenefitID      uuid.UUID       `gorm:"type:uuid;not null" json:"benefitId"`
	SubscriptionID uuid.UUID       `gorm:"type:uuid;not null" json:"subscriptionId"`
	BenefitType    string          `gorm:"type:varchar(50);not null" json:"benefitType"`
	Quantity       decimal.Decimal `gorm:"type:numeric(14,4);not null" json:"quantity"`
	UsageDate      time.Time       `gorm:"type:date;not null" json:"usageDate"`
	CreatedAt      time.Time       `gorm:"default:now()" json:"createdAt"`
}

// DailyBenefitMetricsDelta represents incremental changes to daily benefit metrics.
type DailyBenefitMetricsDelta struct {
	ActiveCount int // subscriptions with this benefit active on that day
	NewCount    int // new subscriptions that attached this benefit on that day
}

// BenefitAnalyticsMetric represents aggregated metrics for a benefit.
type BenefitAnalyticsMetric struct {
	BenefitID         uuid.UUID `json:"benefitId"`
	BenefitType       string    `json:"benefitType"`
	SubscriptionCount int64     `json:"subscriptionCount"`
	UsageCount        int64     `json:"usageCount"`
}

// BillingPolicyUsageFact records each time a billing policy is referenced by a plan or addon.
type BillingPolicyUsageFact struct {
	FactID          uuid.UUID `json:"factId"`
	CompanyID       uuid.UUID `json:"companyId"`
	BillingPolicyID uuid.UUID `json:"billingPolicyId"`
	EntityType      string    `json:"entityType"` // 'plan' or 'addon'
	EntityID        uuid.UUID `json:"entityId"`
	UsageDate       time.Time `json:"usageDate"`
	CreatedAt       time.Time `json:"createdAt"`
}

// DailyBillingPolicyMetricsDelta represents incremental changes for daily billing policy metrics.
type DailyBillingPolicyMetricsDelta struct {
	ActiveCount int
	NewCount    int
	// Revenue decimal.Decimal // uncomment if tracking revenue
}

// BillingPolicyAnalyticsMetric holds aggregated analytics for a billing policy.
type BillingPolicyAnalyticsMetric struct {
	BillingPolicyID   uuid.UUID `json:"billingPolicyId"`
	BillingPolicyName string    `json:"billingPolicyName"`
	ActiveCount       int       `json:"activeCount"`
	NewCount          int       `json:"newCount"`
	// Revenue           decimal.Decimal `json:"revenue,omitempty"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Inserted when a plan is created or its renewal_policy_id changes.
type RenewalPolicyUsageFact struct {
	FactID          uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"factId"`
	CompanyID       uuid.UUID `gorm:"type:uuid;not null" json:"companyId"`
	RenewalPolicyID uuid.UUID `gorm:"type:uuid;not null" json:"renewalPolicyId"`
	PlanID          uuid.UUID `gorm:"type:uuid;not null" json:"planId"`
	UsageDate       time.Time `gorm:"type:date;not null" json:"usageDate"` // day the association became active
	CreatedAt       time.Time `gorm:"default:now()" json:"createdAt"`
}

// DailyRenewalPolicyMetricsDelta represents incremental changes to daily renewal policy metrics.
type DailyRenewalPolicyMetricsDelta struct {
	ActiveCount int
	NewCount    int
}

// RenewalPolicyAnalyticsMetric holds aggregated metrics for a renewal policy.
type RenewalPolicyAnalyticsMetric struct {
	RenewalPolicyID   uuid.UUID `json:"renewalPolicyId"`
	RenewalPolicyName string    `json:"renewalPolicyName"`
	ActiveCount       int       `json:"activeCount"`
	NewCount          int       `json:"newCount"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

// PausePolicyUsageFact records each plan's association with a pause policy.
type PausePolicyUsageFact struct {
	FactID        uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"factId"`
	CompanyID     uuid.UUID `gorm:"type:uuid;not null" json:"companyId"`
	PausePolicyID uuid.UUID `gorm:"type:uuid;not null" json:"pausePolicyId"`
	EntityType    string    `gorm:"type:varchar(20);not null" json:"entityType"` // only 'plan' for now
	EntityID      uuid.UUID `gorm:"type:uuid;not null" json:"entityId"`          // plan_id
	UsageDate     time.Time `gorm:"type:date;not null" json:"usageDate"`
	CreatedAt     time.Time `gorm:"default:now()" json:"createdAt"`
}

// DailyPausePolicyMetricsDelta represents incremental changes to daily pause policy metrics.
type DailyPausePolicyMetricsDelta struct {
	ActiveCount              int
	NewCount                 int
	PausedSubscriptionsCount int
	PauseEventsCount         int
	ResumeEventsCount        int
	AvgPauseDurationDays     decimal.Decimal
}

// PausePolicyAnalyticsMetric holds aggregated metrics for a specific pause policy.
type PausePolicyAnalyticsMetric struct {
	PausePolicyID            uuid.UUID       `json:"pausePolicyId"`
	PausePolicyName          string          `json:"pausePolicyName"`
	ActiveCount              int             `json:"activeCount"`
	NewCount                 int             `json:"newCount"`
	PausedSubscriptionsCount int             `json:"pausedSubscriptionsCount"`
	PauseEventsCount         int             `json:"pauseEventsCount"`
	ResumeEventsCount        int             `json:"resumeEventsCount"`
	AvgPauseDurationDays     decimal.Decimal `json:"avgPauseDurationDays"`
	UpdatedAt                time.Time       `json:"updatedAt"`
}
type EntitlementUsageFact struct {
	FactID         uuid.UUID        `json:"factId"`
	CompanyID      uuid.UUID        `json:"companyId"`
	SubscriptionID uuid.UUID        `json:"subscriptionId"`
	PlanItemID     uuid.UUID        `json:"planItemId"`
	FeatureKey     string           `json:"featureKey"`
	LimitValue     *decimal.Decimal `json:"limitValue,omitempty"`
	LimitPeriod    string           `json:"limitPeriod,omitempty"` // day, week, month, year, lifetime
	IsEnabled      bool             `json:"isEnabled"`
	GrantDate      time.Time        `json:"grantDate"`
	CreatedAt      time.Time        `json:"createdAt"`
}

func (EntitlementUsageFact) TableName() string {
	return "subscription_analytics.entitlement_usage_fact"
}

// DailyEntitlementMetrics holds daily aggregated counts per feature per company.
// Corresponds to `subscription_analytics.daily_entitlement_metrics`.
type DailyEntitlementMetrics struct {
	CompanyID   uuid.UUID `json:"companyId"`
	FeatureKey  string    `json:"featureKey"`
	Date        time.Time `json:"date"`
	ActiveCount int       `json:"activeCount"` // subscriptions with this entitlement enabled on that day
	NewCount    int       `json:"newCount"`    // subscriptions that newly received this entitlement on that day
	UpdatedAt   time.Time `json:"updatedAt"`
}

func (DailyEntitlementMetrics) TableName() string {
	return "subscription_analytics.daily_entitlement_metrics"
}

// EntitlementLimitFact tracks changes to an entitlement's limit over time (optional).
// Corresponds to `subscription_analytics.entitlement_limit_fact`.
type EntitlementLimitFact struct {
	FactID         uuid.UUID        `json:"factId"`
	CompanyID      uuid.UUID        `json:"companyId"`
	PlanItemID     uuid.UUID        `json:"planItemId"`
	FeatureKey     string           `json:"featureKey"`
	OldLimitValue  *decimal.Decimal `json:"oldLimitValue,omitempty"`
	NewLimitValue  *decimal.Decimal `json:"newLimitValue,omitempty"`
	OldLimitPeriod string           `json:"oldLimitPeriod,omitempty"`
	NewLimitPeriod string           `json:"newLimitPeriod,omitempty"`
	EffectiveDate  time.Time        `json:"effectiveDate"`
	CreatedAt      time.Time        `json:"createdAt"`
}

func (EntitlementLimitFact) TableName() string {
	return "subscription_analytics.entitlement_limit_fact"
}

// DailyEntitlementMetricsDelta represents incremental changes for daily aggregation.
type DailyEntitlementMetricsDelta struct {
	ActiveCount int
	NewCount    int
}

// EntitlementAnalyticsMetric is a query result for a single feature's aggregated metrics.
type EntitlementAnalyticsMetric struct {
	FeatureKey  string `json:"featureKey"`
	ActiveCount int    `json:"activeCount"`
	NewCount    int    `json:"newCount"`
	// optional: AvgLimitValue decimal.Decimal
}

// PlanChangeFact represents a single plan change event.
type PlanChangeFact struct {
	FactID         uuid.UUID        `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"factId"`
	CompanyID      uuid.UUID        `gorm:"type:uuid;not null" json:"companyId"`
	SubscriptionID uuid.UUID        `gorm:"type:uuid;not null" json:"subscriptionId"`
	OldPlanID      uuid.UUID        `gorm:"type:uuid;not null" json:"oldPlanId"`
	NewPlanID      uuid.UUID        `gorm:"type:uuid;not null" json:"newPlanId"`
	ChangeType     string           `gorm:"type:varchar(20);not null" json:"changeType"` // 'upgrade', 'downgrade', 'lateral'
	ChangeDate     time.Time        `gorm:"type:date;not null" json:"changeDate"`
	OldPlanVersion *int             `gorm:"column:old_plan_version" json:"oldPlanVersion,omitempty"`
	NewPlanVersion *int             `gorm:"column:new_plan_version" json:"newPlanVersion,omitempty"`
	MRRDelta       *decimal.Decimal `gorm:"type:numeric(14,2)" json:"mrrDelta,omitempty"`
	PerformedBy    *uuid.UUID       `gorm:"type:uuid" json:"performedBy,omitempty"`
	Reason         *string          `gorm:"type:text" json:"reason,omitempty"`
	CreatedAt      time.Time        `gorm:"not null;default:now()" json:"createdAt"`
}

// DailyPlanChangeMetrics stores daily aggregated plan change metrics.
type DailyPlanChangeMetrics struct {
	CompanyID         uuid.UUID `gorm:"type:uuid;not null;primaryKey" json:"companyId"`
	PlanID            uuid.UUID `gorm:"type:uuid;not null;primaryKey" json:"planId"`
	Date              time.Time `gorm:"type:date;primaryKey" json:"date"`
	UpgradeInCount    int       `gorm:"not null;default:0" json:"upgradeInCount"`
	UpgradeOutCount   int       `gorm:"not null;default:0" json:"upgradeOutCount"`
	DowngradeInCount  int       `gorm:"not null;default:0" json:"downgradeInCount"`
	DowngradeOutCount int       `gorm:"not null;default:0" json:"downgradeOutCount"`
	LateralInCount    int       `gorm:"not null;default:0" json:"lateralInCount"`
	LateralOutCount   int       `gorm:"not null;default:0" json:"lateralOutCount"`
	NetChange         int       `gorm:"not null;default:0" json:"netChange"` // (incoming - outgoing) for all types combined
	UpdatedAt         time.Time `gorm:"not null;default:now()" json:"updatedAt"`
}

// PlanChangeDelta represents incremental changes for a plan on a given date.
type PlanChangeDelta struct {
	UpgradeInCount    int
	UpgradeOutCount   int
	DowngradeInCount  int
	DowngradeOutCount int
	LateralInCount    int
	LateralOutCount   int
	NetChange         int
}

// PlanChangeMetricsSummary provides aggregated metrics for a plan over a period.
type PlanChangeMetricsSummary struct {
	PlanID                uuid.UUID `json:"planId"`
	PlanName              string    `json:"planName"`
	TotalUpgradeIn        int64     `json:"totalUpgradeIn"`
	TotalUpgradeOut       int64     `json:"totalUpgradeOut"`
	TotalDowngradeIn      int64     `json:"totalDowngradeIn"`
	TotalDowngradeOut     int64     `json:"totalDowngradeOut"`
	TotalLateralIn        int64     `json:"totalLateralIn"`
	TotalLateralOut       int64     `json:"totalLateralOut"`
	NetChange             int64     `json:"netChange"`
	AverageDailyNetChange float64   `json:"averageDailyNetChange"`
}

// PlanChangeTrendMetric represents daily or aggregated trend data for plan changes.
type PlanChangeTrendMetric struct {
	Period       time.Time `json:"period"`
	UpgradeIn    int       `json:"upgradeIn"`
	UpgradeOut   int       `json:"upgradeOut"`
	DowngradeIn  int       `json:"downgradeIn"`
	DowngradeOut int       `json:"downgradeOut"`
	LateralIn    int       `json:"lateralIn"`
	LateralOut   int       `json:"lateralOut"`
	NetChange    int       `json:"netChange"`
}
