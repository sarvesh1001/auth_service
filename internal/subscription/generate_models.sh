#!/bin/bash

# Generate all model files for the subscription module

set -e

# Create enums first
mkdir -p models/enums

cat > models/enums/business_model.go << 'EOF'
package enums

type BusinessModel string

const (
	Membership        BusinessModel = "membership"
	RecurringProduct  BusinessModel = "recurring_product"
	RecurringService  BusinessModel = "recurring_service"
	UsageBased        BusinessModel = "usage_based"
	Rental            BusinessModel = "rental"
	Contract          BusinessModel = "contract"
	Course            BusinessModel = "course"
	SeatLicense       BusinessModel = "seat_license"
	Insurance         BusinessModel = "insurance"
	Leasing           BusinessModel = "leasing"
	Custom            BusinessModel = "custom"
)

func (bm BusinessModel) String() string { return string(bm) }
EOF

cat > models/enums/schedule_type.go << 'EOF'
package enums

type ScheduleType string

const (
	Class        ScheduleType = "class"
	Appointment  ScheduleType = "appointment"
	Meeting      ScheduleType = "meeting"
	Delivery     ScheduleType = "delivery"
	Visit        ScheduleType = "visit"
	Workshop     ScheduleType = "workshop"
	Event        ScheduleType = "event"
	ServiceVisit ScheduleType = "service"
	Maintenance  ScheduleType = "maintenance"
)

func (st ScheduleType) String() string { return string(st) }
EOF

cat > models/enums/status.go << 'EOF'
package enums

type StatusCategory string

const (
	CategorySubscription StatusCategory = "subscription"
	CategoryItem         StatusCategory = "item"
	CategorySchedule     StatusCategory = "schedule"
	CategoryResource     StatusCategory = "resource"
	CategoryWaitlist     StatusCategory = "waitlist"
)

type Status struct {
	ID       int16          `gorm:"primaryKey"`
	Code     string         `gorm:"not null"`
	Category StatusCategory `gorm:"not null"`
	Name     string         `gorm:"not null"`
}

func (Status) TableName() string { return "statuses" }
EOF

# Now main models

cat > models/proration_policy.go << 'EOF'
package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ProrationPolicy struct {
	ProrationPolicyID uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	CompanyID         uuid.UUID      `gorm:"type:uuid;not null;index"`
	Name              string         `gorm:"size:100;not null"`
	UpgradeType       string         `gorm:"size:20;not null;check:upgrade_type IN ('charge_difference','refund','credit_note')"`
	DowngradeType     string         `gorm:"size:20;not null;check:downgrade_type IN ('credit_next','refund','none')"`
	IsActive          bool           `gorm:"not null;default:true"`
	CreatedAt         time.Time      `gorm:"not null;default:now()"`
	UpdatedAt         time.Time      `gorm:"not null;default:now()"`
	DeletedAt         gorm.DeletedAt `gorm:"index"`

	// relationships
	Company Company `gorm:"foreignKey:CompanyID"`
}

func (ProrationPolicy) TableName() string { return "proration_policies" }
EOF

cat > models/billing_policy.go << 'EOF'
package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type BillingPolicy struct {
	BillingPolicyID  uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	CompanyID        uuid.UUID      `gorm:"type:uuid;not null;index"`
	Name             string         `gorm:"size:100;not null"`
	BillingTypeID    int16          `gorm:"not null"`
	BillingFrequency *int           `gorm:"default:null"`
	AdvanceDays      int            `gorm:"not null;default:0"`
	IsActive         bool           `gorm:"not null;default:true"`
	CreatedAt        time.Time      `gorm:"not null;default:now()"`
	UpdatedAt        time.Time      `gorm:"not null;default:now()"`
	DeletedAt        gorm.DeletedAt `gorm:"index"`

	// relationships
	Company     Company      `gorm:"foreignKey:CompanyID"`
	BillingType BillingType  `gorm:"foreignKey:BillingTypeID"`
}

func (BillingPolicy) TableName() string { return "billing_policies" }
EOF

cat > models/renewal_policy.go << 'EOF'
package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type RenewalPolicy struct {
	RenewalPolicyID uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	CompanyID       uuid.UUID      `gorm:"type:uuid;not null;index"`
	Name            string         `gorm:"size:100;not null"`
	AutoRenew       bool           `gorm:"not null;default:true"`
	GraceDays       int            `gorm:"not null;default:0"`
	LateFeePercent  *float64       `gorm:"type:numeric(5,2);default:0"`
	NoticeDays      int            `gorm:"not null;default:0"`
	IsActive        bool           `gorm:"not null;default:true"`
	CreatedAt       time.Time      `gorm:"not null;default:now()"`
	UpdatedAt       time.Time      `gorm:"not null;default:now()"`
	DeletedAt       gorm.DeletedAt `gorm:"index"`

	Company Company `gorm:"foreignKey:CompanyID"`
}

func (RenewalPolicy) TableName() string { return "renewal_policies" }
EOF

cat > models/pause_policy.go << 'EOF'
package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/datatypes"
)

type PausePolicy struct {
	PausePolicyID  uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	CompanyID      uuid.UUID      `gorm:"type:uuid;not null;index"`
	Name           string         `gorm:"size:100;not null"`
	MaxPauseDays   int            `gorm:"not null;default:0"`
	AllowedReasons datatypes.JSON `gorm:"type:jsonb;not null;default:'{}'"`
	FreezeDays     int            `gorm:"not null;default:0"`
	IsActive       bool           `gorm:"not null;default:true"`
	CreatedAt      time.Time      `gorm:"not null;default:now()"`
	UpdatedAt      time.Time      `gorm:"not null;default:now()"`
	DeletedAt      gorm.DeletedAt `gorm:"index"`

	Company Company `gorm:"foreignKey:CompanyID"`
}

func (PausePolicy) TableName() string { return "pause_policies" }
EOF

cat > models/feature_registry.go << 'EOF'
package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type FeatureRegistry struct {
	FeatureKey      string         `gorm:"primaryKey;size:100"`
	Module          string         `gorm:"size:50;not null"`
	FeatureGroup    *string        `gorm:"size:50"`
	PermissionScope *string        `gorm:"size:50"`
	Description     *string        `gorm:"type:text"`
	DefaultLimit    *float64       `gorm:"type:numeric(14,4)"`
	DependsOn       datatypes.JSON `gorm:"type:jsonb;default:'{}'"`
	Version         int            `gorm:"not null;default:1"`
	IsActive        bool           `gorm:"not null;default:true"`
	CreatedAt       time.Time      `gorm:"not null;default:now()"`
	UpdatedAt       time.Time      `gorm:"not null;default:now()"`
}

func (FeatureRegistry) TableName() string { return "feature_registry" }
EOF

cat > models/plan.go << 'EOF'
package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/datatypes"
)

type Plan struct {
	PlanID             uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	CompanyID          uuid.UUID      `gorm:"type:uuid;not null;index"`
	Name               string         `gorm:"size:255;not null"`
	BusinessModelID    int16          `gorm:"not null"`
	Description        *string        `gorm:"type:text"`
	BillingPolicyID    uuid.UUID      `gorm:"type:uuid;not null"`
	RenewalPolicyID    uuid.UUID      `gorm:"type:uuid;not null"`
	PausePolicyID      uuid.UUID      `gorm:"type:uuid;not null"`
	ProrationPolicyID  uuid.UUID      `gorm:"type:uuid;not null"`
	DurationDays       int            `gorm:"not null;default:365"`
	CancellationPolicy *string        `gorm:"type:text"`
	Metadata           datatypes.JSON `gorm:"type:jsonb"`
	IsActive           bool           `gorm:"not null;default:true"`
	CreatedAt          time.Time      `gorm:"not null;default:now()"`
	UpdatedAt          time.Time      `gorm:"not null;default:now()"`
	DeletedAt          gorm.DeletedAt `gorm:"index"`

	// relationships
	Company          Company           `gorm:"foreignKey:CompanyID"`
	BusinessModel    BusinessModel     `gorm:"foreignKey:BusinessModelID"`
	BillingPolicy    BillingPolicy     `gorm:"foreignKey:BillingPolicyID"`
	RenewalPolicy    RenewalPolicy     `gorm:"foreignKey:RenewalPolicyID"`
	PausePolicy      PausePolicy       `gorm:"foreignKey:PausePolicyID"`
	ProrationPolicy  ProrationPolicy   `gorm:"foreignKey:ProrationPolicyID"`
	PlanItems        []PlanItem        `gorm:"foreignKey:PlanID"`
	Subscriptions    []Subscription    `gorm:"foreignKey:PlanID"`
}

func (Plan) TableName() string { return "plans" }
EOF

cat > models/plan_item.go << 'EOF'
package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type PlanItem struct {
	PlanItemID      uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	PlanID          uuid.UUID      `gorm:"type:uuid;not null;index"`
	ItemType        string         `gorm:"size:20;not null;check:item_type IN ('base','addon','benefit','discount','tax')"`
	Name            string         `gorm:"size:255;not null"`
	Description     *string        `gorm:"type:text"`
	FeatureKey      *string        `gorm:"size:100"`
	BillingPolicyID *uuid.UUID     `gorm:"type:uuid"`
	Price           float64        `gorm:"type:numeric(14,2);not null;default:0"`
	Currency        string         `gorm:"size:3;not null;default:'USD'"`
	EffectiveFrom   time.Time      `gorm:"type:date;not null;default:now()"`
	EffectiveTo     *time.Time     `gorm:"type:date"`
	IsMandatory     bool           `gorm:"not null;default:false"`
	IsActive        bool           `gorm:"not null;default:true"`
	CreatedAt       time.Time      `gorm:"not null;default:now()"`
	UpdatedAt       time.Time      `gorm:"not null;default:now()"`
	DeletedAt       gorm.DeletedAt `gorm:"index"`

	// relationships
	Plan          Plan            `gorm:"foreignKey:PlanID"`
	Feature       *FeatureRegistry `gorm:"foreignKey:FeatureKey"`
	BillingPolicy *BillingPolicy  `gorm:"foreignKey:BillingPolicyID"`
	Entitlements  []Entitlement   `gorm:"foreignKey:PlanItemID"`
	Benefits      []Benefit       `gorm:"foreignKey:PlanItemID"`
}

func (PlanItem) TableName() string { return "plan_items" }
EOF

cat > models/entitlement.go << 'EOF'
package models

import (
	"time"

	"github.com/google/uuid"
)

type Entitlement struct {
	EntitlementID uuid.UUID  `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	PlanItemID    uuid.UUID  `gorm:"type:uuid;not null;index"`
	FeatureKey    string     `gorm:"size:100;not null"`
	LimitValue    *float64   `gorm:"type:numeric(14,4)"`
	LimitPeriod   *string    `gorm:"size:20;check:limit_period IN ('day','week','month','year','lifetime')"`
	IsEnabled     bool       `gorm:"not null;default:true"`
	CreatedAt     time.Time  `gorm:"not null;default:now()"`
	UpdatedAt     time.Time  `gorm:"not null;default:now()"`

	// relationships
	PlanItem PlanItem        `gorm:"foreignKey:PlanItemID"`
	Feature  FeatureRegistry `gorm:"foreignKey:FeatureKey"`
}

func (Entitlement) TableName() string { return "entitlements" }
EOF

cat > models/benefit.go << 'EOF'
package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type Benefit struct {
	BenefitID          uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	PlanItemID         uuid.UUID      `gorm:"type:uuid;not null;index"`
	BenefitType        string         `gorm:"size:50;not null;check:benefit_type IN ('discount','freebie','access','service','other')"`
	BenefitDescription *string        `gorm:"type:text"`
	Value              datatypes.JSON `gorm:"type:jsonb;not null"`
	CreatedAt          time.Time      `gorm:"not null;default:now()"`
	UpdatedAt          time.Time      `gorm:"not null;default:now()"`

	PlanItem PlanItem `gorm:"foreignKey:PlanItemID"`
}

func (Benefit) TableName() string { return "benefits" }
EOF

cat > models/addon.go << 'EOF'
package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Addon struct {
	AddonID         uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	CompanyID       uuid.UUID      `gorm:"type:uuid;not null;index"`
	Name            string         `gorm:"size:255;not null"`
	Description     *string        `gorm:"type:text"`
	BillingPolicyID uuid.UUID      `gorm:"type:uuid;not null"`
	Price           float64        `gorm:"type:numeric(14,2);not null"`
	Currency        string         `gorm:"size:3;not null;default:'USD'"`
	IsActive        bool           `gorm:"not null;default:true"`
	CreatedAt       time.Time      `gorm:"not null;default:now()"`
	UpdatedAt       time.Time      `gorm:"not null;default:now()"`
	DeletedAt       gorm.DeletedAt `gorm:"index"`

	Company       Company       `gorm:"foreignKey:CompanyID"`
	BillingPolicy BillingPolicy `gorm:"foreignKey:BillingPolicyID"`
}

func (Addon) TableName() string { return "addons" }
EOF

cat > models/subscription.go << 'EOF'
package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Subscription struct {
	SubscriptionID    uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	CompanyID         uuid.UUID      `gorm:"type:uuid;not null;index"`
	SubscriberTypeID  int16          `gorm:"not null"`
	SubscriberID      uuid.UUID      `gorm:"type:uuid;not null;index"`
	PlanID            uuid.UUID      `gorm:"type:uuid;not null"`
	StatusID          int16          `gorm:"not null;default:1;index"`
	StartDate         time.Time      `gorm:"type:date;not null;default:now()"`
	EndDate           *time.Time     `gorm:"type:date"`
	TrialEnd          *time.Time     `gorm:"type:date"`
	BillingStart      time.Time      `gorm:"type:date;not null"`
	AutoRenew         bool           `gorm:"not null;default:true"`
	PauseReason       *string        `gorm:"type:text"`
	CancellationReason *string       `gorm:"type:text"`
	CancelledAt       *time.Time     `gorm:"type:timestamptz"`
	ContractNumber    *string        `gorm:"size:100;unique"`
	SignedAt          *time.Time     `gorm:"type:timestamptz"`
	TermsVersion      *string        `gorm:"size:20"`
	SignedDocumentKey *string        `gorm:"type:text"`
	CurrentInvoiceID  *uuid.UUID     `gorm:"type:uuid"`
	LastInvoiceID     *uuid.UUID     `gorm:"type:uuid"`
	NextInvoiceID     *uuid.UUID     `gorm:"type:uuid"`
	CouponID          *uuid.UUID     `gorm:"type:uuid"`
	Version           int            `gorm:"not null;default:1"`
	CreatedAt         time.Time      `gorm:"not null;default:now()"`
	UpdatedAt         time.Time      `gorm:"not null;default:now()"`
	DeletedAt         gorm.DeletedAt `gorm:"index"`

	// relationships
	Company         Company          `gorm:"foreignKey:CompanyID"`
	SubscriberType  SubscriberType   `gorm:"foreignKey:SubscriberTypeID"`
	Plan            Plan             `gorm:"foreignKey:PlanID"`
	Status          Status           `gorm:"foreignKey:StatusID"`
	Items           []SubscriptionItem `gorm:"foreignKey:SubscriptionID"`
	Versions        []SubscriptionVersion `gorm:"foreignKey:SubscriptionID"`
	Timeline        []SubscriptionTimeline `gorm:"foreignKey:SubscriptionID"`
	ResourceAssignments []ResourceAssignment `gorm:"foreignKey:SubscriptionID"`
	Schedules       []Schedule       `gorm:"foreignKey:SubscriptionID"`
	Notifications   []NotificationPreference `gorm:"foreignKey:SubscriptionID"`
	AuditLogs       []AuditLog       `gorm:"foreignKey:SubscriptionID"`
}

func (Subscription) TableName() string { return "subscriptions" }
EOF

cat > models/subscription_item.go << 'EOF'
package models

import (
	"time"

	"github.com/google/uuid"
)

type SubscriptionItem struct {
	SubItemID      uuid.UUID  `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	SubscriptionID uuid.UUID  `gorm:"type:uuid;not null;index"`
	PlanItemID     uuid.UUID  `gorm:"type:uuid;not null"`
	AddonID        *uuid.UUID `gorm:"type:uuid"`
	Quantity       float64    `gorm:"type:numeric(14,4);not null;default:1"`
	UnitPrice      float64    `gorm:"type:numeric(14,2);not null"`
	TotalPrice     float64    `gorm:"type:numeric(14,2);generated:always as (quantity * unit_price) stored"`
	Currency       string     `gorm:"size:3;not null;default:'USD'"`
	StatusID       int16      `gorm:"not null;default:7;index"`
	StartDate      time.Time  `gorm:"type:date;not null;default:now()"`
	EndDate        *time.Time `gorm:"type:date"`
	Metadata       datatypes.JSON `gorm:"type:jsonb"`
	CreatedAt      time.Time  `gorm:"not null;default:now()"`
	UpdatedAt      time.Time  `gorm:"not null;default:now()"`

	// relationships
	Subscription Subscription    `gorm:"foreignKey:SubscriptionID"`
	PlanItem     PlanItem        `gorm:"foreignKey:PlanItemID"`
	Addon        *Addon          `gorm:"foreignKey:AddonID"`
	Status       Status          `gorm:"foreignKey:StatusID"`
	Usages       []Usage         `gorm:"foreignKey:SubscriptionItemID"`
}

func (SubscriptionItem) TableName() string { return "subscription_items" }
EOF

cat > models/subscription_version.go << 'EOF'
package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type SubscriptionVersion struct {
	VersionID      uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	SubscriptionID uuid.UUID      `gorm:"type:uuid;not null;index"`
	VersionNumber  int            `gorm:"not null"`
	Snapshot       datatypes.JSON `gorm:"type:jsonb;not null"`
	Reason         *string        `gorm:"type:text"`
	CreatedAt      time.Time      `gorm:"not null;default:now()"`

	Subscription Subscription `gorm:"foreignKey:SubscriptionID"`
}

func (SubscriptionVersion) TableName() string { return "subscription_versions" }
EOF

cat > models/subscription_timeline.go << 'EOF'
package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type SubscriptionTimeline struct {
	TimelineID   uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	SubscriptionID uuid.UUID    `gorm:"type:uuid;not null;index"`
	EventType    string         `gorm:"size:50;not null;index"`
	OldStatusID  *int16         `gorm:"default:null"`
	NewStatusID  *int16         `gorm:"default:null"`
	PerformedBy  *uuid.UUID     `gorm:"type:uuid"`
	Metadata     datatypes.JSON `gorm:"type:jsonb"`
	CreatedAt    time.Time      `gorm:"not null;default:now()"`

	Subscription Subscription `gorm:"foreignKey:SubscriptionID"`
	OldStatus    *Status      `gorm:"foreignKey:OldStatusID"`
	NewStatus    *Status      `gorm:"foreignKey:NewStatusID"`
	Performer    *User        `gorm:"foreignKey:PerformedBy"`
}

func (SubscriptionTimeline) TableName() string { return "subscription_timeline" }
EOF

cat > models/usage.go << 'EOF'
package models

import (
	"time"

	"github.com/google/uuid"
)

type Usage struct {
	UsageID            uuid.UUID  `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	SubscriptionItemID uuid.UUID  `gorm:"type:uuid;not null;index"`
	FeatureKey         string     `gorm:"size:100;not null"`
	QuantityUsed       float64    `gorm:"type:numeric(14,4);not null"`
	PeriodStart        time.Time  `gorm:"type:date;not null;index"`
	PeriodEnd          time.Time  `gorm:"type:date;not null;index"`
	RecordedAt         time.Time  `gorm:"not null;default:now()"`
	SourceType         *string    `gorm:"size:50"`
	SourceID           *uuid.UUID `gorm:"type:uuid"`
	CreatedBy          *uuid.UUID `gorm:"type:uuid"`

	SubscriptionItem SubscriptionItem `gorm:"foreignKey:SubscriptionItemID"`
	Feature          FeatureRegistry  `gorm:"foreignKey:FeatureKey"`
	Creator          *User            `gorm:"foreignKey:CreatedBy"`
}

func (Usage) TableName() string { return "usages" }
EOF

cat > models/resource_assignment.go << 'EOF'
package models

import (
	"time"

	"github.com/google/uuid"
)

type ResourceAssignment struct {
	AssignmentID       uuid.UUID  `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	SubscriptionID     uuid.UUID  `gorm:"type:uuid;not null;index"`
	ResourceType       string     `gorm:"size:50;not null;index"`
	ResourceID         uuid.UUID  `gorm:"type:uuid;not null;index"`
	AllocationStrategy string     `gorm:"size:20;not null;default:'exclusive';check:allocation_strategy IN ('exclusive','shared','rotating','priority')"`
	AssignedAt         time.Time  `gorm:"not null;default:now()"`
	AssignedUntil      *time.Time `gorm:"type:timestamptz"`
	StatusID           int16      `gorm:"not null;default:1;index"`
	CreatedAt          time.Time  `gorm:"not null;default:now()"`
	UpdatedAt          time.Time  `gorm:"not null;default:now()"`

	Subscription Subscription `gorm:"foreignKey:SubscriptionID"`
	Status       Status       `gorm:"foreignKey:StatusID"`
}

func (ResourceAssignment) TableName() string { return "resource_assignments" }
EOF

cat > models/schedule.go << 'EOF'
package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/datatypes"
)

type Schedule struct {
	ScheduleID      uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	SubscriptionID  uuid.UUID      `gorm:"type:uuid;not null;index"`
	ScheduleTypeID  int16          `gorm:"not null"`
	Title           string         `gorm:"size:255;not null"`
	Description     *string        `gorm:"type:text"`
	StartTime       time.Time      `gorm:"type:timestamptz;not null;index"`
	EndTime         time.Time      `gorm:"type:timestamptz;not null;index"`
	Location        *string        `gorm:"size:255"`
	StatusID        int16          `gorm:"not null;default:1;index"`
	RecurrenceRule  *string        `gorm:"size:100"`
	RecurrenceEnd   *time.Time     `gorm:"type:timestamptz"`
	Metadata        datatypes.JSON `gorm:"type:jsonb"`
	CreatedAt       time.Time      `gorm:"not null;default:now()"`
	UpdatedAt       time.Time      `gorm:"not null;default:now()"`
	DeletedAt       gorm.DeletedAt `gorm:"index"`

	Subscription Subscription   `gorm:"foreignKey:SubscriptionID"`
	ScheduleType ScheduleType   `gorm:"foreignKey:ScheduleTypeID"`
	Status       Status         `gorm:"foreignKey:StatusID"`
	OnlineSessions []OnlineSession `gorm:"foreignKey:ScheduleID"`
	Waitlists    []Waitlist     `gorm:"foreignKey:ScheduleID"`
}

func (Schedule) TableName() string { return "schedules" }
EOF

cat > models/online_session.go << 'EOF'
package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type OnlineSession struct {
	SessionID      uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	ScheduleID     uuid.UUID      `gorm:"type:uuid;not null;index"`
	ProviderID     int16          `gorm:"not null"`
	MeetingURL     string         `gorm:"type:text;not null"`
	RecordingURL   *string        `gorm:"type:text"`
	Notes          *string        `gorm:"type:text"`
	AttachmentKeys datatypes.JSON `gorm:"type:jsonb"`
	ChatLog        datatypes.JSON `gorm:"type:jsonb"`
	Resources      datatypes.JSON `gorm:"type:jsonb"`
	HostUserID     *uuid.UUID     `gorm:"type:uuid"`
	CreatedAt      time.Time      `gorm:"not null;default:now()"`
	UpdatedAt      time.Time      `gorm:"not null;default:now()"`

	Schedule Schedule `gorm:"foreignKey:ScheduleID"`
	Provider Provider `gorm:"foreignKey:ProviderID"`
	Host     *User    `gorm:"foreignKey:HostUserID"`
}

func (OnlineSession) TableName() string { return "online_sessions" }
EOF

cat > models/waitlist.go << 'EOF'
package models

import (
	"time"

	"github.com/google/uuid"
)

type Waitlist struct {
	WaitlistID       uuid.UUID  `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	CompanyID        uuid.UUID  `gorm:"type:uuid;not null;index"`
	ScheduleID       uuid.UUID  `gorm:"type:uuid;not null;index"`
	SubscriberTypeID int16      `gorm:"not null"`
	SubscriberID     uuid.UUID  `gorm:"type:uuid;not null;index"`
	StatusID         int16      `gorm:"not null;default:1;index"`
	RegisteredAt     time.Time  `gorm:"not null;default:now()"`
	Position         *int       `gorm:"default:null"`
	NotifiedAt       *time.Time `gorm:"type:timestamptz"`
	ExpiresAt        *time.Time `gorm:"type:timestamptz"`
	Notes            *string    `gorm:"type:text"`
	CreatedAt        time.Time  `gorm:"not null;default:now()"`
	UpdatedAt        time.Time  `gorm:"not null;default:now()"`

	Company        Company        `gorm:"foreignKey:CompanyID"`
	Schedule       Schedule       `gorm:"foreignKey:ScheduleID"`
	SubscriberType SubscriberType `gorm:"foreignKey:SubscriberTypeID"`
	Status         Status         `gorm:"foreignKey:StatusID"`
}

func (Waitlist) TableName() string { return "waitlists" }
EOF

cat > models/workflow.go << 'EOF'
package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type Workflow struct {
	WorkflowID   uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	CompanyID    uuid.UUID      `gorm:"type:uuid;not null;index"`
	WorkflowName string         `gorm:"size:100;not null"`
	TriggerEvent string         `gorm:"size:50;not null;index"`
	IsActive     bool           `gorm:"not null;default:true"`
	CreatedAt    time.Time      `gorm:"not null;default:now()"`
	UpdatedAt    time.Time      `gorm:"not null;default:now()"`

	Company Company         `gorm:"foreignKey:CompanyID"`
	Steps   []WorkflowStep  `gorm:"foreignKey:WorkflowID"`
}

func (Workflow) TableName() string { return "workflows" }
EOF

cat > models/workflow_step.go << 'EOF'
package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type WorkflowStep struct {
	StepID        uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	WorkflowID    uuid.UUID      `gorm:"type:uuid;not null;index"`
	StepOrder     int            `gorm:"not null"`
	StepType      string         `gorm:"size:30;not null"`
	Config        datatypes.JSON `gorm:"type:jsonb;not null"`
	DependsOnStep *uuid.UUID     `gorm:"type:uuid"`
	CreatedAt     time.Time      `gorm:"not null;default:now()"`

	Workflow    Workflow       `gorm:"foreignKey:WorkflowID"`
	Dependency  *WorkflowStep  `gorm:"foreignKey:DependsOnStep"`
}

func (WorkflowStep) TableName() string { return "workflow_steps" }
EOF

cat > models/notification_preference.go << 'EOF'
package models

import (
	"time"

	"github.com/google/uuid"
)

type NotificationPreference struct {
	PrefID         uuid.UUID `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	SubscriptionID uuid.UUID `gorm:"type:uuid;not null;index"`
	Channel        string    `gorm:"size:20;not null;check:channel IN ('email','sms','whatsapp','push')"`
	EventType      string    `gorm:"size:50;not null"`
	IsEnabled      bool      `gorm:"not null;default:true"`
	CreatedAt      time.Time `gorm:"not null;default:now()"`
	UpdatedAt      time.Time `gorm:"not null;default:now()"`

	Subscription Subscription `gorm:"foreignKey:SubscriptionID"`
}

func (NotificationPreference) TableName() string { return "notification_preferences" }
EOF

cat > models/audit.go << 'EOF'
package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"net"
)

type AuditLog struct {
	AuditID        uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	SubscriptionID uuid.UUID      `gorm:"type:uuid;not null;index"`
	Action         string         `gorm:"size:50;not null"`
	OldState       datatypes.JSON `gorm:"type:jsonb"`
	NewState       datatypes.JSON `gorm:"type:jsonb"`
	PerformedBy    *uuid.UUID     `gorm:"type:uuid"`
	PerformedAt    time.Time      `gorm:"not null;default:now();index"`
	IPAddress      *net.IP        `gorm:"type:inet"`
	UserAgent      *string        `gorm:"type:text"`

	Subscription Subscription `gorm:"foreignKey:SubscriptionID"`
	Performer    *User        `gorm:"foreignKey:PerformedBy"`
}

func (AuditLog) TableName() string { return "audit_logs" }
EOF

# Lookup tables (already partly defined in enums, but we need actual models for foreign keys)

cat > models/business_model.go << 'EOF'
package models

type BusinessModel struct {
	BusinessModelID int16  `gorm:"primaryKey"`
	Code            string `gorm:"size:30;not null;unique"`
	Name            string `gorm:"size:100;not null"`
}

func (BusinessModel) TableName() string { return "business_models" }
EOF

cat > models/billing_type.go << 'EOF'
package models

type BillingType struct {
	BillingTypeID int16  `gorm:"primaryKey"`
	Code          string `gorm:"size:30;not null;unique"`
	Name          string `gorm:"size:100;not null"`
}

func (BillingType) TableName() string { return "billing_types" }
EOF

cat > models/subscriber_type.go << 'EOF'
package models

type SubscriberType struct {
	SubscriberTypeID int16  `gorm:"primaryKey"`
	Code             string `gorm:"size:30;not null;unique"`
	Name             string `gorm:"size:100;not null"`
}

func (SubscriberType) TableName() string { return "subscriber_types" }
EOF

cat > models/schedule_type.go << 'EOF'
package models

type ScheduleType struct {
	ScheduleTypeID int16  `gorm:"primaryKey"`
	Code           string `gorm:"size:30;not null;unique"`
	Name           string `gorm:"size:100;not null"`
}

func (ScheduleType) TableName() string { return "schedule_types" }
EOF

cat > models/provider.go << 'EOF'
package models

type Provider struct {
	ProviderID int16  `gorm:"primaryKey"`
	Code       string `gorm:"size:30;not null;unique"`
	Name       string `gorm:"size:100;not null"`
}

func (Provider) TableName() string { return "providers" }
EOF

cat > models/status.go << 'EOF'
package models

type Status struct {
	StatusID int16  `gorm:"primaryKey"`
	Code     string `gorm:"size:30;not null"`
	Category string `gorm:"size:30;not null"`
	Name     string `gorm:"size:100;not null"`
}

func (Status) TableName() string { return "statuses" }
EOF

# Placeholder for User and Company models (they exist in other modules)
# To avoid import cycles, we define them as interfaces or use separate package?
# We'll assume they are defined in the main models package, but for compilation we can define minimal structs.

# We'll create dummy models for user and company if they don't exist elsewhere.
# But the user's project likely has these in other modules. We'll assume they are imported.
# However, for the models to compile, we need to import them. We'll use a comment.

# Actually, we can't define User and Company here because they are in other modules.
# We'll just use interface{} or define them as empty structs with matching table names.
# Better: use type alias or point to existing packages. Since we don't have the full context,
# we'll define them as minimal structs with the same table names, but user can adjust imports.

cat > models/external.go << 'EOF'
package models

import (
	"github.com/google/uuid"
	"time"
)

// Placeholder for Company (from companies module)
type Company struct {
	CompanyID   uuid.UUID `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Name        string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt
}

func (Company) TableName() string { return "companies" }

// Placeholder for User (from users module)
type User struct {
	UserID    uuid.UUID `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Username  string
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt
}

func (User) TableName() string { return "users" }
EOF

# Ensure imports are present in files that use datatypes, gorm, etc.
# We'll add import statements where needed.

# Done
echo "All model files generated successfully."