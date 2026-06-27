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
