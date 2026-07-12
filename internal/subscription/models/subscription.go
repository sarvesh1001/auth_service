package models

import (
	"auth-service/internal/subscription/models/enums"
	"time"

	"github.com/google/uuid"
)

type Subscription struct {
	SubscriptionID     uuid.UUID                `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"subscriptionId"`
	CompanyID          uuid.UUID                `gorm:"type:uuid;not null;index" json:"companyId"`
	CustomerID         uuid.UUID                `gorm:"type:uuid;not null" json:"customerId"` // from sales.customers
	PlanID             uuid.UUID                `gorm:"type:uuid;not null" json:"planId"`
	Status             enums.SubscriptionStatus `gorm:"type:varchar(20);not null;default:'pending'" json:"status"`
	StartDate          time.Time                `gorm:"type:date;not null;default:CURRENT_DATE" json:"startDate"`
	EndDate            *time.Time               `gorm:"type:date" json:"endDate,omitempty"`
	TrialEnd           *time.Time               `gorm:"type:date" json:"trialEnd,omitempty"`
	BillingStart       time.Time                `gorm:"type:date;not null" json:"billingStart"`
	AutoRenew          bool                     `gorm:"not null;default:true" json:"autoRenew"`
	PauseReason        *string                  `gorm:"type:text" json:"pauseReason,omitempty"`
	CancellationReason *string                  `gorm:"type:text" json:"cancellationReason,omitempty"`
	CancelledAt        *time.Time               `gorm:"type:timestamptz" json:"cancelledAt,omitempty"`
	ContractNumber     *string                  `gorm:"type:varchar(100);uniqueIndex" json:"contractNumber,omitempty"`
	SignedAt           *time.Time               `gorm:"type:timestamptz" json:"signedAt,omitempty"`
	TermsVersion       *string                  `gorm:"type:varchar(20)" json:"termsVersion,omitempty"`
	SignedDocumentKey  *string                  `gorm:"type:text" json:"signedDocumentKey,omitempty"`
	CurrentInvoiceID   *uuid.UUID               `gorm:"type:uuid" json:"currentInvoiceId,omitempty"` // sales.invoices
	LastInvoiceID      *uuid.UUID               `gorm:"type:uuid" json:"lastInvoiceId,omitempty"`
	NextInvoiceID      *uuid.UUID               `gorm:"type:uuid" json:"nextInvoiceId,omitempty"`
	CouponID           *uuid.UUID               `gorm:"type:uuid" json:"couponId,omitempty"` // sales.coupons
	Version            int                      `gorm:"not null;default:1" json:"version"`
	CreatedAt          time.Time                `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt          time.Time                `gorm:"autoUpdateTime" json:"updatedAt"`
	DeletedAt          *time.Time               `gorm:"index" json:"deletedAt,omitempty"`
	SalesOrderID       *uuid.UUID               `gorm:"type:uuid" json:"salesOrderId,omitempty"`       // sales.orders
	ScheduleID         *uuid.UUID               `gorm:"type:uuid" json:"scheduleId,omitempty"`         // external scheduling
	WorkflowID         *uuid.UUID               `gorm:"type:uuid" json:"workflowId,omitempty"`         // external workflow
	NotificationPrefID *uuid.UUID               `gorm:"type:uuid" json:"notificationPrefId,omitempty"` // external notifications
}
