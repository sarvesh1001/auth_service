package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"

	"auth-service/internal/subscription/models/enums"
)

type PlanItem struct {
	PlanItemID uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"planItemId"`
	PlanID     uuid.UUID `gorm:"type:uuid;not null;index" json:"planId"`

	// New fields for event‑driven product sync
	CompanyID uuid.UUID              `gorm:"type:uuid;not null;index" json:"companyId"`   // ✅ Scoping for sales listener
	TaxRate   *decimal.Decimal       `gorm:"type:numeric(10,2)" json:"taxRate,omitempty"` // ✅ Override product tax rate
	ProductID *uuid.UUID             `gorm:"type:uuid;index" json:"productId,omitempty"`  // ✅ Link to sales.product
	Metadata  map[string]interface{} `gorm:"type:jsonb" json:"metadata,omitempty"`        // ✅ Extensibility

	ItemType        enums.ItemType  `gorm:"type:varchar(20);not null" json:"itemType"`
	Name            string          `gorm:"type:varchar(255);not null" json:"name"`
	Description     *string         `gorm:"type:text" json:"description,omitempty"`
	FeatureKey      *string         `gorm:"type:varchar(100)" json:"featureKey,omitempty"`
	BillingPolicyID *uuid.UUID      `gorm:"type:uuid" json:"billingPolicyId,omitempty"`
	Price           decimal.Decimal `gorm:"type:numeric(14,2);not null;default:0" json:"price"`
	Currency        string          `gorm:"type:varchar(3);not null;default:'USD'" json:"currency"`
	EffectiveFrom   time.Time       `gorm:"type:date;not null;default:CURRENT_DATE" json:"effectiveFrom"`
	EffectiveTo     *time.Time      `gorm:"type:date" json:"effectiveTo,omitempty"`
	IsMandatory     bool            `gorm:"not null;default:false" json:"isMandatory"`
	IsActive        bool            `gorm:"not null;default:true" json:"isActive"`
	CreatedAt       time.Time       `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt       time.Time       `gorm:"autoUpdateTime" json:"updatedAt"`
	DeletedAt       *time.Time      `gorm:"index" json:"deletedAt,omitempty"`
}
