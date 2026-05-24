package models

import (
	"auth-service/internal/sales/models/enums"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type SalesRepCommission struct {
	CommissionID   uuid.UUID                `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"commissionId"`
	CompanyID      uuid.UUID                `gorm:"type:uuid;not null;index" json:"companyId"`
	SalesRepID     uuid.UUID                `gorm:"type:uuid;not null;index" json:"salesRepId"`
	EffectiveFrom  time.Time                `gorm:"type:date;not null" json:"effectiveFrom"`
	EffectiveTo    *time.Time               `gorm:"type:date" json:"effectiveTo,omitempty"`
	CommissionRate decimal.Decimal          `gorm:"type:numeric(5,2);not null;check:commission_rate >=0 AND commission_rate <=100" json:"commissionRate"`
	AppliesTo      enums.CommissionBaseType `gorm:"type:commission_base_type;not null" json:"appliesTo"`
	ProductID      *uuid.UUID               `gorm:"type:uuid;index" json:"productId,omitempty"`
	CreatedAt      time.Time                `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt      time.Time                `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy      *uuid.UUID               `gorm:"type:uuid" json:"createdBy,omitempty"`
	UpdatedBy      *uuid.UUID               `gorm:"type:uuid" json:"updatedBy,omitempty"`
}
