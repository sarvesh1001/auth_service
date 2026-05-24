package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type CreditCheckHistory struct {
	CreditHistoryID     uuid.UUID        `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"creditHistoryId"`
	CompanyID           uuid.UUID        `gorm:"type:uuid;not null;index" json:"companyId"`
	CustomerID          uuid.UUID        `gorm:"type:uuid;not null;index" json:"customerId"`
	ActionType          string           `gorm:"type:varchar(30);not null;index" json:"actionType"` // limit_change, hold, release, approval
	PreviousLimit       *decimal.Decimal `gorm:"type:numeric(14,2)" json:"previousLimit,omitempty"`
	NewLimit            *decimal.Decimal `gorm:"type:numeric(14,2)" json:"newLimit,omitempty"`
	PreviousOutstanding *decimal.Decimal `gorm:"type:numeric(14,2)" json:"previousOutstanding,omitempty"`
	NewOutstanding      *decimal.Decimal `gorm:"type:numeric(14,2)" json:"newOutstanding,omitempty"`
	Reason              *string          `gorm:"type:text" json:"reason,omitempty"`
	ApprovedBy          *uuid.UUID       `gorm:"type:uuid;index" json:"approvedBy,omitempty"`
	CreatedBy           *uuid.UUID       `gorm:"type:uuid;index" json:"createdBy,omitempty"`
	CreatedAt           time.Time        `gorm:"not null;default:now();index" json:"createdAt"`
}
