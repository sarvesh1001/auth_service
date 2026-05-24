package discount

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"gorm.io/datatypes"

	"auth-service/internal/sales/models/enums"
)

type AutomaticDiscount struct {
	AutoDiscountID     uuid.UUID          `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"autoDiscountId"`
	CompanyID          uuid.UUID          `gorm:"type:uuid;not null;index" json:"companyId"`
	Name               string             `gorm:"type:varchar(255);not null" json:"name"`
	Description        *string            `gorm:"type:text" json:"description,omitempty"`
	DiscountType       enums.DiscountType `gorm:"type:discount_type;not null" json:"discountType"`
	DiscountValue      decimal.Decimal    `gorm:"type:numeric(14,4);not null" json:"discountValue"`
	MaxDiscountAmount  *decimal.Decimal   `gorm:"type:numeric(14,4)" json:"maxDiscountAmount,omitempty"`
	MinOrderAmount     *decimal.Decimal   `gorm:"type:numeric(14,4)" json:"minOrderAmount,omitempty"`
	ApplicableProducts datatypes.JSON     `gorm:"type:jsonb" json:"applicableProducts,omitempty"`
	StartDate          time.Time          `gorm:"type:timestamptz;not null" json:"startDate"`
	EndDate            time.Time          `gorm:"type:timestamptz;not null" json:"endDate"`
	IsActive           bool               `gorm:"not null;default:true" json:"isActive"`
	Priority           int                `gorm:"not null;default:0" json:"priority"`
	CreatedAt          time.Time          `gorm:"not null;default:now()" json:"createdAt"`
	UpdatedAt          time.Time          `gorm:"autoUpdateTime" json:"updatedAt"`
	CreatedBy          *uuid.UUID         `gorm:"type:uuid" json:"createdBy,omitempty"`
	UpdatedBy          *uuid.UUID         `gorm:"type:uuid" json:"updatedBy,omitempty"`
}

func (AutomaticDiscount) TableName() string {
	return "sales.automatic_discounts"
}
