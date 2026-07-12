package analytics

import (
	"time"
	"github.com/google/uuid"
)

type ChurnReason struct {
	CompanyID      uuid.UUID  `gorm:"type:uuid;primaryKey" json:"companyId"`
	SubscriptionID uuid.UUID  `gorm:"type:uuid;primaryKey" json:"subscriptionId"`
	ChurnDate      time.Time  `gorm:"type:date;not null" json:"churnDate"`
	Reason         *string    `gorm:"type:text" json:"reason,omitempty"`
	Category       *string    `gorm:"type:varchar(50)" json:"category,omitempty"`
	CreatedAt      time.Time  `gorm:"default:now()" json:"createdAt"`
}
