package models

import (
	"time"
	"github.com/google/uuid"
)

type SubscriptionVersion struct {
	VersionID      uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"versionId"`
	SubscriptionID uuid.UUID  `gorm:"type:uuid;not null;index" json:"subscriptionId"`
	VersionNumber  int        `gorm:"not null" json:"versionNumber"`
	Snapshot       JSONB      `gorm:"type:jsonb;not null" json:"snapshot"`
	Reason         *string    `gorm:"type:text" json:"reason,omitempty"`
	CreatedAt      time.Time  `gorm:"not null;default:now()" json:"createdAt"`
}
