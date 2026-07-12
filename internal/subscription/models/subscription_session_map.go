package models

import (
	"time"
	"github.com/google/uuid"
)

type SubscriptionSessionMap struct {
	MapID          uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"mapId"`
	SubscriptionID uuid.UUID  `gorm:"type:uuid;not null;index" json:"subscriptionId"`
	SessionType    string     `gorm:"type:varchar(50);not null" json:"sessionType"`
	SessionID      uuid.UUID  `gorm:"type:uuid;not null" json:"sessionId"`
	CreatedAt      time.Time  `gorm:"not null;default:now()" json:"createdAt"`
}
