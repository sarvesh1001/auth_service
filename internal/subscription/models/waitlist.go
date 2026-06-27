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
