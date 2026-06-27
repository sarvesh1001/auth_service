package models

import (
	"time"

	"github.com/google/uuid"
)

type ResourceAssignment struct {
	AssignmentID       uuid.UUID  `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	SubscriptionID     uuid.UUID  `gorm:"type:uuid;not null;index"`
	ResourceType       string     `gorm:"size:50;not null;index"`
	ResourceID         uuid.UUID  `gorm:"type:uuid;not null;index"`
	AllocationStrategy string     `gorm:"size:20;not null;default:'exclusive';check:allocation_strategy IN ('exclusive','shared','rotating','priority')"`
	AssignedAt         time.Time  `gorm:"not null;default:now()"`
	AssignedUntil      *time.Time `gorm:"type:timestamptz"`
	StatusID           int16      `gorm:"not null;default:1;index"`
	CreatedAt          time.Time  `gorm:"not null;default:now()"`
	UpdatedAt          time.Time  `gorm:"not null;default:now()"`

	Subscription Subscription `gorm:"foreignKey:SubscriptionID"`
	Status       Status       `gorm:"foreignKey:StatusID"`
}

func (ResourceAssignment) TableName() string { return "resource_assignments" }
