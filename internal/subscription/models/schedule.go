package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/datatypes"
)

type Schedule struct {
	ScheduleID      uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	SubscriptionID  uuid.UUID      `gorm:"type:uuid;not null;index"`
	ScheduleTypeID  int16          `gorm:"not null"`
	Title           string         `gorm:"size:255;not null"`
	Description     *string        `gorm:"type:text"`
	StartTime       time.Time      `gorm:"type:timestamptz;not null;index"`
	EndTime         time.Time      `gorm:"type:timestamptz;not null;index"`
	Location        *string        `gorm:"size:255"`
	StatusID        int16          `gorm:"not null;default:1;index"`
	RecurrenceRule  *string        `gorm:"size:100"`
	RecurrenceEnd   *time.Time     `gorm:"type:timestamptz"`
	Metadata        datatypes.JSON `gorm:"type:jsonb"`
	CreatedAt       time.Time      `gorm:"not null;default:now()"`
	UpdatedAt       time.Time      `gorm:"not null;default:now()"`
	DeletedAt       gorm.DeletedAt `gorm:"index"`

	Subscription Subscription   `gorm:"foreignKey:SubscriptionID"`
	ScheduleType ScheduleType   `gorm:"foreignKey:ScheduleTypeID"`
	Status       Status         `gorm:"foreignKey:StatusID"`
	OnlineSessions []OnlineSession `gorm:"foreignKey:ScheduleID"`
	Waitlists    []Waitlist     `gorm:"foreignKey:ScheduleID"`
}

func (Schedule) TableName() string { return "schedules" }
