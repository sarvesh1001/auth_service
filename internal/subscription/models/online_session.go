package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type OnlineSession struct {
	SessionID      uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	ScheduleID     uuid.UUID      `gorm:"type:uuid;not null;index"`
	ProviderID     int16          `gorm:"not null"`
	MeetingURL     string         `gorm:"type:text;not null"`
	RecordingURL   *string        `gorm:"type:text"`
	Notes          *string        `gorm:"type:text"`
	AttachmentKeys []string       `gorm:"type:text[]"` // changed (nullable)
	ChatLog        datatypes.JSON `gorm:"type:jsonb"`
	Resources      datatypes.JSON `gorm:"type:jsonb"`
	HostUserID     *uuid.UUID     `gorm:"type:uuid"`
	CreatedAt      time.Time      `gorm:"not null;default:now()"`
	UpdatedAt      time.Time      `gorm:"not null;default:now()"`
	Schedule       Schedule       `gorm:"foreignKey:ScheduleID"`
	Provider       Provider       `gorm:"foreignKey:ProviderID"`
	Host           *User          `gorm:"foreignKey:HostUserID"`
}

func (OnlineSession) TableName() string { return "online_sessions" }
