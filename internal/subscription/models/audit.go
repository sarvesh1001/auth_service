package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"net"
)

type AuditLog struct {
	AuditID        uuid.UUID      `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	SubscriptionID uuid.UUID      `gorm:"type:uuid;not null;index"`
	Action         string         `gorm:"size:50;not null"`
	OldState       datatypes.JSON `gorm:"type:jsonb"`
	NewState       datatypes.JSON `gorm:"type:jsonb"`
	PerformedBy    *uuid.UUID     `gorm:"type:uuid"`
	PerformedAt    time.Time      `gorm:"not null;default:now();index"`
	IPAddress      *net.IP        `gorm:"type:inet"`
	UserAgent      *string        `gorm:"type:text"`

	Subscription Subscription `gorm:"foreignKey:SubscriptionID"`
	Performer    *User        `gorm:"foreignKey:PerformedBy"`
}

func (AuditLog) TableName() string { return "audit_logs" }
