package models

import (
	"time"
	"github.com/google/uuid"
	"net"
)

type AuditLog struct {
	AuditID        uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"auditId"`
	SubscriptionID uuid.UUID  `gorm:"type:uuid;not null;index" json:"subscriptionId"`
	Action         string     `gorm:"type:varchar(50);not null" json:"action"`
	OldState       JSONB      `gorm:"type:jsonb" json:"oldState,omitempty"`
	NewState       JSONB      `gorm:"type:jsonb" json:"newState,omitempty"`
	PerformedBy    *uuid.UUID `gorm:"type:uuid" json:"performedBy,omitempty"`
	PerformedAt    time.Time  `gorm:"type:timestamptz;not null;default:now()" json:"performedAt"`
	IPAddress      *net.IP    `gorm:"type:inet" json:"ipAddress,omitempty"`
	UserAgent      *string    `gorm:"type:text" json:"userAgent,omitempty"`
}
