package models

import (
	"time"

	"github.com/google/uuid"
)

// NotificationType defines the type of notification.
type NotificationType string

const (
	NotificationTypeInfo         NotificationType = "info"
	NotificationTypeWarning      NotificationType = "warning"
	NotificationTypeAlert        NotificationType = "alert"
	NotificationTypeEvent        NotificationType = "event"
	NotificationTypeAnnouncement NotificationType = "announcement"
)

// NotificationPriority defines the priority level.
type NotificationPriority string

const (
	PriorityLow    NotificationPriority = "low"
	PriorityNormal NotificationPriority = "normal"
	PriorityHigh   NotificationPriority = "high"
	PriorityUrgent NotificationPriority = "urgent"
)

// Notification represents a system notification.
type Notification struct {
	NotificationID uuid.UUID            `json:"notification_id"`
	CompanyID      uuid.UUID            `json:"company_id"`
	Title          string               `json:"title"`
	Message        string               `json:"message"`
	Type           NotificationType     `json:"type"`
	Priority       NotificationPriority `json:"priority"`
	CreatedBy      *uuid.UUID           `json:"created_by,omitempty"`
	UpdatedBy      *uuid.UUID           `json:"updated_by,omitempty"`
	CreatedAt      time.Time            `json:"created_at"`
	ExpiresAt      *time.Time           `json:"expires_at,omitempty"`
	DeletedAt      *time.Time           `json:"deleted_at,omitempty"`
}
