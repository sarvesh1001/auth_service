package models

import (
	"time"

	"github.com/google/uuid"
)

// TargetType defines the type of entity that can receive a notification.
type TargetType string

const (
	TargetStudent TargetType = "student"
	TargetTeacher TargetType = "teacher"
	TargetSection TargetType = "section"
	TargetCourse  TargetType = "course"
	TargetCompany TargetType = "company"
	TargetUser    TargetType = "user"
)

// NotificationTarget specifies the recipients of a notification.
type NotificationTarget struct {
	NotificationTargetID uuid.UUID  `json:"notification_target_id"`
	NotificationID       uuid.UUID  `json:"notification_id"`
	TargetType           TargetType `json:"target_type"`
	TargetEntityID       uuid.UUID  `json:"target_entity_id"`
	CreatedAt            time.Time  `json:"created_at"`
	CreatedBy            *uuid.UUID `json:"created_by,omitempty"`
}
