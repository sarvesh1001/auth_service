package models

type AttendanceEventType struct {
	EventType         string  `json:"event_type" db:"event_type"`
	Category          string  `json:"category" db:"category"`
	Description       *string `json:"description,omitempty" db:"description"`
	IsUserTriggered   bool    `json:"is_user_triggered" db:"is_user_triggered"`
	IsSystemGenerated bool    `json:"is_system_generated" db:"is_system_generated"`
	IsActive          bool    `json:"is_active" db:"is_active"`
}
