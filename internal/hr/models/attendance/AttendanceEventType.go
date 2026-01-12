package attendance

import (
	"time"

	"github.com/google/uuid"
)

// AttendanceEventType represents a valid attendance event type
type AttendanceEventType struct {
	EventType         string  `json:"event_type"`
	Category          string  `json:"category"`
	Description       *string `json:"description,omitempty"`
	IsUserTriggered   bool    `json:"is_user_triggered"`
	IsSystemGenerated bool    `json:"is_system_generated"`
	IsActive          bool    `json:"is_active"`
}

// AttendanceSourceType represents a valid attendance source type
type AttendanceSourceType struct {
	SourceType        string  `json:"source_type"`
	Description       *string `json:"description,omitempty"`
	RequiresReference bool    `json:"requires_reference"`
}

// CompanyAttendanceRules represents company-level attendance rules
type CompanyAttendanceRules struct {
	CompanyID             uuid.UUID `json:"company_id"`
	AllowedSourceTypes    []string  `json:"allowed_source_types"`
	AllowMultipleCheckins bool      `json:"allow_multiple_checkins"`
	Timezone              string    `json:"timezone"`
	CreatedAt             time.Time `json:"created_at"`
}

// DepartmentAttendanceRules represents department-level attendance rules
type DepartmentAttendanceRules struct {
	RuleID             uuid.UUID `json:"rule_id"`
	CompanyID          uuid.UUID `json:"company_id"`
	DepartmentID       uuid.UUID `json:"department_id"`
	AllowedSourceTypes []string  `json:"allowed_source_types"`
	AllowedEventTypes  []string  `json:"allowed_event_types"`
	RequireLocation    bool      `json:"require_location"`
	RequireDevice      bool      `json:"require_device"`
	CreatedAt          time.Time `json:"created_at"`
}

// UserAttendanceProfile represents user-level attendance overrides
type UserAttendanceProfile struct {
	UserID              uuid.UUID `json:"user_id"`
	CompanyID           uuid.UUID `json:"company_id"`
	OverrideSourceTypes []string  `json:"override_source_types,omitempty"`
	OverrideEventTypes  []string  `json:"override_event_types,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
}

type ResolvedAttendanceRules struct {
	// Company
	CompanyID             uuid.UUID
	Timezone              string
	AllowMultipleCheckins bool

	// Internal (fast validation)
	AllowedSourceTypesMap map[string]bool
	AllowedEventTypesMap  map[string]bool
	AllowAllEventTypes    bool

	// API output
	AllowedSourceTypes []string
	AllowedEventTypes  []string

	// Requirements
	RequireLocation  bool
	RequireDevice    bool
	RequireReference bool

	// Metadata
	SourceLevel string // company | department | user_override
	AppliedAt   time.Time
}
