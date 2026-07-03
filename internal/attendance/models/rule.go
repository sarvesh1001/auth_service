package models

import (
	"time"

	"github.com/google/uuid"
)

type CompanyAttendanceRules struct {
	CompanyID             uuid.UUID `json:"company_id" db:"company_id"`
	AllowedSourceTypes    []string  `json:"allowed_source_types" db:"allowed_source_types"`
	AllowMultipleCheckins bool      `json:"allow_multiple_checkins" db:"allow_multiple_checkins"`
	Timezone              string    `json:"timezone" db:"timezone"`
	CreatedAt             time.Time `json:"created_at" db:"created_at"`
}

type DepartmentAttendanceRules struct {
	RuleID             uuid.UUID `json:"rule_id" db:"rule_id"`
	CompanyID          uuid.UUID `json:"company_id" db:"company_id"`
	DepartmentID       uuid.UUID `json:"department_id" db:"department_id"`
	AllowedSourceTypes []string  `json:"allowed_source_types" db:"allowed_source_types"`
	AllowedEventTypes  []string  `json:"allowed_event_types" db:"allowed_event_types"`
	RequireLocation    bool      `json:"require_location" db:"require_location"`
	RequireDevice      bool      `json:"require_device" db:"require_device"`
	CreatedAt          time.Time `json:"created_at" db:"created_at"`
}

type UserAttendanceProfile struct {
	UserID              uuid.UUID `json:"user_id" db:"user_id"`
	CompanyID           uuid.UUID `json:"company_id" db:"company_id"`
	OverrideSourceTypes []string  `json:"override_source_types,omitempty" db:"override_source_types"`
	OverrideEventTypes  []string  `json:"override_event_types,omitempty" db:"override_event_types"`
	CreatedAt           time.Time `json:"created_at" db:"created_at"`
}

type ResolvedAttendanceRules struct {
	CompanyID             uuid.UUID       `json:"company_id"`
	Timezone              string          `json:"timezone"`
	AllowMultipleCheckins bool            `json:"allow_multiple_checkins"`
	AllowedSourceTypesMap map[string]bool `json:"-"`
	AllowedEventTypesMap  map[string]bool `json:"-"`
	AllowAllEventTypes    bool            `json:"allow_all_event_types"`
	AllowedSourceTypes    []string        `json:"allowed_source_types"`
	AllowedEventTypes     []string        `json:"allowed_event_types"`
	RequireLocation       bool            `json:"require_location"`
	RequireDevice         bool            `json:"require_device"`
	RequireReference      bool            `json:"require_reference"`
	SourceLevel           string          `json:"source_level"`
	AppliedAt             time.Time       `json:"applied_at"`
	PolicyID              *uuid.UUID      `json:"policy_id,omitempty"`
	PolicyRules           *PolicyRules    `json:"policy_rules,omitempty"`
	WorkCenterCode        *string         `json:"work_center_code,omitempty"`
	PositionID            *uuid.UUID      `json:"position_id,omitempty"`
	PolicySource          string          `json:"policy_source"`
}
