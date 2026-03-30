package models

import (
	"time"

	"github.com/google/uuid"
)

type StudentTransportAssignment struct {
	AssignmentID  uuid.UUID  `json:"assignment_id"`
	StudentID     uuid.UUID  `json:"student_id"`
	RouteID       uuid.UUID  `json:"route_id"`
	StopID        uuid.UUID  `json:"stop_id"`
	PickupPoint   string     `json:"pickup_point,omitempty"`
	DropPoint     string     `json:"drop_point,omitempty"`
	EffectiveFrom time.Time  `json:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty"`
	IsActive      bool       `json:"is_active"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	CreatedBy     *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy     *uuid.UUID `json:"updated_by,omitempty"`
}
