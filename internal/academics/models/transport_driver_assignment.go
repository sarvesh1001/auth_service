package models

import (
	"time"

	"github.com/google/uuid"
)

type TransportDriverAssignment struct {
	AssignmentID   uuid.UUID  `json:"assignment_id"`
	VehicleID      uuid.UUID  `json:"vehicle_id"`
	DriverName     string     `json:"driver_name"`
	DriverPhone    string     `json:"driver_phone,omitempty"`
	DriverLicense  string     `json:"driver_license,omitempty"`
	AssignmentDate time.Time  `json:"assignment_date"`
	EndDate        *time.Time `json:"end_date,omitempty"`
	IsActive       bool       `json:"is_active"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy      *uuid.UUID `json:"updated_by,omitempty"`
}
