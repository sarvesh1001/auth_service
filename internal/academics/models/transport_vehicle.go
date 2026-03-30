package models

import (
	"time"

	"github.com/google/uuid"
)

type TransportVehicle struct {
	VehicleID       uuid.UUID  `json:"vehicle_id"`
	CompanyID       uuid.UUID  `json:"company_id"`
	VehicleNo       string     `json:"vehicle_no"`
	VehicleType     string     `json:"vehicle_type,omitempty"`
	Capacity        *int       `json:"capacity,omitempty"`
	InsuranceExpiry *time.Time `json:"insurance_expiry,omitempty"`
	FitnessExpiry   *time.Time `json:"fitness_expiry,omitempty"`
	IsActive        bool       `json:"is_active"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	CreatedBy       *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy       *uuid.UUID `json:"updated_by,omitempty"`
	DeletedAt       *time.Time `json:"deleted_at,omitempty"`
}
