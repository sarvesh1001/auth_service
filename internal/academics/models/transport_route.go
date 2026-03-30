package models

import (
	"time"

	"github.com/google/uuid"
)

type TransportRoute struct {
	RouteID    uuid.UUID  `json:"route_id"`
	CompanyID  uuid.UUID  `json:"company_id"`
	RouteName  string     `json:"route_name"`
	StartPoint string     `json:"start_point,omitempty"`
	EndPoint   string     `json:"end_point,omitempty"`
	DistanceKm *float64   `json:"distance_km,omitempty"`
	IsActive   bool       `json:"is_active"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	CreatedBy  *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy  *uuid.UUID `json:"updated_by,omitempty"`
	DeletedAt  *time.Time `json:"deleted_at,omitempty"`
}
