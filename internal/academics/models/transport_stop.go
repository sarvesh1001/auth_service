package models

import (
	"time"

	"github.com/google/uuid"
)

type TransportStop struct {
	StopID     uuid.UUID  `json:"stop_id"`
	RouteID    uuid.UUID  `json:"route_id"`
	StopName   string     `json:"stop_name"`
	StopOrder  int        `json:"stop_order"`
	Latitude   *float64   `json:"latitude,omitempty"`
	Longitude  *float64   `json:"longitude,omitempty"`
	PickupTime *time.Time `json:"pickup_time,omitempty"`
	DropTime   *time.Time `json:"drop_time,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	CreatedBy  *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy  *uuid.UUID `json:"updated_by,omitempty"`
}
