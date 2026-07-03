package models

import (
	"time"

	"github.com/google/uuid"
)

type AttendanceLocation struct {
	LocationID   uuid.UUID `json:"location_id" db:"location_id"`
	CompanyID    uuid.UUID `json:"company_id" db:"company_id"`
	Name         *string   `json:"name" db:"name"`
	LocationCode *string   `json:"location_code,omitempty" db:"location_code"`
	LocationType *string   `json:"location_type" db:"location_type"`
	Zone         *string   `json:"zone,omitempty" db:"zone"`
	GeoLat       *float64  `json:"geo_lat" db:"geo_lat"`
	GeoLng       *float64  `json:"geo_lng" db:"geo_lng"`
	IsActive     bool      `json:"is_active" db:"is_active"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}
