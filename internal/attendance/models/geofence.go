package models

import (
	"time"

	"github.com/google/uuid"
)

// Geofence represents a physical zone (gate, floor, parking lot) belonging
// to exactly one employment location (public.locations).
//
// A geofence is a sub-dimension of an employment location:
//
//	public.locations (Delhi HQ)
//	    ├── attendance.geofences (Delhi HQ — Main Gate)
//	    ├── attendance.geofences (Delhi HQ — Parking Lot)
//	    └── attendance.geofences (Delhi HQ — Loading Dock)
//
// Devices sit inside a geofence. Attendance events snapshot the geofence
// they occurred in. See docs/location-architecture.md for the full model.
type Geofence struct {
	GeofenceID           uuid.UUID `json:"geofence_id" db:"geofence_id"`
	CompanyID            uuid.UUID `json:"company_id" db:"company_id"`
	EmploymentLocationID uuid.UUID `json:"employment_location_id" db:"employment_location_id"`

	Name         *string  `json:"name,omitempty" db:"name"`
	LocationCode *string  `json:"location_code,omitempty" db:"location_code"`
	LocationType *string  `json:"location_type,omitempty" db:"location_type"`
	Zone         *string  `json:"zone,omitempty" db:"zone"`
	GeoLat       *float64 `json:"geo_lat,omitempty" db:"geo_lat"`
	GeoLng       *float64 `json:"geo_lng,omitempty" db:"geo_lng"`

	IsActive  bool      `json:"is_active" db:"is_active"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}
