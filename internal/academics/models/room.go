// File: internal/academics/models/room.go
package models

import (
	"time"

	"github.com/google/uuid"
)

type Room struct {
	RoomID    uuid.UUID  `json:"room_id"`
	CompanyID uuid.UUID  `json:"company_id"`
	RoomCode  string     `json:"room_code"`
	RoomName  string     `json:"room_name,omitempty"`
	Capacity  int        `json:"capacity,omitempty"`
	Building  string     `json:"building,omitempty"`
	Floor     int        `json:"floor,omitempty"`
	IsActive  bool       `json:"is_active"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}
