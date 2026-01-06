package compensation

import "github.com/google/uuid"

type PayUnit struct {
	PayUnitID   uuid.UUID `json:"pay_unit_id" db:"pay_unit_id"`
	Name        string    `json:"name" db:"name"`
	Description *string   `json:"description" db:"description"`
}
