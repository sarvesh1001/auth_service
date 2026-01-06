package compensation

import (
	"time"

	"github.com/shopspring/decimal"

	"github.com/google/uuid"
)

type CompensationStructure struct {
	StructureID   uuid.UUID   `json:"structure_id" db:"structure_id"`
	CompanyID     uuid.UUID   `json:"company_id" db:"company_id"`
	StructureCode string      `json:"structure_code" db:"structure_code"`
	Name          string      `json:"name" db:"name"`
	Currency      string      `json:"currency" db:"currency"`
	Components    []Component `json:"components" db:"components"`
	IsActive      bool        `json:"is_active" db:"is_active"`
	CreatedAt     time.Time   `json:"created_at" db:"created_at"`
}

type Component struct {
	Code    string           `json:"code"`
	Type    string           `json:"type"` // earning, deduction
	Calc    string           `json:"calc"` // fixed, percentage, hourly
	Taxable bool             `json:"taxable"`
	Base    *decimal.Decimal `json:"base,omitempty"`  // For percentage calculations
	Value   *decimal.Decimal `json:"value,omitempty"` // Numeric value or percentage
}
