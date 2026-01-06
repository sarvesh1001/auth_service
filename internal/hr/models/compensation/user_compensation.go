package compensation

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

type UserCompensation struct {
	UserID            uuid.UUID       `json:"user_id" db:"user_id"`
	StructureID       uuid.UUID       `json:"structure_id" db:"structure_id"`
	PayUnitID         *uuid.UUID      `json:"pay_unit_id" db:"pay_unit_id"`
	CTCAmount         decimal.Decimal `json:"ctc_amount" db:"ctc_amount"`
	EffectiveFrom     time.Time       `json:"effective_from" db:"effective_from"`
	EffectiveTo       *time.Time      `json:"effective_to" db:"effective_to"`
	AssignedBy        *uuid.UUID      `json:"assigned_by" db:"assigned_by"`
	StructureSnapshot json.RawMessage
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
}
