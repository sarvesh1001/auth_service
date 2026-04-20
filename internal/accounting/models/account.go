package models

import (
	"time"

	"github.com/google/uuid"
)

type Account struct {
	AccountID       uuid.UUID  `db:"account_id" json:"account_id"`
	CompanyID       uuid.UUID  `db:"company_id" json:"company_id"`
	AccountCode     string     `db:"account_code" json:"account_code"`
	AccountName     string     `db:"account_name" json:"account_name"`
	AccountType     string     `db:"account_type" json:"account_type"` // asset, liability, equity, revenue, expense
	ParentAccountID *uuid.UUID `db:"parent_account_id" json:"parent_account_id,omitempty"`
	IsActive        bool       `db:"is_active" json:"is_active"`
	Description     *string    `db:"description" json:"description,omitempty"`
	CreatedAt       time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt       time.Time  `db:"updated_at" json:"updated_at"`
	CreatedBy       *uuid.UUID `db:"created_by" json:"created_by,omitempty"`
	UpdatedBy       *uuid.UUID `db:"updated_by" json:"updated_by,omitempty"`
	DeletedAt       *time.Time `db:"deleted_at" json:"deleted_at,omitempty"`
}
