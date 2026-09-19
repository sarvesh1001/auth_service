package models

import (
	"time"

	"github.com/google/uuid"
)

// CostCenter is an accounting dimension. Ledger entries and employee
// profiles both reference it. Employees carry it for payroll journal
// snapshotting; ledger entries carry it for departmental / cost-center P&L.
type CostCenter struct {
	CostCenterID   uuid.UUID  `db:"cost_center_id"   json:"cost_center_id"`
	CompanyID      uuid.UUID  `db:"company_id"       json:"company_id"`
	CostCenterCode string     `db:"cost_center_code" json:"cost_center_code"`
	CostCenterName string     `db:"cost_center_name" json:"cost_center_name"`
	Description    *string    `db:"description"      json:"description,omitempty"`
	ParentID       *uuid.UUID `db:"parent_id"        json:"parent_id,omitempty"`
	AccountID      *uuid.UUID `db:"account_id"       json:"account_id,omitempty"`
	IsActive       bool       `db:"is_active"        json:"is_active"`
	CreatedAt      time.Time  `db:"created_at"       json:"created_at"`
	UpdatedAt      time.Time  `db:"updated_at"       json:"updated_at"`
	CreatedBy      *uuid.UUID `db:"created_by"       json:"created_by,omitempty"`
	UpdatedBy      *uuid.UUID `db:"updated_by"       json:"updated_by,omitempty"`
	DeletedAt      *time.Time `db:"deleted_at"       json:"deleted_at,omitempty"`
}

// CostCenterNode is the tree-friendly view returned by list endpoints
// when hierarchy is requested. Children are populated by the service
// layer after fetching a flat list.
type CostCenterNode struct {
	CostCenter
	Children []*CostCenterNode `json:"children,omitempty"`
}
