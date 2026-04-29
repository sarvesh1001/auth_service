package service

import (
	"github.com/google/uuid"
)

// TopicAccountingEvents is the Kafka topic for accounting events.

// CreateAccountRequest DTO
type CreateAccountRequest struct {
	AccountID       uuid.UUID  `json:"account_id"`
	CompanyID       uuid.UUID  `json:"company_id"`
	AccountCode     string     `json:"account_code"`
	AccountName     string     `json:"account_name"`
	AccountType     string     `json:"account_type"`
	ParentAccountID *uuid.UUID `json:"parent_account_id,omitempty"`
	IsActive        bool       `json:"is_active"`
	Description     *string    `json:"description,omitempty"`
	CreatedBy       *uuid.UUID `json:"created_by,omitempty"`
}

// BulkCreateAccountsRequest DTO
type BulkCreateAccountsRequest struct {
	Accounts []*CreateAccountRequest
}

type UpdateAccountRequest struct {
	AccountID       uuid.UUID  `json:"account_id"`
	CompanyID       uuid.UUID  `json:"company_id"` // ← add this field
	AccountName     string     `json:"account_name,omitempty"`
	AccountType     string     `json:"account_type,omitempty"`
	ParentAccountID *uuid.UUID `json:"parent_account_id,omitempty"`
	IsActive        bool       `json:"is_active"`
	Description     *string    `json:"description,omitempty"`
	UpdatedBy       *uuid.UUID `json:"updated_by,omitempty"`
}
