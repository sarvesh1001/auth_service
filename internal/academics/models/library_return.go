package models

import (
	"time"

	"github.com/google/uuid"
)

type LibraryReturn struct {
	ReturnID   uuid.UUID  `json:"return_id"`
	IssueID    uuid.UUID  `json:"issue_id"`
	ReturnDate time.Time  `json:"return_date"`
	FineAmount *float64   `json:"fine_amount,omitempty"`
	Remarks    string     `json:"remarks,omitempty"`
	ReceivedBy *uuid.UUID `json:"received_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	CreatedBy  *uuid.UUID `json:"created_by,omitempty"`
}
