package models

import (
	"time"

	"github.com/google/uuid"
)

type CopyStatus string

const (
	CopyStatusAvailable CopyStatus = "available"
	CopyStatusIssued    CopyStatus = "issued"
	CopyStatusLost      CopyStatus = "lost"
	CopyStatusDamaged   CopyStatus = "damaged"
	CopyStatusReserved  CopyStatus = "reserved"
)

func IsValidCopyStatus(s string) bool {
	switch CopyStatus(s) {
	case CopyStatusAvailable, CopyStatusIssued, CopyStatusLost, CopyStatusDamaged, CopyStatusReserved:
		return true
	default:
		return false
	}
}

type LibraryBookCopy struct {
	CopyID        uuid.UUID  `json:"copy_id"`
	BookID        uuid.UUID  `json:"book_id"`
	AccessionNo   string     `json:"accession_no"`
	Status        CopyStatus `json:"status"`
	PurchaseDate  *time.Time `json:"purchase_date,omitempty"`
	Cost          *float64   `json:"cost,omitempty"`
	ShelfLocation string     `json:"shelf_location,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	CreatedBy     *uuid.UUID `json:"created_by,omitempty"`
}
