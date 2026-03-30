package models

import (
	"time"

	"github.com/google/uuid"
)

type LibraryBook struct {
	BookID          uuid.UUID  `json:"book_id"`
	CompanyID       uuid.UUID  `json:"company_id"`
	CategoryID      *uuid.UUID `json:"category_id,omitempty"`
	Title           string     `json:"title"`
	Author          string     `json:"author,omitempty"`
	ISBN            string     `json:"isbn,omitempty"`
	Publisher       string     `json:"publisher,omitempty"`
	Edition         string     `json:"edition,omitempty"`
	Language        string     `json:"language,omitempty"`
	Pages           int        `json:"pages,omitempty"`
	PublicationYear int        `json:"publication_year,omitempty"`
	Description     string     `json:"description,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	CreatedBy       *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy       *uuid.UUID `json:"updated_by,omitempty"`
	DeletedAt       *time.Time `json:"deleted_at,omitempty"`
}
