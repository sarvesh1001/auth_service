package models

import (
	"time"

	"github.com/google/uuid"
)

type FeeStructure struct {
	FeeStructureID   uuid.UUID  `json:"fee_structure_id"`
	AcademicYearID   uuid.UUID  `json:"academic_year_id"`
	CourseID         uuid.UUID  `json:"course_id"`
	SectionID        *uuid.UUID `json:"section_id,omitempty"`
	FeeStructureName string     `json:"fee_structure_name"`
	TotalAmount      float64    `json:"total_amount"` // numeric(12,2)
	IsActive         bool       `json:"is_active"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	CreatedBy        *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy        *uuid.UUID `json:"updated_by,omitempty"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty"`
}

type FeeStructureItem struct {
	ItemID         uuid.UUID  `json:"item_id"`
	FeeStructureID uuid.UUID  `json:"fee_structure_id"`
	FeeHead        string     `json:"fee_head"`
	Amount         float64    `json:"amount"`
	IsMandatory    bool       `json:"is_mandatory"`
	Description    string     `json:"description,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
}
