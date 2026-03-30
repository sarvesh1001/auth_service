package models

import (
	"time"

	"github.com/google/uuid"
)

type Assignment struct {
	AssignmentID  uuid.UUID  `json:"assignment_id"`
	SectionID     uuid.UUID  `json:"section_id"`
	SubjectID     uuid.UUID  `json:"subject_id"`
	TeacherID     uuid.UUID  `json:"teacher_id"`
	Title         string     `json:"title"`
	Description   string     `json:"description,omitempty"`
	DueDate       time.Time  `json:"due_date"`
	MaxMarks      *float64   `json:"max_marks,omitempty"`
	AttachmentURL string     `json:"attachment_url,omitempty"`
	IsPublished   bool       `json:"is_published"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	CreatedBy     *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy     *uuid.UUID `json:"updated_by,omitempty"`
	DeletedAt     *time.Time `json:"deleted_at,omitempty"`
}
