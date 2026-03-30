package models

import (
	"time"

	"github.com/google/uuid"
)

// TeacherSection links a teacher to a section.
type TeacherSection struct {
	ID             uuid.UUID `json:"id"`
	TeacherID      uuid.UUID `json:"teacher_id"`
	SectionID      uuid.UUID `json:"section_id"`
	IsClassTeacher bool      `json:"is_class_teacher"`
	CreatedAt      time.Time `json:"created_at"`
}
