package models

import (
	"time"

	"github.com/google/uuid"
)

// TeacherSubject links a teacher to a subject.
type TeacherSubject struct {
	ID        uuid.UUID `json:"id"`
	TeacherID uuid.UUID `json:"teacher_id"`
	SubjectID uuid.UUID `json:"subject_id"`
	IsPrimary bool      `json:"is_primary"`
	CreatedAt time.Time `json:"created_at"`
}
