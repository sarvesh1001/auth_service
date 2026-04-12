// File: internal/academics/models/teacher.go
package models

import (
	"time"

	"github.com/google/uuid"
)

type TeacherStatus string

const (
	TeacherActive   TeacherStatus = "active"
	TeacherInactive TeacherStatus = "inactive"
	TeacherResigned TeacherStatus = "resigned"
)

func IsValidTeacherStatus(s string) bool {
	switch TeacherStatus(s) {
	case TeacherActive, TeacherInactive, TeacherResigned:
		return true
	default:
		return false
	}
}

// Teacher represents a teacher record.
type Teacher struct {
	TeacherID      uuid.UUID     `json:"teacher_id"`
	CompanyID      uuid.UUID     `json:"company_id"`
	UserID         uuid.UUID     `json:"user_id"`
	EmployeeCode   string        `json:"employee_code,omitempty"`
	Qualification  string        `json:"qualification,omitempty"`
	Specialization string        `json:"specialization,omitempty"`
	JoiningDate    *time.Time    `json:"joining_date,omitempty"`
	Status         TeacherStatus `json:"status"`

	// Version removed – optimistic locking not used
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}
