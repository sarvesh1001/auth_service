package models

import (
	"time"

	"github.com/google/uuid"
)

type AssignmentComment struct {
	CommentID    uuid.UUID `json:"comment_id"`
	SubmissionID uuid.UUID `json:"submission_id"`
	CommentBy    uuid.UUID `json:"comment_by"`
	Comment      string    `json:"comment"`
	CreatedAt    time.Time `json:"created_at"`
	// CreatedBy removed – actor is comment_by
}
