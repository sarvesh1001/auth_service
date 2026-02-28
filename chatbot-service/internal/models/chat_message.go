package models

import (
	"time"

	"github.com/google/uuid"
)

type ChatRequest struct {
	Message   string                 `json:"message"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

type ChatResponse struct {
	Success bool        `json:"success"`
	Type    string      `json:"type"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type ChatMessage struct {
	ID          uuid.UUID  `json:"id"`
	UserID      uuid.UUID  `json:"user_id"`
	CompanyID   *uuid.UUID `json:"company_id,omitempty"`
	Role        string     `json:"role"` // user, assistant, tool
	Content     string     `json:"content,omitempty"`
	ToolName    *string    `json:"tool_name,omitempty"`
	ToolSuccess *bool      `json:"tool_success,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}
