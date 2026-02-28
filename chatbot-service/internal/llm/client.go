package llm

import (
	"chatbot-service/internal/models"
	"context"
)

type Client interface {
	Process(ctx context.Context, req Request) (*Response, error)
}

type Request struct {
	UserID    string
	Message   string
	History   []models.ChatMessage
	Arguments map[string]interface{} // NEW
}

type Message struct {
	Role    string // "user" or "assistant"
	Content string
}

type Response struct {
	Content  string
	ToolCall *ToolCall
}

type ToolCall struct {
	Name      string
	Arguments map[string]interface{}
}
