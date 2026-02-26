package tools

import (
	"chatbot-service/internal/models"
	"context"
)

type Tool interface {
	Name() string
	Execute(ctx context.Context, input models.ToolCallInput) (*models.ToolResult, error)
}
