package executor

import (
	"context"
	"fmt"

	"chatbot-service/internal/models"
)

type Tool interface {
	Name() string
	Execute(ctx context.Context, input models.ToolCallInput) (*models.ToolResult, error)
}

// UPDATED: added DeviceID field
type ToolExecutionInput struct {
	UserID         string
	CompanyID      interface{}
	SessionType    string
	PermissionMask interface{}
	AuthHeader     string
	DeviceID       string // NEW
	ToolCall       models.ToolCall
}

type ToolExecutor struct {
	tools map[string]Tool
}

func NewToolExecutor(tools []Tool) *ToolExecutor {
	toolMap := make(map[string]Tool)
	for _, t := range tools {
		toolMap[t.Name()] = t
	}
	return &ToolExecutor{
		tools: toolMap,
	}
}

func (e *ToolExecutor) Execute(ctx context.Context, input ToolExecutionInput) (*models.ToolResult, error) {
	tool, ok := e.tools[input.ToolCall.Name]
	if !ok {
		return nil, fmt.Errorf("unknown tool: %s", input.ToolCall.Name)
	}

	// UPDATED: pass DeviceID to ToolCallInput
	return tool.Execute(ctx, models.ToolCallInput{
		UserID:         input.UserID,
		CompanyID:      input.CompanyID,
		SessionType:    input.SessionType,
		PermissionMask: input.PermissionMask,
		AuthHeader:     input.AuthHeader,
		DeviceID:       input.DeviceID, // NEW
		Arguments:      input.ToolCall.Arguments,
	})
}
