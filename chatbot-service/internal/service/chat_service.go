package service

import (
	"context"
	"fmt"
	"time"

	"chatbot-service/internal/executor"
	"chatbot-service/internal/llm"
	"chatbot-service/internal/models"

	"go.uber.org/zap"
)

type ChatService struct {
	llmClient    llm.Client
	toolExecutor *executor.ToolExecutor
	logger       *zap.Logger
}

// UPDATED: added DeviceID field
type ChatInput struct {
	UserID         string
	CompanyID      interface{}
	SessionType    string
	PermissionMask interface{}
	Message        string
	AuthHeader     string
	DeviceID       string // NEW
}

func NewChatService(
	llmClient llm.Client,
	toolExecutor *executor.ToolExecutor,
	logger *zap.Logger,
) *ChatService {
	return &ChatService{
		llmClient:    llmClient,
		toolExecutor: toolExecutor,
		logger:       logger,
	}
}

func (s *ChatService) Handle(ctx context.Context, input ChatInput) (*models.ChatResponse, error) {
	start := time.Now()

	s.logger.Info("Processing chat request",
		zap.String("user_id", input.UserID),
		zap.String("message", input.Message),
	)

	llmResp, err := s.llmClient.Process(ctx, llm.Request{
		UserID:  input.UserID,
		Message: input.Message,
	})
	if err != nil {
		return nil, fmt.Errorf("llm processing failed: %w", err)
	}

	if llmResp.ToolCall != nil {
		s.logger.Info("LLM requested tool execution",
			zap.String("tool_name", llmResp.ToolCall.Name),
		)

		// UPDATED: pass DeviceID to ToolExecutionInput
		toolResult, err := s.toolExecutor.Execute(ctx, executor.ToolExecutionInput{
			UserID:         input.UserID,
			CompanyID:      input.CompanyID,
			SessionType:    input.SessionType,
			PermissionMask: input.PermissionMask,
			AuthHeader:     input.AuthHeader,
			DeviceID:       input.DeviceID, // NEW
			ToolCall: models.ToolCall{
				Name:      llmResp.ToolCall.Name,
				Arguments: llmResp.ToolCall.Arguments,
			},
		})
		if err != nil {
			return nil, err
		}

		return &models.ChatResponse{
			Success: true,
			Type:    "tool_result",
			Data:    toolResult,
		}, nil
	}

	s.logger.Info("Chat processing complete",
		zap.Duration("duration", time.Since(start)),
	)

	return &models.ChatResponse{
		Success: true,
		Type:    "text",
		Message: llmResp.Content,
	}, nil
}
