package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"chatbot-service/internal/executor"
	"chatbot-service/internal/llm"
	"chatbot-service/internal/models"
	"chatbot-service/internal/repository"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type ChatService struct {
	llmClient        llm.Client
	toolExecutor     *executor.ToolExecutor
	conversationRepo repository.ConversationRepository
	logger           *zap.Logger
}

func NewChatService(
	llmClient llm.Client,
	toolExecutor *executor.ToolExecutor,
	conversationRepo repository.ConversationRepository,
	logger *zap.Logger,
) *ChatService {
	return &ChatService{
		llmClient:        llmClient,
		toolExecutor:     toolExecutor,
		conversationRepo: conversationRepo,
		logger:           logger,
	}
}

type ChatInput struct {
	UserID         string
	CompanyID      interface{}
	SessionType    string
	PermissionMask interface{}
	Message        string
	AuthHeader     string
	DeviceID       string
	Arguments      map[string]interface{} // NEW
}

func (s *ChatService) Handle(ctx context.Context, input ChatInput) (*models.ChatResponse, error) {
	start := time.Now()

	userUUID, err := uuid.Parse(input.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user_id format: %w", err)
	}

	history, err := s.conversationRepo.GetRecentMessages(ctx, input.UserID, 5)
	if err != nil {
		s.logger.Error("Failed to load conversation history", zap.Error(err))
	}

	s.logger.Info("Processing chat request",
		zap.String("user_id", input.UserID),
		zap.String("message", input.Message),
		zap.Int("history_count", len(history)),
	)

	userMsg := &models.ChatMessage{
		ID:        uuid.New(),
		UserID:    userUUID,
		CompanyID: parseCompanyID(input.CompanyID),
		Role:      "user",
		Content:   input.Message,
		CreatedAt: time.Now(),
	}
	if err := s.conversationRepo.SaveMessage(ctx, userMsg); err != nil {
		s.logger.Error("Failed to save user message", zap.Error(err))
	}

	llmReq := llm.Request{
		UserID:    input.UserID,
		Message:   input.Message,
		History:   history,
		Arguments: input.Arguments, // NEW: pass arguments
	}

	llmResp, err := s.llmClient.Process(ctx, llmReq)
	if err != nil {
		return nil, fmt.Errorf("llm processing failed: %w", err)
	}

	var response *models.ChatResponse

	if llmResp.ToolCall != nil {
		s.logger.Info("LLM requested tool execution",
			zap.String("tool_name", llmResp.ToolCall.Name),
		)

		toolResult, err := s.toolExecutor.Execute(ctx, executor.ToolExecutionInput{
			UserID:         input.UserID,
			CompanyID:      input.CompanyID,
			SessionType:    input.SessionType,
			PermissionMask: input.PermissionMask,
			AuthHeader:     input.AuthHeader,
			DeviceID:       input.DeviceID,
			ToolCall: models.ToolCall{
				Name:      llmResp.ToolCall.Name,
				Arguments: llmResp.ToolCall.Arguments,
			},
		})
		if err != nil {
			return nil, err
		}

		response = s.mapToolResultToResponse(toolResult)

		toolMsg := &models.ChatMessage{
			ID:          uuid.New(),
			UserID:      userUUID,
			CompanyID:   parseCompanyID(input.CompanyID),
			Role:        "tool",
			ToolName:    &toolResult.ToolName,
			ToolSuccess: &toolResult.Success,
			Content:     toolResult.Error,
			CreatedAt:   time.Now(),
		}
		_ = s.conversationRepo.SaveMessage(ctx, toolMsg)

	} else {
		response = &models.ChatResponse{
			Success: true,
			Type:    "text",
			Message: llmResp.Content,
		}

		assistantMsg := &models.ChatMessage{
			ID:        uuid.New(),
			UserID:    userUUID,
			CompanyID: parseCompanyID(input.CompanyID),
			Role:      "assistant",
			Content:   llmResp.Content,
			CreatedAt: time.Now(),
		}
		_ = s.conversationRepo.SaveMessage(ctx, assistantMsg)
	}

	s.logger.Info("Chat processing complete",
		zap.Duration("duration", time.Since(start)),
	)

	return response, nil
}

func parseCompanyID(cid interface{}) *uuid.UUID {
	if cid == nil {
		return nil
	}
	switch v := cid.(type) {
	case string:
		uid, err := uuid.Parse(v)
		if err != nil {
			return nil
		}
		return &uid
	case uuid.UUID:
		return &v
	default:
		return nil
	}
}

func (s *ChatService) mapToolResultToResponse(tr *models.ToolResult) *models.ChatResponse {
	if tr.Success {
		return &models.ChatResponse{
			Success: true,
			Type:    "text",
			Message: s.formatToolResult(tr),
		}
	}

	switch tr.HTTPStatus {
	case 401:
		s.logger.Warn("Session error from HR", zap.String("tool", tr.ToolName), zap.Int("http_status", tr.HTTPStatus))
		return &models.ChatResponse{
			Success: false,
			Type:    "session_error",
			Message: "Your session has expired or is invalid. Please log in again.",
		}
	case 403:
		s.logger.Warn("Permission denied from HR", zap.String("tool", tr.ToolName), zap.Int("http_status", tr.HTTPStatus))
		return &models.ChatResponse{
			Success: false,
			Type:    "permission_error",
			Message: "You don't have permission to perform this action.",
		}
	default:
		s.logger.Error("Tool execution failed", zap.String("tool", tr.ToolName), zap.Int("http_status", tr.HTTPStatus), zap.String("error", tr.Error))
		msg := tr.Error
		if msg == "" {
			msg = "An error occurred while processing your request."
		}
		return &models.ChatResponse{
			Success: false,
			Type:    "tool_error",
			Message: msg,
		}
	}
}

func (s *ChatService) formatToolResult(tr *models.ToolResult) string {
	switch tr.ToolName {
	case "payroll":
		return s.formatPayrollData(tr.Data)
	default:
		return "Operation completed successfully."
	}
}

func (s *ChatService) formatPayrollData(data interface{}) string {
	if data == nil {
		return "Payroll operation completed successfully (no data)."
	}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "Payroll operation completed successfully."
	}
	return fmt.Sprintf("Payroll result:\n%s", string(b))
}
