package repository

import (
	"chatbot-service/internal/models"
	"context"
)

type ConversationRepository interface {
	SaveMessage(ctx context.Context, msg *models.ChatMessage) error
	GetRecentMessages(ctx context.Context, userID string, limit int) ([]models.ChatMessage, error)
}
