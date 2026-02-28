package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"chatbot-service/internal/models"
	"chatbot-service/internal/repository"

	"github.com/google/uuid"
)

type conversationRepository struct {
	db *sql.DB
}

func NewConversationRepository(db *sql.DB) repository.ConversationRepository {
	return &conversationRepository{db: db}
}

func (r *conversationRepository) SaveMessage(ctx context.Context, msg *models.ChatMessage) error {
	// Convert *uuid.UUID to either uuid.UUID or nil
	var companyID interface{}
	if msg.CompanyID != nil {
		companyID = *msg.CompanyID
	} else {
		companyID = nil
	}

	query := `
        INSERT INTO chat_messages (id, user_id, company_id, role, content, tool_name, tool_success, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `
	_, err := r.db.ExecContext(ctx, query,
		msg.ID,
		msg.UserID,
		companyID, // use the converted value
		msg.Role,
		msg.Content,
		msg.ToolName,
		msg.ToolSuccess,
		msg.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to save chat message: %w", err)
	}
	return nil
}

func (r *conversationRepository) GetRecentMessages(ctx context.Context, userID string, limit int) ([]models.ChatMessage, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user_id format: %w", err)
	}

	query := `
        SELECT id, user_id, company_id, role, content, tool_name, tool_success, created_at
        FROM chat_messages
        WHERE user_id = $1
        ORDER BY created_at DESC
        LIMIT $2
    `
	rows, err := r.db.QueryContext(ctx, query, uid, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query recent messages: %w", err)
	}
	defer rows.Close()

	var messages []models.ChatMessage
	for rows.Next() {
		var msg models.ChatMessage
		var companyID sql.NullString
		var toolName sql.NullString
		var toolSuccess sql.NullBool

		err := rows.Scan(
			&msg.ID,
			&msg.UserID,
			&companyID,
			&msg.Role,
			&msg.Content,
			&toolName,
			&toolSuccess,
			&msg.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan message: %w", err)
		}

		if companyID.Valid {
			cid, _ := uuid.Parse(companyID.String)
			msg.CompanyID = &cid
		}
		if toolName.Valid {
			msg.ToolName = &toolName.String
		}
		if toolSuccess.Valid {
			msg.ToolSuccess = &toolSuccess.Bool
		}

		messages = append(messages, msg)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return messages, nil
}
