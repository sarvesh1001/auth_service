package handler

import (
	"chatbot-service/internal/models"
	"chatbot-service/internal/service"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
)

type ChatHandler struct {
	chatService *service.ChatService
	logger      *zap.Logger
}

func NewChatHandler(chatService *service.ChatService, logger *zap.Logger) *ChatHandler {
	return &ChatHandler{
		chatService: chatService,
		logger:      logger,
	}
}

func (h *ChatHandler) HandleChat(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	start := time.Now()

	rawUserID := ctx.Value("user_id")
	if rawUserID == nil {
		h.respondWithError(w, http.StatusUnauthorized,
			fmt.Errorf("UNAUTHORIZED"),
			"Authentication required")
		return
	}
	userID, ok := rawUserID.(string)
	if !ok || userID == "" {
		h.respondWithError(w, http.StatusUnauthorized,
			fmt.Errorf("INVALID_USER_CONTEXT"),
			"Invalid user context")
		return
	}

	sessionType, _ := ctx.Value("session_type").(string)
	companyID := ctx.Value("company_id")
	permissionMask := ctx.Value("permission_mask")
	deviceID, _ := ctx.Value("device_id").(string)

	var req models.ChatRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	if req.Message == "" {
		h.respondWithError(w, http.StatusBadRequest,
			fmt.Errorf("EMPTY_MESSAGE"),
			"Message is required")
		return
	}

	resp, err := h.chatService.Handle(ctx, service.ChatInput{
		UserID:         userID,
		CompanyID:      companyID,
		SessionType:    sessionType,
		PermissionMask: permissionMask,
		Message:        req.Message,
		AuthHeader:     r.Header.Get("Authorization"),
		DeviceID:       deviceID,
		Arguments:      req.Arguments, // NEW: pass arguments
	})
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, err, "Failed to process chat request")
		return
	}

	h.respondWithJSON(w, http.StatusOK, resp)

	h.logger.Info("Chat request processed",
		zap.String("user_id", userID),
		zap.String("session_type", sessionType),
		zap.Duration("duration", time.Since(start)),
	)
}

func (h *ChatHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *ChatHandler) respondWithError(w http.ResponseWriter, statusCode int, err error, message string) {
	h.logger.Warn("Chat HTTP error",
		zap.Error(err),
		zap.Int("status_code", statusCode),
		zap.String("message", message),
	)
	h.respondWithJSON(w, statusCode, map[string]interface{}{
		"success": false,
		"error":   err.Error(),
		"message": message,
		"code":    statusCode,
	})
}
