// internal/handler/ws_handler.go
package handler

import (
	"net/http"

	"auth-service/internal/service"
	"auth-service/internal/util"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

type WebSocketHandler struct {
	wsService *service.WebSocketService
	logger    *zap.Logger
}

func NewWebSocketHandler(wsService *service.WebSocketService, logger *zap.Logger) *WebSocketHandler {
	return &WebSocketHandler{
		wsService: wsService,
		logger:    logger,
	}
}

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// Implement proper origin validation in production
		origin := r.Header.Get("Origin")
		return origin == "https://yourapp.com" || origin == "http://localhost:3000"
	},
}

func (h *WebSocketHandler) HandleConnection(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		util.JSONError(w, http.StatusBadRequest, "session_id is required")
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Error("WebSocket upgrade failed",
			util.ErrorField(err),
			util.String("session_id", sessionID),
		)
		return
	}

	client := &service.WebSocketClient{
		SessionID: sessionID,
		Conn:      conn,
		Send:      make(chan []byte, 256),
	}

	h.wsService.Register(client)

	h.logger.Info("WebSocket client connected",
		util.String("session_id", sessionID),
	)
}
