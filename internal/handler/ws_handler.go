package handler

import (
	"context"
	"net"
	"net/http"
	"strings"

	"auth-service/internal/contextkeys"
	customErrors "auth-service/internal/errors"
	"auth-service/internal/service"
	"auth-service/internal/util"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

// WebSocketHandler handles WebSocket connections for real-time communication.
type WebSocketHandler struct {
	wsService *service.WebSocketService
}

func NewWebSocketHandler(wsService *service.WebSocketService) *WebSocketHandler {
	return &WebSocketHandler{wsService: wsService}
}

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		allowed := origin == "https://yourapp.com" || origin == "http://localhost:3000"
		if !allowed {
			zap.L().Warn("WebSocket origin not allowed", zap.String("origin", origin))
		}
		return allowed
	},
}

// HandleConnection upgrades the HTTP connection to WebSocket and registers the client.
func (h *WebSocketHandler) HandleConnection(w http.ResponseWriter, r *http.Request) {
	logger := zap.L().With(
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("user_agent", r.UserAgent()),
	)
	logger.Info("WebSocket connection attempt")

	// Inject client IP into context
	clientIP := getClientIP(r)
	ctx := context.WithValue(r.Context(), contextkeys.ClientIP, clientIP)
	r = r.WithContext(ctx)

	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		logger.Warn("WebSocket connection rejected: missing session_id")
		util.JSONError(w, http.StatusBadRequest, customErrors.ErrInvalidInput.Error()+" session_id is required")
		return
	}
	logger = logger.With(zap.String("session_id", sessionID))

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Error("WebSocket upgrade failed", zap.Error(err))
		// Upgrade already sent a response, no further action needed.
		return
	}
	logger.Info("WebSocket connection upgraded successfully")

	client := &service.WebSocketClient{
		SessionID: sessionID,
		Conn:      conn,
		Send:      make(chan []byte, 256),
	}

	h.wsService.Register(client)
	logger.Info("WebSocket client registered")
}

// getClientIP extracts the client IP from the request.
func getClientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if ips := strings.Split(forwarded, ","); len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if parsedIP := net.ParseIP(ip); parsedIP != nil {
				return ip
			}
		}
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		if parsedIP := net.ParseIP(realIP); parsedIP != nil {
			return realIP
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
