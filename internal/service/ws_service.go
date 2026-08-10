package service

import (
	"encoding/json"
	"sync"
	"time"

	"auth-service/internal/models"

	"github.com/gorilla/websocket"
)

// WebSocketService manages WebSocket connections for pairing status updates.
type WebSocketService struct {
	clients    map[string]*WebSocketClient
	clientsMux sync.RWMutex
	broadcast  chan *WebSocketMessage
	register   chan *WebSocketClient
	unregister chan *WebSocketClient
}

// WebSocketClient represents an active WebSocket connection.
type WebSocketClient struct {
	SessionID string
	Conn      *websocket.Conn
	Send      chan []byte
}

// WebSocketMessage is the message structure sent over WebSocket.
type WebSocketMessage struct {
	SessionID string      `json:"session_id"`
	Type      string      `json:"type"`
	Payload   interface{} `json:"payload"`
}

// NewWebSocketService creates a new WebSocketService.
func NewWebSocketService() *WebSocketService {
	return &WebSocketService{
		clients:    make(map[string]*WebSocketClient),
		broadcast:  make(chan *WebSocketMessage, 100),
		register:   make(chan *WebSocketClient, 100),
		unregister: make(chan *WebSocketClient, 100),
	}
}

// Run starts the main event loop for the WebSocket service.
func (s *WebSocketService) Run() {
	for {
		select {
		case client := <-s.register:
			s.registerClient(client)

		case client := <-s.unregister:
			s.unregisterClient(client)

		case message := <-s.broadcast:
			s.broadcastToSession(message.SessionID, message)
		}
	}
}

func (s *WebSocketService) registerClient(client *WebSocketClient) {
	s.clientsMux.Lock()
	defer s.clientsMux.Unlock()

	// Remove existing client for same session
	if existing, exists := s.clients[client.SessionID]; exists {
		close(existing.Send)
		delete(s.clients, client.SessionID)
	}

	s.clients[client.SessionID] = client

	// Start reader and writer goroutines
	go s.readPump(client)
	go s.writePump(client)
}

func (s *WebSocketService) unregisterClient(client *WebSocketClient) {
	s.clientsMux.Lock()
	defer s.clientsMux.Unlock()

	if existing, exists := s.clients[client.SessionID]; exists && existing == client {
		close(client.Send)
		delete(s.clients, client.SessionID)
	}
}

func (s *WebSocketService) broadcastToSession(sessionID string, message *WebSocketMessage) {
	s.clientsMux.RLock()
	defer s.clientsMux.RUnlock()

	if client, exists := s.clients[sessionID]; exists {
		select {
		case client.Send <- s.marshalMessage(message):
		default:
			// Client buffer full, close connection
			close(client.Send)
			delete(s.clients, sessionID)
		}
	}
}

// SendStatusUpdate sends a pairing status update to the client.
func (s *WebSocketService) SendStatusUpdate(sessionID string, status *models.PairingStatusResponse) {
	message := &WebSocketMessage{
		SessionID: sessionID,
		Type:      "status_update",
		Payload:   status,
	}
	s.broadcast <- message
}

// SendPaired sends the token pair after successful pairing.
func (s *WebSocketService) SendPaired(sessionID string, tokenPair *models.TokenPairResponse) {
	message := &WebSocketMessage{
		SessionID: sessionID,
		Type:      "paired",
		Payload:   tokenPair,
	}
	s.broadcast <- message
}

func (s *WebSocketService) readPump(client *WebSocketClient) {
	defer func() {
		s.unregister <- client
		client.Conn.Close()
	}()

	client.Conn.SetReadLimit(512) // 512 bytes max
	client.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	client.Conn.SetPongHandler(func(string) error {
		client.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := client.Conn.ReadMessage()
		if err != nil {
			break
		}

		// Handle ping/pong
		if string(message) == "ping" {
			client.Send <- []byte("pong")
		}
	}
}

func (s *WebSocketService) writePump(client *WebSocketClient) {
	ticker := time.NewTicker(30 * time.Second) // Ping interval
	defer func() {
		ticker.Stop()
		client.Conn.Close()
	}()

	for {
		select {
		case message, ok := <-client.Send:
			if !ok {
				// Channel closed
				client.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			client.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := client.Conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}

		case <-ticker.C:
			client.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := client.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (s *WebSocketService) marshalMessage(message *WebSocketMessage) []byte {
	data, _ := json.Marshal(message)
	return data
}

// Register adds a client to the service.
func (s *WebSocketService) Register(client *WebSocketClient) {
	s.register <- client
}

// Unregister removes a client.
func (s *WebSocketService) Unregister(client *WebSocketClient) {
	s.unregister <- client
}
