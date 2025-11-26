// internal/util/qr.go
package util

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type QRPayload struct {
	SessionID string `json:"sid"`
	Nonce     string `json:"nonce"`
	Signature string `json:"sig"`
	Timestamp int64  `json:"ts"`
}

type QRUtil struct {
	hmac *HMACUtil
}

func NewQRUtil(hmacSecret string) *QRUtil {
	return &QRUtil{
		hmac: NewHMACUtil(hmacSecret),
	}
}

// GenerateQRCode creates QR code data for web login
func (q *QRUtil) GenerateQRCode(sessionID string) (string, string, error) {
	nonce := uuid.New().String()
	timestamp := time.Now().Unix()

	// Create and sign payload
	payload := QRPayload{
		SessionID: sessionID,
		Nonce:     nonce,
		Timestamp: timestamp,
	}

	// Sign the payload
	payloadData := fmt.Sprintf("%s:%s:%d", sessionID, nonce, timestamp)
	signature := q.hmac.Sign(payloadData)
	payload.Signature = signature

	// Encode to JSON and Base64 for QR code
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal QR payload: %w", err)
	}

	qrData := base64.URLEncoding.EncodeToString(jsonData)
	return qrData, nonce, nil
}

// ParseQRCode decodes and validates QR code data
func (q *QRUtil) ParseQRCode(qrData string) (*QRPayload, error) {
	// Decode base64
	jsonData, err := base64.URLEncoding.DecodeString(qrData)
	if err != nil {
		return nil, fmt.Errorf("invalid QR code format: %w", err)
	}

	var payload QRPayload
	if err := json.Unmarshal(jsonData, &payload); err != nil {
		return nil, fmt.Errorf("invalid QR code data: %w", err)
	}

	// Validate signature
	expectedData := fmt.Sprintf("%s:%s:%d", payload.SessionID, payload.Nonce, payload.Timestamp)
	if !q.hmac.Verify(expectedData, payload.Signature) {
		return nil, fmt.Errorf("invalid QR code signature")
	}

	// Check timestamp (QR codes expire in 10 minutes)
	if time.Now().Unix()-payload.Timestamp > 600 {
		return nil, fmt.Errorf("QR code expired")
	}

	return &payload, nil
}
