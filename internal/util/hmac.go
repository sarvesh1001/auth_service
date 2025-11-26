// internal/util/hmac.go
package util

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type HMACUtil struct {
	secret []byte
}

func NewHMACUtil(secret string) *HMACUtil {
	return &HMACUtil{
		secret: []byte(secret),
	}
}

// Sign creates HMAC signature for payload
func (h *HMACUtil) Sign(payload string) string {
	mac := hmac.New(sha256.New, h.secret)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify validates HMAC signature
func (h *HMACUtil) Verify(payload, signature string) bool {
	expected := h.Sign(payload)
	return hmac.Equal([]byte(expected), []byte(signature))
}

// SignQRPayload signs session data for QR code
func (h *HMACUtil) SignQRPayload(sessionID, nonce string) (string, string) {
	payload := fmt.Sprintf("%s:%s", sessionID, nonce)
	signature := h.Sign(payload)
	return payload, signature
}

// VerifyQRPayload verifies QR code signature
func (h *HMACUtil) VerifyQRPayload(sessionID, nonce, signature string) bool {
	payload := fmt.Sprintf("%s:%s", sessionID, nonce)
	return h.Verify(payload, signature)
}
