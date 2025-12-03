package util

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// HashString creates a SHA256 hash of the input string
func HashString(input string) string {
	if input == "" {
		return ""
	}

	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// HashStringWithSalt creates a SHA256 hash with salt
func HashStringWithSalt(input, salt string) string {
	if input == "" {
		return ""
	}

	data := fmt.Sprintf("%s:%s", input, salt)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// ShortHash creates a shorter 8-character hash for non-cryptographic purposes
func ShortHash(input string) string {
	if input == "" {
		return ""
	}

	fullHash := HashString(input)
	if len(fullHash) >= 8 {
		return fullHash[:8]
	}
	return fullHash
}
