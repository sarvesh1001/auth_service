package util

import (
    "math/rand"
    "time"

    "github.com/google/uuid"
)

// HashUUID creates a simple hash from UUID for partition determination
func HashUUID(id uuid.UUID) int {
    // Use the first 8 bytes of the UUID to create a hash
    data := id[:8]
    var hash uint64
    for _, b := range data {
        hash = hash*31 + uint64(b)
    }
    return int(hash & 0x7FFFFFFF) // Ensure positive
}

// GenerateRandomString generates a random alphanumeric string
func GenerateRandomString(length int) string {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))


	b := make([]byte, length)
    for i := range b {
        b[i] = charset[seededRand.Intn(len(charset))]
    }
    return string(b)
}

// MaskString masks sensitive strings for logging (shows first n and last n chars)
func MaskString(s string, visibleChars int) string {
	if len(s) == 0 {
		return ""
	}
	
	if len(s) <= visibleChars*2 {
		return "***"
	}
	
	first := s[:visibleChars]
	last := s[len(s)-visibleChars:]
	return first + "***" + last
}