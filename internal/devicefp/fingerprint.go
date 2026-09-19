package devicefp

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func Hash(fp string) string {
	n := strings.TrimSpace(fp)
	if n == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(n))
	return hex.EncodeToString(sum[:])
}

func Matches(stored, incoming string) bool {
	return Hash(incoming) == stored
}
