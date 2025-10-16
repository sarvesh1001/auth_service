package hashing

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"auth-service/internal/config"
	"auth-service/internal/util"

	"go.uber.org/zap"
	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidHash         = errors.New("invalid hash format")
	ErrIncompatibleVersion = errors.New("incompatible argon2 version")
)

type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

type Pepper struct {
	Value     string
	CreatedAt time.Time
	Version   int
}

type Hasher struct {
	params        Argon2Params
	currentPepper *Pepper
	oldPeppers    []*Pepper
	config        *config.Config
	mu            sync.RWMutex
}

type HashResult struct {
	Hash          string `json:"hash"`
	Salt          string `json:"salt"`
	PepperVersion int    `json:"pepper_version"`
	Algorithm     string `json:"algorithm"`
}

func NewHasher(cfg *config.Config) *Hasher {
	params := Argon2Params{
		Memory:      uint32(cfg.Hashing.Argon2MemoryCost),
		Iterations:  uint32(cfg.Hashing.Argon2TimeCost),
		Parallelism: uint8(cfg.Hashing.Argon2Parallelism),
		SaltLength:  32,
		KeyLength:   32,
	}

	h := &Hasher{
		params: params,
		config: cfg,
	}

	// Generate initial pepper
	h.rotatePepper()

	return h
}

func (h *Hasher) rotatePepper() {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Move current pepper to old peppers if exists
	if h.currentPepper != nil {
		h.oldPeppers = append(h.oldPeppers, h.currentPepper)
	}

	// Generate new pepper
	pepperBytes := make([]byte, 32)
	if _, err := rand.Read(pepperBytes); err != nil {
		util.Fatal("Failed to generate pepper", zap.Error(err))
	}

	h.currentPepper = &Pepper{
		Value:     base64.RawURLEncoding.EncodeToString(pepperBytes),
		CreatedAt: time.Now(),
		Version:   len(h.oldPeppers) + 1,
	}

	util.Info("Pepper rotated",
		zap.Int("version", h.currentPepper.Version),
		zap.Time("created_at", h.currentPepper.CreatedAt),
	)
}

// StartPepperRotation starts background pepper rotation
func (h *Hasher) StartPepperRotation() {
	ticker := time.NewTicker(time.Duration(h.config.Hashing.PepperRotationDays) * 24 * time.Hour)

	go func() {
		for range ticker.C {
			h.rotatePepper()

			// Clean up old peppers (keep only last 2 versions)
			h.mu.Lock()
			if len(h.oldPeppers) > 2 {
				h.oldPeppers = h.oldPeppers[len(h.oldPeppers)-2:]
			}
			h.mu.Unlock()
		}
	}()
}

func (h *Hasher) HashOTP(otp string) (*HashResult, error) {
	return h.hashWithPepper(otp, "otp")
}

func (h *Hasher) HashMPIN(mpin string) (*HashResult, error) {
	return h.hashWithPepper(mpin, "mpin")
}

func (h *Hasher) hashWithPepper(data, context string) (*HashResult, error) {
	h.mu.RLock()
	pepper := h.currentPepper
	h.mu.RUnlock()

	// Generate salt
	salt := make([]byte, h.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Add context to prevent hash reuse between different purposes
	contextualData := data + pepper.Value + context

	// Generate hash using Argon2id
	hash := argon2.IDKey(
		[]byte(contextualData),
		salt,
		h.params.Iterations,
		h.params.Memory,
		h.params.Parallelism,
		h.params.KeyLength,
	)

	return &HashResult{
		Hash:          base64.RawURLEncoding.EncodeToString(hash),
		Salt:          base64.RawURLEncoding.EncodeToString(salt),
		PepperVersion: pepper.Version,
		Algorithm:     "argon2id-v1",
	}, nil
}

func (h *Hasher) VerifyOTP(otp string, hashResult *HashResult) (bool, error) {
	return h.verifyWithPepper(otp, hashResult, "otp")
}

func (h *Hasher) VerifyMPIN(mpin string, hashResult *HashResult) (bool, error) {
	return h.verifyWithPepper(mpin, hashResult, "mpin")
}
func (h *Hasher) verifyWithPepper(data string, hashResult *HashResult, context string) (bool, error) {
	// Get pepper by version
	pepper, err := h.getPepper(hashResult.PepperVersion)
	if err != nil {
		return false, fmt.Errorf("pepper version not found: %w", err)
	}

	// Decode salt
	salt, err := base64.RawURLEncoding.DecodeString(hashResult.Salt)
	if err != nil {
		return false, ErrInvalidHash
	}

	// Decode expected hash
	expectedHash, err := base64.RawURLEncoding.DecodeString(hashResult.Hash)
	if err != nil {
		return false, ErrInvalidHash
	}

	// Add context - FIXED: use pepper directly since it's already a string
	contextualData := data + pepper + context

	// Compute hash for comparison
	computedHash := argon2.IDKey(
		[]byte(contextualData),
		salt,
		h.params.Iterations,
		h.params.Memory,
		h.params.Parallelism,
		uint32(len(expectedHash)),
	)

	// Use constant time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(computedHash, expectedHash) == 1, nil
}
func (h *Hasher) getPepper(version int) (string, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Check current pepper first
	if h.currentPepper != nil && h.currentPepper.Version == version {
		return h.currentPepper.Value, nil
	}

	// Check old peppers
	for _, pepper := range h.oldPeppers {
		if pepper.Version == version {
			return pepper.Value, nil
		}
	}

	return "", errors.New("pepper version not found")
}

// Benchmark hashing performance
func (h *Hasher) Benchmark(iterations int) time.Duration {
	start := time.Now()

	for i := 0; i < iterations; i++ {
		testData := fmt.Sprintf("benchmark%d", i)
		_, err := h.HashOTP(testData)
		if err != nil {
			util.Error("Benchmark failed", zap.Error(err))
			return 0
		}
	}

	return time.Since(start)
}
