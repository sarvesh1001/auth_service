package hashing

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"auth-service/internal/config"
	"auth-service/internal/hashing/pepperstore"
	"auth-service/internal/util"

	"go.uber.org/zap"
	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidHash         = errors.New("invalid hash format")
	ErrIncompatibleVersion = errors.New("incompatible argon2 version")
	ErrHasherNotReady      = errors.New("hasher not properly initialized")
	ErrNoPepperAvailable   = errors.New("no current pepper available")
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
	pepperStore   pepperstore.PepperStore
	mu            sync.RWMutex
	initialized   bool
}

type HashResult struct {
	Hash          string `json:"hash"`
	Salt          string `json:"salt"`
	PepperVersion int    `json:"pepper_version"`
	Algorithm     string `json:"algorithm"`
}

// ✅ UPDATED: NewHasher with retry logic and exponential backoff
func NewHasher(cfg *config.Config, pepperStore pepperstore.PepperStore) (*Hasher, error) {
	params := Argon2Params{
		Memory:      uint32(cfg.Hashing.Argon2MemoryCost),
		Iterations:  uint32(cfg.Hashing.Argon2TimeCost),
		Parallelism: uint8(cfg.Hashing.Argon2Parallelism),
		SaltLength:  32,
		KeyLength:   32,
	}

	h := &Hasher{
		params:      params,
		config:      cfg,
		pepperStore: pepperStore,
		oldPeppers:  make([]*Pepper, 0),
		initialized: false,
	}

	// ✅ NEW: Retry logic with exponential backoff for database connectivity
	maxRetries := 5
	retryDelay := 1 * time.Second
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		util.Info(fmt.Sprintf("Attempting to load peppers from database (attempt %d/%d)", attempt, maxRetries))

		// Try to load existing peppers from database
		if err := h.loadPeppersFromStore(); err != nil {
			lastErr = err
			util.Warn("Failed to load peppers from store, will retry",
				util.ErrorField(err),
				util.Int("attempt", attempt),
				util.Duration("retry_delay", retryDelay),
			)

			if attempt < maxRetries {
				time.Sleep(retryDelay)
				retryDelay *= 2 // Exponential backoff: 1s, 2s, 4s, 8s, 16s
				continue
			}
		} else {
			// Successfully loaded peppers
			lastErr = nil
			break
		}
	}

	// If still no peppers after retries, generate initial one
	if h.currentPepper == nil {
		if lastErr != nil {
			util.Error("Failed to load peppers after all retries, generating new pepper",
				util.ErrorField(lastErr))
		} else {
			util.Info("No peppers found in database, generating initial pepper")
		}

		if err := h.rotateAndSavePepper(); err != nil {
			return nil, fmt.Errorf("failed to generate initial pepper: %w", err)
		}
	}

	// ✅ CRITICAL: Final validation that we have a current pepper
	if h.currentPepper == nil {
		return nil, errors.New("hasher failed to initialize - no current pepper available after all attempts")
	}

	h.initialized = true // Mark as properly initialized

	util.Info("Hasher initialized successfully",
		zap.Int("current_pepper_version", h.currentPepper.Version),
		zap.Int("old_peppers_count", len(h.oldPeppers)),
		zap.Bool("pepper_store_available", pepperStore != nil),
	)

	return h, nil
}

// ✅ NEW: Check if hasher is properly initialized
func (h *Hasher) IsInitialized() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.initialized && h.currentPepper != nil
}

// ✅ FIXED: loadPeppersFromStore with proper error handling and version tracking
func (h *Hasher) loadPeppersFromStore() error {
	if h.pepperStore == nil {
		util.Warn("Pepper store is nil, cannot load peppers")
		return errors.New("pepper store not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	util.Info("Loading peppers from database store...")

	peppers, err := h.pepperStore.GetPeppers(ctx)
	if err != nil {
		util.Error("Failed to get peppers from store", util.ErrorField(err))
		return fmt.Errorf("failed to get peppers from store: %w", err)
	}

	if len(peppers) == 0 {
		util.Info("No peppers found in database store - this is normal for first startup")
		return nil
	}

	util.Info("Successfully retrieved peppers from database",
		zap.Int("pepper_count", len(peppers)),
		zap.Any("versions", h.getPepperVersions(peppers)),
	)

	// Find the highest version for current pepper
	var maxVersion int
	for version := range peppers {
		if version > maxVersion {
			maxVersion = version
		}
	}

	// Set current pepper
	currentPepperBytes := peppers[maxVersion]
	h.currentPepper = &Pepper{
		Value:     base64.RawURLEncoding.EncodeToString(currentPepperBytes),
		Version:   maxVersion,
		CreatedAt: time.Now(),
	}

	util.Info("Set current pepper",
		zap.Int("version", maxVersion),
		zap.Int("pepper_bytes_length", len(currentPepperBytes)),
	)

	// Set old peppers - ALL versions except current
	h.oldPeppers = make([]*Pepper, 0)
	for version, pepperBytes := range peppers {
		if version != maxVersion {
			h.oldPeppers = append(h.oldPeppers, &Pepper{
				Value:     base64.RawURLEncoding.EncodeToString(pepperBytes),
				Version:   version,
				CreatedAt: time.Now(),
			})
		}
	}

	util.Info("Loaded peppers from database store",
		zap.Int("current_version", h.currentPepper.Version),
		zap.Int("old_peppers_count", len(h.oldPeppers)),
		zap.Any("old_versions", h.getOldPepperVersions()),
	)

	return nil
}

// ✅ NEW: Helper to log pepper versions
func (h *Hasher) getPepperVersions(peppers map[int][]byte) []int {
	versions := make([]int, 0, len(peppers))
	for version := range peppers {
		versions = append(versions, version)
	}
	return versions
}

// ✅ NEW: Helper to log old pepper versions
func (h *Hasher) getOldPepperVersions() []int {
	versions := make([]int, 0, len(h.oldPeppers))
	for _, pepper := range h.oldPeppers {
		versions = append(versions, pepper.Version)
	}
	return versions
}

// ✅ UPDATED: rotatePepper with better error handling and state management
func (h *Hasher) rotatePepper() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Store the old current pepper for potential rollback
	oldCurrentPepper := h.currentPepper
	oldPeppers := make([]*Pepper, len(h.oldPeppers))
	copy(oldPeppers, h.oldPeppers)

	// Move current pepper to old peppers if exists
	if h.currentPepper != nil {
		h.oldPeppers = append(h.oldPeppers, h.currentPepper)
	}

	// Generate new pepper
	pepperBytes := make([]byte, 32)
	if _, err := rand.Read(pepperBytes); err != nil {
		return fmt.Errorf("failed to generate pepper: %w", err)
	}

	newVersion := 1
	if oldCurrentPepper != nil {
		newVersion = oldCurrentPepper.Version + 1
	}

	h.currentPepper = &Pepper{
		Value:     base64.RawURLEncoding.EncodeToString(pepperBytes),
		CreatedAt: time.Now(),
		Version:   newVersion,
	}

	// Save to database
	if h.pepperStore != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := h.pepperStore.SavePepper(ctx, newVersion, pepperBytes); err != nil {
			// ✅ IMPROVED: Rollback on failure
			h.currentPepper = oldCurrentPepper
			h.oldPeppers = oldPeppers
			return fmt.Errorf("failed to save pepper to database: %w", err)
		}
	} else {
		util.Warn("Pepper store is nil, pepper rotation not persisted to database")
	}

	util.Info("Pepper rotated successfully",
		zap.Int("version", h.currentPepper.Version),
		zap.Time("created_at", h.currentPepper.CreatedAt),
	)

	return nil
}

// ✅ NEW: Helper method that rotates and saves pepper
func (h *Hasher) rotateAndSavePepper() error {
	return h.rotatePepper()
}

// ✅ UPDATED: StartPepperRotation with safety checks
func (h *Hasher) StartPepperRotation() {
	if !h.IsInitialized() {
		util.Error("Cannot start pepper rotation - hasher not properly initialized")
		return
	}

	rotationInterval := time.Duration(h.config.Hashing.PepperRotationDays) * 24 * time.Hour
	ticker := time.NewTicker(rotationInterval)

	go func() {
		for range ticker.C {
			if !h.IsInitialized() {
				util.Error("Skipping pepper rotation - hasher not initialized")
				continue
			}

			if err := h.rotatePepper(); err != nil {
				util.Error("Failed to rotate pepper", zap.Error(err))
				continue
			}

			// Clean up old peppers in database (keep only last 3 versions)
			if h.pepperStore != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				if err := h.pepperStore.CleanupOldPeppers(ctx, 3); err != nil {
					util.Error("Failed to cleanup old peppers in database", zap.Error(err))
				}
				cancel()
			}

			// Also clean up in-memory old peppers
			h.mu.Lock()
			if len(h.oldPeppers) > 2 {
				h.oldPeppers = h.oldPeppers[len(h.oldPeppers)-2:]
			}
			h.mu.Unlock()
		}
	}()

	util.Info("Started background pepper rotation",
		zap.Duration("interval", rotationInterval),
		zap.Int("current_pepper_version", h.GetCurrentPepperVersion()),
	)
}

// ✅ UPDATED: HashOTP with initialization check
func (h *Hasher) HashOTP(otp string) (*HashResult, error) {
	if !h.IsInitialized() {
		return nil, ErrHasherNotReady
	}
	return h.hashWithPepper(otp, "otp")
}

// ✅ UPDATED: HashMPIN with initialization check
func (h *Hasher) HashMPIN(mpin string) (*HashResult, error) {
	if !h.IsInitialized() {
		return nil, ErrHasherNotReady
	}
	return h.hashWithPepper(mpin, "mpin")
}

// ✅ UPDATED: hashWithPepper with comprehensive safety checks
func (h *Hasher) hashWithPepper(data, context string) (*HashResult, error) {
	// Double-check initialization
	if !h.IsInitialized() {
		return nil, ErrHasherNotReady
	}

	h.mu.RLock()
	pepper := h.currentPepper
	h.mu.RUnlock()

	if pepper == nil {
		return nil, ErrNoPepperAvailable
	}

	// Validate input
	if data == "" {
		return nil, errors.New("data cannot be empty")
	}

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

// ✅ UPDATED: VerifyOTP with initialization check
func (h *Hasher) VerifyOTP(otp string, hashResult *HashResult) (bool, error) {
	if !h.IsInitialized() {
		return false, ErrHasherNotReady
	}
	return h.verifyWithPepper(otp, hashResult, "otp")
}

// ✅ UPDATED: VerifyMPIN with initialization check
func (h *Hasher) VerifyMPIN(mpin string, hashResult *HashResult) (bool, error) {
	if !h.IsInitialized() {
		return false, ErrHasherNotReady
	}
	return h.verifyWithPepper(mpin, hashResult, "mpin")
}

// ✅ UPDATED: verifyWithPepper with better error handling
func (h *Hasher) verifyWithPepper(data string, hashResult *HashResult, context string) (bool, error) {
	if hashResult == nil {
		return false, errors.New("hashResult cannot be nil")
	}

	// Get pepper by version
	pepper, err := h.getPepper(hashResult.PepperVersion)
	if err != nil {
		return false, fmt.Errorf("pepper version %d not found: %w", hashResult.PepperVersion, err)
	}

	// Decode salt
	salt, err := base64.RawURLEncoding.DecodeString(hashResult.Salt)
	if err != nil {
		return false, fmt.Errorf("%w: invalid salt encoding", ErrInvalidHash)
	}

	// Decode expected hash
	expectedHash, err := base64.RawURLEncoding.DecodeString(hashResult.Hash)
	if err != nil {
		return false, fmt.Errorf("%w: invalid hash encoding", ErrInvalidHash)
	}

	// Validate lengths
	if len(salt) != int(h.params.SaltLength) {
		return false, fmt.Errorf("%w: salt length mismatch", ErrInvalidHash)
	}

	// Add context
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

// ✅ UPDATED: getPepper with better error reporting
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

	return "", fmt.Errorf("pepper version %d not found (current: %d, available old versions: %v)",
		version,
		h.getCurrentVersionSafe(),
		h.getAvailableVersions())
}

// ✅ NEW: Helper to safely get current version
func (h *Hasher) getCurrentVersionSafe() int {
	if h.currentPepper == nil {
		return 0
	}
	return h.currentPepper.Version
}

// ✅ NEW: Helper to get available pepper versions for error messages
func (h *Hasher) getAvailableVersions() []int {
	versions := make([]int, 0, len(h.oldPeppers)+1)

	if h.currentPepper != nil {
		versions = append(versions, h.currentPepper.Version)
	}

	for _, pepper := range h.oldPeppers {
		versions = append(versions, pepper.Version)
	}

	return versions
}

// ✅ UPDATED: Benchmark with initialization check
func (h *Hasher) Benchmark(iterations int) time.Duration {
	if !h.IsInitialized() {
		util.Error("Cannot run benchmark - hasher not initialized")
		return 0
	}

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

// ✅ UPDATED: GetCurrentPepperVersion with safety check
func (h *Hasher) GetCurrentPepperVersion() int {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.currentPepper == nil {
		return 0
	}
	return h.currentPepper.Version
}

// ✅ UPDATED: HealthCheck with comprehensive checks
func (h *Hasher) HealthCheck(ctx context.Context) error {
	// Check initialization
	if !h.IsInitialized() {
		return errors.New("hasher not properly initialized")
	}

	// Check pepper store connectivity if available
	if h.pepperStore != nil {
		_, _, err := h.pepperStore.GetCurrentPepper(ctx)
		if err != nil && err.Error() != "no active pepper found" {
			return fmt.Errorf("pepper store health check failed: %w", err)
		}
	}

	// Check current pepper
	h.mu.RLock()
	hasCurrentPepper := h.currentPepper != nil
	h.mu.RUnlock()

	if !hasCurrentPepper {
		return errors.New("no current pepper available")
	}

	return nil
}

// ✅ NEW: GetStatus returns detailed hasher status for debugging
func (h *Hasher) GetStatus() map[string]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()

	status := map[string]interface{}{
		"initialized":        h.initialized,
		"pepper_store_ready": h.pepperStore != nil,
		"has_current_pepper": h.currentPepper != nil,
	}

	if h.currentPepper != nil {
		status["current_pepper_version"] = h.currentPepper.Version
		status["current_pepper_created"] = h.currentPepper.CreatedAt
	}

	status["old_peppers_count"] = len(h.oldPeppers)

	oldVersions := make([]int, len(h.oldPeppers))
	for i, pepper := range h.oldPeppers {
		oldVersions[i] = pepper.Version
	}
	status["old_pepper_versions"] = oldVersions

	return status
}
