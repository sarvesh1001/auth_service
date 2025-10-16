package encryption

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"auth-service/internal/config"
	"auth-service/internal/util"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

var (
	ErrEncryptionFailed = errors.New("encryption failed")
	ErrDecryptionFailed = errors.New("decryption failed")
)

type EncryptedData struct {
	EncryptedValue string    `json:"encrypted_value"`
	EncryptedDEK   string    `json:"encrypted_dek"`
	KeyID          string    `json:"key_id"`
	Version        string    `json:"version"`
	CreatedAt      time.Time `json:"created_at"`
}

type EncryptionManager struct {
	kmsClient *kms.Client
	config    *config.Config
	keyCache  sync.Map // cache decrypted DEKs
	mu        sync.RWMutex
}

type DataKey struct {
	Plaintext  []byte
	Ciphertext []byte
	KeyID      string
}

func NewEncryptionManager(cfg *config.Config, kmsClient *kms.Client) *EncryptionManager {
	return &EncryptionManager{
		kmsClient: kmsClient,
		config:    cfg,
	}
}

// GenerateDataKey generates a new data encryption key using KMS
func (em *EncryptionManager) GenerateDataKey(ctx context.Context, keyPurpose string) (*DataKey, error) {
	if !em.config.KMS.Enabled {
		return em.generateLocalKey(keyPurpose), nil
	}

	input := &kms.GenerateDataKeyInput{
		KeyId:   aws.String(em.config.KMS.KeyID),
		KeySpec: types.DataKeySpecAes256,
	}

	result, err := em.kmsClient.GenerateDataKey(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to generate data key: %w", err)
	}

	return &DataKey{
		Plaintext:  result.Plaintext,
		Ciphertext: result.CiphertextBlob,
		KeyID:      em.config.KMS.KeyID,
	}, nil
}

func (em *EncryptionManager) generateLocalKey(keyPurpose string) *DataKey {
	key := make([]byte, 32) // AES-256
	if _, err := rand.Read(key); err != nil {
		util.Fatal("Failed to generate local encryption key", zap.Error(err))
	}

	// In development, we just base64 encode the "encrypted" key
	ciphertext := []byte(base64.StdEncoding.EncodeToString(key))

	// Generate a valid UUID for the KeyID instead of "local-<purpose>"
	devKeyID := uuid.New().String()

	return &DataKey{
		Plaintext:  key,
		Ciphertext: ciphertext,
		KeyID:      devKeyID,
	}
}

// EncryptField encrypts sensitive field using envelope encryption
func (em *EncryptionManager) EncryptField(ctx context.Context, plaintext, keyPurpose string) (*EncryptedData, error) {
	dataKey, err := em.GenerateDataKey(ctx, keyPurpose)
	if err != nil {
		return nil, err
	}

	// Log the generated DataKey KeyID for debugging
	util.Info(fmt.Sprintf("EncryptField.GenerateDataKey: key_purpose=%s, key_id=%s", keyPurpose, dataKey.KeyID))

	block, err := aes.NewCipher(dataKey.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	cacheKey := base64.StdEncoding.EncodeToString(dataKey.Ciphertext)
	em.keyCache.Store(cacheKey, dataKey.Plaintext)

	return &EncryptedData{
		EncryptedValue: base64.StdEncoding.EncodeToString(ciphertext),
		EncryptedDEK:   base64.StdEncoding.EncodeToString(dataKey.Ciphertext),
		KeyID:          dataKey.KeyID,
		Version:        "v1",
		CreatedAt:      time.Now().UTC(),
	}, nil
}

// DecryptField decrypts encrypted field
func (em *EncryptionManager) DecryptField(ctx context.Context, encryptedData *EncryptedData) (string, error) {
	// Check cache for decrypted DEK
	cacheKey := encryptedData.EncryptedDEK
	if cached, ok := em.keyCache.Load(cacheKey); ok {
		return em.decryptWithKey(encryptedData.EncryptedValue, cached.([]byte))
	}

	// Decrypt DEK first
	var plaintextDEK []byte
	if em.config.KMS.Enabled {
		ciphertextBlob, err := base64.StdEncoding.DecodeString(encryptedData.EncryptedDEK)
		if err != nil {
			return "", fmt.Errorf("%w: invalid DEK format", ErrDecryptionFailed)
		}

		input := &kms.DecryptInput{
			CiphertextBlob: ciphertextBlob,
		}

		result, err := em.kmsClient.Decrypt(ctx, input)
		if err != nil {
			return "", fmt.Errorf("%w: failed to decrypt DEK: %v", ErrDecryptionFailed, err)
		}

		plaintextDEK = result.Plaintext
	} else {
		// In development, just decode the "encrypted" key
		var err error
		plaintextDEK, err = base64.StdEncoding.DecodeString(encryptedData.EncryptedDEK)
		if err != nil {
			return "", fmt.Errorf("%w: invalid local DEK", ErrDecryptionFailed)
		}
	}

	// Cache the decrypted DEK
	em.keyCache.Store(cacheKey, plaintextDEK)

	return em.decryptWithKey(encryptedData.EncryptedValue, plaintextDEK)
}

func (em *EncryptionManager) decryptWithKey(encryptedValue string, key []byte) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedValue)
	if err != nil {
		return "", fmt.Errorf("%w: invalid ciphertext format", ErrDecryptionFailed)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("%w: ciphertext too short", ErrDecryptionFailed)
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return string(plaintext), nil
}

// ClearCache clears the DEK cache (useful for memory management)
func (em *EncryptionManager) ClearCache() {
	em.keyCache.Range(func(key, value interface{}) bool {
		em.keyCache.Delete(key)
		return true
	})
}

// GetCacheSize returns the number of cached DEKs
func (em *EncryptionManager) GetCacheSize() int {
	count := 0
	em.keyCache.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}
