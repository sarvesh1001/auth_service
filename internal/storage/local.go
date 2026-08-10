package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LocalStorage implements Storage on the local filesystem.
type LocalStorage struct {
	basePath string // e.g., "/data" (mounted volume inside container)
	baseURL  string // e.g., "http://localhost:8080/api/v1" for generating upload URLs
}

// NewLocalStorage creates a new LocalStorage.
// basePath: directory where files are stored.
// baseURL: the public base URL of the API (used to construct the upload endpoint).
func NewLocalStorage(basePath, baseURL string) *LocalStorage {
	return &LocalStorage{
		basePath: basePath,
		baseURL:  baseURL,
	}
}

// GenerateUploadURL returns the endpoint where the client should POST the file.
// The upload path is determined by the key prefix:
// - "kyc/"  -> /admin/kyc/documents/upload (KYC routes are under /admin)
// - "avatars/" -> /avatars/upload
func (s *LocalStorage) GenerateUploadURL(ctx context.Context, key string, expiry time.Duration) (string, error) {
	var uploadPath string
	switch {
	case strings.HasPrefix(key, "kyc/"):
		uploadPath = "/admin/kyc/documents/upload"
	case strings.HasPrefix(key, "avatars/"):
		uploadPath = "/avatars/upload"
	default:
		return "", fmt.Errorf("unknown key prefix for upload: %s", key)
	}
	return s.baseURL + uploadPath, nil
}

// UploadFile saves the file content to disk.
// The key is the relative file path (e.g., "kyc/user-uuid/identity/file-uuid.jpg").
// The full path is basePath + key.
func (s *LocalStorage) UploadFile(ctx context.Context, key string, reader io.Reader, metadata map[string]string) error {
	fullPath := filepath.Join(s.basePath, key)

	// Ensure directory exists
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	// Create the file
	out, err := os.Create(fullPath)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer out.Close()

	// Copy data
	_, err = io.Copy(out, reader)
	if err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}

// FileExists checks if the file exists on disk.
func (s *LocalStorage) FileExists(ctx context.Context, key string) (bool, error) {
	fullPath := filepath.Join(s.basePath, key)
	_, err := os.Stat(fullPath)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("stat file: %w", err)
}

// DeleteFile removes the file from disk.
func (s *LocalStorage) DeleteFile(ctx context.Context, key string) error {
	fullPath := filepath.Join(s.basePath, key)
	err := os.Remove(fullPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove file: %w", err)
	}
	return nil
}

// GetFile returns a ReadCloser for the file at the given key.
// The caller is responsible for closing it.
func (s *LocalStorage) GetFile(ctx context.Context, key string) (io.ReadCloser, error) {
	fullPath := filepath.Join(s.basePath, key)
	file, err := os.Open(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file not found: %s", key)
		}
		return nil, fmt.Errorf("open file: %w", err)
	}
	return file, nil
}
