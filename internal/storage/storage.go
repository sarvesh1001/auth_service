package storage

import (
	"context"
	"io"
	"time"
)

// Storage defines the interface for file operations.
// This allows us to swap local disk with S3 or other cloud storage later.
type Storage interface {
	// GenerateUploadURL returns a pre-signed URL for direct client upload.
	// For local storage, it returns the endpoint of our own upload handler.
	GenerateUploadURL(ctx context.Context, key string, expiry time.Duration) (uploadURL string, err error)

	// UploadFile saves the file content to the given key.
	// metadata is optional and storage‑specific (e.g., content‑type, tags).
	UploadFile(ctx context.Context, key string, reader io.Reader, metadata map[string]string) error

	// FileExists checks if a file exists at the given key.
	FileExists(ctx context.Context, key string) (bool, error)

	// DeleteFile removes the file permanently.
	DeleteFile(ctx context.Context, key string) error

	// GetFile returns a ReadCloser for the file at the given key.
	// The caller is responsible for closing it.
	GetFile(ctx context.Context, key string) (io.ReadCloser, error)
}
