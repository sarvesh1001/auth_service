package service

import (
	"auth-service/internal/util"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ============================================================================
// DOCUMENT STORAGE INTERFACE
// ============================================================================

type DocumentStorage interface {
	UploadDocument(ctx context.Context, file multipart.File, header *multipart.FileHeader, companyID, userID uuid.UUID) (*UploadResult, error)
	GetDocument(ctx context.Context, objectKey string) (*DocumentInfo, error)
	DownloadDocument(ctx context.Context, objectKey string) (io.ReadCloser, int64, string, error)
	DeleteDocument(ctx context.Context, objectKey string) error
	GenerateSignedURL(ctx context.Context, objectKey string, expiry time.Duration) (string, error)
	HealthCheck(ctx context.Context) error
}

// ============================================================================
// DTOs
// ============================================================================

type UploadResult struct {
	ObjectKey    string
	FileSize     int64
	MimeType     string
	OriginalName string
	Checksum     string
	UploadedAt   time.Time
}

type DocumentInfo struct {
	ObjectKey    string
	FileSize     int64
	MimeType     string
	OriginalName string
	Checksum     string
	UploadedAt   time.Time
	LastModified time.Time
}

// ============================================================================
// LOCAL FILE STORAGE IMPLEMENTATION
// ============================================================================

type LocalDocumentStorage struct {
	basePath     string
	maxFileSize  int64
	allowedTypes map[string]struct{}
	logger       *zap.Logger
	mu           sync.RWMutex
}

func NewLocalDocumentStorage(basePath string, maxFileSizeMB int, logger *zap.Logger) (*LocalDocumentStorage, error) {
	if basePath == "" {
		basePath = "/tmp/employee_documents"
	}

	if maxFileSizeMB <= 0 {
		maxFileSizeMB = 50
	}

	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create base directory: %w", err)
	}

	allowed := map[string]struct{}{
		"application/pdf":    {},
		"image/jpeg":         {},
		"image/png":          {},
		"image/gif":          {},
		"text/plain":         {},
		"application/zip":    {},
		"application/msword": {},
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document": {},
		"application/vnd.ms-excel": {},
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {},
	}

	return &LocalDocumentStorage{
		basePath:     basePath,
		maxFileSize:  int64(maxFileSizeMB) * 1024 * 1024,
		allowedTypes: allowed,
		logger:       logger,
	}, nil
}

// ============================================================================
// UPLOAD
// ============================================================================

func (s *LocalDocumentStorage) UploadDocument(
	ctx context.Context,
	file multipart.File,
	header *multipart.FileHeader,
	companyID, userID uuid.UUID,
) (*UploadResult, error) {

	start := time.Now()

	if header.Size > s.maxFileSize {
		return nil, fmt.Errorf("file size %d exceeds max %d", header.Size, s.maxFileSize)
	}

	// Read first 512 bytes for MIME sniffing
	buf := make([]byte, 512)
	n, err := file.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read file header: %w", err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		return nil, err
	}

	mimeType := http.DetectContentType(buf[:n])
	if _, ok := s.allowedTypes[mimeType]; !ok {
		return nil, fmt.Errorf("file type %s not allowed", mimeType)
	}

	safeName := filepath.Base(header.Filename)
	ext := filepath.Ext(safeName)

	docID := uuid.New()
	objectKey := filepath.Join(
		companyID.String(),
		userID.String(),
		docID.String(),
		docID.String()+ext,
	)

	fullPath := filepath.Join(s.basePath, objectKey)

	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		return nil, err
	}

	dst, err := os.Create(fullPath)
	if err != nil {
		return nil, err
	}
	defer dst.Close()

	hasher := sha256.New()
	writer := io.MultiWriter(dst, hasher)

	written, err := copyWithContext(ctx, writer, file)
	if err != nil {
		_ = os.Remove(fullPath)
		return nil, err
	}

	checksum := hex.EncodeToString(hasher.Sum(nil))

	s.logger.Info("Document uploaded",
		util.String("object_key", objectKey),
		util.String("company_id", companyID.String()),
		util.String("user_id", userID.String()),
		util.Int64("size", written),
		util.Duration("duration", time.Since(start)),
	)

	return &UploadResult{
		ObjectKey:    objectKey,
		FileSize:     written,
		MimeType:     mimeType,
		OriginalName: safeName,
		Checksum:     checksum,
		UploadedAt:   time.Now().UTC(),
	}, nil
}

// ============================================================================
// GET METADATA
// ============================================================================

func (s *LocalDocumentStorage) GetDocument(ctx context.Context, objectKey string) (*DocumentInfo, error) {
	fullPath := filepath.Join(s.basePath, objectKey)

	info, err := os.Stat(fullPath)
	if err != nil {
		return nil, err
	}

	return &DocumentInfo{
		ObjectKey:    objectKey,
		FileSize:     info.Size(),
		MimeType:     mimeFromExt(objectKey),
		OriginalName: filepath.Base(objectKey),
		Checksum:     "",
		UploadedAt:   info.ModTime(),
		LastModified: info.ModTime(),
	}, nil
}

// ============================================================================
// DOWNLOAD
// ============================================================================

func (s *LocalDocumentStorage) DownloadDocument(ctx context.Context, objectKey string) (io.ReadCloser, int64, string, error) {
	fullPath := filepath.Join(s.basePath, objectKey)

	f, err := os.Open(fullPath)
	if err != nil {
		return nil, 0, "", err
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, "", err
	}

	return f, info.Size(), mimeFromExt(objectKey), nil
}

// ============================================================================
// DELETE
// ============================================================================

func (s *LocalDocumentStorage) DeleteDocument(ctx context.Context, objectKey string) error {
	fullPath := filepath.Join(s.basePath, objectKey)
	return os.Remove(fullPath)
}

// ============================================================================
// SIGNED URL (LOCAL)
// ============================================================================

func (s *LocalDocumentStorage) GenerateSignedURL(ctx context.Context, objectKey string, _ time.Duration) (string, error) {
	fullPath := filepath.Join(s.basePath, objectKey)
	if _, err := os.Stat(fullPath); err != nil {
		return "", err
	}
	return fullPath, nil
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

func (s *LocalDocumentStorage) HealthCheck(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	test := filepath.Join(s.basePath, ".healthcheck")
	f, err := os.Create(test)
	if err != nil {
		return err
	}
	f.Close()
	return os.Remove(test)
}

// ============================================================================
// HELPERS
// ============================================================================

func copyWithContext(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 32*1024)
	var written int64

	for {
		select {
		case <-ctx.Done():
			return written, ctx.Err()
		default:
			n, err := src.Read(buf)
			if n > 0 {
				w, werr := dst.Write(buf[:n])
				written += int64(w)
				if werr != nil {
					return written, werr
				}
			}
			if err != nil {
				if err == io.EOF {
					return written, nil
				}
				return written, err
			}
		}
	}
}

func mimeFromExt(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".pdf":
		return "application/pdf"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".txt":
		return "text/plain"
	default:
		return "application/octet-stream"
	}
}
