package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"auth-service/internal/avatar/errors"
	"auth-service/internal/avatar/models"
	"auth-service/internal/avatar/repository"
	"auth-service/internal/client"
	"auth-service/internal/config"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/storage"

	"github.com/disintegration/imaging"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AvatarService defines the business logic interface
type AvatarService interface {
	GenerateUploadURL(ctx context.Context, userID uuid.UUID, mimeType string) (uploadURL, fileKey string, err error)
	ConfirmUpload(ctx context.Context, userID uuid.UUID, fileKey, mimeType string, setPrimary bool) (*models.Avatar, error)
	GenerateVariants(ctx context.Context, avatarID uuid.UUID) error
	GetAvatar(ctx context.Context, avatarID uuid.UUID) (*models.Avatar, error)
	GetPrimaryAvatar(ctx context.Context, userID uuid.UUID) (*models.Avatar, error)
	GetUserPrimaryAvatar(ctx context.Context, targetUserID, companyID uuid.UUID) (*models.Avatar, error)
	ListAvatars(ctx context.Context, userID uuid.UUID) ([]*models.Avatar, error)
	ListInactiveAvatars(ctx context.Context, userID uuid.UUID) ([]*models.Avatar, error)
	SetPrimary(ctx context.Context, userID, avatarID uuid.UUID) error
	DeleteAvatar(ctx context.Context, userID, avatarID uuid.UUID) error
	ReactivateAvatar(ctx context.Context, userID, avatarID uuid.UUID, setPrimary bool) error
	// GenerateDownloadURL creates a signed URL for downloading a file (used for <Image> without headers)
	GenerateDownloadURL(ctx context.Context, key string, expiry time.Duration) (string, error)
}

type avatarService struct {
	repo             repository.AvatarRepository
	storage          storage.Storage
	db               *client.PostgresClient
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	config           *config.Config
	logger           *zap.Logger
}

func NewAvatarService(
	repo repository.AvatarRepository,
	storage storage.Storage,
	db *client.PostgresClient,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	config *config.Config,
	logger *zap.Logger,
) AvatarService {
	return &avatarService{
		repo:             repo,
		storage:          storage,
		db:               db,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		config:           config,
		logger:           logger.Named("avatar_service"),
	}
}

// GenerateUploadURL generates a file key and a pre-signed URL (or local endpoint)
func (s *avatarService) GenerateUploadURL(ctx context.Context, userID uuid.UUID, mimeType string) (string, string, error) {
	fileUUID := uuid.New().String()
	ext := ".jpg"
	if mimeType != "" {
		switch mimeType {
		case "image/png":
			ext = ".png"
		case "image/gif":
			ext = ".gif"
		case "image/webp":
			ext = ".webp"
		default:
			ext = ".jpg"
		}
	}
	fileName := fileUUID + ext
	fileKey := fmt.Sprintf("avatars/%s/%s", userID.String(), fileName)

	uploadURL, err := s.storage.GenerateUploadURL(ctx, fileKey, 10*time.Minute)
	if err != nil {
		return "", "", fmt.Errorf("generate upload URL: %w", err)
	}
	return uploadURL, fileKey, nil
}

// ConfirmUpload inserts a new avatar record with idempotency and audit.
func (s *avatarService) ConfirmUpload(ctx context.Context, userID uuid.UUID, fileKey, mimeType string, setPrimary bool) (*models.Avatar, error) {
	logger := s.logger.With(zap.String("method", "ConfirmUpload"))

	// Validate input
	if userID == uuid.Nil {
		return nil, fmt.Errorf("%w: user_id required", errors.ErrInvalidInput)
	}
	if fileKey == "" {
		return nil, fmt.Errorf("%w: file_key required", errors.ErrInvalidInput)
	}

	// Check file exists in storage
	exists, err := s.storage.FileExists(ctx, fileKey)
	if err != nil {
		return nil, fmt.Errorf("check file existence: %w", err)
	}
	if !exists {
		return nil, errors.ErrInvalidInput
	}

	// Compute file hash for deduplication
	reader, err := s.storage.GetFile(ctx, fileKey)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer reader.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, reader); err != nil {
		return nil, fmt.Errorf("hash file: %w", err)
	}
	hash := hex.EncodeToString(hasher.Sum(nil))

	// Start transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency key based on user and file hash (or fileKey)
	idempKey := fmt.Sprintf("avatar-confirm-%s-%s", userID.String(), fileKey)

	// Check idempotency store
	var cached *models.Avatar
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached avatar", zap.String("avatar_id", cached.ID.String()))
		return cached, nil
	}

	// Check if user already has a primary
	var hasPrimary bool
	if setPrimary {
		existingPrimary, _ := s.repo.GetPrimaryByUser(ctx, tx, userID)
		if existingPrimary != nil {
			hasPrimary = true
		}
	}

	avatar := &models.Avatar{
		ID:        uuid.New(),
		UserID:    userID,
		Type:      models.AvatarTypeUploaded,
		Hash:      hash,
		ObjectKey: fileKey,
		MimeType:  mimeType,
		IsActive:  true,
		IsPrimary: setPrimary && !hasPrimary,
		Variants:  make(map[string]string),
	}

	if err := s.repo.Create(ctx, tx, avatar); err != nil {
		return nil, fmt.Errorf("create avatar: %w", err)
	}

	if setPrimary && hasPrimary {
		if err := s.repo.UpdatePrimary(ctx, tx, userID, avatar.ID); err != nil {
			return nil, fmt.Errorf("set primary: %w", err)
		}
	}

	// Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "avatar", "upload", "user_avatar",
			&avatar.ID, "user", &userID, nil, nil, map[string]interface{}{
				"user_id":    avatar.UserID.String(),
				"file_key":   avatar.ObjectKey,
				"is_primary": avatar.IsPrimary,
			})
	}

	// Store idempotency
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, avatar); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Async variant generation
	go func() {
		ctxBg := context.Background()
		if err := s.GenerateVariants(ctxBg, avatar.ID); err != nil {
			s.logger.Error("failed to generate variants", zap.String("avatar_id", avatar.ID.String()), zap.Error(err))
		}
	}()

	return avatar, nil
}

// GenerateVariants downloads the original, creates small/medium/large, uploads, and updates DB.
func (s *avatarService) GenerateVariants(ctx context.Context, avatarID uuid.UUID) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	avatar, err := s.repo.GetByID(ctx, tx, avatarID)
	if err != nil {
		return fmt.Errorf("get avatar: %w", err)
	}
	if avatar == nil {
		return errors.ErrNotFound
	}
	if len(avatar.Variants) > 0 {
		return nil // already processed
	}

	reader, err := s.storage.GetFile(ctx, avatar.ObjectKey)
	if err != nil {
		return fmt.Errorf("download original: %w", err)
	}
	defer reader.Close()

	img, format, err := image.Decode(reader)
	if err != nil {
		return fmt.Errorf("decode image: %w", err)
	}

	outFormat := imaging.JPEG
	outExt := ".jpg"
	if format == "png" {
		outFormat = imaging.JPEG
		outExt = ".jpg"
	}

	sizes := map[string]int{
		"small":  150,
		"medium": 320,
		"large":  640,
	}
	variants := make(map[string]string)
	base := strings.TrimSuffix(avatar.ObjectKey, filepath.Ext(avatar.ObjectKey))

	for name, size := range sizes {
		thumb := imaging.Thumbnail(img, size, size, imaging.CatmullRom)

		buf := new(bytes.Buffer)
		var encodeErr error
		switch outFormat {
		case imaging.JPEG:
			encodeErr = jpeg.Encode(buf, thumb, &jpeg.Options{Quality: 85})
		case imaging.PNG:
			encodeErr = png.Encode(buf, thumb)
		default:
			encodeErr = imaging.Encode(buf, thumb, outFormat, imaging.JPEGQuality(85))
		}
		if encodeErr != nil {
			return fmt.Errorf("encode %s: %w", name, encodeErr)
		}

		variantKey := fmt.Sprintf("%s_%s%s", base, name, outExt)
		err = s.storage.UploadFile(ctx, variantKey, buf, map[string]string{
			"content-type": "image/jpeg",
			"size":         fmt.Sprintf("%d", buf.Len()),
			"width":        fmt.Sprintf("%d", size),
			"height":       fmt.Sprintf("%d", size),
		})
		if err != nil {
			return fmt.Errorf("upload %s: %w", name, err)
		}
		variants[name] = variantKey
	}

	if err := s.repo.UpdateVariants(ctx, tx, avatarID, variants); err != nil {
		return fmt.Errorf("update variants: %w", err)
	}

	// Audit variant generation (optional)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "avatar", "generate_variants", "user_avatar",
			&avatarID, "system", nil, nil, nil, map[string]interface{}{
				"variants": variants,
			})
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// GetAvatar returns a single avatar by ID
func (s *avatarService) GetAvatar(ctx context.Context, avatarID uuid.UUID) (*models.Avatar, error) {
	return s.repo.GetByID(ctx, s.db.DB, avatarID)
}

// GetPrimaryAvatar returns the primary avatar for a user
func (s *avatarService) GetPrimaryAvatar(ctx context.Context, userID uuid.UUID) (*models.Avatar, error) {
	return s.repo.GetPrimaryByUser(ctx, s.db.DB, userID)
}

// GetUserPrimaryAvatar returns the primary avatar of a target user, but only if the caller's company matches.
func (s *avatarService) GetUserPrimaryAvatar(ctx context.Context, targetUserID, companyID uuid.UUID) (*models.Avatar, error) {
	// 1. Check if target user belongs to the company
	belongs, err := s.checkUserInCompany(ctx, targetUserID, companyID)
	if err != nil {
		return nil, err
	}
	if !belongs {
		return nil, errors.ErrPermissionDenied
	}

	// 2. Fetch the primary avatar
	return s.repo.GetPrimaryByUser(ctx, s.db.DB, targetUserID)
}

// checkUserInCompany verifies that the given user is an active employee of the company.
func (s *avatarService) checkUserInCompany(ctx context.Context, userID, companyID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM company_employees WHERE user_id = $1 AND company_id = $2 AND is_active = true)`
	err := s.db.DB.QueryRowContext(ctx, query, userID, companyID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check company membership: %w", err)
	}
	return exists, nil
}

// ListAvatars returns all active avatars for a user
func (s *avatarService) ListAvatars(ctx context.Context, userID uuid.UUID) ([]*models.Avatar, error) {
	return s.repo.GetByUser(ctx, s.db.DB, userID)
}

// ListInactiveAvatars returns all soft‑deleted avatars for a user
func (s *avatarService) ListInactiveAvatars(ctx context.Context, userID uuid.UUID) ([]*models.Avatar, error) {
	return s.repo.GetInactiveByUser(ctx, s.db.DB, userID)
}

// SetPrimary sets a given avatar as primary with idempotency and audit.
func (s *avatarService) SetPrimary(ctx context.Context, userID, avatarID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "SetPrimary"))

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency key
	idempKey := fmt.Sprintf("avatar-setprimary-%s-%s", userID.String(), avatarID.String())
	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – primary already set")
		return nil
	}

	av, err := s.repo.GetByID(ctx, tx, avatarID)
	if err != nil {
		return err
	}
	if av.UserID != userID {
		return errors.ErrPermissionDenied
	}
	if !av.IsActive {
		return errors.ErrInvalidInput
	}
	if av.IsPrimary {
		// Already primary, store idempotency and return
		_ = s.idempotencyStore.Store(ctx, tx, idempKey, true)
		return tx.Commit()
	}

	if err := s.repo.UpdatePrimary(ctx, tx, userID, avatarID); err != nil {
		return err
	}

	// Audit
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "avatar", "set_primary", "user_avatar",
			&avatarID, "user", &userID, nil, nil, nil)
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

// DeleteAvatar soft-deletes an avatar with idempotency and audit.
func (s *avatarService) DeleteAvatar(ctx context.Context, userID, avatarID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteAvatar"))

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := fmt.Sprintf("avatar-delete-%s-%s", userID.String(), avatarID.String())
	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – already deleted")
		return nil
	}

	av, err := s.repo.GetByID(ctx, tx, avatarID)
	if err != nil {
		return err
	}
	if av.UserID != userID {
		return errors.ErrPermissionDenied
	}
	if av.IsPrimary {
		others, err := s.repo.GetByUser(ctx, tx, userID)
		if err != nil {
			return err
		}
		var fallback *models.Avatar
		for _, o := range others {
			if o.ID != avatarID && o.IsActive {
				fallback = o
				break
			}
		}
		if fallback == nil {
			return errors.ErrPrimaryRequired
		}
		if err := s.repo.UpdatePrimary(ctx, tx, userID, fallback.ID); err != nil {
			return err
		}
		// Audit: fallback primary set
		if s.auditService != nil {
			_ = s.auditService.LogAction(ctx, nil, nil, "avatar", "set_primary_fallback", "user_avatar",
				&fallback.ID, "user", &userID, nil, nil, map[string]interface{}{
					"deleted_avatar_id": avatarID.String(),
				})
		}
	}
	if err := s.repo.Delete(ctx, tx, avatarID); err != nil {
		return err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "avatar", "delete", "user_avatar",
			&avatarID, "user", &userID, nil, nil, nil)
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

// ReactivateAvatar reactivates a soft‑deleted avatar. If setPrimary is true and no other primary exists,
// it will become primary.
func (s *avatarService) ReactivateAvatar(ctx context.Context, userID, avatarID uuid.UUID, setPrimary bool) error {
	logger := s.logger.With(zap.String("method", "ReactivateAvatar"))

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency key (optional but recommended)
	idempKey := fmt.Sprintf("avatar-reactivate-%s-%s", userID.String(), avatarID.String())
	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – avatar already reactivated")
		return nil
	}

	// Check ownership and existence
	av, err := s.repo.GetByID(ctx, tx, avatarID)
	if err != nil {
		return err
	}
	if av.UserID != userID {
		return errors.ErrPermissionDenied
	}
	if av.IsActive {
		// Already active – store idempotency and return.
		_ = s.idempotencyStore.Store(ctx, tx, idempKey, true)
		return tx.Commit()
	}

	// Reactivate
	if err := s.repo.Reactivate(ctx, tx, avatarID); err != nil {
		return err
	}

	// If setPrimary is true and no primary exists, make this avatar primary.
	if setPrimary {
		existingPrimary, _ := s.repo.GetPrimaryByUser(ctx, tx, userID)
		if existingPrimary == nil {
			if err := s.repo.UpdatePrimary(ctx, tx, userID, avatarID); err != nil {
				return err
			}
		}
	}

	// Audit
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "avatar", "reactivate", "user_avatar",
			&avatarID, "user", &userID, nil, nil, map[string]interface{}{
				"set_primary": setPrimary,
			})
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

// GenerateDownloadURL creates a signed URL for downloading a file.
// The URL includes a signature (HMAC-SHA256) and an expiration timestamp,
// so it can be used in an <Image> component without custom headers.
func (s *avatarService) GenerateDownloadURL(ctx context.Context, key string, expiry time.Duration) (string, error) {
	expiresAt := time.Now().Add(expiry).Unix()
	message := fmt.Sprintf("%s:%d", key, expiresAt)
	h := hmac.New(sha256.New, []byte(s.config.Security.JWTSecret))
	h.Write([]byte(message))
	sig := base64.URLEncoding.EncodeToString(h.Sum(nil))

	baseURL := strings.TrimSuffix(s.config.Server.PublicBaseURL, "/")
	// Strip "/admin" from the base URL
	baseURL = strings.TrimSuffix(baseURL, "/admin")
	baseURL = strings.TrimSuffix(baseURL, "/admin/")
	if baseURL == "" {
		baseURL = fmt.Sprintf("http://localhost:%d/api/v1", s.config.Server.Port)
		if s.config.Server.EnableTLS {
			baseURL = fmt.Sprintf("https://localhost:%d/api/v1", s.config.Server.Port)
		}
	}
	encodedKey := url.QueryEscape(key)
	return fmt.Sprintf("%s/avatars/file?key=%s&exp=%d&sig=%s", baseURL, encodedKey, expiresAt, sig), nil
}
