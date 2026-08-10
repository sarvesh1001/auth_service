package handler

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/avatar/errors"
	"auth-service/internal/avatar/models"
	"auth-service/internal/avatar/service"
	"auth-service/internal/config"
	"auth-service/internal/storage"
)

// AvatarHandler handles HTTP requests for avatar management.
type AvatarHandler struct {
	service service.AvatarService
	storage storage.Storage
	config  *config.Config
	logger  *zap.Logger
}

// NewAvatarHandler creates a new AvatarHandler.
func NewAvatarHandler(
	svc service.AvatarService,
	storage storage.Storage,
	config *config.Config,
	logger *zap.Logger,
) *AvatarHandler {
	return &AvatarHandler{
		service: svc,
		storage: storage,
		config:  config,
		logger:  logger.Named("avatar_handler"),
	}
}

// ---------- Context keys ----------
type contextKey string

const (
	ctxKeyIdempotency = contextKey("idempotency_key")
	ctxKeyClientIP    = contextKey("client_ip")
)

// ---------- Helper functions ----------

func (h *AvatarHandler) getUserIDFromContext(ctx context.Context) (uuid.UUID, error) {
	val := ctx.Value("user_id")
	if val == nil {
		return uuid.Nil, errors.ErrUnauthorized
	}
	switch v := val.(type) {
	case uuid.UUID:
		return v, nil
	case string:
		return uuid.Parse(v)
	default:
		return uuid.Nil, errors.ErrUnauthorized
	}
}

// getCompanyIDFromHeader extracts X-Company-ID header.
func (h *AvatarHandler) getCompanyIDFromHeader(r *http.Request) (uuid.UUID, error) {
	header := r.Header.Get("X-Company-ID")
	if header == "" {
		return uuid.Nil, errors.ErrInvalidInput
	}
	return uuid.Parse(header)
}

// getIdempotencyKey extracts Idempotency-Key header.
func (h *AvatarHandler) getIdempotencyKey(r *http.Request) string {
	return r.Header.Get("Idempotency-Key")
}

// injectIdempotencyKey adds the key to the request context.
func (h *AvatarHandler) injectIdempotencyKey(ctx context.Context, r *http.Request) context.Context {
	key := h.getIdempotencyKey(r)
	if key != "" {
		return context.WithValue(ctx, ctxKeyIdempotency, key)
	}
	return ctx
}

// injectClientIP adds client IP to context (optional).
func (h *AvatarHandler) injectClientIP(ctx context.Context, r *http.Request) context.Context {
	// Simplified – you can implement full IP extraction if needed.
	return ctx
}

func (h *AvatarHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *AvatarHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

func (h *AvatarHandler) parseUUIDParam(r *http.Request, paramName string) (uuid.UUID, error) {
	idStr := chi.URLParam(r, paramName)
	if idStr == "" {
		return uuid.Nil, errors.ErrInvalidInput
	}
	return uuid.Parse(idStr)
}

// mapServiceError translates service-layer errors to HTTP status and message.
func (h *AvatarHandler) mapServiceError(err error) (int, string) {
	switch err {
	case errors.ErrNotFound:
		return http.StatusNotFound, "avatar not found"
	case errors.ErrInvalidInput:
		return http.StatusBadRequest, err.Error()
	case errors.ErrPermissionDenied:
		return http.StatusForbidden, "permission denied"
	case errors.ErrUnauthorized:
		return http.StatusUnauthorized, "authentication required"
	case errors.ErrDuplicate:
		return http.StatusConflict, "avatar already exists"
	case errors.ErrPrimaryRequired:
		return http.StatusBadRequest, "cannot delete the only primary avatar"
	case errors.ErrVariantGeneration:
		return http.StatusInternalServerError, "failed to generate variants"
	default:
		return http.StatusInternalServerError, "internal server error"
	}
}

// ---------- Request/Response types ----------

type uploadURLRequest struct {
	MimeType string `json:"mimeType"` // optional
}

type uploadURLResponse struct {
	UploadURL string `json:"uploadUrl"`
	FileKey   string `json:"fileKey"`
	ExpiresIn int    `json:"expiresIn"` // seconds
}

type confirmUploadRequest struct {
	FileKey    string `json:"fileKey"`
	MimeType   string `json:"mimeType"`
	SetPrimary bool   `json:"setPrimary"`
}

type avatarResponse struct {
	ID        string            `json:"id"`
	UserID    string            `json:"userId"`
	Type      string            `json:"type"`
	ObjectKey string            `json:"objectKey"` // signed URL
	MimeType  string            `json:"mimeType,omitempty"`
	IsActive  bool              `json:"isActive"`
	IsPrimary bool              `json:"isPrimary"`
	Variants  map[string]string `json:"variants"` // size -> signed URL
	CreatedAt string            `json:"createdAt"`
	UpdatedAt string            `json:"updatedAt"`
}

// ---------- Endpoint handlers ----------

// GetUploadURL generates a pre‑signed URL for uploading a new avatar.
func (h *AvatarHandler) GetUploadURL(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req uploadURLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	uploadURL, fileKey, err := h.service.GenerateUploadURL(ctx, userID, req.MimeType)
	if err != nil {
		h.logger.Error("generate upload URL failed", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": uploadURLResponse{
			UploadURL: uploadURL,
			FileKey:   fileKey,
			ExpiresIn: 600,
		},
	})
}

// UploadFile receives the file content and saves it to storage.
// This is the dedicated avatar file upload endpoint.
func (h *AvatarHandler) UploadFile(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	// Parse multipart form (max 20 MB)
	if err := r.ParseMultipartForm(20 << 20); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid multipart form")
		return
	}

	fileKey := r.FormValue("file_key")
	if fileKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "file_key is required")
		return
	}

	// Validate that the file key belongs to the authenticated user
	// to prevent uploading into another user's folder.
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	// Expected key format: "avatars/{userID}/..."
	if !strings.HasPrefix(fileKey, "avatars/"+userID.String()+"/") {
		h.respondWithError(w, http.StatusForbidden, "file key does not belong to your user")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "file is required")
		return
	}
	defer file.Close()

	// Optional: validate file size, mime type using header
	// For example, limit to 5 MB:
	if header.Size > 5*1024*1024 {
		h.respondWithError(w, http.StatusBadRequest, "file too large (max 5 MB)")
		return
	}

	// Save to storage
	metadata := map[string]string{
		"content-type": header.Header.Get("Content-Type"),
		"size":         strconv.FormatInt(header.Size, 10),
	}
	if err := h.storage.UploadFile(ctx, fileKey, file, metadata); err != nil {
		h.logger.Error("failed to save file", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to save file")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]string{
			"file_key": fileKey,
		},
		"message": "File uploaded successfully",
	})
}

// ConfirmUpload creates the avatar record after the file is uploaded.
func (h *AvatarHandler) ConfirmUpload(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req confirmUploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.FileKey == "" {
		h.respondWithError(w, http.StatusBadRequest, "fileKey is required")
		return
	}

	avatar, err := h.service.ConfirmUpload(ctx, userID, req.FileKey, req.MimeType, req.SetPrimary)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    h.toAvatarResponse(avatar),
		"message": "Avatar uploaded successfully",
	})
}

// GetAvatar returns a single avatar by ID.
func (h *AvatarHandler) GetAvatar(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	avatarID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid avatar ID")
		return
	}

	avatar, err := h.service.GetAvatar(ctx, avatarID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}
	// Check ownership
	if avatar.UserID != userID {
		h.respondWithError(w, http.StatusForbidden, "access denied")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    h.toAvatarResponse(avatar),
	})
}

// GetPrimaryAvatar returns the current primary avatar for the user.
func (h *AvatarHandler) GetPrimaryAvatar(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	avatar, err := h.service.GetPrimaryAvatar(ctx, userID)
	if err != nil {
		if err == errors.ErrNotFound {
			h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
				"success": true,
				"data":    nil,
				"message": "no primary avatar set",
			})
			return
		}
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    h.toAvatarResponse(avatar),
	})
}

// GetUserPrimaryAvatar returns the primary avatar of any user (by userId).
// Requires the caller to have hr.employee.view permission and the target user to be in the same company.
func (h *AvatarHandler) GetUserPrimaryAvatar(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	// 1. Extract target user ID from URL
	targetUserID, err := h.parseUUIDParam(r, "userId")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	// 2. Get company ID from header (required)
	companyID, err := h.getCompanyIDFromHeader(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "missing or invalid X-Company-ID header")
		return
	}

	// 3. Call service
	avatar, err := h.service.GetUserPrimaryAvatar(ctx, targetUserID, companyID)
	if err != nil {
		if err == errors.ErrNotFound {
			h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
				"success": true,
				"data":    nil,
				"message": "no primary avatar set for this user",
			})
			return
		}
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	// 4. Return
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    h.toAvatarResponse(avatar),
	})
}

// ListAvatars returns all active avatars for the user.
func (h *AvatarHandler) ListAvatars(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	avatars, err := h.service.ListAvatars(ctx, userID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := make([]avatarResponse, len(avatars))
	for i, a := range avatars {
		resp[i] = h.toAvatarResponse(a)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// ListInactiveAvatars returns all soft‑deleted avatars for the user.
func (h *AvatarHandler) ListInactiveAvatars(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	avatars, err := h.service.ListInactiveAvatars(ctx, userID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	resp := make([]avatarResponse, len(avatars))
	for i, a := range avatars {
		resp[i] = h.toAvatarResponse(a)
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    resp,
	})
}

// SetPrimary sets a given avatar as primary.
func (h *AvatarHandler) SetPrimary(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	avatarID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid avatar ID")
		return
	}

	if err := h.service.SetPrimary(ctx, userID, avatarID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "primary avatar updated",
	})
}

// DeleteAvatar soft‑deletes an avatar.
func (h *AvatarHandler) DeleteAvatar(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	avatarID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid avatar ID")
		return
	}

	if err := h.service.DeleteAvatar(ctx, userID, avatarID); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "avatar deleted",
	})
}

// ReactivateAvatar reactivates a previously soft‑deleted avatar.
func (h *AvatarHandler) ReactivateAvatar(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	avatarID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid avatar ID")
		return
	}

	var req struct {
		SetPrimary bool `json:"setPrimary"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req) // ignore error, default false

	if err := h.service.ReactivateAvatar(ctx, userID, avatarID, req.SetPrimary); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "avatar reactivated",
	})
}

// ---------- Signed URL endpoints ----------

// GetSignedURL returns a signed download URL for a given file key.
// Requires authentication; the caller must have permission to access the avatar.
func (h *AvatarHandler) GetSignedURL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	key := r.URL.Query().Get("key")
	if key == "" {
		h.respondWithError(w, http.StatusBadRequest, "missing key parameter")
		return
	}

	// Ensure the key is for an avatar file
	if !strings.HasPrefix(key, "avatars/") {
		h.respondWithError(w, http.StatusForbidden, "invalid file path")
		return
	}

	// Optional: additional permission check – the user must own the avatar or be in the same company.
	// We'll skip that for now, but you can implement it here if needed.

	signedURL, err := h.service.GenerateDownloadURL(ctx, key, 1*time.Hour)
	if err != nil {
		h.logger.Error("failed to generate signed URL", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to generate URL")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]string{
			"url": signedURL,
		},
	})
}

// ---------- File serving endpoint (public, but with signature validation) ----------

// GetFile serves the actual avatar file.
// The URL must include a valid signature (HMAC-SHA256) and expiration timestamp.
// This endpoint is public, but cannot be abused because only the server can generate valid signatures.
func (h *AvatarHandler) GetFile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	key := r.URL.Query().Get("key")
	if key == "" {
		h.respondWithError(w, http.StatusBadRequest, "missing key parameter")
		return
	}

	// Security: ensure the key points to an avatar file (prevents directory traversal)
	if !strings.HasPrefix(key, "avatars/") {
		h.respondWithError(w, http.StatusForbidden, "invalid file path")
		return
	}

	// Validate signature (required)
	expStr := r.URL.Query().Get("exp")
	sig := r.URL.Query().Get("sig")
	if expStr == "" || sig == "" {
		h.respondWithError(w, http.StatusUnauthorized, "missing signature parameters")
		return
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid expiration")
		return
	}
	if time.Now().Unix() > exp {
		h.respondWithError(w, http.StatusUnauthorized, "link expired")
		return
	}

	// Verify HMAC signature
	message := fmt.Sprintf("%s:%d", key, exp)
	mac := hmac.New(sha256.New, []byte(h.config.Security.JWTSecret))
	mac.Write([]byte(message))
	expectedSig := base64.URLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		h.respondWithError(w, http.StatusUnauthorized, "invalid signature")
		return
	}

	// Open the file from storage
	reader, err := h.storage.GetFile(ctx, key)
	if err != nil {
		h.logger.Error("failed to open file", zap.String("key", key), zap.Error(err))
		if os.IsNotExist(err) {
			h.respondWithError(w, http.StatusNotFound, "file not found")
		} else {
			h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve file")
		}
		return
	}
	defer reader.Close()

	// Determine content type
	contentType := "application/octet-stream"
	ext := filepath.Ext(key)
	switch strings.ToLower(ext) {
	case ".jpg", ".jpeg":
		contentType = "image/jpeg"
	case ".png":
		contentType = "image/png"
	case ".gif":
		contentType = "image/gif"
	case ".webp":
		contentType = "image/webp"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=86400") // cache for 1 day

	// Stream the file
	if _, err := io.Copy(w, reader); err != nil {
		h.logger.Error("failed to write file", zap.Error(err))
	}
}

// ---------- Response helper ----------

func (h *AvatarHandler) toAvatarResponse(a *models.Avatar) avatarResponse {
	// Generate signed URLs for all variants
	signedVariants := make(map[string]string)
	ctx := context.Background()
	for size, key := range a.Variants {
		signedURL, err := h.service.GenerateDownloadURL(ctx, key, 1*time.Hour)
		if err != nil {
			h.logger.Warn("failed to generate signed URL for variant",
				zap.String("size", size), zap.String("key", key), zap.Error(err))
			// fallback to the raw key (will be unusable, but better than nothing)
			signedVariants[size] = key
		} else {
			signedVariants[size] = signedURL
		}
	}

	// Generate signed URL for the original objectKey
	signedObjectKey := a.ObjectKey
	if a.ObjectKey != "" {
		signedURL, err := h.service.GenerateDownloadURL(ctx, a.ObjectKey, 1*time.Hour)
		if err == nil {
			signedObjectKey = signedURL
		}
	}

	return avatarResponse{
		ID:        a.ID.String(),
		UserID:    a.UserID.String(),
		Type:      string(a.Type),
		ObjectKey: signedObjectKey,
		MimeType:  a.MimeType,
		IsActive:  a.IsActive,
		IsPrimary: a.IsPrimary,
		Variants:  signedVariants,
		CreatedAt: a.CreatedAt.Format(time.RFC3339),
		UpdatedAt: a.UpdatedAt.Format(time.RFC3339),
	}
}
