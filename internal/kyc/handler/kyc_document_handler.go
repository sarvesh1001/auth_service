package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	customErrors "auth-service/internal/errors"
	kycErrors "auth-service/internal/kyc/errors"
	"auth-service/internal/kyc/models"
	"auth-service/internal/kyc/models/enums"
	"auth-service/internal/kyc/service"
	"auth-service/internal/storage"
)

// ----------------------------------------------------------------------
// Constants for file key generation
// ----------------------------------------------------------------------

// KYCFileKeyTemplate is the pattern for generating file keys.
// Placeholders: user UUID, document type, random file UUID + extension.
const KYCFileKeyTemplate = "kyc/%s/%s/%s"

// ----------------------------------------------------------------------
// Context keys
// ----------------------------------------------------------------------

type contextKey string

const (
	ctxKeyIdempotency = contextKey("idempotency_key")
	ctxKeyClientIP    = contextKey("client_ip")
)

// ----------------------------------------------------------------------
// Handler struct
// ----------------------------------------------------------------------

// KYCDocumentHandler handles HTTP requests for KYC document management.
type KYCDocumentHandler struct {
	docService service.KYCDocumentService
	storage    storage.Storage
	logger     *zap.Logger
}

// NewKYCDocumentHandler creates a new KYCDocumentHandler.
func NewKYCDocumentHandler(
	docService service.KYCDocumentService,
	storage storage.Storage,
	logger *zap.Logger,
) *KYCDocumentHandler {
	return &KYCDocumentHandler{
		docService: docService,
		storage:    storage,
		logger:     logger.Named("kyc_document_handler"),
	}
}

// ---------- Helper methods ----------

func (h *KYCDocumentHandler) getUserIDFromContext(ctx context.Context) (uuid.UUID, error) {
	val := ctx.Value("user_id")
	if val == nil {
		return uuid.Nil, customErrors.ErrUnauthorized
	}
	switch v := val.(type) {
	case uuid.UUID:
		return v, nil
	case string:
		return uuid.Parse(v)
	default:
		return uuid.Nil, customErrors.ErrUnauthorized
	}
}

// hasPermission is a placeholder – replace with actual permission check.
func (h *KYCDocumentHandler) hasPermission(ctx context.Context, companyID, userID uuid.UUID, perm string) bool {
	// TODO: implement real permission check
	return true
}

func (h *KYCDocumentHandler) parseUUIDParam(r *http.Request, paramName string) (uuid.UUID, error) {
	idStr := chi.URLParam(r, paramName)
	if idStr == "" {
		return uuid.Nil, customErrors.ErrInvalidInput
	}
	return uuid.Parse(idStr)
}

func (h *KYCDocumentHandler) parsePagination(r *http.Request) (limit, offset int) {
	limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	return
}

func (h *KYCDocumentHandler) parseSort(r *http.Request) (field, direction string) {
	field = r.URL.Query().Get("sort_by")
	if field == "" {
		field = "created_at"
	}
	direction = r.URL.Query().Get("sort_dir")
	if direction == "" {
		direction = "DESC"
	}
	if direction != "ASC" && direction != "DESC" {
		direction = "DESC"
	}
	return
}

func (h *KYCDocumentHandler) getIdempotencyKey(r *http.Request) string {
	return r.Header.Get("Idempotency-Key")
}

func (h *KYCDocumentHandler) getClientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if ips := strings.Split(forwarded, ","); len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		if net.ParseIP(realIP) != nil {
			return realIP
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// injectIdempotencyKey adds the idempotency key to the request context.
func (h *KYCDocumentHandler) injectIdempotencyKey(ctx context.Context, r *http.Request) context.Context {
	key := h.getIdempotencyKey(r)
	if key != "" {
		return context.WithValue(ctx, ctxKeyIdempotency, key)
	}
	return ctx
}

// injectClientIP adds the client IP to the request context.
func (h *KYCDocumentHandler) injectClientIP(ctx context.Context, r *http.Request) context.Context {
	ip := h.getClientIP(r)
	return context.WithValue(ctx, ctxKeyClientIP, ip)
}

// ---------- Error mapping ----------

// mapServiceError maps custom error types to HTTP status codes and messages.
func (h *KYCDocumentHandler) mapServiceError(err error) (int, string) {
	if err == nil {
		return http.StatusOK, ""
	}

	switch {
	case errors.Is(err, customErrors.ErrNotFound):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, customErrors.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, customErrors.ErrDuplicate):
		return http.StatusConflict, err.Error()
	case errors.Is(err, customErrors.ErrConflict):
		return http.StatusConflict, err.Error()
	case errors.Is(err, customErrors.ErrPermissionDenied):
		return http.StatusForbidden, err.Error()
	case errors.Is(err, customErrors.ErrUnauthorized):
		return http.StatusUnauthorized, err.Error()
	case errors.Is(err, customErrors.ErrInternal):
		return http.StatusInternalServerError, "internal server error"

	// KYC-specific errors
	case errors.Is(err, kycErrors.ErrDocumentNotFound):
		return http.StatusNotFound, "document not found"
	case errors.Is(err, kycErrors.ErrDocumentExpired):
		return http.StatusBadRequest, "document expired"
	case errors.Is(err, kycErrors.ErrDocumentAlreadyVerified):
		return http.StatusConflict, "document already verified"
	case errors.Is(err, kycErrors.ErrInvalidDocumentType):
		return http.StatusBadRequest, "invalid document type"
	case errors.Is(err, kycErrors.ErrInvalidStatus):
		return http.StatusBadRequest, "invalid document status"
	case errors.Is(err, kycErrors.ErrInvalidTransition):
		return http.StatusBadRequest, "invalid status transition"
	case errors.Is(err, kycErrors.ErrMissingRequiredDoc):
		return http.StatusBadRequest, "missing required document"

	default:
		return http.StatusInternalServerError, "internal server error"
	}
}

// ---------- Response helpers ----------

func (h *KYCDocumentHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *KYCDocumentHandler) respondWithError(w http.ResponseWriter, status int, err error, message string) {
	h.respondWithJSON(w, status, errorResponse(err, message))
}

// successResponse and errorResponse are assumed to be defined in a common package.
// If not, define them here.
func successResponse(data interface{}, message string) map[string]interface{} {
	resp := map[string]interface{}{
		"success": true,
		"message": message,
	}
	if data != nil {
		resp["data"] = data
	}
	return resp
}

func errorResponse(err error, message string) map[string]interface{} {
	if message == "" && err != nil {
		message = err.Error()
	}
	return map[string]interface{}{
		"success": false,
		"error":   message,
	}
}

// ---------- Request/Response Types ----------

// uploadDocumentRequest no longer includes FileKey – it will be auto-generated.
// Replace the existing uploadDocumentRequest with:
type uploadDocumentRequest struct {
	UserID       string       `json:"user_id"`
	DocumentType string       `json:"document_type"`
	FileKey      string       `json:"file_key"` // <-- NEW: client must send this
	FileMetadata models.JSONB `json:"file_metadata"`
	ExpiresAt    *string      `json:"expires_at,omitempty"`
}
type verifyDocumentRequest struct {
	Status string `json:"status"` // "verified" or "rejected"
	Notes  string `json:"notes"`
}

type listDocumentsResponse struct {
	Documents []documentSummary `json:"documents"`
	Total     int64             `json:"total"`
	Limit     int               `json:"limit"`
	Offset    int               `json:"offset"`
}

type documentSummary struct {
	ID           string  `json:"id"`
	UserID       string  `json:"user_id"`
	DocumentType string  `json:"document_type"`
	FileKey      string  `json:"file_key"`
	UploadStatus string  `json:"upload_status"`
	VerifiedBy   *string `json:"verified_by,omitempty"`
	VerifiedAt   *string `json:"verified_at,omitempty"`
	ExpiresAt    *string `json:"expires_at,omitempty"`
	CreatedAt    string  `json:"created_at"`
	UpdatedAt    string  `json:"updated_at"`
}

// ---------- New Endpoints: GetUploadURL and UploadFile ----------

// GetUploadURL generates a file key and returns a presigned upload URL.
// @Summary Get a presigned URL for uploading a KYC document
// @Description Generates a file key and returns a URL where the client can upload the file directly.
// @Tags kyc
// @Accept json
// @Produce json
// @Param body body object true "User ID, document type, and optional file metadata"
// @Success 200 {object} map[string]interface{} "Upload URL and file key"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/kyc/documents/upload-url [post]
func (h *KYCDocumentHandler) GetUploadURL(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "authentication required")
		return
	}

	var req struct {
		UserID       string       `json:"user_id"`
		DocumentType string       `json:"document_type"`
		FileMetadata models.JSONB `json:"file_metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "invalid request body")
		return
	}

	if req.UserID == "" || req.DocumentType == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "user_id and document_type are required")
		return
	}

	targetUserID, err := uuid.Parse(req.UserID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "invalid user_id")
		return
	}

	// Permission check
	if targetUserID != userID && !h.hasPermission(ctx, uuid.Nil, userID, "kyc:admin") {
		h.respondWithError(w, http.StatusForbidden, customErrors.ErrPermissionDenied, "cannot upload for other users")
		return
	}

	docType := enums.DocumentType(req.DocumentType)
	if !docType.IsValid() {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "invalid document_type")
		return
	}

	// Auto-generate file key
	fileUUID := uuid.New().String()
	ext := ""
	if req.FileMetadata != nil {
		if origName, ok := req.FileMetadata["original_name"].(string); ok && origName != "" {
			ext = filepath.Ext(origName)
		}
	}
	fileName := fileUUID + ext
	fileKey := fmt.Sprintf(KYCFileKeyTemplate, targetUserID.String(), string(docType), fileName)

	// Generate upload URL (storage implementation can return a presigned URL or local endpoint)
	uploadURL, err := h.storage.GenerateUploadURL(ctx, fileKey, 10*time.Minute)
	if err != nil {
		h.logger.Error("failed to generate upload URL", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err, "could not generate upload URL")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"file_key":   fileKey,
		"upload_url": uploadURL,
		"expires_in": 600, // 10 minutes in seconds
	}, "Upload URL generated"))
}

// UploadFile receives the file content and saves it to storage.
// @Summary Upload a file to storage using a file key
// @Description Multipart form upload; requires file_key and file.
// @Tags kyc
// @Accept multipart/form-data
// @Produce json
// @Param file_key formData string true "File key (obtained from /upload-url)"
// @Param file formData file true "File to upload"
// @Success 200 {object} map[string]interface{} "File uploaded"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/kyc/documents/upload [post]
func (h *KYCDocumentHandler) UploadFile(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	// Parse multipart form (max 20 MB)
	if err := r.ParseMultipartForm(20 << 20); err != nil {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "invalid multipart form")
		return
	}

	fileKey := r.FormValue("file_key")
	if fileKey == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "file_key is required")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "file is required")
		return
	}
	defer file.Close()

	// Optional: validate file size, mime type using header
	// ...

	// Save to storage
	metadata := map[string]string{
		"content-type": header.Header.Get("Content-Type"),
		"size":         strconv.FormatInt(header.Size, 10),
	}
	if err := h.storage.UploadFile(ctx, fileKey, file, metadata); err != nil {
		h.logger.Error("failed to save file", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err, "failed to save file")
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]string{
		"file_key": fileKey,
	}, "File uploaded successfully"))
}

// ---------- Existing Endpoints ----------

// UploadDocument handles document upload – file_key is auto-generated.
// @Summary Upload a KYC document
// @Description Uploads a new KYC document for a user (admin-only; requires admin.employee.update permission).
// @Tags kyc
// @Accept json
// @Produce json
// @Param body body uploadDocumentRequest true "Document upload details"
// @Success 201 {object} map[string]interface{} "Document uploaded"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Failure 409 {object} map[string]interface{} "Conflict (duplicate)"
// @Router /api/v1/kyc/documents [post]
func (h *KYCDocumentHandler) UploadDocument(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "authentication required")
		return
	}

	var req uploadDocumentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "invalid request body")
		return
	}

	if req.UserID == "" || req.DocumentType == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "user_id and document_type are required")
		return
	}
	if req.FileKey == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "file_key is required")
		return
	}

	targetUserID, err := uuid.Parse(req.UserID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "invalid user_id")
		return
	}

	// Permission check
	if targetUserID != userID && !h.hasPermission(ctx, uuid.Nil, userID, "kyc:admin") {
		h.respondWithError(w, http.StatusForbidden, customErrors.ErrPermissionDenied, "cannot upload for other users")
		return
	}

	docType := enums.DocumentType(req.DocumentType)
	if !docType.IsValid() {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "invalid document_type")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Idempotency-Key header is required")
		return
	}

	// Use the provided file_key directly
	fileKey := req.FileKey

	svcReq := &service.UploadDocumentRequest{
		UserID:       targetUserID,
		DocumentType: docType,
		FileKey:      fileKey,
		FileMetadata: req.FileMetadata,
		UploadedBy:   userID,
	}
	if req.ExpiresAt != nil {
		if t, err := time.Parse(time.RFC3339, *req.ExpiresAt); err == nil {
			svcReq.ExpiresAt = &t
		}
	}

	doc, err := h.docService.UploadDocument(ctx, svcReq)
	if err != nil {
		h.logger.Error("failed to upload document", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	resp := h.toDocumentSummary(doc)
	location := "/kyc/documents/" + doc.ID.String()
	w.Header().Set("Location", location)
	h.respondWithJSON(w, http.StatusCreated, successResponse(resp, "Document uploaded successfully"))
}

// GetDocumentByID retrieves a specific KYC document.
// @Summary Get KYC document by ID
// @Tags kyc
// @Produce json
// @Param id path string true "Document UUID"
// @Success 200 {object} map[string]interface{} "Document details"
// @Failure 400 {object} map[string]interface{} "Invalid document ID"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Failure 404 {object} map[string]interface{} "Document not found"
// @Router /api/v1/kyc/documents/{id} [get]
func (h *KYCDocumentHandler) GetDocumentByID(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	docID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "invalid document ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "authentication required")
		return
	}

	doc, err := h.docService.GetDocumentByID(ctx, docID)
	if err != nil {
		h.logger.Error("failed to get document", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	// Only allow if own document or has read permission
	if doc.UserID != userID && !h.hasPermission(ctx, uuid.Nil, userID, "kyc:read") {
		h.respondWithError(w, http.StatusForbidden, customErrors.ErrPermissionDenied, "insufficient permissions")
		return
	}

	resp := h.toDocumentSummary(doc)
	h.respondWithJSON(w, http.StatusOK, successResponse(resp, "Document retrieved"))
}

// ListDocuments lists KYC documents with filters and pagination.
// @Summary List KYC documents
// @Description Lists documents with optional filters (user, type, status, date range).
// @Tags kyc
// @Produce json
// @Param user_id query string false "Filter by user ID"
// @Param type query string false "Filter by document type (identity, address, business, selfie)"
// @Param status query string false "Filter by upload status (pending, uploaded, verified, rejected)"
// @Param from_date query string false "Filter by created_at >= RFC3339 date"
// @Param to_date query string false "Filter by created_at <= RFC3339 date"
// @Param q query string false "Search in file_key or original_name"
// @Param limit query int false "Page size (default 20, max 100)"
// @Param offset query int false "Offset (default 0)"
// @Param sort_by query string false "Sort field (created_at, updated_at, expires_at, user_id)"
// @Param sort_dir query string false "Sort direction (ASC, DESC)"
// @Success 200 {object} map[string]interface{} "List of documents with metadata"
// @Failure 400 {object} map[string]interface{} "Invalid parameters"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/kyc/documents [get]
func (h *KYCDocumentHandler) ListDocuments(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "authentication required")
		return
	}

	var filter service.ListDocumentsFilter

	if userIDStr := r.URL.Query().Get("user_id"); userIDStr != "" {
		uid, err := uuid.Parse(userIDStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "invalid user_id")
			return
		}
		if uid != userID && !h.hasPermission(ctx, uuid.Nil, userID, "kyc:read") {
			h.respondWithError(w, http.StatusForbidden, customErrors.ErrPermissionDenied, "cannot view other users' documents")
			return
		}
		filter.UserID = &uid
	}

	if docTypeStr := r.URL.Query().Get("type"); docTypeStr != "" {
		dt := enums.DocumentType(docTypeStr)
		if !dt.IsValid() {
			h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "invalid document_type")
			return
		}
		filter.DocumentType = &dt
	}
	if statusStr := r.URL.Query().Get("status"); statusStr != "" {
		st := enums.DocumentUploadStatus(statusStr)
		if !st.IsValid() {
			h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "invalid status")
			return
		}
		filter.Statuses = []enums.DocumentUploadStatus{st}
	}
	if fromStr := r.URL.Query().Get("from_date"); fromStr != "" {
		if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
			filter.FromDate = &t
		}
	}
	if toStr := r.URL.Query().Get("to_date"); toStr != "" {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			filter.ToDate = &t
		}
	}
	if q := r.URL.Query().Get("q"); q != "" {
		filter.SearchQuery = &q
	}

	limit, offset := h.parsePagination(r)
	pagination := service.Pagination{Limit: limit, Offset: offset}
	field, direction := h.parseSort(r)
	sort := service.Sort{Field: field, Direction: direction}

	docs, total, err := h.docService.ListDocuments(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list documents", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err, "failed to list documents")
		return
	}

	summaries := make([]documentSummary, len(docs))
	for i, d := range docs {
		summaries[i] = h.toDocumentSummary(d)
	}
	resp := listDocumentsResponse{
		Documents: summaries,
		Total:     total,
		Limit:     limit,
		Offset:    offset,
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(resp, "Documents listed"))
}

// VerifyDocument verifies or rejects a KYC document.
// @Summary Verify/reject a KYC document
// @Description Updates the verification status of a document (admin-only; requires kyc:verify permission).
// @Tags kyc
// @Accept json
// @Produce json
// @Param id path string true "Document UUID"
// @Param body body verifyDocumentRequest true "Verification action"
// @Success 200 {object} map[string]interface{} "Document verified/rejected"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Failure 404 {object} map[string]interface{} "Document not found"
// @Failure 409 {object} map[string]interface{} "Conflict (already verified)"
// @Router /api/v1/kyc/documents/{id}/verify [patch]
func (h *KYCDocumentHandler) VerifyDocument(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	docID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "invalid document ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "authentication required")
		return
	}

	if !h.hasPermission(ctx, uuid.Nil, userID, "kyc:verify") {
		h.respondWithError(w, http.StatusForbidden, customErrors.ErrPermissionDenied, "insufficient permissions")
		return
	}

	var req verifyDocumentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "invalid request body")
		return
	}
	status := enums.DocumentUploadStatus(req.Status)
	if status != enums.DocumentStatusVerified && status != enums.DocumentStatusRejected {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "status must be 'verified' or 'rejected'")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Idempotency-Key header is required")
		return
	}

	svcReq := &service.VerifyDocumentRequest{
		DocumentID: docID,
		VerifiedBy: userID,
		Status:     status,
		Notes:      req.Notes,
	}
	if err := h.docService.VerifyDocument(ctx, svcReq); err != nil {
		h.logger.Error("failed to verify document", zap.Error(err))
		statusCode, msg := h.mapServiceError(err)
		h.respondWithError(w, statusCode, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Document verified/rejected successfully"))
}

// DeleteDocument deletes a KYC document.
// @Summary Delete a KYC document
// @Description Permanently deletes a document (admin-only; requires kyc:admin permission).
// @Tags kyc
// @Produce json
// @Param id path string true "Document UUID"
// @Success 200 {object} map[string]interface{} "Document deleted"
// @Failure 400 {object} map[string]interface{} "Invalid document ID"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Failure 404 {object} map[string]interface{} "Document not found"
// @Router /api/v1/kyc/documents/{id} [delete]
func (h *KYCDocumentHandler) DeleteDocument(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	docID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "invalid document ID")
		return
	}

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "authentication required")
		return
	}

	if !h.hasPermission(ctx, uuid.Nil, userID, "kyc:admin") {
		h.respondWithError(w, http.StatusForbidden, customErrors.ErrPermissionDenied, "insufficient permissions")
		return
	}

	idempotencyKey := h.getIdempotencyKey(r)
	if idempotencyKey == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "Idempotency-Key header is required")
		return
	}

	if err := h.docService.DeleteDocument(ctx, docID, userID); err != nil {
		h.logger.Error("failed to delete document", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Document deleted successfully"))
}

// GetPendingDocuments retrieves all documents pending verification.
// @Summary Get pending KYC documents
// @Description Lists documents with status 'uploaded' (admin-only; requires kyc:verify permission).
// @Tags kyc
// @Produce json
// @Success 200 {object} map[string]interface{} "List of pending documents"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Permission denied"
// @Router /api/v1/kyc/documents/pending [get]
func (h *KYCDocumentHandler) GetPendingDocuments(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "authentication required")
		return
	}

	if !h.hasPermission(ctx, uuid.Nil, userID, "kyc:verify") {
		h.respondWithError(w, http.StatusForbidden, customErrors.ErrPermissionDenied, "insufficient permissions")
		return
	}

	docs, err := h.docService.GetPendingDocuments(ctx)
	if err != nil {
		h.logger.Error("failed to get pending documents", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err, "failed to get pending documents")
		return
	}

	summaries := make([]documentSummary, len(docs))
	for i, d := range docs {
		summaries[i] = h.toDocumentSummary(d)
	}
	h.respondWithJSON(w, http.StatusOK, successResponse(summaries, "Pending documents retrieved"))
}

// ---------- Response helper ----------

func (h *KYCDocumentHandler) toDocumentSummary(doc *models.KYCDocument) documentSummary {
	summary := documentSummary{
		ID:           doc.ID.String(),
		UserID:       doc.UserID.String(),
		DocumentType: string(doc.DocumentType),
		FileKey:      doc.FileKey,
		UploadStatus: string(doc.UploadStatus),
		CreatedAt:    doc.CreatedAt.Format(time.RFC3339),
		UpdatedAt:    doc.UpdatedAt.Format(time.RFC3339),
	}
	if doc.VerifiedBy != nil {
		vb := doc.VerifiedBy.String()
		summary.VerifiedBy = &vb
	}
	if doc.VerifiedAt != nil {
		va := doc.VerifiedAt.Format(time.RFC3339)
		summary.VerifiedAt = &va
	}
	if doc.ExpiresAt != nil {
		ea := doc.ExpiresAt.Format(time.RFC3339)
		summary.ExpiresAt = &ea
	}
	return summary
}

// GetFile serves the actual document file.
// @Summary Download KYC document file
// @Tags kyc
// @Produce application/octet-stream
// @Param id path string true "Document UUID"
// @Success 200 {file} file "Document file"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Document not found"
// @Router /api/v1/kyc/documents/{id}/file [get]
func (h *KYCDocumentHandler) GetFile(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	docID, err := h.parseUUIDParam(r, "id")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "invalid document ID")
		return
	}

	// Fetch document metadata
	doc, err := h.docService.GetDocumentByID(ctx, docID)
	if err != nil {
		h.logger.Error("failed to get document", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	// Open the file from storage
	reader, err := h.storage.GetFile(ctx, doc.FileKey)
	if err != nil {
		h.logger.Error("failed to open file", zap.Error(err))
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}
	defer reader.Close()

	// Set content type based on file extension (or metadata if available)
	contentType := "application/octet-stream"
	ext := filepath.Ext(doc.FileKey)
	switch strings.ToLower(ext) {
	case ".jpg", ".jpeg":
		contentType = "image/jpeg"
	case ".png":
		contentType = "image/png"
	case ".gif":
		contentType = "image/gif"
	case ".pdf":
		contentType = "application/pdf"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=\"%s\"", filepath.Base(doc.FileKey)))

	// Stream the file
	_, err = io.Copy(w, reader)
	if err != nil {
		h.logger.Error("failed to write file to response", zap.Error(err))
	}
}
