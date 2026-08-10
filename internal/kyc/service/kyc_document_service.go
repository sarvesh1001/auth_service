package service

import (
	"context"
	"fmt"
	"time"

	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	kycErrors "auth-service/internal/kyc/errors"
	"auth-service/internal/kyc/models"
	"auth-service/internal/kyc/models/enums"
	"auth-service/internal/kyc/repository"
	"auth-service/internal/storage"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// -------------------------------------------------------------------------
// DTOs
// -------------------------------------------------------------------------

type UploadDocumentRequest struct {
	UserID       uuid.UUID
	DocumentType enums.DocumentType
	FileKey      string
	FileMetadata models.JSONB
	UploadedBy   uuid.UUID
	ExpiresAt    *time.Time
}

type VerifyDocumentRequest struct {
	DocumentID uuid.UUID
	VerifiedBy uuid.UUID
	Status     enums.DocumentUploadStatus
	Notes      string
}

type ListDocumentsFilter struct {
	UserID       *uuid.UUID
	DocumentType *enums.DocumentType
	Statuses     []enums.DocumentUploadStatus
	FromDate     *time.Time
	ToDate       *time.Time
	SearchQuery  *string
}

// Pagination and Sort are used in the interface but defined in repository.
type Pagination = repository.Pagination
type Sort = repository.Sort

// -------------------------------------------------------------------------
// Service Interface
// -------------------------------------------------------------------------

type KYCDocumentService interface {
	UploadDocument(ctx context.Context, req *UploadDocumentRequest) (*models.KYCDocument, error)
	GetDocumentByID(ctx context.Context, docID uuid.UUID) (*models.KYCDocument, error)
	GetDocumentsByUser(ctx context.Context, userID uuid.UUID) ([]*models.KYCDocument, error)
	ListDocuments(ctx context.Context, filter ListDocumentsFilter, p Pagination, s Sort) ([]*models.KYCDocument, int64, error)
	VerifyDocument(ctx context.Context, req *VerifyDocumentRequest) error
	DeleteDocument(ctx context.Context, docID uuid.UUID, deletedBy uuid.UUID) error
	GetPendingDocuments(ctx context.Context) ([]*models.KYCDocument, error)
	GetExpiredDocuments(ctx context.Context) ([]*models.KYCDocument, error)
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type kycDocumentService struct {
	repo             repository.KYCDocumentRepository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	pgClient         *client.PostgresClient
	storage          storage.Storage
	logger           *zap.Logger
}

func NewKYCDocumentService(
	repo repository.KYCDocumentRepository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	pgClient *client.PostgresClient,
	storage storage.Storage,
	logger *zap.Logger,
) KYCDocumentService {
	return &kycDocumentService{
		repo:             repo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		pgClient:         pgClient,
		storage:          storage,
		logger:           logger.Named("kyc_document_service"),
	}
}

// -------------------------------------------------------------------------
// UploadDocument (idempotent) with user existence and file existence checks
// -------------------------------------------------------------------------

func (s *kycDocumentService) UploadDocument(ctx context.Context, req *UploadDocumentRequest) (*models.KYCDocument, error) {
	logger := s.logger.With(zap.String("method", "UploadDocument"))

	// Basic validation
	if req.UserID == uuid.Nil {
		return nil, fmt.Errorf("%w: user_id required", kycErrors.ErrInvalidInput)
	}
	if !req.DocumentType.IsValid() {
		return nil, fmt.Errorf("%w: invalid document type", kycErrors.ErrInvalidInput)
	}
	if req.FileKey == "" {
		return nil, fmt.Errorf("%w: file_key required", kycErrors.ErrInvalidInput)
	}

	// Start transaction early – we need it for user check as well
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// ------------------------------------------------------------------
	// 1. CHECK THAT THE USER EXISTS IN THE USERS TABLE
	// ------------------------------------------------------------------
	userExists, err := s.repo.UserExists(ctx, tx, req.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to verify user existence: %w", err)
	}
	if !userExists {
		return nil, fmt.Errorf("%w: user %s does not exist", kycErrors.ErrInvalidInput, req.UserID)
	}

	// ------------------------------------------------------------------
	// 2. CHECK THAT THE FILE ACTUALLY EXISTS IN STORAGE
	// ------------------------------------------------------------------
	fileExists, err := s.storage.FileExists(ctx, req.FileKey)
	if err != nil {
		return nil, fmt.Errorf("file existence check failed: %w", err)
	}
	if !fileExists {
		return nil, fmt.Errorf("%w: file not found at key %s", kycErrors.ErrMissingRequiredDoc, req.FileKey)
	}

	// ------------------------------------------------------------------
	// 3. PROCEED WITH IDEMPOTENT METADATA CREATION
	// ------------------------------------------------------------------
	idempKey := fmt.Sprintf("kyc-upload-%s-%s", req.UserID.String(), req.DocumentType)
	var cached *models.KYCDocument
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached document")
		return cached, nil
	}

	doc := &models.KYCDocument{
		ID:           uuid.New(),
		UserID:       req.UserID,
		DocumentType: req.DocumentType,
		FileKey:      req.FileKey,
		FileMetadata: req.FileMetadata,
		UploadStatus: enums.DocumentStatusUploaded,
		ExpiresAt:    req.ExpiresAt,
	}
	if err := s.repo.Upsert(ctx, tx, doc); err != nil {
		return nil, fmt.Errorf("upsert document: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "kyc", "upload_document", "kyc_document",
			&doc.ID, "user", &req.UploadedBy, nil, nil, map[string]interface{}{
				"user_id":       doc.UserID.String(),
				"document_type": string(doc.DocumentType),
				"file_key":      doc.FileKey,
			})
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, doc); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	return doc, nil
}

// -------------------------------------------------------------------------
// GetDocumentByID
// -------------------------------------------------------------------------

func (s *kycDocumentService) GetDocumentByID(ctx context.Context, docID uuid.UUID) (*models.KYCDocument, error) {
	db := s.pgClient.DB
	return s.repo.GetByID(ctx, db, docID)
}

// -------------------------------------------------------------------------
// GetDocumentsByUser
// -------------------------------------------------------------------------

func (s *kycDocumentService) GetDocumentsByUser(ctx context.Context, userID uuid.UUID) ([]*models.KYCDocument, error) {
	db := s.pgClient.DB
	return s.repo.GetByUser(ctx, db, userID)
}

// -------------------------------------------------------------------------
// ListDocuments
// -------------------------------------------------------------------------

func (s *kycDocumentService) ListDocuments(ctx context.Context, filter ListDocumentsFilter, p Pagination, srt Sort) ([]*models.KYCDocument, int64, error) {
	db := s.pgClient.DB
	repoFilter := repository.KYCDocumentFilter{
		UserID:       filter.UserID,
		DocumentType: filter.DocumentType,
		Statuses:     filter.Statuses,
		FromDate:     filter.FromDate,
		ToDate:       filter.ToDate,
		SearchQuery:  filter.SearchQuery,
	}
	return s.repo.List(ctx, db, repoFilter,
		repository.Pagination{Limit: p.Limit, Offset: p.Offset},
		repository.Sort{Field: srt.Field, Direction: srt.Direction})
}

// -------------------------------------------------------------------------
// VerifyDocument (admin action, idempotent)
// -------------------------------------------------------------------------

func (s *kycDocumentService) VerifyDocument(ctx context.Context, req *VerifyDocumentRequest) error {
	logger := s.logger.With(zap.String("method", "VerifyDocument"))
	if req.DocumentID == uuid.Nil {
		return fmt.Errorf("%w: document_id required", kycErrors.ErrInvalidInput)
	}
	if req.VerifiedBy == uuid.Nil {
		return fmt.Errorf("%w: verified_by required", kycErrors.ErrInvalidInput)
	}
	if req.Status != enums.DocumentStatusVerified && req.Status != enums.DocumentStatusRejected {
		return fmt.Errorf("%w: status must be verified or rejected", kycErrors.ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := fmt.Sprintf("kyc-verify-%s", req.DocumentID.String())
	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – already verified/rejected")
		return nil
	}

	doc, err := s.repo.GetByID(ctx, tx, req.DocumentID)
	if err != nil {
		return err
	}
	oldStatus := doc.UploadStatus

	if req.Status == enums.DocumentStatusVerified {
		err = s.repo.MarkVerified(ctx, tx, req.DocumentID, req.VerifiedBy, req.Notes)
	} else {
		err = s.repo.MarkRejected(ctx, tx, req.DocumentID, req.VerifiedBy, req.Notes)
	}
	if err != nil {
		return err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "kyc", "verify_document", "kyc_document",
			&req.DocumentID, "admin", &req.VerifiedBy, nil, nil, map[string]interface{}{
				"old_status": string(oldStatus),
				"new_status": string(req.Status),
				"notes":      req.Notes,
			})
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

// -------------------------------------------------------------------------
// DeleteDocument (admin action, idempotent)
// -------------------------------------------------------------------------

func (s *kycDocumentService) DeleteDocument(ctx context.Context, docID uuid.UUID, deletedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteDocument"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := fmt.Sprintf("kyc-delete-%s", docID.String())
	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – already deleted")
		return nil
	}

	if err := s.repo.Delete(ctx, tx, docID); err != nil {
		return err
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "kyc", "delete_document", "kyc_document",
			&docID, "admin", &deletedBy, nil, nil, nil)
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

// -------------------------------------------------------------------------
// GetPendingDocuments
// -------------------------------------------------------------------------

func (s *kycDocumentService) GetPendingDocuments(ctx context.Context) ([]*models.KYCDocument, error) {
	db := s.pgClient.DB
	return s.repo.GetPendingDocuments(ctx, db)
}

// -------------------------------------------------------------------------
// GetExpiredDocuments
// -------------------------------------------------------------------------

func (s *kycDocumentService) GetExpiredDocuments(ctx context.Context) ([]*models.KYCDocument, error) {
	db := s.pgClient.DB
	return s.repo.GetExpiredDocuments(ctx, db)
}
