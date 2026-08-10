package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	kycErrors "auth-service/internal/kyc/errors" // ✅ correct import alias
	"auth-service/internal/kyc/models"           // ✅ correct model package
	"auth-service/internal/kyc/models/enums"     // ✅ correct enums package

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// -------------------------------------------------------------------------
// KYCDocumentRepository Interface & Filter
// -------------------------------------------------------------------------

type KYCDocumentRepository interface {
	// CRUD
	Create(ctx context.Context, db DBTX, doc *models.KYCDocument) error
	GetByID(ctx context.Context, db DBTX, docID uuid.UUID) (*models.KYCDocument, error)
	GetByUserAndType(ctx context.Context, db DBTX, userID uuid.UUID, docType enums.DocumentType) (*models.KYCDocument, error)
	Update(ctx context.Context, db DBTX, doc *models.KYCDocument) error
	Delete(ctx context.Context, db DBTX, docID uuid.UUID) error
	Upsert(ctx context.Context, db DBTX, doc *models.KYCDocument) error // for idempotent creation

	// Querying
	List(ctx context.Context, db DBTX, filter KYCDocumentFilter, p Pagination, s Sort) ([]*models.KYCDocument, int64, error)
	GetByUser(ctx context.Context, db DBTX, userID uuid.UUID) ([]*models.KYCDocument, error)
	GetPendingDocuments(ctx context.Context, db DBTX) ([]*models.KYCDocument, error) // for admin verification
	GetExpiredDocuments(ctx context.Context, db DBTX) ([]*models.KYCDocument, error) // for expiry job

	// Status updates
	UpdateStatus(ctx context.Context, db DBTX, docID uuid.UUID, status enums.DocumentUploadStatus, verifiedBy *uuid.UUID, notes *string) error
	MarkVerified(ctx context.Context, db DBTX, docID uuid.UUID, verifiedBy uuid.UUID, notes string) error
	MarkRejected(ctx context.Context, db DBTX, docID uuid.UUID, verifiedBy uuid.UUID, notes string) error
	UserExists(ctx context.Context, db DBTX, userID uuid.UUID) (bool, error)

	// Existence
	Exists(ctx context.Context, db DBTX, docID uuid.UUID) (bool, error)
	ExistsForUser(ctx context.Context, db DBTX, userID uuid.UUID, docType enums.DocumentType) (bool, error)
}

type KYCDocumentFilter struct {
	UserID       *uuid.UUID
	DocumentType *enums.DocumentType
	Statuses     []enums.DocumentUploadStatus
	FromDate     *time.Time
	ToDate       *time.Time
	SearchQuery  *string // searches file metadata fields
}

// -------------------------------------------------------------------------
// Repository implementation
// -------------------------------------------------------------------------

type kycDocumentRepository struct {
	logger *zap.Logger
}

func NewKYCDocumentRepository(logger *zap.Logger) KYCDocumentRepository {
	return &kycDocumentRepository{
		logger: logger.Named("kyc_document_repo"),
	}
}

// Helpers
func (r *kycDocumentRepository) scanKYCDocument(s scanner) (*models.KYCDocument, error) {
	var doc models.KYCDocument
	var verifiedBy uuid.NullUUID
	var verifiedAt sql.NullTime
	var expiresAt sql.NullTime
	var notes sql.NullString

	err := s.Scan(
		&doc.ID,
		&doc.UserID,
		&doc.DocumentType,
		&doc.FileKey,
		&doc.FileMetadata,
		&doc.UploadStatus,
		&notes,
		&verifiedBy,
		&verifiedAt,
		&expiresAt,
		&doc.CreatedAt,
		&doc.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, kycErrors.ErrNotFound // ✅ use kycErrors
		}
		return nil, fmt.Errorf("scan KYCDocument: %w", err)
	}
	if notes.Valid {
		doc.VerificationNotes = &notes.String
	}
	if verifiedBy.Valid {
		doc.VerifiedBy = &verifiedBy.UUID
	}
	if verifiedAt.Valid {
		doc.VerifiedAt = &verifiedAt.Time
	}
	if expiresAt.Valid {
		doc.ExpiresAt = &expiresAt.Time
	}
	return &doc, nil
}

func (r *kycDocumentRepository) buildFilter(filter KYCDocumentFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.UserID != nil {
		conds = append(conds, fmt.Sprintf("user_id = $%d", idx))
		args = append(args, *filter.UserID)
		idx++
	}
	if filter.DocumentType != nil {
		conds = append(conds, fmt.Sprintf("document_type = $%d", idx))
		args = append(args, string(*filter.DocumentType))
		idx++
	}
	if len(filter.Statuses) > 0 {
		placeholders := make([]string, len(filter.Statuses))
		for i, st := range filter.Statuses {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, string(st))
			idx++
		}
		conds = append(conds, fmt.Sprintf("upload_status IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.FromDate != nil {
		conds = append(conds, fmt.Sprintf("created_at >= $%d", idx))
		args = append(args, *filter.FromDate)
		idx++
	}
	if filter.ToDate != nil {
		conds = append(conds, fmt.Sprintf("created_at <= $%d", idx))
		args = append(args, *filter.ToDate)
		idx++
	}
	// Search query: search in FileMetadata->>'original_name' or file_key
	if filter.SearchQuery != nil && *filter.SearchQuery != "" {
		pattern := "%" + *filter.SearchQuery + "%"
		conds = append(conds, fmt.Sprintf("(file_key ILIKE $%d OR file_metadata->>'original_name' ILIKE $%d)", idx, idx+1))
		args = append(args, pattern, pattern)
		idx += 2
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (r *kycDocumentRepository) Create(ctx context.Context, db DBTX, doc *models.KYCDocument) error {
	query := `
		INSERT INTO kyc_documents (
			id, user_id, document_type, file_key, file_metadata,
			upload_status, verification_notes, verified_by, verified_at,
			expires_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW())
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		doc.ID,
		doc.UserID,
		doc.DocumentType,
		doc.FileKey,
		doc.FileMetadata,
		doc.UploadStatus,
		doc.VerificationNotes,
		doc.VerifiedBy,
		doc.VerifiedAt,
		doc.ExpiresAt,
	).Scan(&doc.CreatedAt, &doc.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create KYC document", zap.Error(err))
		return fmt.Errorf("create KYC document: %w", err)
	}
	return nil
}

func (r *kycDocumentRepository) GetByID(ctx context.Context, db DBTX, docID uuid.UUID) (*models.KYCDocument, error) {
	query := `
		SELECT id, user_id, document_type, file_key, file_metadata,
			upload_status, verification_notes, verified_by, verified_at,
			expires_at, created_at, updated_at
		FROM kyc_documents
		WHERE id = $1
	`
	row := db.QueryRowContext(ctx, query, docID)
	return r.scanKYCDocument(row)
}

func (r *kycDocumentRepository) GetByUserAndType(ctx context.Context, db DBTX, userID uuid.UUID, docType enums.DocumentType) (*models.KYCDocument, error) {
	query := `
		SELECT id, user_id, document_type, file_key, file_metadata,
			upload_status, verification_notes, verified_by, verified_at,
			expires_at, created_at, updated_at
		FROM kyc_documents
		WHERE user_id = $1 AND document_type = $2
		ORDER BY created_at DESC
		LIMIT 1
	`
	row := db.QueryRowContext(ctx, query, userID, docType)
	return r.scanKYCDocument(row)
}

func (r *kycDocumentRepository) Update(ctx context.Context, db DBTX, doc *models.KYCDocument) error {
	query := `
		UPDATE kyc_documents SET
			user_id = $2,
			document_type = $3,
			file_key = $4,
			file_metadata = $5,
			upload_status = $6,
			verification_notes = $7,
			verified_by = $8,
			verified_at = $9,
			expires_at = $10,
			updated_at = NOW()
		WHERE id = $1
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		doc.ID,
		doc.UserID,
		doc.DocumentType,
		doc.FileKey,
		doc.FileMetadata,
		doc.UploadStatus,
		doc.VerificationNotes,
		doc.VerifiedBy,
		doc.VerifiedAt,
		doc.ExpiresAt,
	).Scan(&doc.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return kycErrors.ErrNotFound
		}
		return fmt.Errorf("update KYC document: %w", err)
	}
	return nil
}

func (r *kycDocumentRepository) Delete(ctx context.Context, db DBTX, docID uuid.UUID) error {
	query := `DELETE FROM kyc_documents WHERE id = $1`
	result, err := db.ExecContext(ctx, query, docID)
	if err != nil {
		return fmt.Errorf("delete KYC document: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return kycErrors.ErrNotFound
	}
	return nil
}

func (r *kycDocumentRepository) Upsert(ctx context.Context, db DBTX, doc *models.KYCDocument) error {
	query := `
		INSERT INTO kyc_documents (
			id, user_id, document_type, file_key, file_metadata,
			upload_status, verification_notes, verified_by, verified_at,
			expires_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW())
		ON CONFLICT (id) DO UPDATE SET
			user_id = EXCLUDED.user_id,
			document_type = EXCLUDED.document_type,
			file_key = EXCLUDED.file_key,
			file_metadata = EXCLUDED.file_metadata,
			upload_status = EXCLUDED.upload_status,
			verification_notes = EXCLUDED.verification_notes,
			verified_by = EXCLUDED.verified_by,
			verified_at = EXCLUDED.verified_at,
			expires_at = EXCLUDED.expires_at,
			updated_at = NOW()
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		doc.ID,
		doc.UserID,
		doc.DocumentType,
		doc.FileKey,
		doc.FileMetadata,
		doc.UploadStatus,
		doc.VerificationNotes,
		doc.VerifiedBy,
		doc.VerifiedAt,
		doc.ExpiresAt,
	).Scan(&doc.CreatedAt, &doc.UpdatedAt)
	if err != nil {
		return fmt.Errorf("upsert KYC document: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Querying
// -------------------------------------------------------------------------

func (r *kycDocumentRepository) List(ctx context.Context, db DBTX, filter KYCDocumentFilter, p Pagination, s Sort) ([]*models.KYCDocument, int64, error) {
	where, args := r.buildFilter(filter)
	if where == "" {
		// At least one filter recommended to avoid full table scan; but we allow if needed.
		// We'll keep empty where.
	}
	allowedSort := map[string]bool{
		"created_at": true,
		"updated_at": true,
		"expires_at": true,
		"user_id":    true,
	}
	orderBy, err := validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY created_at DESC"
	}
	limit, offset := validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM kyc_documents %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count KYC documents: %w", err)
	}
	if total == 0 {
		return []*models.KYCDocument{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT id, user_id, document_type, file_key, file_metadata,
			upload_status, verification_notes, verified_by, verified_at,
			expires_at, created_at, updated_at
		FROM kyc_documents
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list KYC documents: %w", err)
	}
	defer rows.Close()

	var result []*models.KYCDocument
	for rows.Next() {
		doc, err := r.scanKYCDocument(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, doc)
	}
	return result, total, rows.Err()
}

func (r *kycDocumentRepository) GetByUser(ctx context.Context, db DBTX, userID uuid.UUID) ([]*models.KYCDocument, error) {
	query := `
		SELECT id, user_id, document_type, file_key, file_metadata,
			upload_status, verification_notes, verified_by, verified_at,
			expires_at, created_at, updated_at
		FROM kyc_documents
		WHERE user_id = $1
		ORDER BY created_at DESC
	`
	rows, err := db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("get by user: %w", err)
	}
	defer rows.Close()
	var docs []*models.KYCDocument
	for rows.Next() {
		doc, err := r.scanKYCDocument(rows)
		if err != nil {
			return nil, err
		}
		docs = append(docs, doc)
	}
	return docs, rows.Err()
}

func (r *kycDocumentRepository) GetPendingDocuments(ctx context.Context, db DBTX) ([]*models.KYCDocument, error) {
	query := `
		SELECT id, user_id, document_type, file_key, file_metadata,
			upload_status, verification_notes, verified_by, verified_at,
			expires_at, created_at, updated_at
		FROM kyc_documents
		WHERE upload_status = 'uploaded'
		ORDER BY created_at ASC
	`
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("get pending docs: %w", err)
	}
	defer rows.Close()
	var docs []*models.KYCDocument
	for rows.Next() {
		doc, err := r.scanKYCDocument(rows)
		if err != nil {
			return nil, err
		}
		docs = append(docs, doc)
	}
	return docs, rows.Err()
}

func (r *kycDocumentRepository) GetExpiredDocuments(ctx context.Context, db DBTX) ([]*models.KYCDocument, error) {
	query := `
		SELECT id, user_id, document_type, file_key, file_metadata,
			upload_status, verification_notes, verified_by, verified_at,
			expires_at, created_at, updated_at
		FROM kyc_documents
		WHERE expires_at IS NOT NULL AND expires_at < NOW()
	`
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("get expired docs: %w", err)
	}
	defer rows.Close()
	var docs []*models.KYCDocument
	for rows.Next() {
		doc, err := r.scanKYCDocument(rows)
		if err != nil {
			return nil, err
		}
		docs = append(docs, doc)
	}
	return docs, rows.Err()
}

// -------------------------------------------------------------------------
// Status updates
// -------------------------------------------------------------------------

func (r *kycDocumentRepository) UpdateStatus(ctx context.Context, db DBTX, docID uuid.UUID, status enums.DocumentUploadStatus, verifiedBy *uuid.UUID, notes *string) error {
	query := `
		UPDATE kyc_documents
		SET upload_status = $2, verified_by = $3, verification_notes = $4,
			verified_at = CASE WHEN $2 IN ('verified', 'rejected') THEN NOW() ELSE verified_at END,
			updated_at = NOW()
		WHERE id = $1
	`
	result, err := db.ExecContext(ctx, query, docID, status, verifiedBy, notes)
	if err != nil {
		return fmt.Errorf("update status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return kycErrors.ErrNotFound
	}
	return nil
}

func (r *kycDocumentRepository) MarkVerified(ctx context.Context, db DBTX, docID uuid.UUID, verifiedBy uuid.UUID, notes string) error {
	return r.UpdateStatus(ctx, db, docID, enums.DocumentStatusVerified, &verifiedBy, &notes)
}

func (r *kycDocumentRepository) MarkRejected(ctx context.Context, db DBTX, docID uuid.UUID, verifiedBy uuid.UUID, notes string) error {
	return r.UpdateStatus(ctx, db, docID, enums.DocumentStatusRejected, &verifiedBy, &notes)
}

// -------------------------------------------------------------------------
// Existence
// -------------------------------------------------------------------------

func (r *kycDocumentRepository) Exists(ctx context.Context, db DBTX, docID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM kyc_documents WHERE id = $1)`
	err := db.QueryRowContext(ctx, query, docID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists: %w", err)
	}
	return exists, nil
}

func (r *kycDocumentRepository) ExistsForUser(ctx context.Context, db DBTX, userID uuid.UUID, docType enums.DocumentType) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM kyc_documents WHERE user_id = $1 AND document_type = $2)`
	err := db.QueryRowContext(ctx, query, userID, docType).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists for user: %w", err)
	}
	return exists, nil
}
func (r *kycDocumentRepository) UserExists(ctx context.Context, db DBTX, userID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE user_id = $1)`
	err := db.QueryRowContext(ctx, query, userID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check user existence: %w", err)
	}
	return exists, nil
}
