package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
)

// LibraryService defines the high-level operations for the library domain.
type LibraryService interface {
	// Category operations
	CreateCategory(ctx context.Context, req CreateCategoryRequest, idempotencyKey string) (*models.LibraryCategory, error)
	GetCategoryByID(ctx context.Context, id uuid.UUID) (*models.LibraryCategory, error)
	ListCategories(ctx context.Context, filter repository.LibraryCategoryFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.LibraryCategory, int64, error)
	UpdateCategory(ctx context.Context, req UpdateCategoryRequest) (*models.LibraryCategory, error)
	DeleteCategory(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error

	// Book operations
	CreateBook(ctx context.Context, req CreateBookRequest, idempotencyKey string) (*models.LibraryBook, error)
	GetBookByID(ctx context.Context, id uuid.UUID) (*models.LibraryBook, error)
	GetBookByISBN(ctx context.Context, companyID uuid.UUID, isbn string) (*models.LibraryBook, error)
	ListBooks(ctx context.Context, filter repository.LibraryBookFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.LibraryBook, int64, error)
	UpdateBook(ctx context.Context, req UpdateBookRequest) (*models.LibraryBook, error)
	DeleteBook(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error

	// Copy operations
	CreateCopy(ctx context.Context, req CreateCopyRequest, idempotencyKey string) (*models.LibraryBookCopy, error)
	GetCopyByID(ctx context.Context, id uuid.UUID) (*models.LibraryBookCopy, error)
	GetCopyByAccessionNo(ctx context.Context, accessionNo string) (*models.LibraryBookCopy, error)
	ListCopies(ctx context.Context, filter repository.LibraryCopyFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.LibraryBookCopy, int64, error)
	UpdateCopy(ctx context.Context, req UpdateCopyRequest) (*models.LibraryBookCopy, error)
	DeleteCopy(ctx context.Context, id uuid.UUID) error

	// Issue/Return operations
	IssueBook(ctx context.Context, req IssueBookRequest, idempotencyKey string) (*models.LibraryIssue, error)
	GetIssueByID(ctx context.Context, id uuid.UUID) (*models.LibraryIssue, error)
	ListIssues(ctx context.Context, filter repository.LibraryIssueFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.LibraryIssue, int64, error)
	ReturnBook(ctx context.Context, req ReturnBookRequest) (*models.LibraryReturn, error)

	// Fine operations
	CreateFine(ctx context.Context, req CreateFineRequest) (*models.LibraryFine, error)
	UpdateFinePayment(ctx context.Context, req UpdateFinePaymentRequest) error
	ListFines(ctx context.Context, studentID *uuid.UUID, paid *bool) ([]*models.LibraryFine, error)

	// Utility
	GetAvailableCopies(ctx context.Context, bookID uuid.UUID) (int, error)
	HasOverdueIssues(ctx context.Context, studentID uuid.UUID) (bool, error)
}

// ----------------------------------------------------------------------------
// Request/Response types
// ----------------------------------------------------------------------------

type CreateCategoryRequest struct {
	CompanyID    uuid.UUID
	CategoryName string
	Description  string
	CreatedBy    *uuid.UUID
	UpdatedBy    *uuid.UUID
}

type UpdateCategoryRequest struct {
	CategoryID   uuid.UUID
	CategoryName string
	Description  string
	UpdatedBy    *uuid.UUID
}

type CreateBookRequest struct {
	CompanyID       uuid.UUID
	CategoryID      *uuid.UUID
	Title           string
	Author          string
	ISBN            string
	Publisher       string
	Edition         string
	Language        string
	Pages           int
	PublicationYear int
	Description     string
	CreatedBy       *uuid.UUID
	UpdatedBy       *uuid.UUID
}

type UpdateBookRequest struct {
	BookID          uuid.UUID
	CategoryID      *uuid.UUID
	Title           string
	Author          string
	ISBN            string
	Publisher       string
	Edition         string
	Language        string
	Pages           int
	PublicationYear int
	Description     string
	UpdatedBy       *uuid.UUID
}

type CreateCopyRequest struct {
	BookID        uuid.UUID
	AccessionNo   string
	Status        models.CopyStatus
	PurchaseDate  *time.Time
	Cost          *float64
	ShelfLocation string
	CreatedBy     *uuid.UUID
}

type UpdateCopyRequest struct {
	CopyID        uuid.UUID
	Status        models.CopyStatus
	PurchaseDate  *time.Time
	Cost          *float64
	ShelfLocation string
}

type IssueBookRequest struct {
	CopyID    uuid.UUID
	StudentID uuid.UUID
	IssueDate time.Time
	DueDate   time.Time
	IssuedBy  *uuid.UUID
	CreatedBy *uuid.UUID
}

type ReturnBookRequest struct {
	IssueID    uuid.UUID
	ReturnDate time.Time
	FineAmount float64
	Remarks    string
	ReceivedBy *uuid.UUID
}

type CreateFineRequest struct {
	IssueID    uuid.UUID
	FineAmount float64
	CreatedBy  *uuid.UUID
}

type UpdateFinePaymentRequest struct {
	FineID      uuid.UUID
	Paid        bool
	PaidDate    *time.Time
	PaymentMode string
}

// ----------------------------------------------------------------------------
// Service implementation
// ----------------------------------------------------------------------------

type libraryService struct {
	repo             repository.LibraryRepository
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	eventPublisher   EventPublisher
	outboxStore      OutboxStore
	auditLogger      AuditLogger
	idempotencyStore IdempotencyStore
	notifSvc         NotificationService
	studentSvc       StudentService // new field

}

// NewLibraryService creates a new library service with its dependencies.
func NewLibraryService(
	repo repository.LibraryRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	eventPublisher EventPublisher,
	outboxStore OutboxStore,
	auditLogger AuditLogger,
	idempotencyStore IdempotencyStore,
	notifSvc NotificationService,
	studentSvc StudentService, // new parameter

) LibraryService {
	return &libraryService{
		repo:             repo,
		pgClient:         pgClient,
		logger:           logger.Named("library_service"),
		eventPublisher:   eventPublisher,
		outboxStore:      outboxStore,
		auditLogger:      auditLogger,
		idempotencyStore: idempotencyStore,
		notifSvc:         notifSvc,
		studentSvc:       studentSvc,
	}
}

// ----------------------------------------------------------------------------
// Category methods
// ----------------------------------------------------------------------------

func (s *libraryService) CreateCategory(ctx context.Context, req CreateCategoryRequest, idempotencyKey string) (*models.LibraryCategory, error) {
	logger := s.logger.With(
		zap.String("method", "CreateCategory"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("name", req.CategoryName),
		zap.String("idempotency_key", idempotencyKey),
	)

	s.sanitizeCategory(&req)
	if err := s.validateCategoryCreate(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		exists, err := s.idempotencyStore.Exists(ctx, tx, idempotencyKey)
		if err != nil {
			return nil, fmt.Errorf("idempotency check: %w", err)
		}
		if exists {
			var cat models.LibraryCategory
			if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cat); err != nil {
				return nil, fmt.Errorf("failed to retrieve idempotent response: %w", err)
			}
			logger.Info("returning idempotent response")
			return &cat, nil
		}
	}

	category := &models.LibraryCategory{
		CompanyID:    req.CompanyID,
		CategoryName: req.CategoryName,
		Description:  req.Description,
		CreatedBy:    req.CreatedBy,
		UpdatedBy:    req.UpdatedBy,
	}

	if err := s.repo.CreateCategory(ctx, tx, category); err != nil {
		return nil, err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, category); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
			return nil, fmt.Errorf("failed to store idempotency key: %w", err)
		}
	}

	if err := s.auditLogger.Log(ctx, tx, "CREATE", category.CategoryID, nil, category, req.CreatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventLibraryCategoryCreated), category); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("library category created", zap.String("id", category.CategoryID.String()))
	return category, nil
}

func (s *libraryService) GetCategoryByID(ctx context.Context, id uuid.UUID) (*models.LibraryCategory, error) {
	cat, err := s.repo.GetCategoryByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if cat == nil {
		return nil, fmt.Errorf("%w: category %s", ErrNotFound, id)
	}
	return cat, nil
}

func (s *libraryService) ListCategories(ctx context.Context, filter repository.LibraryCategoryFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.LibraryCategory, int64, error) {
	categories, err := s.repo.ListCategories(ctx, s.pgClient.DB, filter, pagination, sort)
	if err != nil {
		return nil, 0, err
	}
	total, err := s.repo.CountCategories(ctx, s.pgClient.DB, filter)
	if err != nil {
		return nil, 0, err
	}
	return categories, total, nil
}

func (s *libraryService) UpdateCategory(ctx context.Context, req UpdateCategoryRequest) (*models.LibraryCategory, error) {
	logger := s.logger.With(
		zap.String("method", "UpdateCategory"),
		zap.String("category_id", req.CategoryID.String()),
	)

	s.sanitizeCategoryUpdate(&req)
	if err := s.validateCategoryUpdate(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	category, err := s.repo.GetCategoryByID(ctx, tx, req.CategoryID)
	if err != nil {
		return nil, err
	}
	if category == nil {
		return nil, fmt.Errorf("%w: category %s", ErrNotFound, req.CategoryID)
	}

	old := *category
	category.CategoryName = req.CategoryName
	category.Description = req.Description
	category.UpdatedBy = req.UpdatedBy

	if err := s.repo.UpdateCategory(ctx, tx, category); err != nil {
		return nil, err
	}

	if err := s.auditLogger.Log(ctx, tx, "UPDATE", category.CategoryID, old, category, req.UpdatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventLibraryCategoryUpdated), map[string]interface{}{
		"old": old,
		"new": category,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("library category updated")
	return category, nil
}

func (s *libraryService) DeleteCategory(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "DeleteCategory"),
		zap.String("category_id", id.String()),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.DeleteCategory(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	if err := s.auditLogger.Log(ctx, tx, "DELETE", id, nil, nil, deletedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventLibraryCategoryDeleted), map[string]interface{}{
		"category_id": id,
		"deleted_by":  deletedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("library category deleted")
	return nil
}

// ----------------------------------------------------------------------------
// Book methods
// ----------------------------------------------------------------------------

func (s *libraryService) CreateBook(ctx context.Context, req CreateBookRequest, idempotencyKey string) (*models.LibraryBook, error) {
	logger := s.logger.With(
		zap.String("method", "CreateBook"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("title", req.Title),
		zap.String("idempotency_key", idempotencyKey),
	)

	s.sanitizeBook(&req)
	if err := s.validateBookCreate(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		exists, err := s.idempotencyStore.Exists(ctx, tx, idempotencyKey)
		if err != nil {
			return nil, fmt.Errorf("idempotency check: %w", err)
		}
		if exists {
			var book models.LibraryBook
			if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &book); err != nil {
				return nil, fmt.Errorf("failed to retrieve idempotent response: %w", err)
			}
			logger.Info("returning idempotent response")
			return &book, nil
		}
	}

	book := &models.LibraryBook{
		CompanyID:       req.CompanyID,
		CategoryID:      req.CategoryID,
		Title:           req.Title,
		Author:          req.Author,
		ISBN:            req.ISBN,
		Publisher:       req.Publisher,
		Edition:         req.Edition,
		Language:        req.Language,
		Pages:           req.Pages,
		PublicationYear: req.PublicationYear,
		Description:     req.Description,
		CreatedBy:       req.CreatedBy,
		UpdatedBy:       req.UpdatedBy,
	}

	if err := s.repo.CreateBook(ctx, tx, book); err != nil {
		return nil, err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, book); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
			return nil, fmt.Errorf("failed to store idempotency key: %w", err)
		}
	}

	if err := s.auditLogger.Log(ctx, tx, "CREATE", book.BookID, nil, book, req.CreatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventLibraryBookCreated), book); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("library book created", zap.String("id", book.BookID.String()))
	return book, nil
}

func (s *libraryService) GetBookByID(ctx context.Context, id uuid.UUID) (*models.LibraryBook, error) {
	book, err := s.repo.GetBookByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if book == nil {
		return nil, fmt.Errorf("%w: book %s", ErrNotFound, id)
	}
	return book, nil
}

func (s *libraryService) GetBookByISBN(ctx context.Context, companyID uuid.UUID, isbn string) (*models.LibraryBook, error) {
	book, err := s.repo.GetBookByISBN(ctx, s.pgClient.DB, companyID, isbn)
	if err != nil {
		return nil, err
	}
	if book == nil {
		return nil, fmt.Errorf("%w: book with ISBN %s not found", ErrNotFound, isbn)
	}
	return book, nil
}

func (s *libraryService) ListBooks(ctx context.Context, filter repository.LibraryBookFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.LibraryBook, int64, error) {
	books, err := s.repo.ListBooks(ctx, s.pgClient.DB, filter, pagination, sort)
	if err != nil {
		return nil, 0, err
	}
	total, err := s.repo.CountBooks(ctx, s.pgClient.DB, filter)
	if err != nil {
		return nil, 0, err
	}
	return books, total, nil
}

func (s *libraryService) UpdateBook(ctx context.Context, req UpdateBookRequest) (*models.LibraryBook, error) {
	logger := s.logger.With(
		zap.String("method", "UpdateBook"),
		zap.String("book_id", req.BookID.String()),
	)

	s.sanitizeBookUpdate(&req)
	if err := s.validateBookUpdate(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	book, err := s.repo.GetBookByID(ctx, tx, req.BookID)
	if err != nil {
		return nil, err
	}
	if book == nil {
		return nil, fmt.Errorf("%w: book %s", ErrNotFound, req.BookID)
	}

	old := *book
	book.CategoryID = req.CategoryID
	book.Title = req.Title
	book.Author = req.Author
	book.ISBN = req.ISBN
	book.Publisher = req.Publisher
	book.Edition = req.Edition
	book.Language = req.Language
	book.Pages = req.Pages
	book.PublicationYear = req.PublicationYear
	book.Description = req.Description
	book.UpdatedBy = req.UpdatedBy

	if err := s.repo.UpdateBook(ctx, tx, book); err != nil {
		return nil, err
	}

	if err := s.auditLogger.Log(ctx, tx, "UPDATE", book.BookID, old, book, req.UpdatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventLibraryBookUpdated), map[string]interface{}{
		"old": old,
		"new": book,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("library book updated")
	return book, nil
}

func (s *libraryService) DeleteBook(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "DeleteBook"),
		zap.String("book_id", id.String()),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.DeleteBook(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	if err := s.auditLogger.Log(ctx, tx, "DELETE", id, nil, nil, deletedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventLibraryBookDeleted), map[string]interface{}{
		"book_id":    id,
		"deleted_by": deletedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("library book deleted")
	return nil
}

// ----------------------------------------------------------------------------
// Copy methods
// ----------------------------------------------------------------------------

func (s *libraryService) CreateCopy(ctx context.Context, req CreateCopyRequest, idempotencyKey string) (*models.LibraryBookCopy, error) {
	logger := s.logger.With(
		zap.String("method", "CreateCopy"),
		zap.String("book_id", req.BookID.String()),
		zap.String("accession_no", req.AccessionNo),
		zap.String("idempotency_key", idempotencyKey),
	)

	if err := s.validateCopyCreate(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		exists, err := s.idempotencyStore.Exists(ctx, tx, idempotencyKey)
		if err != nil {
			return nil, fmt.Errorf("idempotency check: %w", err)
		}
		if exists {
			var copy models.LibraryBookCopy
			if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &copy); err != nil {
				return nil, fmt.Errorf("failed to retrieve idempotent response: %w", err)
			}
			logger.Info("returning idempotent response")
			return &copy, nil
		}
	}

	copy := &models.LibraryBookCopy{
		BookID:        req.BookID,
		AccessionNo:   req.AccessionNo,
		Status:        req.Status,
		PurchaseDate:  req.PurchaseDate,
		Cost:          req.Cost,
		ShelfLocation: req.ShelfLocation,
		CreatedBy:     req.CreatedBy,
	}

	if err := s.repo.CreateCopy(ctx, tx, copy); err != nil {
		return nil, err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, copy); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
			return nil, fmt.Errorf("failed to store idempotency key: %w", err)
		}
	}

	if err := s.auditLogger.Log(ctx, tx, "CREATE", copy.CopyID, nil, copy, req.CreatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventLibraryCopyCreated), copy); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("library copy created", zap.String("copy_id", copy.CopyID.String()))
	return copy, nil
}

func (s *libraryService) GetCopyByID(ctx context.Context, id uuid.UUID) (*models.LibraryBookCopy, error) {
	copy, err := s.repo.GetCopyByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if copy == nil {
		return nil, fmt.Errorf("%w: copy %s", ErrNotFound, id)
	}
	return copy, nil
}

func (s *libraryService) GetCopyByAccessionNo(ctx context.Context, accessionNo string) (*models.LibraryBookCopy, error) {
	copy, err := s.repo.GetCopyByAccessionNo(ctx, s.pgClient.DB, accessionNo)
	if err != nil {
		return nil, err
	}
	if copy == nil {
		return nil, fmt.Errorf("%w: copy with accession no %s not found", ErrNotFound, accessionNo)
	}
	return copy, nil
}

func (s *libraryService) ListCopies(ctx context.Context, filter repository.LibraryCopyFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.LibraryBookCopy, int64, error) {
	copies, err := s.repo.ListCopies(ctx, s.pgClient.DB, filter, pagination, sort)
	if err != nil {
		return nil, 0, err
	}
	total, err := s.repo.CountCopies(ctx, s.pgClient.DB, filter)
	if err != nil {
		return nil, 0, err
	}
	return copies, total, nil
}

func (s *libraryService) UpdateCopy(ctx context.Context, req UpdateCopyRequest) (*models.LibraryBookCopy, error) {
	logger := s.logger.With(
		zap.String("method", "UpdateCopy"),
		zap.String("copy_id", req.CopyID.String()),
	)

	if err := s.validateCopyUpdate(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	copy, err := s.repo.GetCopyByID(ctx, tx, req.CopyID)
	if err != nil {
		return nil, err
	}
	if copy == nil {
		return nil, fmt.Errorf("%w: copy %s", ErrNotFound, req.CopyID)
	}

	old := *copy
	copy.Status = req.Status
	copy.PurchaseDate = req.PurchaseDate
	copy.Cost = req.Cost
	copy.ShelfLocation = req.ShelfLocation

	if err := s.repo.UpdateCopy(ctx, tx, copy); err != nil {
		return nil, err
	}

	if err := s.auditLogger.Log(ctx, tx, "UPDATE", copy.CopyID, old, copy, nil); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventLibraryCopyUpdated), map[string]interface{}{
		"old": old,
		"new": copy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("library copy updated")
	return copy, nil
}

func (s *libraryService) DeleteCopy(ctx context.Context, id uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "DeleteCopy"),
		zap.String("copy_id", id.String()),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.DeleteCopy(ctx, tx, id); err != nil {
		return err
	}

	if err := s.auditLogger.Log(ctx, tx, "DELETE", id, nil, nil, nil); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventLibraryCopyDeleted), map[string]interface{}{
		"copy_id": id,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("library copy deleted")
	return nil
}

// ----------------------------------------------------------------------------
// Issue/Return methods
// ----------------------------------------------------------------------------

func (s *libraryService) IssueBook(ctx context.Context, req IssueBookRequest, idempotencyKey string) (*models.LibraryIssue, error) {
	logger := s.logger.With(
		zap.String("method", "IssueBook"),
		zap.String("copy_id", req.CopyID.String()),
		zap.String("student_id", req.StudentID.String()),
		zap.String("idempotency_key", idempotencyKey),
	)

	if err := s.validateIssue(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		exists, err := s.idempotencyStore.Exists(ctx, tx, idempotencyKey)
		if err != nil {
			return nil, fmt.Errorf("idempotency check: %w", err)
		}
		if exists {
			var issue models.LibraryIssue
			if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &issue); err != nil {
				return nil, fmt.Errorf("failed to retrieve idempotent response: %w", err)
			}
			logger.Info("returning idempotent response")
			return &issue, nil
		}
	}

	// Check if copy is available
	copy, err := s.repo.GetCopyByID(ctx, tx, req.CopyID)
	if err != nil {
		return nil, err
	}
	if copy == nil {
		return nil, fmt.Errorf("%w: copy %s", ErrNotFound, req.CopyID)
	}
	if copy.Status != models.CopyStatusAvailable {
		return nil, fmt.Errorf("%w: copy is %s", ErrInvalidInput, copy.Status)
	}

	// Check if student has overdue issues
	overdue, err := s.repo.HasOverdueIssues(ctx, tx, req.StudentID)
	if err != nil {
		return nil, err
	}
	if overdue {
		return nil, fmt.Errorf("%w: student has overdue books", ErrInvalidInput)
	}

	issue := &models.LibraryIssue{
		CopyID:    req.CopyID,
		StudentID: req.StudentID,
		IssueDate: req.IssueDate,
		DueDate:   req.DueDate,
		Status:    models.IssueStatusIssued,
		IssuedBy:  req.IssuedBy,
		CreatedBy: req.CreatedBy,
	}

	if err := s.repo.IssueBook(ctx, tx, issue); err != nil {
		return nil, err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, issue); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
			return nil, fmt.Errorf("failed to store idempotency key: %w", err)
		}
	}

	if err := s.auditLogger.Log(ctx, tx, "ISSUE", issue.IssueID, nil, issue, req.CreatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventLibraryBookIssued), issue); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Send notification
	if s.notifSvc != nil {
		student, err := s.getStudent(ctx, req.StudentID) // helper method
		if err == nil && student != nil {
			title := "Book Issued"
			message := fmt.Sprintf("You have issued a book. Due date: %s. Please return on time.", req.DueDate.Format("2006-01-02"))
			targets := []NotificationTargetInput{
				{TargetType: models.TargetStudent, TargetEntityID: req.StudentID},
			}
			notifReq := CreateNotificationRequest{
				CompanyID: student.CompanyID,
				Title:     title,
				Message:   message,
				Type:      models.NotificationTypeInfo,
				Priority:  models.PriorityNormal,
				Targets:   targets,
				CreatedBy: req.IssuedBy,
			}
			_, _ = s.notifSvc.Create(ctx, notifReq, "")
		}
	}

	logger.Info("book issued", zap.String("issue_id", issue.IssueID.String()))
	return issue, nil
}

func (s *libraryService) GetIssueByID(ctx context.Context, id uuid.UUID) (*models.LibraryIssue, error) {
	issue, err := s.repo.GetIssueByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if issue == nil {
		return nil, fmt.Errorf("%w: issue %s", ErrNotFound, id)
	}
	return issue, nil
}

func (s *libraryService) ListIssues(ctx context.Context, filter repository.LibraryIssueFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.LibraryIssue, int64, error) {
	issues, err := s.repo.ListIssues(ctx, s.pgClient.DB, filter, pagination, sort)
	if err != nil {
		return nil, 0, err
	}
	total, err := s.repo.CountIssues(ctx, s.pgClient.DB, filter)
	if err != nil {
		return nil, 0, err
	}
	return issues, total, nil
}

func (s *libraryService) ReturnBook(ctx context.Context, req ReturnBookRequest) (*models.LibraryReturn, error) {
	logger := s.logger.With(
		zap.String("method", "ReturnBook"),
		zap.String("issue_id", req.IssueID.String()),
	)

	if err := s.validateReturn(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	issue, err := s.repo.GetIssueByID(ctx, tx, req.IssueID)
	if err != nil {
		return nil, err
	}
	if issue == nil {
		return nil, fmt.Errorf("%w: issue %s", ErrNotFound, req.IssueID)
	}
	if issue.Status != models.IssueStatusIssued && issue.Status != models.IssueStatusOverdue {
		return nil, fmt.Errorf("%w: issue already returned or lost", ErrInvalidInput)
	}

	if err := s.repo.ReturnBook(ctx, tx, req.IssueID, req.ReturnDate, req.FineAmount, req.Remarks, req.ReceivedBy); err != nil {
		return nil, err
	}

	returnRecord, err := s.repo.GetReturnByIssueID(ctx, tx, req.IssueID)
	if err != nil {
		return nil, err
	}
	if returnRecord == nil {
		return nil, fmt.Errorf("return record not found after processing")
	}

	if err := s.auditLogger.Log(ctx, tx, "RETURN", req.IssueID, nil, returnRecord, req.ReceivedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventLibraryBookReturned), returnRecord); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if req.FineAmount > 0 {
		if err := s.outboxStore.Store(ctx, tx, string(EventLibraryFinePaid), map[string]interface{}{
			"issue_id":    req.IssueID,
			"fine_amount": req.FineAmount,
			"paid_date":   req.ReturnDate,
		}); err != nil {
			logger.Error("failed to store fine outbox event", zap.Error(err))
			// non-fatal, continue
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Send notification about return
	if s.notifSvc != nil {
		student, err := s.getStudent(ctx, issue.StudentID)
		if err == nil && student != nil {
			title := "Book Returned"
			message := "Thank you for returning the book."
			if req.FineAmount > 0 {
				message = fmt.Sprintf("Book returned with a fine of %.2f.", req.FineAmount)
			}
			targets := []NotificationTargetInput{
				{TargetType: models.TargetStudent, TargetEntityID: issue.StudentID},
			}
			notifReq := CreateNotificationRequest{
				CompanyID: student.CompanyID,
				Title:     title,
				Message:   message,
				Type:      models.NotificationTypeInfo,
				Priority:  models.PriorityNormal,
				Targets:   targets,
				CreatedBy: req.ReceivedBy,
			}
			_, _ = s.notifSvc.Create(ctx, notifReq, "")
		}
	}

	logger.Info("book returned", zap.String("return_id", returnRecord.ReturnID.String()))
	return returnRecord, nil
}

// ----------------------------------------------------------------------------
// Fine methods
// ----------------------------------------------------------------------------

func (s *libraryService) CreateFine(ctx context.Context, req CreateFineRequest) (*models.LibraryFine, error) {
	logger := s.logger.With(
		zap.String("method", "CreateFine"),
		zap.String("issue_id", req.IssueID.String()),
	)

	if err := s.validateFineCreate(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	fine := &models.LibraryFine{
		IssueID:    req.IssueID,
		FineAmount: req.FineAmount,
		Paid:       false,
		CreatedBy:  req.CreatedBy,
	}

	if err := s.repo.CreateFine(ctx, tx, fine); err != nil {
		return nil, err
	}

	if err := s.auditLogger.Log(ctx, tx, "CREATE_FINE", fine.FineID, nil, fine, req.CreatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventLibraryFineCreated), fine); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("fine created", zap.String("fine_id", fine.FineID.String()))
	return fine, nil
}

func (s *libraryService) UpdateFinePayment(ctx context.Context, req UpdateFinePaymentRequest) error {
	logger := s.logger.With(
		zap.String("method", "UpdateFinePayment"),
		zap.String("fine_id", req.FineID.String()),
	)

	if err := s.validateFinePayment(req); err != nil {
		return err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.UpdateFinePayment(ctx, tx, req.FineID, req.Paid, req.PaidDate, req.PaymentMode); err != nil {
		return err
	}

	if err := s.auditLogger.Log(ctx, tx, "UPDATE_FINE", req.FineID, nil, map[string]interface{}{
		"paid":         req.Paid,
		"paid_date":    req.PaidDate,
		"payment_mode": req.PaymentMode,
	}, nil); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventLibraryFinePaid), map[string]interface{}{
		"fine_id":      req.FineID,
		"paid":         req.Paid,
		"paid_date":    req.PaidDate,
		"payment_mode": req.PaymentMode,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("fine payment updated")
	return nil
}

func (s *libraryService) ListFines(ctx context.Context, studentID *uuid.UUID, paid *bool) ([]*models.LibraryFine, error) {
	return s.repo.ListFines(ctx, s.pgClient.DB, studentID, paid)
}

// ----------------------------------------------------------------------------
// Utility methods
// ----------------------------------------------------------------------------

func (s *libraryService) GetAvailableCopies(ctx context.Context, bookID uuid.UUID) (int, error) {
	return s.repo.GetAvailableCopies(ctx, s.pgClient.DB, bookID)
}

func (s *libraryService) HasOverdueIssues(ctx context.Context, studentID uuid.UUID) (bool, error) {
	return s.repo.HasOverdueIssues(ctx, s.pgClient.DB, studentID)
}

// ----------------------------------------------------------------------------
// Helper functions (sanitize, validate, etc.)
// ----------------------------------------------------------------------------

func (s *libraryService) sanitizeCategory(req *CreateCategoryRequest) {
	req.CategoryName = strings.TrimSpace(req.CategoryName)
	req.Description = strings.TrimSpace(req.Description)
}

func (s *libraryService) validateCategoryCreate(req CreateCategoryRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id is required", ErrInvalidInput)
	}
	if req.CategoryName == "" {
		return fmt.Errorf("%w: category_name is required", ErrInvalidInput)
	}
	return nil
}

func (s *libraryService) sanitizeCategoryUpdate(req *UpdateCategoryRequest) {
	req.CategoryName = strings.TrimSpace(req.CategoryName)
	req.Description = strings.TrimSpace(req.Description)
}

func (s *libraryService) validateCategoryUpdate(req UpdateCategoryRequest) error {
	if req.CategoryID == uuid.Nil {
		return fmt.Errorf("%w: category_id is required", ErrInvalidInput)
	}
	if req.CategoryName == "" {
		return fmt.Errorf("%w: category_name is required", ErrInvalidInput)
	}
	return nil
}

func (s *libraryService) sanitizeBook(req *CreateBookRequest) {
	req.Title = strings.TrimSpace(req.Title)
	req.Author = strings.TrimSpace(req.Author)
	req.ISBN = strings.TrimSpace(req.ISBN)
	req.Publisher = strings.TrimSpace(req.Publisher)
	req.Edition = strings.TrimSpace(req.Edition)
	req.Language = strings.TrimSpace(req.Language)
	req.Description = strings.TrimSpace(req.Description)
}

func (s *libraryService) validateBookCreate(req CreateBookRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id is required", ErrInvalidInput)
	}
	if req.Title == "" {
		return fmt.Errorf("%w: title is required", ErrInvalidInput)
	}
	return nil
}

func (s *libraryService) sanitizeBookUpdate(req *UpdateBookRequest) {
	req.Title = strings.TrimSpace(req.Title)
	req.Author = strings.TrimSpace(req.Author)
	req.ISBN = strings.TrimSpace(req.ISBN)
	req.Publisher = strings.TrimSpace(req.Publisher)
	req.Edition = strings.TrimSpace(req.Edition)
	req.Language = strings.TrimSpace(req.Language)
	req.Description = strings.TrimSpace(req.Description)
}

func (s *libraryService) validateBookUpdate(req UpdateBookRequest) error {
	if req.BookID == uuid.Nil {
		return fmt.Errorf("%w: book_id is required", ErrInvalidInput)
	}
	if req.Title == "" {
		return fmt.Errorf("%w: title is required", ErrInvalidInput)
	}
	return nil
}

func (s *libraryService) validateCopyCreate(req CreateCopyRequest) error {
	if req.BookID == uuid.Nil {
		return fmt.Errorf("%w: book_id is required", ErrInvalidInput)
	}
	if req.AccessionNo == "" {
		return fmt.Errorf("%w: accession_no is required", ErrInvalidInput)
	}
	if req.Status == "" {
		return fmt.Errorf("%w: status is required", ErrInvalidInput)
	}
	if !models.IsValidCopyStatus(string(req.Status)) {
		return fmt.Errorf("%w: invalid copy status", ErrInvalidInput)
	}
	return nil
}

func (s *libraryService) validateCopyUpdate(req UpdateCopyRequest) error {
	if req.CopyID == uuid.Nil {
		return fmt.Errorf("%w: copy_id is required", ErrInvalidInput)
	}
	if req.Status == "" {
		return fmt.Errorf("%w: status is required", ErrInvalidInput)
	}
	if !models.IsValidCopyStatus(string(req.Status)) {
		return fmt.Errorf("%w: invalid copy status", ErrInvalidInput)
	}
	return nil
}

func (s *libraryService) validateIssue(req IssueBookRequest) error {
	if req.CopyID == uuid.Nil {
		return fmt.Errorf("%w: copy_id is required", ErrInvalidInput)
	}
	if req.StudentID == uuid.Nil {
		return fmt.Errorf("%w: student_id is required", ErrInvalidInput)
	}
	if req.IssueDate.IsZero() {
		return fmt.Errorf("%w: issue_date is required", ErrInvalidInput)
	}
	if req.DueDate.IsZero() {
		return fmt.Errorf("%w: due_date is required", ErrInvalidInput)
	}
	if req.DueDate.Before(req.IssueDate) {
		return fmt.Errorf("%w: due_date must be after issue_date", ErrInvalidInput)
	}
	return nil
}

func (s *libraryService) validateReturn(req ReturnBookRequest) error {
	if req.IssueID == uuid.Nil {
		return fmt.Errorf("%w: issue_id is required", ErrInvalidInput)
	}
	if req.ReturnDate.IsZero() {
		return fmt.Errorf("%w: return_date is required", ErrInvalidInput)
	}
	return nil
}

func (s *libraryService) validateFineCreate(req CreateFineRequest) error {
	if req.IssueID == uuid.Nil {
		return fmt.Errorf("%w: issue_id is required", ErrInvalidInput)
	}
	if req.FineAmount < 0 {
		return fmt.Errorf("%w: fine_amount cannot be negative", ErrInvalidInput)
	}
	return nil
}

func (s *libraryService) validateFinePayment(req UpdateFinePaymentRequest) error {
	if req.FineID == uuid.Nil {
		return fmt.Errorf("%w: fine_id is required", ErrInvalidInput)
	}
	if req.Paid && req.PaidDate == nil {
		return fmt.Errorf("%w: paid_date is required when marking as paid", ErrInvalidInput)
	}
	return nil
}

// getStudent fetches a student by ID using the injected StudentService.
// If the student is not found, it returns nil, nil (no error) so that
// notifications can be skipped gracefully.
func (s *libraryService) getStudent(ctx context.Context, studentID uuid.UUID) (*models.Student, error) {
	if s.studentSvc == nil {
		return nil, nil
	}
	student, err := s.studentSvc.GetByID(ctx, studentID)
	if err != nil {
		// Check for not-found error; if it's the expected ErrNotFound, return nil, nil
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return student, nil
}
