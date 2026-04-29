package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
)

// LibraryService defines the high-level operations for the library domain.
type LibraryService interface {
	// Category operations
	CreateCategory(ctx context.Context, req CreateCategoryRequest) (*models.LibraryCategory, error)
	GetCategoryByID(ctx context.Context, id uuid.UUID) (*models.LibraryCategory, error)
	ListCategories(ctx context.Context, filter repository.LibraryCategoryFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.LibraryCategory, int64, error)
	UpdateCategory(ctx context.Context, req UpdateCategoryRequest) (*models.LibraryCategory, error)
	DeleteCategory(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error

	// Book operations
	CreateBook(ctx context.Context, req CreateBookRequest) (*models.LibraryBook, error)
	GetBookByID(ctx context.Context, id uuid.UUID) (*models.LibraryBook, error)
	GetBookByISBN(ctx context.Context, companyID uuid.UUID, isbn string) (*models.LibraryBook, error)
	ListBooks(ctx context.Context, filter repository.LibraryBookFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.LibraryBook, int64, error)
	UpdateBook(ctx context.Context, req UpdateBookRequest) (*models.LibraryBook, error)
	DeleteBook(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error

	// Copy operations
	CreateCopy(ctx context.Context, req CreateCopyRequest) (*models.LibraryBookCopy, error)
	GetCopyByID(ctx context.Context, id uuid.UUID) (*models.LibraryBookCopy, error)
	GetCopyByAccessionNo(ctx context.Context, accessionNo string) (*models.LibraryBookCopy, error)
	ListCopies(ctx context.Context, filter repository.LibraryCopyFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.LibraryBookCopy, int64, error)
	UpdateCopy(ctx context.Context, req UpdateCopyRequest) (*models.LibraryBookCopy, error)
	DeleteCopy(ctx context.Context, id uuid.UUID) error

	// Issue/Return operations
	IssueBook(ctx context.Context, req IssueBookRequest) (*models.LibraryIssue, error)
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
// Request/Response types (unchanged)
// ----------------------------------------------------------------------------

type CreateCategoryRequest struct {
	CompanyID    uuid.UUID  `json:"company_id"`
	CategoryName string     `json:"category_name"`
	Description  string     `json:"description,omitempty"`
	CreatedBy    *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy    *uuid.UUID `json:"updated_by,omitempty"`
}

type UpdateCategoryRequest struct {
	CategoryID   uuid.UUID  `json:"category_id"`
	CategoryName string     `json:"category_name"`
	Description  string     `json:"description,omitempty"`
	UpdatedBy    *uuid.UUID `json:"updated_by,omitempty"`
}

type CreateBookRequest struct {
	CompanyID       uuid.UUID  `json:"company_id"`
	CategoryID      *uuid.UUID `json:"category_id,omitempty"`
	Title           string     `json:"title"`
	Author          string     `json:"author"`
	ISBN            string     `json:"isbn,omitempty"`
	Publisher       string     `json:"publisher,omitempty"`
	Edition         string     `json:"edition,omitempty"`
	Language        string     `json:"language,omitempty"`
	Pages           int        `json:"pages,omitempty"`
	PublicationYear int        `json:"publication_year,omitempty"`
	Description     string     `json:"description,omitempty"`
	CreatedBy       *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy       *uuid.UUID `json:"updated_by,omitempty"`
}

type UpdateBookRequest struct {
	BookID          uuid.UUID  `json:"book_id"`
	CategoryID      *uuid.UUID `json:"category_id,omitempty"`
	Title           string     `json:"title"`
	Author          string     `json:"author"`
	ISBN            string     `json:"isbn,omitempty"`
	Publisher       string     `json:"publisher,omitempty"`
	Edition         string     `json:"edition,omitempty"`
	Language        string     `json:"language,omitempty"`
	Pages           int        `json:"pages,omitempty"`
	PublicationYear int        `json:"publication_year,omitempty"`
	Description     string     `json:"description,omitempty"`
	UpdatedBy       *uuid.UUID `json:"updated_by,omitempty"`
}

type CreateCopyRequest struct {
	BookID        uuid.UUID         `json:"book_id"`
	AccessionNo   string            `json:"accession_no"`
	Status        models.CopyStatus `json:"status"`
	PurchaseDate  *time.Time        `json:"purchase_date,omitempty"`
	Cost          *float64          `json:"cost,omitempty"`
	ShelfLocation string            `json:"shelf_location,omitempty"`
	CreatedBy     *uuid.UUID        `json:"created_by,omitempty"`
}

type UpdateCopyRequest struct {
	CopyID        uuid.UUID         `json:"copy_id"`
	Status        models.CopyStatus `json:"status"`
	PurchaseDate  *time.Time        `json:"purchase_date,omitempty"`
	Cost          *float64          `json:"cost,omitempty"`
	ShelfLocation string            `json:"shelf_location,omitempty"`
}

type IssueBookRequest struct {
	CopyID    uuid.UUID  `json:"copy_id"`
	StudentID uuid.UUID  `json:"student_id"`
	IssueDate time.Time  `json:"issue_date"`
	DueDate   time.Time  `json:"due_date"`
	IssuedBy  *uuid.UUID `json:"issued_by,omitempty"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
}

type ReturnBookRequest struct {
	IssueID    uuid.UUID  `json:"issue_id"`
	ReturnDate time.Time  `json:"return_date"`
	FineAmount float64    `json:"fine_amount,omitempty"`
	Remarks    string     `json:"remarks,omitempty"`
	ReceivedBy *uuid.UUID `json:"received_by,omitempty"`
}

type CreateFineRequest struct {
	IssueID    uuid.UUID  `json:"issue_id"`
	FineAmount float64    `json:"fine_amount"`
	CreatedBy  *uuid.UUID `json:"created_by,omitempty"`
}

type UpdateFinePaymentRequest struct {
	FineID      uuid.UUID  `json:"fine_id"`
	Paid        bool       `json:"paid"`
	PaidDate    *time.Time `json:"paid_date,omitempty"`
	PaymentMode string     `json:"payment_mode,omitempty"`
}

// ----------------------------------------------------------------------------
// Service implementation
// ----------------------------------------------------------------------------

type libraryService struct {
	repo                repository.LibraryRepository
	pgClient            *client.PostgresClient
	logger              *zap.Logger
	outboxRepo          outbox.Repository
	idempotencyStore    idempotency.Store
	auditService        *audit.AuditService
	notificationService NotificationService
	studentService      StudentService
}

// NewLibraryService creates a new library service with its dependencies.
func NewLibraryService(
	repo repository.LibraryRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	notificationService NotificationService,
	studentService StudentService,
) LibraryService {
	return &libraryService{
		repo:                repo,
		pgClient:            pgClient,
		logger:              logger.Named("library_service"),
		outboxRepo:          outboxRepo,
		idempotencyStore:    idempotencyStore,
		auditService:        auditService,
		notificationService: notificationService,
		studentService:      studentService,
	}
}

// ----------------------------------------------------------------------------
// Category methods
// ----------------------------------------------------------------------------

func (s *libraryService) CreateCategory(ctx context.Context, req CreateCategoryRequest) (*models.LibraryCategory, error) {
	logger := s.logger.With(
		zap.String("method", "CreateCategory"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("name", req.CategoryName),
	)

	s.sanitizeCategory(&req)
	if err := s.validateCategoryCreate(req); err != nil {
		return nil, err
	}

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check
	if idempotencyKey != "" {
		var existing models.LibraryCategory
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.CategoryID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existing, nil
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

	// Store idempotency key
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, category); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Outbox event
	payload, _ := json.Marshal(category)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "library_category",
		AggregateID:   category.CategoryID.String(),
		EventType:     string(EventLibraryCategoryCreated),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("library category created", zap.String("id", category.CategoryID.String()))

	// Audit (after commit)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "library", "create", "category",
			&category.CategoryID, "user", req.CreatedBy, nil, nil,
			map[string]interface{}{"name": category.CategoryName})
	}

	// Notification (after commit) - inline construction
	if s.notificationService != nil && req.CreatedBy != nil && *req.CreatedBy != uuid.Nil {
		notifReq := CreateNotificationRequest{
			CompanyID: req.CompanyID,
			Title:     "Library Category Created",
			Message:   fmt.Sprintf("Category '%s' has been created.", category.CategoryName),
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityNormal,
			ExpiresAt: nil,
			Targets: []NotificationTargetInput{
				{
					TargetType:     models.TargetUser,
					TargetEntityID: *req.CreatedBy,
				},
			},
			CreatedBy: req.CreatedBy,
		}
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

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

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing models.LibraryCategory
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.CategoryID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existing, nil
		}
	}

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, category); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Outbox event
	payload, _ := json.Marshal(map[string]interface{}{"old": old, "new": category})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "library_category",
		AggregateID:   category.CategoryID.String(),
		EventType:     string(EventLibraryCategoryUpdated),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("library category updated")

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &category.CompanyID, "library", "update", "category",
			&category.CategoryID, "user", req.UpdatedBy, nil, nil,
			map[string]interface{}{"name": category.CategoryName})
	}

	// Notification (after commit) - inline
	if s.notificationService != nil && req.UpdatedBy != nil && *req.UpdatedBy != uuid.Nil {
		notifReq := CreateNotificationRequest{
			CompanyID: category.CompanyID,
			Title:     "Library Category Updated",
			Message:   fmt.Sprintf("Category '%s' has been updated.", category.CategoryName),
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityNormal,
			ExpiresAt: nil,
			Targets: []NotificationTargetInput{
				{
					TargetType:     models.TargetUser,
					TargetEntityID: *req.UpdatedBy,
				},
			},
			CreatedBy: req.UpdatedBy,
		}
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

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

	category, err := s.repo.GetCategoryByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if category == nil {
		return fmt.Errorf("%w: category %s", ErrNotFound, id)
	}

	if err := s.repo.DeleteCategory(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	// Outbox event
	payload, _ := json.Marshal(map[string]interface{}{"category_id": id, "deleted_by": deletedBy})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "library_category",
		AggregateID:   id.String(),
		EventType:     string(EventLibraryCategoryDeleted),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("library category deleted")

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &category.CompanyID, "library", "delete", "category",
			&id, "user", deletedBy, nil, nil, nil)
	}

	// Notification (after commit) - inline
	if s.notificationService != nil && deletedBy != nil && *deletedBy != uuid.Nil {
		notifReq := CreateNotificationRequest{
			CompanyID: category.CompanyID,
			Title:     "Library Category Deleted",
			Message:   fmt.Sprintf("Category '%s' has been deleted.", category.CategoryName),
			Type:      models.NotificationTypeWarning,
			Priority:  models.PriorityHigh,
			ExpiresAt: nil,
			Targets: []NotificationTargetInput{
				{
					TargetType:     models.TargetUser,
					TargetEntityID: *deletedBy,
				},
			},
			CreatedBy: deletedBy,
		}
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

	return nil
}

// ----------------------------------------------------------------------------
// Book methods
// ----------------------------------------------------------------------------

func (s *libraryService) CreateBook(ctx context.Context, req CreateBookRequest) (*models.LibraryBook, error) {
	logger := s.logger.With(
		zap.String("method", "CreateBook"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("title", req.Title),
	)

	s.sanitizeBook(&req)
	if err := s.validateBookCreate(req); err != nil {
		return nil, err
	}

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing models.LibraryBook
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.BookID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existing, nil
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
		}
	}

	payload, _ := json.Marshal(book)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "library_book",
		AggregateID:   book.BookID.String(),
		EventType:     string(EventLibraryBookCreated),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("library book created", zap.String("id", book.BookID.String()))

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "library", "create", "book",
			&book.BookID, "user", req.CreatedBy, nil, nil,
			map[string]interface{}{"title": book.Title})
	}

	// Notification (after commit) - inline
	if s.notificationService != nil && req.CreatedBy != nil && *req.CreatedBy != uuid.Nil {
		notifReq := CreateNotificationRequest{
			CompanyID: req.CompanyID,
			Title:     "New Book Added",
			Message:   fmt.Sprintf("Book '%s' by %s has been added to the library.", book.Title, book.Author),
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityNormal,
			ExpiresAt: nil,
			Targets: []NotificationTargetInput{
				{
					TargetType:     models.TargetUser,
					TargetEntityID: *req.CreatedBy,
				},
			},
			CreatedBy: req.CreatedBy,
		}
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

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

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing models.LibraryBook
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.BookID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existing, nil
		}
	}

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, book); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	payload, _ := json.Marshal(map[string]interface{}{"old": old, "new": book})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "library_book",
		AggregateID:   book.BookID.String(),
		EventType:     string(EventLibraryBookUpdated),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("library book updated")

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &book.CompanyID, "library", "update", "book",
			&book.BookID, "user", req.UpdatedBy, nil, nil,
			map[string]interface{}{"title": book.Title})
	}

	// Notification (after commit) - inline
	if s.notificationService != nil && req.UpdatedBy != nil && *req.UpdatedBy != uuid.Nil {
		notifReq := CreateNotificationRequest{
			CompanyID: book.CompanyID,
			Title:     "Library Book Updated",
			Message:   fmt.Sprintf("Book '%s' by %s has been updated.", book.Title, book.Author),
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityNormal,
			ExpiresAt: nil,
			Targets: []NotificationTargetInput{
				{
					TargetType:     models.TargetUser,
					TargetEntityID: *req.UpdatedBy,
				},
			},
			CreatedBy: req.UpdatedBy,
		}
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

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

	book, err := s.repo.GetBookByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if book == nil {
		return fmt.Errorf("%w: book %s", ErrNotFound, id)
	}

	if err := s.repo.DeleteBook(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	payload, _ := json.Marshal(map[string]interface{}{"book_id": id, "deleted_by": deletedBy})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "library_book",
		AggregateID:   id.String(),
		EventType:     string(EventLibraryBookDeleted),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("library book deleted")

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &book.CompanyID, "library", "delete", "book",
			&id, "user", deletedBy, nil, nil, nil)
	}

	// Notification (after commit) - inline
	if s.notificationService != nil && deletedBy != nil && *deletedBy != uuid.Nil {
		notifReq := CreateNotificationRequest{
			CompanyID: book.CompanyID,
			Title:     "Library Book Deleted",
			Message:   fmt.Sprintf("Book '%s' by %s has been deleted from the library.", book.Title, book.Author),
			Type:      models.NotificationTypeWarning,
			Priority:  models.PriorityHigh,
			ExpiresAt: nil,
			Targets: []NotificationTargetInput{
				{
					TargetType:     models.TargetUser,
					TargetEntityID: *deletedBy,
				},
			},
			CreatedBy: deletedBy,
		}
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

	return nil
}

// ----------------------------------------------------------------------------
// Copy methods
// ----------------------------------------------------------------------------

func (s *libraryService) CreateCopy(ctx context.Context, req CreateCopyRequest) (*models.LibraryBookCopy, error) {
	logger := s.logger.With(
		zap.String("method", "CreateCopy"),
		zap.String("book_id", req.BookID.String()),
		zap.String("accession_no", req.AccessionNo),
	)

	if err := s.validateCopyCreate(req); err != nil {
		return nil, err
	}

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing models.LibraryBookCopy
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.CopyID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existing, nil
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
		}
	}

	payload, _ := json.Marshal(copy)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "library_copy",
		AggregateID:   copy.CopyID.String(),
		EventType:     string(EventLibraryCopyCreated),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	// Fetch book to get company ID
	book, err := s.repo.GetBookByID(ctx, tx, req.BookID)
	if err != nil {
		logger.Error("failed to fetch book for company ID", zap.Error(err))
		book = nil
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("library copy created", zap.String("copy_id", copy.CopyID.String()))

	if s.auditService != nil && book != nil {
		_ = s.auditService.LogAction(ctx, nil, &book.CompanyID, "library", "create", "copy",
			&copy.CopyID, "user", req.CreatedBy, nil, nil,
			map[string]interface{}{"accession_no": copy.AccessionNo})
	}

	// Notification (after commit) - inline
	if s.notificationService != nil && book != nil && req.CreatedBy != nil && *req.CreatedBy != uuid.Nil {
		notifReq := CreateNotificationRequest{
			CompanyID: book.CompanyID,
			Title:     "New Book Copy Added",
			Message:   fmt.Sprintf("A new copy of '%s' (Accession No: %s) has been added.", book.Title, copy.AccessionNo),
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityNormal,
			ExpiresAt: nil,
			Targets: []NotificationTargetInput{
				{
					TargetType:     models.TargetUser,
					TargetEntityID: *req.CreatedBy,
				},
			},
			CreatedBy: req.CreatedBy,
		}
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

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

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing models.LibraryBookCopy
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.CopyID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existing, nil
		}
	}

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, copy); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	payload, _ := json.Marshal(map[string]interface{}{"old": old, "new": copy})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "library_copy",
		AggregateID:   copy.CopyID.String(),
		EventType:     string(EventLibraryCopyUpdated),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	// Fetch book for company ID
	book, err := s.repo.GetBookByID(ctx, tx, copy.BookID)
	if err != nil {
		logger.Error("failed to fetch book for company ID", zap.Error(err))
		book = nil
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("library copy updated")

	if s.auditService != nil && book != nil {
		_ = s.auditService.LogAction(ctx, nil, &book.CompanyID, "library", "update", "copy",
			&copy.CopyID, "user", nil, nil, nil,
			map[string]interface{}{"status": copy.Status})
	}

	// Notification (optional, only for status change) - inline
	if s.notificationService != nil && book != nil && old.Status != copy.Status && copy.Status == models.CopyStatusAvailable {
		notifReq := CreateNotificationRequest{
			CompanyID: book.CompanyID,
			Title:     "Book Copy Status Updated",
			Message:   fmt.Sprintf("A copy of '%s' (Accession No: %s) is now available.", book.Title, copy.AccessionNo),
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityNormal,
			ExpiresAt: nil,
			Targets:   []NotificationTargetInput{}, // no specific user
			CreatedBy: nil,
		}
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

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

	copy, err := s.repo.GetCopyByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if copy == nil {
		return fmt.Errorf("%w: copy %s", ErrNotFound, id)
	}

	book, err := s.repo.GetBookByID(ctx, tx, copy.BookID)
	if err != nil {
		logger.Error("failed to fetch book for company ID", zap.Error(err))
		book = nil
	}

	if err := s.repo.DeleteCopy(ctx, tx, id); err != nil {
		return err
	}

	payload, _ := json.Marshal(map[string]interface{}{"copy_id": id})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "library_copy",
		AggregateID:   id.String(),
		EventType:     string(EventLibraryCopyDeleted),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("library copy deleted")

	if s.auditService != nil && book != nil {
		_ = s.auditService.LogAction(ctx, nil, &book.CompanyID, "library", "delete", "copy",
			&id, "user", nil, nil, nil, nil)
	}

	return nil
}

// ----------------------------------------------------------------------------
// Issue/Return methods
// ----------------------------------------------------------------------------

func (s *libraryService) IssueBook(ctx context.Context, req IssueBookRequest) (*models.LibraryIssue, error) {
	logger := s.logger.With(
		zap.String("method", "IssueBook"),
		zap.String("copy_id", req.CopyID.String()),
		zap.String("student_id", req.StudentID.String()),
	)

	if err := s.validateIssue(req); err != nil {
		return nil, err
	}

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing models.LibraryIssue
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.IssueID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existing, nil
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
		}
	}

	// Outbox event
	payload, _ := json.Marshal(issue)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "library_issue",
		AggregateID:   issue.IssueID.String(),
		EventType:     string(EventLibraryBookIssued),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	// Fetch book to get company ID and title
	book, err := s.repo.GetBookByID(ctx, tx, copy.BookID)
	if err != nil {
		logger.Error("failed to fetch book for company ID", zap.Error(err))
		book = nil
	}
	student, err := s.getStudent(ctx, req.StudentID)
	if err != nil {
		logger.Error("failed to fetch student for notification", zap.Error(err))
		student = nil
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("book issued", zap.String("issue_id", issue.IssueID.String()))

	if s.auditService != nil && book != nil {
		_ = s.auditService.LogAction(ctx, nil, &book.CompanyID, "library", "issue", "book",
			&issue.IssueID, "user", req.IssuedBy, nil, nil,
			map[string]interface{}{"student_id": req.StudentID.String(), "copy_id": req.CopyID.String()})
	}

	// Send notification to student - inline
	if s.notificationService != nil && student != nil && book != nil {
		notifReq := CreateNotificationRequest{
			CompanyID: student.CompanyID,
			Title:     "Book Issued",
			Message:   fmt.Sprintf("You have issued '%s'. Due date: %s. Please return on time.", book.Title, req.DueDate.Format("2006-01-02")),
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityNormal,
			ExpiresAt: nil,
			Targets: []NotificationTargetInput{
				{
					TargetType:     models.TargetUser,
					TargetEntityID: req.StudentID,
				},
			},
			CreatedBy: req.IssuedBy,
		}
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to send notification to student", zap.Error(err))
		}
	}

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

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existingReturn models.LibraryReturn
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existingReturn); err == nil && existingReturn.ReturnID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existingReturn, nil
		}
	}

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, returnRecord); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Outbox event for return
	payload, _ := json.Marshal(returnRecord)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "library_return",
		AggregateID:   returnRecord.ReturnID.String(),
		EventType:     string(EventLibraryBookReturned),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if req.FineAmount > 0 {
		finePayload, _ := json.Marshal(map[string]interface{}{
			"issue_id":    req.IssueID,
			"fine_amount": req.FineAmount,
			"paid_date":   req.ReturnDate,
		})
		fineEvent := &outbox.Event{
			EventID:       uuid.New().String(),
			AggregateType: "library_fine",
			AggregateID:   req.IssueID.String(),
			EventType:     string(EventLibraryFinePaid),
			Topic:         TopicStudent,
			Payload:       finePayload,
			Status:        "pending",
		}
		if err := s.outboxRepo.Store(ctx, tx, fineEvent); err != nil {
			logger.Error("failed to store fine outbox event", zap.Error(err))
		}
	}

	// Fetch student and book for notification
	student, err := s.getStudent(ctx, issue.StudentID)
	if err != nil {
		logger.Error("failed to fetch student for notification", zap.Error(err))
		student = nil
	}
	copy, err := s.repo.GetCopyByID(ctx, tx, issue.CopyID)
	if err != nil {
		logger.Error("failed to fetch copy for book title", zap.Error(err))
		copy = nil
	}
	var book *models.LibraryBook
	if copy != nil {
		book, _ = s.repo.GetBookByID(ctx, tx, copy.BookID)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("book returned", zap.String("return_id", returnRecord.ReturnID.String()))

	if s.auditService != nil && student != nil {
		_ = s.auditService.LogAction(ctx, nil, &student.CompanyID, "library", "return", "book",
			&returnRecord.ReturnID, "user", req.ReceivedBy, nil, nil,
			map[string]interface{}{"issue_id": req.IssueID.String(), "fine": req.FineAmount})
	}

	// Send notification to student - inline
	if s.notificationService != nil && student != nil {
		title := "Book Returned"
		message := "Thank you for returning the book."
		if req.FineAmount > 0 {
			message = fmt.Sprintf("Book returned with a fine of %.2f. Please clear the fine at the library counter.", req.FineAmount)
		} else if book != nil {
			message = fmt.Sprintf("You have returned '%s'. Thank you!", book.Title)
		}
		notifReq := CreateNotificationRequest{
			CompanyID: student.CompanyID,
			Title:     title,
			Message:   message,
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityNormal,
			ExpiresAt: nil,
			Targets: []NotificationTargetInput{
				{
					TargetType:     models.TargetUser,
					TargetEntityID: issue.StudentID,
				},
			},
			CreatedBy: req.ReceivedBy,
		}
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to send return notification to student", zap.Error(err))
		}
	}

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

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing models.LibraryFine
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.FineID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existing, nil
		}
	}

	fine := &models.LibraryFine{
		IssueID:    req.IssueID,
		FineAmount: req.FineAmount,
		Paid:       false,
		CreatedBy:  req.CreatedBy,
	}

	if err := s.repo.CreateFine(ctx, tx, fine); err != nil {
		return nil, err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, fine); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	payload, _ := json.Marshal(fine)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "library_fine",
		AggregateID:   fine.FineID.String(),
		EventType:     string(EventLibraryFineCreated),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("fine created", zap.String("fine_id", fine.FineID.String()))

	// Audit & notification (simplified)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "library", "create", "fine",
			&fine.FineID, "user", req.CreatedBy, nil, nil,
			map[string]interface{}{"amount": req.FineAmount})
	}

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

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var result interface{}
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &result); err == nil && result != nil {
			logger.Info("idempotent request, skipping")
			return nil
		}
	}

	if err := s.repo.UpdateFinePayment(ctx, tx, req.FineID, req.Paid, req.PaidDate, req.PaymentMode); err != nil {
		return err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"fine_id":      req.FineID,
		"paid":         req.Paid,
		"paid_date":    req.PaidDate,
		"payment_mode": req.PaymentMode,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "library_fine",
		AggregateID:   req.FineID.String(),
		EventType:     string(EventLibraryFinePaid),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
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
	if s.studentService == nil {
		return nil, nil
	}
	student, err := s.studentService.GetByID(ctx, studentID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return student, nil
}
