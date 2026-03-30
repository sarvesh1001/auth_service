package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/util"
)

// LibraryRepository defines all library-related database operations.
type LibraryRepository interface {
	// ========== Categories ==========
	CreateCategory(ctx context.Context, db DBTX, c *models.LibraryCategory) error
	GetCategoryByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.LibraryCategory, error)
	ListCategories(ctx context.Context, db DBTX, filter LibraryCategoryFilter, p Pagination, s Sort) ([]*models.LibraryCategory, error)
	CountCategories(ctx context.Context, db DBTX, filter LibraryCategoryFilter) (int64, error)
	UpdateCategory(ctx context.Context, db DBTX, c *models.LibraryCategory) error
	DeleteCategory(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error

	// ========== Books ==========
	CreateBook(ctx context.Context, db DBTX, b *models.LibraryBook) error
	GetBookByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.LibraryBook, error)
	GetBookByISBN(ctx context.Context, db DBTX, companyID uuid.UUID, isbn string) (*models.LibraryBook, error)
	ListBooks(ctx context.Context, db DBTX, filter LibraryBookFilter, p Pagination, s Sort) ([]*models.LibraryBook, error)
	CountBooks(ctx context.Context, db DBTX, filter LibraryBookFilter) (int64, error)
	UpdateBook(ctx context.Context, db DBTX, b *models.LibraryBook) error
	DeleteBook(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error

	// ========== Copies ==========
	CreateCopy(ctx context.Context, db DBTX, c *models.LibraryBookCopy) error
	GetCopyByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.LibraryBookCopy, error)
	GetCopyByAccessionNo(ctx context.Context, db DBTX, accessionNo string) (*models.LibraryBookCopy, error)
	ListCopies(ctx context.Context, db DBTX, filter LibraryCopyFilter, p Pagination, s Sort) ([]*models.LibraryBookCopy, error)
	CountCopies(ctx context.Context, db DBTX, filter LibraryCopyFilter) (int64, error)
	UpdateCopy(ctx context.Context, db DBTX, c *models.LibraryBookCopy) error
	// DeleteCopy physically (no soft delete) – use with caution, typically we don't delete copies.
	DeleteCopy(ctx context.Context, db DBTX, id uuid.UUID) error

	// ========== Issues ==========
	IssueBook(ctx context.Context, db DBTX, issue *models.LibraryIssue) error // also updates copy status to issued
	GetIssueByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.LibraryIssue, error)
	ListIssues(ctx context.Context, db DBTX, filter LibraryIssueFilter, p Pagination, s Sort) ([]*models.LibraryIssue, error)
	CountIssues(ctx context.Context, db DBTX, filter LibraryIssueFilter) (int64, error)
	// ReturnBook handles returning a copy, updating issue status, copy status, and optionally creating fine/return records.
	ReturnBook(ctx context.Context, db DBTX, issueID uuid.UUID, returnDate time.Time, fineAmount float64, remarks string, receivedBy *uuid.UUID) error
	// UpdateIssueStatus updates just the status (e.g., mark as lost)
	UpdateIssueStatus(ctx context.Context, db DBTX, issueID uuid.UUID, status models.IssueStatus, updatedBy *uuid.UUID) error

	// ========== Returns (mostly for reporting) ==========
	GetReturnByIssueID(ctx context.Context, db DBTX, issueID uuid.UUID) (*models.LibraryReturn, error)
	// ========== Fines ==========
	CreateFine(ctx context.Context, db DBTX, fine *models.LibraryFine) error
	UpdateFinePayment(ctx context.Context, db DBTX, fineID uuid.UUID, paid bool, paidDate *time.Time, paymentMode string) error
	ListFines(ctx context.Context, db DBTX, studentID *uuid.UUID, paid *bool) ([]*models.LibraryFine, error)

	// ========== Domain Helpers ==========
	GetAvailableCopies(ctx context.Context, db DBTX, bookID uuid.UUID) (int, error)
	HasOverdueIssues(ctx context.Context, db DBTX, studentID uuid.UUID) (bool, error)
}

type libraryRepository struct {
	logger *zap.Logger
}

// NewLibraryRepository creates a new library repository.
func NewLibraryRepository(logger *zap.Logger) LibraryRepository {
	return &libraryRepository{
		logger: logger.Named("library_repo"),
	}
}

// --- Sorting & Pagination Helpers ---

var allowedCategorySortFields = map[string]bool{
	"created_at":    true,
	"updated_at":    true,
	"category_name": true,
}

func (r *libraryRepository) validateCategorySort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "category_name"
	}
	if !allowedCategorySortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "ASC"
	}
	return fmt.Sprintf("ORDER BY c.%s %s", field, dir), nil
}

var allowedBookSortFields = map[string]bool{
	"created_at":       true,
	"updated_at":       true,
	"title":            true,
	"author":           true,
	"publication_year": true,
}

func (r *libraryRepository) validateBookSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "title"
	}
	if !allowedBookSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "ASC"
	}
	return fmt.Sprintf("ORDER BY b.%s %s", field, dir), nil
}

var allowedCopySortFields = map[string]bool{
	"created_at":   true,
	"updated_at":   true,
	"accession_no": true,
	"status":       true,
}

func (r *libraryRepository) validateCopySort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "accession_no"
	}
	if !allowedCopySortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "ASC"
	}
	return fmt.Sprintf("ORDER BY cp.%s %s", field, dir), nil
}

var allowedIssueSortFields = map[string]bool{
	"created_at":    true,
	"issue_date":    true,
	"due_date":      true,
	"returned_date": true,
	"status":        true,
}

func (r *libraryRepository) validateIssueSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "issue_date"
	}
	if !allowedIssueSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY i.%s %s", field, dir), nil
}

func (r *libraryRepository) validatePagination(p Pagination) (int, int) {
	limit := p.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := p.Offset
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// --- Categories ---------------------------------------------------------

func (r *libraryRepository) buildCategoryFilter(filter LibraryCategoryFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("c.company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(c.category_name ILIKE $%d OR c.description ILIKE $%d)", idx, idx))
		args = append(args, "%"+filter.Search+"%")
		idx++
	}

	conditions = append(conditions, "c.deleted_at IS NULL")

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *libraryRepository) CreateCategory(ctx context.Context, db DBTX, c *models.LibraryCategory) error {
	query := `
        INSERT INTO academics.library_categories (
            company_id, category_name, description, created_by, updated_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
        RETURNING category_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		c.CompanyID, c.CategoryName, c.Description, c.CreatedBy, c.UpdatedBy,
	).Scan(&c.CategoryID, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create library category", util.ErrorField(err))
		return fmt.Errorf("create category: %w", err)
	}
	return nil
}

func (r *libraryRepository) GetCategoryByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.LibraryCategory, error) {
	query := `
        SELECT category_id, company_id, category_name, description,
               created_at, updated_at, created_by, updated_by
        FROM academics.library_categories
        WHERE category_id = $1 AND deleted_at IS NULL
    `
	var c models.LibraryCategory
	var createdBy, updatedBy uuid.NullUUID

	err := db.QueryRowContext(ctx, query, id).Scan(
		&c.CategoryID, &c.CompanyID, &c.CategoryName, &c.Description,
		&c.CreatedAt, &c.UpdatedAt, &createdBy, &updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get category: %w", err)
	}
	if createdBy.Valid {
		c.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		c.UpdatedBy = &updatedBy.UUID
	}
	return &c, nil
}

func (r *libraryRepository) ListCategories(ctx context.Context, db DBTX, filter LibraryCategoryFilter, p Pagination, s Sort) ([]*models.LibraryCategory, error) {
	where, args := r.buildCategoryFilter(filter)
	orderBy, err := r.validateCategorySort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
        SELECT category_id, company_id, category_name, description,
               created_at, updated_at, created_by, updated_by
        FROM academics.library_categories c
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list categories", util.ErrorField(err))
		return nil, fmt.Errorf("list categories: %w", err)
	}
	defer rows.Close()

	var result []*models.LibraryCategory
	for rows.Next() {
		var c models.LibraryCategory
		var createdBy, updatedBy uuid.NullUUID

		if err := rows.Scan(
			&c.CategoryID, &c.CompanyID, &c.CategoryName, &c.Description,
			&c.CreatedAt, &c.UpdatedAt, &createdBy, &updatedBy,
		); err != nil {
			return nil, fmt.Errorf("scan category: %w", err)
		}
		if createdBy.Valid {
			c.CreatedBy = &createdBy.UUID
		}
		if updatedBy.Valid {
			c.UpdatedBy = &updatedBy.UUID
		}
		result = append(result, &c)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *libraryRepository) CountCategories(ctx context.Context, db DBTX, filter LibraryCategoryFilter) (int64, error) {
	where, args := r.buildCategoryFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.library_categories c %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count categories", util.ErrorField(err))
		return 0, fmt.Errorf("count categories: %w", err)
	}
	return count, nil
}

func (r *libraryRepository) UpdateCategory(ctx context.Context, db DBTX, c *models.LibraryCategory) error {
	query := `
        UPDATE academics.library_categories
        SET category_name = $2, description = $3, updated_by = $4, updated_at = NOW()
        WHERE category_id = $1 AND deleted_at IS NULL
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query, c.CategoryID, c.CategoryName, c.Description, c.UpdatedBy).Scan(&c.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: category %s", ErrNotFound, c.CategoryID)
		}
		r.logger.Error("failed to update category", util.ErrorField(err))
		return fmt.Errorf("update category: %w", err)
	}
	return nil
}

func (r *libraryRepository) DeleteCategory(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error {
	query := `UPDATE academics.library_categories SET deleted_at = NOW(), updated_by = $2, updated_at = NOW() WHERE category_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, deletedBy)
	if err != nil {
		r.logger.Error("failed to delete category", util.ErrorField(err))
		return fmt.Errorf("delete category: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: category %s", ErrNotFound, id)
	}
	return nil
}

// --- Books ---------------------------------------------------------

func (r *libraryRepository) buildBookFilter(filter LibraryBookFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("b.company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}

	if filter.CategoryID != nil {
		conditions = append(conditions, fmt.Sprintf("b.category_id = $%d", idx))
		args = append(args, *filter.CategoryID)
		idx++
	}

	if filter.Title != "" {
		conditions = append(conditions, fmt.Sprintf("b.title ILIKE $%d", idx))
		args = append(args, "%"+filter.Title+"%")
		idx++
	}

	if filter.Author != "" {
		conditions = append(conditions, fmt.Sprintf("b.author ILIKE $%d", idx))
		args = append(args, "%"+filter.Author+"%")
		idx++
	}

	if filter.ISBN != "" {
		conditions = append(conditions, fmt.Sprintf("b.isbn = $%d", idx))
		args = append(args, filter.ISBN)
		idx++
	}

	if filter.Language != "" {
		conditions = append(conditions, fmt.Sprintf("b.language = $%d", idx))
		args = append(args, filter.Language)
		idx++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(b.title ILIKE $%d OR b.author ILIKE $%d OR b.isbn ILIKE $%d OR b.publisher ILIKE $%d)", idx, idx, idx, idx))
		args = append(args, "%"+filter.Search+"%")
		idx++
	}

	conditions = append(conditions, "b.deleted_at IS NULL")

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *libraryRepository) CreateBook(ctx context.Context, db DBTX, b *models.LibraryBook) error {
	query := `
        INSERT INTO academics.library_books (
            company_id, category_id, title, author, isbn, publisher, edition,
            language, pages, publication_year, description, created_by, updated_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), NOW())
        RETURNING book_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		b.CompanyID, b.CategoryID, b.Title, b.Author, b.ISBN, b.Publisher, b.Edition,
		b.Language, b.Pages, b.PublicationYear, b.Description, b.CreatedBy, b.UpdatedBy,
	).Scan(&b.BookID, &b.CreatedAt, &b.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create book", util.ErrorField(err))
		return fmt.Errorf("create book: %w", err)
	}
	return nil
}

func (r *libraryRepository) GetBookByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.LibraryBook, error) {
	query := `
        SELECT book_id, company_id, category_id, title, author, isbn, publisher, edition,
               language, pages, publication_year, description,
               created_at, updated_at, created_by, updated_by
        FROM academics.library_books
        WHERE book_id = $1 AND deleted_at IS NULL
    `
	var b models.LibraryBook
	var categoryID, createdBy, updatedBy uuid.NullUUID

	err := db.QueryRowContext(ctx, query, id).Scan(
		&b.BookID, &b.CompanyID, &categoryID, &b.Title, &b.Author, &b.ISBN, &b.Publisher, &b.Edition,
		&b.Language, &b.Pages, &b.PublicationYear, &b.Description,
		&b.CreatedAt, &b.UpdatedAt, &createdBy, &updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get book: %w", err)
	}
	if categoryID.Valid {
		b.CategoryID = &categoryID.UUID
	}
	if createdBy.Valid {
		b.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		b.UpdatedBy = &updatedBy.UUID
	}
	return &b, nil
}

func (r *libraryRepository) GetBookByISBN(ctx context.Context, db DBTX, companyID uuid.UUID, isbn string) (*models.LibraryBook, error) {
	query := `
        SELECT book_id, company_id, category_id, title, author, isbn, publisher, edition,
               language, pages, publication_year, description,
               created_at, updated_at, created_by, updated_by
        FROM academics.library_books
        WHERE company_id = $1 AND isbn = $2 AND deleted_at IS NULL
    `
	var b models.LibraryBook
	var categoryID, createdBy, updatedBy uuid.NullUUID

	err := db.QueryRowContext(ctx, query, companyID, isbn).Scan(
		&b.BookID, &b.CompanyID, &categoryID, &b.Title, &b.Author, &b.ISBN, &b.Publisher, &b.Edition,
		&b.Language, &b.Pages, &b.PublicationYear, &b.Description,
		&b.CreatedAt, &b.UpdatedAt, &createdBy, &updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get book by ISBN: %w", err)
	}
	if categoryID.Valid {
		b.CategoryID = &categoryID.UUID
	}
	if createdBy.Valid {
		b.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		b.UpdatedBy = &updatedBy.UUID
	}
	return &b, nil
}

func (r *libraryRepository) ListBooks(ctx context.Context, db DBTX, filter LibraryBookFilter, p Pagination, s Sort) ([]*models.LibraryBook, error) {
	where, args := r.buildBookFilter(filter)
	orderBy, err := r.validateBookSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
        SELECT book_id, company_id, category_id, title, author, isbn, publisher, edition,
               language, pages, publication_year, description,
               created_at, updated_at, created_by, updated_by
        FROM academics.library_books b
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list books", util.ErrorField(err))
		return nil, fmt.Errorf("list books: %w", err)
	}
	defer rows.Close()

	var result []*models.LibraryBook
	for rows.Next() {
		var b models.LibraryBook
		var categoryID, createdBy, updatedBy uuid.NullUUID

		if err := rows.Scan(
			&b.BookID, &b.CompanyID, &categoryID, &b.Title, &b.Author, &b.ISBN, &b.Publisher, &b.Edition,
			&b.Language, &b.Pages, &b.PublicationYear, &b.Description,
			&b.CreatedAt, &b.UpdatedAt, &createdBy, &updatedBy,
		); err != nil {
			return nil, fmt.Errorf("scan book: %w", err)
		}
		if categoryID.Valid {
			b.CategoryID = &categoryID.UUID
		}
		if createdBy.Valid {
			b.CreatedBy = &createdBy.UUID
		}
		if updatedBy.Valid {
			b.UpdatedBy = &updatedBy.UUID
		}
		result = append(result, &b)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *libraryRepository) CountBooks(ctx context.Context, db DBTX, filter LibraryBookFilter) (int64, error) {
	where, args := r.buildBookFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.library_books b %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count books", util.ErrorField(err))
		return 0, fmt.Errorf("count books: %w", err)
	}
	return count, nil
}

func (r *libraryRepository) UpdateBook(ctx context.Context, db DBTX, b *models.LibraryBook) error {
	query := `
        UPDATE academics.library_books
        SET category_id = $2, title = $3, author = $4, isbn = $5, publisher = $6,
            edition = $7, language = $8, pages = $9, publication_year = $10,
            description = $11, updated_by = $12, updated_at = NOW()
        WHERE book_id = $1 AND deleted_at IS NULL
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		b.BookID, b.CategoryID, b.Title, b.Author, b.ISBN, b.Publisher, b.Edition,
		b.Language, b.Pages, b.PublicationYear, b.Description, b.UpdatedBy,
	).Scan(&b.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: book %s", ErrNotFound, b.BookID)
		}
		r.logger.Error("failed to update book", util.ErrorField(err))
		return fmt.Errorf("update book: %w", err)
	}
	return nil
}

func (r *libraryRepository) DeleteBook(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error {
	query := `UPDATE academics.library_books SET deleted_at = NOW(), updated_by = $2, updated_at = NOW() WHERE book_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, deletedBy)
	if err != nil {
		r.logger.Error("failed to delete book", util.ErrorField(err))
		return fmt.Errorf("delete book: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: book %s", ErrNotFound, id)
	}
	return nil
}

// --- Copies ---------------------------------------------------------

func (r *libraryRepository) buildCopyFilter(filter LibraryCopyFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.BookID != nil {
		conditions = append(conditions, fmt.Sprintf("cp.book_id = $%d", idx))
		args = append(args, *filter.BookID)
		idx++
	}

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("cp.status = $%d", idx))
		args = append(args, *filter.Status)
		idx++
	}

	if filter.AccessionNo != "" {
		conditions = append(conditions, fmt.Sprintf("cp.accession_no = $%d", idx))
		args = append(args, filter.AccessionNo)
		idx++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(cp.accession_no ILIKE $%d OR cp.shelf_location ILIKE $%d)", idx, idx))
		args = append(args, "%"+filter.Search+"%")
		idx++
	}

	// Copies don't have deleted_at; we only show all copies (soft delete not applicable)
	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *libraryRepository) CreateCopy(ctx context.Context, db DBTX, c *models.LibraryBookCopy) error {
	query := `
        INSERT INTO academics.library_book_copies (
            book_id, accession_no, status, purchase_date, cost, shelf_location, created_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
        RETURNING copy_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		c.BookID, c.AccessionNo, c.Status, c.PurchaseDate, c.Cost, c.ShelfLocation, c.CreatedBy,
	).Scan(&c.CopyID, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create copy", util.ErrorField(err))
		return fmt.Errorf("create copy: %w", err)
	}
	return nil
}

func (r *libraryRepository) GetCopyByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.LibraryBookCopy, error) {
	query := `
        SELECT copy_id, book_id, accession_no, status, purchase_date, cost, shelf_location,
               created_at, updated_at, created_by
        FROM academics.library_book_copies
        WHERE copy_id = $1
    `
	var c models.LibraryBookCopy
	var createdBy uuid.NullUUID

	err := db.QueryRowContext(ctx, query, id).Scan(
		&c.CopyID, &c.BookID, &c.AccessionNo, &c.Status, &c.PurchaseDate, &c.Cost, &c.ShelfLocation,
		&c.CreatedAt, &c.UpdatedAt, &createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get copy: %w", err)
	}
	if createdBy.Valid {
		c.CreatedBy = &createdBy.UUID
	}
	return &c, nil
}

func (r *libraryRepository) GetCopyByAccessionNo(ctx context.Context, db DBTX, accessionNo string) (*models.LibraryBookCopy, error) {
	query := `
        SELECT copy_id, book_id, accession_no, status, purchase_date, cost, shelf_location,
               created_at, updated_at, created_by
        FROM academics.library_book_copies
        WHERE accession_no = $1
    `
	var c models.LibraryBookCopy
	var createdBy uuid.NullUUID

	err := db.QueryRowContext(ctx, query, accessionNo).Scan(
		&c.CopyID, &c.BookID, &c.AccessionNo, &c.Status, &c.PurchaseDate, &c.Cost, &c.ShelfLocation,
		&c.CreatedAt, &c.UpdatedAt, &createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get copy by accession no: %w", err)
	}
	if createdBy.Valid {
		c.CreatedBy = &createdBy.UUID
	}
	return &c, nil
}

func (r *libraryRepository) ListCopies(ctx context.Context, db DBTX, filter LibraryCopyFilter, p Pagination, s Sort) ([]*models.LibraryBookCopy, error) {
	where, args := r.buildCopyFilter(filter)
	orderBy, err := r.validateCopySort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
        SELECT copy_id, book_id, accession_no, status, purchase_date, cost, shelf_location,
               created_at, updated_at, created_by
        FROM academics.library_book_copies cp
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list copies", util.ErrorField(err))
		return nil, fmt.Errorf("list copies: %w", err)
	}
	defer rows.Close()

	var result []*models.LibraryBookCopy
	for rows.Next() {
		var c models.LibraryBookCopy
		var createdBy uuid.NullUUID

		if err := rows.Scan(
			&c.CopyID, &c.BookID, &c.AccessionNo, &c.Status, &c.PurchaseDate, &c.Cost, &c.ShelfLocation,
			&c.CreatedAt, &c.UpdatedAt, &createdBy,
		); err != nil {
			return nil, fmt.Errorf("scan copy: %w", err)
		}
		if createdBy.Valid {
			c.CreatedBy = &createdBy.UUID
		}
		result = append(result, &c)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *libraryRepository) CountCopies(ctx context.Context, db DBTX, filter LibraryCopyFilter) (int64, error) {
	where, args := r.buildCopyFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.library_book_copies cp %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count copies", util.ErrorField(err))
		return 0, fmt.Errorf("count copies: %w", err)
	}
	return count, nil
}

func (r *libraryRepository) UpdateCopy(ctx context.Context, db DBTX, c *models.LibraryBookCopy) error {
	query := `
        UPDATE academics.library_book_copies
        SET status = $2, purchase_date = $3, cost = $4, shelf_location = $5, updated_at = NOW()
        WHERE copy_id = $1
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		c.CopyID, c.Status, c.PurchaseDate, c.Cost, c.ShelfLocation,
	).Scan(&c.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: copy %s", ErrNotFound, c.CopyID)
		}
		r.logger.Error("failed to update copy", util.ErrorField(err))
		return fmt.Errorf("update copy: %w", err)
	}
	return nil
}

func (r *libraryRepository) DeleteCopy(ctx context.Context, db DBTX, id uuid.UUID) error {
	query := `DELETE FROM academics.library_book_copies WHERE copy_id = $1`
	result, err := db.ExecContext(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete copy", util.ErrorField(err))
		return fmt.Errorf("delete copy: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: copy %s", ErrNotFound, id)
	}
	return nil
}

// --- Issues ---------------------------------------------------------

func (r *libraryRepository) buildIssueFilter(filter LibraryIssueFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.StudentID != nil {
		conditions = append(conditions, fmt.Sprintf("i.student_id = $%d", idx))
		args = append(args, *filter.StudentID)
		idx++
	}

	if filter.CopyID != nil {
		conditions = append(conditions, fmt.Sprintf("i.copy_id = $%d", idx))
		args = append(args, *filter.CopyID)
		idx++
	}

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("i.status = $%d", idx))
		args = append(args, *filter.Status)
		idx++
	}

	if filter.FromDate != nil {
		conditions = append(conditions, fmt.Sprintf("i.issue_date >= $%d", idx))
		args = append(args, *filter.FromDate)
		idx++
	}

	if filter.ToDate != nil {
		conditions = append(conditions, fmt.Sprintf("i.issue_date <= $%d", idx))
		args = append(args, *filter.ToDate)
		idx++
	}

	if filter.Overdue != nil && *filter.Overdue {
		conditions = append(conditions, "i.due_date < NOW() AND i.status = 'issued'")
	}

	// No soft delete on issues
	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *libraryRepository) IssueBook(ctx context.Context, db DBTX, issue *models.LibraryIssue) error {
	// Start a transaction to ensure copy status is updated atomically
	tx, isOwner, err := beginTxIfNotTx(ctx, db)
	if err != nil {
		return err
	}
	needRollback := isOwner
	defer func() {
		if needRollback {
			_ = tx.Rollback()
		}
	}()

	// Insert the issue record
	query := `
        INSERT INTO academics.library_issues (
            copy_id, student_id, issue_date, due_date, status, issued_by, created_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
        RETURNING issue_id, created_at, updated_at
    `
	err = tx.QueryRowContext(ctx, query,
		issue.CopyID, issue.StudentID, issue.IssueDate, issue.DueDate, issue.Status,
		issue.IssuedBy, issue.CreatedBy,
	).Scan(&issue.IssueID, &issue.CreatedAt, &issue.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create issue", util.ErrorField(err))
		return fmt.Errorf("create issue: %w", err)
	}

	// Update copy status to issued
	updateCopy := `UPDATE academics.library_book_copies SET status = 'issued', updated_at = NOW() WHERE copy_id = $1`
	_, err = tx.ExecContext(ctx, updateCopy, issue.CopyID)
	if err != nil {
		r.logger.Error("failed to update copy status during issue", util.ErrorField(err))
		return fmt.Errorf("update copy status: %w", err)
	}

	if isOwner {
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit transaction: %w", err)
		}
		needRollback = false
	}
	return nil
}

func (r *libraryRepository) GetIssueByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.LibraryIssue, error) {
	query := `
        SELECT issue_id, copy_id, student_id, issue_date, due_date, returned_date, status, issued_by,
               created_at, updated_at, created_by
        FROM academics.library_issues
        WHERE issue_id = $1
    `
	var i models.LibraryIssue
	var returnedDate sql.NullTime
	var issuedBy, createdBy uuid.NullUUID

	err := db.QueryRowContext(ctx, query, id).Scan(
		&i.IssueID, &i.CopyID, &i.StudentID, &i.IssueDate, &i.DueDate, &returnedDate, &i.Status,
		&issuedBy, &i.CreatedAt, &i.UpdatedAt, &createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get issue: %w", err)
	}
	if returnedDate.Valid {
		i.ReturnedDate = &returnedDate.Time
	}
	if issuedBy.Valid {
		i.IssuedBy = &issuedBy.UUID
	}
	if createdBy.Valid {
		i.CreatedBy = &createdBy.UUID
	}
	return &i, nil
}

func (r *libraryRepository) ListIssues(ctx context.Context, db DBTX, filter LibraryIssueFilter, p Pagination, s Sort) ([]*models.LibraryIssue, error) {
	where, args := r.buildIssueFilter(filter)
	orderBy, err := r.validateIssueSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
        SELECT issue_id, copy_id, student_id, issue_date, due_date, returned_date, status, issued_by,
               created_at, updated_at, created_by
        FROM academics.library_issues i
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list issues", util.ErrorField(err))
		return nil, fmt.Errorf("list issues: %w", err)
	}
	defer rows.Close()

	var result []*models.LibraryIssue
	for rows.Next() {
		var i models.LibraryIssue
		var returnedDate sql.NullTime
		var issuedBy, createdBy uuid.NullUUID

		if err := rows.Scan(
			&i.IssueID, &i.CopyID, &i.StudentID, &i.IssueDate, &i.DueDate, &returnedDate, &i.Status,
			&issuedBy, &i.CreatedAt, &i.UpdatedAt, &createdBy,
		); err != nil {
			return nil, fmt.Errorf("scan issue: %w", err)
		}
		if returnedDate.Valid {
			i.ReturnedDate = &returnedDate.Time
		}
		if issuedBy.Valid {
			i.IssuedBy = &issuedBy.UUID
		}
		if createdBy.Valid {
			i.CreatedBy = &createdBy.UUID
		}
		result = append(result, &i)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *libraryRepository) CountIssues(ctx context.Context, db DBTX, filter LibraryIssueFilter) (int64, error) {
	where, args := r.buildIssueFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.library_issues i %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count issues", util.ErrorField(err))
		return 0, fmt.Errorf("count issues: %w", err)
	}
	return count, nil
}

func (r *libraryRepository) ReturnBook(ctx context.Context, db DBTX, issueID uuid.UUID, returnDate time.Time, fineAmount float64, remarks string, receivedBy *uuid.UUID) error {
	tx, isOwner, err := beginTxIfNotTx(ctx, db)
	if err != nil {
		return err
	}
	needRollback := isOwner
	defer func() {
		if needRollback {
			_ = tx.Rollback()
		}
	}()

	// Update issue: set returned_date, status, updated_at
	updateIssue := `
        UPDATE academics.library_issues
        SET returned_date = $2, status = 'returned', updated_at = NOW()
        WHERE issue_id = $1 AND status IN ('issued', 'overdue')
        RETURNING copy_id
    `
	var copyID uuid.UUID
	err = tx.QueryRowContext(ctx, updateIssue, issueID, returnDate).Scan(&copyID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("issue %s not found or already returned", issueID)
		}
		r.logger.Error("failed to update issue during return", util.ErrorField(err))
		return fmt.Errorf("update issue: %w", err)
	}

	// Update copy status to available
	updateCopy := `UPDATE academics.library_book_copies SET status = 'available', updated_at = NOW() WHERE copy_id = $1`
	_, err = tx.ExecContext(ctx, updateCopy, copyID)
	if err != nil {
		r.logger.Error("failed to update copy status during return", util.ErrorField(err))
		return fmt.Errorf("update copy: %w", err)
	}

	// Insert into library_returns
	insertReturn := `
        INSERT INTO academics.library_returns (issue_id, return_date, fine_amount, remarks, received_by, created_at, created_by)
        VALUES ($1, $2, $3, $4, $5, NOW(), $6)
        RETURNING return_id
    `
	var returnID uuid.UUID
	err = tx.QueryRowContext(ctx, insertReturn, issueID, returnDate, fineAmount, remarks, receivedBy, receivedBy).Scan(&returnID)
	if err != nil {
		r.logger.Error("failed to create return record", util.ErrorField(err))
		return fmt.Errorf("create return: %w", err)
	}

	// If fine is > 0, also insert into library_fines
	if fineAmount > 0 {
		insertFine := `
            INSERT INTO academics.library_fines (issue_id, fine_amount, paid, created_at, updated_at, created_by)
            VALUES ($1, $2, false, NOW(), NOW(), $3)
        `
		_, err = tx.ExecContext(ctx, insertFine, issueID, fineAmount, receivedBy)
		if err != nil {
			r.logger.Error("failed to create fine record", util.ErrorField(err))
			return fmt.Errorf("create fine: %w", err)
		}
	}

	if isOwner {
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit transaction: %w", err)
		}
		needRollback = false
	}
	return nil
}

func (r *libraryRepository) UpdateIssueStatus(ctx context.Context, db DBTX, issueID uuid.UUID, status models.IssueStatus, updatedBy *uuid.UUID) error {
	query := `UPDATE academics.library_issues SET status = $2, updated_at = NOW() WHERE issue_id = $1`
	result, err := db.ExecContext(ctx, query, issueID, status)
	if err != nil {
		r.logger.Error("failed to update issue status", util.ErrorField(err))
		return fmt.Errorf("update issue status: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: issue %s", ErrNotFound, issueID)
	}
	return nil
}

// --- Returns ---------------------------------------------------------

func (r *libraryRepository) GetReturnByIssueID(ctx context.Context, db DBTX, issueID uuid.UUID) (*models.LibraryReturn, error) {
	query := `
        SELECT return_id, issue_id, return_date, fine_amount, remarks, received_by, created_at, created_by
        FROM academics.library_returns
        WHERE issue_id = $1
    `
	var ret models.LibraryReturn
	var receivedBy, createdBy uuid.NullUUID

	err := db.QueryRowContext(ctx, query, issueID).Scan(
		&ret.ReturnID, &ret.IssueID, &ret.ReturnDate, &ret.FineAmount, &ret.Remarks,
		&receivedBy, &ret.CreatedAt, &createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get return: %w", err)
	}
	if receivedBy.Valid {
		ret.ReceivedBy = &receivedBy.UUID
	}
	if createdBy.Valid {
		ret.CreatedBy = &createdBy.UUID
	}
	return &ret, nil
}

// --- Fines ---------------------------------------------------------

func (r *libraryRepository) CreateFine(ctx context.Context, db DBTX, fine *models.LibraryFine) error {
	query := `
        INSERT INTO academics.library_fines (issue_id, fine_amount, paid, created_at, updated_at, created_by)
        VALUES ($1, $2, $3, NOW(), NOW(), $4)
        RETURNING fine_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query, fine.IssueID, fine.FineAmount, fine.Paid, fine.CreatedBy).Scan(&fine.FineID, &fine.CreatedAt, &fine.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create fine", util.ErrorField(err))
		return fmt.Errorf("create fine: %w", err)
	}
	return nil
}

func (r *libraryRepository) UpdateFinePayment(ctx context.Context, db DBTX, fineID uuid.UUID, paid bool, paidDate *time.Time, paymentMode string) error {
	query := `
        UPDATE academics.library_fines
        SET paid = $2, paid_date = $3, payment_mode = $4, updated_at = NOW()
        WHERE fine_id = $1
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query, fineID, paid, paidDate, paymentMode).Scan(new(time.Time))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: fine %s", ErrNotFound, fineID)
		}
		r.logger.Error("failed to update fine payment", util.ErrorField(err))
		return fmt.Errorf("update fine payment: %w", err)
	}
	return nil
}

func (r *libraryRepository) ListFines(ctx context.Context, db DBTX, studentID *uuid.UUID, paid *bool) ([]*models.LibraryFine, error) {
	// Build query with optional joins to filter by student
	var conditions []string
	var args []interface{}
	idx := 1

	if studentID != nil {
		conditions = append(conditions, fmt.Sprintf("i.student_id = $%d", idx))
		args = append(args, *studentID)
		idx++
	}
	if paid != nil {
		conditions = append(conditions, fmt.Sprintf("f.paid = $%d", idx))
		args = append(args, *paid)
		idx++
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	query := fmt.Sprintf(`
        SELECT f.fine_id, f.issue_id, f.fine_amount, f.paid, f.paid_date, f.payment_mode,
               f.created_at, f.updated_at, f.created_by
        FROM academics.library_fines f
        LEFT JOIN academics.library_issues i ON f.issue_id = i.issue_id
        %s
        ORDER BY f.created_at DESC
    `, where)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list fines", util.ErrorField(err))
		return nil, fmt.Errorf("list fines: %w", err)
	}
	defer rows.Close()

	var result []*models.LibraryFine
	for rows.Next() {
		var f models.LibraryFine
		var paidDate sql.NullTime
		var createdBy uuid.NullUUID

		if err := rows.Scan(
			&f.FineID, &f.IssueID, &f.FineAmount, &f.Paid, &paidDate, &f.PaymentMode,
			&f.CreatedAt, &f.UpdatedAt, &createdBy,
		); err != nil {
			return nil, fmt.Errorf("scan fine: %w", err)
		}
		if paidDate.Valid {
			f.PaidDate = &paidDate.Time
		}
		if createdBy.Valid {
			f.CreatedBy = &createdBy.UUID
		}
		result = append(result, &f)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// --- Domain Helpers -------------------------------------------------

func (r *libraryRepository) GetAvailableCopies(ctx context.Context, db DBTX, bookID uuid.UUID) (int, error) {
	query := `SELECT COUNT(*) FROM academics.library_book_copies WHERE book_id = $1 AND status = 'available'`
	var count int64
	err := db.QueryRowContext(ctx, query, bookID).Scan(&count)
	if err != nil {
		r.logger.Error("failed to get available copies", util.ErrorField(err))
		return 0, fmt.Errorf("get available copies: %w", err)
	}
	return int(count), nil
}

func (r *libraryRepository) HasOverdueIssues(ctx context.Context, db DBTX, studentID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM academics.library_issues WHERE student_id = $1 AND due_date < NOW() AND status = 'issued')`
	var exists bool
	err := db.QueryRowContext(ctx, query, studentID).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check overdue issues", util.ErrorField(err))
		return false, fmt.Errorf("check overdue: %w", err)
	}
	return exists, nil
}
