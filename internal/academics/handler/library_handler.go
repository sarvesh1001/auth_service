package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/repository"
	"auth-service/internal/academics/service"
)

type LibraryHandler struct {
	libraryService service.LibraryService
	logger         *zap.Logger
}

func NewLibraryHandler(libraryService service.LibraryService, logger *zap.Logger) *LibraryHandler {
	return &LibraryHandler{
		libraryService: libraryService,
		logger:         logger.Named("library_handler"),
	}
}

// ----------------------------------------------------------------------------
// Categories
// ----------------------------------------------------------------------------

// CreateCategory handles POST /api/v1/companies/{companyID}/library/categories
func (h *LibraryHandler) CreateCategory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromURL(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "library:category:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateCategoryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.CompanyID = companyID
	req.CreatedBy = &userID
	req.UpdatedBy = &userID

	idempotencyKey := r.Header.Get("X-Idempotency-Key")

	category, err := h.libraryService.CreateCategory(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to create library category",
			zap.String("company_id", companyID.String()),
			zap.String("name", req.CategoryName),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    category,
		"message": "Category created successfully",
	})
}

// GetCategory handles GET /api/v1/companies/{companyID}/library/categories/{categoryID}
func (h *LibraryHandler) GetCategory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromURL(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	categoryID, err := getUUIDFromURL(r, "categoryID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid category ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "library:category:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	category, err := h.libraryService.GetCategoryByID(ctx, categoryID)
	if err != nil {
		h.logger.Error("Failed to get category",
			zap.String("category_id", categoryID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    category,
	})
}

// ListCategories handles GET /api/v1/companies/{companyID}/library/categories
func (h *LibraryHandler) ListCategories(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromURL(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "library:category:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Filter
	filter := repository.LibraryCategoryFilter{
		CompanyID: companyID,
	}
	if search := r.URL.Query().Get("search"); search != "" {
		filter.Search = search
	}

	// Pagination
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	// Sorting
	sortField := r.URL.Query().Get("sort_field")
	if sortField == "" {
		sortField = "category_name"
	}
	sortDirection := r.URL.Query().Get("sort_direction")
	if sortDirection == "" {
		sortDirection = "ASC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDirection}

	categories, total, err := h.libraryService.ListCategories(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list categories",
			zap.Any("filter", filter),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list categories")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"categories": categories,
			"total":      total,
			"limit":      limit,
			"offset":     offset,
		},
	})
}

// UpdateCategory handles PUT /api/v1/companies/{companyID}/library/categories/{categoryID}
func (h *LibraryHandler) UpdateCategory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromURL(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	categoryID, err := getUUIDFromURL(r, "categoryID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid category ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "library:category:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateCategoryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.CategoryID = categoryID
	req.UpdatedBy = &userID

	category, err := h.libraryService.UpdateCategory(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update category",
			zap.String("category_id", categoryID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    category,
		"message": "Category updated successfully",
	})
}

// DeleteCategory handles DELETE /api/v1/companies/{companyID}/library/categories/{categoryID}
func (h *LibraryHandler) DeleteCategory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromURL(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	categoryID, err := getUUIDFromURL(r, "categoryID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid category ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "library:category:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.libraryService.DeleteCategory(ctx, categoryID, &userID)
	if err != nil {
		h.logger.Error("Failed to delete category",
			zap.String("category_id", categoryID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Category deleted successfully",
	})
}

// ----------------------------------------------------------------------------
// Books
// ----------------------------------------------------------------------------

// CreateBook handles POST /api/v1/companies/{companyID}/library/books
func (h *LibraryHandler) CreateBook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromURL(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "library:book:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateBookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.CompanyID = companyID
	req.CreatedBy = &userID
	req.UpdatedBy = &userID

	idempotencyKey := r.Header.Get("X-Idempotency-Key")

	book, err := h.libraryService.CreateBook(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to create book",
			zap.String("company_id", companyID.String()),
			zap.String("title", req.Title),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    book,
		"message": "Book created successfully",
	})
}

// GetBook handles GET /api/v1/companies/{companyID}/library/books/{bookID}
func (h *LibraryHandler) GetBook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromURL(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	bookID, err := getUUIDFromURL(r, "bookID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid book ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "library:book:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	book, err := h.libraryService.GetBookByID(ctx, bookID)
	if err != nil {
		h.logger.Error("Failed to get book",
			zap.String("book_id", bookID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    book,
	})
}

// GetBookByISBN handles GET /api/v1/companies/{companyID}/library/books/isbn/{isbn}
func (h *LibraryHandler) GetBookByISBN(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromURL(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	isbn := chi.URLParam(r, "isbn")
	if isbn == "" {
		h.respondWithError(w, http.StatusBadRequest, "ISBN is required")
		return
	}

	if !h.hasPermission(ctx, companyID, "library:book:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	book, err := h.libraryService.GetBookByISBN(ctx, companyID, isbn)
	if err != nil {
		h.logger.Error("Failed to get book by ISBN",
			zap.String("company_id", companyID.String()),
			zap.String("isbn", isbn),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    book,
	})
}

// ListBooks handles GET /api/v1/companies/{companyID}/library/books
func (h *LibraryHandler) ListBooks(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromURL(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "library:book:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Filter
	filter := repository.LibraryBookFilter{
		CompanyID: companyID,
	}
	if categoryIDStr := r.URL.Query().Get("category_id"); categoryIDStr != "" {
		if categoryID, err := uuid.Parse(categoryIDStr); err == nil {
			filter.CategoryID = &categoryID
		}
	}
	if title := r.URL.Query().Get("title"); title != "" {
		filter.Title = title // was &title
	}
	if author := r.URL.Query().Get("author"); author != "" {
		filter.Author = author // was &author
	}
	if isbn := r.URL.Query().Get("isbn"); isbn != "" {
		filter.ISBN = isbn // was &isbn
	}
	if search := r.URL.Query().Get("search"); search != "" {
		filter.Search = search
	}

	// Pagination
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	// Sorting
	sortField := r.URL.Query().Get("sort_field")
	if sortField == "" {
		sortField = "title"
	}
	sortDirection := r.URL.Query().Get("sort_direction")
	if sortDirection == "" {
		sortDirection = "ASC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDirection}

	books, total, err := h.libraryService.ListBooks(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list books",
			zap.Any("filter", filter),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list books")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"books":  books,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		},
	})
}

// UpdateBook handles PUT /api/v1/companies/{companyID}/library/books/{bookID}
func (h *LibraryHandler) UpdateBook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromURL(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	bookID, err := getUUIDFromURL(r, "bookID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid book ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "library:book:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateBookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.BookID = bookID
	req.UpdatedBy = &userID

	book, err := h.libraryService.UpdateBook(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update book",
			zap.String("book_id", bookID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    book,
		"message": "Book updated successfully",
	})
}

// DeleteBook handles DELETE /api/v1/companies/{companyID}/library/books/{bookID}
func (h *LibraryHandler) DeleteBook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromURL(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	bookID, err := getUUIDFromURL(r, "bookID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid book ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "library:book:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.libraryService.DeleteBook(ctx, bookID, &userID)
	if err != nil {
		h.logger.Error("Failed to delete book",
			zap.String("book_id", bookID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Book deleted successfully",
	})
}

// ----------------------------------------------------------------------------
// Copies
// ----------------------------------------------------------------------------

// CreateCopy handles POST /api/v1/companies/{companyID}/library/copies
func (h *LibraryHandler) CreateCopy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromURL(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "library:copy:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateCopyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.CreatedBy = &userID

	idempotencyKey := r.Header.Get("X-Idempotency-Key")

	copy, err := h.libraryService.CreateCopy(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to create copy",
			zap.String("company_id", companyID.String()),
			zap.String("book_id", req.BookID.String()),
			zap.String("accession_no", req.AccessionNo),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    copy,
		"message": "Copy created successfully",
	})
}

// GetCopy handles GET /api/v1/companies/{companyID}/library/copies/{copyID}
func (h *LibraryHandler) GetCopy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromURL(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	copyID, err := getUUIDFromURL(r, "copyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid copy ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "library:copy:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	copy, err := h.libraryService.GetCopyByID(ctx, copyID)
	if err != nil {
		h.logger.Error("Failed to get copy",
			zap.String("copy_id", copyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    copy,
	})
}

// GetCopyByAccessionNo handles GET /api/v1/companies/{companyID}/library/copies/accession/{accessionNo}
func (h *LibraryHandler) GetCopyByAccessionNo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromURL(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	accessionNo := chi.URLParam(r, "accessionNo")
	if accessionNo == "" {
		h.respondWithError(w, http.StatusBadRequest, "accession number is required")
		return
	}

	if !h.hasPermission(ctx, companyID, "library:copy:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	copy, err := h.libraryService.GetCopyByAccessionNo(ctx, accessionNo)
	if err != nil {
		h.logger.Error("Failed to get copy by accession number",
			zap.String("company_id", companyID.String()),
			zap.String("accession_no", accessionNo),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    copy,
	})
}

// ListCopies handles GET /api/v1/companies/{companyID}/library/copies
func (h *LibraryHandler) ListCopies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromURL(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "library:copy:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Filter
	filter := repository.LibraryCopyFilter{}
	if bookIDStr := r.URL.Query().Get("book_id"); bookIDStr != "" {
		if bookID, err := uuid.Parse(bookIDStr); err == nil {
			filter.BookID = &bookID
		}
	}
	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = &status
	}
	if accessionNo := r.URL.Query().Get("accession_no"); accessionNo != "" {
		filter.AccessionNo = accessionNo // was &accessionNo
	}
	if search := r.URL.Query().Get("search"); search != "" {
		filter.Search = search
	}

	// Pagination
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	// Sorting
	sortField := r.URL.Query().Get("sort_field")
	if sortField == "" {
		sortField = "accession_no"
	}
	sortDirection := r.URL.Query().Get("sort_direction")
	if sortDirection == "" {
		sortDirection = "ASC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDirection}

	copies, total, err := h.libraryService.ListCopies(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list copies",
			zap.Any("filter", filter),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list copies")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"copies": copies,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		},
	})
}

// UpdateCopy handles PUT /api/v1/companies/{companyID}/library/copies/{copyID}
func (h *LibraryHandler) UpdateCopy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromURL(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	copyID, err := getUUIDFromURL(r, "copyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid copy ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "library:copy:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateCopyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.CopyID = copyID

	copy, err := h.libraryService.UpdateCopy(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update copy",
			zap.String("copy_id", copyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    copy,
		"message": "Copy updated successfully",
	})
}

// DeleteCopy handles DELETE /api/v1/companies/{companyID}/library/copies/{copyID}
func (h *LibraryHandler) DeleteCopy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromURL(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	copyID, err := getUUIDFromURL(r, "copyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid copy ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "library:copy:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.libraryService.DeleteCopy(ctx, copyID)
	if err != nil {
		h.logger.Error("Failed to delete copy",
			zap.String("copy_id", copyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Copy deleted successfully",
	})
}

// ----------------------------------------------------------------------------
// Issue / Return
// ----------------------------------------------------------------------------

// IssueBook handles POST /api/v1/companies/{companyID}/library/issues
func (h *LibraryHandler) IssueBook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromURL(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "library:issue:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.IssueBookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.IssuedBy = &userID
	req.CreatedBy = &userID

	idempotencyKey := r.Header.Get("X-Idempotency-Key")

	issue, err := h.libraryService.IssueBook(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to issue book",
			zap.String("company_id", companyID.String()),
			zap.String("copy_id", req.CopyID.String()),
			zap.String("student_id", req.StudentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    issue,
		"message": "Book issued successfully",
	})
}

// GetIssue handles GET /api/v1/companies/{companyID}/library/issues/{issueID}
func (h *LibraryHandler) GetIssue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromURL(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	issueID, err := getUUIDFromURL(r, "issueID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid issue ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "library:issue:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	issue, err := h.libraryService.GetIssueByID(ctx, issueID)
	if err != nil {
		h.logger.Error("Failed to get issue",
			zap.String("issue_id", issueID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    issue,
	})
}

// ListIssues handles GET /api/v1/companies/{companyID}/library/issues
func (h *LibraryHandler) ListIssues(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromURL(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "library:issue:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Filter
	filter := repository.LibraryIssueFilter{}
	if studentIDStr := r.URL.Query().Get("student_id"); studentIDStr != "" {
		if studentID, err := uuid.Parse(studentIDStr); err == nil {
			filter.StudentID = &studentID
		}
	}
	if copyIDStr := r.URL.Query().Get("copy_id"); copyIDStr != "" {
		if copyID, err := uuid.Parse(copyIDStr); err == nil {
			filter.CopyID = &copyID
		}
	}
	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = &status
	}
	if fromDateStr := r.URL.Query().Get("from_date"); fromDateStr != "" {
		if fromDate, err := time.Parse("2006-01-02", fromDateStr); err == nil {
			filter.FromDate = &fromDate
		}
	}
	if toDateStr := r.URL.Query().Get("to_date"); toDateStr != "" {
		if toDate, err := time.Parse("2006-01-02", toDateStr); err == nil {
			filter.ToDate = &toDate
		}
	}

	// Pagination
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	// Sorting
	sortField := r.URL.Query().Get("sort_field")
	if sortField == "" {
		sortField = "issue_date"
	}
	sortDirection := r.URL.Query().Get("sort_direction")
	if sortDirection == "" {
		sortDirection = "DESC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDirection}

	issues, total, err := h.libraryService.ListIssues(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list issues",
			zap.Any("filter", filter),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list issues")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"issues": issues,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		},
	})
}

// ReturnBook handles POST /api/v1/companies/{companyID}/library/returns
func (h *LibraryHandler) ReturnBook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromURL(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "library:return:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.ReturnBookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.ReceivedBy = &userID

	returnRecord, err := h.libraryService.ReturnBook(ctx, req)
	if err != nil {
		h.logger.Error("Failed to return book",
			zap.String("company_id", companyID.String()),
			zap.String("issue_id", req.IssueID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    returnRecord,
		"message": "Book returned successfully",
	})
}

// ----------------------------------------------------------------------------
// Fines
// ----------------------------------------------------------------------------

// CreateFine handles POST /api/v1/companies/{companyID}/library/fines
func (h *LibraryHandler) CreateFine(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromURL(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "library:fine:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateFineRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.CreatedBy = &userID

	fine, err := h.libraryService.CreateFine(ctx, req)
	if err != nil {
		h.logger.Error("Failed to create fine",
			zap.String("company_id", companyID.String()),
			zap.String("issue_id", req.IssueID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    fine,
		"message": "Fine created successfully",
	})
}

// UpdateFinePayment handles PATCH /api/v1/companies/{companyID}/library/fines/{fineID}/payment
func (h *LibraryHandler) UpdateFinePayment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromURL(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	fineID, err := getUUIDFromURL(r, "fineID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid fine ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "library:fine:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateFinePaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.FineID = fineID

	err = h.libraryService.UpdateFinePayment(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update fine payment",
			zap.String("fine_id", fineID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Fine payment updated successfully",
	})
}

// ListFines handles GET /api/v1/companies/{companyID}/library/fines
func (h *LibraryHandler) ListFines(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromURL(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "library:fine:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var studentID *uuid.UUID
	if studentIDStr := r.URL.Query().Get("student_id"); studentIDStr != "" {
		if id, err := uuid.Parse(studentIDStr); err == nil {
			studentID = &id
		}
	}

	var paid *bool
	if paidStr := r.URL.Query().Get("paid"); paidStr != "" {
		b, err := strconv.ParseBool(paidStr)
		if err == nil {
			paid = &b
		}
	}

	fines, err := h.libraryService.ListFines(ctx, studentID, paid)
	if err != nil {
		h.logger.Error("Failed to list fines",
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list fines")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    fines,
	})
}

// ----------------------------------------------------------------------------
// Utility
// ----------------------------------------------------------------------------

// GetAvailableCopies handles GET /api/v1/companies/{companyID}/library/books/{bookID}/available-copies
func (h *LibraryHandler) GetAvailableCopies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromURL(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	bookID, err := getUUIDFromURL(r, "bookID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid book ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "library:book:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	count, err := h.libraryService.GetAvailableCopies(ctx, bookID)
	if err != nil {
		h.logger.Error("Failed to get available copies",
			zap.String("book_id", bookID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get available copies")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"book_id":          bookID,
			"available_copies": count,
		},
	})
}

// HasOverdueIssues handles GET /api/v1/companies/{companyID}/library/students/{studentID}/overdue
func (h *LibraryHandler) HasOverdueIssues(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromURL(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	studentID, err := getUUIDFromURL(r, "studentID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "library:issue:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	hasOverdue, err := h.libraryService.HasOverdueIssues(ctx, studentID)
	if err != nil {
		h.logger.Error("Failed to check overdue issues",
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check overdue issues")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"student_id":  studentID,
			"has_overdue": hasOverdue,
		},
	})
}

// ----------------------------------------------------------------------------
// Helper functions
// ----------------------------------------------------------------------------

func (h *LibraryHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	// Placeholder – implement actual permission check
	return true
}

func (h *LibraryHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *LibraryHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

// Helper to get company ID from URL
func getCompanyIDFromURL(r *http.Request, param string) (uuid.UUID, error) {
	str := chi.URLParam(r, param)
	if str == "" {
		return uuid.Nil, fmt.Errorf("missing %s", param)
	}
	return uuid.Parse(str)
}

// Helper to get UUID from URL
func getUUIDFromURL(r *http.Request, param string) (uuid.UUID, error) {
	str := chi.URLParam(r, param)
	if str == "" {
		return uuid.Nil, fmt.Errorf("missing %s", param)
	}
	return uuid.Parse(str)
}
