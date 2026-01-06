package handler

import (
	"auth-service/internal/hr/models/employee"
	"auth-service/internal/hr/service"
	"auth-service/internal/util"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// EmployeeHandler handles HTTP requests for employee operations
type EmployeeHandler struct {
	employeeService      *service.EmployeeService
	employeeQueryService *service.EmployeeQueryService
	auditService         *service.AuditService
	logger               *zap.Logger
	maxDocumentSizeMB    int
}

// NewEmployeeHandler creates a new employee handler
func NewEmployeeHandler(
	employeeService *service.EmployeeService,
	employeeQueryService *service.EmployeeQueryService,
	auditService *service.AuditService,
	logger *zap.Logger,
	maxDocumentSizeMB int,
) *EmployeeHandler {
	if maxDocumentSizeMB <= 0 {
		maxDocumentSizeMB = 50
	}

	return &EmployeeHandler{
		employeeService:      employeeService,
		employeeQueryService: employeeQueryService,
		auditService:         auditService,
		logger:               logger,
		maxDocumentSizeMB:    maxDocumentSizeMB,
	}
}

// ============================================================================
// EMPLOYEE PROFILE HANDLERS
// ============================================================================

// CreateEmployeeProfileRequest represents the request to create an employee profile
type CreateEmployeeProfileRequest struct {
	UserID           uuid.UUID  `json:"user_id" validate:"required"`
	DateOfBirth      *time.Time `json:"date_of_birth,omitempty"`
	Gender           *string    `json:"gender,omitempty"`
	MaritalStatus    *string    `json:"marital_status,omitempty"`
	Nationality      *string    `json:"nationality,omitempty"`
	EmploymentType   *string    `json:"employment_type,omitempty"`
	EmploymentStatus *string    `json:"employment_status,omitempty"`
	ProbationEndDate *time.Time `json:"probation_end_date,omitempty"`
	ConfirmationDate *time.Time `json:"confirmation_date,omitempty"`
	JobTitle         *string    `json:"job_title,omitempty"`
	Grade            *string    `json:"grade,omitempty"`
	CostCenter       *string    `json:"cost_center,omitempty"`
	TaxID            *string    `json:"tax_id,omitempty"`
	SocialSecurityID *string    `json:"social_security_id,omitempty"`
}

// CreateEmployeeProfile creates a new employee profile
func (h *EmployeeHandler) CreateEmployeeProfile(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Get company ID from URL params
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// Get actor info from context
	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse request
	var req CreateEmployeeProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate required fields
	if req.UserID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "User ID is required")
		return
	}

	// Create employee profile
	profile := &employee.EmployeeProfile{
		EmployeeProfileID: uuid.New(),
		UserID:            req.UserID,
		CompanyID:         companyID,
		DateOfBirth:       req.DateOfBirth,
		Gender:            req.Gender,
		MaritalStatus:     req.MaritalStatus,
		Nationality:       req.Nationality,
		EmploymentType:    req.EmploymentType,
		EmploymentStatus:  req.EmploymentStatus,
		ProbationEndDate:  req.ProbationEndDate,
		ConfirmationDate:  req.ConfirmationDate,
		JobTitle:          req.JobTitle,
		Grade:             req.Grade,
		CostCenter:        req.CostCenter,
		TaxID:             req.TaxID,
		SocialSecurityID:  req.SocialSecurityID,
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}

	// Prepare metadata for audit
	metadata := map[string]interface{}{
		"ip_address":     r.RemoteAddr,
		"user_agent":     r.UserAgent(),
		"endpoint":       r.URL.Path,
		"request_method": r.Method,
	}

	createdProfile, err := h.employeeService.CreateEmployeeProfile(
		ctx,
		profile,
		actorType,
		actorID,
		metadata,
	)
	if err != nil {
		h.logger.Error("Failed to create employee profile",
			util.String("company_id", companyID.String()),
			util.String("user_id", req.UserID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to create employee profile")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    createdProfile,
		"message": "Employee profile created successfully",
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

// GetEmployeeProfile retrieves an employee profile
func (h *EmployeeHandler) GetEmployeeProfile(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Get company ID from URL params
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// Get employee ID from URL params
	employeeIDStr := chi.URLParam(r, "employeeID")
	employeeID, err := uuid.Parse(employeeIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid employee ID")
		return
	}

	profile, err := h.employeeQueryService.GetEmployeeProfile(ctx, employeeID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Employee profile not found")
		} else {
			h.logger.Error("Failed to get employee profile",
				util.String("company_id", companyID.String()),
				util.String("employee_id", employeeID.String()),
				util.ErrorField(err))
			h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve employee profile")
		}
		return
	}

	// Check if profile belongs to the company
	if profile.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "Employee does not belong to this company")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    profile,
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

// GetEmployeeProfileByUserID retrieves employee profile by user ID
func (h *EmployeeHandler) GetEmployeeProfileByUserID(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Get company ID from URL params
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// Get user ID from URL params
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	profile, err := h.employeeQueryService.GetEmployeeProfileByUserID(ctx, userID, companyID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Employee profile not found")
		} else {
			h.logger.Error("Failed to get employee profile by user ID",
				util.String("company_id", companyID.String()),
				util.String("user_id", userID.String()),
				util.ErrorField(err))
			h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve employee profile")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    profile,
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

// UpdateEmployeeProfileRequest represents the request to update an employee profile
type UpdateEmployeeProfileRequest struct {
	DateOfBirth      *time.Time `json:"date_of_birth,omitempty"`
	Gender           *string    `json:"gender,omitempty"`
	MaritalStatus    *string    `json:"marital_status,omitempty"`
	Nationality      *string    `json:"nationality,omitempty"`
	EmploymentType   *string    `json:"employment_type,omitempty"`
	EmploymentStatus *string    `json:"employment_status,omitempty"`
	ProbationEndDate *time.Time `json:"probation_end_date,omitempty"`
	ConfirmationDate *time.Time `json:"confirmation_date,omitempty"`
	JobTitle         *string    `json:"job_title,omitempty"`
	Grade            *string    `json:"grade,omitempty"`
	CostCenter       *string    `json:"cost_center,omitempty"`
	TaxID            *string    `json:"tax_id,omitempty"`
	SocialSecurityID *string    `json:"social_security_id,omitempty"`
}

// UpdateEmployeeProfile updates an employee profile
func (h *EmployeeHandler) UpdateEmployeeProfile(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Get company ID from URL params
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// Get employee ID from URL params
	employeeIDStr := chi.URLParam(r, "employeeID")
	employeeID, err := uuid.Parse(employeeIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid employee ID")
		return
	}

	// Get actor info from context
	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse request
	var req UpdateEmployeeProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Convert request to updates map
	updates := make(map[string]interface{})
	if req.DateOfBirth != nil {
		updates["date_of_birth"] = *req.DateOfBirth
	}
	if req.Gender != nil {
		updates["gender"] = *req.Gender
	}
	if req.MaritalStatus != nil {
		updates["marital_status"] = *req.MaritalStatus
	}
	if req.Nationality != nil {
		updates["nationality"] = *req.Nationality
	}
	if req.EmploymentType != nil {
		updates["employment_type"] = *req.EmploymentType
	}
	if req.EmploymentStatus != nil {
		updates["employment_status"] = *req.EmploymentStatus
	}
	if req.ProbationEndDate != nil {
		updates["probation_end_date"] = *req.ProbationEndDate
	}
	if req.ConfirmationDate != nil {
		updates["confirmation_date"] = *req.ConfirmationDate
	}
	if req.JobTitle != nil {
		updates["job_title"] = *req.JobTitle
	}
	if req.Grade != nil {
		updates["grade"] = *req.Grade
	}
	if req.CostCenter != nil {
		updates["cost_center"] = *req.CostCenter
	}
	if req.TaxID != nil {
		updates["tax_id"] = *req.TaxID
	}
	if req.SocialSecurityID != nil {
		updates["social_security_id"] = *req.SocialSecurityID
	}

	if len(updates) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "No update fields provided")
		return
	}

	// Prepare metadata for audit
	metadata := map[string]interface{}{
		"ip_address":     r.RemoteAddr,
		"user_agent":     r.UserAgent(),
		"endpoint":       r.URL.Path,
		"request_method": r.Method,
		"updated_fields": updates,
	}

	updatedProfile, err := h.employeeService.UpdateEmployeeProfile(
		ctx,
		employeeID,
		updates,
		actorType,
		actorID,
		metadata,
	)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Employee profile not found")
		} else {
			h.logger.Error("Failed to update employee profile",
				util.String("company_id", companyID.String()),
				util.String("employee_id", employeeID.String()),
				util.ErrorField(err))
			h.respondWithError(w, http.StatusInternalServerError, "Failed to update employee profile")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    updatedProfile,
		"message": "Employee profile updated successfully",
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

// DeleteEmployeeProfile deletes an employee profile
func (h *EmployeeHandler) DeleteEmployeeProfile(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Get company ID from URL params
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// Get employee ID from URL params
	employeeIDStr := chi.URLParam(r, "employeeID")
	employeeID, err := uuid.Parse(employeeIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid employee ID")
		return
	}

	// Get actor info from context
	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Prepare metadata for audit
	metadata := map[string]interface{}{
		"ip_address":     r.RemoteAddr,
		"user_agent":     r.UserAgent(),
		"endpoint":       r.URL.Path,
		"request_method": r.Method,
	}

	err = h.employeeService.DeleteEmployeeProfile(
		ctx,
		employeeID,
		actorType,
		actorID,
		metadata,
	)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Employee profile not found")
		} else {
			h.logger.Error("Failed to delete employee profile",
				util.String("company_id", companyID.String()),
				util.String("employee_id", employeeID.String()),
				util.ErrorField(err))
			h.respondWithError(w, http.StatusInternalServerError, "Failed to delete employee profile")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Employee profile deleted successfully",
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

// ListEmployeeProfiles lists employee profiles with pagination
func (h *EmployeeHandler) ListEmployeeProfiles(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Get company ID from URL params
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// Parse pagination parameters
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	profiles, totalCount, err := h.employeeQueryService.ListEmployeeProfiles(ctx, companyID, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to list employee profiles",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to list employee profiles")
		return
	}

	totalPages := (totalCount + pageSize - 1) / pageSize

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    profiles,
		"meta": map[string]interface{}{
			"page":         page,
			"page_size":    pageSize,
			"total_count":  totalCount,
			"total_pages":  totalPages,
			"has_next":     page < totalPages,
			"has_previous": page > 1,
			"duration":     time.Since(startTime).String(),
		},
	})
}

// SearchEmployeeProfiles searches employee profiles with filters
func (h *EmployeeHandler) SearchEmployeeProfiles(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Get company ID from URL params
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// Parse pagination parameters
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	// Parse filter parameters
	filters := make(map[string]interface{})

	if employmentType := r.URL.Query().Get("employment_type"); employmentType != "" {
		filters["employment_type"] = employmentType
	}
	if employmentStatus := r.URL.Query().Get("employment_status"); employmentStatus != "" {
		filters["employment_status"] = employmentStatus
	}
	if departmentID := r.URL.Query().Get("department_id"); departmentID != "" {
		depID, err := uuid.Parse(departmentID)
		if err == nil {
			filters["department_id"] = depID
		}
	}
	if jobTitle := r.URL.Query().Get("job_title"); jobTitle != "" {
		filters["job_title"] = jobTitle
	}
	if gender := r.URL.Query().Get("gender"); gender != "" {
		filters["gender"] = gender
	}
	if hireDateFrom := r.URL.Query().Get("hire_date_from"); hireDateFrom != "" {
		if date, err := time.Parse(time.RFC3339, hireDateFrom); err == nil {
			filters["hire_date_from"] = date
		}
	}

	profiles, totalCount, err := h.employeeQueryService.SearchEmployeeProfiles(
		ctx, companyID, filters, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to search employee profiles",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to search employee profiles")
		return
	}

	totalPages := (totalCount + pageSize - 1) / pageSize

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    profiles,
		"meta": map[string]interface{}{
			"page":         page,
			"page_size":    pageSize,
			"total_count":  totalCount,
			"total_pages":  totalPages,
			"has_next":     page < totalPages,
			"has_previous": page > 1,
			"filters":      filters,
			"duration":     time.Since(startTime).String(),
		},
	})
}

// ============================================================================
// EMPLOYEE DOCUMENT HANDLERS
// ============================================================================

// UploadEmployeeDocumentRequest represents the request to upload a document
type UploadEmployeeDocumentRequest struct {
	DocumentType   string `json:"document_type" validate:"required"`
	DocumentName   string `json:"document_name" validate:"required"`
	IsConfidential bool   `json:"is_confidential"`
}

// UploadEmployeeDocument uploads a document for an employee
func (h *EmployeeHandler) UploadEmployeeDocument(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Get company ID from URL params
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// Get user ID from URL params
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	// Get actor info from context
	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse multipart form
	err = r.ParseMultipartForm(int64(h.maxDocumentSizeMB) * 1024 * 1024)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Failed to parse form data")
		return
	}

	// Get file from form
	file, header, err := r.FormFile("file")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "File is required")
		return
	}
	defer file.Close()

	// Get document metadata from form
	documentType := r.FormValue("document_type")
	documentName := r.FormValue("document_name")
	isConfidential := r.FormValue("is_confidential") == "true"

	if documentType == "" || documentName == "" {
		h.respondWithError(w, http.StatusBadRequest, "Document type and name are required")
		return
	}

	// Prepare metadata for audit
	metadata := map[string]interface{}{
		"ip_address":      r.RemoteAddr,
		"user_agent":      r.UserAgent(),
		"endpoint":        r.URL.Path,
		"request_method":  r.Method,
		"file_name":       header.Filename,
		"file_size":       header.Size,
		"document_type":   documentType,
		"is_confidential": isConfidential,
	}

	document, err := h.employeeService.UploadEmployeeDocument(
		ctx,
		file,
		header,
		companyID,
		userID,
		documentType,
		documentName,
		isConfidential,
		actorType,
		actorID,
		metadata,
	)
	if err != nil {
		h.logger.Error("Failed to upload employee document",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to upload document")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    document,
		"message": "Document uploaded successfully",
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

// GetEmployeeDocuments retrieves documents for an employee
func (h *EmployeeHandler) GetEmployeeDocuments(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Get company ID from URL params
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// Get user ID from URL params
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	// Check if confidential documents are requested
	includeConfidential := r.URL.Query().Get("include_confidential") == "true"

	var documents []*employee.EmployeeDocument

	if includeConfidential {
		documents, err = h.employeeQueryService.GetConfidentialDocuments(ctx, userID, companyID)
	} else {
		documents, err = h.employeeQueryService.GetEmployeeDocuments(ctx, userID, companyID)
	}

	if err != nil {
		h.logger.Error("Failed to get employee documents",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve documents")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    documents,
		"meta": map[string]interface{}{
			"count":                len(documents),
			"include_confidential": includeConfidential,
			"duration":             time.Since(startTime).String(),
		},
	})
}

// DownloadEmployeeDocument downloads a document file
func (h *EmployeeHandler) DownloadEmployeeDocument(w http.ResponseWriter, r *http.Request) {
	_ = time.Now()
	ctx := r.Context()

	// Get document ID from URL params
	documentIDStr := chi.URLParam(r, "documentID")
	documentID, err := uuid.Parse(documentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid document ID")
		return
	}

	reader, size, mimeType, document, err := h.employeeQueryService.DownloadEmployeeDocument(ctx, documentID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Document not found")
		} else {
			h.logger.Error("Failed to download document",
				util.String("document_id", documentID.String()),
				util.ErrorField(err))
			h.respondWithError(w, http.StatusInternalServerError, "Failed to download document")
		}
		return
	}
	defer reader.Close()

	// Set headers for file download
	w.Header().Set("Content-Type", mimeType)
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", *document.DocumentName))
	w.Header().Set("X-Document-ID", documentID.String())
	w.Header().Set("X-Document-Type", *document.DocumentType)
	w.Header().Set("X-Is-Confidential", strconv.FormatBool(document.IsConfidential))

	// Stream the file
	_, err = io.Copy(w, reader)
	if err != nil {
		h.logger.Error("Failed to stream document",
			util.String("document_id", documentID.String()),
			util.ErrorField(err))
	}
}

// GenerateDocumentURL generates a temporary URL for document access
func (h *EmployeeHandler) GenerateDocumentURL(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Get document ID from URL params
	documentIDStr := chi.URLParam(r, "documentID")
	documentID, err := uuid.Parse(documentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid document ID")
		return
	}

	// Parse expiry duration (default: 1 hour)
	expiryStr := r.URL.Query().Get("expiry")
	expiry := time.Hour
	if expiryStr != "" {
		if duration, err := time.ParseDuration(expiryStr); err == nil && duration > 0 {
			expiry = duration
		}
	}

	url, err := h.employeeQueryService.GenerateDocumentURL(ctx, documentID, expiry)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Document not found")
		} else {
			h.logger.Error("Failed to generate document URL",
				util.String("document_id", documentID.String()),
				util.ErrorField(err))
			h.respondWithError(w, http.StatusInternalServerError, "Failed to generate document URL")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"signed_url": url,
			"expires_in": expiry.String(),
			"expires_at": time.Now().Add(expiry).Format(time.RFC3339),
		},
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

// DeleteEmployeeDocument deletes an employee document
func (h *EmployeeHandler) DeleteEmployeeDocument(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Get document ID from URL params
	documentIDStr := chi.URLParam(r, "documentID")
	documentID, err := uuid.Parse(documentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid document ID")
		return
	}

	// Get actor info from context
	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Prepare metadata for audit
	metadata := map[string]interface{}{
		"ip_address":     r.RemoteAddr,
		"user_agent":     r.UserAgent(),
		"endpoint":       r.URL.Path,
		"request_method": r.Method,
	}

	err = h.employeeService.DeleteEmployeeDocument(
		ctx,
		documentID,
		actorType,
		actorID,
		metadata,
	)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Document not found")
		} else {
			h.logger.Error("Failed to delete employee document",
				util.String("document_id", documentID.String()),
				util.ErrorField(err))
			h.respondWithError(w, http.StatusInternalServerError, "Failed to delete document")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Document deleted successfully",
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

// ============================================================================
// EMPLOYEE DEPARTMENT HISTORY HANDLERS
// ============================================================================

// CreateDepartmentAssignmentRequest represents the request to assign an employee to a department
type CreateDepartmentAssignmentRequest struct {
	DepartmentID uuid.UUID `json:"department_id" validate:"required"`
	ChangeReason string    `json:"change_reason,omitempty"`
}

// CreateDepartmentAssignment assigns an employee to a department
func (h *EmployeeHandler) CreateDepartmentAssignment(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Get company ID from URL params
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// Get user ID from URL params
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	// Get actor info from context
	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse request
	var req CreateDepartmentAssignmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate required fields
	if req.DepartmentID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "Department ID is required")
		return
	}

	// Prepare metadata for audit
	metadata := map[string]interface{}{
		"ip_address":     r.RemoteAddr,
		"user_agent":     r.UserAgent(),
		"endpoint":       r.URL.Path,
		"request_method": r.Method,
	}

	history, err := h.employeeService.CreateDepartmentAssignment(
		ctx,
		userID,
		companyID,
		req.DepartmentID,
		req.ChangeReason,
		actorType,
		actorID,
		metadata,
	)
	if err != nil {
		h.logger.Error("Failed to create department assignment",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.String("department_id", req.DepartmentID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to create department assignment")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    history,
		"message": "Department assignment created successfully",
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

// GetDepartmentHistory retrieves department history for an employee
func (h *EmployeeHandler) GetDepartmentHistory(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Get company ID from URL params
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// Get user ID from URL params
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	history, err := h.employeeQueryService.GetDepartmentHistory(ctx, userID, companyID)
	if err != nil {
		h.logger.Error("Failed to get department history",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve department history")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    history,
		"meta": map[string]interface{}{
			"count":    len(history),
			"duration": time.Since(startTime).String(),
		},
	})
}

// ============================================================================
// EMPLOYEE EXIT HANDLERS
// ============================================================================

// CreateEmployeeExitRequest represents the request to create an employee exit record
type CreateEmployeeExitRequest struct {
	ExitDate          time.Time `json:"exit_date" validate:"required"`
	ExitReason        string    `json:"exit_reason"`
	EligibleForRehire bool      `json:"eligible_for_rehire"`
}

// CreateEmployeeExit creates an employee exit record
func (h *EmployeeHandler) CreateEmployeeExit(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Get company ID from URL params
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// Get user ID from URL params
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	// Get actor info from context
	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse request
	var req CreateEmployeeExitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate exit date
	if req.ExitDate.IsZero() {
		h.respondWithError(w, http.StatusBadRequest, "Exit date is required")
		return
	}

	// Prepare metadata for audit
	metadata := map[string]interface{}{
		"ip_address":     r.RemoteAddr,
		"user_agent":     r.UserAgent(),
		"endpoint":       r.URL.Path,
		"request_method": r.Method,
	}

	exit, err := h.employeeService.CreateEmployeeExit(
		ctx,
		userID,
		companyID,
		req.ExitDate,
		req.ExitReason,
		req.EligibleForRehire,
		actorType,
		actorID,
		metadata,
	)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			h.respondWithError(w, http.StatusConflict, "Employee exit record already exists")
		} else {
			h.logger.Error("Failed to create employee exit record",
				util.String("company_id", companyID.String()),
				util.String("user_id", userID.String()),
				util.ErrorField(err))
			h.respondWithError(w, http.StatusInternalServerError, "Failed to create employee exit record")
		}
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    exit,
		"message": "Employee exit record created successfully",
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

// GetEmployeeExit retrieves employee exit record
func (h *EmployeeHandler) GetEmployeeExit(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Get company ID from URL params
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// Get user ID from URL params
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	exit, err := h.employeeQueryService.GetEmployeeExit(ctx, userID, companyID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Employee exit record not found")
		} else {
			h.logger.Error("Failed to get employee exit record",
				util.String("company_id", companyID.String()),
				util.String("user_id", userID.String()),
				util.ErrorField(err))
			h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve employee exit record")
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    exit,
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

// ============================================================================
// POSITION HANDLERS
// ============================================================================

// CreatePositionRequest represents the request to create a position
type CreatePositionRequest struct {
	DepartmentID uuid.UUID `json:"department_id" validate:"required"`
	Title        string    `json:"title" validate:"required"`
	IsOpen       bool      `json:"is_open"`
}

// CreatePosition creates a new position
func (h *EmployeeHandler) CreatePosition(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Get company ID from URL params
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// Get actor info from context
	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Parse request
	var req CreatePositionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate required fields
	if req.DepartmentID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "Department ID is required")
		return
	}
	if req.Title == "" {
		h.respondWithError(w, http.StatusBadRequest, "Position title is required")
		return
	}

	// Create position
	position := &employee.Position{
		PositionID:   uuid.New(),
		CompanyID:    companyID,
		DepartmentID: req.DepartmentID,
		Title:        &req.Title,
		IsOpen:       req.IsOpen,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}

	// Prepare metadata for audit
	metadata := map[string]interface{}{
		"ip_address":     r.RemoteAddr,
		"user_agent":     r.UserAgent(),
		"endpoint":       r.URL.Path,
		"request_method": r.Method,
	}

	createdPosition, err := h.employeeService.CreatePosition(
		ctx,
		position,
		actorType,
		actorID,
		metadata,
	)
	if err != nil {
		h.logger.Error("Failed to create position",
			util.String("company_id", companyID.String()),
			util.String("department_id", req.DepartmentID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to create position")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    createdPosition,
		"message": "Position created successfully",
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

// GetPositionsByDepartment retrieves positions in a department
func (h *EmployeeHandler) GetPositionsByDepartment(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Get company ID from URL params
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// Get department ID from URL params
	departmentIDStr := chi.URLParam(r, "departmentID")
	departmentID, err := uuid.Parse(departmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid department ID")
		return
	}

	// Check if only open positions are requested
	onlyOpen := r.URL.Query().Get("only_open") == "true"

	var positions []*employee.Position

	if onlyOpen {
		positions, err = h.employeeQueryService.GetOpenPositions(ctx, companyID)
	} else {
		positions, err = h.employeeQueryService.GetPositionsByDepartment(ctx, companyID, departmentID)
	}

	if err != nil {
		h.logger.Error("Failed to get positions",
			util.String("company_id", companyID.String()),
			util.String("department_id", departmentID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve positions")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    positions,
		"meta": map[string]interface{}{
			"count":     len(positions),
			"only_open": onlyOpen,
			"duration":  time.Since(startTime).String(),
		},
	})
}

// ============================================================================
// ROLE HISTORY HANDLERS
// ============================================================================

// GetRoleHistory retrieves role history for an employee
func (h *EmployeeHandler) GetRoleHistory(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Get user ID from URL params
	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	history, err := h.employeeQueryService.GetRoleHistory(ctx, userID)
	if err != nil {
		h.logger.Error("Failed to get role history",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve role history")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    history,
		"meta": map[string]interface{}{
			"count":    len(history),
			"duration": time.Since(startTime).String(),
		},
	})
}

// ============================================================================
// ANALYTICS AND STATISTICS HANDLERS
// ============================================================================

// GetEmployeeStats provides statistics about employees
func (h *EmployeeHandler) GetEmployeeStats(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Get company ID from URL params
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	stats, err := h.employeeQueryService.GetEmployeeStats(ctx, companyID)
	if err != nil {
		h.logger.Error("Failed to get employee stats",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve employee statistics")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    stats,
		"meta": map[string]interface{}{
			"duration": time.Since(startTime).String(),
		},
	})
}

// ExportEmployeeData exports employee data for reporting
func (h *EmployeeHandler) ExportEmployeeData(w http.ResponseWriter, r *http.Request) {
	_ = time.Now()
	ctx := r.Context()

	// Get company ID from URL params
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	// Get export format (default: json)
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	data, contentType, err := h.employeeQueryService.ExportEmployeeData(ctx, companyID, format)
	if err != nil {
		h.logger.Error("Failed to export employee data",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to export employee data")
		return
	}

	// Set headers for file download
	filename := fmt.Sprintf("employees_%s_%s.%s", companyID.String(), time.Now().Format("20060102"), format)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))

	// Write the data
	if _, err := w.Write(data); err != nil {
		h.logger.Error("Failed to write export data",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
	}
}

// ============================================================================
// HEALTH CHECK HANDLER
// ============================================================================

// HealthCheck performs health check for employee services
func (h *EmployeeHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := h.employeeService.HealthCheck(ctx); err != nil {
		h.respondWithError(w, http.StatusServiceUnavailable, fmt.Sprintf("Employee service health check failed: %v", err))
		return
	}

	if err := h.employeeQueryService.HealthCheck(ctx); err != nil {
		h.respondWithError(w, http.StatusServiceUnavailable, fmt.Sprintf("Employee query service health check failed: %v", err))
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"message":   "Employee services are healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// ============================================================================
// HELPER METHODS
// ============================================================================

// getActorInfo extracts actor information from context
func (h *EmployeeHandler) getActorInfo(ctx context.Context) (string, uuid.UUID, error) {
	// Get session type from context
	sessionType, ok := ctx.Value("session_type").(string)
	if !ok {
		return "", uuid.Nil, fmt.Errorf("session type not found in context")
	}

	// Get user ID from context
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		return "", uuid.Nil, fmt.Errorf("user ID not found in context")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return "", uuid.Nil, fmt.Errorf("invalid user ID in context: %v", err)
	}

	// Determine actor type based on session type
	actorType := "user"
	if sessionType == "admin" {
		actorType = "admin"
	}

	return actorType, userID, nil
}

// respondWithJSON sends a JSON response
func (h *EmployeeHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

// respondWithError sends an error response
func (h *EmployeeHandler) respondWithError(w http.ResponseWriter, statusCode int, message string) {
	h.respondWithJSON(w, statusCode, map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    statusCode,
	})
}
