package handler

import (
	hrEmployee "auth-service/internal/hr/models/employee"
	hrservice "auth-service/internal/hr/service"
	a "auth-service/internal/infrastructure/audit"
	"auth-service/internal/locationctx"
	mainservice "auth-service/internal/service"
	"auth-service/internal/util"
	"context"
	"encoding/json"
	"errors"
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

type EmployeeHandler struct {
	employeeService      *hrservice.EmployeeService
	employeeQueryService *hrservice.EmployeeQueryService
	companyService       *mainservice.CompanyService // 👈 ADD
	auditService         *a.AuditService
	logger               *zap.Logger
	maxDocumentSizeMB    int
}

func NewEmployeeHandler(
	employeeService *hrservice.EmployeeService,
	employeeQueryService *hrservice.EmployeeQueryService,
	companyService *mainservice.CompanyService, // 👈 ADD
	auditService *a.AuditService,
	logger *zap.Logger,
	maxDocumentSizeMB int,
) *EmployeeHandler {
	if maxDocumentSizeMB <= 0 {
		maxDocumentSizeMB = 50
	}
	return &EmployeeHandler{
		employeeService:      employeeService,
		employeeQueryService: employeeQueryService,
		companyService:       companyService, // 👈 ADD
		auditService:         auditService,
		logger:               logger,
		maxDocumentSizeMB:    maxDocumentSizeMB,
	}
}

// mapLocationScopeError — same helper used across HR handlers.
func (h *EmployeeHandler) mapLocationScopeError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, hrservice.ErrEmployeeOutsideScope):
		h.respondWithError(w, http.StatusForbidden,
			"employee belongs to a different location than your current scope")
		return true
	case errors.Is(err, hrservice.ErrEmployeeHasNoLocation):
		h.respondWithError(w, http.StatusBadRequest,
			"target employee has no employment location assigned")
		return true
	}
	return false
}

// ============================================================================
// EMPLOYEE PROFILE HANDLERS
// ============================================================================

// CreateEmployeeProfile — atomic hire.
//
// Delegates to CompanyService.AddMember, which writes in ONE transaction:
//   - users               (create or reuse by phone)
//   - company_employees   (roster row)
//   - employee_profiles   (HR dossier — includes cost_center_id)
//   - employee_location_* (grants + scope + history)
//
// This replaces the old handler behaviour that wrote only a bare
// employee_profiles row and required `user_id` in the body.
func (h *EmployeeHandler) CreateEmployeeProfile(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}

	var req mainservice.AddMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error("failed to decode create-employee request", util.ErrorField(err))
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	req.CompanyID = companyID
	if req.MemberType == "" {
		req.MemberType = "employee"
	}

	if err := h.companyService.AddMember(ctx, &req); err != nil {
		h.logger.Error("Failed to create employee",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": "Employee created successfully",
		"meta":    map[string]interface{}{"duration": time.Since(startTime).String()},
	})
}

// GetEmployeeProfile
func (h *EmployeeHandler) GetEmployeeProfile(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	employeeID, err := uuid.Parse(chi.URLParam(r, "employeeID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid employee ID")
		return
	}
	profile, err := h.employeeQueryService.GetEmployeeProfile(ctx, employeeID)
	if err != nil {
		if h.mapLocationScopeError(w, err) {
			return
		}
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Employee profile not found")
		} else {
			h.logger.Error("Failed to get employee profile",
				util.String("company_id", companyID.String()),
				util.String("employee_id", employeeID.String()), util.ErrorField(err))
			h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve employee profile")
		}
		return
	}
	if profile.CompanyID != companyID {
		h.respondWithError(w, http.StatusForbidden, "Employee does not belong to this company")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true, "data": profile,
		"meta": map[string]interface{}{"duration": time.Since(startTime).String()},
	})
}

// GetEmployeeProfileByUserID
func (h *EmployeeHandler) GetEmployeeProfileByUserID(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}
	profile, err := h.employeeQueryService.GetEmployeeProfileByUserID(ctx, userID, companyID)
	if err != nil {
		if h.mapLocationScopeError(w, err) {
			return
		}
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Employee profile not found")
		} else {
			h.logger.Error("Failed to get employee profile by user ID",
				util.String("company_id", companyID.String()),
				util.String("user_id", userID.String()), util.ErrorField(err))
			h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve employee profile")
		}
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true, "data": profile,
		"meta": map[string]interface{}{"duration": time.Since(startTime).String()},
	})
}

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
	CostCenter       *string    `json:"cost_center,omitempty"`    // legacy text
	CostCenterID     *uuid.UUID `json:"cost_center_id,omitempty"` // 👈 ADD
	TaxID            *string    `json:"tax_id,omitempty"`
	SocialSecurityID *string    `json:"social_security_id,omitempty"`
	Email            *string    `json:"email,omitempty"`
}

func (h *EmployeeHandler) UpdateEmployeeProfile(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	employeeID, err := uuid.Parse(chi.URLParam(r, "employeeID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid employee ID")
		return
	}
	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	var req UpdateEmployeeProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
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
	if req.CostCenterID != nil { // 👈 ADD
		updates["cost_center_id"] = *req.CostCenterID
	}
	if req.TaxID != nil {
		updates["tax_id"] = *req.TaxID
	}
	if req.SocialSecurityID != nil {
		updates["social_security_id"] = *req.SocialSecurityID
	}
	if req.Email != nil {
		updates["email"] = *req.Email
	}
	if len(updates) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "No update fields provided")
		return
	}
	metadata := map[string]interface{}{
		"ip_address": r.RemoteAddr, "user_agent": r.UserAgent(),
		"endpoint": r.URL.Path, "request_method": r.Method,
		"updated_fields": updates,
	}
	updatedProfile, err := h.employeeService.UpdateEmployeeProfile(ctx, employeeID, updates, actorType, actorID, metadata)
	if err != nil {
		if h.mapLocationScopeError(w, err) {
			return
		}
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Employee profile not found")
		} else {
			h.logger.Error("Failed to update employee profile",
				util.String("company_id", companyID.String()),
				util.String("employee_id", employeeID.String()), util.ErrorField(err))
			h.respondWithError(w, http.StatusInternalServerError, "Failed to update employee profile")
		}
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true, "data": updatedProfile,
		"message": "Employee profile updated successfully",
		"meta":    map[string]interface{}{"duration": time.Since(startTime).String()},
	})
}

func (h *EmployeeHandler) DeleteEmployeeProfile(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	employeeID, err := uuid.Parse(chi.URLParam(r, "employeeID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid employee ID")
		return
	}
	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	metadata := map[string]interface{}{
		"ip_address": r.RemoteAddr, "user_agent": r.UserAgent(),
		"endpoint": r.URL.Path, "request_method": r.Method,
	}
	err = h.employeeService.DeleteEmployeeProfile(ctx, employeeID, actorType, actorID, metadata)
	if err != nil {
		if h.mapLocationScopeError(w, err) {
			return
		}
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Employee profile not found")
		} else {
			h.logger.Error("Failed to delete employee profile",
				util.String("company_id", companyID.String()),
				util.String("employee_id", employeeID.String()), util.ErrorField(err))
			h.respondWithError(w, http.StatusInternalServerError, "Failed to delete employee profile")
		}
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true, "message": "Employee profile deleted successfully",
		"meta": map[string]interface{}{"duration": time.Since(startTime).String()},
	})
}

// ListEmployeeProfiles
func (h *EmployeeHandler) ListEmployeeProfiles(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}
	locFilter := locationctx.Filter(ctx)
	profiles, totalCount, err := h.employeeQueryService.ListEmployeeProfiles(ctx, companyID, locFilter, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to list employee profiles",
			util.String("company_id", companyID.String()), util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to list employee profiles")
		return
	}
	totalPages := (totalCount + pageSize - 1) / pageSize
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true, "data": profiles,
		"meta": map[string]interface{}{
			"page": page, "page_size": pageSize,
			"total_count": totalCount, "total_pages": totalPages,
			"has_next": page < totalPages, "has_previous": page > 1,
			"duration": time.Since(startTime).String(),
		},
	})
}

func (h *EmployeeHandler) SearchEmployeeProfiles(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}
	filters := make(map[string]interface{})
	if v := r.URL.Query().Get("employment_type"); v != "" {
		filters["employment_type"] = v
	}
	if v := r.URL.Query().Get("employment_status"); v != "" {
		filters["employment_status"] = v
	}
	if v := r.URL.Query().Get("department_id"); v != "" {
		if depID, err := uuid.Parse(v); err == nil {
			filters["department_id"] = depID
		}
	}
	if v := r.URL.Query().Get("job_title"); v != "" {
		filters["job_title"] = v
	}
	if v := r.URL.Query().Get("gender"); v != "" {
		filters["gender"] = v
	}
	if v := r.URL.Query().Get("email"); v != "" {
		filters["email"] = v
	}
	if v := r.URL.Query().Get("hire_date_from"); v != "" {
		if d, err := time.Parse(time.RFC3339, v); err == nil {
			filters["hire_date_from"] = d
		}
	}
	locFilter := locationctx.Filter(ctx)
	profiles, totalCount, err := h.employeeQueryService.SearchEmployeeProfiles(ctx, companyID, locFilter, filters, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to search employee profiles",
			util.String("company_id", companyID.String()), util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to search employee profiles")
		return
	}
	totalPages := (totalCount + pageSize - 1) / pageSize
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true, "data": profiles,
		"meta": map[string]interface{}{
			"page": page, "page_size": pageSize,
			"total_count": totalCount, "total_pages": totalPages,
			"has_next": page < totalPages, "has_previous": page > 1,
			"filters": filters, "duration": time.Since(startTime).String(),
		},
	})
}

// ============================================================================
// DOCUMENT HANDLERS
// ============================================================================

func (h *EmployeeHandler) UploadEmployeeDocument(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}
	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	if err := r.ParseMultipartForm(int64(h.maxDocumentSizeMB) * 1024 * 1024); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Failed to parse form data")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "File is required")
		return
	}
	defer file.Close()
	documentType := r.FormValue("document_type")
	documentName := r.FormValue("document_name")
	isConfidential := r.FormValue("is_confidential") == "true"
	if documentType == "" || documentName == "" {
		h.respondWithError(w, http.StatusBadRequest, "Document type and name are required")
		return
	}
	metadata := map[string]interface{}{
		"ip_address": r.RemoteAddr, "user_agent": r.UserAgent(),
		"endpoint": r.URL.Path, "request_method": r.Method,
		"file_name": header.Filename, "file_size": header.Size,
		"document_type": documentType, "is_confidential": isConfidential,
	}
	document, err := h.employeeService.UploadEmployeeDocument(
		ctx, file, header, companyID, userID,
		documentType, documentName, isConfidential, actorType, actorID, metadata)
	if err != nil {
		if h.mapLocationScopeError(w, err) {
			return
		}
		h.logger.Error("Failed to upload employee document",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()), util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to upload document")
		return
	}
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true, "data": document,
		"message": "Document uploaded successfully",
		"meta":    map[string]interface{}{"duration": time.Since(startTime).String()},
	})
}

func (h *EmployeeHandler) GetEmployeeDocuments(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}
	includeConfidential := r.URL.Query().Get("include_confidential") == "true"
	var documents []*hrEmployee.EmployeeDocument
	if includeConfidential {
		documents, err = h.employeeQueryService.GetConfidentialDocuments(ctx, userID, companyID)
	} else {
		documents, err = h.employeeQueryService.GetEmployeeDocuments(ctx, userID, companyID)
	}
	if err != nil {
		if h.mapLocationScopeError(w, err) {
			return
		}
		h.logger.Error("Failed to get employee documents",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()), util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve documents")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true, "data": documents,
		"meta": map[string]interface{}{
			"count": len(documents), "include_confidential": includeConfidential,
			"duration": time.Since(startTime).String(),
		},
	})
}

func (h *EmployeeHandler) DownloadEmployeeDocument(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	documentID, err := uuid.Parse(chi.URLParam(r, "documentID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid document ID")
		return
	}
	reader, size, mimeType, document, err := h.employeeQueryService.DownloadEmployeeDocument(ctx, documentID)
	if err != nil {
		if h.mapLocationScopeError(w, err) {
			return
		}
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Document not found")
		} else {
			h.logger.Error("Failed to download document",
				util.String("document_id", documentID.String()), util.ErrorField(err))
			h.respondWithError(w, http.StatusInternalServerError, "Failed to download document")
		}
		return
	}
	defer reader.Close()
	w.Header().Set("Content-Type", mimeType)
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", *document.DocumentName))
	w.Header().Set("X-Document-ID", documentID.String())
	w.Header().Set("X-Document-Type", *document.DocumentType)
	w.Header().Set("X-Is-Confidential", strconv.FormatBool(document.IsConfidential))
	if _, err := io.Copy(w, reader); err != nil {
		h.logger.Error("Failed to stream document",
			util.String("document_id", documentID.String()), util.ErrorField(err))
	}
}

func (h *EmployeeHandler) GenerateDocumentURL(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	documentID, err := uuid.Parse(chi.URLParam(r, "documentID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid document ID")
		return
	}
	expiryStr := r.URL.Query().Get("expiry")
	expiry := time.Hour
	if expiryStr != "" {
		if d, err := time.ParseDuration(expiryStr); err == nil && d > 0 {
			expiry = d
		}
	}
	url, err := h.employeeQueryService.GenerateDocumentURL(ctx, documentID, expiry)
	if err != nil {
		if h.mapLocationScopeError(w, err) {
			return
		}
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Document not found")
		} else {
			h.logger.Error("Failed to generate document URL",
				util.String("document_id", documentID.String()), util.ErrorField(err))
			h.respondWithError(w, http.StatusInternalServerError, "Failed to generate document URL")
		}
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"signed_url": url, "expires_in": expiry.String(),
			"expires_at": time.Now().Add(expiry).Format(time.RFC3339),
		},
		"meta": map[string]interface{}{"duration": time.Since(startTime).String()},
	})
}

func (h *EmployeeHandler) DeleteEmployeeDocument(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	documentID, err := uuid.Parse(chi.URLParam(r, "documentID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid document ID")
		return
	}
	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	metadata := map[string]interface{}{
		"ip_address": r.RemoteAddr, "user_agent": r.UserAgent(),
		"endpoint": r.URL.Path, "request_method": r.Method,
	}
	err = h.employeeService.DeleteEmployeeDocument(ctx, documentID, actorType, actorID, metadata)
	if err != nil {
		if h.mapLocationScopeError(w, err) {
			return
		}
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Document not found")
		} else {
			h.logger.Error("Failed to delete employee document",
				util.String("document_id", documentID.String()), util.ErrorField(err))
			h.respondWithError(w, http.StatusInternalServerError, "Failed to delete document")
		}
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true, "message": "Document deleted successfully",
		"meta": map[string]interface{}{"duration": time.Since(startTime).String()},
	})
}

// ============================================================================
// DEPARTMENT / EXIT / POSITION / ROLE HANDLERS
// ============================================================================

type CreateDepartmentAssignmentRequest struct {
	DepartmentID uuid.UUID `json:"department_id" validate:"required"`
	ChangeReason string    `json:"change_reason,omitempty"`
}

func (h *EmployeeHandler) CreateDepartmentAssignment(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	employeeProfileID, err := uuid.Parse(chi.URLParam(r, "employeeID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid employee profile ID")
		return
	}
	profile, err := h.employeeService.GetEmployeeProfileByID(ctx, employeeProfileID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "Employee profile not found")
		return
	}
	userID := profile.UserID
	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	var req CreateDepartmentAssignmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.DepartmentID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "Department ID is required")
		return
	}
	metadata := map[string]interface{}{
		"ip_address": r.RemoteAddr, "user_agent": r.UserAgent(),
		"endpoint": r.URL.Path, "request_method": r.Method,
	}
	history, err := h.employeeService.CreateDepartmentAssignment(
		ctx, userID, companyID, req.DepartmentID, req.ChangeReason,
		actorType, actorID, metadata)
	if err != nil {
		if h.mapLocationScopeError(w, err) {
			return
		}
		h.logger.Error("Failed to create department assignment",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()), util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to create department assignment")
		return
	}
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true, "data": history,
		"message": "Department assignment created successfully",
		"meta":    map[string]interface{}{"duration": time.Since(startTime).String()},
	})
}

func (h *EmployeeHandler) GetDepartmentHistory(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	employeeProfileID, err := uuid.Parse(chi.URLParam(r, "employeeID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid employee profile ID")
		return
	}
	profile, err := h.employeeService.GetEmployeeProfileByID(ctx, employeeProfileID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "Employee profile not found")
		return
	}
	userID := profile.UserID
	history, err := h.employeeQueryService.GetDepartmentHistory(ctx, userID, companyID)
	if err != nil {
		if h.mapLocationScopeError(w, err) {
			return
		}
		h.logger.Error("Failed to get department history",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()), util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve department history")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true, "data": history,
		"meta": map[string]interface{}{
			"count": len(history), "duration": time.Since(startTime).String(),
		},
	})
}

type CreateEmployeeExitRequest struct {
	ExitDate          time.Time `json:"exit_date" validate:"required"`
	ExitReason        string    `json:"exit_reason"`
	EligibleForRehire bool      `json:"eligible_for_rehire"`
}

func (h *EmployeeHandler) CreateEmployeeExit(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	employeeProfileID, err := uuid.Parse(chi.URLParam(r, "employeeID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid employee profile ID")
		return
	}
	profile, err := h.employeeService.GetEmployeeProfileByID(ctx, employeeProfileID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "Employee profile not found")
		return
	}
	userID := profile.UserID
	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	var req CreateEmployeeExitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.ExitDate.IsZero() {
		h.respondWithError(w, http.StatusBadRequest, "Exit date is required")
		return
	}
	metadata := map[string]interface{}{
		"ip_address": r.RemoteAddr, "user_agent": r.UserAgent(),
		"endpoint": r.URL.Path, "request_method": r.Method,
	}
	exit, err := h.employeeService.CreateEmployeeExit(
		ctx, userID, companyID, req.ExitDate, req.ExitReason,
		req.EligibleForRehire, actorType, actorID, metadata)
	if err != nil {
		if h.mapLocationScopeError(w, err) {
			return
		}
		if strings.Contains(err.Error(), "already exists") {
			h.respondWithError(w, http.StatusConflict, "Employee exit record already exists")
			return
		}
		h.logger.Error("Failed to create employee exit record",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()), util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to create employee exit record")
		return
	}
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true, "data": exit,
		"message": "Employee exit record created successfully",
		"meta":    map[string]interface{}{"duration": time.Since(startTime).String()},
	})
}

func (h *EmployeeHandler) GetEmployeeExit(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	employeeProfileID, err := uuid.Parse(chi.URLParam(r, "employeeID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid employee profile ID")
		return
	}
	profile, err := h.employeeService.GetEmployeeProfileByID(ctx, employeeProfileID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "Employee profile not found")
		return
	}
	userID := profile.UserID
	exit, err := h.employeeQueryService.GetEmployeeExit(ctx, userID, companyID)
	if err != nil {
		if h.mapLocationScopeError(w, err) {
			return
		}
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(w, http.StatusNotFound, "Employee exit record not found")
		} else {
			h.logger.Error("Failed to get employee exit record",
				util.String("company_id", companyID.String()),
				util.String("user_id", userID.String()), util.ErrorField(err))
			h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve employee exit record")
		}
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true, "data": exit,
		"meta": map[string]interface{}{"duration": time.Since(startTime).String()},
	})
}

type CreatePositionRequest struct {
	DepartmentID uuid.UUID `json:"department_id" validate:"required"`
	Title        string    `json:"title" validate:"required"`
	IsOpen       bool      `json:"is_open"`
}

func (h *EmployeeHandler) CreatePosition(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	var req CreatePositionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.DepartmentID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "Department ID is required")
		return
	}
	if req.Title == "" {
		h.respondWithError(w, http.StatusBadRequest, "Position title is required")
		return
	}
	position := &hrEmployee.Position{
		PositionID: uuid.New(), CompanyID: companyID, DepartmentID: req.DepartmentID,
		Title: &req.Title, IsOpen: req.IsOpen,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	metadata := map[string]interface{}{
		"ip_address": r.RemoteAddr, "user_agent": r.UserAgent(),
		"endpoint": r.URL.Path, "request_method": r.Method,
	}
	createdPosition, err := h.employeeService.CreatePosition(ctx, position, actorType, actorID, metadata)
	if err != nil {
		h.logger.Error("Failed to create position",
			util.String("company_id", companyID.String()),
			util.String("department_id", req.DepartmentID.String()), util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to create position")
		return
	}
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true, "data": createdPosition,
		"message": "Position created successfully",
		"meta":    map[string]interface{}{"duration": time.Since(startTime).String()},
	})
}

func (h *EmployeeHandler) GetPositionsByDepartment(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	departmentID, err := uuid.Parse(chi.URLParam(r, "departmentID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid department ID")
		return
	}
	onlyOpen := r.URL.Query().Get("only_open") == "true"
	var positions []*hrEmployee.Position
	if onlyOpen {
		positions, err = h.employeeQueryService.GetOpenPositions(ctx, companyID)
	} else {
		positions, err = h.employeeQueryService.GetPositionsByDepartment(ctx, companyID, departmentID)
	}
	if err != nil {
		h.logger.Error("Failed to get positions",
			util.String("company_id", companyID.String()),
			util.String("department_id", departmentID.String()), util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve positions")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true, "data": positions,
		"meta": map[string]interface{}{
			"count": len(positions), "only_open": onlyOpen,
			"duration": time.Since(startTime).String(),
		},
	})
}

func (h *EmployeeHandler) GetRoleHistory(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	employeeProfileID, err := uuid.Parse(chi.URLParam(r, "employeeID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid employee profile ID")
		return
	}
	profile, err := h.employeeService.GetEmployeeProfileByID(ctx, employeeProfileID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "Employee profile not found")
		return
	}
	userID := profile.UserID
	history, err := h.employeeQueryService.GetRoleHistory(ctx, companyID, userID)
	if err != nil {
		if h.mapLocationScopeError(w, err) {
			return
		}
		h.logger.Error("Failed to get role history",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()), util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve role history")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true, "data": history,
		"meta": map[string]interface{}{
			"count": len(history), "duration": time.Since(startTime).String(),
		},
	})
}

// ============================================================================
// STATS / EXPORT / HEALTH / ENFORCE / REHIRE
// ============================================================================

func (h *EmployeeHandler) GetEmployeeStats(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	locFilter := locationctx.Filter(ctx)
	stats, err := h.employeeQueryService.GetEmployeeStats(ctx, companyID, locFilter)
	if err != nil {
		h.logger.Error("Failed to get employee stats",
			util.String("company_id", companyID.String()), util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to retrieve employee statistics")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true, "data": stats,
		"meta": map[string]interface{}{"duration": time.Since(startTime).String()},
	})
}

func (h *EmployeeHandler) ExportEmployeeData(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid company ID")
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	locFilter := locationctx.Filter(ctx)
	data, contentType, err := h.employeeQueryService.ExportEmployeeData(ctx, companyID, locFilter, format)
	if err != nil {
		h.logger.Error("Failed to export employee data",
			util.String("company_id", companyID.String()), util.ErrorField(err))
		h.respondWithError(w, http.StatusInternalServerError, "Failed to export employee data")
		return
	}
	filename := fmt.Sprintf("employees_%s_%s.%s", companyID.String(), time.Now().Format("20060102"), format)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	if _, err := w.Write(data); err != nil {
		h.logger.Error("Failed to write export data",
			util.String("company_id", companyID.String()), util.ErrorField(err))
	}
}

func (h *EmployeeHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)
	if err := h.employeeService.HealthCheck(ctx); err != nil {
		h.respondWithError(w, http.StatusServiceUnavailable, fmt.Sprintf("Employee service health check failed: %v", err))
		return
	}
	if err := h.employeeQueryService.HealthCheck(ctx); err != nil {
		h.respondWithError(w, http.StatusServiceUnavailable, fmt.Sprintf("Employee query service health check failed: %v", err))
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true, "message": "Employee services are healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (h *EmployeeHandler) EnforceEmployeeExits(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil || actorType != "admin" {
		h.respondWithError(w, http.StatusForbidden, "Admin access required")
		return
	}
	dateStr := r.URL.Query().Get("date")
	effectiveDate := time.Now().UTC()
	if dateStr != "" {
		effectiveDate, err = time.Parse("2006-01-02", dateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "Invalid date format")
			return
		}
	}
	count, err := h.employeeService.EnforceScheduledEmployeeExits(ctx, effectiveDate, actorID)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "Failed to enforce exits")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true, "message": "Employee exits enforced",
		"data": map[string]interface{}{
			"affected_count": count, "effective_date": effectiveDate,
		},
	})
}

func (h *EmployeeHandler) RehireEmployee(w http.ResponseWriter, r *http.Request) {
	ctx := injectCommonContext(r.Context(), r)

	companyID, ok := ctx.Value("company_id").(uuid.UUID)
	if !ok {
		h.respondWithError(w, http.StatusBadRequest, "Company context missing")
		return
	}
	employeeProfileID, err := uuid.Parse(chi.URLParam(r, "employeeID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid employee profile ID")
		return
	}
	profile, err := h.employeeService.GetEmployeeProfileByID(ctx, employeeProfileID)
	if err != nil {
		h.respondWithError(w, http.StatusNotFound, "Employee profile not found")
		return
	}
	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	metadata := map[string]interface{}{"endpoint": r.URL.Path, "method": r.Method}
	if err := h.employeeService.RehireEmployee(ctx, companyID, profile.UserID, actorType, actorID, metadata); err != nil {
		if h.mapLocationScopeError(w, err) {
			return
		}
		h.respondWithError(w, http.StatusInternalServerError, "Failed to rehire employee")
		return
	}
	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true, "message": "Employee rehired successfully",
	})
}

// ============================================================================
// HELPERS
// ============================================================================

func (h *EmployeeHandler) getActorInfo(ctx context.Context) (string, uuid.UUID, error) {
	sessionType, ok := ctx.Value("session_type").(string)
	if !ok {
		return "", uuid.Nil, fmt.Errorf("session type not found in context")
	}
	userIDStr, ok := ctx.Value("user_id").(string)
	if !ok {
		return "", uuid.Nil, fmt.Errorf("user ID not found in context")
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return "", uuid.Nil, fmt.Errorf("invalid user ID in context: %v", err)
	}
	actorType := "user"
	if sessionType == "admin" {
		actorType = "admin"
	}
	return actorType, userID, nil
}

func (h *EmployeeHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

func (h *EmployeeHandler) respondWithError(w http.ResponseWriter, statusCode int, message string) {
	h.respondWithJSON(w, statusCode, map[string]interface{}{
		"success": false, "error": message, "code": statusCode,
	})
}
