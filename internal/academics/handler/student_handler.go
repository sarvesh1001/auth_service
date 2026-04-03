package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/academics/service"
	mainService "auth-service/internal/service"
)

// StudentHandler handles all student-related endpoints.
type StudentHandler struct {
	studentService     service.StudentService
	studentAuthService service.StudentAuthService
	sessionService     *mainService.SessionService
	logger             *zap.Logger
}

// NewStudentHandler creates a new StudentHandler.
func NewStudentHandler(
	studentService service.StudentService,
	studentAuthService service.StudentAuthService,
	sessionService *mainService.SessionService,
	logger *zap.Logger,
) *StudentHandler {
	return &StudentHandler{
		studentService:     studentService,
		studentAuthService: studentAuthService,
		sessionService:     sessionService,
		logger:             logger.Named("student_handler"),
	}
}

// ---------------------- Student CRUD ----------------------------------------

// CreateStudentRequest is the body for creating a single student.
type CreateStudentRequest struct {
	FirstName             string     `json:"first_name"`
	LastName              string     `json:"last_name,omitempty"`
	AdmissionNo           string     `json:"admission_no"`
	Email                 string     `json:"email,omitempty"`
	Phone                 string     `json:"phone,omitempty"`
	DateOfBirth           *time.Time `json:"date_of_birth,omitempty"`
	Gender                string     `json:"gender,omitempty"`
	BloodGroup            string     `json:"blood_group,omitempty"`
	Nationality           string     `json:"nationality,omitempty"`
	Religion              string     `json:"religion,omitempty"`
	Category              string     `json:"category,omitempty"`
	AadharNo              string     `json:"aadhar_no,omitempty"`
	EmergencyContactName  string     `json:"emergency_contact_name,omitempty"`
	EmergencyContactPhone string     `json:"emergency_contact_phone,omitempty"`
	MedicalConditions     string     `json:"medical_conditions,omitempty"`
	Status                string     `json:"status,omitempty"` // defaults to "active"
}

// Create handles POST /api/v1/companies/{companyID}/students
func (h *StudentHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "student:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req CreateStudentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.FirstName == "" {
		h.respondWithError(w, http.StatusBadRequest, "first_name is required")
		return
	}
	if req.AdmissionNo == "" {
		h.respondWithError(w, http.StatusBadRequest, "admission_no is required")
		return
	}
	if req.Status == "" {
		req.Status = string(models.StudentActive)
	}

	// Prepare service request
	createReq := service.CreateStudentRequest{
		CompanyID:             companyID,
		FirstName:             req.FirstName,
		LastName:              req.LastName,
		AdmissionNo:           req.AdmissionNo,
		Email:                 req.Email,
		Phone:                 req.Phone,
		DateOfBirth:           req.DateOfBirth,
		Gender:                req.Gender,
		BloodGroup:            req.BloodGroup,
		Nationality:           req.Nationality,
		Religion:              req.Religion,
		Category:              req.Category,
		AadharNo:              req.AadharNo,
		EmergencyContactName:  req.EmergencyContactName,
		EmergencyContactPhone: req.EmergencyContactPhone,
		MedicalConditions:     req.MedicalConditions,
		Status:                req.Status,
		CreatedBy:             &userID,
		UpdatedBy:             &userID,
	}

	student, err := h.studentService.Create(ctx, createReq, "")
	if err != nil {
		h.logger.Error("Failed to create student",
			zap.String("company_id", companyID.String()),
			zap.String("admission_no", req.AdmissionNo),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    student,
		"message": "Student created successfully",
	})
}

// BulkCreate handles POST /api/v1/companies/{companyID}/students/bulk
func (h *StudentHandler) BulkCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "student:bulk_create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var reqs []CreateStudentRequest
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(reqs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "empty batch")
		return
	}

	// Convert to service requests
	createReqs := make([]service.CreateStudentRequest, len(reqs))
	for i, r := range reqs {
		if r.FirstName == "" {
			h.respondWithError(w, http.StatusBadRequest, "first_name is required for all students")
			return
		}
		if r.AdmissionNo == "" {
			h.respondWithError(w, http.StatusBadRequest, "admission_no is required for all students")
			return
		}
		if r.Status == "" {
			r.Status = string(models.StudentActive)
		}
		createReqs[i] = service.CreateStudentRequest{
			CompanyID:             companyID,
			FirstName:             r.FirstName,
			LastName:              r.LastName,
			AdmissionNo:           r.AdmissionNo,
			Email:                 r.Email,
			Phone:                 r.Phone,
			DateOfBirth:           r.DateOfBirth,
			Gender:                r.Gender,
			BloodGroup:            r.BloodGroup,
			Nationality:           r.Nationality,
			Religion:              r.Religion,
			Category:              r.Category,
			AadharNo:              r.AadharNo,
			EmergencyContactName:  r.EmergencyContactName,
			EmergencyContactPhone: r.EmergencyContactPhone,
			MedicalConditions:     r.MedicalConditions,
			Status:                r.Status,
			CreatedBy:             &userID,
			UpdatedBy:             &userID,
		}
	}

	students, err := h.studentService.BulkCreate(ctx, createReqs)
	if err != nil {
		h.logger.Error("Failed to bulk create students",
			zap.Int("count", len(reqs)),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    students,
		"message": "Students created successfully",
	})
}

// GetByID handles GET /api/v1/companies/{companyID}/students/{studentID}
func (h *StudentHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	studentIDStr := chi.URLParam(r, "studentID")
	studentID, err := uuid.Parse(studentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "student:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	student, err := h.studentService.GetByID(ctx, studentID)
	if err != nil {
		h.logger.Error("Failed to get student",
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    student,
	})
}

// GetByAdmissionNumber handles GET /api/v1/companies/{companyID}/students/admission/{admissionNo}
func (h *StudentHandler) GetByAdmissionNumber(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	admissionNo := chi.URLParam(r, "admissionNo")
	if admissionNo == "" {
		h.respondWithError(w, http.StatusBadRequest, "admission number is required")
		return
	}

	if !h.hasPermission(ctx, companyID, "student:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	student, err := h.studentService.GetByAdmissionNumber(ctx, companyID, admissionNo)
	if err != nil {
		h.logger.Error("Failed to get student by admission number",
			zap.String("company_id", companyID.String()),
			zap.String("admission_no", admissionNo),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    student,
	})
}

// List handles GET /api/v1/companies/{companyID}/students with query params
func (h *StudentHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "student:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Build filter
	filter := repository.StudentFilter{
		CompanyID: companyID,
	}
	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = &status
	}
	// Add other filters if they exist in StudentFilter. For example:
	// if admissionNo := r.URL.Query().Get("admission_no"); admissionNo != "" {
	//     filter.AdmissionNo = &admissionNo
	// }
	if sectionIDStr := r.URL.Query().Get("section_id"); sectionIDStr != "" {
		if sectionID, err := uuid.Parse(sectionIDStr); err == nil {
			filter.SectionID = &sectionID
		}
	}
	if termIDStr := r.URL.Query().Get("term_id"); termIDStr != "" {
		if termID, err := uuid.Parse(termIDStr); err == nil {
			filter.TermID = &termID
		}
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
		sortField = "created_at"
	}
	sortDirection := r.URL.Query().Get("sort_direction")
	if sortDirection == "" {
		sortDirection = "DESC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDirection}

	students, err := h.studentService.List(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list students",
			zap.Any("filter", filter),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list students")
		return
	}

	count, err := h.studentService.Count(ctx, filter)
	if err != nil {
		h.logger.Error("Failed to count students", zap.Error(err))
		// non-fatal
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"students": students,
			"total":    count,
			"limit":    limit,
			"offset":   offset,
		},
	})
}

// UpdateStudentRequest is the body for updating a student.
type UpdateStudentRequest struct {
	FirstName             string     `json:"first_name,omitempty"`
	LastName              string     `json:"last_name,omitempty"`
	AdmissionNo           string     `json:"admission_no,omitempty"`
	Email                 string     `json:"email,omitempty"`
	Phone                 string     `json:"phone,omitempty"`
	DateOfBirth           *time.Time `json:"date_of_birth,omitempty"`
	Gender                string     `json:"gender,omitempty"`
	BloodGroup            string     `json:"blood_group,omitempty"`
	Nationality           string     `json:"nationality,omitempty"`
	Religion              string     `json:"religion,omitempty"`
	Category              string     `json:"category,omitempty"`
	AadharNo              string     `json:"aadhar_no,omitempty"`
	EmergencyContactName  string     `json:"emergency_contact_name,omitempty"`
	EmergencyContactPhone string     `json:"emergency_contact_phone,omitempty"`
	MedicalConditions     string     `json:"medical_conditions,omitempty"`
	Status                string     `json:"status,omitempty"`
}

// Update handles PUT /api/v1/companies/{companyID}/students/{studentID}
func (h *StudentHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	studentIDStr := chi.URLParam(r, "studentID")
	studentID, err := uuid.Parse(studentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "student:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req UpdateStudentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// At least one field must be provided
	if req.FirstName == "" && req.LastName == "" && req.AdmissionNo == "" && req.Email == "" &&
		req.Phone == "" && req.DateOfBirth == nil && req.Gender == "" && req.BloodGroup == "" &&
		req.Nationality == "" && req.Religion == "" && req.Category == "" && req.AadharNo == "" &&
		req.EmergencyContactName == "" && req.EmergencyContactPhone == "" && req.MedicalConditions == "" &&
		req.Status == "" {
		h.respondWithError(w, http.StatusBadRequest, "no fields to update")
		return
	}

	// Build update request
	updateReq := service.UpdateStudentRequest{
		StudentID:             studentID,
		FirstName:             req.FirstName,
		LastName:              req.LastName,
		AdmissionNo:           req.AdmissionNo,
		Email:                 req.Email,
		Phone:                 req.Phone,
		DateOfBirth:           req.DateOfBirth,
		Gender:                req.Gender,
		BloodGroup:            req.BloodGroup,
		Nationality:           req.Nationality,
		Religion:              req.Religion,
		Category:              req.Category,
		AadharNo:              req.AadharNo,
		EmergencyContactName:  req.EmergencyContactName,
		EmergencyContactPhone: req.EmergencyContactPhone,
		MedicalConditions:     req.MedicalConditions,
		Status:                req.Status,
		UpdatedBy:             &userID,
	}

	student, err := h.studentService.Update(ctx, updateReq)
	if err != nil {
		h.logger.Error("Failed to update student",
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    student,
		"message": "Student updated successfully",
	})
}

// UpdateContactInfo handles PATCH /api/v1/companies/{companyID}/students/{studentID}/contact
func (h *StudentHandler) UpdateContactInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	studentIDStr := chi.URLParam(r, "studentID")
	studentID, err := uuid.Parse(studentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "student:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req struct {
		Phone string `json:"phone"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Phone == "" {
		h.respondWithError(w, http.StatusBadRequest, "phone is required")
		return
	}

	err = h.studentService.UpdateContactInfo(ctx, studentID, req.Phone, &userID)
	if err != nil {
		h.logger.Error("Failed to update contact info",
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Contact information updated",
	})
}

// Activate handles PATCH /api/v1/companies/{companyID}/students/{studentID}/activate
func (h *StudentHandler) Activate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	studentIDStr := chi.URLParam(r, "studentID")
	studentID, err := uuid.Parse(studentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "student:activate") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.studentService.Activate(ctx, studentID, &userID)
	if err != nil {
		h.logger.Error("Failed to activate student",
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Student activated",
	})
}

// Deactivate handles PATCH /api/v1/companies/{companyID}/students/{studentID}/deactivate
func (h *StudentHandler) Deactivate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	studentIDStr := chi.URLParam(r, "studentID")
	studentID, err := uuid.Parse(studentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "student:deactivate") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.studentService.Deactivate(ctx, studentID, &userID)
	if err != nil {
		h.logger.Error("Failed to deactivate student",
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Student deactivated",
	})
}

// ---------------------- Promotion / Graduation / Dropout --------------------

// PromoteRequest is the body for promoting a student.
type PromoteRequest struct {
	NewCourseID  string `json:"new_course_id"`
	NewSectionID string `json:"new_section_id"`
}

// Promote handles POST /api/v1/companies/{companyID}/students/{studentID}/promote
func (h *StudentHandler) Promote(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	studentIDStr := chi.URLParam(r, "studentID")
	studentID, err := uuid.Parse(studentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "student:promote") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req PromoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	newCourseID, err := uuid.Parse(req.NewCourseID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid new_course_id")
		return
	}
	newSectionID, err := uuid.Parse(req.NewSectionID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid new_section_id")
		return
	}

	err = h.studentService.Promote(ctx, studentID, newCourseID, newSectionID, &userID)
	if err != nil {
		h.logger.Error("Failed to promote student",
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Student promoted successfully",
	})
}

// Graduate handles POST /api/v1/companies/{companyID}/students/{studentID}/graduate
func (h *StudentHandler) Graduate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	studentIDStr := chi.URLParam(r, "studentID")
	studentID, err := uuid.Parse(studentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "student:graduate") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.studentService.Graduate(ctx, studentID, &userID)
	if err != nil {
		h.logger.Error("Failed to graduate student",
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Student graduated",
	})
}

// DropoutRequest is the body for dropout.
type DropoutRequest struct {
	Reason string `json:"reason"`
}

// Dropout handles POST /api/v1/companies/{companyID}/students/{studentID}/dropout
func (h *StudentHandler) Dropout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	studentIDStr := chi.URLParam(r, "studentID")
	studentID, err := uuid.Parse(studentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "student:dropout") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req DropoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	err = h.studentService.Dropout(ctx, studentID, req.Reason, &userID)
	if err != nil {
		h.logger.Error("Failed to dropout student",
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Student dropped out",
	})
}

// BulkPromoteRequest is the body for bulk promotion.
type BulkPromoteRequest struct {
	StudentIDs   []string `json:"student_ids"`
	NewCourseID  string   `json:"new_course_id"`
	NewSectionID string   `json:"new_section_id"`
}

// BulkPromote handles POST /api/v1/companies/{companyID}/students/bulk/promote
func (h *StudentHandler) BulkPromote(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "student:bulk_promote") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req BulkPromoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.StudentIDs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "student_ids is required")
		return
	}
	newCourseID, err := uuid.Parse(req.NewCourseID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid new_course_id")
		return
	}
	newSectionID, err := uuid.Parse(req.NewSectionID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid new_section_id")
		return
	}

	studentIDs := make([]uuid.UUID, len(req.StudentIDs))
	for i, sid := range req.StudentIDs {
		uid, err := uuid.Parse(sid)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid student_id in list")
			return
		}
		studentIDs[i] = uid
	}

	err = h.studentService.BulkPromote(ctx, studentIDs, newCourseID, newSectionID, &userID)
	if err != nil {
		h.logger.Error("Failed to bulk promote students",
			zap.Int("count", len(studentIDs)),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Students promoted successfully",
	})
}

// BulkUpdateStatusRequest is the body for bulk status update.
type BulkUpdateStatusRequest struct {
	StudentIDs []string `json:"student_ids"`
	Status     string   `json:"status"`
}

// BulkUpdateStatus handles PATCH /api/v1/companies/{companyID}/students/bulk/status
func (h *StudentHandler) BulkUpdateStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "student:bulk_update_status") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req BulkUpdateStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.StudentIDs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "student_ids is required")
		return
	}
	if req.Status == "" {
		h.respondWithError(w, http.StatusBadRequest, "status is required")
		return
	}
	if !models.IsValidStudentStatus(req.Status) {
		h.respondWithError(w, http.StatusBadRequest, "invalid status")
		return
	}

	studentIDs := make([]uuid.UUID, len(req.StudentIDs))
	for i, sid := range req.StudentIDs {
		uid, err := uuid.Parse(sid)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid student_id in list")
			return
		}
		studentIDs[i] = uid
	}

	err = h.studentService.BulkUpdateStatus(ctx, studentIDs, req.Status, &userID)
	if err != nil {
		h.logger.Error("Failed to bulk update student status",
			zap.Int("count", len(studentIDs)),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Student statuses updated",
	})
}

// Delete handles DELETE /api/v1/companies/{companyID}/students/{studentID}
func (h *StudentHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	studentIDStr := chi.URLParam(r, "studentID")
	studentID, err := uuid.Parse(studentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "student:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.studentService.Delete(ctx, studentID, nil) // deletedBy? we can get userID if needed
	if err != nil {
		h.logger.Error("Failed to delete student",
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Student deleted",
	})
}

// ValidateAdmissionNumber handles GET /api/v1/companies/{companyID}/students/validate-admission?admission_no=...
func (h *StudentHandler) ValidateAdmissionNumber(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	admissionNo := r.URL.Query().Get("admission_no")
	if admissionNo == "" {
		h.respondWithError(w, http.StatusBadRequest, "admission_no query param is required")
		return
	}

	if !h.hasPermission(ctx, companyID, "student:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.studentService.ValidateAdmissionNumber(ctx, companyID, admissionNo)
	if err != nil {
		// If error is duplicate, that means admission number exists, so not valid
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"valid":   false,
			"message": err.Error(),
		})
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"valid":   true,
	})
}

// Search handles GET /api/v1/companies/{companyID}/students/search?q=...
func (h *StudentHandler) Search(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	query := r.URL.Query().Get("q")
	if query == "" {
		h.respondWithError(w, http.StatusBadRequest, "q query param is required")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 20
	}
	if limit > 50 {
		limit = 50
	}

	if !h.hasPermission(ctx, companyID, "student:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	students, err := h.studentService.Search(ctx, companyID, query, limit)
	if err != nil {
		h.logger.Error("Failed to search students",
			zap.String("company_id", companyID.String()),
			zap.String("query", query),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "search failed")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    students,
	})
}

// ---------------------- Student Authentication -----------------------------

// StudentLoginRequest is the body for student login.
type StudentLoginRequest struct {
	Identifier string `json:"identifier"` // email or phone
	Password   string `json:"password"`
}

// StudentLoginResponse is the response for successful login.
type StudentLoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	StudentID    string `json:"student_id"`
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name"`
	AdmissionNo  string `json:"admission_no"`
	Email        string `json:"email"`
	Phone        string `json:"phone"`
	CompanyID    string `json:"company_id"`
}

// Login handles POST /api/v1/students/login (no company ID in path, as it's inside request)
func (h *StudentHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req StudentLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if strings.TrimSpace(req.Identifier) == "" || strings.TrimSpace(req.Password) == "" {
		h.respondWithError(w, http.StatusBadRequest, "identifier and password are required")
		return
	}

	// We need companyID – it might be passed in the request or we could infer from identifier? But let's assume it's part of the login request.
	// However, our service expects companyID. In the original design, the login request had company_id. Let's adjust.
	// For now, we'll add company_id to the request body.
	// I'll modify the request to include company_id.
	// Actually, the original LoginRequest in service expects CompanyID. So we need to parse it.
	var loginReq struct {
		CompanyID  string `json:"company_id"`
		Identifier string `json:"identifier"`
		Password   string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	companyID, err := uuid.Parse(loginReq.CompanyID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company_id")
		return
	}

	authResp, err := h.studentAuthService.Login(r.Context(), service.LoginRequest{
		Identifier: loginReq.Identifier,
		Password:   loginReq.Password,
		CompanyID:  companyID,
	})
	if err != nil {
		switch err {
		case service.ErrInvalidCredentials:
			h.respondWithError(w, http.StatusUnauthorized, "invalid credentials")
		case service.ErrAccountLocked:
			h.respondWithError(w, http.StatusTooManyRequests, "account locked")
		case service.ErrNoPasswordSet:
			h.respondWithError(w, http.StatusUnauthorized, "no password set")
		default:
			h.logger.Error("student login failed", zap.Error(err))
			h.respondWithError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}

	// Issue JWT tokens using session service
	tokenPair, err := h.sessionService.IssueTokenPair(r.Context(), &mainService.IssueTokenPairRequest{
		UserID:         authResp.Student.StudentID.String(),
		Role:           "student",
		DeviceID:       r.Header.Get("X-Device-ID"),
		SessionType:    "student",
		IPAddress:      r.RemoteAddr,
		CompanyID:      authResp.Student.CompanyID.String(),
		PermissionMask: []uint64{},
	})
	if err != nil {
		h.logger.Error("failed to issue token pair", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "could not create session")
		return
	}

	resp := StudentLoginResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    tokenPair.ExpiresIn,
		TokenType:    tokenPair.TokenType,
		StudentID:    authResp.Student.StudentID.String(),
		FirstName:    authResp.Student.FirstName,
		LastName:     authResp.Student.LastName,
		AdmissionNo:  authResp.Student.AdmissionNo,
		Email:        authResp.Student.Email,
		Phone:        authResp.Student.Phone,
		CompanyID:    authResp.Student.CompanyID.String(),
	}

	h.respondWithJSON(w, http.StatusOK, resp)
}

// SetPasswordRequest is the body for setting a password.
type SetPasswordRequest struct {
	Password string `json:"password"`
}

// SetPassword handles POST /api/v1/students/{studentID}/password (requires admin)
func (h *StudentHandler) SetPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	studentIDStr := chi.URLParam(r, "studentID")
	studentID, err := uuid.Parse(studentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Permission: admin or the student themselves? Usually admin only.
	if !h.hasPermission(ctx, uuid.Nil, "student:set_password") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req SetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Password == "" {
		h.respondWithError(w, http.StatusBadRequest, "password is required")
		return
	}

	err = h.studentAuthService.SetPassword(ctx, studentID, req.Password, &userID)
	if err != nil {
		h.logger.Error("Failed to set password",
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Password set successfully",
	})
}

// ChangePasswordRequest is the body for changing password (authenticated student).
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// ChangePassword handles POST /api/v1/students/me/change-password (authenticated student)
func (h *StudentHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	studentID, err := getUserIDFromContext(ctx) // assume context holds student ID
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.OldPassword == "" || req.NewPassword == "" {
		h.respondWithError(w, http.StatusBadRequest, "old_password and new_password are required")
		return
	}

	err = h.studentAuthService.ChangePassword(ctx, studentID, req.OldPassword, req.NewPassword, &studentID)
	if err != nil {
		if err == service.ErrInvalidCredentials {
			h.respondWithError(w, http.StatusUnauthorized, "invalid old password")
		} else {
			h.logger.Error("Failed to change password",
				zap.String("student_id", studentID.String()),
				zap.Error(err))
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Password changed successfully",
	})
}

// ResetPasswordRequest is the body for admin reset.
type ResetPasswordRequest struct {
	NewPassword string `json:"new_password"`
}

// ResetPassword handles POST /api/v1/students/{studentID}/reset-password (admin)
func (h *StudentHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	studentIDStr := chi.URLParam(r, "studentID")
	studentID, err := uuid.Parse(studentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, uuid.Nil, "student:reset_password") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.NewPassword == "" {
		h.respondWithError(w, http.StatusBadRequest, "new_password is required")
		return
	}

	err = h.studentAuthService.ResetPassword(ctx, studentID, req.NewPassword, &userID)
	if err != nil {
		h.logger.Error("Failed to reset password",
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Password reset successfully",
	})
}

// ---------------------- Helper Methods -------------------------------------

func (h *StudentHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	// Placeholder – implement actual permission check
	return true
}

func (h *StudentHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *StudentHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
