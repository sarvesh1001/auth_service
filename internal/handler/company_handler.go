package handler

// import (
// 	"auth-service/internal/service"
// 	"encoding/json"
// 	"fmt"
// 	"net/http"
// 	"time"
// 	"auth-service/internal/util"
// 	"github.com/go-chi/chi/v5"
// 	"github.com/google/uuid"
// 	"go.uber.org/zap"
// )

// // CompanyHandler handles company-specific operations
// type CompanyHandler struct {
// 	companyService *service.CompanyService
// 	logger         *zap.Logger
// }

// func NewCompanyHandler(companyService *service.CompanyService, logger *zap.Logger) *CompanyHandler {
// 	return &CompanyHandler{
// 		companyService: companyService,
// 		logger:         logger,
// 	}
// }

// // ============================================================================
// // PHASE 2 - OWNER OPERATIONS
// // ============================================================================

// // RenameDepartmentRequest for renaming a department
// type RenameDepartmentRequest struct {
// 	DepartmentName string `json:"department_name" validate:"required"`
// }

// // RenameDepartment renames a department (Owner only)
// func (h *CompanyHandler) RenameDepartment(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	companyIDStr := chi.URLParam(r, "companyID")
// 	companyID, err := uuid.Parse(companyIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
// 		return
// 	}

// 	departmentIDStr := chi.URLParam(r, "departmentID")
// 	departmentID, err := uuid.Parse(departmentIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid department ID")
// 		return
// 	}

// 	// Get user ID from JWT context
// 	userID := r.Context().Value("user_id")
// 	if userID == nil {
// 		h.respondWithError(w, http.StatusUnauthorized,
// 			fmt.Errorf("UNAUTHORIZED: User not authenticated"),
// 			"Authentication required")
// 		return
// 	}

// 	userIDParsed, err := uuid.Parse(userID.(string))
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
// 		return
// 	}

// 	var req RenameDepartmentRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	// Sanitize input
// 	req.DepartmentName = service.SanitizeInput(req.DepartmentName)

// 	if err := h.companyService.RenameDepartment(ctx, companyID, departmentID, req.DepartmentName, userIDParsed); err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to rename department")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Department renamed successfully"))

// 	h.logger.Info("Department renamed",
// 		util.String("company_id", companyID.String()),
// 		util.String("department_id", departmentID.String()),
// 		util.String("new_name", req.DepartmentName),
// 		util.String("updated_by", userIDParsed.String()),
// 		util.Duration("duration", time.Since(startTime)))
// }

// // AddDepartmentRequest for adding a new department
// type AddDepartmentRequest struct {
// 	DepartmentName     string    `json:"department_name" validate:"required"`
// 	SystemDepartmentID uuid.UUID `json:"system_department_id" validate:"required"`
// }

// // AddDepartment adds a new department (Owner only)
// func (h *CompanyHandler) AddDepartment(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	companyIDStr := chi.URLParam(r, "companyID")
// 	companyID, err := uuid.Parse(companyIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
// 		return
// 	}

// 	// Get user ID from JWT context
// 	userID := r.Context().Value("user_id")
// 	if userID == nil {
// 		h.respondWithError(w, http.StatusUnauthorized,
// 			fmt.Errorf("UNAUTHORIZED: User not authenticated"),
// 			"Authentication required")
// 		return
// 	}

// 	userIDParsed, err := uuid.Parse(userID.(string))
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
// 		return
// 	}

// 	var req AddDepartmentRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	// Sanitize input
// 	req.DepartmentName = service.SanitizeInput(req.DepartmentName)

// 	department, err := h.companyService.AddDepartment(ctx, companyID, req.DepartmentName, req.SystemDepartmentID, userIDParsed)
// 	if err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to add department")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusCreated, successResponse(department, "Department added successfully"))

// 	h.logger.Info("Department added",
// 		util.String("company_id", companyID.String()),
// 		util.String("department_id", department.DepartmentID.String()),
// 		util.String("department_name", req.DepartmentName),
// 		util.String("system_department_id", req.SystemDepartmentID.String()),
// 		util.String("created_by", userIDParsed.String()),
// 		util.Duration("duration", time.Since(startTime)))
// }

// // AddManagerRequest for adding a manager
// type AddManagerRequest struct {
// 	PhoneNumber  string     `json:"phone" validate:"required"`
// 	RoleName     string     `json:"role_name" validate:"required"`
// 	DepartmentID uuid.UUID  `json:"department_id" validate:"required"`
// 	Permissions  []string   `json:"permissions" validate:"required"`
// 	ReportsTo    *uuid.UUID `json:"reports_to,omitempty"`
// }

// // AddManager adds a new manager (Owner only)
// func (h *CompanyHandler) AddManager(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	companyIDStr := chi.URLParam(r, "companyID")
// 	companyID, err := uuid.Parse(companyIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
// 		return
// 	}

// 	// Get user ID from JWT context
// 	userID := r.Context().Value("user_id")
// 	if userID == nil {
// 		h.respondWithError(w, http.StatusUnauthorized,
// 			fmt.Errorf("UNAUTHORIZED: User not authenticated"),
// 			"Authentication required")
// 		return
// 	}

// 	userIDParsed, err := uuid.Parse(userID.(string))
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
// 		return
// 	}

// 	var req AddManagerRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	// Sanitize inputs
// 	req.PhoneNumber = service.SanitizeInput(req.PhoneNumber)
// 	req.RoleName = service.SanitizeInput(req.RoleName)

// 	serviceReq := &service.AddManagerRequest{
// 		CompanyID:    companyID,
// 		PhoneNumber:  req.PhoneNumber,
// 		RoleName:     req.RoleName,
// 		DepartmentID: req.DepartmentID,
// 		Permissions:  req.Permissions,
// 		ReportsTo:    req.ReportsTo,
// 	}

// 	if err := h.companyService.AddManager(ctx, serviceReq, userIDParsed); err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to add manager")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusCreated, successResponse(nil, "Manager added successfully"))

// 	h.logger.Info("Manager added",
// 		util.String("company_id", companyID.String()),
// 		util.String("phone", req.PhoneNumber),
// 		util.String("role_name", req.RoleName),
// 		util.String("department_id", req.DepartmentID.String()),
// 		util.Int("permissions_count", len(req.Permissions)),
// 		util.String("added_by", userIDParsed.String()),
// 		util.Duration("duration", time.Since(startTime)))
// }

// // AddEmployeeRequest for adding an employee (Owner version)
// type AddEmployeeRequest struct {
// 	PhoneNumber  string     `json:"phone" validate:"required"`
// 	RoleName     string     `json:"role_name" validate:"required"`
// 	EmployeeID   string     `json:"employee_id" validate:"required"`
// 	RoleID       uuid.UUID  `json:"role_id" validate:"required"`
// 	DepartmentID uuid.UUID  `json:"department_id" validate:"required"`
// 	ReportsTo    *uuid.UUID `json:"reports_to,omitempty"`
// 	Permissions  []string   `json:"permissions"`
// }

// // AddEmployee adds a new employee (Owner only)
// func (h *CompanyHandler) AddEmployee(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	companyIDStr := chi.URLParam(r, "companyID")
// 	companyID, err := uuid.Parse(companyIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
// 		return
// 	}

// 	// Get user ID from JWT context
// 	userID := r.Context().Value("user_id")
// 	if userID == nil {
// 		h.respondWithError(w, http.StatusUnauthorized,
// 			fmt.Errorf("UNAUTHORIZED: User not authenticated"),
// 			"Authentication required")
// 		return
// 	}

// 	userIDParsed, err := uuid.Parse(userID.(string))
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
// 		return
// 	}

// 	var req AddEmployeeRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	// Sanitize inputs
// 	req.PhoneNumber = service.SanitizeInput(req.PhoneNumber)
// 	req.RoleName = service.SanitizeInput(req.RoleName)
// 	req.EmployeeID = service.SanitizeInput(req.EmployeeID)

// 	serviceReq := &service.AddEmployeeRequest{
// 		CompanyID:    companyID,
// 		PhoneNumber:  req.PhoneNumber,
// 		RoleName:     req.RoleName,
// 		EmployeeID:   req.EmployeeID,
// 		RoleID:       req.RoleID,
// 		DepartmentID: req.DepartmentID,
// 		ReportsTo:    req.ReportsTo,
// 		Permissions:  req.Permissions,
// 		AddedBy:      userIDParsed,
// 	}

// 	if err := h.companyService.AddEmployee(ctx, serviceReq, userIDParsed); err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to add employee")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusCreated, successResponse(nil, "Employee added successfully"))

// 	h.logger.Info("Employee added by owner",
// 		util.String("company_id", companyID.String()),
// 		util.String("phone", req.PhoneNumber),
// 		util.String("employee_id", req.EmployeeID),
// 		util.String("role_id", req.RoleID.String()),
// 		util.String("department_id", req.DepartmentID.String()),
// 		util.String("added_by", userIDParsed.String()),
// 		util.Duration("duration", time.Since(startTime)))
// }

// // PermissionAssignmentRequest for assigning/revoking permissions
// type PermissionAssignmentRequest struct {
// 	PermissionNames []string `json:"permissions" validate:"required"`
// }

// // AssignManagerPermissions assigns permissions to a manager (Owner only)
// func (h *CompanyHandler) AssignManagerPermissions(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	companyIDStr := chi.URLParam(r, "companyID")
// 	companyID, err := uuid.Parse(companyIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
// 		return
// 	}

// 	managerIDStr := chi.URLParam(r, "managerID")
// 	managerID, err := uuid.Parse(managerIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid manager ID")
// 		return
// 	}

// 	// Get user ID from JWT context
// 	userID := r.Context().Value("user_id")
// 	if userID == nil {
// 		h.respondWithError(w, http.StatusUnauthorized,
// 			fmt.Errorf("UNAUTHORIZED: User not authenticated"),
// 			"Authentication required")
// 		return
// 	}

// 	userIDParsed, err := uuid.Parse(userID.(string))
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
// 		return
// 	}

// 	var req PermissionAssignmentRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	if err := h.companyService.AssignManagerPermissions(ctx, companyID, managerID, req.PermissionNames, userIDParsed); err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to assign permissions")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Permissions assigned successfully"))

// 	h.logger.Info("Manager permissions assigned",
// 		util.String("company_id", companyID.String()),
// 		util.String("manager_id", managerID.String()),
// 		util.Int("permissions_count", len(req.PermissionNames)),
// 		util.String("assigned_by", userIDParsed.String()),
// 		util.Duration("duration", time.Since(startTime)))
// }

// // RevokeManagerPermissions revokes permissions from a manager (Owner only)
// func (h *CompanyHandler) RevokeManagerPermissions(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	companyIDStr := chi.URLParam(r, "companyID")
// 	companyID, err := uuid.Parse(companyIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
// 		return
// 	}

// 	managerIDStr := chi.URLParam(r, "managerID")
// 	managerID, err := uuid.Parse(managerIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid manager ID")
// 		return
// 	}

// 	// Get user ID from JWT context
// 	userID := r.Context().Value("user_id")
// 	if userID == nil {
// 		h.respondWithError(w, http.StatusUnauthorized,
// 			fmt.Errorf("UNAUTHORIZED: User not authenticated"),
// 			"Authentication required")
// 		return
// 	}

// 	userIDParsed, err := uuid.Parse(userID.(string))
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid user ID in token")
// 		return
// 	}

// 	var req PermissionAssignmentRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	if err := h.companyService.RevokeManagerPermissions(ctx, companyID, managerID, req.PermissionNames, userIDParsed); err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to revoke permissions")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Permissions revoked successfully"))

// 	h.logger.Info("Manager permissions revoked",
// 		util.String("company_id", companyID.String()),
// 		util.String("manager_id", managerID.String()),
// 		util.Int("permissions_count", len(req.PermissionNames)),
// 		util.String("revoked_by", userIDParsed.String()),
// 		util.Duration("duration", time.Since(startTime)))
// }

// // ============================================================================
// // PHASE 3 - MANAGER OPERATIONS
// // ============================================================================

// // ManagerAddEmployeeRequest for adding employee by manager
// type ManagerAddEmployeeRequest struct {
// 	PhoneNumber  string     `json:"phone" validate:"required"`
// 	RoleName     string     `json:"role_name" validate:"required"`
// 	EmployeeID   string     `json:"employee_id" validate:"required"`
// 	RoleID       uuid.UUID  `json:"role_id" validate:"required"`
// 	DepartmentID uuid.UUID  `json:"department_id" validate:"required"`
// 	Permissions  []string   `json:"permissions"`
// }

// // ManagerAddEmployee adds an employee by manager (Manager only)
// func (h *CompanyHandler) ManagerAddEmployee(w http.ResponseWriter, r *http.Request) {
// 	ctx := r.Context()
// 	startTime := time.Now()

// 	companyIDStr := chi.URLParam(r, "companyID")
// 	companyID, err := uuid.Parse(companyIDStr)
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
// 		return
// 	}

// 	// Get manager ID from JWT context
// 	managerID := r.Context().Value("user_id")
// 	if managerID == nil {
// 		h.respondWithError(w, http.StatusUnauthorized,
// 			fmt.Errorf("UNAUTHORIZED: User not authenticated"),
// 			"Authentication required")
// 		return
// 	}

// 	managerIDParsed, err := uuid.Parse(managerID.(string))
// 	if err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid manager ID in token")
// 		return
// 	}

// 	var req ManagerAddEmployeeRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
// 		return
// 	}

// 	// Sanitize inputs
// 	req.PhoneNumber = service.SanitizeInput(req.PhoneNumber)
// 	req.RoleName = service.SanitizeInput(req.RoleName)
// 	req.EmployeeID = service.SanitizeInput(req.EmployeeID)

// 	serviceReq := &service.AddEmployeeRequest{
// 		CompanyID:    companyID,
// 		PhoneNumber:  req.PhoneNumber,
// 		RoleName:     req.RoleName,
// 		EmployeeID:   req.EmployeeID,
// 		RoleID:       req.RoleID,
// 		DepartmentID: req.DepartmentID,
// 		ReportsTo:    &managerIDParsed, // Manager becomes the reports_to
// 		Permissions:  req.Permissions,
// 		AddedBy:      managerIDParsed,
// 	}

// 	if err := h.companyService.ManagerAddEmployee(ctx, serviceReq, managerIDParsed); err != nil {
// 		statusCode := h.getStatusCode(err)
// 		h.respondWithError(w, statusCode, err, "Failed to add employee")
// 		return
// 	}

// 	h.respondWithJSON(w, http.StatusCreated, successResponse(nil, "Employee added successfully"))

// 	h.logger.Info("Employee added by manager",
// 		util.String("company_id", companyID.String()),
// 		util.String("phone", req.PhoneNumber),
// 		util.String("employee_id", req.EmployeeID),
// 		util.String("role_id", req.RoleID.String()),
// 		util.String("department_id", req.DepartmentID.String()),
// 		util.String("manager_id", managerIDParsed.String()),
// 		util.Duration("duration", time.Since(startTime)))
// }

// // ============================================================================
// // HELPER METHODS
// // ============================================================================

// func (h *CompanyHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(statusCode)
// 	json.NewEncoder(w).Encode(data)
// }

// func (h *CompanyHandler) respondWithError(w http.ResponseWriter, statusCode int, err error, message string) {
// 	h.logger.Warn("Company HTTP error",
// 		util.ErrorField(err),
// 		util.Int("status_code", statusCode),
// 		util.String("message", message),
// 	)
// 	h.respondWithJSON(w, statusCode, errorResponse(err, message))
// }

// func (h *CompanyHandler) getStatusCode(err error) int {
// 	switch {
// 	case errors.Is(err, service.ErrUserNotFound):
// 		return http.StatusNotFound
// 	case errors.Is(err, service.ErrInvalidInput):
// 		return http.StatusBadRequest
// 	case errors.Is(err, service.ErrUserAlreadyExists):
// 		return http.StatusConflict
// 	case errors.Is(err, service.ErrPermissionDenied):
// 		return http.StatusForbidden
// 	default:
// 		return http.StatusInternalServerError
// 	}
// }
