package handler

// import (
//     "encoding/json"
//     "fmt"
//     "net/http"
//     "strconv"
//     "strings"
//     "time"
// 	"context"
//     "github.com/go-chi/chi/v5"
//     "github.com/google/uuid"
//     "go.uber.org/zap"

//     "auth-service/internal/service"
//     "auth-service/internal/models"
// )

// type CompanyHandler struct {
//     companyService *service.CompanyService
//     adminService   *service.AdminService
//     logger         *zap.Logger
// }

// func NewCompanyHandler(
//     companyService *service.CompanyService,
//     adminService *service.AdminService,
//     logger *zap.Logger,
// ) *CompanyHandler {
//     return &CompanyHandler{
//         companyService: companyService,
//         adminService:   adminService,
//         logger:         logger,
//     }
// }

// func (h *CompanyHandler) RegisterAdminRoutes(router chi.Router) {
//     router.Route("/companies", func(r chi.Router) {
//         // Admin-only company management
//         r.Post("/", h.CreateCompany)
//         r.Patch("/{companyID}/block", h.BlockCompany)
//         r.Patch("/{companyID}/unblock", h.UnblockCompany)
//         r.Patch("/{companyID}/subscription", h.UpdateSubscription)
//         r.Patch("/{companyID}/extend", h.ExtendSubscription)
//         r.Get("/", h.ListCompanies)
//         r.Get("/{companyID}", h.GetCompany)
//     })
// }

// func (h *CompanyHandler) RegisterCompanyRoutes(router chi.Router) {
//     router.Route("/company", func(r chi.Router) {
//         // Company owner/manager operations
//         r.With(h.RequireCompanyPermission(models.PermissionEmployeeRead)).Get("/employees", h.ListEmployees)
//         r.With(h.RequireCompanyPermission(models.PermissionEmployeeWrite)).Post("/employees", h.AddEmployee)
//         r.Get("/context", h.GetCompanyContext)
//     })
// }

// // ---------- Admin handlers ---------- //

// // CreateCompany - Admin creates a new company
// func (h *CompanyHandler) CreateCompany(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     adminID, err := h.getRequesterAdminID(r)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
//         return
//     }

//     var req service.CreateCompanyRequest
//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     req.CreatedByAdmin = adminID

//     company, err := h.companyService.CreateCompany(ctx, &req)
//     if err != nil {
//         statusCode := h.getStatusCode(err)
//         h.respondWithError(w, statusCode, err, "Failed to create company")
//         return
//     }

//     h.respondWithJSON(w, http.StatusCreated, successResponse(company, "Company created successfully"))

//     h.logger.Info("Company created by admin",
//         zap.String("company_id", company.CompanyID.String()),
//         zap.String("company_name", company.CompanyName),
//         zap.String("owner_phone", company.OwnerPhone),
//         zap.String("created_by", adminID.String()),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// // ListCompanies - Admin list with pagination & filters
// // Query params supported: page (1-based), limit, name (partial), tier, is_active
// func (h *CompanyHandler) ListCompanies(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()

//     // parse pagination
//     page := parseIntDefault(r.URL.Query().Get("page"), 1)
//     limit := parseIntDefault(r.URL.Query().Get("limit"), 25)
//     if limit <= 0 || limit > 1000 {
//         limit = 25
//     }

//     // filters
//     name := strings.TrimSpace(r.URL.Query().Get("name"))
//     tier := strings.TrimSpace(r.URL.Query().Get("tier"))
//     isActiveStr := strings.TrimSpace(r.URL.Query().Get("is_active"))
//     var isActive *bool
//     if isActiveStr != "" {
//         b, err := strconv.ParseBool(isActiveStr)
//         if err == nil {
//             isActive = &b
//         }
//     }

//     // Build filter struct (service layer should implement filtering)
//     filter := service.CompanyFilter{
//         NameContains: name,
//         SubscriptionTier: tier,
//         IsActive: isActive,
//     }

//     companies, total, err := h.adminService.ListCompanies(ctx, filter, page, limit)
//     if err != nil {
//         h.respondWithError(w, h.getStatusCode(err), err, "Failed to list companies")
//         return
//     }

//     meta := map[string]interface{}{
//         "page": page,
//         "limit": limit,
//         "total": total,
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{"items": companies, "meta": meta}, "Companies retrieved successfully"))
// }

// // GetCompany - Admin fetches a single company
// func (h *CompanyHandler) GetCompany(w http.ResponseWriter, r *http.Request) {
//     companyID, _ := uuid.Parse(chi.URLParam(r, "companyID"))
//     company, err := h.companyService.CompanyRepo().GetCompany(r.Context(), companyID)
//     if err != nil {
//         h.respondWithError(w, http.StatusNotFound, err, "Company not found")
//         return
//     }
//     h.respondWithJSON(w, http.StatusOK, successResponse(company, "Company details fetched"))
// }

// // BlockCompany - Admin blocks a company
// func (h *CompanyHandler) BlockCompany(w http.ResponseWriter, r *http.Request) {
//     companyID, _ := uuid.Parse(chi.URLParam(r, "companyID"))
//     adminID, err := h.getRequesterAdminID(r)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
//         return
//     }

//     var req struct{ Reason string `json:"reason"` }
//     json.NewDecoder(r.Body).Decode(&req)

//     if err := h.companyService.BlockCompany(r.Context(), companyID, req.Reason, adminID); err != nil {
//         h.respondWithError(w, h.getStatusCode(err), err, "Failed to block company")
//         return
//     }
//     h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Company blocked successfully"))
// }

// // UnblockCompany - Admin unblocks a company
// func (h *CompanyHandler) UnblockCompany(w http.ResponseWriter, r *http.Request) {
//     companyID, _ := uuid.Parse(chi.URLParam(r, "companyID"))
//     adminID, err := h.getRequesterAdminID(r)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Admin authentication required")
//         return
//     }

//     if err := h.companyService.UnblockCompany(r.Context(), companyID, adminID); err != nil {
//         h.respondWithError(w, h.getStatusCode(err), err, "Failed to unblock company")
//         return
//     }
//     h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Company unblocked successfully"))
// }

// // UpdateSubscription - Admin updates company subscription
// func (h *CompanyHandler) UpdateSubscription(w http.ResponseWriter, r *http.Request) {
//     companyID, _ := uuid.Parse(chi.URLParam(r, "companyID"))
//     adminID, _ := h.getRequesterAdminID(r)

//     var req struct {
//         Tier         string  `json:"tier"`
//         Premium      float64 `json:"premium"`
//         MaxEmployees int     `json:"max_employees"`
//     }
//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     if err := h.companyService.UpdateSubscription(r.Context(), companyID, req.Tier, req.Premium, req.MaxEmployees, adminID); err != nil {
//         h.respondWithError(w, h.getStatusCode(err), err, "Failed to update subscription")
//         return
//     }
//     h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Subscription updated successfully"))
// }

// // ExtendSubscription - Admin extends subscription
// func (h *CompanyHandler) ExtendSubscription(w http.ResponseWriter, r *http.Request) {
//     companyID, _ := uuid.Parse(chi.URLParam(r, "companyID"))
//     adminID, _ := h.getRequesterAdminID(r)

//     var req struct{ Months int `json:"months"` }
//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     if err := h.companyService.ExtendSubscription(r.Context(), companyID, req.Months, adminID); err != nil {
//         h.respondWithError(w, h.getStatusCode(err), err, "Failed to extend subscription")
//         return
//     }
//     h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Subscription extended successfully"))
// }

// // ---------- Company handlers ---------- //

// // AddEmployee - Company owner adds employee
// func (h *CompanyHandler) AddEmployee(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     startTime := time.Now()

//     userID, err := h.getRequesterUserID(r)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Authentication required")
//         return
//     }

//     // Verify user has permission to add employees
//     companyContext, err := h.companyService.GetCompanyContext(ctx, userID)
//     if err != nil || companyContext == nil {
//         h.respondWithError(w, http.StatusForbidden,
//             fmt.Errorf("user not associated with company"),
//             "Company access required")
//         return
//     }

//     // Check if user has employee management permission
//     if !h.hasPermission(companyContext.Permissions, models.PermissionEmployeeManage) {
//         h.respondWithError(w, http.StatusForbidden,
//             fmt.Errorf("insufficient permissions"),
//             "Employee management permission required")
//         return
//     }

//     var req service.AddEmployeeRequest
//     if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
//         h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
//         return
//     }

//     req.CompanyID = uuid.MustParse(companyContext.CompanyID)

//     if err := h.companyService.AddEmployee(ctx, &req); err != nil {
//         statusCode := h.getStatusCode(err)
//         h.respondWithError(w, statusCode, err, "Failed to add employee")
//         return
//     }

//     h.respondWithJSON(w, http.StatusCreated, successResponse(nil, "Employee added successfully"))

//     h.logger.Info("Employee added to company",
//         zap.String("company_id", companyContext.CompanyID),
//         zap.String("added_by", userID.String()),
//         zap.String("employee_phone", req.PhoneNumber),
//         zap.Duration("duration", time.Since(startTime)),
//     )
// }

// // ListEmployees - Owner/Manager lists company employees with pagination & filters
// // Query params: page, limit, q (search by name/employee_id), role_id, department_id, is_active
// func (h *CompanyHandler) ListEmployees(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()
//     userID, err := h.getRequesterUserID(r)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Authentication required")
//         return
//     }

//     companyCtx, err := h.companyService.GetCompanyContext(ctx, userID)
//     if err != nil || companyCtx == nil {
//         h.respondWithError(w, http.StatusForbidden, err, "No company association found")
//         return
//     }

//     page := parseIntDefault(r.URL.Query().Get("page"), 1)
//     limit := parseIntDefault(r.URL.Query().Get("limit"), 25)
//     if limit <= 0 || limit > 1000 {
//         limit = 25
//     }

//     q := strings.TrimSpace(r.URL.Query().Get("q"))
//     roleIDStr := strings.TrimSpace(r.URL.Query().Get("role_id"))
//     deptIDStr := strings.TrimSpace(r.URL.Query().Get("department_id"))
//     isActiveStr := strings.TrimSpace(r.URL.Query().Get("is_active"))

//     var roleID, deptID uuid.UUID
//     if roleIDStr != "" {
//         roleID, _ = uuid.Parse(roleIDStr)
//     }
//     if deptIDStr != "" {
//         deptID, _ = uuid.Parse(deptIDStr)
//     }

//     var isActive *bool
//     if isActiveStr != "" {
//         b, err := strconv.ParseBool(isActiveStr)
//         if err == nil {
//             isActive = &b
//         }
//     }

//     filter := service.EmployeeFilter{
//         Query: q,
//         RoleID: roleID,
//         DepartmentID: deptID,
//         IsActive: isActive,
//     }

//     companyID := uuid.MustParse(companyCtx.CompanyID)
//     employees, total, err := h.adminService.ListEmployeesByCompany(ctx, companyID, filter, page, limit)
//     if err != nil {
//         h.respondWithError(w, h.getStatusCode(err), err, "Failed to list employees")
//         return
//     }

//     meta := map[string]interface{}{"page": page, "limit": limit, "total": total}
//     h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{"items": employees, "meta": meta}, "Employees retrieved"))
// }

// // GetCompanyContext - Get user's company context
// func (h *CompanyHandler) GetCompanyContext(w http.ResponseWriter, r *http.Request) {
//     ctx := r.Context()

//     userID, err := h.getRequesterUserID(r)
//     if err != nil {
//         h.respondWithError(w, http.StatusUnauthorized, err, "Authentication required")
//         return
//     }

//     companyContext, err := h.companyService.GetCompanyContext(ctx, userID)
//     if err != nil {
//         h.respondWithError(w, http.StatusNotFound, err, "Company context not found")
//         return
//     }

//     if companyContext == nil {
//         h.respondWithError(w, http.StatusNotFound,
//             fmt.Errorf("user not associated with any company"),
//             "No company association found")
//         return
//     }

//     h.respondWithJSON(w, http.StatusOK, successResponse(companyContext, "Company context retrieved"))
// }

// // ---------- RBAC middleware ---------- //

// // RequireAdminPermission returns a middleware that ensures the requester (admin) has the required permission.
// func (h *CompanyHandler) RequireAdminPermission(permission string) func(http.Handler) http.Handler {
//     return func(next http.Handler) http.Handler {
//         return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//             // admin permissions are expected to be on context as []string under "admin_permissions"
//             perms, _ := r.Context().Value("admin_permissions").([]string)
//             for _, p := range perms {
//                 if p == permission {
//                     next.ServeHTTP(w, r)
//                     return
//                 }
//             }
//             h.respondWithError(w, http.StatusForbidden, fmt.Errorf("missing admin permission %s", permission), "Forbidden")
//         })
//     }
// }

// // RequireCompanyPermission ensures that the user belongs to a company and has the required permission
// func (h *CompanyHandler) RequireCompanyPermission(permission string) func(http.Handler) http.Handler {
//     return func(next http.Handler) http.Handler {
//         return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//             userID, err := h.getRequesterUserID(r)
//             if err != nil {
//                 h.respondWithError(w, http.StatusUnauthorized, err, "Authentication required")
//                 return
//             }
//             ctx := r.Context()
//             companyCtx, err := h.companyService.GetCompanyContext(ctx, userID)
//             if err != nil || companyCtx == nil {
//                 h.respondWithError(w, http.StatusForbidden, fmt.Errorf("no company association"), "Forbidden")
//                 return
//             }
//             if !h.hasPermission(companyCtx.Permissions, permission) {
//                 h.respondWithError(w, http.StatusForbidden, fmt.Errorf("missing permission %s", permission), "Forbidden")
//                 return
//             }
//             // attach company context to request for handlers that need it
//             ctx = contextWithCompanyContext(ctx, companyCtx)
//             next.ServeHTTP(w, r.WithContext(ctx))
//         })
//     }
// }

// // small helper to add company context to request context
// func contextWithCompanyContext(ctx context.Context, cc *models.CompanyContext) context.Context {
//     return context.WithValue(ctx, "company_context", cc)
// }

// // ---------- Helpers ---------- //

// func (h *CompanyHandler) getRequesterAdminID(r *http.Request) (uuid.UUID, error) {
//     userID, ok := r.Context().Value("user_id").(string)
//     if !ok || userID == "" {
//         return uuid.Nil, fmt.Errorf("admin ID not found in request context")
//     }
//     return uuid.Parse(userID)
// }

// func (h *CompanyHandler) getRequesterUserID(r *http.Request) (uuid.UUID, error) {
//     userID, ok := r.Context().Value("user_id").(string)
//     if !ok || userID == "" {
//         return uuid.Nil, fmt.Errorf("user ID not found in request context")
//     }
//     return uuid.Parse(userID)
// }

// func (h *CompanyHandler) hasPermission(permissions []string, required string) bool {
//     for _, perm := range permissions {
//         if perm == required {
//             return true
//         }
//     }
//     return false
// }

// func (h *CompanyHandler) getStatusCode(err error) int {
//     errMsg := err.Error()
//     switch {
//     case strings.Contains(errMsg, "not found"):
//         return http.StatusNotFound
//     case strings.Contains(errMsg, "already exists"):
//         return http.StatusConflict
//     case strings.Contains(errMsg, "permission") || strings.Contains(errMsg, "unauthorized"):
//         return http.StatusForbidden
//     case strings.Contains(errMsg, "invalid"):
//         return http.StatusBadRequest
//     default:
//         return http.StatusInternalServerError
//     }
// }

// func (h *CompanyHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
//     w.Header().Set("Content-Type", "application/json")
//     w.WriteHeader(statusCode)
//     json.NewEncoder(w).Encode(data)
// }

// func (h *CompanyHandler) respondWithError(w http.ResponseWriter, statusCode int, err error, message string) {
//     h.logger.Warn("Company HTTP error",
//         zap.Error(err),
//         zap.Int("status_code", statusCode),
//         zap.String("message", message),
//     )
//     h.respondWithJSON(w, statusCode, errorResponse(err, message))
// }

// // parseIntDefault parses string to int and returns def on error or empty
// func parseIntDefault(s string, def int) int {
//     if s == "" {
//         return def
//     }
//     i, err := strconv.Atoi(s)
//     if err != nil {
//         return def
//     }
//     return i
// }
