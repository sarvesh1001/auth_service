package handler

import (
	authMiddleware "auth-service/internal/middleware"
	"auth-service/internal/service"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func NewRouter(
	otpHandler *OTPHandler,
	adminHandler *AdminHandler,
	authHandler *AuthHandler,
	rbacHandler *RBACHandler,
	pairingHandler *PairingHandler,
	wsHandler *WebSocketHandler,
	sessionService *service.SessionService,
	jwtService *service.JWTService,
	logger *zap.Logger,
) chi.Router {
	router := chi.NewRouter()

	// ============================================================
	// GLOBAL MIDDLEWARES
	// ============================================================
	// router.Use(requireHTTPS)
	router.Use(chiMiddleware.RequestID)
	router.Use(chiMiddleware.RealIP)
	router.Use(LoggerMiddleware(logger))
	router.Use(chiMiddleware.Recoverer)
	router.Use(chiMiddleware.Timeout(60 * time.Second))

	// CORS - Add required headers
	router.Use(cors.Handler(cors.Options{
		AllowedOrigins: []string{"https://*", "http://localhost:3000", "http://localhost:8080"},
		AllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token",
			"X-Session-Type", "X-Device-ID", "X-Company-ID"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// ============================================================
	// HEALTH CHECK
	// ============================================================
	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		logger.Info("Health check requested")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "healthy",
			"service": "auth-service",
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
	})

	// ============================================================
	// MAIN API
	// ============================================================
	router.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", adminHandler.HealthCheckHandler)

		// ============================================================
		// PUBLIC ROUTES (NO AUTH REQUIRED)
		// ============================================================

		// Super admin initialization endpoints (public - for initial setup)
		r.Route("/setup", func(r chi.Router) {
			r.Post("/super-admin", adminHandler.InitSuperAdminHandler)
			r.Get("/super-admin/status", adminHandler.CheckSuperAdminStatusHandler)
		})

		// Admin authentication routes (public)
		r.Route("/admin-auth", func(r chi.Router) {
			r.Post("/login/initiate", adminHandler.InitiateAdminLogin)
			r.Post("/login/verify-otp", adminHandler.VerifyAdminOTPLogin)
			r.Post("/login/verify-mpin", adminHandler.VerifyAdminMPINLogin)
			r.Post("/mpin/setup", adminHandler.SetupAdminMPIN)
			r.Post("/mpin/change", adminHandler.ChangeAdminMPIN)
			r.Post("/mpin/forgot", adminHandler.ForgotAdminMPIN)
			r.Post("/mpin/forgot/verify", adminHandler.VerifyForgotAdminMPIN)
			r.Post("/refresh", adminHandler.RefreshAdminTokens)
			r.Post("/logout", adminHandler.LogoutAdmin)
			r.Get("/health", adminHandler.HealthCheck)
		})

		// User public routes
		authHandler.RegisterPublicRoutes(r)
		authHandler.RegisterUserPublicRoutes(r)
		otpHandler.RegisterRoutes(r)

		// ============================================================
		// WEB LOGIN (QR PAIRING) ROUTES (PUBLIC)
		// ============================================================
		r.Route("/web/login", func(r chi.Router) {
			r.Get("/qr", pairingHandler.GenerateQR)
			r.Get("/status", pairingHandler.Status)
			r.Post("/confirm", pairingHandler.Confirm)
			r.Get("/ws", pairingHandler.WebSocket)

			// Mobile pairing (requires JWT + Session Validation)
			r.With(
				authMiddleware.JWTAuthMiddlewareWithRedis(sessionService, logger),
				authMiddleware.SessionValidationMiddleware(sessionService, logger),
			).Post("/pair", pairingHandler.Pair)
		})

		// ============================================================
		// PROTECTED ROUTES (JWT + SESSION VALIDATION REQUIRED)
		// ============================================================
		r.Group(func(r chi.Router) {
			// JWT Middleware (parses token and adds claims to context)
			r.Use(authMiddleware.JWTAuthMiddlewareWithRedis(sessionService, logger))

			// Session Validation Middleware (performs all security checks)
			r.Use(authMiddleware.SessionValidationMiddleware(sessionService, logger))

			// ============================================================
			// USER AUTH PROTECTED ROUTES
			// ============================================================
			authHandler.RegisterProtectedRoutes(r)

			// ============================================================
			// COMPANY EMPLOYEE SEARCH ROUTES
			// ============================================================
			r.Route("/companies/{companyID}/employees", func(r chi.Router) {
				// Use EnhancedCompanyAccessMiddleware which checks JWT company ID
				r.Use(EnhancedCompanyAccessMiddleware(jwtService, logger))

				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
					Post("/search", authHandler.SearchCompanyEmployees)

				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
					Get("/search/advanced", authHandler.SearchCompanyEmployeesAdvanced)

				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
					Get("/search/suggestions", authHandler.GetCompanyEmployeeSuggestions)

				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
					Get("/suggestions", authHandler.GetCompanyEmployeeSuggestions)

				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
					Get("/username/{username}", authHandler.FindCompanyEmployeeByUsername)
			})

			// ============================================================
			// COMPANY OWNER ROUTES (NON-ADMIN COMPANY OWNERS)
			// ============================================================
			r.Route("/companies/{companyID}", func(r chi.Router) {
				r.Use(EnhancedCompanyAccessMiddleware(jwtService, logger))

				r.Get("/", adminHandler.GetCompany)
				r.Get("/getemployees", adminHandler.GetCompanyEmployees)
				r.Get("/roles", adminHandler.GetCompanyRoles)
				r.Get("/hierarchy", adminHandler.GetCompanyHierarchy)
				r.Get("/stats", adminHandler.GetCompanyStats)

				// Owner-only operations
				// r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.create", logger)).
				//     Post("/departments/create", rbacHandler.CreateDepartment)

				// r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
				//     Put("/employees/{userID}/role", adminHandler.UpdateEmployeeRole)
			})

			// ============================================================
			// COMPANY RBAC ROUTES
			// ============================================================
			r.Route("/companies/{companyID}/rbac", func(r chi.Router) {
				r.Use(EnhancedCompanyAccessMiddleware(jwtService, logger))

				// ===============================
				// ROLE MANAGEMENT
				// ===============================
				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.create", logger)).
					Post("/roles", rbacHandler.CreateRole)

				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
					Get("/roles", rbacHandler.ListRoles)

				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
					Get("/roles/{roleID}", rbacHandler.GetRole)

				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.update", logger)).
					Put("/roles/{roleID}", rbacHandler.UpdateRole)

				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.delete", logger)).
					Delete("/roles/{roleID}", rbacHandler.DeleteRole)

				// Employee Management
				r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create", logger)).
					Post("/employees", rbacHandler.AddEmployee)

				// Manager Management
				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
					Post("/managers", rbacHandler.AddManager)

				// Available Permissions
				r.With(authMiddleware.BitmaskPermissionMiddleware("hr.employee.create", logger)).
					Get("/available-permissions", rbacHandler.GetAvailablePermissions)

				// ===============================
				// PERMISSION MANAGEMENT
				// ===============================
				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
					Post("/roles/{roleID}/permissions", rbacHandler.AssignPermissionsToRole)

				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
					Delete("/roles/{roleID}/permissions", rbacHandler.RemovePermissionsFromRole)

				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
					Get("/roles/{roleID}/permissions", rbacHandler.GetRolePermissions)

				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
					Put("/roles/{roleID}/permissions", rbacHandler.ReplaceRolePermissions)

				// ===============================
				// GLOBAL PERMISSION QUERIES
				// ===============================
				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
					Get("/permissions", rbacHandler.ListAllPermissions)

				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
					Get("/permissions/module/{module}", rbacHandler.ListPermissionsByModule)

				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
					Get("/permissions/name/{permissionName}", rbacHandler.GetPermissionByName)

				// ===============================
				// DEPARTMENT MANAGEMENT
				// ===============================
				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.view", logger)).
					Get("/departments", rbacHandler.ListDepartments)

				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.department.update", logger)).
					Put("/departments/{departmentID}/rename", rbacHandler.RenameDepartment)

				// ===============================
				// USER PERMISSIONS & HIERARCHY
				// ===============================
				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
					Get("/users/{userID}/permissions", rbacHandler.GetUserPermissions)

				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
					Get("/users/{userID}/permissions/bitmask", rbacHandler.GetUserPermissionBitmask)

				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
					Get("/users/{userID}/permissions/check", rbacHandler.CheckUserPermission)

				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
					Get("/users/{userID}/hierarchy", rbacHandler.GetUserHierarchy)

				// ===============================
				// BULK ROLE ASSIGNMENT
				// ===============================
				r.With(authMiddleware.BitmaskPermissionMiddleware("administrative.role.assign", logger)).
					Post("/bulk-assign", rbacHandler.BulkAssignRoles)
			})

			// ============================================================
			// ADMIN PROTECTED ROUTES (WITH ADMIN SESSION CHECK)
			// ============================================================
			r.Route("/admin", func(r chi.Router) {
				// Admin session type check
				r.Use(AdminSessionMiddleware(logger))

				// ===== ADMIN MANAGEMENT ROUTES =====
				r.Route("/admins", func(r chi.Router) {
					// Admin stats
					r.Get("/stats", adminHandler.GetStats)

					// Create admin
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.create", logger)).
						Post("/", adminHandler.CreateAdminUser)

					// Get admin phone (super admin only)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.system_config", logger)).
						Get("/{adminID}/phone", adminHandler.GetAdminPhoneNumber)

					// List admins
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
						Get("/", adminHandler.ListAdmins)

					// Get all admins
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
						Get("/all", adminHandler.GetAllAdmins)

					// Get active admins
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
						Get("/active", adminHandler.GetActiveAdmins)

					// Get inactive admins
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
						Get("/inactive", adminHandler.GetInactiveAdmins)

					// Get admins by role type
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
						Get("/role-type/{roleType}", adminHandler.GetAdminsByRoleType)

					// Get admins by role
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
						Get("/role/{roleID}", adminHandler.GetAdminsByRole)

					// Available managers
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
						Get("/available-managers", adminHandler.GetAvailableManagers)

					// Admin search routes
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
						Get("/search", adminHandler.SearchAdmins)

					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
						Get("/search/advanced", adminHandler.SearchAdminsAdvanced)

					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
						Get("/search/name", adminHandler.SearchAdminsByName)

					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
						Get("/search/employees", adminHandler.SearchAdminEmployees)

					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
						Get("/search/managers", adminHandler.SearchAdminManagers)

					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
						Get("/search/suggestions", adminHandler.GetAdminSuggestions)

					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
						Get("/search/analytics", adminHandler.GetAdminSearchAnalytics)

					// ===== ADMIN BY ID ROUTES =====
					r.Route("/{adminID}", func(r chi.Router) {
						// Get admin
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
							Get("/", adminHandler.GetAdminUser)
						// Add this new route for getting admin departments
						r.Get("/departments", adminHandler.GetAdminDepartments)

						// Update admin
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.update", logger)).
							Put("/", adminHandler.UpdateAdminUser)

						// Delete admin
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.delete", logger)).
							Delete("/", adminHandler.DeleteAdminUser)

						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.manage_roles", logger)).
							Put("/role", adminHandler.UpdateAdminUserRole)
						// Admin profile management
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.update", logger)).
							Put("/profile", adminHandler.UpdateAdminProfile)

						// Change admin phone
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.update", logger)).
							Put("/phone", adminHandler.ChangeAdminPhone)

						// Update reports to
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.update", logger)).
							Put("/reports-to", adminHandler.UpdateAdminReportsTo)

						// Status management
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.update", logger)).
							Post("/activate", adminHandler.ActivateAdmin)

						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.update", logger)).
							Post("/deactivate", adminHandler.DeactivateAdmin)

						// Avatar management
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.update", logger)).
							Post("/avatar", adminHandler.SetAdminAvatar)

						r.Get("/avatar", adminHandler.GetAdminAvatar)

						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.update", logger)).
							Delete("/avatar", adminHandler.DeactivateAdminAvatar)

						r.Get("/avatar/with-fallback", adminHandler.GetAdminAvatarWithFallback)
						r.Get("/avatar/info", adminHandler.GetAvatarInfo)

						// Hierarchy management
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
							Get("/direct-reports", adminHandler.GetDirectReports)

						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
							Get("/reporting-chain", adminHandler.GetReportingChain)

						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
							Get("/hierarchy", adminHandler.GetAdminHierarchy)

						// Permission management
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.permission.view", logger)).
							Get("/permissions", adminHandler.GetAdminPermissions)

						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.permission.view", logger)).
							Get("/permissions/mask", adminHandler.GetAdminPermissionMask)

						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.permission.view", logger)).
							Get("/permissions/check", adminHandler.CheckAdminPermission)

						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.permission.view", logger)).
							Get("/with-permissions", adminHandler.GetAdminWithPermissions)

						// Admin details
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
							Get("/details", adminHandler.GetAdminWithDetails)

						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
							Get("/with-reports-to-name", adminHandler.GetAdminWithReportsToName)

						// Department access
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
							Get("/department-access/{department}", adminHandler.CheckAdminDepartmentAccess)

						// Failed login management
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.update", logger)).
							Post("/reset-failed-login", adminHandler.ResetAdminFailedLoginAttempts)
					})

					// Bulk operations
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.update", logger)).
						Post("/bulk-update-reports-to", adminHandler.BulkUpdateReportsTo)
				})

				// ===== ADMIN ROLE MANAGEMENT ROUTES =====
				// In the router.go file, inside the RegisterRoutes method or NewRouter function:

				// ===== ADMIN ROLE MANAGEMENT ROUTES =====
				r.Route("/roles", func(r chi.Router) {
					// ===== EMPLOYEE ROLE MANAGEMENT (Employee Management Dept) =====
					// Create employee role
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.create", logger)).
						Post("/employee", adminHandler.CreateEmployeeRole)

					// Get employee roles
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.employee.view", logger)).
						Get("/employee", adminHandler.GetEmployeeAdminRoles)

					// ===== MANAGER ROLE MANAGEMENT (Manager Management Dept) =====
					// Create manager role
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.manager.create", logger)).
						Post("/manager", adminHandler.CreateManagerRole)

					// Get manager roles
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.manager.view", logger)).
						Get("/manager", adminHandler.GetManagerAdminRoles)

					// ===== GENERAL ROLE MANAGEMENT (Company Management Dept) =====
					// Create general admin role (if needed)
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.create", logger)).
						Post("/", adminHandler.CreateAdminRole)

					// Get all roles
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
						Get("/", adminHandler.GetAdminRoles)

					// Search roles
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
						Get("/search", adminHandler.SearchAdminRoles)

					// Get roles by type
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
						Get("/type/{roleType}", adminHandler.GetAdminRolesByType)

					// ===== ROLE-SPECIFIC OPERATIONS =====
					r.Route("/{roleID}", func(r chi.Router) {
						// Get role by ID
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
							Get("/", adminHandler.GetAdminRole)

						// Get role with details
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
							Get("/details", adminHandler.GetAdminRoleWithDetails)

						// Update role
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update", logger)).
							Put("/", adminHandler.UpdateAdminRole)

						// Delete role
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.delete", logger)).
							Delete("/", adminHandler.DeleteAdminRole)

						// ===== ROLE DEPARTMENT MANAGEMENT =====
						// Get role departments
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
							Get("/departments", adminHandler.GetAdminRoleDepartments)

						// Assign department to role
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update", logger)).
							Post("/departments/{departmentID}", adminHandler.AssignDepartmentToAdminRole)

						// Remove department from role
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update", logger)).
							Delete("/departments/{departmentID}", adminHandler.RemoveDepartmentFromAdminRole)
					})
				})

				// ===== SYSTEM DEPARTMENT BITMASK UTILITIES =====
				r.Route("/departments", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.department.view", logger)).
						Get("/", adminHandler.GetSystemDepartments)

					// Admin by department
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
						Get("/{departmentID}/admins", adminHandler.GetAdminsByDepartment)
				})

				// ===== ADMIN MPIN MANAGEMENT BY ADMIN =====
				r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.update", logger)).
					Post("/mpin/change-by-admin", adminHandler.ChangeAdminMPINByAdmin)

				// ===== USER MANAGEMENT ROUTES (NON-ADMIN USERS) =====
				r.Route("/user-management", func(r chi.Router) {
					// Advanced user search
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
						Get("/search/advanced", adminHandler.SearchUsersAdvanced)

					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
						Get("/search/username", adminHandler.SearchUsersByUsername)

					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
						Get("/search/full-name", adminHandler.SearchUsersByFullName)

					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
						Get("/suggestions", adminHandler.GetUserSuggestions)

					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
						Get("/kyc/{status}", adminHandler.ListUsersByKYCStatus)

					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
						Get("/recently-active", adminHandler.GetRecentlyActiveUsers)

					// Get Banned Users
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
						Get("/banned", adminHandler.GetBannedUsers)

					// User by ID routes
					r.Route("/{userID}", func(r chi.Router) {
						// Update user
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.update", logger)).
							Put("/", adminHandler.UpdateUser)

						// Update User KYC
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.update", logger)).
							Patch("/kyc", adminHandler.UpdateUserKYC)

						// Ban User
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.suspend", logger)).
							Post("/ban", adminHandler.BanUser)

						// Unban User
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.suspend", logger)).
							Post("/unban", adminHandler.UnbanUser)
					})
				})

				// ===== COMPANY MANAGEMENT ROUTES =====
				r.Route("/companies", func(r chi.Router) {
					// CREATE COMPANY
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update", logger)).
						Post("/", adminHandler.CreateCompany)

					// GET COMPANY
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
						Get("/", adminHandler.GetRecentCompanies)

					// SEARCH COMPANIES
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
						Get("/search", adminHandler.SearchCompanies)

					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
						Get("/suggestions", adminHandler.GetCompanySuggestions)

					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
						Get("/analytics/search", adminHandler.GetCompanySearchAnalytics)

					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update", logger)).
						Post("/search/benchmark", adminHandler.BenchmarkCompanySearch)

					// COMPANY BY STATUS/TIER
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
						Get("/status/{status}", adminHandler.GetCompaniesByStatus)

					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
						Get("/tier/{tier}", adminHandler.GetCompaniesByTier)

					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
						Get("/expiring", adminHandler.GetCompaniesWithExpiringSubscription)

					// OWNER-SPECIFIC SEARCH
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
						Get("/owner/{ownerID}/search", adminHandler.SearchCompaniesByOwner)

					// COMPANY BY ID ROUTES
					r.Route("/{companyID}", func(r chi.Router) {
						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
							Get("/", adminHandler.GetCompany)

						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
							Get("/stats", adminHandler.GetCompanyStats)

						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
							Get("/employees", adminHandler.GetCompanyEmployees)

						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
							Get("/departments", adminHandler.GetCompanyDepartments)

						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
							Get("/hierarchy", adminHandler.GetCompanyHierarchy)

						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
							Get("/rbac-stats", adminHandler.GetCompanyRBACStats)

						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.view", logger)).
							Get("/roles", adminHandler.GetCompanyRoles)

						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update", logger)).
							Put("/subscription", adminHandler.UpdateSubscription)

						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update", logger)).
							Post("/subscription/extend", adminHandler.ExtendSubscription)

						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.suspend", logger)).
							Post("/deactivate", adminHandler.DeactivateCompany)

						r.With(authMiddleware.BitmaskPermissionMiddleware("admin.company.update", logger)).
							Post("/reactivate", adminHandler.ReactivateCompany)
					})
				})

				// ===== SYSTEM MANAGEMENT ROUTES =====
				r.Route("/system", func(r chi.Router) {
					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.department.view", logger)).
						Get("/departments", adminHandler.GetSystemDepartments)

					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.permission.view", logger)).
						Get("/permissions", adminHandler.GetAllPermissions)

					r.With(authMiddleware.BitmaskPermissionMiddleware("admin.permission.view", logger)).
						Get("/permissions/module/{module}", adminHandler.GetPermissionsByModule)
				})

				// ===== BULK AVATAR INFO =====
				r.With(authMiddleware.BitmaskPermissionMiddleware("admin.user.view", logger)).
					Post("/bulk-avatar-info", adminHandler.BulkGetAvatarInfo)

				// ===== ADMIN OWNER ROUTES =====
				// r.With(authMiddleware.BitmaskPermissionMiddleware("admin.super.system_config", logger)).
				// 	Get("/owner", adminHandler.GetAdminOwner)

			})
		})
	})

	// ============================================================
	// GLOBAL ERROR HANDLERS
	// ============================================================
	router.NotFound(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "endpoint not found",
			"path":    r.URL.Path,
			"method":  r.Method,
			"service": "auth-service",
		})
	})

	router.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "method not allowed",
			"path":    r.URL.Path,
			"method":  r.Method,
			"service": "auth-service",
		})
	})

	return router
}

// ============================================================================
// MIDDLEWARES
// ============================================================================

func AdminSessionMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionType, ok := r.Context().Value("session_type").(string)
			if !ok || sessionType != "admin" {
				logger.Warn("Access denied: not an admin session",
					zap.String("session_type", sessionType),
					zap.String("path", r.URL.Path),
				)
				respondWithJWTError(w, logger, http.StatusForbidden, "Access denied: admin session required")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Enhanced Company Access Middleware
func EnhancedCompanyAccessMiddleware(jwtService *service.JWTService, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract company ID from URL params
			companyIDStr := chi.URLParam(r, "companyID")
			companyID, err := uuid.Parse(companyIDStr)
			if err != nil {
				respondWithJWTError(w, logger, http.StatusBadRequest, "Invalid company ID")
				return
			}

			// Get session type from context
			sessionType, ok := r.Context().Value("session_type").(string)
			if !ok {
				respondWithJWTError(w, logger, http.StatusUnauthorized, "Session type not found")
				return
			}

			// Get user ID from context
			userIDStr, ok := r.Context().Value("user_id").(string)
			if !ok {
				respondWithJWTError(w, logger, http.StatusUnauthorized, "User not authenticated")
				return
			}

			userID, err := uuid.Parse(userIDStr)
			if err != nil {
				respondWithJWTError(w, logger, http.StatusBadRequest, "Invalid user ID")
				return
			}

			// For non-admin users, check company access
			if sessionType != "admin" {
				// Get company ID from context (validated by session validation middleware)
				validatedCompanyID, ok := r.Context().Value("validated_company_id").(string)
				if !ok || validatedCompanyID == "" {
					respondWithJWTError(w, logger, http.StatusForbidden,
						"Company access denied: No validated company context")
					return
				}

				validatedCompanyUUID, err := uuid.Parse(validatedCompanyID)
				if err != nil {
					respondWithJWTError(w, logger, http.StatusForbidden,
						"Company access denied: Invalid company ID in validated session")
					return
				}

				// Verify the user is accessing their own company
				if validatedCompanyUUID != companyID {
					logger.Warn("Company access violation",
						zap.String("user_id", userID.String()),
						zap.String("requested_company", companyID.String()),
						zap.String("validated_company", validatedCompanyID),
						zap.String("session_type", sessionType))

					respondWithJWTError(w, logger, http.StatusForbidden,
						"Company access denied: You can only access your own company")
					return
				}

				logger.Debug("Company access verified for non-admin user",
					zap.String("user_id", userID.String()),
					zap.String("company_id", companyID.String()),
					zap.String("session_type", sessionType))
			} else {
				logger.Debug("Admin user accessing company - no company restriction",
					zap.String("admin_id", userID.String()),
					zap.String("company_id", companyID.String()))
			}

			// Add company ID and user ID to context
			ctx := context.WithValue(r.Context(), "company_id", companyID)
			ctx = context.WithValue(ctx, "current_user_id", userID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Updated JWTAuthMiddlewareWithRedis to include bitmask handling
// Updated JWTAuthMiddlewareWithRedis to handle role string to role type conversion
func JWTAuthMiddlewareWithRedis(sessionService *service.SessionService, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				respondWithJWTError(w, logger, http.StatusUnauthorized, "Missing authorization header")
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				respondWithJWTError(w, logger, http.StatusUnauthorized, "Invalid authorization header format")
				return
			}

			accessToken := parts[1]
			claims, err := sessionService.ValidateAccessToken(ctx, accessToken)
			if err != nil {
				logger.Warn("Invalid JWT token", zap.Error(err))
				respondWithJWTError(w, logger, http.StatusUnauthorized, "Invalid or expired token")
				return
			}

			// Add claims to context
			ctx = context.WithValue(ctx, "user_id", claims.UserID)
			ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
			ctx = context.WithValue(ctx, "role", claims.Role)
			ctx = context.WithValue(ctx, "session_type", claims.SessionType)
			ctx = context.WithValue(ctx, "jti", claims.JTI)

			// Include permission mask and company ID in context
			if claims.PermissionMask != nil {
				ctx = context.WithValue(ctx, "permission_mask", claims.PermissionMask)
			}

			if claims.CompanyID != "" {
				ctx = context.WithValue(ctx, "company_id", claims.CompanyID)
			}

			// Derive role type from the role string
			roleType := deriveRoleTypeFromString(claims.Role)
			ctx = context.WithValue(ctx, "role_type", roleType)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Helper function to convert role string to role type integer
func deriveRoleTypeFromString(role string) int {
	// Convert role string to role type integer
	switch role {
	case "super_admin", "owner":
		return 4 // RoleTypeSuperAdmin
	case "admin_manager", "manager":
		return 2 // RoleTypeManager
	case "admin_employee", "employee":
		return 1 // RoleTypeEmployee
	default:
		// Default to employee if unknown
		return 1 // RoleTypeEmployee
	}
}

func LoggerMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := chiMiddleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)

			logger.Info("HTTP request",
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.String("query", r.URL.RawQuery),
				zap.String("remote_addr", r.RemoteAddr),
				zap.Int("status", ww.Status()),
				zap.Duration("duration", time.Since(start)),
				zap.String("user_agent", r.UserAgent()),
			)
		})
	}
}

func requireHTTPS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		host := r.Host

		// Allow HTTP on local dev networks:
		if r.TLS == nil &&
			(strings.HasPrefix(host, "localhost") ||
				strings.HasPrefix(host, "127.0.0.1") ||
				strings.HasPrefix(host, "192.168.") ||
				strings.HasPrefix(host, "10.") ||
				strings.HasPrefix(host, "172.16.")) {

			next.ServeHTTP(w, r)
			return
		}

		// All other cases require HTTPS
		if r.TLS == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUpgradeRequired)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "https required"})
			return
		}

		next.ServeHTTP(w, r)
	})
}

func respondWithJWTError(w http.ResponseWriter, logger *zap.Logger, statusCode int, message string) {
	if logger != nil {
		logger.Warn("JWT auth error",
			zap.Int("status_code", statusCode),
			zap.String("message", message),
		)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
		"message": "Authentication failed",
		"code":    statusCode,
	})
}
