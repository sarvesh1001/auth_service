package handler

import (
	c "auth-service/internal/middleware"
	"auth-service/internal/service"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
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
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(LoggerMiddleware(logger))
	router.Use(middleware.Recoverer)
	router.Use(middleware.Timeout(60 * time.Second))

	// CORS
	router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://localhost:3000", "http://localhost:8080"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Session-Type", "X-Device-ID"},
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

		//-----------------------------------------------------------
		// PUBLIC ROUTES
		//-----------------------------------------------------------
		authHandler.RegisterPublicRoutes(r)
		authHandler.RegisterUserPublicRoutes(r)
		otpHandler.RegisterRoutes(r)

		//-----------------------------------------------------------
		// ✅ NEW: WEB LOGIN (QR PAIRING) ROUTES
		//-----------------------------------------------------------
		r.Route("/web/login", func(r chi.Router) {
			r.Get("/qr", pairingHandler.GenerateQR)
			r.Get("/status", pairingHandler.Status)
			r.Post("/confirm", pairingHandler.Confirm)
			r.Get("/ws", pairingHandler.WebSocket)

			// Mobile pairing (requires JWT)
			r.With(c.JWTAuthMiddleware(jwtService, logger)).
				Post("/pair", pairingHandler.Pair)
		})

		//-----------------------------------------------------------
		// ADMIN AUTH (PUBLIC) - Use RegisterRoutes for all admin auth endpoints
		//-----------------------------------------------------------
		adminHandler.RegisterRoutes(r)

		//-----------------------------------------------------------
		// PROTECTED ROUTES (JWT REQUIRED)
		//-----------------------------------------------------------
		r.Group(func(r chi.Router) {

			// NEW JWT Middleware (injects permission mask + session type)
			r.Use(c.JWTAuthMiddleware(jwtService, logger))

			//-----------------------------------------------------------
			// USER AUTH PROTECTED ROUTES
			//-----------------------------------------------------------
			authHandler.RegisterProtectedRoutes(r)

			//-----------------------------------------------------------
			// COMPANY OWNER ROUTES (NON-ADMIN COMPANY OWNERS)
			//-----------------------------------------------------------
			r.Route("/companies/{companyID}", func(r chi.Router) {
				r.Get("/", adminHandler.GetCompany)
				r.Get("/employees", adminHandler.GetCompanyEmployees)
				r.Get("/departments", adminHandler.GetCompanyDepartments)
				r.Get("/roles", adminHandler.GetCompanyRoles)
				r.Get("/hierarchy", adminHandler.GetCompanyHierarchy)
				r.Get("/stats", adminHandler.GetCompanyStats)

				// Owner-only operations (protected by bitmask)
				r.With(c.BitmaskPermissionMiddleware("administrative.department.create", logger)).
					Post("/departments", adminHandler.CreateDepartment)

				r.With(c.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
					Put("/employees/{userID}/role", adminHandler.UpdateEmployeeRole)
			})

			//-----------------------------------------------------------
			// COMPANY RBAC ROUTES
			//-----------------------------------------------------------
			r.Route("/companies/{companyID}/rbac", func(r chi.Router) {

				r.Use(CompanyAccessMiddleware())

				// ===============================
				// ROLE MANAGEMENT
				// ===============================
				r.With(c.BitmaskPermissionMiddleware("administrative.department.create", logger)).
					Post("/roles", rbacHandler.CreateRole)

				r.With(c.BitmaskPermissionMiddleware("administrative.department.view", logger)).
					Get("/roles", rbacHandler.ListRoles)

				r.With(c.BitmaskPermissionMiddleware("administrative.department.view", logger)).
					Get("/roles/{roleID}", rbacHandler.GetRole)

				r.With(c.BitmaskPermissionMiddleware("administrative.department.update", logger)).
					Put("/roles/{roleID}", rbacHandler.UpdateRole)

				r.With(c.BitmaskPermissionMiddleware("administrative.department.delete", logger)).
					Delete("/roles/{roleID}", rbacHandler.DeleteRole)

				// Employee Management
				r.With(c.BitmaskPermissionMiddleware("hr.employee.create", logger)).
					Post("/employees", rbacHandler.AddEmployee)

				// Manager Management
				r.With(c.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
					Post("/managers", rbacHandler.AddManager)

				// Available Permissions for current user
				r.With(c.BitmaskPermissionMiddleware("hr.employee.create", logger)).
					Get("/available-permissions", rbacHandler.GetAvailablePermissions)

				// ===============================
				// PERMISSION MANAGEMENT
				// ===============================
				r.With(c.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
					Post("/roles/{roleID}/permissions", rbacHandler.AssignPermissionsToRole)

				r.With(c.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
					Delete("/roles/{roleID}/permissions", rbacHandler.RemovePermissionsFromRole)

				r.With(c.BitmaskPermissionMiddleware("administrative.department.view", logger)).
					Get("/roles/{roleID}/permissions", rbacHandler.GetRolePermissions)

				r.With(c.BitmaskPermissionMiddleware("administrative.employee.manage", logger)).
					Put("/roles/{roleID}/permissions", rbacHandler.ReplaceRolePermissions)

				// ===============================
				// GLOBAL PERMISSION QUERIES
				// ===============================
				r.With(c.BitmaskPermissionMiddleware("administrative.department.view", logger)).
					Get("/permissions", rbacHandler.ListAllPermissions)

				r.With(c.BitmaskPermissionMiddleware("administrative.department.view", logger)).
					Get("/permissions/module/{module}", rbacHandler.ListPermissionsByModule)

				r.With(c.BitmaskPermissionMiddleware("administrative.department.view", logger)).
					Get("/permissions/name/{permissionName}", rbacHandler.GetPermissionByName)

				// ===============================
				// DEPARTMENT MANAGEMENT
				// ===============================
				r.With(c.BitmaskPermissionMiddleware("administrative.department.create", logger)).
					Post("/departments", rbacHandler.CreateDepartment)

				r.With(c.BitmaskPermissionMiddleware("administrative.department.view", logger)).
					Get("/departments", rbacHandler.ListDepartments)

				r.With(c.BitmaskPermissionMiddleware("administrative.department.update", logger)).
					Put("/departments/{departmentID}", rbacHandler.UpdateDepartment)

				r.With(c.BitmaskPermissionMiddleware("administrative.department.update", logger)).
					Put("/departments/{departmentID}/rename", rbacHandler.RenameDepartment)

				r.With(c.BitmaskPermissionMiddleware("administrative.department.delete", logger)).
					Delete("/departments/{departmentID}", rbacHandler.DeactivateDepartment)

				// ===============================
				// USER PERMISSIONS & HIERARCHY
				// ===============================
				r.With(c.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
					Get("/users/{userID}/permissions", rbacHandler.GetUserPermissions)

				r.With(c.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
					Get("/users/{userID}/permissions/bitmask", rbacHandler.GetUserPermissionBitmask)

				r.With(c.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
					Get("/users/{userID}/permissions/check", rbacHandler.CheckUserPermission)

				r.With(c.BitmaskPermissionMiddleware("administrative.employee.view", logger)).
					Get("/users/{userID}/hierarchy", rbacHandler.GetUserHierarchy)

				// ===============================
				// BULK ROLE ASSIGNMENT
				// ===============================
				r.With(c.BitmaskPermissionMiddleware("administrative.role.assign", logger)).
					Post("/bulk-assign", rbacHandler.BulkAssignRoles)
			})

			//-----------------------------------------------------------
			// ADMIN PROTECTED ROUTES
			//-----------------------------------------------------------
			r.Route("/admin", func(r chi.Router) {

				// NEW: Admin JWT middleware (admins automatically get full access)
				r.Use(c.AdminJWTAuthMiddleware(jwtService, logger))
				r.Post("/mpin/change-by-admin", adminHandler.ChangeAdminMPINByAdmin)

				// All admin routes remain as they are
				// --------------------------------------------------------
				// SYSTEM / PERMISSIONS / COMPANY / EMPLOYEE / RBAC
				// --------------------------------------------------------
				r.Get("/debug/companies/{companyID}/departments", adminHandler.DebugCompanyDepartments)
				r.Route("/permissions", func(r chi.Router) {
					r.Get("/system-departments", adminHandler.GetSystemDepartments)
					r.Get("/", adminHandler.GetAllPermissions)
					r.Get("/module/{module}", adminHandler.GetPermissionsByModule)
				})

				// Company Management
				r.Route("/companies", func(r chi.Router) {
					r.Post("/", adminHandler.CreateCompany)
					r.Get("/status/{status}", adminHandler.GetCompaniesByStatus)
					r.Get("/recent", adminHandler.GetRecentCompanies)
					r.Get("/expiring-subscriptions", adminHandler.GetCompaniesWithExpiringSubscription)
					r.Get("/tier/{tier}", adminHandler.GetCompaniesByTier)

					r.Route("/{companyID}", func(r chi.Router) {
						r.Get("/", adminHandler.GetCompany)
						r.Patch("/deactivate", adminHandler.DeactivateCompany)
						r.Patch("/activate", adminHandler.ReactivateCompany)
						r.Patch("/extend-subscription", adminHandler.ExtendSubscription)
						r.Patch("/subscription", adminHandler.UpdateSubscription)
						r.Get("/stats", adminHandler.GetCompanyStats)
						r.Get("/rbac-stats", adminHandler.GetCompanyRBACStats)

						r.Get("/employees", adminHandler.GetCompanyEmployees)
						r.Get("/departments", adminHandler.GetCompanyDepartments)
						r.Post("/departments", adminHandler.CreateDepartment)
						r.Get("/roles", adminHandler.GetCompanyRoles)
						r.Post("/roles", adminHandler.CreateRole)
						r.Get("/hierarchy", adminHandler.GetCompanyHierarchy)

						r.Post("/employees/bulk-assign", adminHandler.BulkAssignRoles)
					})
				})

				// Employee Management
				r.Route("/employees", func(r chi.Router) {
					r.Route("/{userID}", func(r chi.Router) {
						r.Put("/role", adminHandler.UpdateEmployeeRole)
						r.Get("/permissions", adminHandler.GetEmployeePermissions)
						r.Get("/hierarchy", adminHandler.GetUserHierarchy)
					})
					r.Post("/check-permission", adminHandler.CheckEmployeePermission)
				})

				// Role Permission Management
				r.Route("/roles", func(r chi.Router) {
					r.Route("/{roleID}", func(r chi.Router) {
						r.Post("/permissions", adminHandler.GrantRolePermissions)
					})
				})

				// Admin Management
				r.Route("/admins", func(r chi.Router) {
					r.Get("/stats", adminHandler.GetStats)
					r.Patch("/owner/phone", adminHandler.ChangeOwnerPhone)
					r.Post("/invite", adminHandler.InviteAdmin)
					r.Patch("/{adminID}/role", adminHandler.PromoteAdmin)
					r.Patch("/{adminID}/permissions", adminHandler.UpdateAdminPermissions)
					r.Delete("/{adminID}", adminHandler.RemoveAdmin)
					r.Patch("/{adminID}/deactivate", adminHandler.DeactivateAdmin)
					r.Patch("/{adminID}/activate", adminHandler.ActivateAdmin)
					r.Get("/{adminID}", adminHandler.GetAdminByID)
					r.Get("/phone/{phone}", adminHandler.GetAdminByPhone)
					r.Get("/", adminHandler.ListAdmins)
					r.Get("/role/{roleLevel}", adminHandler.GetAdminsByRole)
					r.Get("/status/{status}", adminHandler.GetAdminsByStatus)
				})

				// Global RBAC (Admin-only)
				r.Route("/rbac", func(r chi.Router) {
					r.Post("/permissions", rbacHandler.CreatePermission)
				})
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

func CompanyAccessMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract company ID from URL params
			companyIDStr := chi.URLParam(r, "companyID")
			companyID, err := uuid.Parse(companyIDStr)
			if err != nil {
				respondWithJWTError(w, nil, http.StatusBadRequest, "Invalid company ID")
				return
			}

			// Get user ID from context
			userIDStr, ok := r.Context().Value("user_id").(string)
			if !ok {
				respondWithJWTError(w, nil, http.StatusUnauthorized, "User not authenticated")
				return
			}

			userID, err := uuid.Parse(userIDStr)
			if err != nil {
				respondWithJWTError(w, nil, http.StatusBadRequest, "Invalid user ID")
				return
			}

			// Add company ID and user ID to context
			ctx := context.WithValue(r.Context(), "company_id", companyID)
			ctx = context.WithValue(ctx, "current_user_id", userID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func JWTAuthMiddleware(jwtService *service.JWTService, logger *zap.Logger) func(http.Handler) http.Handler {
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
			claims, err := jwtService.ValidateAccessToken(ctx, accessToken)
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

			if claims.AdminRoleLevel != "" {
				ctx = context.WithValue(ctx, "admin_role_level", claims.AdminRoleLevel)
			}
			if claims.AdminPermissions != nil {
				ctx = context.WithValue(ctx, "admin_permissions", claims.AdminPermissions)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func LoggerMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
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
