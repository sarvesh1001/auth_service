package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"auth-service/internal/service"

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
	sessionService *service.SessionService,
	jwtService *service.JWTService,
	logger *zap.Logger,
) chi.Router {
	router := chi.NewRouter()

	// Global middlewares
	router.Use(requireHTTPS)
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(LoggerMiddleware(logger))
	router.Use(middleware.Recoverer)
	router.Use(middleware.Timeout(60 * time.Second))

	// CORS configuration
	router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://localhost:3000", "http://localhost:8080"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Session-Type", "X-Device-ID"},
		ExposedHeaders:   []string{"Link", "Retry-After", "Content-Disposition"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Health check
	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		logger.Info("Health check requested")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "healthy",
			"service": "auth-service",
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
	})

	// Main API routes
	router.Route("/api/v1", func(r chi.Router) {
		// Public routes
		authHandler.RegisterPublicRoutes(r)
		authHandler.RegisterUserPublicRoutes(r)
		otpHandler.RegisterRoutes(r)

		// Admin auth routes (public)
		r.Route("/admin-auth", func(r chi.Router) {
			r.Post("/init-owner", adminHandler.InitializeOwner)
			r.Get("/health", adminHandler.HealthCheck)
			r.Post("/login/initiate", adminHandler.InitiateAdminLogin)
			r.Post("/login/verify-otp", adminHandler.VerifyAdminOTPLogin)
			r.Post("/login/verify-mpin", adminHandler.VerifyAdminMPINLogin)
			r.Post("/mpin/setup", adminHandler.SetupAdminMPIN)
			r.Post("/refresh", adminHandler.RefreshAdminTokens)
			r.Post("/logout", adminHandler.LogoutAdmin)
		})

		// Protected routes (JWT required)
		r.Group(func(r chi.Router) {
			r.Use(JWTAuthMiddleware(jwtService, logger))

			// Auth protected routes (user session)
			authHandler.RegisterProtectedRoutes(r)

			// Company RBAC routes (user session)
			r.Route("/companies/{companyID}/rbac", func(r chi.Router) {
				r.Use(CompanyAccessMiddleware())

				// Role management
				r.Post("/roles", rbacHandler.CreateRole)
				r.Get("/roles", rbacHandler.ListRoles)
				r.Put("/roles/{roleID}", rbacHandler.UpdateRole)
				r.Delete("/roles/{roleID}", rbacHandler.DeleteRole)

				// Permission management
				r.Post("/roles/{roleID}/permissions", rbacHandler.AssignPermissionsToRole)
				r.Delete("/roles/{roleID}/permissions", rbacHandler.RemovePermissionsFromRole)
				r.Get("/roles/{roleID}/permissions", rbacHandler.GetRolePermissions)
				r.Put("/roles/{roleID}/permissions", rbacHandler.ReplaceRolePermissions)

				// Global permission queries
				r.Get("/permissions", rbacHandler.ListAllPermissions)
				r.Get("/permissions/module/{module}", rbacHandler.ListPermissionsByModule)
				r.Get("/permissions/name/{permissionName}", rbacHandler.GetPermissionByName)

				// Department management
				r.Post("/departments", rbacHandler.CreateDepartment)
				r.Get("/departments", rbacHandler.ListDepartments)
				r.Put("/departments/{departmentID}", rbacHandler.UpdateDepartment)
				r.Delete("/departments/{departmentID}", rbacHandler.DeactivateDepartment)

				// User permissions and hierarchy
				r.Get("/users/{userID}/permissions", rbacHandler.GetUserPermissions)
				r.Get("/users/{userID}/permissions/check", rbacHandler.CheckUserPermission)
				r.Get("/users/{userID}/hierarchy", rbacHandler.GetUserHierarchy)

				// Bulk operations
				r.Post("/bulk-assign", rbacHandler.BulkAssignRoles)
			})

			// Admin protected routes (admin session)
			r.Route("/admin", func(r chi.Router) {
				r.Use(AdminSessionMiddleware(logger))

				// ============================================================================
				// COMPLETE RBAC FLOW MANAGEMENT
				// ============================================================================

				// System and Permission Management
				r.Route("/permissions", func(r chi.Router) {
					r.Get("/system-departments", adminHandler.GetSystemDepartments)
					r.Get("/", adminHandler.GetAllPermissions)
					r.Get("/module/{module}", adminHandler.GetPermissionsByModule)
				})

				// Enhanced Company Management with RBAC
				r.Route("/companies", func(r chi.Router) {
					// Enhanced company creation with RBAC setup
					r.Post("/", adminHandler.CreateCompany)

					// Company listing and filtering
					r.Get("/status/{status}", adminHandler.GetCompaniesByStatus)
					r.Get("/recent", adminHandler.GetRecentCompanies)
					r.Get("/expiring-subscriptions", adminHandler.GetCompaniesWithExpiringSubscription)
					r.Get("/tier/{tier}", adminHandler.GetCompaniesByTier)

					// Company-specific operations
					r.Route("/{companyID}", func(r chi.Router) {
						r.Get("/", adminHandler.GetCompany)
						r.Patch("/deactivate", adminHandler.DeactivateCompany)
						r.Patch("/activate", adminHandler.ReactivateCompany)
						r.Patch("/extend-subscription", adminHandler.ExtendSubscription)
						r.Patch("/subscription", adminHandler.UpdateSubscription)
						r.Get("/stats", adminHandler.GetCompanyStats)
						r.Get("/rbac-stats", adminHandler.GetCompanyRBACStats)

						// Company employees
						r.Get("/employees", adminHandler.GetCompanyEmployees)

						// Company departments
						r.Get("/departments", adminHandler.GetCompanyDepartments)
						r.Post("/departments", adminHandler.CreateDepartment)

						// Company roles
						r.Get("/roles", adminHandler.GetCompanyRoles)
						r.Post("/roles", adminHandler.CreateRole)

						// Company hierarchy
						r.Get("/hierarchy", adminHandler.GetCompanyHierarchy)

						// Bulk operations
						r.Post("/employees/bulk-assign", adminHandler.BulkAssignRoles)
					})
				})

				// Enhanced Employee Management with RBAC
				r.Route("/employees", func(r chi.Router) {
					// r.Post("/", adminHandler.AddEmployee)

					// Employee-specific operations
					r.Route("/{userID}", func(r chi.Router) {
						r.Put("/role", adminHandler.UpdateEmployeeRole)
						r.Get("/permissions", adminHandler.GetEmployeePermissions)
						r.Get("/hierarchy", adminHandler.GetUserHierarchy)
					})

					// Permission checking
					r.Post("/check-permission", adminHandler.CheckEmployeePermission)
				})

				// Role Permission Management
				r.Route("/roles", func(r chi.Router) {
					r.Route("/{roleID}", func(r chi.Router) {
						r.Post("/permissions", adminHandler.GrantRolePermissions)
					})
				})

				// ============================================================================
				// EXISTING ADMIN MANAGEMENT ROUTES
				// ============================================================================

				// Admin management routes
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

				// User management routes
				r.Route("/users", func(r chi.Router) {
					r.Post("/{userID}/ban", adminHandler.BanUser)
					r.Post("/{userID}/unban", adminHandler.UnbanUser)
					r.Get("/banned", adminHandler.GetBannedUsers)
					r.Patch("/{userID}/kyc", adminHandler.UpdateUserKYC)
					r.Get("/kyc/{status}", adminHandler.ListUsersByKYCStatus)
					r.Get("/search", adminHandler.SearchUsers)
					r.Get("/recently-active", adminHandler.GetRecentlyActiveUsers)
				})

				// Global RBAC Management (Admin only)
				r.Route("/rbac", func(r chi.Router) {
					r.Post("/permissions", rbacHandler.CreatePermission)
				})
			})
		})
	})

	// Global error handlers
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
// MIDDLEWARES (KEEP AS IS)
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

func requireHTTPS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil && !strings.Contains(r.Host, "localhost") && !strings.Contains(r.Host, "127.0.0.1") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUpgradeRequired)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "https required"})
			return
		}
		next.ServeHTTP(w, r)
	})
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
