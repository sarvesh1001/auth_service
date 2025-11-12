
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"auth-service/internal/service"
	"auth-service/internal/util"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"go.uber.org/zap"
)

// NewRouter initializes all routes, middlewares, and handlers
func NewRouter(
	otpHandler *OTPHandler,
	adminHandler *AdminHandler,
	authHandler *AuthHandler,
	sessionService *service.SessionService,
	jwtService *service.JWTService,
	logger *zap.Logger,
) chi.Router {
	router := chi.NewRouter()

	// ============================================
	// GLOBAL MIDDLEWARES
	// ============================================
	router.Use(requireHTTPS)
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(LoggerMiddleware(logger))
	router.Use(middleware.Recoverer)
	router.Use(middleware.Timeout(60 * time.Second))

	// CORS configuration
	router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Session-Type", "X-Device-ID"},
		ExposedHeaders:   []string{"Link", "Retry-After", "Content-Disposition"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// ============================================
	// HEALTH CHECK
	// ============================================
	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		util.Info("Health check requested")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "healthy",
			"service": "auth-service",
		})
	})

	// ============================================
	// MAIN API ROUTES
	// ============================================// ============================================
// MAIN API ROUTES
// ============================================
router.Route("/api/v1", func(r chi.Router) {

    // --------------------------
    // PUBLIC ROUTES
    // --------------------------
    authHandler.RegisterPublicRoutes(r)
    authHandler.RegisterUserPublicRoutes(r)
    otpHandler.RegisterRoutes(r)

    // --------------------------
    // ADMIN AUTH ROUTES (PUBLIC)
    // --------------------------
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

    // --------------------------
    // PROTECTED ROUTES (JWT REQUIRED)
    // --------------------------
    r.Group(func(r chi.Router) {
        r.Use(JWTAuthMiddleware(jwtService, logger))

        // ✅ Auth protected routes
        authHandler.RegisterProtectedRoutes(r)

        // ✅ Admin protected routes - Use the proven middlewares
        r.Route("/admins", func(r chi.Router) {
            r.Use(AdminSessionMiddleware(logger))

            // --- Admin General ---
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

            // --- User Management ---
            r.Post("/users/{userID}/ban", adminHandler.BanUser)
            r.Post("/users/{userID}/unban", adminHandler.UnbanUser)
            r.Get("/users/banned", adminHandler.GetBannedUsers)
            r.Patch("/users/{userID}/kyc", adminHandler.UpdateUserKYC)
            r.Get("/users/kyc/{status}", adminHandler.ListUsersByKYCStatus)

            // --- Company Management ---
            r.Route("/companies", func(r chi.Router) {
				r.Post("/", adminHandler.CreateCompany)
    
				// ✅ ADD THESE NEW OPTIMIZED ENDPOINTS
				// r.Get("/tier/{tier}", adminHandler.GetCompaniesByTier)
				// r.Get("/tier/{tier}/status/{status}", adminHandler.GetCompaniesByTierAndStatus)
				// r.Get("/subscription-date-range", adminHandler.GetCompaniesBySubscriptionDateRange)
				r.Get("/expiring-subscriptions", adminHandler.GetCompaniesWithExpiringSubscription)
				r.Get("/status/{status}", adminHandler.GetCompaniesByStatus) // For active/inactive/blocked
				r.Get("/recent", adminHandler.GetRecentCompanies) // For recent companies
				
				// Existing endpoints
				r.Get("/{companyID}", adminHandler.GetCompany)
				r.Patch("/{companyID}/block", adminHandler.BlockCompany)
				r.Patch("/{companyID}/unblock", adminHandler.UnblockCompany)
				r.Patch("/{companyID}/subscription", adminHandler.UpdateSubscription)
				r.Patch("/{companyID}/extend", adminHandler.ExtendSubscription)
				r.Get("/{companyID}/employees", adminHandler.GetCompanyEmployees)
            })
        })
    })
})

	// ============================================
	// GLOBAL ERROR HANDLERS
	// ============================================
	router.NotFound(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "endpoint not found"})
	})

	router.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
	})

	return router
}

// ============================================
// MIDDLEWARES (unchanged)
// ============================================

// ✅ Ensures the JWT token is from an admin session
func AdminSessionMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionType, ok := r.Context().Value("session_type").(string)
			if !ok || sessionType != "admin" {
				logger.Warn("Access denied: not an admin session",
					zap.String("session_type", sessionType),
				)
				respondWithJWTError(w, logger, http.StatusForbidden, "Access denied: admin session required")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Enforce HTTPS connections
func requireHTTPS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUpgradeRequired)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "https required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// JWTAuthMiddleware validates and injects JWT claims into context
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

// LoggerMiddleware logs all HTTP requests
func LoggerMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			logger.Info("HTTP request",
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.String("remote_addr", r.RemoteAddr),
				zap.Int("status", ww.Status()),
				zap.Duration("duration", time.Since(start)),
				zap.String("user_agent", r.UserAgent()),
			)
		})
	}
}

// Helper for uniform JWT error responses
func respondWithJWTError(w http.ResponseWriter, logger *zap.Logger, statusCode int, message string) {
	logger.Warn("JWT auth error",
		zap.Int("status_code", statusCode),
		zap.String("message", message),
	)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
		"message": "Unauthorized",
	})
}