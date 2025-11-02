// internal/handler/router.go - FIXED VERSION
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
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// requireHTTPS rejects any request that wasn't made over TLS
func requireHTTPS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUpgradeRequired) // 426
			w.Write([]byte(`{"error":"https required"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// NewRouter creates and configures the Chi router with all middleware and routes
func NewRouter(
	userHandler *UserHandler,
	otpHandler *OTPHandler,
	mpinHandler *MPINHandler,
	sessionHandler *SessionHandler,
	deviceHandler *DeviceHandler,
	adminHandler *AdminHandler,
	sessionService *service.SessionService, // ✅ REMOVED: auditHandler parameter
	logger *zap.Logger,
) chi.Router {
	router := chi.NewRouter()

	// Enforce HTTPS-only
	router.Use(requireHTTPS)

	// Middleware stack
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(LoggerMiddleware(logger))
	router.Use(middleware.Recoverer)
	router.Use(middleware.Timeout(60 * time.Second))

	// CORS configuration
	router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Session-Type"},
		ExposedHeaders:   []string{"Link", "Retry-After", "Content-Disposition"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Health check endpoint
	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		util.Info("Health check requested")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","service":"auth-service"}`))
	})

	// API routes
	router.Route("/api/v1", func(r chi.Router) {
		// User, OTP, MPIN, Session, Device routes
		userHandler.RegisterRoutes(r)
		otpHandler.RegisterRoutes(r)
		mpinHandler.RegisterRoutes(r)
		sessionHandler.RegisterRoutes(r)
		deviceHandler.RegisterRoutes(r)

		// ✅ UPDATED: Admin routes with proper auth middleware
		r.Route("/admins", func(r chi.Router) {
			// PUBLIC admin routes (no authentication required)
			r.Post("/init-owner", adminHandler.InitializeOwner)
			r.Get("/health", adminHandler.HealthCheck)
			r.Post("/authenticate", adminHandler.AuthenticateAdmin) // ✅ MOVED: This should be public

			// PROTECTED admin routes (require admin authentication)
			r.Group(func(r chi.Router) {
				// ✅ USE THE PROPER ADMIN AUTH MIDDLEWARE
				r.Use(AdminAuthMiddleware(sessionService, logger))

				// All other admin routes go here
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
			})
		})

		// ❌ REMOVED: Audit routes completely
	})

	// 404 handler
	router.NotFound(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"endpoint not found"}`))
	})

	// Method not allowed handler
	router.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte(`{"error":"method not allowed"}`))
	})

	return router
}

// LoggerMiddleware creates a middleware that logs HTTP requests
func LoggerMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			defer func() {
				logger.Info("HTTP request",
					util.String("method", r.Method),
					util.String("path", r.URL.Path),
					util.String("remote_addr", r.RemoteAddr),
					util.Int("status", ww.Status()),
					util.Duration("duration", time.Since(start)),
					util.String("user_agent", r.UserAgent()),
				)
			}()
			next.ServeHTTP(ww, r)
		})
	}
}

// ✅ UPDATED: AdminAuthMiddleware validates admin session using session service
func AdminAuthMiddleware(sessionService *service.SessionService, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Get session token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				respondWithAdminError(w, logger, http.StatusUnauthorized, "Missing authorization header")
				return
			}

			// Extract token from "Bearer <token>"
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				respondWithAdminError(w, logger, http.StatusUnauthorized, "Invalid authorization header format")
				return
			}

			sessionToken := parts[1]

			// Validate session using session service
			session, err := sessionService.GetSessionByToken(ctx, sessionToken)
			if err != nil {
				respondWithAdminError(w, logger, http.StatusUnauthorized, "Invalid session token")
				return
			}

			// Check if it's an admin session
			if session.SessionType != "admin" {
				respondWithAdminError(w, logger, http.StatusUnauthorized, "Not an admin session")
				return
			}

			// Parse admin ID from session
			adminID, err := uuid.Parse(session.UserID)
			if err != nil {
				respondWithAdminError(w, logger, http.StatusUnauthorized, "Invalid admin ID in session")
				return
			}

			// ✅ SET THE ADMIN ID IN REQUEST CONTEXT
			ctx = context.WithValue(ctx, "adminID", adminID)
			ctx = context.WithValue(ctx, "adminRole", session.AdminRoleLevel)

			// Update the request with new context
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// ✅ ADD THIS HELPER FUNCTION
func respondWithAdminError(w http.ResponseWriter, logger *zap.Logger, statusCode int, message string) {
	logger.Warn("Admin auth error",
		util.Int("status_code", statusCode),
		util.String("message", message),
	)
	
	errorResp := map[string]interface{}{
		"success": false,
		"error":   message,
		"message": "Unauthorized",
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(errorResp)
}