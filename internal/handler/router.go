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

// ✅ FIXED: NewRouter with proper admin route structure (no duplicates)
func NewRouter(
    userHandler *UserHandler,
    otpHandler *OTPHandler,
    // mpinHandler *MPINHandler,
    sessionHandler *SessionHandler,
    // deviceHandler *DeviceHandler,
    adminHandler *AdminHandler,
    authHandler *AuthHandler,
    sessionService *service.SessionService,
    jwtService *service.JWTService,
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
        AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Session-Type", "X-Device-ID"},
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
        // ============================================
        // PUBLIC ROUTES (No authentication required)
        // ============================================

        // ✅ AUTH FLOW: Login, logout, token management (public operations)
        authHandler.RegisterPublicRoutes(r)

        // ✅ PUBLIC USER ROUTES: For checking user existence without auth
        authHandler.RegisterUserPublicRoutes(r)

        // OTP routes (public - for authentication)
        otpHandler.RegisterRoutes(r)

        // MPIN routes (public - for authentication)
        // mpinHandler.RegisterRoutes(r)

        // ✅ FIXED: Single admin route definition with proper grouping
        r.Route("/admins", func(r chi.Router) {
            // ========== PUBLIC ADMIN ROUTES ==========
            // Owner initialization - public (first-time setup)
            r.Post("/init-owner", adminHandler.InitializeOwner)

            // Health check - public
            r.Get("/health", adminHandler.HealthCheck)

            // Admin Authentication Flow with JWT
            r.Post("/auth/initiate", adminHandler.InitiateAdminLogin)
            r.Post("/auth/verify-otp", adminHandler.VerifyAdminOTPLogin)
            r.Post("/auth/verify-mpin", adminHandler.VerifyAdminMPINLogin)
            r.Post("/auth/mpin/setup", adminHandler.SetupAdminMPIN)
            r.Post("/auth/refresh", adminHandler.RefreshAdminTokens)
            r.Post("/auth/logout", adminHandler.LogoutAdmin)

            // ========== PROTECTED ADMIN ROUTES ==========
            r.Group(func(r chi.Router) {
                // Apply JWT authentication middleware
                r.Use(JWTAuthMiddleware(jwtService, logger))
                // Apply admin-specific middleware to ensure session_type = "admin"
                r.Use(AdminSessionMiddleware(logger))

                // Statistics - protected
                r.Get("/stats", adminHandler.GetStats)

                // Owner management - owner only
                r.Patch("/owner/phone", adminHandler.ChangeOwnerPhone)

                // Admin invitation - owner/super_employee
                r.Post("/invite", adminHandler.InviteAdmin)

                // Admin management - owner/super_employee (role-based)
                r.Patch("/{adminID}/role", adminHandler.PromoteAdmin)
                r.Patch("/{adminID}/permissions", adminHandler.UpdateAdminPermissions)
                r.Delete("/{adminID}", adminHandler.RemoveAdmin)
                r.Patch("/{adminID}/deactivate", adminHandler.DeactivateAdmin)
                r.Patch("/{adminID}/activate", adminHandler.ActivateAdmin)

                // Admin queries
                r.Get("/{adminID}", adminHandler.GetAdminByID)
                r.Get("/phone/{phone}", adminHandler.GetAdminByPhone)
                r.Get("/", adminHandler.ListAdmins)
                r.Get("/role/{roleLevel}", adminHandler.GetAdminsByRole)

                // User Management (Ban/Unban)
                r.Post("/users/{userID}/ban", adminHandler.BanUser)
                r.Post("/users/{userID}/unban", adminHandler.UnbanUser)
                r.Get("/users/banned", adminHandler.GetBannedUsers)
            })
        })

        // User creation and health are PUBLIC
        r.Post("/users", userHandler.CreateUser)
        r.Get("/users/health", userHandler.HealthCheck)

        // ============================================
        // PROTECTED ROUTES (Require JWT Authentication)
        // ============================================

        r.Group(func(r chi.Router) {
            // Apply JWT authentication middleware
            r.Use(JWTAuthMiddleware(jwtService, logger))

            // ✅ FIXED: Session validation endpoints moved to protected routes
            r.Get("/auth/validate", authHandler.ValidateSession)
            r.Get("/auth/status", authHandler.GetAuthStatus)
            r.Post("/auth/logout", authHandler.Logout)
            r.Post("/auth/logout/all", authHandler.LogoutAllDevices)

            // Protected user operations
            r.Route("/user", func(r chi.Router) {
                r.Get("/{userID}", userHandler.GetUserByID)
                r.Put("/{userID}", userHandler.UpdateUser)
                r.Patch("/{userID}/profile", userHandler.UpdateUserProfile)
                r.Patch("/{userID}/status", userHandler.UpdateUserStatus)
                r.Patch("/{userID}/last-login", userHandler.UpdateLastLogin)

                // Batch operations
                r.Post("/batch", userHandler.CreateUsersBatch)
                r.Post("/batch/get", userHandler.GetUsersByIDBatch)
                r.Put("/batch", userHandler.UpdateUsersBatch)

                // KYC operations
                r.Patch("/{userID}/kyc", userHandler.UpdateKYCStatus)
                r.Get("/kyc/{status}", userHandler.GetUsersByKYCStatus)
                r.Patch("/{userID}/consent", userHandler.UpdateUserConsent)

                // Administrative operations
                r.Post("/{userID}/ban", userHandler.BanUser)
                r.Post("/{userID}/unban", userHandler.UnbanUser)
                r.Get("/banned", userHandler.GetBannedUsers)

                // Stats
                r.Get("/stats", userHandler.GetServiceStats)
            })

            // Protected session routes
            sessionHandler.RegisterRoutes(r)

            // Protected device routes
            // deviceHandler.RegisterRoutes(r)
        })
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

// ✅ FIXED: AdminSessionMiddleware ensures the JWT token has session_type = "admin"
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

// JWTAuthMiddleware validates JWT access tokens
func JWTAuthMiddleware(jwtService *service.JWTService, logger *zap.Logger) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            ctx := r.Context()

            // Get token from Authorization header
            authHeader := r.Header.Get("Authorization")
            if authHeader == "" {
                respondWithJWTError(w, logger, http.StatusUnauthorized, "Missing authorization header")
                return
            }

            // Extract token from "Bearer <token>"
            parts := strings.Split(authHeader, " ")
            if len(parts) != 2 || parts[0] != "Bearer" {
                respondWithJWTError(w, logger, http.StatusUnauthorized, "Invalid authorization header format")
                return
            }

            accessToken := parts[1]

            // Validate JWT token
            claims, err := jwtService.ValidateAccessToken(ctx, accessToken)
            if err != nil {
                logger.Warn("Invalid JWT token", zap.Error(err))
                respondWithJWTError(w, logger, http.StatusUnauthorized, "Invalid or expired token")
                return
            }

            // Set user context from claims
            ctx = context.WithValue(ctx, "user_id", claims.UserID)
            ctx = context.WithValue(ctx, "device_id", claims.DeviceID)
            ctx = context.WithValue(ctx, "role", claims.Role)
            ctx = context.WithValue(ctx, "session_type", claims.SessionType)
            ctx = context.WithValue(ctx, "jti", claims.JTI)

            // Add admin-specific context if present
            if claims.AdminRoleLevel != "" {
                ctx = context.WithValue(ctx, "admin_role_level", claims.AdminRoleLevel)
            }
            if claims.AdminPermissions != nil {
                ctx = context.WithValue(ctx, "admin_permissions", claims.AdminPermissions)
            }

            // Update request with new context
            r = r.WithContext(ctx)

            next.ServeHTTP(w, r)
        })
    }
}

// LoggerMiddleware creates a middleware that logs HTTP requests
func LoggerMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            start := time.Now()
            ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
            defer func() {
                logger.Info("HTTP request",
                    zap.String("method", r.Method),
                    zap.String("path", r.URL.Path),
                    zap.String("remote_addr", r.RemoteAddr),
                    zap.Int("status", ww.Status()),
                    zap.Duration("duration", time.Since(start)),
                    zap.String("user_agent", r.UserAgent()),
                )
            }()
            next.ServeHTTP(ww, r)
        })
    }
}

func respondWithJWTError(w http.ResponseWriter, logger *zap.Logger, statusCode int, message string) {
    logger.Warn("JWT auth error",
        zap.Int("status_code", statusCode),
        zap.String("message", message),
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