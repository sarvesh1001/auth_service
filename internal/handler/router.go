package handler

import (
	"net/http"
	"time"

	"auth-service/internal/util"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"go.uber.org/zap"
)

// requireHTTPS rejects any request that wasn’t made over TLS
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
func NewRouter(userHandler *UserHandler, logger *zap.Logger) chi.Router {
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
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Health check endpoint (supports GET only; HEAD will be rejected as non-TLS)
	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		util.Info("Health check requested")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","service":"auth-service"}`))
	})

	// API routes
	router.Route("/api/v1", func(r chi.Router) {
		userHandler.RegisterRoutes(r)
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
