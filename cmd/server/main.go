package main

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "os"
    "os/signal"
    "strconv"
    "syscall"
    "time"

    "auth-service/internal/config"
    "auth-service/internal/factory"
    "auth-service/internal/tls"
    "auth-service/internal/util"

    "go.uber.org/zap"
)

type Application struct {
    config        *config.Config
    clientFactory *factory.ClientFactory
    httpsServer   *http.Server
}

func main() {
    util.Init("development", "info", "console")
    defer util.Sync()

    cfg := config.LoadConfig()
    util.Init(cfg.Environment, cfg.Logging.Level, cfg.Logging.Format)

    app := &Application{
        config: cfg,
    }

    app.clientFactory = factory.NewClientFactory(cfg, util.Get())

    if err := app.initializeClients(); err != nil {
        util.Fatal("Failed to initialize clients", zap.Error(err))
    }

    // ✅ Pass context to health check
    ctx := context.Background()
    if err := app.healthCheck(ctx); err != nil {
        util.Fatal("Health check failed", zap.Error(err))
    }

    go app.startServer()
    app.waitForShutdown()
}

// ==================== INITIALIZATION ====================
func (app *Application) initializeClients() error {
    util.Info("Initializing core clients...")

    // Initialize ScyllaDB
    if _, err := app.clientFactory.GetScyllaClient(); err != nil {
        return fmt.Errorf("failed to initialize ScyllaDB client: %w", err)
    }
    util.Info("ScyllaDB client initialized successfully")

    // Initialize Redis
    if _, err := app.clientFactory.GetRedisClient(); err != nil {
        return fmt.Errorf("failed to initialize Redis client: %w", err)
    }
    util.Info("Redis client initialized successfully")

    // Initialize ClickHouse for analytics (500M users scale)
    if _, err := app.clientFactory.GetClickHouseClient(); err != nil {
        return fmt.Errorf("failed to initialize ClickHouse client: %w", err)
    }
    util.Info("ClickHouse client initialized successfully for analytics")

    return nil
}// ==================== HEALTH CHECK ====================

func (app *Application) healthCheck(ctx context.Context) error {
    util.Info("Performing initial service health check...")
    health := app.clientFactory.HealthCheck(ctx)
    unhealthy := false

    for svc, status := range health {
        util.Info(fmt.Sprintf("Health check: %s = %s", svc, status))
        if status != "healthy" {
            unhealthy = true
        }
    }

    if unhealthy {
        return fmt.Errorf("one or more services unhealthy")
    }
    return nil
}

// ==================== SERVER ====================

func (app *Application) startServer() {
    handler := app.createRouter()

    tlsManager := tls.NewTLSManager(&tls.TLSConfig{
        EnableTLS:   app.config.Server.EnableTLS,
        AutoCert:    app.config.Server.AutoCert,
        Domain:      app.config.Server.Domain,
        CertFile:    app.config.Server.CertFile,
        KeyFile:     app.config.Server.KeyFile,
        AutoCertDir: app.config.Server.AutoCertDir,
        Email:       app.config.Server.Email,
        Environment: app.config.Environment,
    })

    app.httpsServer = &http.Server{
        Addr:         ":" + strconv.Itoa(app.config.Server.TLSPort),
        Handler:      handler,
        ReadTimeout:  app.config.Server.ReadTimeout,
        WriteTimeout: app.config.Server.WriteTimeout,
        IdleTimeout:  app.config.Server.IdleTimeout,
        TLSConfig:    tlsManager.GetTLSConfig(),
    }

    util.Info("Starting HTTPS-only server",
        zap.String("address", app.httpsServer.Addr),
        zap.Bool("auto_cert", app.config.Server.AutoCert),
        zap.String("domain", app.config.Server.Domain),
    )

    var err error
    if app.config.Server.AutoCert && tlsManager.GetAutocertManager() != nil {
        err = app.httpsServer.Serve(tlsManager.GetAutocertManager().Listener())
    } else if app.config.Server.CertFile != "" && app.config.Server.KeyFile != "" {
        err = app.httpsServer.ListenAndServeTLS(app.config.Server.CertFile, app.config.Server.KeyFile)
    } else {
        err = app.httpsServer.ListenAndServeTLS("", "")
    }

    if err != nil && err != http.ErrServerClosed {
        util.Fatal("HTTPS server failed", zap.Error(err))
    }
}

// ==================== ROUTER ====================

func (app *Application) createRouter() http.Handler {
    mux := http.NewServeMux()

    mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        ctx := r.Context()
        healthStatus := map[string]string{
            "status":      "healthy",
            "timestamp":   time.Now().UTC().Format(time.RFC3339),
            "environment": app.config.Environment,
        }

        factoryHealth := app.clientFactory.HealthCheck(ctx)
        for service, status := range factoryHealth {
            healthStatus[service] = status
            if status != "healthy" {
                healthStatus["status"] = "degraded"
            }
        }

        w.Header().Set("Content-Type", "application/json")
        if healthStatus["status"] != "healthy" {
            w.WriteHeader(http.StatusServiceUnavailable)
        }
        json.NewEncoder(w).Encode(healthStatus)
    })

    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("Auth Service is running (HTTPS Only)"))
    })

    mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
        ctx := r.Context()
        healthStatus := app.clientFactory.HealthCheck(ctx)
        allHealthy := true

        for _, status := range healthStatus {
            if status != "healthy" {
                allHealthy = false
                break
            }
        }

        w.Header().Set("Content-Type", "application/json")
        if allHealthy {
            w.WriteHeader(http.StatusOK)
            json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
        } else {
            w.WriteHeader(http.StatusServiceUnavailable)
            json.NewEncoder(w).Encode(map[string]string{"status": "not ready"})
        }
    })

    mux.HandleFunc("/live", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(map[string]string{"status": "alive"})
    })

    return mux
}

// ==================== SHUTDOWN ====================

func (app *Application) waitForShutdown() {
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    util.Info("Shutdown signal received, initiating graceful shutdown...")

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    if app.httpsServer != nil {
        util.Info("Shutting down HTTPS server...")
        if err := app.httpsServer.Shutdown(ctx); err != nil {
            util.Error("HTTPS server shutdown error", zap.Error(err))
        } else {
            util.Info("HTTPS server stopped gracefully")
        }
    }

    if app.clientFactory != nil {
        util.Info("Closing all client connections...")
        app.clientFactory.CloseAll()
    }

    util.Info("Application shutdown completed")
}
