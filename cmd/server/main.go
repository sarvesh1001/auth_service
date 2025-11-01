// cmd/server/main.go - UPDATED VERSION
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"auth-service/internal/config"
	"auth-service/internal/factory"
	"auth-service/internal/handler"
	"auth-service/internal/util"
)

func main() {
	// Initialize factory
	f, err := factory.NewFactory()
	if err != nil {
		util.Fatal("Failed to initialize factory", util.ErrorField(err))
	}
	defer f.Close()

	cfg := f.Config()
	logger := util.Get()

	// ========================================================================
	// Create handlers
	// ========================================================================

	// ✅ All handlers created the SAME WAY
	userHandler := handler.NewUserHandler(f.GetUserService(), logger)
	otpHandler := handler.NewOTPHandler(f.GetOTPService(), logger)
	mpinHandler := handler.NewMPINHandler(f.GetMPINService(), logger)
	sessionHandler := handler.NewSessionHandler(f.GetSessionService(), logger)
	deviceHandler := handler.NewDeviceHandler(f.GetDeviceService(), logger)

	// ✅ FIXED: Pass pointers directly (services already return pointers)
	adminHandler := handler.NewAdminHandler(f.GetAdminService(), logger)
	auditHandler := handler.NewAuditHandler(f.GetAuditService(), logger)

	// ✅ GET SESSION SERVICE FOR MIDDLEWARE
	sessionService := f.GetSessionService()

	// ========================================================================
	// Setup router with all handlers
	// ========================================================================

	// ✅ UPDATED: Pass sessionService to router for admin auth middleware
	router := handler.NewRouter(
		userHandler,
		otpHandler,
		mpinHandler,
		sessionHandler,
		deviceHandler,
		adminHandler,
		auditHandler,
		sessionService, // ✅ ADD THIS LINE
		logger,
	)

	// ========================================================================
	// Determine server address
	// ========================================================================

	var addr string
	if cfg.Server.EnableTLS {
		addr = fmt.Sprintf(":%d", cfg.Server.TLSPort)
	} else {
		addr = cfg.GetServerAddress()
	}

	server := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// ========================================================================
	// TLS configuration
	// ========================================================================

	if cfg.Server.EnableTLS {
		tlsMgr := f.TLSManager()
		server.TLSConfig = tlsMgr.GetTLSConfig()

		if cfg.IsProduction() && cfg.Server.AutoCert {
			startProductionServerWithAutoCert(f, server, cfg, router)
			return
		}

		logger.Info("Starting HTTPS server",
			util.String("environment", cfg.Environment),
			util.Int("port", cfg.Server.TLSPort),
			util.Bool("auto_cert", cfg.Server.AutoCert),
		)
	} else {
		logger.Warn("Starting HTTP server - TLS is disabled",
			util.String("environment", cfg.Environment),
			util.Int("port", cfg.Server.Port),
		)
	}

	startServer(f, server, cfg)
}

// startProductionServerWithAutoCert starts HTTP redirect and HTTPS with autocert
func startProductionServerWithAutoCert(f *factory.Factory, server *http.Server, cfg *config.Config, router http.Handler) {
	tlsMgr := f.TLSManager()
	autoCert := tlsMgr.GetAutocertManager()
	if autoCert == nil {
		util.Fatal("AutoCert manager unavailable")
	}

	httpRedirect := &http.Server{
		Addr:    ":80",
		Handler: autoCert.HTTPHandler(nil),
	}
	httpsAPI := &http.Server{
		Addr:      ":443",
		Handler:   router,
		TLSConfig: server.TLSConfig,
	}

	go func() {
		util.Info("Starting HTTP redirect on :80")
		if err := httpRedirect.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			util.Error("HTTP redirect failed", util.ErrorField(err))
		}
	}()

	go func() {
		util.Info("Starting HTTPS autocert on :443",
			util.String("domain", cfg.Server.Domain),
		)
		if err := httpsAPI.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			util.Error("HTTPS autocert failed", util.ErrorField(err))
		}
	}()

	waitForShutdown(f, httpsAPI, httpRedirect)
}

// startServer starts the main HTTP/S server
func startServer(f *factory.Factory, server *http.Server, cfg *config.Config) {
	go func() {
		var err error
		if cfg.Server.EnableTLS {
			if cfg.Server.CertFile != "" && cfg.Server.KeyFile != "" {
				err = server.ListenAndServeTLS(cfg.Server.CertFile, cfg.Server.KeyFile)
			} else {
				err = server.ListenAndServeTLS("", "")
			}
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			util.Fatal("Server failed to start", util.ErrorField(err))
		}
	}()

	util.Info("Server started",
		util.String("environment", cfg.Environment),
		util.Bool("tls_enabled", cfg.Server.EnableTLS),
		util.String("address", server.Addr),
	)

	waitForShutdown(f, server)
}

// waitForShutdown gracefully shuts down servers
func waitForShutdown(f *factory.Factory, servers ...*http.Server) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	sig := <-stop
	util.Info("Shutdown signal received", util.String("signal", sig.String()))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, srv := range servers {
		if srv != nil {
			if err := srv.Shutdown(ctx); err != nil {
				util.Error("Shutdown failed", util.ErrorField(err))
			} else {
				util.Info("Server shutdown complete")
			}
		}
	}
	f.Close()
}