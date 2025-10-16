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
	// Initialize factory (which loads config and initializes all clients)
	f, err := factory.NewFactory()
	if err != nil {
		util.Fatal("Failed to initialize factory", util.ErrorField(err))
	}
	defer f.Close()

	cfg := f.Config()

	// Setup HTTP router with handlers using Chi
	router := setupRouter(f)

	// Determine server address based on TLS config
	var serverAddr string
	if cfg.Server.EnableTLS {
		serverAddr = fmt.Sprintf(":%d", cfg.Server.TLSPort)
	} else {
		serverAddr = cfg.GetServerAddress()
	}

	// Create HTTP server with configured timeouts
	server := &http.Server{
		Addr:         serverAddr,
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// TLS configuration
	if cfg.Server.EnableTLS {
		tlsManager := f.TLSManager()
		server.TLSConfig = tlsManager.GetTLSConfig()

		// In production with AutoCert, handle redirect and cert management
		if cfg.IsProduction() && cfg.Server.AutoCert {
			startProductionServerWithAutoCert(f, server, cfg, router)
			return
		}

		util.Info("Starting HTTPS server",
			util.String("environment", cfg.Environment),
			util.Int("port", cfg.Server.TLSPort),
			util.Bool("auto_cert", cfg.Server.AutoCert),
		)
	} else {
		util.Warn("Starting HTTP server - TLS is disabled",
			util.String("environment", cfg.Environment),
			util.Int("port", cfg.Server.Port),
		)
	}

	// Start server based on TLS configuration
	startServer(f, server, cfg)
}

// setupRouter creates the HTTP router with all handlers using Chi
func setupRouter(f *factory.Factory) http.Handler {
	serviceFactory := f.ServiceFactory()
	userService := serviceFactory.UserService()
	userHandler := handler.NewUserHandler(userService, util.Get())
	return handler.NewRouter(userHandler, util.Get())
}

func startProductionServerWithAutoCert(f *factory.Factory, server *http.Server, cfg *config.Config, router http.Handler) {
	tlsManager := f.TLSManager()
	autoCertManager := tlsManager.GetAutocertManager()
	if autoCertManager == nil {
		util.Fatal("AutoCert manager is not available in production")
	}

	// HTTP server for ACME challenge and redirect only
	httpServer := &http.Server{
		Addr:    ":80",
		Handler: autoCertManager.HTTPHandler(nil),
	}

	// HTTPS server for API
	httpsServer := &http.Server{
		Addr:      ":443",
		Handler:   router,
		TLSConfig: server.TLSConfig,
	}

	go func() {
		util.Info("Starting HTTP redirect server on port 80")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			util.Error("HTTP redirect server failed", util.ErrorField(err))
		}
	}()

	go func() {
		util.Info("Starting HTTPS server with AutoCert on port 443",
			util.String("domain", cfg.Server.Domain),
		)
		if err := httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			util.Error("HTTPS AutoCert server failed", util.ErrorField(err))
		}
	}()

	waitForShutdown(f, httpsServer, httpServer)
}

func startServer(f *factory.Factory, server *http.Server, cfg *config.Config) {
	go func() {
		var err error
		if cfg.Server.EnableTLS {
			if cfg.Server.AutoCert {
				err = server.ListenAndServeTLS("", "")
			} else if cfg.Server.CertFile != "" && cfg.Server.KeyFile != "" {
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

	util.Info("Server started successfully",
		util.String("environment", cfg.Environment),
		util.Bool("tls_enabled", cfg.Server.EnableTLS),
		util.String("address", server.Addr),
	)

	waitForShutdown(f, server, nil)
}

func waitForShutdown(f *factory.Factory, servers ...*http.Server) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	sig := <-signalChan
	util.Info("Received shutdown signal", util.String("signal", sig.String()))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, srv := range servers {
		if srv != nil {
			if err := srv.Shutdown(ctx); err != nil {
				util.Error("Failed to shutdown server gracefully", util.ErrorField(err))
			} else {
				util.Info("Server shutdown completed")
			}
		}
	}
	f.Close()
}
