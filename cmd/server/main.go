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

	// Initialize router
	router := f.GetRouter()

	// Determine server address
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

	// ==========================
	// TLS CONFIGURATION
	// ==========================
	if cfg.Server.EnableTLS {
		tlsMgr := f.TLSManager()
		server.TLSConfig = tlsMgr.GetTLSConfig()

		logger.Info("Starting HTTPS server",
			util.String("environment", cfg.Environment),
			util.Int("port", cfg.Server.TLSPort),
		)
	} else {
		logger.Warn("Starting HTTP server (TLS disabled)",
			util.String("environment", cfg.Environment),
			util.Int("port", cfg.Server.Port),
		)
	}

	startServer(f, server, cfg)
}

// ==============================
// Start Server
// ==============================
func startServer(f *factory.Factory, server *http.Server, cfg *config.Config) {
	go func() {
		var err error
		if cfg.Server.EnableTLS {
			err = server.ListenAndServeTLS(cfg.Server.CertFile, cfg.Server.KeyFile)
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

	waitForShutdown(f, server)
}

// ==============================
// Graceful Shutdown
// ==============================
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
	util.Info("Application shutdown complete")
}
