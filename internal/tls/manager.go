// internal/tls/manager.go
package tls

import (
    "crypto/tls"
    "fmt"
    "os"

    "auth-service/internal/util"
    "golang.org/x/crypto/acme/autocert"
    "go.uber.org/zap"
)

type TLSManager struct {
    config   *TLSConfig
    autoCert *autocert.Manager
}

type TLSConfig struct {
    EnableTLS   bool
    AutoCert    bool
    Domain      string
    CertFile    string
    KeyFile     string
    AutoCertDir string
    Email       string
    Environment string
}

func NewTLSManager(config *TLSConfig) *TLSManager {
    manager := &TLSManager{
        config: config,
    }

    if config.AutoCert && config.EnableTLS {
        manager.setupAutoCert()
    }

    return manager
}

func (m *TLSManager) setupAutoCert() {
    // Create cert directory
    if err := os.MkdirAll(m.config.AutoCertDir, 0700); err != nil {
        util.Warn("Could not create autocert directory", zap.Error(err))
        return
    }

    m.autoCert = &autocert.Manager{
        Prompt:     autocert.AcceptTOS,
        HostPolicy: autocert.HostWhitelist(m.config.Domain),
        Cache:      autocert.DirCache(m.config.AutoCertDir),
        Email:      m.config.Email,
    }

    util.Info("AutoCert configured", 
        zap.String("domain", m.config.Domain),
        zap.String("cache_dir", m.config.AutoCertDir))
}

func (m *TLSManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
    // Try AutoCert first if enabled
    if m.autoCert != nil {
        if cert, err := m.autoCert.GetCertificate(hello); err == nil {
            return cert, nil
        }
    }

    // Fallback to file-based certificates
    if m.config.CertFile != "" && m.config.KeyFile != "" {
        cert, err := tls.LoadX509KeyPair(m.config.CertFile, m.config.KeyFile)
        if err == nil {
            return &cert, nil
        }
    }

    // Final fallback: generate self-signed certificate
    return m.generateSelfSignedCert()
}

func (m *TLSManager) generateSelfSignedCert() (*tls.Certificate, error) {
    generator := NewDevCertGenerator(m.config.AutoCertDir)
    hosts := []string{
        m.config.Domain,
        "localhost",
        "127.0.0.1",
        "::1",
    }

    cert, err := generator.GenerateCert(hosts)
    if err != nil {
        return nil, fmt.Errorf("failed to generate self-signed certificate: %v", err)
    }

    util.Info("Generated self-signed certificate", zap.Strings("hosts", hosts))
    return &cert, nil
}

func (m *TLSManager) GetTLSConfig() *tls.Config {
    return &tls.Config{
        GetCertificate: m.GetCertificate,
        NextProtos:     []string{"h2", "http/1.1"},
        MinVersion:     tls.VersionTLS12,
        CurvePreferences: []tls.CurveID{
            tls.X25519,
            tls.CurveP256,
        },
        CipherSuites: []uint16{
            tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
            tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
            tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        },
    }
}

func (m *TLSManager) GetAutocertManager() *autocert.Manager {
    return m.autoCert
}
