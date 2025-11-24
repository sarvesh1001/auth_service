package tls

import (
	"crypto/tls"
	"fmt"
)

type TLSConfig struct {
	EnableTLS bool
	CertFile  string
	KeyFile   string
}

type TLSManager struct {
	config *TLSConfig
}

func NewTLSManager(cfg *TLSConfig) *TLSManager {
	return &TLSManager{config: cfg}
}

func (m *TLSManager) GetTLSConfig() *tls.Config {
	if !m.config.EnableTLS {
		return nil
	}

	cert, err := tls.LoadX509KeyPair(m.config.CertFile, m.config.KeyFile)
	if err != nil {
		panic(fmt.Errorf("failed to load TLS certificate: %w", err))
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
}
