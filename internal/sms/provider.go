package sms

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"auth-service/internal/util"

	"go.uber.org/zap"
)

// SMSProvider represents an SMS provider configuration
type SMSProvider struct {
	Name     string
	Priority int
	Enabled  bool
}

// SMSManager handles SMS sending with failover support
type SMSManager struct {
	providers []SMSProvider
	logger    *zap.Logger
	mu        sync.RWMutex
}

// SMSRequest represents an SMS send request
type SMSRequest struct {
	PhoneNumber       string
	OTP               string
	PreferredProvider string
	Purpose           string
}

// SMSResponse represents the result of an SMS send attempt
type SMSResponse struct {
	Success      bool
	ProviderUsed string
	Error        string
}

// NewSMSManager creates a new SMS manager
func NewSMSManager(logger *zap.Logger) *SMSManager {
	// Initialize with default providers
	providers := []SMSProvider{
		{Name: "twilio", Priority: 1, Enabled: true},
		{Name: "aws-sns", Priority: 2, Enabled: true},
		{Name: "nexmo", Priority: 3, Enabled: true},
	}

	return &SMSManager{
		providers: providers,
		logger:    logger,
	}
}

// SendOTP sends an OTP via SMS with failover support
func (m *SMSManager) SendOTP(ctx context.Context, req SMSRequest) SMSResponse {
	// Sort providers by priority
	providers := make([]SMSProvider, len(m.providers))
	copy(providers, m.providers)

	// Try preferred provider first if specified
	if req.PreferredProvider != "" && req.PreferredProvider != "auto" {
		for i, provider := range providers {
			if provider.Name == req.PreferredProvider && provider.Enabled {
				// Move preferred provider to front
				providers = append([]SMSProvider{provider}, append(providers[:i], providers[i+1:]...)...)
				break
			}
		}
	}

	// Sort by priority (if preferred provider wasn't specified or found)
	sort.Slice(providers, func(i, j int) bool {
		return providers[i].Priority < providers[j].Priority
	})

	// Try each provider
	for _, provider := range providers {
		if !provider.Enabled {
			continue
		}

		success := m.tryProvider(ctx, provider.Name, req.PhoneNumber, req.OTP)
		if success {
			m.logger.Info("SMS sent successfully",
				util.String("provider", provider.Name),
				util.String("phone", req.PhoneNumber),
				util.String("purpose", req.Purpose),
			)
			return SMSResponse{
				Success:      true,
				ProviderUsed: provider.Name,
			}
		}

		m.logger.Warn("SMS provider failed",
			util.String("provider", provider.Name),
			util.String("phone", req.PhoneNumber),
			util.String("purpose", req.Purpose),
		)
	}

	return SMSResponse{
		Success: false,
		Error:   "all SMS providers failed",
	}
}

// tryProvider attempts to send SMS via a specific provider
func (m *SMSManager) tryProvider(ctx context.Context, provider, phoneNumber, otp string) bool {
	switch provider {
	case "twilio":
		return m.sendViaTwilio(ctx, phoneNumber, otp)
	case "aws-sns":
		return m.sendViaAWSSNS(ctx, phoneNumber, otp)
	case "nexmo":
		return m.sendViaNexmo(ctx, phoneNumber, otp)
	default:
		return false
	}
}

// sendViaTwilio sends SMS via Twilio
func (m *SMSManager) sendViaTwilio(ctx context.Context, phoneNumber, otp string) bool {
	// Implement actual Twilio integration here
	// For now, simulate success
	m.logger.Debug("Sending SMS via Twilio",
		util.String("phone", phoneNumber),
		util.String("otp", otp),
	)
	return true
}

// sendViaAWSSNS sends SMS via AWS SNS
func (m *SMSManager) sendViaAWSSNS(ctx context.Context, phoneNumber, otp string) bool {
	// Implement actual AWS SNS integration here
	// For now, simulate success
	m.logger.Debug("Sending SMS via AWS SNS",
		util.String("phone", phoneNumber),
		util.String("otp", otp),
	)
	return true
}

// sendViaNexmo sends SMS via Nexmo/Vonage
func (m *SMSManager) sendViaNexmo(ctx context.Context, phoneNumber, otp string) bool {
	// Implement actual Nexmo/Vonage integration here
	// For now, simulate success
	m.logger.Debug("Sending SMS via Nexmo",
		util.String("phone", phoneNumber),
		util.String("otp", otp),
	)
	return true
}

// GetProviders returns the list of available providers
func (m *SMSManager) GetProviders() []SMSProvider {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.providers
}

// UpdateProvider updates provider configuration
func (m *SMSManager) UpdateProvider(name string, enabled bool, priority int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, provider := range m.providers {
		if provider.Name == name {
			m.providers[i].Enabled = enabled
			m.providers[i].Priority = priority
			return nil
		}
	}
	return fmt.Errorf("provider not found: %s", name)
}

// HealthCheck checks the health of all enabled providers
func (m *SMSManager) HealthCheck(ctx context.Context) map[string]bool {
	health := make(map[string]bool)

	for _, provider := range m.providers {
		if provider.Enabled {
			// Simple health check - in production, you might want to actually test each provider
			health[provider.Name] = true
		}
	}

	return health
}
