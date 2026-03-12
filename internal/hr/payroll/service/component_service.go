package service

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/hr/payroll/models"
)

// ComponentRepository defines the data access methods needed by the component service.
type ComponentRepository interface {
	// GetComponentsByCompany returns all active payroll components for a company.
	GetComponentsByCompany(ctx context.Context, companyID uuid.UUID) (map[string]*models.PayrollComponent, error)

	// GetComponent returns a single component by company and code.
	GetComponent(ctx context.Context, companyID uuid.UUID, code string) (*models.PayrollComponent, error)

	// GetComponentsByCodes returns components for the given codes (bulk lookup).
	GetComponentsByCodes(ctx context.Context, companyID uuid.UUID, codes []string) ([]*models.PayrollComponent, error)
}

// CompanySettingsRepository provides access to company payroll settings.
type CompanySettingsRepository interface {
	GetPayrollSettings(ctx context.Context, companyID uuid.UUID) (*models.CompanyPayrollSettings, error)
}

// ComponentService handles component validation, retrieval, and caching.
type ComponentService interface {
	// GetComponents returns a map of component_code -> component for the company.
	// It may cache the result for the duration of the context.
	GetComponents(ctx context.Context, companyID uuid.UUID) (map[string]*models.PayrollComponent, error)

	// GetComponent returns a single component. Returns nil, nil if not found.
	GetComponent(ctx context.Context, companyID uuid.UUID, code string) (*models.PayrollComponent, error)

	// ValidateComponentExists returns an error if the component does not exist or is inactive.
	ValidateComponentExists(ctx context.Context, companyID uuid.UUID, code string) error

	// GetDefaultComponent returns the default component code for a given purpose (fine, arrears, loan, basic).
	// Returns empty string and no error if no default is configured.
	GetDefaultComponent(ctx context.Context, companyID uuid.UUID, purpose string) (string, error)

	// ClearCache removes cached components for a company (useful after updates).
	ClearCache(companyID uuid.UUID)
}

type componentService struct {
	compRepo     ComponentRepository
	settingsRepo CompanySettingsRepository
	logger       *zap.Logger

	// simple in-memory cache keyed by companyID
	mu    sync.RWMutex
	cache map[uuid.UUID]map[string]*models.PayrollComponent
}

// NewComponentService creates a new component service with caching.
func NewComponentService(
	compRepo ComponentRepository,
	settingsRepo CompanySettingsRepository,
	logger *zap.Logger,
) ComponentService {
	return &componentService{
		compRepo:     compRepo,
		settingsRepo: settingsRepo,
		logger:       logger.Named("component_service"),
		cache:        make(map[uuid.UUID]map[string]*models.PayrollComponent),
	}
}

// GetComponents returns all active components for a company, using a cached copy if available.
func (s *componentService) GetComponents(ctx context.Context, companyID uuid.UUID) (map[string]*models.PayrollComponent, error) {
	s.mu.RLock()
	cached, ok := s.cache[companyID]
	s.mu.RUnlock()
	if ok {
		return cached, nil
	}

	components, err := s.compRepo.GetComponentsByCompany(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch components: %w", err)
	}

	// Store in cache
	s.mu.Lock()
	s.cache[companyID] = components
	s.mu.Unlock()

	return components, nil
}

// GetComponent returns a single component, using the cache if possible.
func (s *componentService) GetComponent(ctx context.Context, companyID uuid.UUID, code string) (*models.PayrollComponent, error) {
	// First try cache
	components, err := s.GetComponents(ctx, companyID)
	if err != nil {
		return nil, err
	}
	if comp, ok := components[code]; ok {
		return comp, nil
	}
	return nil, nil
}

// ValidateComponentExists returns an error if the component does not exist.
func (s *componentService) ValidateComponentExists(ctx context.Context, companyID uuid.UUID, code string) error {
	comp, err := s.GetComponent(ctx, companyID, code)
	if err != nil {
		return err
	}
	if comp == nil {
		return fmt.Errorf("component %s does not exist for company %s", code, companyID)
	}
	if !comp.IsActive {
		return fmt.Errorf("component %s is inactive", code)
	}
	return nil
}

// GetDefaultComponent returns the default component code for a given purpose.
// Purpose should be one of: "fine", "arrears", "loan", "basic".
func (s *componentService) GetDefaultComponent(ctx context.Context, companyID uuid.UUID, purpose string) (string, error) {
	settings, err := s.settingsRepo.GetPayrollSettings(ctx, companyID)
	if err != nil {
		return "", fmt.Errorf("failed to get company payroll settings: %w", err)
	}
	if settings == nil {
		return "", nil // no defaults configured
	}

	switch purpose {
	case "fine":
		if settings.DefaultFineComponent != nil {
			return *settings.DefaultFineComponent, nil
		}
	case "arrears":
		if settings.DefaultArrearsComponent != nil {
			return *settings.DefaultArrearsComponent, nil
		}
	case "loan":
		if settings.DefaultLoanComponent != nil {
			return *settings.DefaultLoanComponent, nil
		}
	case "basic":
		if settings.DefaultBasicComponent != nil {
			return *settings.DefaultBasicComponent, nil
		}
	default:
		return "", errors.New("invalid default component purpose")
	}
	return "", nil
}

// ClearCache removes cached components for a company.
func (s *componentService) ClearCache(companyID uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.cache, companyID)
}
