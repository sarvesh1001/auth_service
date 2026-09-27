package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"

	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
)

// ComponentRepository defines the data access methods needed by the component service.
type ComponentRepository interface {
	GetComponentsByCompany(ctx context.Context, companyID uuid.UUID) (map[string]*models.PayrollComponent, error)
	GetComponent(ctx context.Context, companyID uuid.UUID, code string) (*models.PayrollComponent, error)
	GetComponentsByCodes(ctx context.Context, companyID uuid.UUID, codes []string) ([]*models.PayrollComponent, error)
}

// CompanySettingsRepository provides access to company payroll settings.
type CompanySettingsRepository interface {
	GetPayrollSettings(ctx context.Context, companyID uuid.UUID) (*models.CompanyPayrollSettings, error)
}

// ComponentService handles component validation, retrieval, and caching.
type ComponentService interface {
	GetComponents(ctx context.Context, companyID uuid.UUID) (map[string]*models.PayrollComponent, error)
	GetComponent(ctx context.Context, companyID uuid.UUID, code string) (*models.PayrollComponent, error)
	ValidateComponentExists(ctx context.Context, companyID uuid.UUID, code string) error
	GetDefaultComponent(ctx context.Context, companyID uuid.UUID, purpose string) (string, error)
	ClearCache(companyID uuid.UUID)
}

type componentService struct {
	compRepo         ComponentRepository
	settingsRepo     CompanySettingsRepository
	auditService     *audit.AuditService
	idempotencyStore idempotency.Store

	mu    sync.RWMutex
	cache map[uuid.UUID]map[string]*models.PayrollComponent
}

// NewComponentService creates a new component service with caching, audit, and idempotency.
func NewComponentService(
	compRepo ComponentRepository,
	settingsRepo CompanySettingsRepository,
	auditService *audit.AuditService,
	idempotencyStore idempotency.Store,
) ComponentService {
	return &componentService{
		compRepo:         compRepo,
		settingsRepo:     settingsRepo,
		auditService:     auditService,
		idempotencyStore: idempotencyStore,
		cache:            make(map[uuid.UUID]map[string]*models.PayrollComponent),
	}
}

// GetComponents returns all active components for a company, using a cached copy if available.
//
// The returned map is keyed by component_code; each value carries both
// ComponentID (the surrogate PK) and ComponentCode. Callers that need to
// write a child row must use comp.ComponentID.
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

	s.mu.Lock()
	s.cache[companyID] = components
	s.mu.Unlock()

	return components, nil
}

// GetComponent returns a single component, using the cache if possible.
func (s *componentService) GetComponent(ctx context.Context, companyID uuid.UUID, code string) (*models.PayrollComponent, error) {
	components, err := s.GetComponents(ctx, companyID)
	if err != nil {
		return nil, err
	}
	if comp, ok := components[code]; ok {
		return comp, nil
	}
	return nil, nil
}

// ValidateComponentExists validates that a component exists and is active.
// Also logs an audit entry for the validation (with IP).
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

	ip, _ := ctx.Value("ip_address").(string)
	compJSON, _ := json.Marshal(comp)
	_ = s.auditService.LogAction(
		ctx,
		nil,
		&companyID,
		"payroll",
		"component.validate",
		"payroll_component",
		&comp.ComponentID,
		"system",
		nil,
		nil,
		compJSON,
		map[string]interface{}{
			"ip":         ip,
			"company_id": companyID.String(),
			"code":       code,
		},
	)

	return nil
}

// GetDefaultComponent returns the default component *code* for a given purpose.
//
// Purposes: "fine", "arrears", "loan", "basic".
//
// The underlying company_payroll_settings table now stores a UUID FK; the
// repository JOINs the catalog and populates the *_component_code fields on
// the returned struct. This method reads those display codes — callers that
// need the ID should fetch the component separately via GetComponent.
func (s *componentService) GetDefaultComponent(ctx context.Context, companyID uuid.UUID, purpose string) (string, error) {
	settings, err := s.settingsRepo.GetPayrollSettings(ctx, companyID)
	if err != nil {
		return "", fmt.Errorf("failed to get company payroll settings: %w", err)
	}
	if settings == nil {
		return "", nil
	}

	switch purpose {
	case "fine":
		if settings.DefaultFineComponentCode != nil {
			return *settings.DefaultFineComponentCode, nil
		}
	case "arrears":
		if settings.DefaultArrearsComponentCode != nil {
			return *settings.DefaultArrearsComponentCode, nil
		}
	case "loan":
		if settings.DefaultLoanComponentCode != nil {
			return *settings.DefaultLoanComponentCode, nil
		}
	case "basic":
		if settings.DefaultBasicComponentCode != nil {
			return *settings.DefaultBasicComponentCode, nil
		}
	default:
		return "", errors.New("invalid default component purpose")
	}
	return "", nil
}

// ClearCache removes cached components for a company.
// No audit needed – this is an internal operation.
func (s *componentService) ClearCache(companyID uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.cache, companyID)
}
