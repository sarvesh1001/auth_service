package service

import (
	"context"
	"fmt"

	"auth-service/internal/rbac"
	"auth-service/internal/repository/postgres"
)

// RBACInitService initializes the permission registry from the database.
type RBACInitService struct {
	companyRepo postgres.CompanyRepository
}

// NewRBACInitService creates a new RBACInitService.
func NewRBACInitService(companyRepo postgres.CompanyRepository) *RBACInitService {
	return &RBACInitService{
		companyRepo: companyRepo,
	}
}

// InitializePermissionRegistry loads permissions from DB and sets up the global registry.
func (s *RBACInitService) InitializePermissionRegistry(ctx context.Context) error {
	permissions, err := s.companyRepo.GetPermissionsWithBitIndex(ctx)
	if err != nil {
		return fmt.Errorf("failed to get permissions: %w", err)
	}

	permissionMap := make(map[string]uint64)
	for _, perm := range permissions {
		permissionMap[perm.Name] = uint64(perm.BitIndex)
	}

	registry := rbac.GetPermissionRegistry()
	registry.Initialize(permissionMap)

	// No logger – this is a system init, we assume success.
	// Optionally, you could add an audit log here if auditService is injected.
	return nil
}
