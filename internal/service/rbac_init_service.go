// internal/service/rbac_init_service.go
package service

import (
	"auth-service/internal/rbac"
	"auth-service/internal/repository/postgres"
	"context"
	"fmt"

	"go.uber.org/zap"
)

type RBACInitService struct {
	companyRepo postgres.CompanyRepository
	logger      *zap.Logger
}

func NewRBACInitService(companyRepo postgres.CompanyRepository, logger *zap.Logger) *RBACInitService {
	return &RBACInitService{
		companyRepo: companyRepo,
		logger:      logger,
	}
}

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

	s.logger.Info("Permission registry initialized",
		zap.Int("permission_count", len(permissionMap)),
		zap.Any("permission_map", permissionMap),
	)

	return nil
}
