// internal/service/service_factory.go
package service

import (
	"auth-service/internal/encryption"
	"auth-service/internal/hashing"
	"auth-service/internal/repository/postgres"

	"go.uber.org/zap"
)

// ServiceFactory creates and manages service instances
type ServiceFactory struct {
	userRepo      postgres.UserRepository
	hasher        *hashing.Hasher
	encryptionMgr *encryption.EncryptionManager
	logger        *zap.Logger
	userService   *UserService
}

// NewServiceFactory creates a new service factory
func NewServiceFactory(
	userRepo postgres.UserRepository,
	hasher *hashing.Hasher,
	encryptionMgr *encryption.EncryptionManager,
	logger *zap.Logger,
) *ServiceFactory {
	return &ServiceFactory{
		userRepo:      userRepo,
		hasher:        hasher,
		encryptionMgr: encryptionMgr,
		logger:        logger,
	}
}

// UserService returns the user service instance (singleton)
func (f *ServiceFactory) UserService() *UserService {
	if f.userService == nil {
		f.userService = NewUserService(
			f.userRepo,
			f.hasher,
			f.encryptionMgr,
			f.logger,
		)
	}
	return f.userService
}

// Cleanup cleans up all services
func (f *ServiceFactory) Cleanup() {
	if f.userService != nil {
		f.userService.Cleanup()
	}
}
