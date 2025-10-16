package factory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"auth-service/internal/bucketing"
	"auth-service/internal/client"
	"auth-service/internal/config"
	"auth-service/internal/encryption"
	"auth-service/internal/hashing"
	"auth-service/internal/repository/scylla"
	"auth-service/internal/service"
	"auth-service/internal/tls"
	"auth-service/internal/util"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// Factory manages the lifecycle of all application dependencies
type Factory struct {
	config     *config.Config
	tlsManager *tls.TLSManager

	// Clients
	redisClient      *client.RedisClient
	scyllaClient     *scylla.ScyllaClient
	kafkaProducer    *client.KafkaProducer
	esClient         *client.ESClient
	clickhouseClient *client.ClickHouseClient

	// New Managers
	hasher            *hashing.Hasher
	encryptionManager *encryption.EncryptionManager
	bucketingManager  *bucketing.BucketingManager

	// Repositories
	userRepository scylla.UserRepository // Use interface type
	serviceFactory *service.ServiceFactory

	closeOnce sync.Once
	closed    chan struct{}
}

// NewFactory creates and initializes all application dependencies
func NewFactory() (*Factory, error) {
	cfg := config.LoadConfig()

	util.Init(cfg.Environment, cfg.Logging.Level, cfg.Logging.Format)

	factory := &Factory{
		config: cfg,
		closed: make(chan struct{}),
	}

	if cfg.Server.EnableTLS {
		tlsConfig := &tls.TLSConfig{
			EnableTLS:   cfg.Server.EnableTLS,
			AutoCert:    cfg.Server.AutoCert,
			Domain:      cfg.Server.Domain,
			CertFile:    cfg.Server.CertFile,
			KeyFile:     cfg.Server.KeyFile,
			AutoCertDir: cfg.Server.AutoCertDir,
			Email:       cfg.Server.Email,
			Environment: cfg.Environment,
		}
		factory.tlsManager = tls.NewTLSManager(tlsConfig)
	}

	if err := factory.initializeClients(); err != nil {
		return nil, fmt.Errorf("failed to initialize clients: %w", err)
	}

	factory.initializeManagers()

	util.Info("Factory initialized successfully",
		util.String("environment", cfg.Environment),
		util.Bool("tls_enabled", cfg.Server.EnableTLS),
		util.Bool("kms_enabled", cfg.KMS.Enabled),
	)

	return factory, nil
}

// initializeClients initializes all external service clients with health checks
func (f *Factory) initializeClients() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var initErrors []error

	// Redis
	if client, err := client.NewRedisClient(f.config, util.Get()); err != nil {
		initErrors = append(initErrors, fmt.Errorf("redis: %w", err))
	} else {
		f.redisClient = client
		if err := f.redisClient.HealthCheck(ctx); err != nil {
			initErrors = append(initErrors, fmt.Errorf("redis health check: %w", err))
		} else {
			util.Info("Redis client initialized and healthy")
		}
	}

	// ScyllaDB
	if client, err := scylla.NewScyllaClient(f.config, util.Get()); err != nil {
		initErrors = append(initErrors, fmt.Errorf("scylla: %w", err))
	} else {
		f.scyllaClient = client
		if err := f.scyllaClient.HealthCheck(); err != nil {
			initErrors = append(initErrors, fmt.Errorf("scylla health check: %w", err))
		} else {
			util.Info("ScyllaDB client initialized and healthy")
		}
	}

	// Kafka
	if producer, err := client.NewKafkaProducer(f.config, util.Get()); err != nil {
		util.Warn("Kafka producer initialization failed - proceeding without Kafka", util.ErrorField(err))
	} else {
		f.kafkaProducer = producer
		util.Info("Kafka producer initialized")
	}

	// Elasticsearch
	if client, err := client.NewElasticsearchClient(f.config, util.Get()); err != nil {
		initErrors = append(initErrors, fmt.Errorf("elasticsearch: %w", err))
	} else {
		f.esClient = client
		if err := f.esClient.HealthCheck(); err != nil {
			initErrors = append(initErrors, fmt.Errorf("elasticsearch health check: %w", err))
		} else {
			util.Info("Elasticsearch client initialized and healthy")
		}
	}

	// ClickHouse
	if client, err := client.NewClickHouseClient(f.config, util.Get()); err != nil {
		initErrors = append(initErrors, fmt.Errorf("clickhouse: %w", err))
	} else {
		f.clickhouseClient = client
		if err := f.clickhouseClient.HealthCheck(ctx); err != nil {
			initErrors = append(initErrors, fmt.Errorf("clickhouse health check: %w", err))
		} else {
			util.Info("ClickHouse client initialized and healthy")
		}
	}

	if len(initErrors) > 0 {
		if f.config.IsProduction() {
			return fmt.Errorf("critical service initialization failed: %v", initErrors)
		}
		for _, err := range initErrors {
			util.Warn("Service initialization warning", util.ErrorField(err))
		}
	}

	return nil
}

// initializeManagers initializes hashing, encryption, and bucketing managers
func (f *Factory) initializeManagers() {
	f.hasher = hashing.NewHasher(f.config)

	var kmsClient *kms.Client
	if f.config.KMS.Enabled {
		kmsClient = nil
	}

	f.encryptionManager = encryption.NewEncryptionManager(f.config, kmsClient)
	f.bucketingManager = bucketing.NewBucketingManager(f.config)

	if f.config.IsProduction() {
		f.hasher.StartPepperRotation()
	}

	util.Info("Managers initialized successfully",
		util.Bool("hashing_initialized", f.hasher != nil),
		util.Bool("encryption_initialized", f.encryptionManager != nil),
		util.Bool("bucketing_initialized", f.bucketingManager != nil),
	)
}

// ==============================
// Repository Initialization
// ==============================
// Update the UserRepository method to use interface type
func (f *Factory) UserRepository() scylla.UserRepository {
	if f.userRepository == nil {
		// Create the concrete implementation but return as interface
		repo := scylla.NewUserRepository(
			f.ScyllaClient(),
			f.Hasher(),
			f.EncryptionManager(),
			f.BucketingManager(),
			util.Get(),
		)
		f.userRepository = repo // This works because *UserRepository implements UserRepository interface
	}
	return f.userRepository
}

// ==============================
// Service Factory
// ==============================
func (f *Factory) ServiceFactory() *service.ServiceFactory {
	if f.serviceFactory == nil {
		f.serviceFactory = service.NewServiceFactory(
			f.UserRepository(), // Now returns the interface type
			f.Hasher(),
			f.EncryptionManager(),
			f.BucketingManager(),
			util.Get(),
		)
	}
	return f.serviceFactory
}

// ==============================
// Health Checks
// ==============================

func (f *Factory) HealthCheck(ctx context.Context) map[string]error {
	healthErrors := make(map[string]error)

	if f.redisClient != nil {
		if err := f.redisClient.HealthCheck(ctx); err != nil {
			healthErrors["redis"] = err
		}
	} else {
		healthErrors["redis"] = fmt.Errorf("redis client not initialized")
	}

	if f.scyllaClient != nil {
		if err := f.scyllaClient.HealthCheck(); err != nil {
			healthErrors["scylla"] = err
		}
	} else {
		healthErrors["scylla"] = fmt.Errorf("scylla client not initialized")
	}

	if f.esClient != nil {
		if err := f.esClient.HealthCheck(); err != nil {
			healthErrors["elasticsearch"] = err
		}
	} else {
		healthErrors["elasticsearch"] = fmt.Errorf("elasticsearch client not initialized")
	}

	if f.clickhouseClient != nil {
		if err := f.clickhouseClient.HealthCheck(ctx); err != nil {
			healthErrors["clickhouse"] = err
		}
	} else {
		healthErrors["clickhouse"] = fmt.Errorf("clickhouse client not initialized")
	}

	if f.kafkaProducer != nil {
		if err := f.kafkaProducer.HealthCheck(ctx); err != nil {
			healthErrors["kafka"] = err
		}
	}

	if f.hasher == nil {
		healthErrors["hasher"] = fmt.Errorf("hasher not initialized")
	}
	if f.encryptionManager == nil {
		healthErrors["encryption"] = fmt.Errorf("encryption manager not initialized")
	}
	if f.bucketingManager == nil {
		healthErrors["bucketing"] = fmt.Errorf("bucketing manager not initialized")
	}

	// User repository health check
	if f.userRepository != nil {
		if err := f.userRepository.HealthCheck(ctx); err != nil {
			healthErrors["user_repository"] = err
		}
	} else {
		healthErrors["user_repository"] = fmt.Errorf("user repository not initialized")
	}

	return healthErrors
}

// ==============================
// Other Utility Methods
// ==============================

func (f *Factory) IsHealthy(ctx context.Context) bool {
	healthErrors := f.HealthCheck(ctx)
	delete(healthErrors, "kafka")
	return len(healthErrors) == 0
}

func (f *Factory) Close() error {
	f.closeOnce.Do(func() {
		close(f.closed)
		util.Info("Shutting down factory...")

		if f.clickhouseClient != nil {
			if err := f.clickhouseClient.Close(); err != nil {
				util.Error("Failed to close ClickHouse client", util.ErrorField(err))
			} else {
				util.Info("ClickHouse client closed")
			}
		}

		if f.esClient != nil {
			f.esClient.Close()
			util.Info("Elasticsearch client closed")
		}

		if f.kafkaProducer != nil {
			if err := f.kafkaProducer.Close(); err != nil {
				util.Error("Failed to close Kafka producer", util.ErrorField(err))
			} else {
				util.Info("Kafka producer closed")
			}
		}

		if f.serviceFactory != nil {
			f.serviceFactory.Cleanup()
			util.Info("Service factory cleaned up")
		}

		if f.scyllaClient != nil {
			f.scyllaClient.Close()
			util.Info("ScyllaDB client closed")
		}

		if f.redisClient != nil {
			if err := f.redisClient.Close(); err != nil {
				util.Error("Failed to close Redis client", util.ErrorField(err))
			} else {
				util.Info("Redis client closed")
			}
		}

		if f.encryptionManager != nil {
			f.encryptionManager.ClearCache()
			util.Info("Encryption manager cache cleared")
		}

		util.Sync()
		util.Info("Factory shutdown completed")
	})

	return nil
}

func (f *Factory) WaitForClose() {
	<-f.closed
}

// Add these getter methods to your factory

func (f *Factory) Config() *config.Config {
	return f.config
}

func (f *Factory) TLSManager() *tls.TLSManager {
	return f.tlsManager
}

func (f *Factory) ScyllaClient() *scylla.ScyllaClient {
	return f.scyllaClient
}

func (f *Factory) Hasher() *hashing.Hasher {
	return f.hasher
}

func (f *Factory) EncryptionManager() *encryption.EncryptionManager {
	return f.encryptionManager
}

func (f *Factory) BucketingManager() *bucketing.BucketingManager {
	return f.bucketingManager
}
