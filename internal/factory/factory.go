// File: internal/factory/factory.go - OPTIMIZED EVENT DISTRIBUTION
// ✅ UPDATED: Optimized event distribution between ES and ClickHouse

package factory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"auth-service/internal/bucketing"
	"auth-service/internal/client"
	"auth-service/internal/config"
	"auth-service/internal/consumer"
	"auth-service/internal/encryption"
	"auth-service/internal/hashing"
	"auth-service/internal/repository/redis"
	"auth-service/internal/repository/scylla"
	"auth-service/internal/service"
	"auth-service/internal/tls"
	"auth-service/internal/util"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"go.uber.org/zap"
)

type Factory struct {
	config            *config.Config
	tlsManager        *tls.TLSManager
	redisClient       *client.RedisClient
	scyllaClient      *scylla.ScyllaClient
	kafkaProducer     *client.KafkaProducer
	esClient          *client.ESClient
	clickhouseClient  *client.ClickHouseClient
	hasher            *hashing.Hasher
	encryptionManager *encryption.EncryptionManager
	bucketingManager  *bucketing.BucketingManager
	userRepository    scylla.UserRepository
	serviceFactory    *service.ServiceFactory
	userService       *service.UserService
	once              sync.Once
	closeOnce         sync.Once
	closed            chan struct{}
	mpinRepository    scylla.MPINRepository
	mpinService       *service.MPINService
	deviceTrustRepo   scylla.DeviceTrustRepository
	otpRepository     scylla.OTPRepository
	otpService        *service.OTPService
	sessionRepo       redis.SessionRepository
	sessionService    *service.SessionService
	deviceRepository  scylla.DeviceRepository
	deviceService     *service.DeviceService
	deviceHistoryRepo *scylla.DeviceHistoryRepositoryImpl
	kafkaLoggingMgr   *KafkaLoggingManager

	// ✅ Admin repositories and services
	adminRepository scylla.AdminRepository
	adminService    *service.AdminService

	logger *zap.Logger
}

// ============================================================================
// KAFKA LOGGING MANAGER STRUCT
// ============================================================================

type KafkaLoggingManager struct {
	producer   *service.LogProducerService
	esConsumer *consumer.ESConsumer
	chConsumer *consumer.ClickHouseConsumer
	cancelCtx  context.CancelFunc
	wg         sync.WaitGroup
	logger     *zap.Logger
}

func (m *KafkaLoggingManager) Shutdown() error {
	if m == nil {
		return nil
	}

	m.logger.Info("Shutting down Kafka logging manager...")

	// Cancel the context to stop consumers
	if m.cancelCtx != nil {
		m.cancelCtx()
	}

	// Wait for consumers to finish
	m.wg.Wait()

	// Close the producer
	if m.producer != nil {
		if err := m.producer.Close(); err != nil {
			m.logger.Error("Failed to close log producer", zap.Error(err))
		}
	}

	m.logger.Info("Kafka logging manager shut down successfully")
	return nil
}

func (m *KafkaLoggingManager) GetLogProducerService() *service.LogProducerService {
	return m.producer
}

// ============================================================================
// FACTORY INITIALIZATION
// ============================================================================

func NewFactory() (*Factory, error) {
	cfg := config.LoadConfig()
	util.Init(cfg.Environment, cfg.Logging.Level, cfg.Logging.Format)
	logger := util.Get()

	f := &Factory{
		config: cfg,
		closed: make(chan struct{}),
		logger: logger,
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
		f.tlsManager = tls.NewTLSManager(tlsConfig)
	}

	if err := f.initializeClients(); err != nil {
		return nil, fmt.Errorf("failed to initialize clients: %w", err)
	}
	f.initializeManagers()

	// ✅ Initialize Kafka logging with optimized event distribution
	kafkaLoggingMgr, err := f.InitializeKafkaLogging()
	if err != nil {
		logger.Error("failed to initialize Kafka logging", zap.Error(err))
		// Don't fail - logging should not break service startup
	}
	f.kafkaLoggingMgr = kafkaLoggingMgr

	util.Info("Factory initialized successfully",
		util.String("environment", cfg.Environment),
		util.Bool("tls_enabled", cfg.Server.EnableTLS),
		util.Bool("kms_enabled", cfg.KMS.Enabled),
		util.Bool("kafka_logging_enabled", f.kafkaLoggingMgr != nil),
	)

	return f, nil
}

// ============================================================================
// KAFKA LOGGING INITIALIZATION - OPTIMIZED EVENT DISTRIBUTION
// ============================================================================

// File: internal/factory/factory.go - FIXED CLICKHOUSE CONSUMER INITIALIZATION

// ============================================================================
// KAFKA LOGGING INITIALIZATION - OPTIMIZED EVENT DISTRIBUTION (FIXED)
// ============================================================================

// InitializeKafkaLogging sets up Kafka producer and consumers with optimized event distribution
func (f *Factory) InitializeKafkaLogging() (*KafkaLoggingManager, error) {
	logger := util.Get()

	if len(f.config.Kafka.Brokers) == 0 {
		logger.Warn("Kafka brokers not configured, logging to stdout only")
		return nil, nil
	}

	kafkaProducer, err := client.NewKafkaProducer(f.config, logger)
	if err != nil {
		logger.Error("failed to initialize Kafka producer", zap.Error(err))
		return nil, err
	}

	logProducer := service.NewLogProducerService(
		kafkaProducer,
		f.config.Environment,
		"v1.0.0",
	)

	consumerCtx, cancel := context.WithCancel(context.Background())

	mgr := &KafkaLoggingManager{
		producer:  logProducer,
		cancelCtx: cancel,
		logger:    logger,
	}

	// ✅ ELASTICSEARCH CONSUMER - Search & Analytics Events
	if f.config.Elasticsearch.URL != "" && f.esClient != nil {
		esTopics := []string{
			"admin-events",    // Audit trails, role searches
			"user-events",     // User behavior analysis  
			"security-events", // Fraud investigation (dual-purpose)
			"session-events",  // Session analytics
		}
		
		// Create Kafka consumer for ES topics
		kafkaConsumerES, err := client.NewKafkaConsumer(
			f.config,
			"admin-events",      // Primary topic
			"es-consumer-group", 
			logger,
		)
		if err == nil {
			esConsumer, err := consumer.NewESConsumer(kafkaConsumerES, f.esClient.Client)
			if err != nil {
				logger.Error("failed to create Elasticsearch consumer", zap.Error(err))
			} else {
				mgr.esConsumer = esConsumer
				mgr.wg.Add(1)
				go func() {
					defer mgr.wg.Done()
					if err := esConsumer.Start(consumerCtx); err != nil {
						logger.Error("ES consumer error", zap.Error(err))
					}
				}()
				logger.Info("Elasticsearch consumer started for search events",
					zap.Strings("topics", esTopics))
			}
		} else {
			logger.Error("failed to create Elasticsearch Kafka consumer", zap.Error(err))
		}
	}

	// ✅ CLICKHOUSE CONSUMER - Time-Series & Metrics Events (MULTI-TOPIC)
	if f.config.Clickhouse.URL != "" && f.clickhouseClient != nil {
		chTopics := []string{
			"device-events",     // Device metrics, binding trends
			"mpin-events",       // Authentication patterns
			"otp-events",        // Delivery metrics
			"security-events",   // Real-time fraud detection (dual-purpose)
		}
		
		// Create multiple Kafka consumers for ClickHouse (one per topic)
		chConsumers := make(map[string]*client.KafkaConsumer)
		
		for _, topic := range chTopics {
			kafkaConsumer, err := client.NewKafkaConsumer(
				f.config,
				topic,
				"clickhouse-consumer-group",  
				logger,
			)
			if err != nil {
				logger.Error("failed to create ClickHouse Kafka consumer", 
					zap.String("topic", topic), 
					zap.Error(err))
				continue
			}
			chConsumers[topic] = kafkaConsumer
		}

		if len(chConsumers) > 0 {
			// ✅ FIXED: Use the new multi-topic ClickHouse consumer - pass the MAP, not individual consumer
			chConsumer := consumer.NewClickHouseConsumer(
				chConsumers, // ✅ This is the map, not a single consumer
				f.clickhouseClient.Conn(),
				1000,          // batch size
				5*time.Second, // flush interval
			)
			mgr.chConsumer = chConsumer
			mgr.wg.Add(1)
			go func() {
				defer mgr.wg.Done()
				if err := chConsumer.Start(consumerCtx); err != nil {
					logger.Error("ClickHouse consumer error", zap.Error(err))
				}
			}()
			logger.Info("ClickHouse multi-topic consumer started for time-series events",
				zap.Int("topic_count", len(chConsumers)),
				zap.Strings("topics", chTopics))
		}
	}

	logger.Info("Kafka logging system initialized with optimized event distribution",
		zap.Bool("es_enabled", mgr.esConsumer != nil),
		zap.Bool("ch_enabled", mgr.chConsumer != nil),
	)

	return mgr, nil
}
// ============================================================================
// CLIENT INITIALIZATION
// ============================================================================

func (f *Factory) initializeClients() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var initErrors []error

	// Redis
	if rc, err := client.NewRedisClient(f.config, f.logger); err != nil {
		initErrors = append(initErrors, fmt.Errorf("redis: %w", err))
	} else {
		f.redisClient = rc
		if err := f.redisClient.HealthCheck(ctx); err != nil {
			initErrors = append(initErrors, fmt.Errorf("redis health check: %w", err))
		} else {
			util.Info("Redis client initialized and healthy")
		}
	}

	// ScyllaDB
	if sc, err := scylla.NewScyllaClient(f.config, f.logger); err != nil {
		initErrors = append(initErrors, fmt.Errorf("scylla: %w", err))
	} else {
		f.scyllaClient = sc
		if err := f.scyllaClient.HealthCheck(); err != nil {
			initErrors = append(initErrors, fmt.Errorf("scylla health check: %w", err))
		} else {
			util.Info("ScyllaDB client initialized and healthy")
		}
	}

	// Kafka
	if kp, err := client.NewKafkaProducer(f.config, f.logger); err != nil {
		util.Warn("Kafka producer initialization failed - proceeding without Kafka", util.ErrorField(err))
	} else {
		f.kafkaProducer = kp
		util.Info("Kafka producer initialized")
	}

	// Elasticsearch
	if ec, err := client.NewElasticsearchClient(f.config, f.logger); err != nil {
		initErrors = append(initErrors, fmt.Errorf("elasticsearch: %w", err))
	} else {
		f.esClient = ec
		if err := f.esClient.HealthCheck(); err != nil {
			initErrors = append(initErrors, fmt.Errorf("elasticsearch health check: %w", err))
		} else {
			util.Info("Elasticsearch client initialized and healthy")
		}
	}

	// ClickHouse
	if chc, err := client.NewClickHouseClient(f.config, f.logger); err != nil {
		initErrors = append(initErrors, fmt.Errorf("clickhouse: %w", err))
	} else {
		f.clickhouseClient = chc
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
		for _, e := range initErrors {
			util.Warn("Service initialization warning", util.ErrorField(e))
		}
	}
	return nil
}

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

// ============================================================================
// LOG PRODUCER SERVICE GETTER
// ============================================================================

// GetLogProducerService returns the log producer service for use in handlers/services
func (f *Factory) GetLogProducerService() *service.LogProducerService {
	if f.kafkaLoggingMgr == nil {
		return nil
	}
	return f.kafkaLoggingMgr.GetLogProducerService()
}

// ========================================================================
// REPOSITORY GETTERS
// ========================================================================

func (f *Factory) UserRepository() scylla.UserRepository {
	if f.userRepository == nil {
		f.userRepository = scylla.NewUserRepository(
			f.ScyllaClient(),
			f.Hasher(),
			f.EncryptionManager(),
			f.BucketingManager(),
			f.logger,
		)
	}
	return f.userRepository
}

func (f *Factory) OTPRepository() scylla.OTPRepository {
	if f.otpRepository == nil {
		f.otpRepository = scylla.NewOTPRepository(
			f.ScyllaClient(),
			f.Hasher(),
			f.BucketingManager(),
			f.logger,
		)
	}
	return f.otpRepository
}

func (f *Factory) MPINRepository() scylla.MPINRepository {
	if f.mpinRepository == nil {
		f.mpinRepository = scylla.NewMPINRepository(
			f.ScyllaClient(),
			f.logger,
		)
	}
	return f.mpinRepository
}

func (f *Factory) GetDeviceTrustRepository() scylla.DeviceTrustRepository {
	if f.deviceTrustRepo == nil {
		f.deviceTrustRepo = scylla.NewDeviceTrustRepository(f.scyllaClient, f.logger)
	}
	return f.deviceTrustRepo
}

func (f *Factory) SessionRepository() redis.SessionRepository {
	if f.sessionRepo == nil {
		f.sessionRepo = redis.NewSessionRepository(
			f.redisClient.Client(),
			f.logger,
		)
	}
	return f.sessionRepo
}

func (f *Factory) DeviceRepository() scylla.DeviceRepository {
	if f.deviceRepository == nil {
		f.deviceRepository = scylla.NewDeviceRepository(
			f.ScyllaClient(),
			f.logger,
		)
	}
	return f.deviceRepository
}

// ✅ DEVICE HISTORY REPOSITORY
func (f *Factory) GetDeviceHistoryRepository() *scylla.DeviceHistoryRepositoryImpl {
	if f.deviceHistoryRepo == nil {
		f.deviceHistoryRepo = scylla.NewDeviceHistoryRepository(
			f.ScyllaClient(),
			f.logger,
		)
	}
	return f.deviceHistoryRepo
}

// ========================================================================
// ✅ REFACTORED: ADMIN REPOSITORY GETTERS
// ========================================================================

// AdminRepository returns the admin repository
func (f *Factory) AdminRepository() scylla.AdminRepository {
	if f.adminRepository == nil {
		f.adminRepository = scylla.NewAdminRepository(
			f.ScyllaClient(),
			f.logger,
		)
	}
	return f.adminRepository
}

// ========================================================================
// SERVICE GETTERS
// ========================================================================

func (f *Factory) ServiceFactory() *service.ServiceFactory {
	if f.serviceFactory == nil {
		f.serviceFactory = service.NewServiceFactory(
			f.UserRepository(),
			f.Hasher(),
			f.EncryptionManager(),
			f.BucketingManager(),
			f.logger,
		)
	}
	return f.serviceFactory
}

func (f *Factory) GetUserService() *service.UserService {
	f.once.Do(func() {
		repo := f.UserRepository()
		hasher := f.Hasher()
		encMgr := f.EncryptionManager()
		bucketMgr := f.BucketingManager()
		logger := f.logger

		var distCache *service.DistributedCache
		if f.redisClient != nil {
			distCache = service.NewDistributedCache(f.redisClient.Client(), logger)
		}

		f.userService = service.NewUserServiceWithCache(
			repo, hasher, encMgr, bucketMgr, distCache, logger,
		)
	})
	return f.userService
}

func (f *Factory) GetOTPService() *service.OTPService {
	if f.otpService == nil {
		repo := f.OTPRepository()
		hasher := f.Hasher()
		cfg := f.Config()
		logger := f.logger

		var distCache *service.DistributedCache
		if f.redisClient != nil {
			distCache = service.NewDistributedCache(f.redisClient.Client(), logger)
		}

		f.otpService = service.NewOTPService(repo, hasher, cfg, distCache, logger)
	}
	return f.otpService
}

func (f *Factory) GetMPINService() *service.MPINService {
	if f.mpinService == nil {
		mpinRepo := f.MPINRepository()
		userRepo := f.UserRepository()
		deviceTrustRepo := f.GetDeviceTrustRepository()
		otpService := f.GetOTPService()
		encryptionMgr := f.EncryptionManager()
		hasher := f.Hasher()
		cfg := f.Config()
		logger := f.logger

		var distCache *service.DistributedCache
		if f.redisClient != nil {
			distCache = service.NewDistributedCache(f.redisClient.Client(), logger)
		}

		f.mpinService = service.NewMPINService(
			mpinRepo,
			userRepo,
			deviceTrustRepo,
			otpService,
			encryptionMgr,
			hasher,
			cfg,
			logger,
		)

		if distCache != nil {
			f.mpinService.SetDistributedCache(distCache)
		}
	}
	return f.mpinService
}

func (f *Factory) GetSessionService() *service.SessionService {
	if f.sessionService == nil {
		sessionRepo := f.SessionRepository()
		cfg := f.Config()
		logger := f.logger

		f.sessionService = service.NewSessionService(
			sessionRepo,
			cfg,
			logger,
		)
	}
	return f.sessionService
}

// ✅ DEVICE SERVICE WITH HISTORY AND LOG PRODUCER
func (f *Factory) GetDeviceService() *service.DeviceService {
	if f.deviceService == nil {
		deviceRepo := f.DeviceRepository()
		cfg := f.Config()
		logger := f.logger

		var distCache *service.DistributedCache
		if f.redisClient != nil {
			distCache = service.NewDistributedCache(f.redisClient.Client(), logger)
		}

		f.deviceService = service.NewDeviceService(
			deviceRepo,
			distCache,
			*cfg,
			logger,
		)

		// ✅ SET HISTORY REPOSITORY
		historyRepo := f.GetDeviceHistoryRepository()
		f.deviceService.SetHistoryRepository(historyRepo)

		// ✅ SET LOG PRODUCER
		logProducer := f.GetLogProducerService()
		if logProducer != nil {
			f.deviceService.SetLogProducerService(logProducer)
		}
	}
	return f.deviceService
}

// ========================================================================
// ✅ REFACTORED: ADMIN SERVICE GETTERS
// ========================================================================

// GetAdminService returns the admin service
func (f *Factory) GetAdminService() *service.AdminService {
	if f.adminService == nil {
		f.adminService = service.NewAdminService(
			f.AdminRepository(),
			f.UserRepository(),
			f.GetSessionService(),
			f.Hasher(),
			f.EncryptionManager(),
			f.logger,
		)
		
		// ✅ SET LOG PRODUCER FOR ADMIN SERVICE
		logProducer := f.GetLogProducerService()
		if logProducer != nil {
			f.adminService.SetLogProducerService(logProducer)
		}
	}
	return f.adminService
}

// ========================================================================
// HEALTH CHECK
// ========================================================================

func (f *Factory) HealthCheck(ctx context.Context) map[string]error {
	errs := make(map[string]error)

	if f.redisClient != nil {
		if err := f.redisClient.HealthCheck(ctx); err != nil {
			errs["redis"] = err
		}
	} else {
		errs["redis"] = fmt.Errorf("redis client not initialized")
	}

	if f.mpinRepository != nil {
		if err := f.mpinRepository.HealthCheck(ctx); err != nil {
			errs["mpin_repository"] = err
		}
	} else {
		errs["mpin_repository"] = fmt.Errorf("mpin repository not initialized")
	}

	if f.scyllaClient != nil {
		if err := f.scyllaClient.HealthCheck(); err != nil {
			errs["scylla"] = err
		}
	} else {
		errs["scylla"] = fmt.Errorf("scylla client not initialized")
	}

	if f.esClient != nil {
		if err := f.esClient.HealthCheck(); err != nil {
			errs["elasticsearch"] = err
		}
	} else {
		errs["elasticsearch"] = fmt.Errorf("elasticsearch client not initialized")
	}

	if f.clickhouseClient != nil {
		if err := f.clickhouseClient.HealthCheck(ctx); err != nil {
			errs["clickhouse"] = err
		}
	} else {
		errs["clickhouse"] = fmt.Errorf("clickhouse client not initialized")
	}

	if f.kafkaProducer != nil {
		if err := f.kafkaProducer.HealthCheck(ctx); err != nil {
			errs["kafka"] = err
		}
	}

	if f.hasher == nil {
		errs["hasher"] = fmt.Errorf("hasher not initialized")
	}

	if f.encryptionManager == nil {
		errs["encryption"] = fmt.Errorf("encryption manager not initialized")
	}

	if f.bucketingManager == nil {
		errs["bucketing"] = fmt.Errorf("bucketing manager not initialized")
	}

	if f.userRepository != nil {
		if err := f.userRepository.HealthCheck(ctx); err != nil {
			errs["user_repository"] = err
		}
	} else {
		errs["user_repository"] = fmt.Errorf("user repository not initialized")
	}

	if f.sessionRepo != nil {
		if err := f.sessionRepo.HealthCheck(ctx); err != nil {
			errs["session_repository"] = err
		}
	} else {
		errs["session_repository"] = fmt.Errorf("session repository not initialized")
	}

	if f.deviceRepository != nil {
		if err := f.deviceRepository.HealthCheck(ctx); err != nil {
			errs["device_repository"] = err
		}
	} else {
		errs["device_repository"] = fmt.Errorf("device repository not initialized")
	}

	// ✅ DEVICE HISTORY REPOSITORY HEALTH CHECK
	if f.deviceHistoryRepo != nil {
		if err := f.deviceHistoryRepo.HealthCheck(ctx); err != nil {
			errs["device_history_repository"] = err
		}
	} else {
		errs["device_history_repository"] = fmt.Errorf("device history repository not initialized")
	}

	// ✅ ADMIN REPOSITORY HEALTH CHECK
	if f.adminRepository != nil {
		if err := f.adminRepository.HealthCheck(ctx); err != nil {
			errs["admin_repository"] = err
		}
	} else {
		errs["admin_repository"] = fmt.Errorf("admin repository not initialized")
	}

	return errs
}

// ========================================================================
// CLEANUP - UPDATED WITH KAFKA LOGGING SHUTDOWN
// ========================================================================

func (f *Factory) Close() error {
	f.closeOnce.Do(func() {
		close(f.closed)
		util.Info("Shutting down factory...")

		// ✅ Shutdown Kafka logging first
		if f.kafkaLoggingMgr != nil {
			if err := f.kafkaLoggingMgr.Shutdown(); err != nil {
				util.Error("Failed to shutdown Kafka logging", util.ErrorField(err))
			}
			util.Info("Kafka logging system shut down")
		}

		if f.clickhouseClient != nil {
			f.clickhouseClient.Close()
			util.Info("ClickHouse client closed")
		}

		if f.esClient != nil {
			f.esClient.Close()
			util.Info("Elasticsearch client closed")
		}

		if f.kafkaProducer != nil {
			f.kafkaProducer.Close()
			util.Info("Kafka producer closed")
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
			f.redisClient.Close()
			util.Info("Redis client closed")
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

// ========================================================================
// SIMPLE GETTERS
// ========================================================================

func (f *Factory) Config() *config.Config                           { return f.config }
func (f *Factory) TLSManager() *tls.TLSManager                      { return f.tlsManager }
func (f *Factory) ScyllaClient() *scylla.ScyllaClient               { return f.scyllaClient }
func (f *Factory) Hasher() *hashing.Hasher                          { return f.hasher }
func (f *Factory) EncryptionManager() *encryption.EncryptionManager { return f.encryptionManager }
func (f *Factory) BucketingManager() *bucketing.BucketingManager    { return f.bucketingManager }