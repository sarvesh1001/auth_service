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
    logger            *zap.Logger
}

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

    util.Info("Factory initialized successfully",
        util.String("environment", cfg.Environment),
        util.Bool("tls_enabled", cfg.Server.EnableTLS),
        util.Bool("kms_enabled", cfg.KMS.Enabled),
    )

    return f, nil
}

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

func (f *Factory) HealthCheck(ctx context.Context) map[string]error {
    errs := make(map[string]error)
    if f.redisClient != nil {
        if err := f.redisClient.HealthCheck(ctx); err != nil {
            errs["redis"] = err
        }
    } else {
        errs["redis"] = fmt.Errorf("redis client not initialized")
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
    return errs
}

func (f *Factory) Close() error {
    f.closeOnce.Do(func() {
        close(f.closed)
        util.Info("Shutting down factory...")
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

// Getters

func (f *Factory) Config() *config.Config                       { return f.config }
func (f *Factory) TLSManager() *tls.TLSManager                   { return f.tlsManager }
func (f *Factory) ScyllaClient() *scylla.ScyllaClient            { return f.scyllaClient }
func (f *Factory) Hasher() *hashing.Hasher                       { return f.hasher }
func (f *Factory) EncryptionManager() *encryption.EncryptionManager { return f.encryptionManager }
func (f *Factory) BucketingManager() *bucketing.BucketingManager { return f.bucketingManager }
