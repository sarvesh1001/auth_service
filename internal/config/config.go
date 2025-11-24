// internal/config/config.go
package config

import (
	"context"
	"encoding/base64"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"auth-service/internal/util"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/joho/godotenv"
	"go.uber.org/zap"
)

type Config struct {
	Environment   string
	Server        ServerConfig
	Redis         RedisConfig
	Scylla        ScyllaConfig
	Kafka         KafkaConfig
	Elasticsearch ElasticsearchConfig
	Clickhouse    ClickhouseConfig
	Security      SecurityConfig
	Postgres      PostgresConfig
	Logging       LoggingConfig
	Hashing       HashingConfig
	Auth          AuthConfig
	RateLimiting  RateLimitingConfig
	Bucketing     BucketingConfig
	KMS           KMSConfig
	OTP           OTPConfig
	MPIN          MPINConfig
	JWT           JWTConfig
	Encryption    EncryptionConfig
}

// ----------------------------
// Structs
// ----------------------------

type PostgresConfig struct {
	Host              string        `mapstructure:"host"`
	Port              int           `mapstructure:"port"`
	Database          string        `mapstructure:"database"`
	Username          string        `mapstructure:"username"`
	Password          string        `mapstructure:"password"`
	SSLMode           string        `mapstructure:"ssl_mode"`
	PoolSize          int           `mapstructure:"pool_size"`
	MaxIdleConns      int           `mapstructure:"max_idle_conns"`
	MaxOpenConns      int           `mapstructure:"max_open_conns"`
	ConnMaxLifetime   time.Duration `mapstructure:"conn_max_lifetime"`
	ConnMaxIdleTime   time.Duration `mapstructure:"conn_max_idle_time"`
	ConnectionTimeout time.Duration `mapstructure:"connection_timeout"`
}

type JWTConfig struct {
	Secret              string        `mapstructure:"secret"`
	AccessTTL           time.Duration `mapstructure:"access_ttl"`
	RefreshTTL          time.Duration `mapstructure:"refresh_ttl"`
	SigningMethod       string        `mapstructure:"signing_method"`
	RotateRefreshTokens bool          `mapstructure:"rotate_refresh_tokens"`
}

type MPINConfig struct {
	MinLength              int           `json:"min_length"`
	MaxLength              int           `json:"max_length"`
	MaxAttempts            int           `json:"max_attempts"`
	LockDuration           time.Duration `json:"lock_duration"`
	VerifyLimit30Sec       int           `json:"verify_limit_30sec"`
	VerifyLimitMin         int           `json:"verify_limit_min"`
	SetupLimitHour         int           `json:"setup_limit_hour"`
	ChangeLimitDay         int           `json:"change_limit_day"`
	RequireDeviceBinding   bool          `json:"require_device_binding"`
	AutoUnlockExpired      bool          `json:"auto_unlock_expired"`
	LogWeakAttempts        bool          `json:"log_weak_attempts"`
	EnforceComplexity      bool          `json:"enforce_complexity"`
	CacheTTL               time.Duration `json:"cache_ttl"`
	FailedAttemptsCacheTTL time.Duration `json:"failed_attempts_cache_ttl"`
	CleanupInterval        time.Duration `json:"cleanup_interval"`
	CleanupBatchSize       int           `json:"cleanup_batch_size"`
	LogVerificationInDev   bool          `json:"log_verification_in_dev"`
	BypassComplexityDev    bool          `json:"bypass_complexity_dev"`
	AllowWeakPinsDev       bool          `json:"allow_weak_pins_dev"`
}

type EncryptionConfig struct {
	MasterKey  string `json:"-"`
	KMSEnabled bool   `json:"kms_enabled"`
	KEKEnabled bool   `json:"kek_enabled"`
}

type ServerConfig struct {
	Port         int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
	EnableTLS    bool
	TLSPort      int    `mapstructure:"tls_port"`
	CertFile     string `mapstructure:"cert_file"`
	KeyFile      string `mapstructure:"key_file"`
	AutoCert     bool   `mapstructure:"auto_cert"`
	AutoCertDir  string `mapstructure:"auto_cert_dir"`
	Domain       string `mapstructure:"domain"`
	Email        string `mapstructure:"email"`
}

type RedisConfig struct {
	URL      string
	Password string
	DB       int
	PoolSize int
}

type ScyllaConfig struct {
	Nodes       []string
	Username    string
	Password    string
	Keyspace    string
	Consistency string
}

type KafkaConfig struct {
	Brokers []string
}

type ElasticsearchConfig struct {
	URL      string
	Username string
	Password string
}

type ClickhouseConfig struct {
	URL      string
	Username string
	Password string
	Database string
	CAFile   string `mapstructure:"ca_file"`
}

type SecurityConfig struct {
	JWTSecret    string
	APIKey       string
	CORSOrigins  []string
	RateLimitRPS int
}

type LoggingConfig struct {
	Level  string
	Format string
}

type HashingConfig struct {
	Argon2TimeCost     int `mapstructure:"argon2_time_cost"`
	Argon2MemoryCost   int `mapstructure:"argon2_memory_cost"`
	Argon2Parallelism  int `mapstructure:"argon2_parallelism"`
	PepperRotationDays int `mapstructure:"pepper_rotation_days"`
}

type AuthConfig struct {
	OTPTTL          int `mapstructure:"otp_ttl"`
	SessionTTL      int `mapstructure:"session_ttl"`
	MPINMaxAttempts int `mapstructure:"mpin_max_attempts"`
	AdminSessionTTL int `mapstructure:"admin_session_ttl"`
}

type RateLimitingConfig struct {
	OTPPerPhoneMinute        int `mapstructure:"otp_per_phone_minute"`
	OTPPerPhoneHour          int `mapstructure:"otp_per_phone_hour"`
	LoginAttemptsPerIPMinute int `mapstructure:"login_attempts_per_ip_minute"`
	MPINAttemptsPerUserHour  int `mapstructure:"mpin_attempts_per_user_hour"`
}

type BucketingConfig struct {
	UserBuckets  int `mapstructure:"user_buckets"`
	EventBuckets int `mapstructure:"event_buckets"`
}

type KMSConfig struct {
	KeyID    string `mapstructure:"key_id"`
	Region   string `mapstructure:"region"`
	Endpoint string `mapstructure:"endpoint"`
	Enabled  bool   `mapstructure:"enabled"`
}

type OTPConfig struct {
	Length             int           `json:"length"`
	ExpiryDuration     time.Duration `json:"expiry_duration"`
	MaxAttempts        int           `json:"max_attempts"`
	ResendCooldown     time.Duration `json:"resend_cooldown"`
	SendLimit1Min      int           `json:"send_limit_1min"`
	SendLimit5Min      int           `json:"send_limit_5min"`
	SendLimitHour      int           `json:"send_limit_hour"`
	VerifyLimit30Sec   int           `json:"verify_limit_30sec"`
	VerifyLimitMin     int           `json:"verify_limit_min"`
	LockoutThreshold   int           `json:"lockout_threshold"`
	LockoutDuration    time.Duration `json:"lockout_duration"`
	CacheTTL           time.Duration `json:"cache_ttl"`
	RateLimitCacheTTL  time.Duration `json:"rate_limit_cache_ttl"`
	SMSProvider        string        `json:"sms_provider"`
	SMSEnabled         bool          `json:"sms_enabled"`
	SMSAPIKEY          string        `json:"-"`
	SMSAPISecret       string        `json:"-"`
	SMSFromNumber      string        `json:"sms_from_number"`
	SMSTemplateID      string        `json:"sms_template_id"`
	LogOTPInDev        bool          `json:"log_otp_in_dev"`
	BypassRateLimitDev bool          `json:"bypass_rate_limit_dev"`
}

var (
	cfg       *Config
	once      sync.Once
	kmsClient *kms.Client
	awsCfg    aws.Config
)

// ----------------------------
// LoadConfig
// ----------------------------

func LoadConfig() *Config {
	once.Do(func() {
		environment := getEnv("ENVIRONMENT", "development")
		isDev := environment == "development"

		if isDev {
			if err := godotenv.Load(".env"); err != nil {
				util.Info("No .env file found, using system environment variables")
			}
		}

		cfg = &Config{
			Environment: environment,

			Server: ServerConfig{
				Port:         getEnvAsInt("SERVER_PORT", 8080),
				TLSPort:      getEnvAsInt("SERVER_TLS_PORT", 8443),
				ReadTimeout:  getEnvAsDuration("SERVER_READ_TIMEOUT", 30*time.Second),
				WriteTimeout: getEnvAsDuration("SERVER_WRITE_TIMEOUT", 30*time.Second),
				IdleTimeout:  getEnvAsDuration("SERVER_IDLE_TIMEOUT", 60*time.Second),

				// UPDATED TLS SETTINGS
				EnableTLS: false,
				AutoCert:  false,
				CertFile:  "",
				KeyFile:   "",

				AutoCertDir: getEnv("SERVER_AUTO_CERT_DIR", "/app/certs"),
				Domain:      getEnv("SERVER_DOMAIN", "localhost"),
				Email:       getEnv("SERVER_EMAIL", "admin@localhost"),
			},

			Postgres: PostgresConfig{
				Host:              getEnv("POSTGRES_HOST", "postgres"),
				Port:              getEnvAsInt("POSTGRES_PORT", 5432),
				Database:          getEnv("POSTGRES_DATABASE", "auth_service"),
				Username:          getEnv("POSTGRES_USER", "auth_user"),
				Password:          getSecureEnv("POSTGRES_PASSWORD", "postgres_password"),
				SSLMode:           getEnv("POSTGRES_SSLMODE", "disable"),
				PoolSize:          getEnvAsInt("POSTGRES_POOL_SIZE", 50),
				MaxIdleConns:      getEnvAsInt("POSTGRES_MAX_IDLE_CONNS", 10),
				MaxOpenConns:      getEnvAsInt("POSTGRES_MAX_OPEN_CONNS", 100),
				ConnMaxLifetime:   getEnvAsDuration("POSTGRES_CONN_MAX_LIFETIME", 300*time.Second),
				ConnMaxIdleTime:   getEnvAsDuration("POSTGRES_CONN_MAX_IDLE_TIME", 60*time.Second),
				ConnectionTimeout: getEnvAsDuration("POSTGRES_CONNECTION_TIMEOUT", 30*time.Second),
			},

			Redis: RedisConfig{
				URL:      getEnv("REDIS_URL", "redis://redis:6379"),
				Password: getSecureEnv("REDIS_PASSWORD", ""),
				DB:       getEnvAsInt("REDIS_DB", 0),
				PoolSize: getEnvAsInt("REDIS_POOL_SIZE", 100),
			},

			Scylla: ScyllaConfig{
				Nodes:       getEnvAsSlice("SCYLLA_NODES", []string{"scylla:9042"}, ","),
				Username:    getEnv("SCYLLA_USERNAME", ""),
				Password:    getSecureEnv("SCYLLA_PASSWORD", ""),
				Keyspace:    getEnv("SCYLLA_KEYSPACE", "core_auth"),
				Consistency: getEnv("SCYLLA_CONSISTENCY", "LOCAL_QUORUM"),
			},

			Kafka: KafkaConfig{
				Brokers: getEnvAsSlice("KAFKA_BROKERS", []string{"kafka:9092"}, ","),
			},

			Elasticsearch: ElasticsearchConfig{
				URL:      getEnv("ELASTICSEARCH_URL", "http://elasticsearch:9200"),
				Username: getEnv("ELASTICSEARCH_USERNAME", "elastic"),
				Password: getSecureEnv("ELASTIC_PASSWORD", ""),
			},

			Clickhouse: ClickhouseConfig{
				URL:      getEnv("CLICKHOUSE_URL", "http://clickhouse:8123"),
				Username: getEnv("CLICKHOUSE_USER", "default"),
				Password: getSecureEnv("CLICKHOUSE_PASSWORD", ""),
				Database: getEnv("CLICKHOUSE_DATABASE", "auth_analytics"),
				CAFile:   getEnv("CLICKHOUSE_CA_FILE", ""),
			},

			Security: SecurityConfig{
				JWTSecret:    getSecureEnv("JWT_SECRET", "default-insecure-secret-change-in-production"),
				APIKey:       getSecureEnv("API_KEY", ""),
				CORSOrigins:  getEnvAsSlice("CORS_ORIGINS", []string{"*"}, ","),
				RateLimitRPS: getEnvAsInt("RATE_LIMIT_RPS", 1000),
			},

			Logging: LoggingConfig{
				Level:  getEnv("LOG_LEVEL", "info"),
				Format: getEnv("LOG_FORMAT", "json"),
			},

			Hashing: HashingConfig{
				Argon2TimeCost:     getEnvAsInt("ARGON2_TIME_COST", 3),
				Argon2MemoryCost:   getEnvAsInt("ARGON2_MEMORY_COST", 65536),
				Argon2Parallelism:  getEnvAsInt("ARGON2_PARALLELISM", 2),
				PepperRotationDays: getEnvAsInt("PEPPER_ROTATION_DAYS", 90),
			},

			Auth: AuthConfig{
				OTPTTL:          getEnvAsInt("OTP_TTL", 300),
				SessionTTL:      getEnvAsInt("SESSION_TTL", 2592000),
				MPINMaxAttempts: getEnvAsInt("MPIN_MAX_ATTEMPTS", 5),
				AdminSessionTTL: getEnvAsInt("ADMIN_SESSION_TTL", 28800),
			},

			RateLimiting: RateLimitingConfig{
				OTPPerPhoneMinute:        getEnvAsInt("RATE_LIMIT_OTP_PER_PHONE_MINUTE", 3),
				OTPPerPhoneHour:          getEnvAsInt("RATE_LIMIT_OTP_PER_PHONE_HOUR", 10),
				LoginAttemptsPerIPMinute: getEnvAsInt("RATE_LIMIT_LOGIN_ATTEMPTS_PER_IP_MINUTE", 20),
				MPINAttemptsPerUserHour:  getEnvAsInt("RATE_LIMIT_MPIN_ATTEMPTS_PER_USER_HOUR", 10),
			},

			Bucketing: BucketingConfig{
				UserBuckets:  getEnvAsInt("USER_BUCKETS", 1024),
				EventBuckets: getEnvAsInt("EVENT_BUCKETS", 256),
			},

			KMS: KMSConfig{
				KeyID:    getEnv("KMS_KEY_ID", ""),
				Region:   getEnv("KMS_REGION", "us-east-1"),
				Endpoint: getEnv("KMS_ENDPOINT", ""),
				Enabled:  !isDev,
			},

			OTP:  loadOTPConfig(environment),
			MPIN: loadMPINConfig(environment),
			JWT:  loadJWTConfig(environment),

			Encryption: EncryptionConfig{
				MasterKey:  getEnv("ENCRYPTION_MASTER_KEY", ""),
				KMSEnabled: getEnvAsBool("ENCRYPTION_KMS_ENABLED", false),
				KEKEnabled: getEnvAsBool("ENCRYPTION_KEK_ENABLED", false),
			},
		}

		if cfg.KMS.Enabled {
			if err := initKMSClient(cfg); err != nil {
				util.Warn("Failed to initialize KMS client, falling back to plaintext", zap.Error(err))
				cfg.KMS.Enabled = false
			}
		}

		validateConfig(cfg)

		util.Info("configuration loaded",
			zap.String("environment", cfg.Environment),
			zap.Bool("tls_enabled", cfg.Server.EnableTLS),
			zap.Bool("kms_enabled", cfg.KMS.Enabled),
			zap.Int("user_buckets", cfg.Bucketing.UserBuckets),
			zap.Int("event_buckets", cfg.Bucketing.EventBuckets),
			zap.Bool("otp_sms_enabled", cfg.OTP.SMSEnabled),
			zap.String("otp_provider", cfg.OTP.SMSProvider),
			zap.Duration("jwt_access_ttl", cfg.JWT.AccessTTL),
			zap.Duration("jwt_refresh_ttl", cfg.JWT.RefreshTTL),
			zap.Bool("jwt_rotate_refresh", cfg.JWT.RotateRefreshTokens),
		)
	})

	return cfg
}

// ----------------------------
// loadJWTConfig
// ----------------------------

func loadJWTConfig(env string) JWTConfig {
	isDev := env == "development"

	return JWTConfig{
		Secret:              getSecureEnv("JWT_SECRET", "default-insecure-secret-change-in-production"),
		AccessTTL:           getEnvAsDuration("JWT_ACCESS_TTL", 15*time.Minute),
		RefreshTTL:          getEnvAsDuration("JWT_REFRESH_TTL", 168*time.Hour),
		SigningMethod:       getEnv("JWT_SIGNING_METHOD", "HS256"),
		RotateRefreshTokens: getEnvAsBool("JWT_ROTATE_REFRESH_TOKENS", !isDev),
	}
}

// ----------------------------
// loadMPINConfig
// ----------------------------

func loadMPINConfig(env string) MPINConfig {
	isDev := env == "development"

	return MPINConfig{
		MinLength:              getEnvAsInt("MPIN_MIN_LENGTH", 4),
		MaxLength:              getEnvAsInt("MPIN_MAX_LENGTH", 8),
		MaxAttempts:            getEnvAsInt("MPIN_MAX_ATTEMPTS", ifInt(isDev, 5, 3)),
		LockDuration:           getEnvAsDuration("MPIN_LOCK_DURATION", 30*time.Second),
		VerifyLimit30Sec:       getEnvAsInt("RATE_LIMIT_MPIN_VERIFY_30SEC", ifInt(isDev, 10, 3)),
		VerifyLimitMin:         getEnvAsInt("RATE_LIMIT_MPIN_VERIFY_MIN", ifInt(isDev, 15, 5)),
		SetupLimitHour:         getEnvAsInt("RATE_LIMIT_MPIN_SETUP_PER_USER_HOUR", ifInt(isDev, 3, 2)),
		ChangeLimitDay:         getEnvAsInt("RATE_LIMIT_MPIN_CHANGE_PER_USER_DAY", ifInt(isDev, 5, 3)),
		RequireDeviceBinding:   getEnvAsBool("MPIN_REQUIRE_DEVICE_BINDING", true),
		AutoUnlockExpired:      getEnvAsBool("MPIN_AUTO_UNLOCK_EXPIRED", true),
		LogWeakAttempts:        getEnvAsBool("MPIN_LOG_WEAK_ATTEMPTS", true),
		EnforceComplexity:      getEnvAsBool("MPIN_ENFORCE_COMPLEXITY", !isDev),
		CacheTTL:               getEnvAsDuration("MPIN_CACHE_TTL", ifDuration(isDev, 10*time.Minute, 5*time.Minute)),
		FailedAttemptsCacheTTL: getEnvAsDuration("MPIN_FAILED_ATTEMPTS_CACHE_TTL", ifDuration(isDev, 1*time.Hour, 30*time.Minute)),
		CleanupInterval:        getEnvAsDuration("MPIN_CLEANUP_INTERVAL", ifDuration(isDev, 1*time.Hour, 30*time.Minute)),
		CleanupBatchSize:       getEnvAsInt("MPIN_CLEANUP_BATCH_SIZE", ifInt(isDev, 100, 50)),
		LogVerificationInDev:   getEnvAsBool("MPIN_LOG_VERIFICATION_IN_DEV", isDev),
		BypassComplexityDev:    getEnvAsBool("MPIN_BYPASS_COMPLEXITY_DEV", false),
		AllowWeakPinsDev:       getEnvAsBool("MPIN_ALLOW_WEAK_PINS_DEV", false),
	}
}

// ----------------------------
// loadOTPConfig
// ----------------------------

func loadOTPConfig(env string) OTPConfig {
	isDev := env == "development"

	return OTPConfig{
		Length:             getEnvAsInt("OTP_LENGTH", 6),
		ExpiryDuration:     getEnvAsDuration("OTP_EXPIRY_DURATION", 5*time.Minute),
		MaxAttempts:        getEnvAsInt("OTP_MAX_ATTEMPTS", 3),
		ResendCooldown:     getEnvAsDuration("OTP_RESEND_COOLDOWN", 60*time.Second),
		SendLimit1Min:      getEnvAsInt("RATE_LIMIT_OTP_SEND_1MIN", ifInt(isDev, 5, 2)),
		SendLimit5Min:      getEnvAsInt("RATE_LIMIT_OTP_SEND_5MIN", ifInt(isDev, 10, 3)),
		SendLimitHour:      getEnvAsInt("RATE_LIMIT_OTP_SEND_HOUR", ifInt(isDev, 50, 10)),
		VerifyLimit30Sec:   getEnvAsInt("RATE_LIMIT_OTP_VERIFY_30SEC", ifInt(isDev, 10, 3)),
		VerifyLimitMin:     getEnvAsInt("RATE_LIMIT_OTP_VERIFY_MIN", ifInt(isDev, 20, 5)),
		LockoutThreshold:   getEnvAsInt("OTP_LOCKOUT_THRESHOLD", ifInt(isDev, 100, 5)),
		LockoutDuration:    getEnvAsDuration("OTP_LOCKOUT_DURATION", ifDuration(isDev, 5*time.Minute, 30*time.Minute)),
		CacheTTL:           getEnvAsDuration("OTP_CACHE_TTL", 6*time.Minute),
		RateLimitCacheTTL:  getEnvAsDuration("OTP_RATE_LIMIT_CACHE_TTL", 1*time.Hour),
		SMSProvider:        getEnv("SMS_PROVIDER", ifString(isDev, "mock", "twilio")),
		SMSEnabled:         getEnvAsBool("SMS_ENABLED", !isDev),
		SMSAPIKEY:          getSecureEnv("SMS_API_KEY", ""),
		SMSAPISecret:       getSecureEnv("SMS_API_SECRET", ""),
		SMSFromNumber:      getEnv("SMS_FROM_NUMBER", ""),
		SMSTemplateID:      getEnv("SMS_TEMPLATE_ID", ""),
		LogOTPInDev:        isDev,
		BypassRateLimitDev: getEnvAsBool("OTP_BYPASS_RATE_LIMIT_DEV", isDev),
	}
}

// ----------------------------
// KMS Support
// ----------------------------

func initKMSClient(cfg *Config) error {
	ctx := context.Background()

	opts := []func(*awsConfig.LoadOptions) error{
		awsConfig.WithRegion(cfg.KMS.Region),
	}

	if cfg.KMS.Endpoint != "" {
		customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			if service == kms.ServiceID {
				return aws.Endpoint{
					URL:           cfg.KMS.Endpoint,
					SigningRegion: region,
				}, nil
			}
			return aws.Endpoint{}, &aws.EndpointNotFoundError{}
		})
		opts = append(opts, awsConfig.WithEndpointResolverWithOptions(customResolver))
	}

	var err error
	awsCfg, err = awsConfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return err
	}

	kmsClient = kms.NewFromConfig(awsCfg)

	util.Info("KMS client initialized",
		zap.String("region", cfg.KMS.Region),
		zap.String("key_id", cfg.KMS.KeyID),
		zap.String("endpoint", cfg.KMS.Endpoint),
	)

	return nil
}

func getSecureEnv(key, defaultValue string) string {
	value := getEnv(key, "")
	if value == "" {
		return defaultValue
	}

	if cfg == nil || !cfg.KMS.Enabled || kmsClient == nil {
		return value
	}

	if isBase64Encoded(value) {
		decrypted, err := decryptWithKMS(context.Background(), value)
		if err != nil {
			util.Warn("Failed to decrypt with KMS, using plaintext fallback",
				zap.String("key", key),
				zap.Error(err),
			)
			return value
		}
		return decrypted
	}

	util.Warn("Plaintext secret detected in production",
		zap.String("key", key),
		zap.String("action", "please encrypt this value with KMS"),
	)
	return value
}

func decryptWithKMS(ctx context.Context, ciphertext string) (string, error) {
	ciphertextBlob, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	input := &kms.DecryptInput{
		CiphertextBlob: ciphertextBlob,
	}

	result, err := kmsClient.Decrypt(ctx, input)
	if err != nil {
		return "", err
	}

	return string(result.Plaintext), nil
}

func isBase64Encoded(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

// ----------------------------
// validateConfig
// ----------------------------

func validateConfig(cfg *Config) {
	if cfg.Environment == "production" {
		if cfg.KMS.Enabled && cfg.KMS.KeyID == "" {
			util.Warn("KMS_KEY_ID is not set - secure encryption will not work")
		}
		if cfg.MPIN.MinLength < 4 {
			util.Warn("MPIN_MIN_LENGTH is less than 4 - this may be insecure for production")
		}
		if cfg.MPIN.MaxAttempts < 3 {
			util.Warn("MPIN_MAX_ATTEMPTS is very low - consider increasing to at least 3")
		}
		if cfg.MPIN.LockDuration < 15*time.Minute {
			util.Warn("MPIN_LOCK_DURATION is less than 15 minutes - consider increasing for security")
		}
		if !cfg.MPIN.RequireDeviceBinding {
			util.Warn("MPIN_REQUIRE_DEVICE_BINDING is disabled - this may reduce security")
		}
		if !cfg.MPIN.EnforceComplexity {
			util.Warn("MPIN_ENFORCE_COMPLEXITY is disabled - this may reduce security")
		}

		if cfg.JWT.Secret == "" || cfg.JWT.Secret == "default-insecure-secret-change-in-production" {
			util.Warn("JWT_SECRET is using default value - this is insecure for production")
		}
		if len(cfg.JWT.Secret) < 32 {
			util.Warn("JWT_SECRET is too short - should be at least 32 characters for production")
		}
		if cfg.JWT.AccessTTL > 30*time.Minute {
			util.Warn("JWT_ACCESS_TTL is longer than 30 minutes - consider reducing")
		}
		if cfg.JWT.RefreshTTL > 30*24*time.Hour {
			util.Warn("JWT_REFRESH_TTL is longer than 30 days")
		}
		if cfg.JWT.SigningMethod != "HS256" && cfg.JWT.SigningMethod != "RS256" {
			util.Warn("JWT_SIGNING_METHOD should be HS256 or RS256")
		}
		if !cfg.JWT.RotateRefreshTokens {
			util.Warn("JWT_ROTATE_REFRESH_TOKENS is disabled")
		}

		if cfg.Security.JWTSecret == "default-insecure-secret-change-in-production" {
			util.Warn("JWT_SECRET is using default value")
		}

		if cfg.Redis.Password == "" {
			util.Warn("REDIS_PASSWORD is not set")
		}
		if cfg.Scylla.Password == "" {
			util.Warn("SCYLLA_PASSWORD is not set")
		}
		if cfg.Elasticsearch.Password == "" {
			util.Warn("ELASTIC_PASSWORD is not set")
		}

		if cfg.OTP.SMSEnabled && cfg.OTP.SMSAPIKEY == "" {
			util.Warn("SMS_API_KEY missing")
		}
		if cfg.OTP.SMSEnabled && cfg.OTP.SMSFromNumber == "" {
			util.Warn("SMS_FROM_NUMBER missing")
		}
		if cfg.OTP.LogOTPInDev {
			util.Warn("OTP logging enabled in production")
		}
	}

	if cfg.Hashing.Argon2MemoryCost < 65536 {
		util.Warn("Argon2 memory cost is very low")
	}
}

// ----------------------------
// utilities
// ----------------------------

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	strValue := getEnv(key, "")
	if value, err := strconv.Atoi(strValue); err == nil {
		return value
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	strValue := getEnv(key, "")
	if value, err := strconv.ParseBool(strValue); err == nil {
		return value
	}
	return defaultValue
}

func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	strValue := getEnv(key, "")
	if value, err := time.ParseDuration(strValue); err == nil {
		return value
	}
	return defaultValue
}

func getEnvAsSlice(key string, defaultValue []string, separator string) []string {
	strValue := getEnv(key, "")
	if strValue == "" {
		return defaultValue
	}
	return strings.Split(strValue, separator)
}

func ifInt(condition bool, trueVal, falseVal int) int {
	if condition {
		return trueVal
	}
	return falseVal
}

func ifString(condition bool, trueVal, falseVal string) string {
	if condition {
		return trueVal
	}
	return falseVal
}

func ifDuration(condition bool, trueVal, falseVal time.Duration) time.Duration {
	if condition {
		return trueVal
	}
	return falseVal
}

func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

func (c *Config) GetServerAddress() string {
	return ":" + strconv.Itoa(c.Server.Port)
}

func (c *Config) GetTLSServerAddress() string {
	return ":" + strconv.Itoa(c.Server.TLSPort)
}

func (c *Config) Validate() error {
	if c.IsProduction() {
		if c.OTP.SMSEnabled && c.OTP.SMSAPIKEY == "" {
			util.Warn("SMS_API_KEY required in production")
		}
		if c.OTP.SMSEnabled && c.OTP.SMSFromNumber == "" {
			util.Warn("SMS_FROM_NUMBER required in production")
		}
	}
	return nil
}
