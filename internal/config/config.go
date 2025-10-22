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
	Logging       LoggingConfig
	Hashing       HashingConfig
	Auth          AuthConfig
	RateLimiting  RateLimitingConfig
	Bucketing     BucketingConfig
	KMS           KMSConfig
	OTP           OTPConfig // NEW
	MPIN		  MPINConfig // NEW

}
type MPINConfig struct {
    // Basic Settings
    MinLength     int           `json:"min_length"`
    MaxLength     int           `json:"max_length"`
    MaxAttempts   int           `json:"max_attempts"`
    LockDuration  time.Duration `json:"lock_duration"`
    
    // Rate Limiting
    VerifyLimit30Sec     int `json:"verify_limit_30sec"`
    VerifyLimitMin       int `json:"verify_limit_min"`
    SetupLimitHour       int `json:"setup_limit_hour"`
    ChangeLimitDay       int `json:"change_limit_day"`
    
    // Security Settings
    RequireDeviceBinding bool `json:"require_device_binding"`
    AutoUnlockExpired    bool `json:"auto_unlock_expired"`
    LogWeakAttempts      bool `json:"log_weak_attempts"`
    EnforceComplexity    bool `json:"enforce_complexity"`
    
    // Cache Settings
    CacheTTL               time.Duration `json:"cache_ttl"`
    FailedAttemptsCacheTTL time.Duration `json:"failed_attempts_cache_ttl"`
    
    // Cleanup Settings
    CleanupInterval time.Duration `json:"cleanup_interval"`
    CleanupBatchSize int          `json:"cleanup_batch_size"`
    
    // Development Settings
    LogVerificationInDev bool `json:"log_verification_in_dev"`
    BypassComplexityDev  bool `json:"bypass_complexity_dev"`
    AllowWeakPinsDev     bool `json:"allow_weak_pins_dev"`
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

// OTPConfig contains OTP-related configuration
type OTPConfig struct {
	// OTP Settings
	Length         int           `json:"length"`
	ExpiryDuration time.Duration `json:"expiry_duration"`
	MaxAttempts    int           `json:"max_attempts"`
	ResendCooldown time.Duration `json:"resend_cooldown"`

	// Rate Limiting
	SendLimit1Min    int `json:"send_limit_1min"`
	SendLimit5Min    int `json:"send_limit_5min"`
	SendLimitHour    int `json:"send_limit_hour"`
	VerifyLimit30Sec int `json:"verify_limit_30sec"`
	VerifyLimitMin   int `json:"verify_limit_min"`

	// Lockout Settings
	LockoutThreshold int           `json:"lockout_threshold"`
	LockoutDuration  time.Duration `json:"lockout_duration"`

	// Cache Settings
	CacheTTL          time.Duration `json:"cache_ttl"`
	RateLimitCacheTTL time.Duration `json:"rate_limit_cache_ttl"`

	// SMS Provider Settings
	SMSProvider   string `json:"sms_provider"`
	SMSEnabled    bool   `json:"sms_enabled"`
	SMSAPIKEY     string `json:"-"` // Hidden in JSON
	SMSAPISecret  string `json:"-"` // Hidden in JSON
	SMSFromNumber string `json:"sms_from_number"`
	SMSTemplateID string `json:"sms_template_id"`

	// Development Settings
	LogOTPInDev        bool `json:"log_otp_in_dev"`
	BypassRateLimitDev bool `json:"bypass_rate_limit_dev"`
}

var (
	cfg       *Config
	once      sync.Once
	kmsClient *kms.Client
	awsCfg    aws.Config
)
// LoadConfig loads configuration from environment variables or KMS
func LoadConfig() *Config {
	once.Do(func() {
		environment := getEnv("ENVIRONMENT", "development")
		isDev := environment == "development"

		// Load .env file only in development
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
				EnableTLS:    getEnvAsBool("SERVER_ENABLE_TLS", !isDev),
				AutoCert:     getEnvAsBool("SERVER_AUTO_CERT", !isDev),
				AutoCertDir:  getEnv("SERVER_AUTO_CERT_DIR", "/app/certs"),
				CertFile:     getEnv("SERVER_CERT_FILE", ""),
				KeyFile:      getEnv("SERVER_KEY_FILE", ""),
				Domain:       getEnv("SERVER_DOMAIN", "localhost"),
				Email:        getEnv("SERVER_EMAIL", "admin@"+getEnv("SERVER_DOMAIN", "localhost")),
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
			OTP: loadOTPConfig(environment),
			MPIN: loadMPINConfig(environment),
			// NEW
		}

		// Initialize KMS client for production after basic config is loaded
		if cfg.KMS.Enabled {
			if err := initKMSClient(cfg); err != nil {
				util.Warn("Failed to initialize KMS client, falling back to plaintext", zap.Error(err))
				cfg.KMS.Enabled = false
			}
		}

		// Validate configuration
		validateConfig(cfg)

		util.Info("configuration loaded",
			zap.String("environment", cfg.Environment),
			zap.Bool("tls_enabled", cfg.Server.EnableTLS),
			zap.Bool("kms_enabled", cfg.KMS.Enabled),
			zap.Int("user_buckets", cfg.Bucketing.UserBuckets),
			zap.Int("event_buckets", cfg.Bucketing.EventBuckets),
			zap.Bool("otp_sms_enabled", cfg.OTP.SMSEnabled),
			zap.String("otp_provider", cfg.OTP.SMSProvider),
		)
	})

	return cfg
}
func loadMPINConfig(env string) MPINConfig {
    isDev := env == "development"

    return MPINConfig{
        // Basic Settings
        MinLength:    getEnvAsInt("MPIN_MIN_LENGTH", 4),
        MaxLength:    getEnvAsInt("MPIN_MAX_LENGTH", 8),
        MaxAttempts:  getEnvAsInt("MPIN_MAX_ATTEMPTS", ifInt(isDev, 5, 3)),
        LockDuration: getEnvAsDuration("MPIN_LOCK_DURATION", 30*time.Minute),
        
        // Rate Limiting (more lenient in dev)
        VerifyLimit30Sec: getEnvAsInt("RATE_LIMIT_MPIN_VERIFY_30SEC", ifInt(isDev, 10, 3)),
        VerifyLimitMin:   getEnvAsInt("RATE_LIMIT_MPIN_VERIFY_MIN", ifInt(isDev, 15, 5)),
        SetupLimitHour:   getEnvAsInt("RATE_LIMIT_MPIN_SETUP_PER_USER_HOUR", ifInt(isDev, 3, 2)),
        ChangeLimitDay:   getEnvAsInt("RATE_LIMIT_MPIN_CHANGE_PER_USER_DAY", ifInt(isDev, 5, 3)),
        
        // Security Settings
        RequireDeviceBinding: getEnvAsBool("MPIN_REQUIRE_DEVICE_BINDING", true),
        AutoUnlockExpired:    getEnvAsBool("MPIN_AUTO_UNLOCK_EXPIRED", true),
        LogWeakAttempts:      getEnvAsBool("MPIN_LOG_WEAK_ATTEMPTS", true),
        EnforceComplexity:    getEnvAsBool("MPIN_ENFORCE_COMPLEXITY", !isDev),
        
        // Cache Settings
        CacheTTL:               getEnvAsDuration("MPIN_CACHE_TTL", ifDuration(isDev, 10*time.Minute, 5*time.Minute)),
        FailedAttemptsCacheTTL: getEnvAsDuration("MPIN_FAILED_ATTEMPTS_CACHE_TTL", ifDuration(isDev, 1*time.Hour, 30*time.Minute)),
        
        // Cleanup Settings
        CleanupInterval:  getEnvAsDuration("MPIN_CLEANUP_INTERVAL", ifDuration(isDev, 1*time.Hour, 30*time.Minute)),
        CleanupBatchSize: getEnvAsInt("MPIN_CLEANUP_BATCH_SIZE", ifInt(isDev, 100, 50)),
        
        // Development Settings
        LogVerificationInDev: getEnvAsBool("MPIN_LOG_VERIFICATION_IN_DEV", isDev),
        BypassComplexityDev:  getEnvAsBool("MPIN_BYPASS_COMPLEXITY_DEV", false),
        AllowWeakPinsDev:     getEnvAsBool("MPIN_ALLOW_WEAK_PINS_DEV", false),
    }
}
// loadOTPConfig loads OTP-specific configuration
func loadOTPConfig(env string) OTPConfig {
	isDev := env == "development"

	return OTPConfig{
		// OTP Settings
		Length:         getEnvAsInt("OTP_LENGTH", 6),
		ExpiryDuration: getEnvAsDuration("OTP_EXPIRY_DURATION", 5*time.Minute),
		MaxAttempts:    getEnvAsInt("OTP_MAX_ATTEMPTS", 3),
		ResendCooldown: getEnvAsDuration("OTP_RESEND_COOLDOWN", 60*time.Second),

		// Rate Limiting (more lenient in dev)
		SendLimit1Min:    getEnvAsInt("RATE_LIMIT_OTP_SEND_1MIN", ifInt(isDev, 5, 2)),
		SendLimit5Min:    getEnvAsInt("RATE_LIMIT_OTP_SEND_5MIN", ifInt(isDev, 10, 3)),
		SendLimitHour:    getEnvAsInt("RATE_LIMIT_OTP_SEND_HOUR", ifInt(isDev, 50, 10)),
		VerifyLimit30Sec: getEnvAsInt("RATE_LIMIT_OTP_VERIFY_30SEC", ifInt(isDev, 10, 3)),
		VerifyLimitMin:   getEnvAsInt("RATE_LIMIT_OTP_VERIFY_MIN", ifInt(isDev, 20, 5)),

		// Lockout Settings (disabled in dev by default)
		LockoutThreshold: getEnvAsInt("OTP_LOCKOUT_THRESHOLD", ifInt(isDev, 100, 5)),
		LockoutDuration:  getEnvAsDuration("OTP_LOCKOUT_DURATION", ifDuration(isDev, 5*time.Minute, 30*time.Minute)),

		// Cache Settings
		CacheTTL:          getEnvAsDuration("OTP_CACHE_TTL", 6*time.Minute),
		RateLimitCacheTTL: getEnvAsDuration("OTP_RATE_LIMIT_CACHE_TTL", 1*time.Hour),

		// SMS Provider Settings
		SMSProvider:   getEnv("SMS_PROVIDER", ifString(isDev, "mock", "twilio")),
		SMSEnabled:    getEnvAsBool("SMS_ENABLED", !isDev),
		SMSAPIKEY:     getSecureEnv("SMS_API_KEY", ""),
		SMSAPISecret:  getSecureEnv("SMS_API_SECRET", ""),
		SMSFromNumber: getEnv("SMS_FROM_NUMBER", ""),
		SMSTemplateID: getEnv("SMS_TEMPLATE_ID", ""),

		// Development Settings
		LogOTPInDev:        isDev,
		BypassRateLimitDev: getEnvAsBool("OTP_BYPASS_RATE_LIMIT_DEV", isDev),
	}
}

// initKMSClient initializes AWS KMS client for production using SDK v2
func initKMSClient(cfg *Config) error {
	ctx := context.Background()

	// Build AWS config options
	opts := []func(*awsConfig.LoadOptions) error{
		awsConfig.WithRegion(cfg.KMS.Region),
	}

	// Use custom endpoint for local testing (if provided)
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

	// Load AWS configuration
	var err error
	awsCfg, err = awsConfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return err
	}

	// Create KMS client
	kmsClient = kms.NewFromConfig(awsCfg)

	util.Info("KMS client initialized",
		zap.String("region", cfg.KMS.Region),
		zap.String("key_id", cfg.KMS.KeyID),
		zap.String("endpoint", cfg.KMS.Endpoint),
	)

	return nil
}

// getSecureEnv retrieves environment variables, decrypting with KMS in production
func getSecureEnv(key, defaultValue string) string {
	value := getEnv(key, "")
	if value == "" {
		return defaultValue
	}

	// In development or if KMS is not configured, return plaintext
	if cfg == nil || !cfg.KMS.Enabled || kmsClient == nil {
		return value
	}

	// Check if the value is base64 encoded (KMS ciphertext)
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

	// Value is plaintext, encrypt it for storage and log warning
	util.Warn("Plaintext secret detected in production",
		zap.String("key", key),
		zap.String("action", "please encrypt this value with KMS"),
	)
	return value
}

// decryptWithKMS decrypts a base64-encoded ciphertext using AWS KMS v2
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

// isBase64Encoded checks if a string is base64 encoded
func isBase64Encoded(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

func validateConfig(cfg *Config) {
	if cfg.Environment == "production" {
		// Validate KMS configuration
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
		// Validate secrets are not using default values
		if cfg.Security.JWTSecret == "default-insecure-secret-change-in-production" {
			util.Warn("JWT_SECRET is using default value - this is insecure for production")
		}

		// Check if any passwords are empty
		if cfg.Redis.Password == "" {
			util.Warn("REDIS_PASSWORD is not set - this may be insecure for production")
		}
		if cfg.Scylla.Password == "" {
			util.Warn("SCYLLA_PASSWORD is not set - this may be insecure for production")
		}
		if cfg.Elasticsearch.Password == "" {
			util.Warn("ELASTIC_PASSWORD is not set - this may be insecure for production")
		}

		// Validate OTP configuration for production
		if cfg.OTP.SMSEnabled && cfg.OTP.SMSAPIKEY == "" {
			util.Warn("SMS_API_KEY is not set but SMS is enabled")
		}
		if cfg.OTP.SMSEnabled && cfg.OTP.SMSFromNumber == "" {
			util.Warn("SMS_FROM_NUMBER is not set but SMS is enabled")
		}
		if cfg.OTP.LogOTPInDev {
			util.Warn("OTP logging is enabled in production - this is a security risk")
		}
	}

	// Validate hashing parameters
	if cfg.Hashing.Argon2MemoryCost < 65536 {
		util.Warn("Argon2 memory cost is very low, consider increasing for better security")
	}
}

// Helper functions
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

// Conditional helper functions
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

// Utility methods
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

// Validate validates the OTP configuration
func (c *Config) Validate() error {
	if c.IsProduction() {
		if c.OTP.SMSEnabled && c.OTP.SMSAPIKEY == "" {
			util.Warn("SMS_API_KEY is required in production when SMS is enabled")
		}
		if c.OTP.SMSEnabled && c.OTP.SMSFromNumber == "" {
			util.Warn("SMS_FROM_NUMBER is required in production when SMS is enabled")
		}
	}
	return nil
}
