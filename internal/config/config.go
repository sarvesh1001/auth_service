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

		// Load .env file only in development
		if environment == "development" {
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
				EnableTLS:    getEnvAsBool("SERVER_ENABLE_TLS", environment == "production"),
				AutoCert:     getEnvAsBool("SERVER_AUTO_CERT", environment == "production"),
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
				Enabled:  environment == "production",
			},
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
		)
	})

	return cfg
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
	}

	// Validate hashing parameters
	if cfg.Hashing.Argon2MemoryCost < 65536 {
		util.Warn("Argon2 memory cost is very low, consider increasing for better security")
	}
}

// Helper functions (unchanged)
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
