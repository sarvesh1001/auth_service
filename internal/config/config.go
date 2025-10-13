// internal/config/config.go
package config

import (
    "os"
    "strconv"
    "strings"
    "sync"
    "time"

    "auth-service/internal/util"
    "github.com/joho/godotenv"
    "go.uber.org/zap"
)

type Config struct {
    Environment string
    Server      ServerConfig
    Redis       RedisConfig
    Scylla      ScyllaConfig
    Kafka       KafkaConfig
    Elasticsearch ElasticsearchConfig
    Clickhouse  ClickhouseConfig
    Security    SecurityConfig
    Logging     LoggingConfig
}

type ServerConfig struct {
    Port         int
    ReadTimeout  time.Duration
    WriteTimeout  time.Duration
    IdleTimeout  time.Duration
    EnableTLS    bool
    TLSPort      int           `mapstructure:"tls_port"`
    CertFile     string        `mapstructure:"cert_file"`
    KeyFile      string        `mapstructure:"key_file"`
    AutoCert     bool          `mapstructure:"auto_cert"`
    AutoCertDir  string        `mapstructure:"auto_cert_dir"`
    Domain       string        `mapstructure:"domain"`
    Email        string        `mapstructure:"email"`
}

type RedisConfig struct {
    URL      string
    Password string
    DB       int
    PoolSize int
}

type ScyllaConfig struct {
    Nodes    []string
    Username string
    Password string
    Keyspace string
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

var (
    cfg  *Config
    once sync.Once
)

// LoadConfig loads configuration from environment variables with .env support
func LoadConfig() *Config {
    once.Do(func() {
        // Load .env file if exists (for local development)
        // In production, these should be set as actual environment variables
        if err := godotenv.Load(".env"); err != nil {
            util.Info("No .env file found, using system environment variables")
        }

        environment := getEnv("ENVIRONMENT", "development")
        
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
                Password: getEnv("REDIS_PASSWORD", ""),
                DB:       getEnvAsInt("REDIS_DB", 0),
                PoolSize: getEnvAsInt("REDIS_POOL_SIZE", 100),
            },
            Scylla: ScyllaConfig{
                Nodes:    getEnvAsSlice("SCYLLA_NODES", []string{"scylla:9042"}, ","),
                Username: getEnv("SCYLLA_USERNAME", ""),
                Password: getEnv("SCYLLA_PASSWORD", ""),
                Keyspace: getEnv("SCYLLA_KEYSPACE", "auth_service"),
            },
            Kafka: KafkaConfig{
                Brokers: getEnvAsSlice("KAFKA_BROKERS", []string{"kafka:9092"}, ","),
            },
            Elasticsearch: ElasticsearchConfig{
                URL:      getEnv("ELASTICSEARCH_URL", "http://elasticsearch:9200"),
                Username: getEnv("ELASTICSEARCH_USERNAME", "elastic"),
                Password: getEnv("ELASTIC_PASSWORD", ""),
            },
            Clickhouse: ClickhouseConfig{
                URL:      getEnv("CLICKHOUSE_URL", "http://clickhouse:8123"),
                Username: getEnv("CLICKHOUSE_USER", "default"),
                Password: getEnv("CLICKHOUSE_PASSWORD", ""),
                Database: getEnv("CLICKHOUSE_DATABASE", "default"),
                CAFile:   getEnv("CLICKHOUSE_CA_FILE", ""),

            },
            Security: SecurityConfig{
                JWTSecret:    getEnv("JWT_SECRET", "default-insecure-secret-change-in-production"),
                APIKey:       getEnv("API_KEY", ""),
                CORSOrigins:  getEnvAsSlice("CORS_ORIGINS", []string{"*"}, ","),
                RateLimitRPS: getEnvAsInt("RATE_LIMIT_RPS", 1000),
            },
            Logging: LoggingConfig{
                Level:  getEnv("LOG_LEVEL", "info"),
                Format: getEnv("LOG_FORMAT", "json"),
            },
        }

        // Validate critical production config
        if environment == "production" {
            validateProductionConfig(cfg)
        }

        util.Info("configuration loaded",
            zap.String("environment", cfg.Environment),
            zap.Bool("tls_enabled", cfg.Server.EnableTLS),
        )
    })

    return cfg
}

func validateProductionConfig(cfg *Config) {
    // Validate secrets are set in production
    if cfg.Security.JWTSecret == "default-insecure-secret-change-in-production" {
        util.Warn("JWT_SECRET is using default value - this is insecure for production")
    }

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

// Get returns the configuration (must call LoadConfig first)
func Get() *Config {
    if cfg == nil {
        panic("config not loaded - call LoadConfig() first")
    }
    return cfg
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