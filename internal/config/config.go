package config

type Config struct {
    Env        string
    HTTPSCert  string
    HTTPSKey   string
    RedisURL   string
    ScyllaURL  string
    KafkaBrokers []string
    ElasticURL string
    ClickHouseURL string
    JwtPrivateKeyPath string
    JwtPublicKeyPath  string
}
