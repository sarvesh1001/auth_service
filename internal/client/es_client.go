package client

import (
    "bytes"
    "context"
    "crypto/tls"
    "encoding/json"
    "fmt"
    "io"
    "net/http"

    "github.com/elastic/go-elasticsearch/v8"
    "github.com/elastic/go-elasticsearch/v8/esapi"
    "go.uber.org/zap"

    "auth-service/internal/config"
    "auth-service/internal/util"
)

type ESClient struct {
    Client *elasticsearch.Client
    config *config.ElasticsearchConfig
    logger *zap.Logger
}

func NewElasticsearchClient(cfg *config.Config, logger *zap.Logger) (*ESClient, error) {
    esConfig := cfg.Elasticsearch

    tlsConfig := &tls.Config{
        InsecureSkipVerify: cfg.IsDevelopment(), // Skip verify in dev only
    }

    transport := &http.Transport{
        TLSClientConfig: tlsConfig,
    }

    elasticConfig := elasticsearch.Config{
        Addresses: []string{esConfig.URL},
        Username:  esConfig.Username,
        Password:  esConfig.Password,
        Transport: transport,
    }

    // Create client
    client, err := elasticsearch.NewClient(elasticConfig)
    if err != nil {
        return nil, fmt.Errorf("failed to create Elasticsearch client: %w", err)
    }

    esClient := &ESClient{
        Client: client,
        config: &esConfig,
        logger: util.Get(),
    }

    // Test connection
    if err := esClient.HealthCheck(); err != nil {
        return nil, fmt.Errorf("elasticsearch connection test failed: %w", err)
    }

    util.Info("Elasticsearch client initialized",
        zap.String("url", esConfig.URL),
    )

    return esClient, nil
}

func (e *ESClient) Close() {
    util.Info("Elasticsearch client shutdown")
}

func (e *ESClient) HealthCheck() error {
    res, err := e.Client.Info()
    if err != nil {
        return fmt.Errorf("failed to get cluster info: %w", err)
    }
    defer res.Body.Close()

    if res.IsError() {
        return fmt.Errorf("elasticsearch error: %s", res.String())
    }

    util.Debug("Elasticsearch health check passed")
    return nil
}

func (e *ESClient) Search(index string, query map[string]interface{}) (*esapi.Response, error) {
    var buf bytes.Buffer
    if err := json.NewEncoder(&buf).Encode(query); err != nil {
        return nil, fmt.Errorf("error encoding query: %w", err)
    }

    res, err := e.Client.Search(
        e.Client.Search.WithContext(context.Background()),
        e.Client.Search.WithIndex(index),
        e.Client.Search.WithBody(&buf),
        e.Client.Search.WithTrackTotalHits(true),
        e.Client.Search.WithPretty(),
    )

    if err != nil {
        return nil, fmt.Errorf("error executing search: %w", err)
    }

    return res, nil
}

func (e *ESClient) IndexDocument(index, id string, document interface{}) (*esapi.Response, error) {
    var buf bytes.Buffer
    if err := json.NewEncoder(&buf).Encode(document); err != nil {
        return nil, fmt.Errorf("error encoding document: %w", err)
    }

    res, err := e.Client.Index(
        index,
        &buf,
        e.Client.Index.WithDocumentID(id),
        e.Client.Index.WithRefresh("true"),
    )

    if err != nil {
        return nil, fmt.Errorf("error indexing document: %w", err)
    }

    return res, nil
}

func (e *ESClient) GetDocument(index, id string) (*esapi.Response, error) {
    res, err := e.Client.Get(
        index,
        id,
        e.Client.Get.WithPretty(),
    )

    if err != nil {
        return nil, fmt.Errorf("error getting document: %w", err)
    }

    return res, nil
}

func (e *ESClient) ParseResponse(res *esapi.Response, target interface{}) error {
    defer res.Body.Close()

    if res.IsError() {
        var e map[string]interface{}
        if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
            return fmt.Errorf("error parsing error response: %w", err)
        }
        return fmt.Errorf("elasticsearch error: [%s] %s",
            res.Status(),
            e["error"].(map[string]interface{})["reason"],
        )
    }

    body, err := io.ReadAll(res.Body)
    if err != nil {
        return fmt.Errorf("error reading response body: %w", err)
    }

    if err := json.Unmarshal(body, target); err != nil {
        return fmt.Errorf("error unmarshaling response: %w", err)
    }

    return nil
}
