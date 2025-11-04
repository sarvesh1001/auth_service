package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/elastic/go-elasticsearch/v8"
)

// LogEvent defines the event schema
type LogEvent struct {
	EventID     string                 `json:"event_id"`
	EventType   string                 `json:"event_type"`
	ServiceName string                 `json:"service_name"`
	Timestamp   time.Time              `json:"timestamp"`
	UserID      string                 `json:"user_id"`
	DeviceID    string                 `json:"device_id"`
	Action      string                 `json:"action"`
	Status      string                 `json:"status"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	DurationMS  int64                  `json:"duration_ms"`
}

func main() {
	topic := flag.String("topic", "device-events", "Kafka topic name")
	batchSize := flag.Int("batch-size", 500, "Batch size for ClickHouse insert")
	duration := flag.Duration("duration", 10*time.Minute, "How long to consume before shutting down")
	flag.Parse()

	// Detect Kafka brokers
	brokersEnv := os.Getenv("KAFKA_BROKERS")
	if brokersEnv == "" {
		brokersEnv = "kafka:9092"
	}
	brokers := strings.Split(brokersEnv, ",")
	fmt.Println("⚙️ Using Kafka brokers:", brokers)

	// Initialize ClickHouse client - FIXED CONNECTION
	clickhouseURL := os.Getenv("CLICKHOUSE_URL")
	if clickhouseURL == "" {
		clickhouseURL = "clickhouse:9000"
	}
	
	clickhouseUser := os.Getenv("CLICKHOUSE_USER")
	if clickhouseUser == "" {
		clickhouseUser = "auth_svc_user"
	}
	
	clickhousePassword := os.Getenv("CLICKHOUSE_PASSWORD") 
	if clickhousePassword == "" {
		clickhousePassword = "Vu8eeS4ahtha3Aithae1ie2IeMae4ee1oo1o"
	}
	
	clickhouseDB := os.Getenv("CLICKHOUSE_DATABASE")
	if clickhouseDB == "" {
		clickhouseDB = "auth_analytics"
	}

	fmt.Printf("🧱 Connecting to ClickHouse: %s@%s/%s\n", clickhouseUser, clickhouseURL, clickhouseDB)

	// Use the correct connection format
	chConn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{clickhouseURL},
		Auth: clickhouse.Auth{
			Database: clickhouseDB,
			Username: clickhouseUser,
			Password: clickhousePassword,
		},
		DialTimeout: 30 * time.Second,
	})
	if err != nil {
		log.Fatalf("❌ ClickHouse connect error: %v", err)
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := chConn.Ping(ctx); err != nil {
		log.Fatalf("❌ ClickHouse ping failed: %v", err)
	}
	fmt.Println("✅ ClickHouse connected")

	// Rest of your existing code...
	// Initialize Elasticsearch client
	esURL := os.Getenv("ES_URL")
	if esURL == "" {
		esURL = "http://elasticsearch:9200"
	}
	esClient, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{esURL},
	})
	if err != nil {
		log.Fatalf("❌ Elasticsearch connect error: %v", err)
	}
	fmt.Println("🔍 Connected to Elasticsearch:", esURL)

	// Initialize Kafka reader
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  brokers,
		GroupID:  "clickhouse-es-consumer",
		Topic:    *topic,
		MaxBytes: 10e6, // 10MB
	})
	defer reader.Close()

	// Context with duration timeout
	ctx, cancel = context.WithTimeout(context.Background(), *duration)
	defer cancel()

	// Handle SIGINT/SIGTERM for graceful shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\n🛑 Received shutdown signal...")
		cancel()
	}()

	// Consume messages
	var buffer []LogEvent
	lastFlush := time.Now()

	for {
		msg, err := reader.FetchMessage(ctx)
		if err != nil {
			break
		}

		var event LogEvent
		if err := json.Unmarshal(msg.Value, &event); err != nil {
			log.Println("⚠️ Invalid message:", err)
			continue
		}

		buffer = append(buffer, event)

		// Flush to ClickHouse/ES on batch or timeout
		if len(buffer) >= *batchSize || time.Since(lastFlush) > 5*time.Second {
			if err := writeToClickHouse(ctx, chConn, buffer); err != nil {
				log.Println("❌ ClickHouse insert failed:", err)
			}
			if err := writeToElasticsearch(esClient, buffer); err != nil {
				log.Println("❌ Elasticsearch insert failed:", err)
			}
			buffer = buffer[:0]
			lastFlush = time.Now()
		}

		_ = reader.CommitMessages(ctx, msg)
	}

	fmt.Println("✅ Consumer stopped after duration or signal.")
}

func writeToClickHouse(ctx context.Context, conn clickhouse.Conn, events []LogEvent) error {
	if len(events) == 0 {
		return nil
	}
	batch, err := conn.PrepareBatch(ctx, "INSERT INTO auth_analytics.device_events (event_type, user_id, device_id, action, timestamp)")
	if err != nil {
		return err
	}
	for _, e := range events {
		if err := batch.Append(e.EventType, e.UserID, e.DeviceID, e.Action, e.Timestamp); err != nil {
			return err
		}
	}
	return batch.Send()
}

func writeToElasticsearch(es *elasticsearch.Client, events []LogEvent) error {
	if len(events) == 0 {
		return nil
	}
	for _, e := range events {
		body, _ := json.Marshal(e)
		_, err := es.Index("device-events", strings.NewReader(string(body)))
		if err != nil {
			log.Println("⚠️ ES index error:", err)
		}
	}
	return nil
}