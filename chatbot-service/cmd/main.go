package main

import (
	"chatbot-service/internal/executor"
	"chatbot-service/internal/handler"
	"chatbot-service/internal/llm"
	"chatbot-service/internal/middleware"
	"chatbot-service/internal/repository/postgres"
	"chatbot-service/internal/service"
	"chatbot-service/internal/tools"
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

func main() {
	if os.Getenv("ENVIRONMENT") == "" {
		if err := godotenv.Load(); err != nil {
			log.Println("No .env file found, assuming production environment")
		}
	}

	logger, _ := zap.NewProduction()
	defer logger.Sync()

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		logger.Fatal("JWT_SECRET environment variable not set")
	}

	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "9090"
	}

	hrBaseURL := os.Getenv("HR_BASE_URL")
	if hrBaseURL == "" {
		hrBaseURL = "http://localhost:8080"
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		logger.Fatal("DATABASE_URL environment variable not set")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		logger.Fatal("Failed to connect to database", zap.Error(err))
	}
	defer db.Close()

	if err = db.Ping(); err != nil {
		logger.Fatal("Database unreachable", zap.Error(err))
	}
	logger.Info("Connected to database")

	llmClient := llm.NewMockClient()
	hrClient := tools.NewHRClient(hrBaseURL)
	payrollTool := tools.NewPayrollTool(hrClient)

	toolExecutor := executor.NewToolExecutor([]executor.Tool{
		payrollTool,
	})

	conversationRepo := postgres.NewConversationRepository(db)

	chatService := service.NewChatService(
		llmClient,
		toolExecutor,
		conversationRepo,
		logger,
	)

	chatHandler := handler.NewChatHandler(chatService, logger)

	mux := http.NewServeMux()
	mux.HandleFunc("/chat", chatHandler.HandleChat)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	wrapped := middleware.JWTMiddleware(middleware.JWTConfig{
		Secret: jwtSecret,
		Logger: logger,
	})(
		middleware.RateLimitMiddleware(mux),
	)

	logger.Info("Chatbot service running",
		zap.String("port", port),
		zap.String("hr_base_url", hrBaseURL),
	)

	log.Fatal(http.ListenAndServe(":"+port, wrapped))
}
