package main

import (
	"chatbot-service/internal/executor"
	"chatbot-service/internal/handler"
	"chatbot-service/internal/llm"
	"chatbot-service/internal/middleware"
	"chatbot-service/internal/service"
	"chatbot-service/internal/tools" // ✅ REQUIRED
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"go.uber.org/zap"
)

func main() {

	// ----------------------------------------------------
	// Load .env (only if ENVIRONMENT not already set)
	// ----------------------------------------------------
	if os.Getenv("ENVIRONMENT") == "" {
		if err := godotenv.Load(); err != nil {
			log.Println("No .env file found, assuming production environment")
		}
	}

	// ----------------------------------------------------
	// Logger
	// ----------------------------------------------------
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	// ----------------------------------------------------
	// Load JWT Secret
	// ----------------------------------------------------
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		logger.Fatal("JWT_SECRET environment variable not set")
	}

	// ----------------------------------------------------
	// Load Server Port (default 9090)
	// ----------------------------------------------------
	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "9090"
	}

	// ----------------------------------------------------
	// HR Base URL (default localhost:8080)
	// ----------------------------------------------------
	hrBaseURL := os.Getenv("HR_BASE_URL")
	if hrBaseURL == "" {
		hrBaseURL = "http://localhost:8080"
	}

	// ----------------------------------------------------
	// LLM (mock for now)
	// ----------------------------------------------------
	llmClient := llm.NewMockClient()

	// ----------------------------------------------------
	// HR Client
	// ----------------------------------------------------
	hrClient := tools.NewHRClient(hrBaseURL)

	// ----------------------------------------------------
	// Tools
	// ----------------------------------------------------
	payrollTool := tools.NewPayrollTool(hrClient)

	toolExecutor := executor.NewToolExecutor([]executor.Tool{
		payrollTool,
	})

	// ----------------------------------------------------
	// Service
	// ----------------------------------------------------
	chatService := service.NewChatService(
		llmClient,
		toolExecutor,
		logger,
	)

	// ----------------------------------------------------
	// Handler
	// ----------------------------------------------------
	chatHandler := handler.NewChatHandler(chatService, logger)

	// ----------------------------------------------------
	// Router
	// ----------------------------------------------------
	mux := http.NewServeMux()
	mux.HandleFunc("/chat", chatHandler.HandleChat)

	// ----------------------------------------------------
	// Middleware Chain
	// RateLimit → JWT → Handler
	// ----------------------------------------------------
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
