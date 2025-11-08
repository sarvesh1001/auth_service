package util

import (
	"encoding/json" // ✅ add this
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	globalLogger *zap.Logger
	once         sync.Once
)

// Init initializes the global logger based on environment
func Init(environment, level, format string) *zap.Logger {
	once.Do(func() {
		var config zap.Config

		if environment == "production" {
			config = zap.NewProductionConfig()
			config.Level = zap.NewAtomicLevelAt(parseLogLevel(level))
			config.EncoderConfig.TimeKey = "timestamp"
			config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

			// Production optimizations
			config.DisableStacktrace = true
			config.Sampling = &zap.SamplingConfig{
				Initial:    100,
				Thereafter: 100,
			}
		} else {
			config = zap.NewDevelopmentConfig()
			config.Level = zap.NewAtomicLevelAt(parseLogLevel(level))
			config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		}

		// Set format
		if format == "json" {
			config.Encoding = "json"
		} else {
			config.Encoding = "console"
		}

		// Always log to stdout for Docker
		config.OutputPaths = []string{"stdout"}
		config.ErrorOutputPaths = []string{"stderr"}

		var err error
		globalLogger, err = config.Build(
			zap.AddCaller(),
			zap.AddCallerSkip(1),
		)
		if err != nil {
			panic("failed to initialize logger: " + err.Error())
		}

		// Replace global logger
		zap.ReplaceGlobals(globalLogger)
	})

	return globalLogger
}

// Get returns the global logger instance
func Get() *zap.Logger {
	if globalLogger == nil {
		// Fallback to production logger if not initialized
		return Init("production", "info", "json")
	}
	return globalLogger
}

// Sync flushes any buffered log entries
func Sync() {
	if globalLogger != nil {
		_ = globalLogger.Sync()
	}
}

func parseLogLevel(level string) zapcore.Level {
	switch level {
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warn", "warning":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	case "fatal":
		return zapcore.FatalLevel
	case "panic":
		return zapcore.PanicLevel
	default:
		return zapcore.InfoLevel
	}
}

// Convenience methods
func Debug(msg string, fields ...zap.Field) {
	Get().Debug(msg, fields...)
}

func Info(msg string, fields ...zap.Field) {
	Get().Info(msg, fields...)
}

func Warn(msg string, fields ...zap.Field) {
	Get().Warn(msg, fields...)
}

// Error function for logging error messages
func Error(msg string, fields ...zap.Field) {
	Get().Error(msg, fields...)
}

func Fatal(msg string, fields ...zap.Field) {
	Get().Fatal(msg, fields...)
}

// Common field helpers
func String(key, value string) zap.Field {
	return zap.String(key, value)
}

func Bool(key string, value bool) zap.Field {
	return zap.Bool(key, value)
}

func Int(key string, value int) zap.Field {
	return zap.Int(key, value)
}

// ErrorField creates an error field (renamed to avoid conflict)
func ErrorField(err error) zap.Field {
	return zap.Error(err)
}

func Any(key string, value interface{}) zap.Field {
	return zap.Any(key, value)
}

func Duration(key string, value time.Duration) zap.Field {
	return zap.Duration(key, value)
}
func Int64(key string, value int64) zap.Field {
	return zap.Int64(key, value)
}

// Time creates a time.Time field
func Time(key string, value time.Time) zap.Field {
	return zap.Time(key, value)
}

// Strings creates a string slice field
func Strings(key string, value []string) zap.Field {
	return zap.Strings(key, value)
}

// JSONError writes a structured JSON error response to the client and logs it.
func JSONError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := map[string]interface{}{
		"status":  statusCode,
		"error":   http.StatusText(statusCode),
		"message": message,
		"time":    time.Now().Format(time.RFC3339),
	}

	// Write JSON response to client
	if err := json.NewEncoder(w).Encode(response); err != nil {
		Get().Error("failed to write JSON error response",
			zap.Int("status", statusCode),
			zap.String("message", message),
			zap.Error(err),
		)
		return
	}

	// Log error (optional)
	Get().Warn("API error response",
		zap.Int("status", statusCode),
		zap.String("message", message),
	)
}
