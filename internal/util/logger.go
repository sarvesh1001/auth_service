package util

import (
	"encoding/json" // ✅ add this
	"errors"
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

var (
	ErrUnauthorized = errors.New("unauthorized")
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

// JSONResponse writes a successful JSON response
func JSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := map[string]interface{}{
		"status": statusCode,
		"data":   data,
		"time":   time.Now().Format(time.RFC3339),
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		Get().Error("failed to write JSON response",
			zap.Int("status", statusCode),
			zap.Any("data", data),
			zap.Error(err),
		)
	}
}

func Uint64(key string, val uint64) zap.Field {
	return zap.Uint64(key, val)
}

// ToJSON marshals any value into pretty-printed JSON bytes
func ToJSON(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

// IsDuplicateError checks whether an error is caused by a duplicate/unique constraint violation
func IsDuplicateError(err error) bool {
	if err == nil {
		return false
	}

	// Common PostgreSQL duplicate indicators
	errMsg := err.Error()

	switch {
	case
		// lib/pq
		contains(errMsg, "duplicate key value violates unique constraint"),
		// pgx
		contains(errMsg, "SQLSTATE 23505"),
		// generic
		contains(errMsg, "unique constraint"),
		contains(errMsg, "already exists"):
		return true
	default:
		return false
	}
}

// small helper to avoid strings import pollution
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (stringIndex(s, substr) >= 0)
}

// inline implementation to avoid extra imports
func stringIndex(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// StringSliceToJSON converts a string slice to JSON string (safe for logs & audits)
func StringSliceToJSON(values []string) string {
	if len(values) == 0 {
		return "[]"
	}

	b, err := json.Marshal(values)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func Float64(key string, value float64) zap.Field {
	return zap.Float64(key, value)
}

// RespondWithJSON writes a JSON response using the global logger
func RespondWithJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(payload); err != nil {
		Get().Error(
			"failed to encode JSON response",
			zap.Int("status", status),
			zap.Error(err),
		)
	}
}

// RespondWithError writes a standard error JSON response
func RespondWithError(w http.ResponseWriter, status int, message string) {
	RespondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

// SafeString safely dereferences a *string for logging or JSON
// Returns empty string if nil
func SafeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
func BoolPtr(v bool) *bool {
	return &v
}
func JSONEncode(w http.ResponseWriter, payload interface{}) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(payload)
}

// MustMarshalJSON marshals v to JSON and panics on error.
// Useful for audit logging where failure is unexpected.
func MustMarshalJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic("failed to marshal JSON: " + err.Error())
	}
	return b
}

// UniqueStrings removes duplicate strings from a slice while preserving order.
func UniqueStrings(input []string) []string {
	if len(input) == 0 {
		return input
	}

	seen := make(map[string]struct{}, len(input))
	result := make([]string, 0, len(input))

	for _, v := range input {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		result = append(result, v)
	}

	return result
}
func Contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}
