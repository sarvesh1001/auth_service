package util

import (
	"sync"

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

func Error(msg string, fields ...zap.Field) {
	Get().Error(msg, fields...)
}

func Fatal(msg string, fields ...zap.Field) {
	Get().Fatal(msg, fields...)
}