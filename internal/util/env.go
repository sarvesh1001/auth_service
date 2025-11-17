// File: internal/util/env.go
// Environment variable utilities

package util

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// GetEnv gets environment variable with default
func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetEnvAsInt gets environment variable as int with default
func GetEnvAsInt(key string, defaultValue int) int {
	strValue := GetEnv(key, "")
	if value, err := strconv.Atoi(strValue); err == nil {
		return value
	}
	return defaultValue
}

// GetEnvAsBool gets environment variable as bool with default
func GetEnvAsBool(key string, defaultValue bool) bool {
	strValue := GetEnv(key, "")
	if value, err := strconv.ParseBool(strValue); err == nil {
		return value
	}
	return defaultValue
}

// GetEnvAsDuration gets environment variable as duration with default
func GetEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	strValue := GetEnv(key, "")
	if value, err := time.ParseDuration(strValue); err == nil {
		return value
	}
	return defaultValue
}

// GetEnvAsSlice gets environment variable as slice with separator
func GetEnvAsSlice(key string, defaultValue []string, separator string) []string {
	strValue := GetEnv(key, "")
	if strValue == "" {
		return defaultValue
	}
	return strings.Split(strValue, separator)
}
