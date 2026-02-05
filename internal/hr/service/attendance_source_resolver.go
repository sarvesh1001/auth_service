package service

import (
	"context"
	"fmt"
	"sync"

	"go.uber.org/zap"
)

// ==============================================
// INTERFACE
// ==============================================

type AttendanceSourceResolver interface {
	Resolve(ctx context.Context, sourceType string) (*ResolvedSourceRules, error)
	GetAvailableSourceTypes(ctx context.Context) []*ResolvedSourceRules
}

// ==============================================
// RUNTIME RULES (AUTHORITATIVE)
// ==============================================

type ResolvedSourceRules struct {
	SourceType     string
	Category       string
	RequiresDevice bool
	IsSystem       bool
	AllowBackdated bool
	AllowFuture    bool
	TrustLevel     int16
	IsSelfService  bool
}

// ==============================================
// IMPLEMENTATION
// ==============================================

type attendanceSourceResolver struct {
	logger *zap.Logger
	cache  sync.Map
}

// NewAttendanceSourceResolver creates resolver
func NewAttendanceSourceResolver(
	logger *zap.Logger,
) AttendanceSourceResolver {
	return &attendanceSourceResolver{
		logger: logger,
		cache:  sync.Map{},
	}
}

// ==============================================
// CANONICAL SOURCE DEFINITIONS (SAP STYLE)
// ==============================================

var canonicalSourceRules = map[string]*ResolvedSourceRules{

	// ─────────────────────────────
	// HUMAN SOURCES
	// ─────────────────────────────

	"manual": {
		SourceType:     "manual",
		Category:       "human",
		RequiresDevice: false,
		IsSystem:       false,
		AllowBackdated: true,
		AllowFuture:    false,
		TrustLevel:     90,
		IsSelfService:  false,
	},

	"mobile": {
		SourceType:     "mobile",
		Category:       "human",
		RequiresDevice: false,
		IsSystem:       false,
		AllowBackdated: false,
		AllowFuture:    false,
		TrustLevel:     70,
		IsSelfService:  true,
	},

	"web": {
		SourceType:     "web",
		Category:       "human",
		RequiresDevice: false,
		IsSystem:       false,
		AllowBackdated: false,
		AllowFuture:    false,
		TrustLevel:     70,
		IsSelfService:  false,
	},

	// ─────────────────────────────
	// DEVICE SOURCES
	// ─────────────────────────────

	"biometric": {
		SourceType:     "biometric",
		Category:       "device",
		RequiresDevice: true,
		IsSystem:       false,
		AllowBackdated: false,
		AllowFuture:    false,
		TrustLevel:     100,
		IsSelfService:  true,
	},

	"kiosk": {
		SourceType:     "kiosk",
		Category:       "device",
		RequiresDevice: true,
		IsSystem:       false,
		AllowBackdated: false,
		AllowFuture:    false,
		TrustLevel:     95,
		IsSelfService:  true,
	},

	"classroom": {
		SourceType:     "classroom",
		Category:       "device",
		RequiresDevice: true,
		IsSystem:       false,
		AllowBackdated: false,
		AllowFuture:    false,
		TrustLevel:     90,
		IsSelfService:  false,
	},

	// ─────────────────────────────
	// SYSTEM SOURCES
	// ─────────────────────────────

	"auto": {
		SourceType:     "auto",
		Category:       "system",
		RequiresDevice: false,
		IsSystem:       true,
		AllowBackdated: true,
		AllowFuture:    true,
		TrustLevel:     100,
		IsSelfService:  false,
	},
}

// ==============================================
// RESOLVE
// ==============================================

func (r *attendanceSourceResolver) Resolve(
	ctx context.Context,
	sourceType string,
) (*ResolvedSourceRules, error) {

	if sourceType == "" {
		return nil, fmt.Errorf("source_type is required")
	}

	// Cache
	if cached, ok := r.cache.Load(sourceType); ok {
		return cached.(*ResolvedSourceRules), nil
	}

	// Canonical lookup
	rules, ok := canonicalSourceRules[sourceType]
	if !ok {
		r.logger.Warn("Unsupported attendance source type",
			zap.String("source_type", sourceType))
		return nil, fmt.Errorf("unsupported source type: %s", sourceType)
	}

	// Defensive copy
	resolved := *rules
	r.cache.Store(sourceType, &resolved)

	r.logger.Debug("Resolved attendance source rules",
		zap.String("source_type", resolved.SourceType),
		zap.String("category", resolved.Category),
		zap.Bool("requires_device", resolved.RequiresDevice),
		zap.Bool("is_system", resolved.IsSystem),
		zap.Int16("trust_level", resolved.TrustLevel),
	)

	return &resolved, nil
}

// ==============================================
// LIST ALL
// ==============================================

func (r *attendanceSourceResolver) GetAvailableSourceTypes(
	ctx context.Context,
) []*ResolvedSourceRules {

	var result []*ResolvedSourceRules
	for _, v := range canonicalSourceRules {
		c := *v
		result = append(result, &c)
	}
	return result
}
