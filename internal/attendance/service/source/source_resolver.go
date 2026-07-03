package source

import (
	"context"
	"fmt"
	"sync"

	"go.uber.org/zap"
)

// ResolvedSourceRules holds the runtime rules for a source type
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

// SourceResolver resolves source rules at runtime (cached)
type SourceResolver interface {
	Resolve(ctx context.Context, sourceType string) (*ResolvedSourceRules, error)
	GetAvailableSourceTypes(ctx context.Context) []*ResolvedSourceRules
}

// canonicalSourceRules defines the authoritative set of source types and their rules.
// This is the single source of truth – extend here when adding new source types.
var canonicalSourceRules = map[string]*ResolvedSourceRules{
	// Human sources
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

	// Device sources
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

	// System sources
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
	"system": {
		SourceType:     "system",
		Category:       "system",
		RequiresDevice: false,
		IsSystem:       true,
		AllowBackdated: true,
		AllowFuture:    true,
		TrustLevel:     100,
		IsSelfService:  false,
	},
	"correction": {
		SourceType:     "correction",
		Category:       "system",
		RequiresDevice: false,
		IsSystem:       true,
		AllowBackdated: true,
		AllowFuture:    false,
		TrustLevel:     100,
		IsSelfService:  false,
	},
}

type sourceResolver struct {
	logger *zap.Logger
	cache  sync.Map
}

// NewSourceResolver creates a resolver with the canonical rule set
func NewSourceResolver(logger *zap.Logger) SourceResolver {
	return &sourceResolver{
		logger: logger,
	}
}

// Resolve returns the rules for the given source type, caching the result
func (r *sourceResolver) Resolve(ctx context.Context, sourceType string) (*ResolvedSourceRules, error) {
	if sourceType == "" {
		return nil, fmt.Errorf("source_type is required")
	}

	// Check cache
	if cached, ok := r.cache.Load(sourceType); ok {
		return cached.(*ResolvedSourceRules), nil
	}

	// Look up canonical rules
	rules, ok := canonicalSourceRules[sourceType]
	if !ok {
		r.logger.Warn("Unsupported attendance source type", zap.String("source_type", sourceType))
		return nil, fmt.Errorf("unsupported source type: %s", sourceType)
	}

	// Defensive copy to avoid mutation
	resolved := *rules
	r.cache.Store(sourceType, &resolved)

	r.logger.Debug("Resolved source rules",
		zap.String("source_type", resolved.SourceType),
		zap.String("category", resolved.Category),
		zap.Bool("requires_device", resolved.RequiresDevice),
		zap.Bool("is_system", resolved.IsSystem),
		zap.Int16("trust_level", resolved.TrustLevel),
	)

	return &resolved, nil
}

// GetAvailableSourceTypes returns a list of all known source types (copies)
func (r *sourceResolver) GetAvailableSourceTypes(ctx context.Context) []*ResolvedSourceRules {
	result := make([]*ResolvedSourceRules, 0, len(canonicalSourceRules))
	for _, v := range canonicalSourceRules {
		c := *v // copy
		result = append(result, &c)
	}
	return result
}
