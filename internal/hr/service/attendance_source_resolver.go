// attendance_source_resolver.go
package service

import (
	"auth-service/internal/hr/models/attendance"
	"auth-service/internal/hr/repository"
	"context"
	"fmt"
	"sync"

	"go.uber.org/zap"
)

// ==============================================
// INTERFACE
// ==============================================

// AttendanceSourceResolver converts a source_type into runtime rules used by ingest
// Source types are GLOBAL - same for all companies
type AttendanceSourceResolver interface {
	Resolve(ctx context.Context, sourceType string) (*ResolvedSourceRules, error)
}

// ==============================================
// RUNTIME RULES STRUCT (NOT a DB model)
// ==============================================

// ResolvedSourceRules contains runtime validation rules for a specific source type
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
	repo   repository.AttendanceRepository
	logger *zap.Logger
	cache  sync.Map // sourceType -> *ResolvedSourceRules
}

// NewAttendanceSourceResolver creates a new source resolver
func NewAttendanceSourceResolver(
	repo repository.AttendanceRepository,
	logger *zap.Logger,
) AttendanceSourceResolver {
	return &attendanceSourceResolver{
		repo:   repo,
		logger: logger,
		cache:  sync.Map{},
	}
}

// Resolve converts a source_type into runtime rules (company-agnostic)
func (r *attendanceSourceResolver) Resolve(
	ctx context.Context,
	sourceType string,
) (*ResolvedSourceRules, error) {
	// 1. Validate input
	if sourceType == "" {
		return nil, fmt.Errorf("sourceType is required")
	}

	// 2. Check cache first
	if cached, found := r.cache.Load(sourceType); found {
		rules := cached.(*ResolvedSourceRules)
		r.logger.Debug("Cache hit for source type",
			zap.String("source_type", sourceType))
		return rules, nil
	}

	// 3. Get all source types from repository
	sourceTypes, err := r.repo.GetAttendanceSourceTypes(ctx)
	if err != nil {
		r.logger.Error("Failed to get attendance source types",
			zap.String("source_type", sourceType),
			zap.Error(err))
		return nil, fmt.Errorf("failed to load source types: %w", err)
	}

	// 4. Find the specific source type
	var resolvedType *attendance.AttendanceSourceType
	for _, st := range sourceTypes {
		if st.SourceType == sourceType {
			resolvedType = st
			break
		}
	}

	// 5. Return error if not found
	if resolvedType == nil {
		r.logger.Warn("Source type not found",
			zap.String("source_type", sourceType))
		return nil, fmt.Errorf("source type '%s' not found or not supported", sourceType)
	}

	// 6. Create resolved rules
	rules := &ResolvedSourceRules{
		SourceType:     resolvedType.SourceType,
		Category:       resolvedType.Category,
		RequiresDevice: resolvedType.RequiresDevice,
		IsSystem:       resolvedType.IsSystem,
		AllowBackdated: resolvedType.AllowBackdated,
		AllowFuture:    resolvedType.AllowFuture,
		TrustLevel:     resolvedType.TrustLevel,
		IsSelfService:  resolvedType.IsSelfService,
	}

	// 7. Cache the result
	r.cache.Store(sourceType, rules)

	r.logger.Debug("Resolved source type rules",
		zap.String("source_type", sourceType),
		zap.String("category", rules.Category),
		zap.Bool("requires_device", rules.RequiresDevice),
		zap.Bool("is_system", rules.IsSystem),
		zap.Bool("allow_backdated", rules.AllowBackdated),
		zap.Bool("allow_future", rules.AllowFuture),
		zap.Int16("trust_level", rules.TrustLevel),
		zap.Bool("is_self_service", rules.IsSelfService))

	return rules, nil
}

// GetAvailableSourceTypes returns all valid source types
func (r *attendanceSourceResolver) GetAvailableSourceTypes(
	ctx context.Context,
) ([]*ResolvedSourceRules, error) {
	// Get all source types from repository
	sourceTypes, err := r.repo.GetAttendanceSourceTypes(ctx)
	if err != nil {
		r.logger.Error("Failed to get attendance source types",
			zap.Error(err))
		return nil, fmt.Errorf("failed to load source types: %w", err)
	}

	// Convert to resolved rules
	var rules []*ResolvedSourceRules
	for _, st := range sourceTypes {
		rules = append(rules, &ResolvedSourceRules{
			SourceType:     st.SourceType,
			Category:       st.Category,
			RequiresDevice: st.RequiresDevice,
			IsSystem:       st.IsSystem,
			AllowBackdated: st.AllowBackdated,
			AllowFuture:    st.AllowFuture,
			TrustLevel:     st.TrustLevel,
			IsSelfService:  st.IsSelfService,
		})
	}

	return rules, nil
}

// ValidateSourceType checks if a source type is valid
func (r *attendanceSourceResolver) ValidateSourceType(
	ctx context.Context,
	sourceType string,
) (bool, error) {
	_, err := r.Resolve(ctx, sourceType)
	if err != nil {
		return false, err
	}
	return true, nil
}
