package resolver

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type CompositeResolver struct {
	resolvers map[string]SubjectResolver
}

func NewCompositeResolver(resolvers map[string]SubjectResolver) *CompositeResolver {
	return &CompositeResolver{resolvers: resolvers}
}

func (c *CompositeResolver) Resolve(ctx context.Context, companyID uuid.UUID, subjectType string, subjectID uuid.UUID, date time.Time) (*ResolvedSubject, error) {
	resolver, ok := c.resolvers[subjectType]
	if !ok {
		return nil, fmt.Errorf("no resolver for subject_type=%s", subjectType)
	}
	return resolver.Resolve(ctx, companyID, subjectType, subjectID, date)
}
