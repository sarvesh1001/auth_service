package resolver

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// CustomerResolver resolves customers (simple)
type CustomerResolver struct {
	// Could fetch company timezone from company repo
	logger *zap.Logger
}

func NewCustomerResolver(logger *zap.Logger) *CustomerResolver {
	return &CustomerResolver{logger: logger}
}

func (r *CustomerResolver) Resolve(ctx context.Context, companyID uuid.UUID, subjectType string, subjectID uuid.UUID, date time.Time) (*ResolvedSubject, error) {
	if subjectType != SubjectTypeCustomer {
		return nil, fmt.Errorf("customer resolver called with subject_type=%s", subjectType)
	}

	// For customers, we assume they are always active and have no schedule.
	// They can still punch attendance (e.g., visitor check-in/out) but we don't enforce work hours.
	return &ResolvedSubject{
		IsActive:       true,
		Timezone:       "UTC", // could be from company
		ScheduleStatus: "not_schedulable",
		// No schedule, no policies
	}, nil
}
