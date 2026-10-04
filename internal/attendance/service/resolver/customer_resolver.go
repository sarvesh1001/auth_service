package resolver

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type CustomerResolver struct {
	// ── NEW
	tzProvider TimezoneProvider

	logger *zap.Logger
}

func NewCustomerResolver(
	tzProvider TimezoneProvider,
	logger *zap.Logger,
) *CustomerResolver {
	return &CustomerResolver{
		tzProvider: tzProvider,
		logger:     logger,
	}
}

func (r *CustomerResolver) Resolve(
	ctx context.Context,
	companyID uuid.UUID,
	subjectType string,
	subjectID uuid.UUID,
	date time.Time,
) (*ResolvedSubject, error) {
	if subjectType != SubjectTypeCustomer {
		return nil, fmt.Errorf("customer resolver called with subject_type=%s", subjectType)
	}

	// ── NEW: use company tz for customers (they're not bound to a
	//    specific position or work center; the company default is the
	//    right resolution).
	tz, tzErr := r.tzProvider.ResolveTimezone(ctx, companyID, nil, nil, nil)
	if tzErr != nil || tz == "" {
		r.logger.Warn("customer tz resolution failed, defaulting to UTC",
			zap.String("customer_id", subjectID.String()),
			zap.Error(tzErr),
		)
		tz = "UTC"
	}

	return &ResolvedSubject{
		IsActive:       true,
		Timezone:       tz,
		ScheduleStatus: "not_schedulable",
	}, nil
}
