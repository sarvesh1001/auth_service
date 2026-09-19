package resolver

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

type compositeLocationResolver struct {
	employee SubjectLocationResolver
	student  SubjectLocationResolver
	customer SubjectLocationResolver
}

// NewCompositeLocationResolver dispatches to the appropriate per-subject
// resolver based on subject_type.
func NewCompositeLocationResolver(
	employee SubjectLocationResolver,
	student SubjectLocationResolver,
	customer SubjectLocationResolver,
) SubjectLocationResolver {
	return &compositeLocationResolver{
		employee: employee,
		student:  student,
		customer: customer,
	}
}

func (c *compositeLocationResolver) ResolveLocation(
	ctx context.Context,
	companyID uuid.UUID,
	subjectType string,
	subjectID uuid.UUID,
) (*uuid.UUID, error) {
	switch subjectType {
	case SubjectTypeEmployee:
		return c.employee.ResolveLocation(ctx, companyID, subjectType, subjectID)
	case SubjectTypeStudent:
		return c.student.ResolveLocation(ctx, companyID, subjectType, subjectID)
	case SubjectTypeCustomer:
		return c.customer.ResolveLocation(ctx, companyID, subjectType, subjectID)
	default:
		return nil, fmt.Errorf("unknown subject type: %s", subjectType)
	}
}
