package resolver

import (
	"context"

	"github.com/google/uuid"
)

type customerLocationResolver struct{}

// NewCustomerLocationResolver always returns (nil, nil).
//
// Customers are company-scoped, not location-scoped. The Apollo Ynr customer
// who orders medicine can buy from any Apollo branch. Their location is a
// *visit* location, derived from the device geofence or the admin's
// X-Location-ID — never from the customer record itself.
func NewCustomerLocationResolver() SubjectLocationResolver {
	return &customerLocationResolver{}
}

func (r *customerLocationResolver) ResolveLocation(
	_ context.Context,
	_ uuid.UUID,
	_ string,
	_ uuid.UUID,
) (*uuid.UUID, error) {
	return nil, nil
}
