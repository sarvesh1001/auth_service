package resolver

import (
	"context"

	"github.com/google/uuid"
)

// SubjectLocationResolver resolves the org-unit location of a subject.
//
// Contract:
//   - employee: reads company_employees.employment_location_id
//   - student:  reads academics.students.location_id
//   - customer: always returns (nil, nil) — customers are company-scoped
//
// Return values:
//   - (id, nil)  → subject belongs to this location
//   - (nil, nil) → subject has no location (customers, or unconfigured)
//   - (nil, err) → lookup failed
//
// This is a WRITE-side concern. It's called when attendance is recorded to
// stamp the row with the subject's location. Read-side filtering uses the
// denormalized column on the attendance row, not this resolver.
//
// Distinct from SubjectResolver (in resolver.go) — that one resolves schedule,
// leave, policy, and subscription state. This one answers one question:
// "which location does this subject belong to?"
type SubjectLocationResolver interface {
	ResolveLocation(
		ctx context.Context,
		companyID uuid.UUID,
		subjectType string,
		subjectID uuid.UUID,
	) (*uuid.UUID, error)
}
