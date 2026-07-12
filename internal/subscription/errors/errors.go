package errors

import "errors"

var (
	// General
	ErrNotFound         = errors.New("subscription: record not found")
	ErrInvalidInput     = errors.New("subscription: invalid input")
	ErrDuplicate        = errors.New("subscription: duplicate record")
	ErrConflict         = errors.New("subscription: conflict")
	ErrPermissionDenied = errors.New("subscription: permission denied")
	ErrUnauthorized     = errors.New("subscription: unauthorized")
	ErrInvalidState     = errors.New("subscription: invalid state")
	ErrVersionMismatch  = errors.New("subscription: version mismatch")
	ErrConcurrentUpdate = errors.New("subscription: concurrent update detected")

	// Subscription
	ErrSubscriptionNotFound     = errors.New("subscription: not found")
	ErrSubscriptionInactive     = errors.New("subscription: is not active")
	ErrSubscriptionCancelled    = errors.New("subscription: already cancelled")
	ErrSubscriptionExpired      = errors.New("subscription: already expired")
	ErrSubscriptionPaused       = errors.New("subscription: is paused")
	ErrSubscriptionNotRenewable = errors.New("subscription: cannot be renewed")
	ErrInvalidStatusTransition  = errors.New("subscription: invalid status transition")
	ErrInvalidStatus            = errors.New("subscription: invalid status")

	// Plan
	ErrPlanNotFound     = errors.New("subscription: plan not found")
	ErrPlanInactive     = errors.New("subscription: plan is inactive")
	ErrPlanNotPublished = errors.New("subscription: plan not published")

	// Trial
	ErrTrialNotFound      = errors.New("subscription: trial not found")
	ErrTrialAlreadyActive = errors.New("subscription: trial already exists")
	ErrTrialExpired       = errors.New("subscription: trial has expired")
	ErrTrialNotActive     = errors.New("subscription: trial is not active")

	// Addon
	ErrAddonNotFound      = errors.New("subscription: addon not found")
	ErrAddonInactive      = errors.New("subscription: addon is inactive")
	ErrAddonAlreadyExists = errors.New("subscription: addon already attached")
	ErrAddonNotAttached   = errors.New("subscription: addon not attached")

	// Coupon – not used directly, but may be referenced in events
	ErrCouponNotFound       = errors.New("subscription: coupon not found")
	ErrCouponInactive       = errors.New("subscription: coupon inactive")
	ErrCouponExpired        = errors.New("subscription: coupon expired")
	ErrCouponUsageLimit     = errors.New("subscription: coupon usage limit exceeded")
	ErrCouponAlreadyApplied = errors.New("subscription: coupon already applied")

	// Pause Policy
	ErrPausePolicyNotFound      = errors.New("subscription: pause policy not found")
	ErrPausePolicyAlreadyExists = errors.New("subscription: pause policy with this name already exists")
	ErrPausePolicyInUse         = errors.New("subscription: pause policy is in use by one or more plans")
	ErrBillingPolicyNotFound    = errors.New("billing policy not found")
	// ErrInvalidCurrency indicates an unsupported currency code.
	ErrInvalidCurrency     = errors.New("invalid currency code")
	ErrPlanHasNoItems      = errors.New("plan has no items; cannot create subscription without at least one item")
	ErrNoSubscriptionItems = errors.New("subscription: no items found")
)
