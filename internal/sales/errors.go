package sales

import "errors"

var (
	ErrNotFound          = errors.New("record not found")
	ErrInvalidInput      = errors.New("invalid input")
	ErrDuplicate         = errors.New("duplicate record")
	ErrConflict          = errors.New("conflict")
	ErrInvalidStatus     = errors.New("invalid status")
	ErrInvalidTransition = errors.New("invalid status transition")

	ErrCustomerInactive = errors.New("customer inactive")
	ErrProductInactive  = errors.New("product inactive")

	ErrInvoiceLocked = errors.New("invoice locked")
	ErrInvoicePaid   = errors.New("invoice already paid")

	ErrPaymentOverAlloc = errors.New("payment allocation exceeds payment amount")
	ErrOverRefund       = errors.New("refund exceeds allowed amount")

	ErrCouponExpired    = errors.New("coupon expired")
	ErrCouponInactive   = errors.New("coupon inactive")
	ErrCouponUsageLimit = errors.New("coupon usage limit exceeded")

	ErrPromotionInactive = errors.New("promotion inactive")

	ErrInvalidQuantity = errors.New("invalid quantity")
	ErrInvalidAmount   = errors.New("invalid amount")
)
