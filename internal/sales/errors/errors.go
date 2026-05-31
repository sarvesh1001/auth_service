package errors

import "errors"

var (
	// General errors
	ErrNotFound         = errors.New("sales: record not found")
	ErrInvalidInput     = errors.New("sales: invalid input")
	ErrDuplicate        = errors.New("sales: duplicate record")
	ErrConflict         = errors.New("sales: conflict")
	ErrPermissionDenied = errors.New("sales: permission denied")
	ErrUnauthorized     = errors.New("sales: unauthorized") // <-- ADD THIS

	// Status transitions
	ErrInvalidStatus     = errors.New("sales: invalid status")
	ErrInvalidTransition = errors.New("sales: invalid status transition")

	// Customer / Product
	ErrCustomerInactive = errors.New("sales: customer inactive")
	ErrProductInactive  = errors.New("sales: product inactive")

	// Invoice
	ErrInvoiceLocked = errors.New("sales: invoice locked")
	ErrInvoicePaid   = errors.New("sales: invoice already paid")

	// Payments
	ErrPaymentOverAlloc = errors.New("sales: payment allocation exceeds payment amount")
	ErrOverRefund       = errors.New("sales: refund exceeds allowed amount")

	// Coupons
	ErrCouponExpired    = errors.New("sales: coupon expired")
	ErrCouponInactive   = errors.New("sales: coupon inactive")
	ErrCouponUsageLimit = errors.New("sales: coupon usage limit exceeded")

	// Promotions
	ErrPromotionInactive = errors.New("sales: promotion inactive")

	// Quantity / Amount
	ErrInvalidQuantity = errors.New("sales: invalid quantity")
	ErrInvalidAmount   = errors.New("sales: invalid amount")
	ErrInvalidState    = errors.New("sales: invalid state transition")

	// Payment Terms
	ErrPaymentTermInactive   = errors.New("sales: payment term is inactive")
	ErrPaymentTermAssigned   = errors.New("sales: payment term is assigned to customers and cannot be deleted")
	ErrInventoryItemNotFound = errors.New("inventory item not found or inactive")
)
