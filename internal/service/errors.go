// Add these to internal/service/errors.go
package service

import (
	"errors"
	"fmt"
)

// Session errors
var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
	ErrInvalidToken    = errors.New("invalid session token")
)

// OTPError represents structured OTP errors
type OTPError struct {
	Code    string
	Message string
	Err     error
}

func (e *OTPError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s", e.Code, e.Err.Error())
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *OTPError) Unwrap() error {
	return e.Err
}

// NewOTPError creates a new OTP error
func NewOTPError(code, message string, err error) *OTPError {
	return &OTPError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}
