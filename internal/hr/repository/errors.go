// auth-service/internal/hr/repository/errors.go
package repository

import "errors"

var (
	ErrDeviceAlreadyExists     = errors.New("device already exists")
	ErrDeviceAlreadyActive     = errors.New("device is already active")
	ErrDeviceAlreadyInactive   = errors.New("device is already inactive")
	ErrDeviceAlreadyTrusted    = errors.New("device is already trusted")
	ErrDeviceAlreadyNotTrusted = errors.New("device is already not trusted")
	ErrValidationFailed        = errors.New("validation failed")
)
