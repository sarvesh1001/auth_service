package repository

import "errors"

var ErrValidationFailed = errors.New("validation failed")
var ErrBatchNotFound = errors.New("batch not found")
var ErrDeviceNotFound = errors.New("device not found")
