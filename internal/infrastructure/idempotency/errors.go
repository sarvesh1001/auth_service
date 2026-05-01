package idempotency

import "errors"

var ErrKeyNotFound = errors.New("idempotency key not found")
