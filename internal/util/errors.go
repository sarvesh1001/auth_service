// If you don't have a NewError function, you can create one in util/errors.go:
package util

import "fmt"

// NewError creates a new formatted error
func NewError(format string, args ...interface{}) error {
    return fmt.Errorf(format, args...)
}