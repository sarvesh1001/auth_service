// Add these to internal/service/errors.go
package service

import( "errors")
// Session errors
var (
    ErrSessionNotFound    = errors.New("session not found")
    ErrSessionExpired     = errors.New("session expired")
    ErrInvalidToken       = errors.New("invalid session token")
)
