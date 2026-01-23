// util/request_tracker.go
package util

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

type RequestBodyTracker struct {
	io.ReadCloser
	body       []byte
	parsedBody map[string]interface{}
}

func NewRequestBodyTracker(r *http.Request) *RequestBodyTracker {
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	return &RequestBodyTracker{
		ReadCloser: io.NopCloser(bytes.NewBuffer(body)),
		body:       body,
	}
}

func (t *RequestBodyTracker) FieldExists(fieldName string) bool {
	if t.parsedBody == nil {
		json.Unmarshal(t.body, &t.parsedBody)
	}
	_, exists := t.parsedBody[fieldName]
	return exists
}

// Middleware to wrap request body
func TrackRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tracker := NewRequestBodyTracker(r)
		r.Body = tracker
		next.ServeHTTP(w, r)
	})
}

// StringPtrToString converts a string pointer to string
func StringPtrToString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
