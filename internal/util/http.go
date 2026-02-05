package util

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// PathParam extracts a URL path parameter from chi router
func PathParam(r *http.Request, name string) string {
	return chi.URLParam(r, name)
}

// StringPtr returns a pointer to the given string
func StringPtr(s string) *string {
	return &s
}
