package locationctx

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func ctxWith(mode string, id uuid.UUID, level string) context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, CtxMode, mode)
	if id != uuid.Nil {
		ctx = context.WithValue(ctx, CtxLocationID, id)
	}
	if level != "" {
		ctx = context.WithValue(ctx, CtxAccessLevel, level)
	}
	return ctx
}

func TestFromContext_Location(t *testing.T) {
	id := uuid.New()
	c, err := FromContext(ctxWith("LOCATION", id, "MANAGE"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Mode != ScopeLocation {
		t.Fatalf("want LOCATION, got %s", c.Mode)
	}
	if c.LocationID == nil || *c.LocationID != id {
		t.Fatalf("location id mismatch")
	}
	if c.AccessLevel != AccessManage {
		t.Fatalf("want MANAGE, got %s", c.AccessLevel)
	}
}

func TestFromContext_All(t *testing.T) {
	c, err := FromContext(ctxWith("ALL", uuid.Nil, "MANAGE"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Mode != ScopeAll {
		t.Fatalf("want ALL, got %s", c.Mode)
	}
	if c.LocationID != nil {
		t.Fatalf("want nil location for ALL, got %v", c.LocationID)
	}
}

func TestFromContext_Missing(t *testing.T) {
	_, err := FromContext(context.Background())
	if err != ErrLocationContextMissing {
		t.Fatalf("want ErrLocationContextMissing, got %v", err)
	}
}

func TestFromContext_Malformed(t *testing.T) {
	// Mode says LOCATION, but no UUID was set.
	if _, err := FromContext(ctxWith("LOCATION", uuid.Nil, "MANAGE")); err != ErrLocationContextMissing {
		t.Fatalf("want ErrLocationContextMissing, got %v", err)
	}
	// Unknown mode.
	if _, err := FromContext(ctxWith("BOGUS", uuid.New(), "MANAGE")); err != ErrLocationContextMissing {
		t.Fatalf("want ErrLocationContextMissing for unknown mode, got %v", err)
	}
}

func TestFilter_Location(t *testing.T) {
	id := uuid.New()
	got := Filter(ctxWith("LOCATION", id, "VIEW"))
	if got == nil || *got != id {
		t.Fatalf("want %v, got %v", id, got)
	}
}

func TestFilter_All(t *testing.T) {
	got := Filter(ctxWith("ALL", uuid.Nil, "MANAGE"))
	if got != nil {
		t.Fatalf("want nil for ALL, got %v", got)
	}
}

func TestFilter_Missing_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on missing context")
		}
	}()
	Filter(context.Background())
}

func TestCanWrite(t *testing.T) {
	id := uuid.New()
	cases := []struct {
		name string
		ctx  context.Context
		want bool
	}{
		{"location manage", ctxWith("LOCATION", id, "MANAGE"), true},
		{"location view", ctxWith("LOCATION", id, "VIEW"), false},
		{"all manage", ctxWith("ALL", uuid.Nil, "MANAGE"), false},
		{"missing", context.Background(), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CanWrite(tc.ctx); got != tc.want {
				t.Fatalf("want %v, got %v", tc.want, got)
			}
		})
	}
}
