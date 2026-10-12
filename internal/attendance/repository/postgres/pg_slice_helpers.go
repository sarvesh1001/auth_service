package postgres

// int64SliceToInt converts a pq-decoded INTEGER[] to the []int the
// attendance models use.
//
// lib/pq cannot scan INTEGER[] directly into []int — its reflective fallback
// tries to instantiate each element as a sql.Scanner, and *int does not
// implement that interface. Decoding as []int64 uses pq's built-in
// Int64Array path, then narrows here.
//
// Empty input yields a non-nil empty slice so JSON marshalling produces
// [] rather than null.
func int64SliceToInt(src []int64) []int {
	if len(src) == 0 {
		return []int{}
	}
	out := make([]int, len(src))
	for i, v := range src {
		out[i] = int(v)
	}
	return out
}
