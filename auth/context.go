package auth

import "context"

// ctxKey is an unexported type for context keys in this package.
// Using a package-local type prevents collisions with other packages
// that also use context.WithValue.
type ctxKey int

const (
	ctxKeySub    ctxKey = iota // JWT "sub" claim (user/client identity)
	ctxKeyScopes               // JWT "scope" claim (space-delimited, split into []string)
)

// ContextWithClaims returns a new context enriched with the JWT subject and scopes.
func ContextWithClaims(ctx context.Context, sub string, scopes []string) context.Context {
	ctx = context.WithValue(ctx, ctxKeySub, sub)
	ctx = context.WithValue(ctx, ctxKeyScopes, scopes)
	return ctx
}

// SubFromContext extracts the JWT subject (sub) from a request context.
// Returns an empty string if not present (i.e., OAuth2 is disabled).
func SubFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeySub).(string)
	return v
}

// ScopesFromContext extracts the JWT scopes from a request context.
// Returns nil if not present.
func ScopesFromContext(ctx context.Context) []string {
	v, _ := ctx.Value(ctxKeyScopes).([]string)
	return v
}

// HasScope returns true if the given scope is present in the request context.
func HasScope(ctx context.Context, required string) bool {
	for _, s := range ScopesFromContext(ctx) {
		if s == required {
			return true
		}
	}
	return false
}
