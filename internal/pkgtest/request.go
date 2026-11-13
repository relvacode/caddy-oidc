package pkgtest

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/caddyserver/caddy/v2"
)

// NewRequest returns a new http.Request with a context containing an empty replacer.
func NewRequest(method, target string, body io.Reader) *http.Request {
	//nolint:noctx
	r := httptest.NewRequest(method, target, body)
	r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewEmptyReplacer()))

	return r
}
