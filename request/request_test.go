package request

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/relvacode/caddy-oidc/internal/pkgtest"
	"github.com/stretchr/testify/assert"
)

func TestURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		request  func() *http.Request
		expected string
	}{
		{
			name: "basic http",
			request: func() *http.Request {
				r := pkgtest.NewRequest(http.MethodGet, "http://localhost/path?query=1", nil)

				return r
			},
			expected: "http://localhost/path?query=1",
		},
		{
			name: "https via TLS",
			request: func() *http.Request {
				r := pkgtest.NewRequest(http.MethodGet, "http://localhost/", nil)
				r.TLS = &tls.ConnectionState{}

				return r
			},
			expected: "https://localhost/",
		},
		{
			name: "https via X-Forwarded-Proto untrusted",
			request: func() *http.Request {
				r := pkgtest.NewRequest(http.MethodGet, "http://localhost/", nil)
				r.Header.Set("X-Forwarded-Proto", "https")

				return r
			},
			expected: "http://localhost/",
		},
		{
			name: "https via X-Forwarded-Proto",
			request: func() *http.Request {
				r := pkgtest.NewRequest(http.MethodGet, "http://localhost/", nil)
				caddyhttp.SetVar(r.Context(), caddyhttp.TrustedProxyVarKey, true)
				r.Header.Set("X-Forwarded-Proto", "https")

				return r
			},
			expected: "https://localhost/",
		},
		{
			name: "host from X-Forwarded-Host untrusted",
			request: func() *http.Request {
				r := pkgtest.NewRequest(http.MethodGet, "http://localhost/foo", nil)
				r.Header.Set("X-Forwarded-Host", "example.com")

				return r
			},
			expected: "http://localhost/foo",
		},
		{
			name: "host from X-Forwarded-Host",
			request: func() *http.Request {
				r := pkgtest.NewRequest(http.MethodGet, "http://localhost/foo", nil)
				caddyhttp.SetVar(r.Context(), caddyhttp.TrustedProxyVarKey, true)
				r.Header.Set("X-Forwarded-Host", "example.com")

				return r
			},
			expected: "http://example.com/foo",
		},
		{
			name: "complex proxy headers",
			request: func() *http.Request {
				r := pkgtest.NewRequest(http.MethodPost, "http://internal-ip:8080/api", nil)
				caddyhttp.SetVar(r.Context(), caddyhttp.TrustedProxyVarKey, true)

				r.Host = "internal-ip:8080"
				r.Header.Set("X-Forwarded-Proto", "https")
				r.Header.Set("X-Forwarded-Host", "public.example.com")

				return r
			},
			expected: "https://public.example.com/api",
		},
		{
			// Proof of concept from GHSA-96gc-j5p6-fp6q: a direct client tries to inject
			// both its own host and a downgraded scheme into the redirect_uri.
			name: "advisory proof of concept untrusted",
			request: func() *http.Request {
				r := pkgtest.NewRequest(http.MethodGet, "http://app.example.com/dashboard", nil)
				r.TLS = &tls.ConnectionState{}
				r.Header.Set("X-Forwarded-Host", "attacker.example")
				r.Header.Set("X-Forwarded-Proto", "http")

				return r
			},
			expected: "https://app.example.com/dashboard",
		},
		{
			name: "scheme downgrade via X-Forwarded-Proto untrusted",
			request: func() *http.Request {
				r := pkgtest.NewRequest(http.MethodGet, "http://localhost/", nil)
				r.TLS = &tls.ConnectionState{}
				r.Header.Set("X-Forwarded-Proto", "http")

				return r
			},
			expected: "https://localhost/",
		},
		{
			name: "trusted proxy explicitly false",
			request: func() *http.Request {
				r := pkgtest.NewRequest(http.MethodGet, "http://localhost/foo", nil)
				caddyhttp.SetVar(r.Context(), caddyhttp.TrustedProxyVarKey, false)
				r.Header.Set("X-Forwarded-Proto", "https")
				r.Header.Set("X-Forwarded-Host", "example.com")

				return r
			},
			expected: "http://localhost/foo",
		},
		{
			name: "trusted proxy var with non-bool value",
			request: func() *http.Request {
				r := pkgtest.NewRequest(http.MethodGet, "http://localhost/foo", nil)
				caddyhttp.SetVar(r.Context(), caddyhttp.TrustedProxyVarKey, "true")
				r.Header.Set("X-Forwarded-Proto", "https")
				r.Header.Set("X-Forwarded-Host", "example.com")

				return r
			},
			expected: "http://localhost/foo",
		},
		{
			name: "no caddy vars in context",
			request: func() *http.Request {
				//nolint:noctx
				r := httptest.NewRequest(http.MethodGet, "http://localhost/foo", nil)
				r.Header.Set("X-Forwarded-Proto", "https")
				r.Header.Set("X-Forwarded-Host", "example.com")

				return r
			},
			expected: "http://localhost/foo",
		},
		{
			name: "multiple X-Forwarded values untrusted",
			request: func() *http.Request {
				r := pkgtest.NewRequest(http.MethodGet, "http://localhost/foo", nil)
				r.Header.Add("X-Forwarded-Proto", "https")
				r.Header.Add("X-Forwarded-Proto", "https")
				r.Header.Add("X-Forwarded-Host", "attacker.example")
				r.Header.Add("X-Forwarded-Host", "example.com")

				return r
			},
			expected: "http://localhost/foo",
		},
		{
			name: "multiple X-Forwarded values trusted uses last",
			request: func() *http.Request {
				r := pkgtest.NewRequest(http.MethodGet, "http://localhost/foo", nil)
				caddyhttp.SetVar(r.Context(), caddyhttp.TrustedProxyVarKey, true)
				r.Header.Add("X-Forwarded-Proto", "http")
				r.Header.Add("X-Forwarded-Proto", "https")
				r.Header.Add("X-Forwarded-Host", "attacker.example")
				r.Header.Add("X-Forwarded-Host", "example.com")

				return r
			},
			expected: "https://example.com/foo",
		},
		{
			name: "empty X-Forwarded values trusted fall back to request",
			request: func() *http.Request {
				r := pkgtest.NewRequest(http.MethodGet, "http://localhost/foo", nil)
				r.TLS = &tls.ConnectionState{}
				caddyhttp.SetVar(r.Context(), caddyhttp.TrustedProxyVarKey, true)
				r.Header.Set("X-Forwarded-Proto", "")
				r.Header.Set("X-Forwarded-Host", "")

				return r
			},
			expected: "https://localhost/foo",
		},
		{
			name: "trusted proxy without X-Forwarded headers",
			request: func() *http.Request {
				r := pkgtest.NewRequest(http.MethodGet, "http://localhost:8080/foo", nil)
				caddyhttp.SetVar(r.Context(), caddyhttp.TrustedProxyVarKey, true)

				return r
			},
			expected: "http://localhost:8080/foo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := tt.request()
			got := URL(req)
			assert.Equal(t, tt.expected, got.String())
		})
	}
}

func TestShouldStartLogin(t *testing.T) {
	t.Parallel()

	t.Run("incorrect method", func(t *testing.T) {
		t.Parallel()

		r := pkgtest.NewRequest(http.MethodPost, "/", nil)
		assert.False(t, IsBrowserInteractive(r))
	})
	t.Run("can't accept", func(t *testing.T) {
		t.Parallel()

		r := pkgtest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Accept", "application/json")
		assert.False(t, IsBrowserInteractive(r))
	})
	t.Run("Sec-Fetch-Dest", func(t *testing.T) {
		t.Parallel()

		r := pkgtest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Sec-Fetch-Dest", "document")
		assert.True(t, IsBrowserInteractive(r))
	})
	t.Run("navigation mode with empty destination", func(t *testing.T) {
		t.Parallel()

		r := pkgtest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		r.Header.Set("Sec-Fetch-Dest", "empty")
		assert.True(t, IsBrowserInteractive(r))
	})
	t.Run("service worker navigation", func(t *testing.T) {
		t.Parallel()

		r := pkgtest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Accept", "text/html")
		r.Header.Set("Sec-Fetch-Mode", "same-origin")
		r.Header.Set("Sec-Fetch-Dest", "empty")
		r.Header.Set("Upgrade-Insecure-Requests", "1")
		assert.True(t, IsBrowserInteractive(r))
	})
	t.Run("non-navigation with empty destination", func(t *testing.T) {
		t.Parallel()

		r := pkgtest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Accept", "text/html")
		r.Header.Set("Sec-Fetch-Mode", "same-origin")
		r.Header.Set("Sec-Fetch-Dest", "empty")
		assert.False(t, IsBrowserInteractive(r))
	})
	t.Run("service worker request without HTML", func(t *testing.T) {
		t.Parallel()

		r := pkgtest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Accept", "application/json")
		r.Header.Set("Sec-Fetch-Mode", "same-origin")
		r.Header.Set("Sec-Fetch-Dest", "empty")
		r.Header.Set("Upgrade-Insecure-Requests", "1")
		assert.False(t, IsBrowserInteractive(r))
	})
	t.Run("accept HTML", func(t *testing.T) {
		t.Parallel()

		r := pkgtest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Accept", "text/html")
		assert.True(t, IsBrowserInteractive(r))
	})
}
