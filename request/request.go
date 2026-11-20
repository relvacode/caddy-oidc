// Package request provides utilities for working with HTTP requests.
package request

import (
	"net/http"
	"net/url"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/munnerz/goautoneg"
)

// lastHeaderValue returns the last value of the given header field, if any.
// Implementation taken from github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy/reverseproxy.go.
func lastHeaderValue(h http.Header, field string) (string, bool) {
	values, ok := h[http.CanonicalHeaderKey(field)]
	if ok && values == nil {
		return "", true
	}

	if len(values) == 0 {
		return "", false
	}

	return values[len(values)-1], true
}

// URL returns the original fully qualified request URL made by the client before any intermediate proxies.
// X-Forwarded headers are only considered if the client is a trusted proxy.
func URL(r *http.Request) *url.URL {
	var u = new(url.URL)

	*u = *r.URL

	// Check if the client is a trusted proxy
	trusted, _ := caddyhttp.GetVar(r.Context(), caddyhttp.TrustedProxyVarKey).(bool)

	u.Scheme = "http"
	if r.TLS != nil {
		u.Scheme = "https"
	}

	prior, ok := lastHeaderValue(r.Header, "X-Forwarded-Proto")

	if trusted && ok && prior != "" {
		u.Scheme = prior
	}

	u.Host = r.Host

	prior, ok = lastHeaderValue(r.Header, "X-Forwarded-Host")
	if trusted && ok && prior != "" {
		u.Host = prior
	}

	return u
}

// IsBrowserInteractive returns true if the request is likely coming from a browser.
func IsBrowserInteractive(r *http.Request) bool {
	// Navigation mode directly identifies a document navigation, even when the
	// destination has been generalized or omitted.
	if r.Header.Get("Sec-Fetch-Mode") == "navigate" {
		return true
	}

	dest := r.Header.Get("Sec-Fetch-Dest")
	if dest != "" {
		if dest == "document" || dest == "iframe" {
			return true
		}

		// A service worker may replace navigation Fetch Metadata while retaining
		// the browser's navigation preference and accepted document type.
		return dest == "empty" && r.Header.Get("Upgrade-Insecure-Requests") == "1" &&
			goautoneg.Negotiate(r.Header.Get("Accept"), []string{"text/html"}) == "text/html"
	}

	// Fallback for older browsers: check Accept header for HTML.
	// If the browser doesn't send Sec-Fetch-Dest, we check if it's looking for HTML.
	return goautoneg.Negotiate(r.Header.Get("Accept"), []string{"text/html"}) == "text/html"
}
