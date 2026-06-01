package authenticator

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/relvacode/caddy-oidc/internal/pkgtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQueryAuthenticator_UnmarshalCaddyfile(t *testing.T) {
	t.Parallel()

	d := caddyfile.NewTestDispenser("api-key")

	var au QueryAuthenticator

	err := au.UnmarshalCaddyfile(d)
	require.NoError(t, err)
	require.Equal(t, "api-key", au.Query)
}

func TestQueryAuthenticator_AuthenticateRequest(t *testing.T) {
	t.Parallel()

	var (
		cfg pkgtest.TestOIDCConfiguration
		au  = QueryAuthenticator{
			Query: "api-key",
		}
	)

	r := httptest.NewRequest(http.MethodGet, "/?api-key="+pkgtest.GenerateTestJWTExpiresAt(cfg.Now().Add(time.Hour)), nil)

	_, err := au.AuthenticateRequest(&cfg, make(http.Header), r)
	require.NoError(t, err)
}

func TestQueryAuthenticator_AuthenticateRequest_MissingQuery(t *testing.T) {
	t.Parallel()

	var (
		cfg pkgtest.TestOIDCConfiguration
		au  = QueryAuthenticator{
			Query: "api-key",
		}
	)

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	_, err := au.AuthenticateRequest(&cfg, make(http.Header), r)
	assert.ErrorIs(t, err, ErrNoAuthentication)
}

func TestQueryAuthenticator_StripRequest(t *testing.T) {
	t.Parallel()

	var au = QueryAuthenticator{
		Query: "api-key",
	}

	r := httptest.NewRequest(http.MethodGet, "/?api-key=xyz&foo=bar", nil)

	au.StripRequest(r)

	assert.Empty(t, r.URL.Query().Get("api-key"))
	assert.Equal(t, "foo=bar", r.URL.RawQuery)
}
