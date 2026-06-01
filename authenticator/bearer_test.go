package authenticator

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/relvacode/caddy-oidc/internal/pkgtest"
	"github.com/relvacode/caddy-oidc/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBearerAuthenticator_AuthenticateRequest(t *testing.T) {
	t.Parallel()

	var (
		cfg pkgtest.TestOIDCConfiguration
		au  BearerAuthenticator
	)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+pkgtest.GenerateTestJWTExpiresAt(cfg.Now().Add(time.Hour)))

	s, err := au.AuthenticateRequest(&cfg, make(http.Header), r)
	require.NoError(t, err)
	assert.Equal(t, "test", s.UID)
}

func TestBearerAuthentication_AuthenticateRequest_WithoutBearerToken(t *testing.T) {
	t.Parallel()

	var (
		cfg pkgtest.TestOIDCConfiguration
		au  BearerAuthenticator
	)

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	_, err := au.AuthenticateRequest(&cfg, make(http.Header), r)
	assert.ErrorIs(t, err, ErrNoAuthentication)
}

func TestBearerAuthentication_AuthenticateRequest_InvalidBearerToken(t *testing.T) {
	t.Parallel()

	var (
		cfg pkgtest.TestOIDCConfiguration
		au  BearerAuthenticator
	)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer xxxxx")

	_, err := au.AuthenticateRequest(&cfg, make(http.Header), r)
	require.Error(t, err)
	assert.ErrorContains(t, err, "compact JWS format must have three parts")
}

func TestBearerAuthentication_AuthenticateRequest_EmailForUsernameClaim(t *testing.T) {
	t.Parallel()

	var (
		cfg pkgtest.TestOIDCConfiguration
		au  BearerAuthenticator
	)

	cfg.UsernameClaim = "email"

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+pkgtest.GenerateTestJWTExpiresAt(cfg.Now().Add(time.Hour)))

	s, err := au.AuthenticateRequest(&cfg, make(http.Header), r)
	require.NoError(t, err)
	assert.Equal(t, "x@example.org", s.UID)
}

func TestBearerAuthentication_AuthenticateRequest_MissingUsernameClaim(t *testing.T) {
	t.Parallel()

	var (
		cfg pkgtest.TestOIDCConfiguration
		au  BearerAuthenticator
	)

	cfg.UsernameClaim = "not exist"

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+pkgtest.GenerateTestJWTExpiresAt(cfg.Now().Add(time.Hour)))

	_, err := au.AuthenticateRequest(&cfg, make(http.Header), r)

	var mce session.MissingRequiredClaimError
	if assert.ErrorAs(t, err, &mce) {
		assert.Equal(t, "not exist", mce.Claim)
	}
}

func TestBearerAuthentication_AuthenticateRequest_BearerTokenExpired(t *testing.T) {
	t.Parallel()

	var (
		cfg pkgtest.TestOIDCConfiguration
		au  BearerAuthenticator
	)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+pkgtest.GenerateTestJWTExpiresAt(cfg.Now().Add(-time.Hour)))

	_, err := au.AuthenticateRequest(&cfg, make(http.Header), r)
	require.Error(t, err)

	var ee *oidc.TokenExpiredError
	assert.ErrorAs(t, err, &ee)
}

func TestBearerAuthenticator_StripRequest(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer xyz")

	var au BearerAuthenticator
	au.StripRequest(r)
}
