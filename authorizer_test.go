package caddy_oidc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

func GenerateTestAuthorizer() *Authorizer {
	return &Authorizer{
		cookie: &DefaultCookieOptions,
		clock: func() time.Time {
			return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		},
		redirectUri: &url.URL{
			Scheme: "http",
			Host:   "localhost",
			Path:   "/oauth/callback",
		},
		log:     zap.NewNop(),
		cookies: securecookie.New([]byte("VTQOz22ZZiyYNciwtDyckU1aJWQSCXnm"), []byte("VTQOz22ZZiyYNciwtDyckU1aJWQSCXnm")),
		verifier: oidc.NewVerifier("http://openid/example", AlwaysValidKeySet{}, &oidc.Config{
			ClientID:             "xyz",
			SupportedSigningAlgs: []string{"none"},
		}),
		oauth2: &oauth2.Config{
			ClientID:    "xyz",
			RedirectURL: "http://localhost/oauth/callback",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "http://openid/example/authorize",
				TokenURL: "http://openid/example/token",
			},
		},
	}
}

func TestAuthorizer_Authenticate_WithBearerAuthentication(t *testing.T) {
	pr := GenerateTestAuthorizer()

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+GenerateTestJWTUnsigned())

	s, err := pr.Authenticate(r)
	if assert.NoError(t, err) {
		assert.Equal(t, "test", s.Uid)
	}
}

func TestAuthorizer_Authenticate_WithSessionCookie(t *testing.T) {
	pr := GenerateTestAuthorizer()

	r := httptest.NewRequest("GET", "/", nil)

	s := &Session{Uid: "test"}
	cookie, err := s.HttpCookie(pr.cookie, pr.cookies)
	assert.NoError(t, err)

	r.AddCookie(cookie)

	s, err = pr.Authenticate(r)
	if assert.NoError(t, err) {
		assert.Equal(t, "test", s.Uid)
	}
}

func TestAuthorizer_Authenticate_WithSessionCookie_SignedByOther(t *testing.T) {
	pr := GenerateTestAuthorizer()

	r := httptest.NewRequest("GET", "/", nil)

	s := &Session{Uid: "test"}
	cookieSigner := securecookie.New([]byte("EPb6FR6Uehz2uWdfhtb7l6c4tXzgMJT8"), []byte("EPb6FR6Uehz2uWdfhtb7l6c4tXzgMJT8"))

	cookie, err := s.HttpCookie(pr.cookie, cookieSigner)
	assert.NoError(t, err)

	r.AddCookie(cookie)

	s, err = pr.Authenticate(r)
	assert.Error(t, err)

	var he caddyhttp.HandlerError
	if assert.ErrorAs(t, err, &he) {
		assert.Equal(t, http.StatusBadRequest, he.StatusCode)
	}
}

func TestAuthorizer_SessionFromCookie(t *testing.T) {
	pr := GenerateTestAuthorizer()

	r := httptest.NewRequest("GET", "/", nil)

	s := &Session{Uid: "test", ExpiresAt: pr.clock().Add(-1 * time.Hour).Unix()}

	cookie, err := s.HttpCookie(pr.cookie, pr.cookies)
	assert.NoError(t, err)

	r.AddCookie(cookie)

	_, err = pr.SessionFromCookie(r)
	assert.Error(t, err)

	var e *oidc.TokenExpiredError
	assert.ErrorAs(t, err, &e)
}
