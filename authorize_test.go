package caddy_oauth2_proxy_auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"github.com/stretchr/testify/assert"
)

type TestHandler struct {
	calls int
}

func (h *TestHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) error {
	h.calls++
	w.WriteHeader(http.StatusOK)
	return nil
}

func TestOIDCAuthorizer_ServeHTTP_WithoutAuth(t *testing.T) {
	auth := &OIDCAuthorizer{
		m: GenerateTestProvider(),
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	assert.NoError(t, err)
	assert.Equal(t, 0, h.calls)
	assert.Equal(t, http.StatusFound, w.Code)

	redir, err := url.Parse(w.Header().Get("Location"))
	assert.NoError(t, err)

	assert.Equal(t, "http", redir.Scheme)
	assert.Equal(t, "openid", redir.Host)
	assert.Equal(t, "/example/authorize", redir.Path)
	assert.Equal(t, "S256", redir.Query().Get("code_challenge_method"))
	assert.NotEmpty(t, redir.Query().Get("code_challenge"))
	assert.Equal(t, "code", redir.Query().Get("response_type"))
	assert.Equal(t, auth.m.oauth2.ClientID, redir.Query().Get("client_id"))
	assert.NotEmpty(t, redir.Query().Get("state"))
	assert.Equal(t, auth.m.oauth2.RedirectURL, redir.Query().Get("redirect_uri"))

	c, err := http.ParseSetCookie(w.Header().Get("Set-Cookie"))
	if assert.NoError(t, err) {
		assert.Equal(t, fmt.Sprintf("%s|%s", auth.m.cookie.Name, redir.Query().Get("state")), c.Name)
	}
}

func TestOIDCAuthorizer_Authenticate_WithBearerAuthentication(t *testing.T) {
	auth := &OIDCAuthorizer{
		m: GenerateTestProvider(),
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+GenerateTestJWTUnsigned())

	s, err := auth.Authenticate(r)
	if assert.NoError(t, err) {
		assert.Equal(t, "test", s.Uid)
	}
}

func TestOIDCAuthorizer_Authenticate_WithSessionCookie(t *testing.T) {
	auth := &OIDCAuthorizer{
		m: GenerateTestProvider(),
	}

	r := httptest.NewRequest("GET", "/", nil)

	s := &Session{Uid: "test"}
	cookie, err := s.HttpCookie(auth.m.cookie, auth.m.cookies)
	assert.NoError(t, err)

	r.AddCookie(cookie)

	s, err = auth.Authenticate(r)
	if assert.NoError(t, err) {
		assert.Equal(t, "test", s.Uid)
	}
}

func TestOIDCAuthorizer_Authenticate_WithSessionCookie_SignedByOther(t *testing.T) {
	auth := &OIDCAuthorizer{
		m: GenerateTestProvider(),
	}

	r := httptest.NewRequest("GET", "/", nil)

	s := &Session{Uid: "test"}
	cookieSigner := securecookie.New([]byte("EPb6FR6Uehz2uWdfhtb7l6c4tXzgMJT8"), []byte("EPb6FR6Uehz2uWdfhtb7l6c4tXzgMJT8"))

	cookie, err := s.HttpCookie(auth.m.cookie, cookieSigner)
	assert.NoError(t, err)

	r.AddCookie(cookie)

	s, err = auth.Authenticate(r)
	assert.Error(t, err)

	var he caddyhttp.HandlerError
	if assert.ErrorAs(t, err, &he) {
		assert.Equal(t, http.StatusBadRequest, he.StatusCode)
	}
}

func TestOIDCAuthorizer_Authenticate_WithSessionCookie_IsExpired(t *testing.T) {
	auth := &OIDCAuthorizer{
		m: GenerateTestProvider(),
	}

	auth.m.clock = func() time.Time {
		return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	}

	r := httptest.NewRequest("GET", "/", nil)

	s := &Session{Uid: "test", ExpiresAt: auth.m.clock().Add(-1 * time.Hour).Unix()}

	cookie, err := s.HttpCookie(auth.m.cookie, auth.m.cookies)
	assert.NoError(t, err)

	r.AddCookie(cookie)

	s, err = auth.Authenticate(r)
	assert.Error(t, err)

	var e *oidc.TokenExpiredError
	assert.ErrorAs(t, err, &e)
}
