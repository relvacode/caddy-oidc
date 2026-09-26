package authenticator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"github.com/relvacode/caddy-oidc/internal/pkgtest"
	"github.com/relvacode/caddy-oidc/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestSessionCookieAuthenticator_UnmarshalCaddyfile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		expect    SessionCookieAuthenticator
		shouldErr bool
	}{
		{
			name:   "empty",
			input:  "",
			expect: SessionCookieAuthenticator{},
		},
		{
			name:  "inline name",
			input: `my_cookie`,
			expect: SessionCookieAuthenticator{
				Name: "my_cookie",
			},
		},
		{
			name: "block configuration",
			input: `{
				name block_cookie
				same_site strict
				insecure
				domain example.com
				path /auth
				claim email
				claim preferred_username
				id_claim roles
			}`,
			expect: SessionCookieAuthenticator{
				Name:     "block_cookie",
				SameSite: SameSiteStrict,
				Insecure: true,
				Domain:   "example.com",
				Path:     "/auth",
				Claims:   []string{"email", "preferred_username"},
				IDClaims: []string{"roles"},
			},
		},
		{
			name: "max_age",
			input: `{
				name caddy
				max_age 168h
			}`,
			expect: SessionCookieAuthenticator{
				Name:   "caddy",
				MaxAge: caddy.Duration(168 * time.Hour),
			},
		},
		{
			name: "invalid max_age",
			input: `{
				max_age not-a-duration
			}`,
			shouldErr: true,
		},
		{
			name: "invalid same_site",
			input: `{
				same_site mysterious
			}`,
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := caddyfile.NewTestDispenser(tt.input)

			var cookies SessionCookieAuthenticator

			err := cookies.UnmarshalCaddyfile(d)

			if tt.shouldErr {
				assert.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expect, cookies)
		})
	}
}

func TestSessionCookieAuthenticator_GetAbsRedirectUri(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		redirect string
		expect   string
	}{
		{
			name:     "relative",
			redirect: "/foo",
			expect:   "http://example.com/foo",
		},
		{
			name:     "absolute",
			redirect: "http://example.org/foo",
			expect:   "http://example.org/foo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			u, err := url.Parse(tt.redirect)
			require.NoError(t, err)

			var au = &SessionCookieAuthenticator{
				redirectURL: u,
			}

			r := pkgtest.NewRequest(http.MethodGet, "http://example.com/auth?bar=baz#xyz", nil)

			assert.Equal(t, tt.expect, au.GetAbsRedirectURI(r).String())
		})
	}
}

func TestSessionCookieAuthenticator_AuthenticateRequest_WithCookie(t *testing.T) {
	t.Parallel()

	var (
		cfg pkgtest.TestOIDCConfiguration
		au  = &SessionCookieAuthenticator{
			Name:   "test-cookie",
			Secret: "Y4lbVNr01M4NyBCUSNbrAL4cavA6kjdM",
		}
	)

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := au.Provision(ctx)
	require.NoError(t, err)

	r := pkgtest.NewRequest(http.MethodGet, "/", nil)

	s := &session.Session{UID: "test"}
	cookieValue, err := au.secure.Encode(au.Name, s)
	require.NoError(t, err)

	r.AddCookie(au.NewCookie(cookieValue))

	s, err = au.AuthenticateRequest(&cfg, r)
	if assert.NoError(t, err) {
		assert.Equal(t, "test", s.UID)
	}
}

func TestSessionCookieAuthenticator_AuthenticateRequest_WithCookieSignedByOther(t *testing.T) {
	t.Parallel()

	var (
		cfg pkgtest.TestOIDCConfiguration
		au  = &SessionCookieAuthenticator{
			Name:   "test-cookie",
			Secret: "Y4lbVNr01M4NyBCUSNbrAL4cavA6kjdM",
		}
	)

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := au.Provision(ctx)
	require.NoError(t, err)

	r := pkgtest.NewRequest(http.MethodGet, "/", nil)

	s := &session.Session{UID: "test"}
	cookieSigner := securecookie.New([]byte("EPb6FR6Uehz2uWdfhtb7l6c4tXzgMJT8"), []byte("EPb6FR6Uehz2uWdfhtb7l6c4tXzgMJT8"))

	cookie, err := cookieSigner.Encode(au.Name, s)
	require.NoError(t, err)

	r.AddCookie(au.NewCookie(cookie))

	_, err = au.AuthenticateRequest(&cfg, r)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoAuthentication)

	var he caddyhttp.HandlerError
	if assert.ErrorAs(t, err, &he) {
		assert.Equal(t, http.StatusUnauthorized, he.StatusCode)
	}
}

func TestSessionCookieAuthenticator_AuthenticateRequest_CookiePastSecureCookieMaxAge(t *testing.T) {
	t.Parallel()

	var (
		cfg pkgtest.TestOIDCConfiguration
		au  = &SessionCookieAuthenticator{
			Name:   "test-cookie",
			Secret: "Y4lbVNr01M4NyBCUSNbrAL4cavA6kjdM",
		}
	)

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := au.Provision(ctx)
	require.NoError(t, err)

	cookieValue, err := au.secure.Encode(au.Name, &session.Session{UID: "test"})
	require.NoError(t, err)

	// Any timestamp is now past max age
	au.secure.MaxAge(-1)

	r := pkgtest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(au.NewCookie(cookieValue))

	_, err = au.AuthenticateRequest(&cfg, r)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoAuthentication)

	var he caddyhttp.HandlerError
	if assert.ErrorAs(t, err, &he) {
		assert.Equal(t, http.StatusUnauthorized, he.StatusCode)
	}
}

func TestSessionCookieAuthenticator_AuthenticateRequest_SessionExpired(t *testing.T) {
	t.Parallel()

	var (
		cfg pkgtest.TestOIDCConfiguration
		au  = &SessionCookieAuthenticator{
			Name:   "test-cookie",
			Secret: "Y4lbVNr01M4NyBCUSNbrAL4cavA6kjdM",
		}
	)

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := au.Provision(ctx)
	require.NoError(t, err)

	r := pkgtest.NewRequest(http.MethodGet, "/", nil)

	s := &session.Session{UID: "test", ExpiresAt: cfg.Now().Add(-time.Hour).Unix()}
	cookieValue, err := au.secure.Encode(au.Name, s)
	require.NoError(t, err)

	r.AddCookie(au.NewCookie(cookieValue))

	_, err = au.AuthenticateRequest(&cfg, r)
	require.Error(t, err)

	var ee *oidc.TokenExpiredError
	assert.ErrorAs(t, err, &ee)
}

func TestSessionCookieAuthenticator_Provision_64ByteSecret(t *testing.T) {
	t.Parallel()

	var au = &SessionCookieAuthenticator{
		Name:   "test-cookie",
		Secret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := au.Provision(ctx)
	require.NoError(t, err)

	r := pkgtest.NewRequest(http.MethodGet, "/", nil)

	s := &session.Session{UID: "test"}
	cookieValue, err := au.secure.Encode(au.Name, s)
	require.NoError(t, err)

	r.AddCookie(au.NewCookie(cookieValue))

	session, err := au.AuthenticateRequest(&pkgtest.TestOIDCConfiguration{}, r)
	require.NoError(t, err)
	assert.Equal(t, "test", session.UID)
}

func TestSessionCookieAuthenticator_StripRequest(t *testing.T) {
	t.Parallel()

	var au = &SessionCookieAuthenticator{
		Name:   "test-cookie",
		Secret: "Y4lbVNr01M4NyBCUSNbrAL4cavA6kjdM",
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := au.Provision(ctx)
	require.NoError(t, err)

	r := pkgtest.NewRequest(http.MethodGet, "/", nil)

	r.Header.Add("Cookie", "some-other-cookie=foobar")
	r.Header.Add("Cookie", "test-cookie=xyz; some-second-cookie=barfoo")

	au.StripRequest(r)

	cookies := r.Cookies()
	if assert.Len(t, cookies, 2) {
		assert.Equal(t, "some-other-cookie=foobar", cookies[0].String())
		assert.Equal(t, "some-second-cookie=barfoo", cookies[1].String())
	}
}

type testHandleCallbackConfiguration struct {
	pkgtest.TestOIDCConfiguration

	userInfo *oidc.UserInfo
	expires  time.Time
}

func (cfg *testHandleCallbackConfiguration) AuthCodeURL(_ context.Context, _ string, _ ...oauth2.AuthCodeOption) (string, error) {
	return "", nil
}

func (cfg *testHandleCallbackConfiguration) Exchange(_ context.Context, _ string, _ ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return (&oauth2.Token{
		AccessToken: "test-access-token",
		TokenType:   "Bearer",
		Expiry:      cfg.expires,
	}).WithExtra(map[string]any{
		"id_token": pkgtest.GenerateTestJWTExpiresAt(cfg.expires),
	}), nil
}

func (cfg *testHandleCallbackConfiguration) UserInfo(_ context.Context, _ oauth2.TokenSource) (*oidc.UserInfo, error) {
	return cfg.userInfo, nil
}

func newTestUserInfo(t *testing.T, claims string) *oidc.UserInfo {
	t.Helper()

	userInfo := new(oidc.UserInfo)
	claimsField := reflect.ValueOf(userInfo).Elem().FieldByName("claims")
	require.True(t, claimsField.IsValid())

	//nolint:gosec // This is only used for testing
	reflect.NewAt(claimsField.Type(), unsafe.Pointer(claimsField.UnsafeAddr())).
		Elem().
		SetBytes([]byte(claims))

	return userInfo
}

func TestSessionCookieAuthenticator_HandleCallback_CopiesClaimsAsRawJSON(t *testing.T) {
	t.Parallel()

	au := &SessionCookieAuthenticator{
		Name:     "test-cookie",
		Secret:   "Y4lbVNr01M4NyBCUSNbrAL4cavA6kjdM",
		Claims:   []string{"preferred_username", "roles", "email_verified"},
		IDClaims: []string{"iss"},
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := au.Provision(ctx)
	require.NoError(t, err)

	const state = "test-state"

	csrfCookieValue, err := au.secure.Encode(au.Name+"|"+state, &CSRFToken{
		PKCEVerifier: "test-pkce-verifier",
		RedirectURI:  "/original",
	})
	require.NoError(t, err)

	r := pkgtest.NewRequest(http.MethodGet, "/oauth2/callback?state="+state+"&code=test-code", nil)
	csrfCookie := au.NewCookie(csrfCookieValue)
	csrfCookie.Name = au.Name + "|" + state
	r.AddCookie(csrfCookie)

	cfg := &testHandleCallbackConfiguration{
		TestOIDCConfiguration: pkgtest.TestOIDCConfiguration{
			UsernameClaim: "preferred_username",
		},
		userInfo: newTestUserInfo(t, `{
			"preferred_username": "admin",
			"roles": ["admin", "user"],
			"email_verified": true
		}`),
		expires: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	w := httptest.NewRecorder()

	err = au.HandleCallback(cfg, w, r)
	require.NoError(t, err)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/original", w.Header().Get("Location"))

	var sessionCookie *http.Cookie

	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == au.Name {
			sessionCookie = cookie

			break
		}
	}

	require.NotNil(t, sessionCookie)

	var s session.Session

	err = au.secure.Decode(au.Name, sessionCookie.Value, &s)
	require.NoError(t, err)

	assert.Equal(t, "admin", s.UID)
	assert.Equal(t, cfg.expires.Unix(), s.ExpiresAt)
	assert.JSONEq(t, `{
		"iss":"http://openid/example",
		"preferred_username": "admin",
		"roles": ["admin", "user"],
		"email_verified": true
	}`, string(s.Claims))
	assert.Equal(t, 0, sessionCookie.MaxAge)
}

func TestSessionCookieAuthenticator_HandleCallback_MaxAge(t *testing.T) {
	t.Parallel()

	const maxAge = 2 * time.Hour

	au := &SessionCookieAuthenticator{
		Name:   "test-cookie",
		Secret: "Y4lbVNr01M4NyBCUSNbrAL4cavA6kjdM",
		MaxAge: caddy.Duration(maxAge),
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := au.Provision(ctx)
	require.NoError(t, err)

	const state = "test-state"

	csrfCookieValue, err := au.secure.Encode(au.Name+"|"+state, &CSRFToken{
		PKCEVerifier: "test-pkce-verifier",
		RedirectURI:  "/original",
	})
	require.NoError(t, err)

	r := pkgtest.NewRequest(http.MethodGet, "/oauth2/callback?state="+state+"&code=test-code", nil)
	csrfCookie := au.NewCookie(csrfCookieValue)
	csrfCookie.Name = au.Name + "|" + state
	// NewCookie with MaxAge set also applies to CSRF cookie construction here;
	// override so CSRF still works as a short-lived cookie in production code paths.
	csrfCookie.MaxAge = 900
	r.AddCookie(csrfCookie)

	// TestOIDCConfiguration.Now() defaults to 2021-01-01 UTC.
	now := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := &testHandleCallbackConfiguration{
		TestOIDCConfiguration: pkgtest.TestOIDCConfiguration{
			UsernameClaim: "sub",
		},
		userInfo: newTestUserInfo(t, `{"sub": "user-1"}`),
		// Token expiry sooner than max_age — session should follow max_age.
		expires: now.Add(15 * time.Minute),
	}

	w := httptest.NewRecorder()

	err = au.HandleCallback(cfg, w, r)
	require.NoError(t, err)

	var sessionCookie *http.Cookie

	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == au.Name {
			sessionCookie = cookie

			break
		}
	}

	require.NotNil(t, sessionCookie)
	assert.Equal(t, int(maxAge.Seconds()), sessionCookie.MaxAge)

	var s session.Session

	err = au.secure.Decode(au.Name, sessionCookie.Value, &s)
	require.NoError(t, err)

	assert.Equal(t, "user-1", s.UID)
	assert.Equal(t, now.Add(maxAge).Unix(), s.ExpiresAt)
}

func TestSessionCookieAuthenticator_NewCookie_MaxAge(t *testing.T) {
	t.Parallel()

	au := &SessionCookieAuthenticator{
		Name:   "caddy",
		MaxAge: caddy.Duration(168 * time.Hour),
	}

	c := au.NewCookie("value")
	assert.Equal(t, int((168 * time.Hour).Seconds()), c.MaxAge)

	au.MaxAge = 0
	c = au.NewCookie("value")
	assert.Equal(t, 0, c.MaxAge)
}
