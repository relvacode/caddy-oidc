package authenticator

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
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

	_ "github.com/caddyserver/caddy/v2/modules/filestorage"
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
			}`,
			expect: SessionCookieAuthenticator{
				Name:     "block_cookie",
				SameSite: SameSiteStrict,
				Insecure: true,
				Domain:   "example.com",
				Path:     "/auth",
			},
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

			r := httptest.NewRequest(http.MethodGet, "http://example.com/auth?bar=baz#xyz", nil)

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

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	s := &session.Session{UID: "test"}
	cookieValue, err := au.secure.Encode(au.Name, s)
	require.NoError(t, err)

	r.AddCookie(au.makeCookie(cookieValue))

	s, err = au.AuthenticateRequest(&cfg, make(http.Header), r)
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

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	s := &session.Session{UID: "test"}
	cookieSigner := securecookie.New([]byte("EPb6FR6Uehz2uWdfhtb7l6c4tXzgMJT8"), []byte("EPb6FR6Uehz2uWdfhtb7l6c4tXzgMJT8"))

	cookie, err := cookieSigner.Encode(au.Name, s)
	require.NoError(t, err)

	r.AddCookie(au.makeCookie(cookie))

	_, err = au.AuthenticateRequest(&cfg, make(http.Header), r)
	require.Error(t, err)

	var he caddyhttp.HandlerError
	if assert.ErrorAs(t, err, &he) {
		assert.Equal(t, http.StatusBadRequest, he.StatusCode)
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

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	s := &session.Session{UID: "test", ExpiresAt: cfg.Now().Add(-time.Hour).Unix()}
	cookieValue, err := au.secure.Encode(au.Name, s)
	require.NoError(t, err)

	r.AddCookie(au.makeCookie(cookieValue))

	hdr := make(http.Header)
	_, err = au.AuthenticateRequest(&cfg, hdr, r)
	require.Error(t, err)

	assert.Empty(t, hdr.Get("Set-Cookie"))

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

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	s := &session.Session{UID: "test"}
	cookieValue, err := au.secure.Encode(au.Name, s)
	require.NoError(t, err)

	r.AddCookie(au.makeCookie(cookieValue))

	newSession, err := au.AuthenticateRequest(&pkgtest.TestOIDCConfiguration{}, make(http.Header), r)
	require.NoError(t, err)
	assert.Equal(t, "test", newSession.UID)
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

	r := httptest.NewRequest(http.MethodGet, "/", nil)

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

	reflect.NewAt(claimsField.Type(), unsafe.Pointer(claimsField.UnsafeAddr())).
		Elem().
		SetBytes([]byte(claims))

	return userInfo
}

func TestSessionCookieAuthenticator_HandleCallback_CopiesClaimsAsRawJSON(t *testing.T) {
	t.Parallel()

	au := &SessionCookieAuthenticator{
		Name:   "test-cookie",
		Secret: "Y4lbVNr01M4NyBCUSNbrAL4cavA6kjdM",
		Claims: []string{"preferred_username", "roles", "email_verified"},
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

	r := httptest.NewRequest(http.MethodGet, "/oauth2/callback?state="+state+"&code=test-code", nil)
	csrfCookie := au.makeCookie(csrfCookieValue)
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
		"preferred_username": "admin",
		"roles": ["admin", "user"],
		"email_verified": true
	}`, string(s.Claims))
}

//nolint:tparallel // Tests need to run in order
func TestSessionCookieAuthenticator_RefreshToken(t *testing.T) {
	t.Parallel()

	au := &SessionCookieAuthenticator{
		Name:    "test-cookie",
		Secret:  "Y4lbVNr01M4NyBCUSNbrAL4cavA6kjdM",
		Claims:  []string{},
		Refresh: true,
	}

	storageRaw, err := json.Marshal(map[string]any{
		"module": "file_system",
		"root":   t.TempDir(),
	})
	require.NoError(t, err)

	ctx, err := caddy.ProvisionContext(&caddy.Config{
		StorageRaw: storageRaw,
	})
	require.NoError(t, err)

	err = au.Provision(ctx)
	require.NoError(t, err)

	var (
		authCookie       *http.Cookie
		sessionStorePath string
	)

	//nolint:paralleltest
	t.Run("Callback", func(t *testing.T) {
		var (
			csrfCookieName    = fmt.Sprintf("%s|%s", au.Name, "test-state")
			csrfCookiePayload = &CSRFToken{PKCEVerifier: "verifier"}
		)

		csrfCookieValue, err := au.secure.Encode(csrfCookieName, csrfCookiePayload)
		require.NoError(t, err)

		csrfCookie := au.makeCookie(csrfCookieValue)
		csrfCookie.Name = csrfCookieName

		r := httptest.NewRequest(http.MethodGet, "/oauth2/callback?state=test-state&code=test-code", nil)
		r.AddCookie(csrfCookie)

		rw := httptest.NewRecorder()

		cfg := new(pkgtest.TestOIDCConfiguration)
		cfg.ExchangeFunc = func(_ context.Context, code string, _ ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
			assert.Equal(t, "test-code", code)

			tok := &oauth2.Token{RefreshToken: "test-refresh-token", ExpiresIn: 3600}

			return tok.WithExtra(map[string]any{"id_token": pkgtest.GenerateTestJWTExpiresAt(cfg.Now().Add(time.Hour))}), nil
		}
		cfg.UserInfoFunc = func(_ context.Context, _ oauth2.TokenSource) (*oidc.UserInfo, error) {
			return newTestUserInfo(t, `{
				"sub": "admin",
				"preferred_username": "admin",
				"email_verified": true
			}`), nil
		}

		err = au.HandleCallback(cfg, rw, r)
		require.NoError(t, err)

		entries, err := ctx.Storage().List(ctx, path.Join("oidc", "sessions"), false)
		require.NoError(t, err)
		require.Len(t, entries, 1)

		sessionStorePath = entries[0]

		cookieHeaderValue := rw.Header().Values("Set-Cookie")[1]
		require.NotEmpty(t, cookieHeaderValue)

		t.Log(cookieHeaderValue)

		authCookie, err = http.ParseSetCookie(cookieHeaderValue)
		require.NoError(t, err)
	})

	//nolint:paralleltest
	t.Run("AuthenticateWithValidToken", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(authCookie)

		s, err := au.AuthenticateRequest(&pkgtest.TestOIDCConfiguration{}, make(http.Header), r)
		require.NoError(t, err)

		assert.Equal(t, "admin", s.UID)
	})

	var authCookie2 *http.Cookie

	//nolint:paralleltest
	t.Run("AuthenticateWithExpiredTokenDoRefresh", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(authCookie)

		cfg := new(pkgtest.TestOIDCConfiguration)
		cfg.ClockAdjust = time.Hour * 2
		cfg.UserInfoFunc = func(_ context.Context, _ oauth2.TokenSource) (*oidc.UserInfo, error) {
			return newTestUserInfo(t, `{
				"sub": "admin2",
				"preferred_username": "admin",
				"email_verified": true
			}`), nil
		}

		var refreshCalled bool

		cfg.RefreshFunc = func(_ context.Context, refreshToken string) (*oauth2.Token, error) {
			refreshCalled = true

			assert.Equal(t, "test-refresh-token", refreshToken)

			tok := &oauth2.Token{RefreshToken: "test-refresh-token2", ExpiresIn: 3600}

			return tok.WithExtra(map[string]any{"id_token": pkgtest.GenerateTestJWTExpiresAt(cfg.Now().Add(time.Hour))}), nil
		}

		hdr := make(http.Header)
		s, err := au.AuthenticateRequest(cfg, hdr, r)
		require.NoError(t, err)

		assert.Equal(t, "admin2", s.UID)
		assert.True(t, refreshCalled)

		assert.False(t, ctx.Storage().Exists(ctx, sessionStorePath))

		cookieHeaderValue := hdr.Values("Set-Cookie")[0]
		require.NotEmpty(t, cookieHeaderValue)

		t.Log(cookieHeaderValue)

		authCookie2, err = http.ParseSetCookie(cookieHeaderValue)
		require.NoError(t, err)
	})

	//nolint:paralleltest
	t.Run("AuthenticateAgainWithSameExpiredToken", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(authCookie)

		cfg := new(pkgtest.TestOIDCConfiguration)
		cfg.ClockAdjust = time.Hour * 2

		_, err := au.AuthenticateRequest(cfg, make(http.Header), r)
		t.Log(err)
		require.Error(t, err)
	})

	//nolint:paralleltest
	t.Run("AuthenticateWithExpiredRefreshToken", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(authCookie2)

		cfg := new(pkgtest.TestOIDCConfiguration)
		cfg.ClockAdjust = time.Hour * 4

		var refreshCalled bool

		cfg.RefreshFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
			refreshCalled = true

			return nil, &oauth2.RetrieveError{
				ErrorCode: "invalid_grant",
			}
		}

		_, err := au.AuthenticateRequest(cfg, make(http.Header), r)

		assert.True(t, refreshCalled)

		var te *oidc.TokenExpiredError
		require.ErrorAs(t, err, &te)
	})
}
