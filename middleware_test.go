package caddy_oidc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/stretchr/testify/assert"
)

func TestOIDCAuthorizer_UnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expect    OIDCMiddleware
		shouldErr bool
	}{
		{
			name:  "without block",
			input: `oidc test`,
			expect: OIDCMiddleware{
				Provider: "test",
			},
		},
		{
			name: "with block",
			input: `oidc test {
				allow {
					anonymous
				}
			}`,
			expect: OIDCMiddleware{
				Provider: "test",
				Policies: PolicySet{
					&Policy{
						Action: Allow,
						RequestMatcher: RequestMatcher{
							Anonymous: true,
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)

			var o OIDCMiddleware
			err := o.UnmarshalCaddyfile(d)

			if tt.shouldErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.EqualValues(t, tt.expect, o)
		})
	}
}

type TestHandler struct {
	calls int
}

func (h *TestHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) error {
	h.calls++
	w.WriteHeader(http.StatusOK)
	return nil
}

func TestOIDCAuthorizer_ServeHTTP_WithoutAuth(t *testing.T) {
	pr := GenerateTestAuthorizer()
	auth := &OIDCMiddleware{
		m: Defer(func() (*Authorizer, error) {
			return pr, nil
		}),
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
	assert.Equal(t, pr.oauth2.ClientID, redir.Query().Get("client_id"))
	assert.NotEmpty(t, redir.Query().Get("state"))
	assert.Equal(t, pr.oauth2.RedirectURL, redir.Query().Get("redirect_uri"))

	c, err := http.ParseSetCookie(w.Header().Get("Set-Cookie"))
	if assert.NoError(t, err) {
		assert.Equal(t, fmt.Sprintf("%s|%s", pr.cookie.Name, redir.Query().Get("state")), c.Name)
	}
}

func TestOIDCAuthorizer_ServeHTTP_WithBearerAuthentication_NoPolicy(t *testing.T) {
	auth := &OIDCMiddleware{
		m: Defer(func() (*Authorizer, error) {
			return GenerateTestAuthorizer(), nil
		}),
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+GenerateTestJWTUnsigned())
	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	assert.ErrorIs(t, err, ErrAccessDenied)
}

func TestOIDCAuthorizer_ServeHTTP_WithBearerAuthentication_AllowUser(t *testing.T) {
	pr := GenerateTestAuthorizer()
	auth := &OIDCMiddleware{
		Policies: PolicySet{
			&Policy{
				Action: Allow,
				RequestMatcher: RequestMatcher{
					User: []Wildcard{"test"},
				},
			},
		},
		m: Defer(func() (*Authorizer, error) {
			return pr, nil
		}),
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+GenerateTestJWTUnsigned())
	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	assert.NoError(t, err)
	assert.Equal(t, 1, h.calls)
}

func TestOIDCAuthorizer_ServeHTTP_SetsReplacerUserID(t *testing.T) {
	pr := GenerateTestAuthorizer()
	auth := &OIDCMiddleware{
		Policies: PolicySet{
			&Policy{
				Action: Allow,
				RequestMatcher: RequestMatcher{
					User: []Wildcard{"test"},
				},
			},
		},
		m: Defer(func() (*Authorizer, error) {
			return pr, nil
		}),
	}

	var repl = caddy.NewEmptyReplacer()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+GenerateTestJWTUnsigned())
	r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl))
	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	assert.NoError(t, err)

	assert.Equal(t, repl.ReplaceAll("{http.auth.user.id}", ""), "test")
}

func TestOIDCAuthorizer_ServeHTTP_WithBearerAuthentication_AllowUser_WithDeny(t *testing.T) {
	pr := GenerateTestAuthorizer()
	auth := &OIDCMiddleware{
		Policies: PolicySet{
			&Policy{
				Action: Allow,
				RequestMatcher: RequestMatcher{
					User: []Wildcard{"test"},
				},
			},
			&Policy{
				Action: Deny,
				RequestMatcher: RequestMatcher{
					User: []Wildcard{"test"},
				},
			},
		},
		m: Defer(func() (*Authorizer, error) {
			return pr, nil
		}),
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+GenerateTestJWTUnsigned())
	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	assert.ErrorIs(t, err, ErrAccessDenied)
}
