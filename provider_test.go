package caddy_oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/gorilla/securecookie"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jws"
)

type AlwaysValidKeySet struct {
}

func (AlwaysValidKeySet) VerifySignature(ctx context.Context, jwt string) (payload []byte, err error) {
	j, err := jose.ParseSigned(jwt, []jose.SignatureAlgorithm{"none"})
	if err != nil {
		return nil, err
	}
	return j.UnsafePayloadWithoutVerification(), nil
}

func GenerateTestJWTUnsigned() string {
	j, _ := jws.EncodeWithSigner(&jws.Header{
		Algorithm: "none",
	}, &jws.ClaimSet{
		Sub: "test",
		Iss: "http://openid/example",
		Aud: "xyz",
	}, func(data []byte) (sig []byte, err error) {
		return []byte{}, nil
	})
	return j
}

func GenerateTestProvider() *OIDCProvider {
	return &OIDCProvider{
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

func TestOIDCProvider_UnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		shouldErr bool
		expect    *OIDCProviderModule
	}{
		{
			name: "full configuration",
			input: `{
				issuer_url http://openid/example
				client_id xyz
				redirect_uri http://localhost/oauth/callback
				secret_key 7DFSrbya1rvBBmcaxD
				cookie {
					name session_id
					same_site strict
					insecure
				}
			}`,
			shouldErr: false,
			expect: &OIDCProviderModule{
				IssuerURL:   "http://openid/example",
				ClientID:    "xyz",
				RedirectURI: "http://localhost/oauth/callback",
				SecretKey:   "7DFSrbya1rvBBmcaxD",
				Cookie: &Cookies{
					Name:     "session_id",
					SameSite: http.SameSiteStrictMode,
					Insecure: true,
					Path:     "/",
				},
			},
		},
		{
			name: "missing issuer_url argument",
			input: `{
				issuer_url
			}`,
			shouldErr: true,
		},
		{
			name: "invalid cookie same_site",
			input: `{
				cookie {
					same_site invalid
				}
			}`,
			shouldErr: true,
		},
		{
			name: "unknown directive",
			input: `{
				unknown_directive foo
			}`,
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := new(OIDCProviderModule)
			d := caddyfile.NewTestDispenser(tt.input)

			err := p.UnmarshalCaddyfile(d)

			if tt.shouldErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.EqualValues(t, tt.expect, p)
		})
	}
}

func TestOIDCProvider_Authenticate_WithBearerAuthentication(t *testing.T) {
	pr := GenerateTestProvider()

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+GenerateTestJWTUnsigned())

	s, err := pr.Authenticate(r)
	if assert.NoError(t, err) {
		assert.Equal(t, "test", s.Uid)
	}
}

func TestOIDCProvider_Authenticate_WithSessionCookie(t *testing.T) {
	pr := GenerateTestProvider()

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

func TestOIDCProvider_Authenticate_WithSessionCookie_SignedByOther(t *testing.T) {
	pr := GenerateTestProvider()

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

func TestOIDCProvider_SessionFromCookie(t *testing.T) {
	pr := GenerateTestProvider()

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
