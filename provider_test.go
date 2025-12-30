package caddy_oauth2_proxy_auth

import (
	"context"
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
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
		cookie:  &DefaultCookieOptions,
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
					insecure true
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
