package authenticator

import (
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/relvacode/caddy-oidc/session"
)

func init() {
	caddy.RegisterModule(new(BearerAuthenticator))
}

var (
	_ caddy.Module          = (*BearerAuthenticator)(nil)
	_ caddyfile.Unmarshaler = (*BearerAuthenticator)(nil)
	_ RequestAuthenticator  = (*BearerAuthenticator)(nil)
)

// BearerAuthenticator authenticates the request from a JWT found in the "Authorization" header.
type BearerAuthenticator struct {
}

func (*BearerAuthenticator) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.oidc.authenticators.bearer",
		New: func() caddy.Module {
			return new(BearerAuthenticator)
		},
	}
}

func (*BearerAuthenticator) UnmarshalCaddyfile(_ *caddyfile.Dispenser) error {
	return nil
}

func (*BearerAuthenticator) Method() AuthMethod { return AuthMethodBearer }

func (*BearerAuthenticator) AuthenticateRequest(cfg OIDCConfiguration, _ http.Header, r *http.Request) (*session.Session, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, caddyhttp.Error(http.StatusUnauthorized, ErrNoAuthentication)
	}

	parts := strings.SplitN(authHeader, " ", 2) //nolint:mnd
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return nil, caddyhttp.Error(http.StatusUnauthorized, ErrNoAuthentication)
	}

	verifier, err := cfg.GetVerifier(r.Context())
	if err != nil {
		return nil, err
	}

	id, err := verifier.Verify(r.Context(), parts[1])
	if err != nil {
		return nil, caddyhttp.Error(http.StatusUnauthorized, err)
	}

	return session.NewFromClaims(cfg.GetUsernameClaim(), id)
}

func (*BearerAuthenticator) StripRequest(r *http.Request) {
	r.Header.Del("Authorization")
}
