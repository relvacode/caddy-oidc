package authenticator

import (
	"errors"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/relvacode/caddy-oidc/session"
)

func init() {
	caddy.RegisterModule(new(QueryAuthenticator))
}

var (
	_ caddy.Module          = (*QueryAuthenticator)(nil)
	_ caddy.Validator       = (*QueryAuthenticator)(nil)
	_ caddyfile.Unmarshaler = (*QueryAuthenticator)(nil)
	_ RequestAuthenticator  = (*QueryAuthenticator)(nil)
)

// QueryAuthenticator authenticates a request from a JWT found in an HTTP query parameter.
type QueryAuthenticator struct {
	Query string `json:"query,omitempty"`
}

func (*QueryAuthenticator) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.oidc.authenticators.query",
		New: func() caddy.Module {
			return new(QueryAuthenticator)
		},
	}
}

func (au *QueryAuthenticator) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Args(&au.Query) {
		return d.ArgErr()
	}

	return nil
}

func (au *QueryAuthenticator) Validate() error {
	if au.Query == "" {
		return errors.New("query key cannot be empty")
	}

	return nil
}

func (*QueryAuthenticator) Method() AuthMethod { return AuthMethodQuery }

func (au *QueryAuthenticator) AuthenticateRequest(cfg OIDCConfiguration, _ http.Header, r *http.Request) (*session.Session, error) {
	queryValue := r.URL.Query().Get(au.Query)
	if queryValue == "" {
		return nil, caddyhttp.Error(http.StatusUnauthorized, ErrNoAuthentication)
	}

	verifier, err := cfg.GetVerifier(r.Context())
	if err != nil {
		return nil, err
	}

	id, err := verifier.Verify(r.Context(), queryValue)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusUnauthorized, err)
	}

	return session.NewFromClaims(cfg.GetUsernameClaim(), id)
}

func (au *QueryAuthenticator) StripRequest(r *http.Request) {
	q := r.URL.Query()
	q.Del(au.Query)

	r.URL.RawQuery = q.Encode()
}
