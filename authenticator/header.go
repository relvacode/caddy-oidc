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
	caddy.RegisterModule(new(HeaderAuthenticator))
}

var (
	_ caddy.Module          = (*HeaderAuthenticator)(nil)
	_ caddy.Validator       = (*HeaderAuthenticator)(nil)
	_ caddyfile.Unmarshaler = (*HeaderAuthenticator)(nil)
	_ RequestAuthenticator  = (*HeaderAuthenticator)(nil)
)

// HeaderAuthenticator authenticates a request from a JWT found in a named HTTP request header.
type HeaderAuthenticator struct {
	Header string `json:"header,omitempty"`
}

func (*HeaderAuthenticator) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.oidc.authenticators.header",
		New: func() caddy.Module {
			return new(HeaderAuthenticator)
		},
	}
}

func (au *HeaderAuthenticator) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Args(&au.Header) {
		return d.ArgErr()
	}

	return nil
}

func (au *HeaderAuthenticator) Validate() error {
	if au.Header == "" {
		return errors.New("header name cannot be empty")
	}

	return nil
}

func (*HeaderAuthenticator) Method() AuthMethod { return AuthMethodHeader }

func (au *HeaderAuthenticator) AuthenticateRequest(cfg OIDCConfiguration, _ http.Header, r *http.Request) (*session.Session, error) {
	headerValue := r.Header.Get(au.Header)
	if headerValue == "" {
		return nil, caddyhttp.Error(http.StatusUnauthorized, ErrNoAuthentication)
	}

	verifier, err := cfg.GetVerifier(r.Context())
	if err != nil {
		return nil, err
	}

	id, err := verifier.Verify(r.Context(), headerValue)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusUnauthorized, err)
	}

	return session.NewFromClaims(cfg.GetUsernameClaim(), id)
}

func (au *HeaderAuthenticator) StripRequest(r *http.Request) {
	r.Header.Del(au.Header)
}
