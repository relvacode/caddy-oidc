package caddy_oidc

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(new(OIDCMiddleware))
	httpcaddyfile.RegisterHandlerDirective("oidc", parseCaddyfileHandler[OIDCMiddleware])
	httpcaddyfile.RegisterDirectiveOrder("oidc", httpcaddyfile.Before, "basicauth")
}

var ErrAccessDenied = errors.New("access denied")

var _ caddy.Module = (*OIDCMiddleware)(nil)
var _ caddy.Provisioner = (*OIDCMiddleware)(nil)
var _ caddy.Validator = (*OIDCMiddleware)(nil)
var _ caddyfile.Unmarshaler = (*OIDCMiddleware)(nil)
var _ caddyhttp.MiddlewareHandler = (*OIDCMiddleware)(nil)

type OIDCMiddleware struct {
	Provider string    `json:"provider"`
	Policies PolicySet `json:"policies"`

	m *Deferred[*Authorizer]
}

func (d *OIDCMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.oidc",
		New: func() caddy.Module { return new(OIDCMiddleware) },
	}
}

// UnmarshalCaddyfile sets up the OIDCMiddleware from Caddyfile tokens.
/*
oidc example {
	allow|deny {
		...
	}
}
*/
func (d *OIDCMiddleware) UnmarshalCaddyfile(dis *caddyfile.Dispenser) error {
	for dis.Next() {
		if !dis.NextArg() {
			return dis.ArgErr()
		}
		d.Provider = dis.Val()

		err := d.Policies.UnmarshalCaddyfile(dis)
		if err != nil {
			return err
		}
	}

	return nil
}

func (d *OIDCMiddleware) Provision(ctx caddy.Context) error {
	val, err := ctx.App(ModuleID)
	if err != nil {
		return err
	}

	app := val.(*App)

	p, ok := app.Providers[d.Provider]
	if !ok {
		return fmt.Errorf("oidc provider '%s' not configured", d.Provider)
	}

	d.m = p.data

	return nil
}

func (d *OIDCMiddleware) Validate() error {
	if len(d.Policies) == 0 {
		return errors.New("at least one policy must be specified")
	}

	if !d.Policies.ContainsAllow() {
		return errors.New("no authorization policy is configured to allow access, all requests will be denied without at least one allow policy")
	}

	return nil
}

func (d *OIDCMiddleware) ServeHTTP(rw http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	pr, err := d.m.Get()
	if err != nil {
		return err
	}

	// Check if the request is an OAuth callback
	if r.Method == http.MethodGet && r.URL.Path == pr.redirectUri.Path {
		return pr.HandleOauthCallback(rw, r, next)
	}

	s, err := pr.Authenticate(r)
	if err != nil {
		return err
	}

	if !s.Anonymous {
		if repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
			repl.Set("http.auth.user.id", s.Uid)
		}
	}

	e, err := d.Policies.Evaluate(r, s)
	if err != nil {
		return err
	}

	switch e {
	case Permit:
		return next.ServeHTTP(rw, r)
	case RejectExplicit:
		return caddyhttp.Error(http.StatusForbidden, ErrAccessDenied)
	case RejectImplicit:
		// If the evaluation result is an implicit reject, then check if the session is anonymous.
		// If anonymous, then start the authorization flow.
		// In other words, if not authenticated and not otherwise explicitly denied, then start the authorization flow.
		if s.Anonymous && r.Method == http.MethodGet {
			return pr.StartLogin(rw, r)
		}

		return caddyhttp.Error(http.StatusForbidden, ErrAccessDenied)
	default:
		// impossible
		panic("invalid policy evaluation result")
	}
}
