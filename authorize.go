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
	caddy.RegisterModule(new(OIDCAuthorizer))
	httpcaddyfile.RegisterHandlerDirective("oidc", parseCaddyfileHandler[OIDCAuthorizer])
	httpcaddyfile.RegisterDirectiveOrder("oidc", httpcaddyfile.Before, "basicauth")
}

var ErrAccessDenied = errors.New("access denied")

var _ caddy.Module = (*OIDCAuthorizer)(nil)
var _ caddy.Provisioner = (*OIDCAuthorizer)(nil)
var _ caddy.Validator = (*OIDCAuthorizer)(nil)
var _ caddyfile.Unmarshaler = (*OIDCAuthorizer)(nil)
var _ caddyhttp.MiddlewareHandler = (*OIDCAuthorizer)(nil)

type OIDCAuthorizer struct {
	Provider string    `json:"provider"`
	Policies PolicySet `json:"policies"`

	m *Deferred[*OIDCProvider]
}

func (d *OIDCAuthorizer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.oidc_authorize",
		New: func() caddy.Module { return new(OIDCAuthorizer) },
	}
}

// UnmarshalCaddyfile sets up the OIDCAuthorizer from Caddyfile tokens.
/*
oidc example {
	allow|deny {
		...
	}
}
*/
func (d *OIDCAuthorizer) UnmarshalCaddyfile(dis *caddyfile.Dispenser) error {
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

func (d *OIDCAuthorizer) Provision(ctx caddy.Context) error {
	ctx.Logger(d).Debug("provisioning oidc_authorize middleware")

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

func (d *OIDCAuthorizer) Validate() error {
	if len(d.Policies) == 0 {
		return errors.New("at least one policy must be specified")
	}

	if !d.Policies.ContainsAllow() {
		return errors.New("no authorization policy is configured to allow access, all requests will be denied without at least one allow policy")
	}

	return nil
}

func (d *OIDCAuthorizer) ServeHTTP(rw http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
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
			return pr.StartAuthorization(rw, r)
		}

		return caddyhttp.Error(http.StatusForbidden, ErrAccessDenied)
	default:
		// impossible
		panic("invalid policy evaluation result")
	}
}
