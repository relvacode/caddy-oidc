package caddy_oidc

import (
	"encoding/json"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const ModuleID = "oidc"

func init() {
	caddy.RegisterModule(new(App))
	httpcaddyfile.RegisterGlobalOption("oidc", parseGlobalConfig)
}

func parseGlobalConfig(d *caddyfile.Dispenser, prev any) (any, error) {
	var app App

	switch prev := prev.(type) {
	case httpcaddyfile.App:
		err := json.Unmarshal(prev.Value, &app)
		if err != nil {
			return nil, err
		}
	case nil:
		app.Providers = make(map[string]*OIDCProviderModule)
	default:
		return nil, fmt.Errorf("conflicting global parser option for the oidc directive: %T", prev)
	}

	for d.Next() {
		if !d.NextArg() {
			return nil, d.ArgErr()
		}

		var name = d.Val()

		var config OIDCProviderModule
		if err := config.UnmarshalCaddyfile(d); err != nil {
			return nil, err
		}

		app.Providers[name] = &config
	}

	return httpcaddyfile.App{
		Name:  ModuleID,
		Value: caddyconfig.JSON(&app, nil),
	}, nil
}

func parseCaddyfileHandler[T any, Ptr interface {
	*T
	caddyfile.Unmarshaler
	caddyhttp.MiddlewareHandler
}](h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := new(T)
	err := Ptr(m).UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}

	return Ptr(m), nil
}

var _ caddy.App = (*App)(nil)
var _ caddy.Module = (*App)(nil)
var _ caddy.Validator = (*App)(nil)
var _ caddy.Provisioner = (*App)(nil)

type App struct {
	Providers map[string]*OIDCProviderModule `json:"providers,omitempty"`
	provided  map[string]*DeferredResult[*Authenticator]
}

func (*App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  ModuleID,
		New: func() caddy.Module { return new(App) },
	}
}

func (*App) Start() error { return nil }
func (*App) Stop() error  { return nil }

func (a *App) Provision(ctx caddy.Context) error {
	a.provided = make(map[string]*DeferredResult[*Authenticator], len(a.Providers))

	for k := range a.Providers {
		var p = a.Providers[k]

		err := p.Provision(ctx)
		if err != nil {
			return fmt.Errorf("failed to provision oidc provider '%s': %w", k, err)
		}

		// Built authenticator configuration is deferred as we don't want to block provision during OIDC discovery.
		// Doing so might mean discovery isn't even possible until Caddy fully initializes if the IDP is proxied by Caddy as well.
		a.provided[k] = Defer(func() (*Authenticator, error) {
			return p.Create(ctx)
		})
	}

	return nil
}

func (a *App) Validate() error {
	for k, p := range a.Providers {
		if err := p.Validate(); err != nil {
			return fmt.Errorf("oidc provider '%s' validation failed: %w", k, err)
		}
	}
	return nil
}
