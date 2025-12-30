package caddy_oauth2_proxy_auth

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

const ModuleID = "oidc.relvacode.github.com"

func init() {
	caddy.RegisterModule(new(App))
	httpcaddyfile.RegisterGlobalOption("oidc", parseGlobalConfig)
}

func parseGlobalConfig(d *caddyfile.Dispenser, prev any) (any, error) {
	app, ok := prev.(*App)
	if !ok {
		app = &App{
			Providers: make(map[string]*OIDCProviderModule),
		}
	}

	for d.Next() {
		if !d.NextArg() {
			return nil, d.ArgErr()
		}

		var name = d.Val()
		caddy.Log().Info("parsing oidc provider", zap.String("name", name))

		var config OIDCProviderModule
		if err := config.UnmarshalCaddyfile(d); err != nil {
			return nil, err
		}

		caddy.Log().Info("parsed named oidc provider", zap.Any("config", config))

		app.Providers[name] = &config
	}

	return httpcaddyfile.App{
		Name:  ModuleID,
		Value: caddyconfig.JSON(app, nil),
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
var _ caddy.Provisioner = (*App)(nil)

type App struct {
	Providers map[string]*OIDCProviderModule `json:"providers,omitempty"`
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
	caddy.Log().Info("provisioning oidc module", zap.Any("providers", a.Providers))
	for _, p := range a.Providers {
		if err := p.Provision(ctx); err != nil {
			return err
		}
	}
	return nil
}
