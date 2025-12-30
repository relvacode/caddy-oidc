package caddy_oidc

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"github.com/hashicorp/go-retryablehttp"
	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
	"golang.org/x/oauth2"
)

func init() {
	caddy.RegisterModule(new(OIDCProviderModule))
}

var _ caddy.Module = (*OIDCProviderModule)(nil)
var _ caddy.Provisioner = (*OIDCProviderModule)(nil)
var _ caddyfile.Unmarshaler = (*OIDCProviderModule)(nil)

// OIDCProviderModule holds the configuration for an OIDC provider
type OIDCProviderModule struct {
	IssuerURL   string   `json:"issuer_url"`
	ClientID    string   `json:"client_id"`
	SecretKey   string   `json:"secret_key"`
	RedirectURI string   `json:"redirect_uri"`
	Cookie      *Cookies `json:"cookie"`

	data *Deferred[*Authorizer]
}

func (*OIDCProviderModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  ModuleID + ".provider",
		New: func() caddy.Module { return new(OIDCProviderModule) },
	}
}

// UnmarshalCaddyfile sets up the OIDCProviderModule instance from Caddyfile tokens.
/*
{
	issuer_url <issuer_url>
	client_id <client_id>
	redirect_uri <redirect_uri>
	secret_key <secret_key>
	cookie <name> | {
		name <name>
		same_site <same_site>
		insecure
		domain <domain>
		path <path>
	}
}
*/
func (m *OIDCProviderModule) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "issuer_url":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.IssuerURL = d.Val()
		case "client_id":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.ClientID = d.Val()
		case "redirect_uri":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.RedirectURI = d.Val()
		case "secret_key":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.SecretKey = d.Val()
		case "cookie":
			m.Cookie = new(Cookies)
			*m.Cookie = DefaultCookieOptions // Apply defaults
			if err := m.Cookie.UnmarshalCaddyfile(d); err != nil {
				return err
			}
		default:
			return d.Errf("unrecognized subdirective '%s'", d.Val())
		}
	}

	caddy.Log().Info("parsed oidc provider", zap.Any("config", m))
	return nil
}

// Provision initializes the OIDC verifier
func (m *OIDCProviderModule) Provision(ctx caddy.Context) error {
	redirectUri, err := url.Parse(m.RedirectURI)
	if err != nil {
		return fmt.Errorf("invalid redirect_uri: %w", err)
	}

	var repl = caddy.NewReplacer()

	m.SecretKey = repl.ReplaceAll(m.SecretKey, "")

	if l := len(m.SecretKey); l != 32 && l != 64 {
		return fmt.Errorf("secret_key must be 32 or 64 bytes, got %d", l)
	}

	m.data = Defer(func() (*Authorizer, error) {
		// TODO input validation, but it can't be done during the regular caddy Validate lifecycle at the moment

		var data = &Authorizer{
			log:         ctx.Logger(m),
			redirectUri: redirectUri,
			clock:       time.Now,
			cookies:     securecookie.New([]byte(m.SecretKey), []byte(m.SecretKey)),
			cookie:      m.Cookie,
		}

		if data.cookie == nil {
			data.cookie = new(Cookies)
			*data.cookie = DefaultCookieOptions
		}

		data.log.Debug("performing OIDC discovery")

		// Set up a retryable HTTP client to inject into the provider for discovery.
		retryClient := retryablehttp.NewClient()
		retryClient.Logger = slog.New(zapslog.NewHandler(data.log.Core(), zapslog.WithName(data.log.Name()), zapslog.WithCaller(false)))
		retryClient.RetryMax = 5
		providerCtx := context.WithValue(ctx.Context, oauth2.HTTPClient, retryClient.StandardClient())

		provider, err := oidc.NewProvider(providerCtx, m.IssuerURL)
		if err != nil {
			return nil, fmt.Errorf("oidc discovery failed: %w", err)
		}

		data.log.Debug("OIDC provider discovery successful", zap.Any("discovery", provider.Endpoint()))

		data.verifier = provider.Verifier(&oidc.Config{
			ClientID: m.ClientID,
			Now:      data.clock,
		})

		data.oauth2 = &oauth2.Config{
			ClientID:    m.ClientID,
			RedirectURL: redirectUri.String(),
			Endpoint:    provider.Endpoint(),
			// TODO configurable (offline access always?)
			Scopes: []string{oidc.ScopeOpenID},
		}

		return data, nil
	})

	return nil
}
