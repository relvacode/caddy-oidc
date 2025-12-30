package caddy_oauth2_proxy_auth

import (
	"context"
	"errors"
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

var _ caddy.Validator = (*OIDCProvider)(nil)

type OIDCProvider struct {
	log         *zap.Logger
	redirectUri *url.URL
	clock       func() time.Time
	verifier    *oidc.IDTokenVerifier
	oauth2      *oauth2.Config
	cookie      *Cookies
	cookies     *securecookie.SecureCookie
}

func (p *OIDCProvider) Validate() error {
	if p.oauth2.ClientID == "" {
		return errors.New("client_id is required")
	}
	if p.oauth2.RedirectURL == "" {
		return errors.New("redirect_uri is required")
	}
	if !p.redirectUri.IsAbs() {
		return errors.New("redirect_uri must be absolute")
	}

	if err := p.cookie.Validate(); err != nil {
		return fmt.Errorf("invalid cookie options: %w", err)
	}
	return nil
}

var _ caddy.Module = (*OIDCProviderModule)(nil)
var _ caddy.Provisioner = (*OIDCProviderModule)(nil)
var _ caddy.Validator = (*OIDCProviderModule)(nil)
var _ caddyfile.Unmarshaler = (*OIDCProviderModule)(nil)

// OIDCProviderModule holds the configuration for an OIDC provider
type OIDCProviderModule struct {
	IssuerURL   string   `json:"issuer_url"`
	ClientID    string   `json:"client_id"`
	SecretKey   string   `json:"secret_key"`
	RedirectURI string   `json:"redirect_uri"`
	Cookie      *Cookies `json:"cookie"`

	data *OIDCProvider
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

	if l := len(m.SecretKey); l != 32 && l != 64 {
		return fmt.Errorf("secret_key must be 32 or 64 bytes, got %d", l)
	}

	m.data = &OIDCProvider{
		log:         ctx.Logger(m),
		redirectUri: redirectUri,
		clock:       time.Now,
		cookies:     securecookie.New([]byte(m.SecretKey), []byte(m.SecretKey)),
		cookie:      m.Cookie,
	}

	if m.data.cookie == nil {
		m.data.cookie = new(Cookies)
		*m.data.cookie = DefaultCookieOptions
	}

	m.data.log.Debug("performing OIDC discovery")

	// Set up a retryable HTTP client to inject into the provider for discovery.
	retryClient := retryablehttp.NewClient()
	retryClient.Logger = slog.New(zapslog.NewHandler(m.data.log.Core(), zapslog.WithName(m.data.log.Name()), zapslog.WithCaller(false)))
	retryClient.RetryMax = 5
	providerCtx := context.WithValue(ctx.Context, oauth2.HTTPClient, retryClient.StandardClient())

	provider, err := oidc.NewProvider(providerCtx, m.IssuerURL)
	if err != nil {
		return fmt.Errorf("oidc discovery failed: %w", err)
	}

	m.data.log.Debug("OIDC provider discovery successful", zap.Any("discovery", provider.Endpoint()))

	m.data.verifier = provider.Verifier(&oidc.Config{
		ClientID: m.ClientID,
		Now:      m.data.clock,
	})

	m.data.oauth2 = &oauth2.Config{
		ClientID:    m.ClientID,
		RedirectURL: redirectUri.String(),
		Endpoint:    provider.Endpoint(),
		// TODO configurable (offline access always?)
		Scopes: []string{oidc.ScopeOpenID},
	}

	return nil
}

func (m *OIDCProviderModule) Validate() error {
	return m.data.Validate()
}
