package caddy_oidc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
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
var _ caddy.Validator = (*OIDCProviderModule)(nil)
var _ caddyfile.Unmarshaler = (*OIDCProviderModule)(nil)

// OIDCProviderModule holds the configuration for an OIDC provider
type OIDCProviderModule struct {
	Issuer                string   `json:"issuer"`
	ClientID              string   `json:"client_id"`
	SecretKey             string   `json:"secret_key"`
	RedirectURI           string   `json:"redirect_uri"`
	TLSInsecureSkipVerify bool     `json:"tls_insecure_skip_verify"`
	Cookie                *Cookies `json:"cookie"`
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
	issuer <issuer>
	client_id <client_id>
	redirect_uri <redirect_uri>
	secret_key <secret_key>
	tls_insecure_skip_verify
	discovery_url <discovery_url>
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
		case "issuer":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.Issuer = d.Val()
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
		case "tls_insecure_skip_verify":
			m.TLSInsecureSkipVerify = true
		default:
			return d.Errf("unrecognized subdirective '%s'", d.Val())
		}
	}

	caddy.Log().Info("parsed oidc provider", zap.Any("config", m))
	return nil
}

func (m *OIDCProviderModule) Provision(_ caddy.Context) error {
	var repl = caddy.NewReplacer()
	m.SecretKey = repl.ReplaceAll(m.SecretKey, "")

	if m.Cookie == nil {
		m.Cookie = new(Cookies)
		*m.Cookie = DefaultCookieOptions
	}

	return nil
}

func (m *OIDCProviderModule) Validate() error {
	if m.Issuer == "" {
		return errors.New("issuer cannot be empty")
	}
	if m.ClientID == "" {
		return errors.New("client_id cannot be empty")
	}
	if m.SecretKey == "" {
		return errors.New("secret_key cannot be empty")
	}
	if len(m.SecretKey) != 32 && len(m.SecretKey) != 64 {
		return errors.New("secret_key must be 32 or 64 bytes")
	}

	if err := m.Cookie.Validate(); err != nil {
		return err
	}

	return nil
}

// Create creates an Authenticator instance from this provider configuration.
func (m *OIDCProviderModule) Create(ctx caddy.Context) (*Authenticator, error) {
	redirectUri, err := url.Parse(m.RedirectURI)
	if err != nil {
		return nil, fmt.Errorf("invalid redirect_uri: %w", err)
	}

	log := ctx.Logger(m)

	// Set up a retryable HTTP client to inject into the provider for discovery.
	retryClient := retryablehttp.NewClient()
	retryClient.Logger = slog.New(zapslog.NewHandler(log.Core(), zapslog.WithName(log.Name()), zapslog.WithCaller(false)))
	retryClient.RetryMax = 5

	// Copy the default settings from HTTP DefaultTransport
	retryClientTransport := http.DefaultTransport.(*http.Transport).Clone()
	if m.TLSInsecureSkipVerify {
		if retryClientTransport.TLSClientConfig == nil {
			retryClientTransport.TLSClientConfig = new(tls.Config)
		}

		retryClientTransport.TLSClientConfig.InsecureSkipVerify = true
	}

	retryClient.HTTPClient = &http.Client{
		Transport: retryClientTransport,
	}

	var authorizer = &Authenticator{
		log:         log,
		redirectUri: redirectUri,
		httpClient:  retryClient.StandardClient(),
		clock:       time.Now,
		cookies:     securecookie.New([]byte(m.SecretKey), []byte(m.SecretKey)),
		cookie:      m.Cookie,
	}

	authorizer.log.Debug("performing OIDC discovery")

	providerCtx := context.WithValue(ctx, oauth2.HTTPClient, authorizer.httpClient)
	provider, err := oidc.NewProvider(providerCtx, m.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery failed: %w", err)
	}

	authorizer.log.Debug("OIDC provider discovery successful", zap.Any("discovery", provider.Endpoint()))

	authorizer.verifier = provider.Verifier(&oidc.Config{
		ClientID: m.ClientID,
		Now:      authorizer.clock,
	})

	authorizer.oauth2 = &oauth2ConfigWithHTTPClient{
		httpClient: authorizer.httpClient,
		Config: &oauth2.Config{
			ClientID:    m.ClientID,
			RedirectURL: redirectUri.String(),
			Endpoint:    provider.Endpoint(),
			// TODO configurable (offline access always?)
			Scopes: []string{oidc.ScopeOpenID},
		},
	}

	return authorizer, nil
}
