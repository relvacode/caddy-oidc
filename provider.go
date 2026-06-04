package caddy_oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/relvacode/caddy-oidc/authenticator"
	"github.com/relvacode/caddy-oidc/request"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// oauth2Client is an interface for the oauth2 client.
type oauth2Client interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
	Refresh(ctx context.Context, refreshToken string) (*oauth2.Token, error)
	Scopes() []string
	ClientID() string
}

// oauth2ClientTemplate wraps an oauth2.Config to inject an HTTP client instance for token exchange
// and provide request-time Caddy replacer replacement.
type oauth2ClientTemplate struct {
	httpClient  *http.Client
	template    *oauth2.Config
	tokenParams map[string]string
}

func (c *oauth2ClientTemplate) prepare(ctx context.Context) (context.Context, *oauth2.Config, error) {
	//nolint:forcetypeassert // Caddy will always provide a replacer in the context. A missing replacer will result in a panic.
	repl := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.httpClient)

	cfg := new(oauth2.Config)
	*cfg = *c.template

	var err error

	cfg.ClientSecret, err = repl.ReplaceOrErr(c.template.ClientSecret, false, true)
	if err != nil {
		return ctx, nil, fmt.Errorf("failed to replace client secret: %w", err)
	}

	return ctx, cfg, nil
}

func (c *oauth2ClientTemplate) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	ctx, cfg, err := c.prepare(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare oauth2 config: %w", err)
	}

	if len(c.tokenParams) > 0 {
		for urlParam, v := range c.tokenParams {
			//nolint:forcetypeassert // Caddy will always provide a replacer in the context. A missing replacer will result in a panic.
			pv, err := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer).ReplaceOrErr(v, false, true)
			if err != nil {
				return nil, fmt.Errorf("failed to replace token param %s: %w", urlParam, err)
			}

			opts = append(opts, oauth2.SetAuthURLParam(urlParam, pv))
		}
	}

	return cfg.Exchange(ctx, code, opts...)
}

func (c *oauth2ClientTemplate) Refresh(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	ctx, cfg, err := c.prepare(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare oauth2 config: %w", err)
	}

	return cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
}

func (c *oauth2ClientTemplate) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return c.template.AuthCodeURL(state, opts...)
}

func (c *oauth2ClientTemplate) Scopes() []string {
	return c.template.Scopes
}

func (c *oauth2ClientTemplate) ClientID() string {
	return c.template.ClientID
}

type userInfoClient interface {
	UserInfo(ctx context.Context, tokenSource oauth2.TokenSource) (*oidc.UserInfo, error)
}

type providerDiscoveryConfiguration struct {
	Verifier *oidc.IDTokenVerifier
	UserInfo userInfoClient
	OAuth2   oauth2Client
}

var _ authenticator.OIDCConfiguration = (*Provider)(nil)

// Provider holds the built configuration for an OIDC provider and authentication logic.
type Provider struct {
	Log               *zap.Logger
	Clock             func() time.Time
	Issuer            string
	UsernameClaim     string
	ProtectedResource *ProtectedResourceMetadataConfiguration
	Authenticators    authenticator.Set
	Discovery         *DeferredResult[*providerDiscoveryConfiguration]
}

func (pr *Provider) Now() time.Time           { return pr.Clock() }
func (pr *Provider) GetUsernameClaim() string { return pr.UsernameClaim }

func (pr *Provider) GetVerifier(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	discovery, err := pr.Discovery.Get(ctx)
	if err != nil {
		return nil, err
	}

	return discovery.Verifier, nil
}

func (pr *Provider) AuthCodeURL(ctx context.Context, state string, opts ...oauth2.AuthCodeOption) (string, error) {
	discovery, err := pr.Discovery.Get(ctx)
	if err != nil {
		return "", err
	}

	return discovery.OAuth2.AuthCodeURL(state, opts...), nil
}

func (pr *Provider) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	discovery, err := pr.Discovery.Get(ctx)
	if err != nil {
		return nil, err
	}

	return discovery.OAuth2.Exchange(ctx, code, opts...)
}

func (pr *Provider) Refresh(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	discovery, err := pr.Discovery.Get(ctx)
	if err != nil {
		return nil, err
	}

	return discovery.OAuth2.Refresh(ctx, refreshToken)
}

func (pr *Provider) UserInfo(ctx context.Context, tokenSource oauth2.TokenSource) (*oidc.UserInfo, error) {
	discovery, err := pr.Discovery.Get(ctx)
	if err != nil {
		return nil, err
	}

	return discovery.UserInfo.UserInfo(ctx, tokenSource)
}

// ProtectedResourceMetadata returns the OAuth protected resource metadata for this authenticator.
// If protected resource metadata is not enabled, then false is returned.
func (pr *Provider) ProtectedResourceMetadata(r *http.Request) (*OAuthProtectedResource, bool) {
	if pr.ProtectedResource.Disable {
		return nil, false
	}

	discovery, err := pr.Discovery.Get(r.Context())
	if err != nil {
		return nil, false
	}

	var (
		requestURL = request.URL(r)
		metadata   = &OAuthProtectedResource{
			Resource:        fmt.Sprintf("%s://%s", requestURL.Scheme, requestURL.Host),
			ScopesSupported: discovery.OAuth2.Scopes(),
			AuthorizationServers: []string{
				pr.Issuer,
			},
			// OIDC middleware only supports bearer authentication via the Authorization header
			BearerMethodsSupported: []string{
				"header",
			},
		}
	)

	if pr.ProtectedResource.Audience {
		metadata.Audience = discovery.OAuth2.ClientID()
	}

	return metadata, true
}

// WellKnownOAuthProtectedResourcePath is the path for the OAuth protected resource metadata endpoint.
const WellKnownOAuthProtectedResourcePath = "/.well-known/oauth-protected-resource"

// ServeHTTPOAuthProtectedResource returns the OAuth protected resource metadata for the endpoint
// .well-known/oauth-protected-resource.
// If the endpoint is disabled, then a 404 not found response is returned.
func (pr *Provider) ServeHTTPOAuthProtectedResource(rw http.ResponseWriter, r *http.Request) error {
	metadata, ok := pr.ProtectedResourceMetadata(r)
	if !ok {
		return caddyhttp.Error(http.StatusNotFound, errors.New("protected resource metadata is disabled"))
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)

	enc := json.NewEncoder(rw)
	enc.SetIndent("", "  ")

	return enc.Encode(metadata)
}
