package caddy_oidc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/hashicorp/go-retryablehttp"
	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
	"golang.org/x/oauth2"
)

func init() {
	caddy.RegisterModule(new(OIDCProviderModule))
}

var ErrNoAuthorization = errors.New("no authorization provided")

type CSRFToken struct {
	PKCEVerifier string `json:"v"`
	RedirectURI  string `json:"r"`
}

type OIDCProvider struct {
	log         *zap.Logger
	redirectUri *url.URL
	clock       func() time.Time
	verifier    *oidc.IDTokenVerifier
	oauth2      *oauth2.Config
	cookie      *Cookies
	cookies     *securecookie.SecureCookie
}

// SessionFromAuthorizationHeader extracts the session an access or ID token parsed from the request Authorization header.
// Returns ErrNoAuthorization if a valid token could not be found or a valid, signed token exists but is expired.
func (pr *OIDCProvider) SessionFromAuthorizationHeader(r *http.Request) (*Session, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, caddyhttp.Error(http.StatusUnauthorized, ErrNoAuthorization)
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return nil, caddyhttp.Error(http.StatusUnauthorized, ErrNoAuthorization)
	}

	id, err := pr.verifier.Verify(r.Context(), parts[1])
	if err != nil {
		return nil, caddyhttp.Error(http.StatusUnauthorized, err)
	}

	return SessionFromIDToken(id), nil
}

// SessionFromCookie extracts the session from the secure request cookie.
// Returns ErrNoAuthorization if the cookie is not found or a signed token does exist but is not expired.
func (pr *OIDCProvider) SessionFromCookie(r *http.Request) (*Session, error) {
	cookiePlain, err := r.Cookie(pr.cookie.Name)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusUnauthorized, errors.Join(ErrNoAuthorization, err))
	}

	var session Session
	err = pr.cookies.Decode(pr.cookie.Name, cookiePlain.Value, &session)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusBadRequest, err)
	}

	// Validate the session cookie.
	// TODO refresh token exchange
	err = session.ValidateClock(pr.clock())
	if err != nil {
		return nil, err
	}

	return &session, nil
}

// Authenticate the incoming request by either reading a token from the Authorization header or the session token,
// preferring an explicit token from the Authorization header.
func (pr *OIDCProvider) Authenticate(r *http.Request) (*Session, error) {
	// Each of these sources are expected to return a valid non-anonymous non-expired session if the error is not-nil.
	// Returning ErrNoAuthorization or *oidc.TokenExpiredError indicates that no valid token was found.
	// Any other error is returned directory.
	var authSources = []func(*http.Request) (*Session, error){
		pr.SessionFromAuthorizationHeader,
		pr.SessionFromCookie,
	}

	for _, source := range authSources {
		s, err := source(r)
		if err == nil {
			return s, nil
		}

		var e *oidc.TokenExpiredError
		if !errors.Is(err, ErrNoAuthorization) && !errors.As(err, &e) {
			return nil, err
		}
	}

	return AnonymousSession, nil
}

// StartAuthorization starts the authorization flow by setting the state cookie and redirecting to the authorization endpoint.
// The state cookie is in the format of `<cookie_name>|<state>`, with the value containing the PKCE code verifier.
func (pr *OIDCProvider) StartAuthorization(w http.ResponseWriter, r *http.Request) error {
	var (
		state             = uuid.New().String()
		pkceVerifier      = oauth2.GenerateVerifier()
		csrfCookieName    = fmt.Sprintf("%s|%s", pr.cookie.Name, state)
		csrfCookiePayload = &CSRFToken{PKCEVerifier: pkceVerifier, RedirectURI: r.RequestURI}
	)

	csrfCookieValue, err := pr.cookies.Encode(csrfCookieName, csrfCookiePayload)
	if err != nil {
		return err
	}

	csrfCookie := pr.cookie.New(csrfCookieValue)
	csrfCookie.Name = csrfCookieName
	csrfCookie.MaxAge = 900 // 15-minute short expiry time for the CSRF cookie

	http.SetCookie(w, csrfCookie)

	authCodeUrl := pr.oauth2.AuthCodeURL(state,
		oauth2.S256ChallengeOption(pkceVerifier),
	)

	http.Redirect(w, r, authCodeUrl, http.StatusFound)

	return nil
}

func (pr *OIDCProvider) HandleOauthCallback(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	if errValue := r.FormValue("error"); errValue != "" {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("error: %s, description: %s", errValue, r.FormValue("error_description")))
	}

	// Read CSRF state cookie
	var csrfCookieName = fmt.Sprintf("%s|%s", pr.cookie.Name, r.FormValue("state"))

	csrfCookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid CSRF cookie: %w", err))
	}

	// Delete CSRF cookie
	deleteCsrfCookie := pr.cookie.New("")
	deleteCsrfCookie.Name = csrfCookieName
	deleteCsrfCookie.MaxAge = -1

	http.SetCookie(w, deleteCsrfCookie)

	// Decode PKCE code verifier from CSRF cookie
	var csrfToken CSRFToken
	err = pr.cookies.Decode(csrfCookieName, csrfCookie.Value, &csrfToken)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid CSRF cookie: %w", err))
	}

	// Exchange code for tokens
	response, err := pr.oauth2.Exchange(r.Context(), r.FormValue("code"), oauth2.VerifierOption(csrfToken.PKCEVerifier))
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("failed to exchange token: %w", err))
	}

	idTokenPlain, ok := response.Extra("id_token").(string)
	if !ok {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("no id_token in response"))
	}

	idToken, err := pr.verifier.Verify(r.Context(), idTokenPlain)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("failed to verify id_token: %w", err))
	}

	var session = SessionFromIDToken(idToken)

	// Attach the refresh token to the session (if one is available)
	if refreshToken, ok := response.Extra("refresh_token").(string); ok {
		session.RefreshToken = &refreshToken
	}

	// Generate the session cookie and set it
	sessionCookie, err := session.HttpCookie(pr.cookie, pr.cookies)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("failed to create session cookie: %w", err))
	}

	http.SetCookie(w, sessionCookie)

	// Redirect to the configured redirect URI
	var redirectUri = csrfToken.RedirectURI
	if redirectUri == "" {
		redirectUri = "/" // Fall back to root
	}

	http.Redirect(w, r, redirectUri, http.StatusFound)

	return nil
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

	data *Deferred[*OIDCProvider]
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

	m.data = Defer(func() (*OIDCProvider, error) {
		// TODO input validation, but it can't be done during the regular caddy Validate lifecycle at the moment

		var data = &OIDCProvider{
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
