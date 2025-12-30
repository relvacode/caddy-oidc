package caddy_oauth2_proxy_auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

// TODO validation
// TODO bypass client ip (can it be done in caddy natively?)

func init() {
	caddy.RegisterModule(new(OIDCAuthorizer))
	httpcaddyfile.RegisterHandlerDirective("oidc", parseCaddyfileHandler[OIDCAuthorizer])
	httpcaddyfile.RegisterDirectiveOrder("oidc", httpcaddyfile.Before, "basicauth")
}

type CSRFToken struct {
	PKCEVerifier string `json:"v"`
	RedirectURI  string `json:"r"`
}

var _ caddy.Module = (*OIDCAuthorizer)(nil)
var _ caddy.Provisioner = (*OIDCAuthorizer)(nil)
var _ caddyfile.Unmarshaler = (*OIDCAuthorizer)(nil)
var _ caddyhttp.MiddlewareHandler = (*OIDCAuthorizer)(nil)

type OIDCAuthorizer struct {
	Provider string `json:"provider"`
	m        *OIDCProvider
}

func (d *OIDCAuthorizer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.oidc_authorize",
		New: func() caddy.Module { return new(OIDCAuthorizer) },
	}
}

// UnmarshalCaddyfile sets up the OIDCAuthorizer from Caddyfile tokens.
/*
oidc example
*/
func (d *OIDCAuthorizer) UnmarshalCaddyfile(dis *caddyfile.Dispenser) error {
	for dis.Next() {
		if !dis.NextArg() {
			return dis.ArgErr()
		}

		d.Provider = dis.Val()
		break
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

var ErrNoAuthorization = errors.New("no authorization provided")

// AuthIsRequired returns true the error indicates that the request is unauthenticated,
// and therefore the request should initiate the login flow before continuing.
func AuthIsRequired(err error) bool {
	var expired *oidc.TokenExpiredError
	return err != nil && (errors.Is(err, ErrNoAuthorization) || errors.As(err, &expired))
}

// SessionFromAuthorizationHeader extracts the session an access or ID token parsed from the request Authorization header.
// Returns ErrNoAuthorization if a valid token could not be found.
func (d *OIDCAuthorizer) SessionFromAuthorizationHeader(r *http.Request) (*Session, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, caddyhttp.Error(http.StatusUnauthorized, ErrNoAuthorization)
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return nil, caddyhttp.Error(http.StatusUnauthorized, ErrNoAuthorization)
	}

	id, err := d.m.verifier.Verify(r.Context(), parts[1])
	if err != nil {
		return nil, caddyhttp.Error(http.StatusUnauthorized, err)
	}

	return SessionFromIDToken(id), nil
}

func (d *OIDCAuthorizer) SessionFromCookie(r *http.Request) (*Session, error) {
	cookiePlain, err := r.Cookie(d.m.cookie.Name)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusUnauthorized, errors.Join(ErrNoAuthorization, err))
	}

	var session Session
	err = d.m.cookies.Decode(d.m.cookie.Name, cookiePlain.Value, &session)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusBadRequest, err)
	}

	// Validate the session cookie.
	// TODO refresh token exchange
	err = session.ValidateClock(d.m.clock())
	if err != nil {
		return nil, err
	}

	return &session, nil
}

// Authenticate the incoming request by either reading a token from the Authorization header or the session token,
// preferring an explicit token from the Authorization header.
func (d *OIDCAuthorizer) Authenticate(r *http.Request) (*Session, error) {
	s, err := d.SessionFromAuthorizationHeader(r)
	if err != nil && errors.Is(err, ErrNoAuthorization) {
		s, err = d.SessionFromCookie(r)
	}

	return s, err
}

// StartAuthorization starts the authorization flow by setting the state cookie and redirecting to the authorization endpoint.
// The state cookie is in the format of `<cookie_name>|<state>`, with the value containing the PKCE code verifier.
func (d *OIDCAuthorizer) StartAuthorization(w http.ResponseWriter, r *http.Request) error {
	var (
		state             = uuid.New().String()
		pkceVerifier      = oauth2.GenerateVerifier()
		csrfCookieName    = fmt.Sprintf("%s|%s", d.m.cookie.Name, state)
		csrfCookiePayload = &CSRFToken{PKCEVerifier: pkceVerifier, RedirectURI: r.RequestURI}
	)

	csrfCookieValue, err := d.m.cookies.Encode(csrfCookieName, csrfCookiePayload)
	if err != nil {
		return err
	}

	csrfCookie := d.m.cookie.New(csrfCookieValue)
	csrfCookie.Name = csrfCookieName
	csrfCookie.MaxAge = 900 // 15-minute short expiry time for the CSRF cookie

	http.SetCookie(w, csrfCookie)

	authCodeUrl := d.m.oauth2.AuthCodeURL(state,
		oauth2.S256ChallengeOption(pkceVerifier),
	)

	http.Redirect(w, r, authCodeUrl, http.StatusFound)

	return nil
}

func (d *OIDCAuthorizer) HandleOauthCallback(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	d.m.log.Info("Handling OAuth callback")

	if errValue := r.FormValue("error"); errValue != "" {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("error: %s, description: %s", errValue, r.FormValue("error_description")))
	}

	// Read CSRF state cookie
	var csrfCookieName = fmt.Sprintf("%s|%s", d.m.cookie.Name, r.FormValue("state"))

	csrfCookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid CSRF cookie: %w", err))
	}

	// Delete CSRF cookie
	deleteCsrfCookie := d.m.cookie.New("")
	deleteCsrfCookie.Name = csrfCookieName
	deleteCsrfCookie.MaxAge = -1

	http.SetCookie(w, deleteCsrfCookie)

	// Decode PKCE code verifier from CSRF cookie
	var csrfToken CSRFToken
	err = d.m.cookies.Decode(csrfCookieName, csrfCookie.Value, &csrfToken)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid CSRF cookie: %w", err))
	}

	// Exchange code for tokens
	response, err := d.m.oauth2.Exchange(r.Context(), r.FormValue("code"), oauth2.VerifierOption(csrfToken.PKCEVerifier))
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("failed to exchange token: %w", err))
	}

	idTokenPlain, ok := response.Extra("id_token").(string)
	if !ok {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("no id_token in response"))
	}

	idToken, err := d.m.verifier.Verify(r.Context(), idTokenPlain)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("failed to verify id_token: %w", err))
	}

	var session = SessionFromIDToken(idToken)

	// Attach the refresh token to the session (if one is available)
	if refreshToken, ok := response.Extra("refresh_token").(string); ok {
		session.RefreshToken = &refreshToken
	}

	// Generate the session cookie and set it
	sessionCookie, err := session.HttpCookie(d.m.cookie, d.m.cookies)
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

func (d *OIDCAuthorizer) ServeHTTP(rw http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	caddy.Log().Info("OIDCAuthorizer handling request")

	// Check if the request is an OAuth callback
	if r.URL.Path == d.m.redirectUriPath {
		return d.HandleOauthCallback(rw, r, next)
	}

	_, err := d.Authenticate(r)

	// If authentication is required and the HTTP method is GET, then initiate a login flow
	// and redirect the client to the authorization endpoint of the OIDC provider.
	if AuthIsRequired(err) && r.Method == http.MethodGet {
		return d.StartAuthorization(rw, r)
	}

	// Any other error is propagated up to caddy for handling
	if err != nil {
		return err
	}

	// TODO inject caddy username

	// Authentication succeeded
	return next.ServeHTTP(rw, r)
}
