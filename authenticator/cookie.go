package authenticator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/relvacode/caddy-oidc/request"
	"github.com/relvacode/caddy-oidc/session"
	"golang.org/x/oauth2"
)

//go:generate go tool go-enum -f=$GOFILE --marshal

func init() {
	caddy.RegisterModule(new(SessionCookieAuthenticator))
}

const (
	defaultCookiePath  = "/"
	defaultRedirectURL = "/oauth2/callback"
)

// ErrNoIDToken is returned when an OAuth2 code exchange response does not contain an ID token.
var ErrNoIDToken = errors.New("authentication server did not return an ID token")

// OAuthAuthorizationFlowConfiguration represents the configuration required
// to implement an OAuth2 Authorization Code Flow.
type OAuthAuthorizationFlowConfiguration interface {
	OIDCConfiguration

	AuthCodeURL(ctx context.Context, state string, opts ...oauth2.AuthCodeOption) (string, error)
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
	UserInfo(ctx context.Context, tokenSource oauth2.TokenSource) (*oidc.UserInfo, error)
}

// SameSite represents the same site attribute of a cookie.
// ENUM(lax, strict, none, default = "")
type SameSite string

func (ss SameSite) HTTPSameSite() http.SameSite {
	switch ss {
	case SameSiteLax:
		return http.SameSiteLaxMode
	case SameSiteStrict:
		return http.SameSiteStrictMode
	case SameSiteNone:
		return http.SameSiteNoneMode
	case SameSiteDefault:
		return http.SameSiteDefaultMode
	default:
		return http.SameSiteDefaultMode
	}
}

func parseClaims(claims interface{ Claims(value any) error }) (map[string]json.RawMessage, error) {
	var raw = make(map[string]json.RawMessage)

	err := claims.Claims(&raw)
	if err != nil {
		return nil, err
	}

	return raw, nil
}

func extractClaims(dst, src map[string]json.RawMessage, keys ...string) {
	for _, key := range keys {
		value, ok := src[key]
		if ok {
			dst[key] = value
		}
	}
}

func extractAndVerifyIDToken(ctx context.Context, cfg OAuthAuthorizationFlowConfiguration, response *oauth2.Token) (*oidc.IDToken, error) {
	idTokenPlain, ok := response.Extra("id_token").(string)
	if !ok {
		return nil, ErrNoIDToken
	}

	verifier, err := cfg.GetVerifier(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get verifier: %w", err)
	}

	idToken, err := verifier.Verify(ctx, idTokenPlain)
	if err != nil {
		return nil, fmt.Errorf("failed to verify id_token: %w", err)
	}

	return idToken, nil
}

func extractUsernameClaim(claims map[string]json.RawMessage, name string) (string, error) {
	uidJSON, ok := claims[name]
	if !ok {
		return "", session.MissingRequiredClaimError{Claim: name}
	}

	var uid string

	err := json.Unmarshal(uidJSON, &uid)
	if err != nil {
		return "", errors.Join(
			fmt.Errorf("expected a string value for %s claim: %w", name, err),
			session.MissingRequiredClaimError{Claim: name},
		)
	}

	return uid, nil
}

var (
	_ caddy.Module          = (*SessionCookieAuthenticator)(nil)
	_ caddy.Provisioner     = (*SessionCookieAuthenticator)(nil)
	_ caddy.Validator       = (*SessionCookieAuthenticator)(nil)
	_ caddyfile.Unmarshaler = (*SessionCookieAuthenticator)(nil)
	_ RequestAuthenticator  = (*SessionCookieAuthenticator)(nil)
)

// SessionCookieAuthenticator authenticates the request from a signed cookie.
type SessionCookieAuthenticator struct {
	Name     string   `json:"name,omitempty"`
	SameSite SameSite `json:"same_site,omitempty"`
	Insecure bool     `json:"insecure,omitempty"`
	Domain   string   `json:"domain,omitempty"`
	Path     string   `json:"path,omitempty"`
	Secret   string   `json:"secret,omitempty"`
	// IDClaims are the claims to extract from the ID token.
	IDClaims []string `json:"id_claims,omitempty"`
	// Claims are the claims to extract from the user info endpoint response.
	// User info claims take precedence over ID token claims.
	Claims      []string `json:"claims,omitempty"`
	RedirectURL string   `json:"redirect_url,omitempty"`
	// MaxAge is the cookie and session lifetime. When unset or zero, the browser
	// gets a session cookie and session expiry follows the OAuth token response.
	// When set, the browser cookie uses Max-Age and session ExpiresAt is set to
	// now+MaxAge (cookie sessions do not re-validate the access token).
	MaxAge caddy.Duration `json:"max_age,omitempty"`

	secure      *securecookie.SecureCookie
	redirectURL *url.URL
}

func (*SessionCookieAuthenticator) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.oidc.authenticators.cookie",
		New: func() caddy.Module {
			return new(SessionCookieAuthenticator)
		},
	}
}

func (au *SessionCookieAuthenticator) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// If there's an argument, it must be the name (and no block follows)
	if d.NextArg() {
		au.Name = d.Val()
		if d.NextArg() || d.NextBlock(0) {
			return d.ArgErr()
		}

		return nil
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		err := au.unmarshalCookieDirective(d)
		if err != nil {
			return err
		}
	}

	return nil
}

func (au *SessionCookieAuthenticator) unmarshalCookieDirective(d *caddyfile.Dispenser) error {
	switch d.Val() {
	case "name":
		if !d.Args(&au.Name) {
			return d.ArgErr()
		}
	case "same_site":
		return au.unmarshalSameSite(d)
	case "insecure":
		au.Insecure = true
	case "domain":
		if !d.Args(&au.Domain) {
			return d.ArgErr()
		}
	case "path":
		if !d.Args(&au.Path) {
			return d.ArgErr()
		}
	case "claim":
		au.Claims = append(au.Claims, d.RemainingArgs()...)
	case "id_claim":
		au.IDClaims = append(au.IDClaims, d.RemainingArgs()...)
	case "secret":
		if !d.Args(&au.Secret) {
			return d.ArgErr()
		}
	case "redirect_url":
		if !d.Args(&au.RedirectURL) {
			return d.ArgErr()
		}
	case "max_age":
		return au.unmarshalMaxAge(d)
	default:
		return d.Errf("unrecognized cookie subdirective: %s", d.Val())
	}

	return nil
}

func (au *SessionCookieAuthenticator) unmarshalSameSite(d *caddyfile.Dispenser) error {
	if !d.NextArg() {
		return d.ArgErr()
	}

	ss, err := ParseSameSite(d.Val())
	if err != nil {
		return err
	}

	au.SameSite = ss

	return nil
}

func (au *SessionCookieAuthenticator) unmarshalMaxAge(d *caddyfile.Dispenser) error {
	if !d.NextArg() {
		return d.ArgErr()
	}

	dur, err := caddy.ParseDuration(d.Val())
	if err != nil {
		return d.Errf("invalid max_age: %v", err)
	}

	au.MaxAge = caddy.Duration(dur)

	return nil
}

func (au *SessionCookieAuthenticator) Provision(_ caddy.Context) error {
	repl := caddy.NewReplacer()

	var err error

	au.Name, err = repl.ReplaceOrErr(au.Name, true, true)
	if err != nil {
		return err
	}

	if au.Path == "" {
		au.Path = defaultCookiePath
	}

	au.Path, err = repl.ReplaceOrErr(au.Path, false, true)
	if err != nil {
		return err
	}

	au.Domain, err = repl.ReplaceOrErr(au.Domain, false, true)
	if err != nil {
		return err
	}

	au.Secret, err = repl.ReplaceOrErr(au.Secret, true, true)
	if err != nil {
		return err
	}

	if len(au.Secret) != 32 && len(au.Secret) != 64 {
		return fmt.Errorf("secret must be 32 or 64 bytes long (given %d)", len(au.Secret))
	}

	var hashKey, blockKey []byte
	if len(au.Secret) == 64 { //nolint:mnd // 64-byte secret is intentionally split into two 32-byte keys (HMAC + AES-256)
		hashKey = []byte(au.Secret[:32])
		blockKey = []byte(au.Secret[32:])
	} else {
		hashKey = []byte(au.Secret)
		blockKey = []byte(au.Secret)
	}

	au.secure = securecookie.New(hashKey, blockKey)
	au.secure.SetSerializer(&securecookie.JSONEncoder{})

	// Do not restrict max age of the cookie at the securecookie level,
	// as we will validate the session expiration time as part of the session payload.
	au.secure.MaxAge(0)

	if au.RedirectURL == "" {
		au.RedirectURL = defaultRedirectURL
	}

	au.RedirectURL, err = repl.ReplaceOrErr(au.RedirectURL, true, true)
	if err != nil {
		return err
	}

	au.redirectURL, err = url.Parse(au.RedirectURL)
	if err != nil {
		return fmt.Errorf("invalid redirect_url: %w", err)
	}

	return nil
}

func (au *SessionCookieAuthenticator) Validate() error {
	if au.Name == "" {
		return errors.New("cookie name is required")
	}

	if !au.SameSite.IsValid() {
		return fmt.Errorf("invalid cookie same_site value: %s", au.SameSite)
	}

	return nil
}

func (*SessionCookieAuthenticator) Method() AuthMethod { return AuthMethodCookie }

func (au *SessionCookieAuthenticator) AuthenticateRequest(cfg OIDCConfiguration, r *http.Request) (*session.Session, error) {
	cookiePlain, err := r.Cookie(au.Name)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return nil, caddyhttp.Error(http.StatusUnauthorized, ErrNoAuthentication)
		}

		return nil, caddyhttp.Error(http.StatusBadRequest, err)
	}

	var s session.Session

	err = au.secure.Decode(au.Name, cookiePlain.Value, &s)
	if err != nil {
		// Expired or foreign-signed cookie, treat as unauthenticated
		return nil, caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("%w: %w", ErrNoAuthentication, err))
	}

	err = s.ValidateClock(cfg.Now())
	if err != nil {
		return nil, err
	}

	return &s, nil
}

func (au *SessionCookieAuthenticator) NewCookie(value string) *http.Cookie {
	cookie := &http.Cookie{
		Name:     au.Name,
		Value:    value,
		SameSite: au.SameSite.HTTPSameSite(),
		Path:     au.Path,
		Domain:   au.Domain,
		HttpOnly: true,
		Secure:   !au.Insecure,
	}

	if au.MaxAge > 0 {
		cookie.MaxAge = int(time.Duration(au.MaxAge).Seconds())
	}

	return cookie
}

// CSRFToken is the CSRF cookie payload when perform an OAuth2 Authorization Flow.
type CSRFToken struct {
	PKCEVerifier string `json:"v"`
	RedirectURI  string `json:"r"`
}

// GetAbsRedirectURI returns the absolute redirect URI, resolving it relative to the request URL if necessary.
func (au *SessionCookieAuthenticator) GetAbsRedirectURI(r *http.Request) *url.URL {
	if au.redirectURL.IsAbs() {
		return au.redirectURL
	}

	return request.URL(r).ResolveReference(au.redirectURL)
}

// StartLogin starts the authorization flow by setting the state cookie and redirecting to the authorization endpoint.
// The state cookie is in the format of `<cookie_name>|<state>`, with the value containing the PKCE code verifier.
// The OAuth2 redirect URI is set to the configured redirect URI made absolute relative to the request URL.
func (au *SessionCookieAuthenticator) StartLogin(cfg OAuthAuthorizationFlowConfiguration, rw http.ResponseWriter, r *http.Request) error {
	var (
		state             = uuid.New().String()
		pkceVerifier      = oauth2.GenerateVerifier()
		csrfCookieName    = fmt.Sprintf("%s|%s", au.Name, state)
		csrfCookiePayload = &CSRFToken{PKCEVerifier: pkceVerifier, RedirectURI: r.RequestURI}
	)

	csrfCookieValue, err := au.secure.Encode(csrfCookieName, csrfCookiePayload)
	if err != nil {
		return err
	}

	csrfCookie := au.NewCookie(csrfCookieValue)
	csrfCookie.Name = csrfCookieName
	csrfCookie.MaxAge = 900 // 15-minute short expiry time for the CSRF cookie

	http.SetCookie(rw, csrfCookie)

	authCodeURL, err := cfg.AuthCodeURL(r.Context(), state,
		oauth2.S256ChallengeOption(pkceVerifier),
		oauth2.SetAuthURLParam("redirect_uri", au.GetAbsRedirectURI(r).String()),
	)
	if err != nil {
		return err
	}

	http.Redirect(rw, r, authCodeURL, http.StatusFound)

	return nil
}

// handleCallbackParseCSRFCookie parses the CSRF cookie from the request and returns the CSRF token payload.
// If any CSRF cookie is found, then a Set-Cookie is sent to remove the cookie from the client.
func (au *SessionCookieAuthenticator) handleCallbackParseCSRFCookie(rw http.ResponseWriter, r *http.Request) (*CSRFToken, error) {
	var csrfCookieName = fmt.Sprintf("%s|%s", au.Name, r.FormValue("state"))

	csrfCookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return nil, fmt.Errorf("invalid CSRF cookie: %w", err)
	}

	// Delete CSRF cookie
	deleteCsrfCookie := au.NewCookie("")
	deleteCsrfCookie.Name = csrfCookieName
	deleteCsrfCookie.MaxAge = -1

	http.SetCookie(rw, deleteCsrfCookie)

	var csrfToken CSRFToken

	err = au.secure.Decode(csrfCookieName, csrfCookie.Value, &csrfToken)
	if err != nil {
		return nil, fmt.Errorf("invalid CSRF cookie: %w", err)
	}

	return &csrfToken, nil
}

// handleCodeExchange performs the OAuth2 token exchange using the PKCE code Verifier.
// It then verifies the ID token, extracts claims, and returns a constructed Session.
// If any userinfo claims are requested, it also fetches and parses the userinfo response.
func (au *SessionCookieAuthenticator) handleCodeExchange(
	cfg OAuthAuthorizationFlowConfiguration,
	r *http.Request,
	pkceVerifier string,
) (*session.Session, error) {
	response, err := cfg.Exchange(r.Context(), r.FormValue("code"),
		oauth2.VerifierOption(pkceVerifier),
		oauth2.SetAuthURLParam("redirect_uri", au.GetAbsRedirectURI(r).String()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %w", err)
	}

	idToken, err := extractAndVerifyIDToken(r.Context(), cfg, response)
	if err != nil {
		return nil, err
	}

	idTokenClaims, err := parseClaims(idToken)
	if err != nil {
		return nil, fmt.Errorf("failed to parse id_token claims: %w", err)
	}

	expiresAt := idToken.Expiry
	if au.MaxAge > 0 {
		// Cookie session is self-contained (UID + claims); it does not re-check
		// the access token. Allow lifetime independent of token Expiry.
		expiresAt = cfg.Now().Add(time.Duration(au.MaxAge))
	}

	// Extract claims to store in the session cookie
	var sessionClaims = make(map[string]json.RawMessage)

	extractClaims(sessionClaims, idTokenClaims, au.IDClaims...)

	userInfo, err := cfg.UserInfo(r.Context(), oauth2.StaticTokenSource(response))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch userinfo: %w", err)
	}

	userInfoClaims, err := parseClaims(userInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse userinfo claims: %w", err)
	}

	extractClaims(sessionClaims, userInfoClaims, au.Claims...)

	uid, err := extractUsernameClaim(userInfoClaims, cfg.GetUsernameClaim())
	if err != nil {
		return nil, fmt.Errorf("failed to extract username claim from userinfo response claims: %w", err)
	}

	sessionClaimsJSON, err := json.Marshal(sessionClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal session claims: %w", err)
	}

	return &session.Session{
		UID:       uid,
		Claims:    sessionClaimsJSON,
		ExpiresAt: expiresAt.Unix(),
	}, nil
}

// IsCallbackURL returns true if the request is a callback from the authorization endpoint.
// Determined if the absolute form of the redirect URI relative to the current request
// matches the scheme, host, and path of the current request.
func (au *SessionCookieAuthenticator) IsCallbackURL(r *http.Request) bool {
	var (
		req      = request.URL(r)
		redirect = au.GetAbsRedirectURI(r)
	)

	return req.Scheme == redirect.Scheme && req.Host == redirect.Host && req.Path == redirect.Path
}

// HandleCallback handles the callback from the authorization endpoint.
func (au *SessionCookieAuthenticator) HandleCallback(cfg OAuthAuthorizationFlowConfiguration, rw http.ResponseWriter, r *http.Request) error {
	if errValue := r.FormValue("error"); errValue != "" {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("error: %s, description: %s", errValue, r.FormValue("error_description")))
	}

	csrfToken, err := au.handleCallbackParseCSRFCookie(rw, r)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	s, err := au.handleCodeExchange(cfg, r, csrfToken.PKCEVerifier)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	cookieValue, err := au.secure.Encode(au.Name, s)
	if err != nil {
		return fmt.Errorf("failed to encode session cookie: %w", err)
	}

	http.SetCookie(rw, au.NewCookie(cookieValue))

	// Redirect to the configured redirect URI
	var redirectURI = csrfToken.RedirectURI
	if redirectURI == "" {
		redirectURI = "/" // Fall back to root
	}

	http.Redirect(rw, r, redirectURI, http.StatusFound)

	return nil
}

func (au *SessionCookieAuthenticator) StripRequest(r *http.Request) {
	// Read all cookies and only keep any that aren't our session cookie
	cookies := slices.DeleteFunc(r.Cookies(), func(cookie *http.Cookie) bool {
		return cookie.Name == au.Name
	})

	// Delete any original Cookie header
	r.Header.Del("Cookie")

	// Add any remaining cookies back to the request
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
}
