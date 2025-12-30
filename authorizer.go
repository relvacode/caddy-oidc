package caddy_oidc

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

var ErrNoAuthorization = errors.New("no authorization provided")

type CSRFToken struct {
	PKCEVerifier string `json:"v"`
	RedirectURI  string `json:"r"`
}

type Authorizer struct {
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
func (au *Authorizer) SessionFromAuthorizationHeader(r *http.Request) (*Session, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, caddyhttp.Error(http.StatusUnauthorized, ErrNoAuthorization)
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return nil, caddyhttp.Error(http.StatusUnauthorized, ErrNoAuthorization)
	}

	id, err := au.verifier.Verify(r.Context(), parts[1])
	if err != nil {
		return nil, caddyhttp.Error(http.StatusUnauthorized, err)
	}

	return SessionFromIDToken(id), nil
}

// SessionFromCookie extracts the session from the secure request cookie.
// Returns ErrNoAuthorization if the cookie is not found or a signed token does exist but is not expired.
func (au *Authorizer) SessionFromCookie(r *http.Request) (*Session, error) {
	cookiePlain, err := r.Cookie(au.cookie.Name)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusUnauthorized, errors.Join(ErrNoAuthorization, err))
	}

	var session Session
	err = au.cookies.Decode(au.cookie.Name, cookiePlain.Value, &session)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusBadRequest, err)
	}

	// Validate the session cookie.
	// TODO refresh token exchange
	err = session.ValidateClock(au.clock())
	if err != nil {
		return nil, err
	}

	return &session, nil
}

// AuthFromRequestSources are request token sources that are expected to return a valid non-anonymous non-expired session if the error is not-nil.
// Returning ErrNoAuthorization or *oidc.TokenExpiredError indicates that no valid token was found.
// Any other error is returned directly.
var AuthFromRequestSources = []func(*Authorizer, *http.Request) (*Session, error){
	(*Authorizer).SessionFromAuthorizationHeader,
	(*Authorizer).SessionFromCookie,
}

// Authenticate the incoming request by either reading a token from the Authorization header or the session token,
// preferring an explicit token from the Authorization header.
func (au *Authorizer) Authenticate(r *http.Request) (*Session, error) {
	for _, source := range AuthFromRequestSources {
		s, err := source(au, r)
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

// StartLogin starts the authorization flow by setting the state cookie and redirecting to the authorization endpoint.
// The state cookie is in the format of `<cookie_name>|<state>`, with the value containing the PKCE code verifier.
func (au *Authorizer) StartLogin(w http.ResponseWriter, r *http.Request) error {
	var (
		state             = uuid.New().String()
		pkceVerifier      = oauth2.GenerateVerifier()
		csrfCookieName    = fmt.Sprintf("%s|%s", au.cookie.Name, state)
		csrfCookiePayload = &CSRFToken{PKCEVerifier: pkceVerifier, RedirectURI: r.RequestURI}
	)

	csrfCookieValue, err := au.cookies.Encode(csrfCookieName, csrfCookiePayload)
	if err != nil {
		return err
	}

	csrfCookie := au.cookie.New(csrfCookieValue)
	csrfCookie.Name = csrfCookieName
	csrfCookie.MaxAge = 900 // 15-minute short expiry time for the CSRF cookie

	http.SetCookie(w, csrfCookie)

	authCodeUrl := au.oauth2.AuthCodeURL(state,
		oauth2.S256ChallengeOption(pkceVerifier),
	)

	http.Redirect(w, r, authCodeUrl, http.StatusFound)

	return nil
}

func (au *Authorizer) HandleOauthCallback(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	if errValue := r.FormValue("error"); errValue != "" {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("error: %s, description: %s", errValue, r.FormValue("error_description")))
	}

	// Read CSRF state cookie
	var csrfCookieName = fmt.Sprintf("%s|%s", au.cookie.Name, r.FormValue("state"))

	csrfCookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid CSRF cookie: %w", err))
	}

	// Delete CSRF cookie
	deleteCsrfCookie := au.cookie.New("")
	deleteCsrfCookie.Name = csrfCookieName
	deleteCsrfCookie.MaxAge = -1

	http.SetCookie(w, deleteCsrfCookie)

	// Decode PKCE code verifier from CSRF cookie
	var csrfToken CSRFToken
	err = au.cookies.Decode(csrfCookieName, csrfCookie.Value, &csrfToken)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid CSRF cookie: %w", err))
	}

	// Exchange code for tokens
	response, err := au.oauth2.Exchange(r.Context(), r.FormValue("code"), oauth2.VerifierOption(csrfToken.PKCEVerifier))
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("failed to exchange token: %w", err))
	}

	idTokenPlain, ok := response.Extra("id_token").(string)
	if !ok {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("no id_token in response"))
	}

	idToken, err := au.verifier.Verify(r.Context(), idTokenPlain)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("failed to verify id_token: %w", err))
	}

	var session = SessionFromIDToken(idToken)

	// Attach the refresh token to the session (if one is available)
	if refreshToken, ok := response.Extra("refresh_token").(string); ok {
		session.RefreshToken = &refreshToken
	}

	// Generate the session cookie and set it
	sessionCookie, err := session.HttpCookie(au.cookie, au.cookies)
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
