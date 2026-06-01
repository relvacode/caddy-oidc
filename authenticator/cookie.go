package authenticator

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"slices"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/certmagic"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/relvacode/caddy-oidc/request"
	"github.com/relvacode/caddy-oidc/session"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"go.uber.org/zap"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/oauth2"
)

//go:generate go tool go-enum -f=$GOFILE --marshal

func init() {
	caddy.RegisterModule(new(SessionCookieAuthenticator))
}

const (
	defaultCookiePath  = "/"
	defaultRedirectURL = "/oauth2/callback"

	byteSizeU64 = 8

	refreshCookieMaxAge = 30 * 24 * time.Hour
	csrfCookieMaxAge    = 15 * time.Minute
)

// ErrNoIDToken is returned when an OAuth2 code exchange response does not contain an ID token.
var ErrNoIDToken = errors.New("authentication server did not return an ID token")

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

// RefreshSession is the secure cookie JSON payload that stores refresh session information.
type RefreshSession struct {
	ID string `json:"id"`
	// Secret is the unique refresh session token secret.
	// This is used to decrypt the refresh token stored in the session storage.
	Secret []byte `json:"s"`
}

// CSRFToken is the CSRF cookie payload when perform an OAuth2 Authorization Flow.
type CSRFToken struct {
	PKCEVerifier string `json:"v"`
	RedirectURI  string `json:"r"`
}

func introspectToken(ctx context.Context, tok *oauth2.Token, cfg OIDCConfiguration) (*oidc.UserInfo, time.Time, string, error) {
	idTokenPlain, ok := tok.Extra("id_token").(string)
	if !ok {
		return nil, time.Time{}, "", ErrNoIDToken
	}

	verifier, err := cfg.GetVerifier(ctx)
	if err != nil {
		return nil, time.Time{}, "", fmt.Errorf("failed to get verifier: %w", err)
	}

	_, err = verifier.Verify(ctx, idTokenPlain)
	if err != nil {
		return nil, time.Time{}, "", fmt.Errorf("failed to verify id_token: %w", err)
	}

	userInfo, err := cfg.UserInfo(ctx, oauth2.StaticTokenSource(tok))
	if err != nil {
		return nil, time.Time{}, "", fmt.Errorf("failed to fetch userinfo: %w", err)
	}

	var expires = tok.Expiry
	if expires.IsZero() && tok.ExpiresIn > 0 {
		expires = cfg.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	}

	return userInfo, expires, tok.RefreshToken, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
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
	Name        string   `json:"name,omitempty"`
	SameSite    SameSite `json:"same_site,omitempty"`
	Insecure    bool     `json:"insecure,omitempty"`
	Domain      string   `json:"domain,omitempty"`
	Path        string   `json:"path,omitempty"`
	Secret      string   `json:"secret,omitempty"`
	Claims      []string `json:"claims,omitempty"`
	RedirectURL string   `json:"redirect_url,omitempty"`
	Refresh     bool     `json:"refresh,omitempty"`

	log         *zap.Logger
	secure      *securecookie.SecureCookie
	storage     certmagic.Storage
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
		switch d.Val() {
		case "name":
			if !d.Args(&au.Name) {
				return d.ArgErr()
			}
		case "same_site":
			if !d.NextArg() {
				return d.ArgErr()
			}

			ss, err := ParseSameSite(d.Val())
			if err != nil {
				return err
			}

			au.SameSite = ss
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
		case "secret":
			if !d.Args(&au.Secret) {
				return d.ArgErr()
			}
		case "redirect_url":
			if !d.Args(&au.RedirectURL) {
				return d.ArgErr()
			}
		case "refresh":
			au.Refresh = true
		default:
			return d.Errf("unrecognized cookie subdirective: %s", d.Val())
		}
	}

	return nil
}

func (au *SessionCookieAuthenticator) Provision(ctx caddy.Context) error {
	au.log = ctx.Logger()

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

	if au.Refresh {
		au.storage = ctx.Storage()
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

func (au *SessionCookieAuthenticator) sessionCookieName() string {
	return au.Name
}

func (au *SessionCookieAuthenticator) csrfCookieName(state string) string {
	return au.Name + "|" + state
}

// refreshCookieName returns the name of the refresh cookie.
func (au *SessionCookieAuthenticator) refreshCookieName() string {
	return au.Name + "|refresh"
}

// makeSecureCookie creates a new http.Cookie using the SessionCookieAuthenticator configuration
// from a payload to be passed to the secure cookie signer.
// If v is nil, then the cookie is given no value.
func (au *SessionCookieAuthenticator) makeSecureCookie(v any, name string) (*http.Cookie, error) {
	var value string
	if v != nil {
		var err error
		value, err = au.secure.Encode(name, v)
		if err != nil {
			return nil, fmt.Errorf("failed to encode session cookie: %w", err)
		}
	}

	//nolint:gosec // User controls whether the CSRF cookie is secure or not
	return &http.Cookie{
		Name:     name,
		Value:    value,
		SameSite: au.SameSite.HTTPSameSite(),
		Path:     au.Path,
		Domain:   au.Domain,
		HttpOnly: true,
		Secure:   !au.Insecure,
	}, nil
}

func (*SessionCookieAuthenticator) storageKeyForID(id string) string {
	return path.Join("oidc", "sessions", id)
}

// storeRefreshToken generates and stores a new refresh session into the configured storage of this authenticator.
// It assumes that this authenticator has a valid storage configuration enabled.
//
// When a refresh session is generated, a session identifier is derived
// and a 32-byte XCHACHA20-POLY1305 key is generated.
//
// The refresh token is encrypted using this key using random nonce
// and stored in the storage implementation, keyed by the unique identifier.
// Only the client has the secret needed to decrypt their refresh token.
func (au *SessionCookieAuthenticator) storeRefreshToken(ctx context.Context, hdr http.Header, refreshToken string) error {
	var (
		id     = uuid.New().String()
		secret = make([]byte, chacha20poly1305.KeySize)
		nonce  = make([]byte, chacha20poly1305.NonceSizeX)
	)

	// rand.Read never returns an error
	_, _ = rand.Read(secret)
	_, _ = rand.Read(nonce)

	aead, err := chacha20poly1305.NewX(secret)
	if err != nil {
		return fmt.Errorf("failed to create AEAD: %w", err)
	}

	// Format:
	// Unix timestamp, 32 byte None, Payload.
	// The timestamp is currently unused but may be used in the future for token expiration.
	sealed := make([]byte, byteSizeU64+chacha20poly1305.NonceSizeX, byteSizeU64+chacha20poly1305.NonceSizeX+len(refreshToken)+chacha20poly1305.Overhead)

	//nolint:gosec // int64 -> uint64 is perfectly valid
	binary.LittleEndian.PutUint64(sealed[:byteSizeU64], uint64(time.Now().Unix()))
	copy(sealed[byteSizeU64:], nonce)

	sealed = aead.Seal(sealed, nonce, []byte(refreshToken), nil)

	au.log.Debug("Storing new refresh token in persistent storage", zap.String("session_id", id))

	err = au.storage.Store(ctx, au.storageKeyForID(id), sealed)
	if err != nil {
		return fmt.Errorf("failed to store refresh token session: %w", err)
	}

	refreshSessionCookie, err := au.makeSecureCookie(&RefreshSession{ID: id, Secret: secret}, au.refreshCookieName())
	if err != nil {
		return err
	}

	refreshSessionCookie.MaxAge = int(refreshCookieMaxAge.Seconds())

	hdr.Add("Set-Cookie", refreshSessionCookie.String())

	return nil
}

// prepareSessionFromTokenExchange prepares a session from the token exchange response by extracting the userinfo claims
// and copying the claims into the session's claims field.
// The session's UID is set to the value of the userinfo claim specified by the provided OAuthAuthorizationFlowConfiguration.
func (au *SessionCookieAuthenticator) prepareSessionFromTokenExchange(cfg OIDCConfiguration, userInfo *oidc.UserInfo, idTokenExpires time.Time) (*session.Session, error) { //nolint:lll
	var jsonClaims *json.RawMessage

	err := userInfo.Claims(&jsonClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to extract claims from user info: %w", err)
	}

	uidJSON := gjson.GetBytes(*jsonClaims, cfg.GetUsernameClaim())
	if !uidJSON.Exists() || uidJSON.Type != gjson.String {
		return nil, fmt.Errorf("invalid response from user info endpoint: %w", session.MissingRequiredClaimError{Claim: cfg.GetUsernameClaim()})
	}

	s := session.Session{
		UID:       uidJSON.String(),
		Claims:    json.RawMessage(`{}`),
		ExpiresAt: idTokenExpires.Unix(),
	}

	// Copy claims
	claimValues := gjson.GetManyBytes(*jsonClaims, au.Claims...)
	for i, claimValue := range claimValues {
		if claimValue.Exists() {
			s.Claims, err = sjson.SetRawBytes(s.Claims, au.Claims[i], []byte(claimValue.Raw))
			if err != nil {
				return nil, fmt.Errorf("failed to set claim %s: %w", au.Claims[i], err)
			}
		}
	}

	return &s, nil
}

// convertOAuthTokenIntoStoredSession performs all the necessary actions to convert an OAuth2 token response into a request session.
// The OAuth2 token is introspected and used to populate the session claims and metadata.
//
// If the token contains a refresh token, then the refresh token is stored in the storage system for future use
// and an additional cookie is stored in the provided response headers.
func (au *SessionCookieAuthenticator) convertOAuthTokenIntoStoredSession(ctx context.Context, cfg OIDCConfiguration, hdr http.Header, tok *oauth2.Token) (*session.Session, error) { //nolint:lll
	userInfo, idTokenExpires, refreshToken, err := introspectToken(ctx, tok, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect token: %w", err)
	}

	s, err := au.prepareSessionFromTokenExchange(cfg, userInfo, idTokenExpires)
	if err != nil {
		return nil, err
	}

	// If the code exchange provided a refresh token to use and this authenticator is configured to use session storage,
	// then we will generate and store a new refresh session in the configured storage.
	if refreshToken != "" && au.storage != nil {
		err = au.storeRefreshToken(ctx, hdr, refreshToken)
		if err != nil {
			return nil, fmt.Errorf("failed to generate and store a refresh token session: %w", err)
		}
	}

	sessionCookie, err := au.makeSecureCookie(s, au.sessionCookieName())
	if err != nil {
		return nil, err
	}

	sessionCookie.Expires = idTokenExpires

	hdr.Add("Set-Cookie", sessionCookie.String())

	return s, nil
}

// decryptRefreshTokenFromStorage decrypts the stored refresh token in storage for the provided RefreshSession.
// It returns the plain text refresh token or an error if decryption fails.
// If present, the session is always deleted from storage.
// It does not hold a lock on the storage implementation.
// If there is no refresh token stored in the storage system, then it returns fs.ErrNotExist.
func (au *SessionCookieAuthenticator) decryptRefreshTokenFromStorage(ctx context.Context, refreshSession *RefreshSession) (string, error) {
	var storagePath = au.storageKeyForID(refreshSession.ID)

	refreshTokenSealed, err := au.storage.Load(ctx, storagePath)
	if err != nil {
		return "", fmt.Errorf("failed to load refresh token session: %w", err)
	}

	// Always drop the session from Caddy storage
	defer func() {
		_ = au.storage.Delete(ctx, storagePath)
	}()

	if len(refreshTokenSealed) < (byteSizeU64 + chacha20poly1305.NonceSizeX + chacha20poly1305.Overhead) {
		return "", errors.New("sealed refresh token session is too short")
	}

	var (
		nonce  = refreshTokenSealed[byteSizeU64 : byteSizeU64+chacha20poly1305.NonceSizeX]
		sealed = refreshTokenSealed[byteSizeU64+chacha20poly1305.NonceSizeX:]
	)

	aead, err := chacha20poly1305.NewX(refreshSession.Secret)
	if err != nil {
		return "", fmt.Errorf("failed to create AEAD: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt refresh token session: %w", err)
	}

	return string(plaintext), nil
}

// tryRefreshSession attempts to automatically refresh session credentials using the refresh session
// stored in the request cookies.
//
// If the request does not contain a refresh session cookie, or this authenticator is not configured with
// a storage implementation, then a session can never be refreshed and false is returned.
//
// If the session was successfully refreshed, then the session cookie is updated in-place with
// the new session information retrieved from the token exchange as well as storing a new refresh session
// if the exchange provided a new one.
//
// If the refresh fails due to `invalid_grant`, it assumes that the refresh token is no longer valid.
//
//nolint:funlen
func (au *SessionCookieAuthenticator) tryRefreshSession(ctx context.Context, cfg OIDCConfiguration, hdr http.Header, r *http.Request) (*session.Session, bool, error) { //nolint:lll
	if au.storage == nil {
		return nil, false, nil
	}

	refreshCookie, err := r.Cookie(au.refreshCookieName())
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return nil, false, nil
		}

		return nil, false, fmt.Errorf("failed to read refresh cookie: %w", err)
	}

	// Unless successful, delete the refresh cookie from the client
	var deleteRefreshCookie = true
	defer func() {
		if deleteRefreshCookie {
			refreshCookie, _ = au.makeSecureCookie(nil, au.refreshCookieName())
			refreshCookie.MaxAge = -1

			if refreshCookie != nil {
				hdr.Add("Set-Cookie", refreshCookie.String())
			}
		}
	}()

	var refreshSession = new(RefreshSession)

	defer func() {
		zero(refreshSession.Secret)
	}()

	err = au.secure.Decode(au.refreshCookieName(), refreshCookie.Value, refreshSession)
	if err != nil {
		return nil, false, fmt.Errorf("failed to decode refresh cookie: %w", err)
	}

	storagePath := au.storageKeyForID(refreshSession.ID)

	log := au.log.With(zap.String("session_id", refreshSession.ID))
	log.Debug("Trying to refresh session using stored refresh token")

	// Lock the storage for this session.
	// This prevents concurrent in-flight requests from attempting to refresh the same session at the same time.
	err = au.storage.Lock(ctx, storagePath)
	if err != nil {
		return nil, false, fmt.Errorf("failed to lock refresh token session: %w", err)
	}

	defer func() {
		_ = au.storage.Unlock(ctx, storagePath)
	}()

	refreshToken, err := au.decryptRefreshTokenFromStorage(ctx, refreshSession)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			log.Debug("Refresh token session is no longer valid, dropping session")

			return nil, false, nil
		}

		return nil, false, fmt.Errorf("failed to decrypt refresh token session: %w", err)
	}

	// Exchange code for ID token
	log.Debug("Found a valid refresh token, trying to refresh it with the provider")

	tok, err := cfg.Refresh(ctx, refreshToken)
	if err != nil {
		log.Debug("Refresh token is no longer valid, dropping session")

		// If the server gave an error related to the token,
		// then we should assume that the refresh token is no longer valid.
		// We don't want to make this a hard error as at this point the user should start a new login flow.
		if oe, ok := errors.AsType[*oauth2.RetrieveError](err); ok {
			switch oe.ErrorCode {
			case "invalid_grant",
				// Pocket ID specific workaround
				// https://github.com/pocket-id/pocket-id/issues/1502
				"Refresh token is invalid or expired":
				return nil, false, nil
			}
		}

		return nil, false, fmt.Errorf("failed to refresh token: %w", err)
	}

	log.Debug("Successfully refreshed token, updating session cookie with new token and refresh token")

	// At this point we have a new refresh cookie to store, so we should no longer delete the refresh cookie from the client
	deleteRefreshCookie = false

	s, err := au.convertOAuthTokenIntoStoredSession(ctx, cfg, hdr, tok)
	if err != nil {
		return nil, false, err
	}

	return s, true, nil
}

func (au *SessionCookieAuthenticator) AuthenticateRequest(cfg OIDCConfiguration, hdr http.Header, r *http.Request) (*session.Session, error) {
	cookiePlain, err := r.Cookie(au.Name)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return nil, caddyhttp.Error(http.StatusUnauthorized, ErrNoAuthentication)
		}

		return nil, caddyhttp.Error(http.StatusBadRequest, err)
	}

	var s = new(session.Session)

	err = au.secure.Decode(au.Name, cookiePlain.Value, s)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusBadRequest, err)
	}

	// It's unlikely that the browser would send a cookie set to expire at the same time the session does.
	// But for completeness of security, we will check it here too.
	err = s.ValidateClock(cfg.Now())
	if err == nil {
		// Session is still valid, so it can be returned immediately
		return s, nil
	}

	// If the session is expired, then attempt to refresh the token
	if _, ok := errors.AsType[*oidc.TokenExpiredError](err); ok {
		var (
			refreshErr error
			refreshOk  bool
		)

		s, refreshOk, refreshErr = au.tryRefreshSession(r.Context(), cfg, hdr, r)
		if refreshErr != nil {
			return nil, fmt.Errorf("failed to refresh session: %w", refreshErr)
		}

		// Only when refresh is OK do we mask the original error
		if refreshOk {
			err = nil
		}
	}

	return s, err
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
func (au *SessionCookieAuthenticator) StartLogin(cfg OIDCConfiguration, rw http.ResponseWriter, r *http.Request) error {
	var (
		state             = uuid.New().String()
		pkceVerifier      = oauth2.GenerateVerifier()
		csrfCookiePayload = &CSRFToken{PKCEVerifier: pkceVerifier, RedirectURI: r.RequestURI}
	)

	//nolint:gosec // User controls whether the CSRF cookie is secure or not
	csrfCookie, err := au.makeSecureCookie(csrfCookiePayload, au.csrfCookieName(state))
	if err != nil {
		return err
	}

	csrfCookie.MaxAge = int(csrfCookieMaxAge.Seconds())

	http.SetCookie(rw, csrfCookie)

	authCodeURL, err := cfg.AuthCodeURL(r.Context(), state,
		oauth2.S256ChallengeOption(pkceVerifier),
		oauth2.SetAuthURLParam("redirect_uri", au.GetAbsRedirectURI(r).String()),
	)
	if err != nil {
		return err
	}

	//nolint:gosec // Implicit trust in the auth code URL provided by the OIDC provider
	http.Redirect(rw, r, authCodeURL, http.StatusFound)

	return nil
}

// handleCallbackParseCSRFCookie parses the CSRF cookie from the request and returns the CSRF token payload.
// If any CSRF cookie is found, then a Set-Cookie is sent to remove the cookie from the client.
func (au *SessionCookieAuthenticator) handleCallbackParseCSRFCookie(rw http.ResponseWriter, r *http.Request) (*CSRFToken, error) {
	var csrfCookieName = au.csrfCookieName(r.FormValue("state"))

	csrfCookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return nil, fmt.Errorf("invalid CSRF cookie: %w", err)
	}

	// Delete CSRF cookie
	//nolint:gosec // User controls whether the CSRF cookie is secure or not
	deleteCsrfCookie, err := au.makeSecureCookie(nil, csrfCookieName)
	if err != nil {
		return nil, fmt.Errorf("failed to create delete CSRF cookie: %w", err)
	}

	deleteCsrfCookie.MaxAge = -1

	http.SetCookie(rw, deleteCsrfCookie)

	var csrfToken CSRFToken

	err = au.secure.Decode(csrfCookieName, csrfCookie.Value, &csrfToken)
	if err != nil {
		return nil, fmt.Errorf("invalid CSRF cookie: %w", err)
	}

	return &csrfToken, nil
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
func (au *SessionCookieAuthenticator) HandleCallback(cfg OIDCConfiguration, rw http.ResponseWriter, r *http.Request) error {
	if errValue := r.FormValue("error"); errValue != "" {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("error: %s, description: %s", errValue, r.FormValue("error_description")))
	}

	csrfToken, err := au.handleCallbackParseCSRFCookie(rw, r)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, err)
	}

	// Exchange code for ID token
	tok, err := cfg.Exchange(r.Context(), r.FormValue("code"),
		oauth2.VerifierOption(csrfToken.PKCEVerifier),
		oauth2.SetAuthURLParam("redirect_uri", au.GetAbsRedirectURI(r).String()),
	)
	if err != nil {
		return fmt.Errorf("failed to exchange code for id_token: %w", err)
	}

	_, err = au.convertOAuthTokenIntoStoredSession(r.Context(), cfg, rw.Header(), tok)
	if err != nil {
		return err
	}

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
