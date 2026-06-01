// Package authenticator provides a modular plugin interface
// for providing authentication mechanisms to the caddy-oidc plugin.
// Including a built-in set of authenticators for working with most authentication sources from HTTP requests.
package authenticator

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/relvacode/caddy-oidc/session"
	"github.com/tidwall/sjson"
	"golang.org/x/oauth2"
)

//go:generate go tool go-enum -f=$GOFILE --marshal

// AuthMethod represents one of the supported authentication methods.
// ENUM(none, bearer, cookie, header, query)
type AuthMethod string

// ErrNoAuthentication is returned when no valid authentication could be found in the request.
var ErrNoAuthentication = errors.New("no valid authentication credentials provided")

// OIDCConfiguration represents the configuration required to authenticate incoming requests
// using configuration from an OIDC provider.
type OIDCConfiguration interface {
	// Now returns the current time according to the OIDC configuration clock.
	Now() time.Time
	// GetVerifier returns the ID token verifier configured for the OIDC provider.
	GetVerifier(ctx context.Context) (*oidc.IDTokenVerifier, error)
	// GetUsernameClaim returns the claim name used to extract the username from the ID token.
	GetUsernameClaim() string

	AuthCodeURL(ctx context.Context, state string, opts ...oauth2.AuthCodeOption) (string, error)
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
	Refresh(ctx context.Context, refreshToken string) (*oauth2.Token, error)
	UserInfo(ctx context.Context, tokenSource oauth2.TokenSource) (*oidc.UserInfo, error)
}

// A RequestAuthenticator extracts authentication information from an incoming request.
type RequestAuthenticator interface {
	// Method returns the authentication method type provided by this RequestAuthenticator
	Method() AuthMethod

	// AuthenticateRequest extracts authentication session information from the incoming request.
	// If the request does not contain valid authentication, then it must return ErrNoAuthentication.
	// AuthenticateRequest may read and write to the provided HTTP request header.
	AuthenticateRequest(cfg OIDCConfiguration, hdr http.Header, r *http.Request) (*session.Session, error)

	// StripRequest removes any authentication information from the request.
	StripRequest(r *http.Request)
}

var (
	_ caddyfile.Unmarshaler = (*Set)(nil)
	_ caddy.Provisioner     = (*Set)(nil)
	_ caddy.Validator       = (*Set)(nil)
)

// Set contains an ordered list of RequestAuthenticator implementations.
type Set struct {
	AuthenticatorsRaw []json.RawMessage      `caddy:"namespace=http.oidc.authenticators inline_key=authenticator" json:"authenticators"`
	Authenticators    []RequestAuthenticator `json:"-"`
	PreserveRequest   bool                   `json:"preserve_request,omitzero"`
	Required          bool                   `json:"required,omitempty"`
}

// Default returns the JSON configuration for the default set of authenticators.
//
//nolint:gochecknoglobals
var defaults = []json.RawMessage{
	json.RawMessage(`{"authenticator": "bearer"}`),
	json.RawMessage(`{"authenticator": "cookie", "name": "caddy", "secret": "{env.COOKIE_SECRET}"}`),
}

func (set *Set) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	type RequestAuthenticatorAndCaddyfileUnmarshaler interface {
		caddyfile.Unmarshaler
		RequestAuthenticator
	}

	for nesting := d.Nesting(); d.NextArg() || d.NextBlock(nesting); {
		directive := d.Val()

		switch directive {
		case "preserve_request":
			set.PreserveRequest = true

			continue

		case "default":
			set.AuthenticatorsRaw = append(set.AuthenticatorsRaw, defaults...)

			continue

		case "required":
			set.Required = true

			continue
		}

		mod, err := caddy.GetModule("http.oidc.authenticators." + directive)
		if err != nil {
			return d.Errf("getting authenticator module '%s': %v", directive, err)
		}

		unm, ok := mod.New().(RequestAuthenticatorAndCaddyfileUnmarshaler)
		if !ok {
			return d.Errf("authenticator module '%s' is not a Caddyfile unmarshaler", directive)
		}

		err = unm.UnmarshalCaddyfile(d)
		if err != nil {
			return err
		}

		jsonBytes, err := json.Marshal(unm)
		if err == nil {
			jsonBytes, err = sjson.SetBytes(jsonBytes, "authenticator", directive)
		}

		if err != nil {
			return d.Errf("marshaling authenticator module '%s': %v", directive, err)
		}

		set.AuthenticatorsRaw = append(set.AuthenticatorsRaw, jsonBytes)
	}

	return nil
}

func (set *Set) Provision(ctx caddy.Context) error {
	if len(set.AuthenticatorsRaw) == 0 {
		set.AuthenticatorsRaw = slices.Clone(defaults)
	}

	modules, err := ctx.LoadModule(set, "AuthenticatorsRaw")
	if err != nil {
		return err
	}

	for _, mod := range modules.([]any) { //nolint:forcetypeassert
		impl, ok := mod.(RequestAuthenticator)
		if !ok {
			return errors.New("loaded module is not a valid RequestAuthenticator implementation")
		}

		set.Authenticators = append(set.Authenticators, impl)
	}

	return nil
}

func (set *Set) Validate() error {
	if len(set.Authenticators) == 0 {
		return errors.New("no request authenticators configured")
	}

	return nil
}

// AuthenticateRequest attempts to authenticate the request using the configured authenticators.
// It returns the first successful authentication method and session.
//
// Any ErrNoAuthentication or oidc.TokenExpiredError errors are ignored, and the next authenticator in the sequence is tried.
// If no authenticators succeed and Required is set, then ErrNoAuthentication is returned.
// Otherwise, an anonymous session is returned.
func (set *Set) AuthenticateRequest(cfg OIDCConfiguration, hdr http.Header, r *http.Request) (AuthMethod, *session.Session, error) {
	for _, authenticator := range set.Authenticators {
		s, err := authenticator.AuthenticateRequest(cfg, hdr, r)
		if err == nil {
			return authenticator.Method(), s, nil
		}

		var ee *oidc.TokenExpiredError
		if !errors.Is(err, ErrNoAuthentication) && !errors.As(err, &ee) {
			return AuthMethodNone, nil, err
		}
	}

	// If authentication is required and no authenticators succeed, return unauthorized
	if set.Required {
		return AuthMethodNone, session.Anonymous(), caddyhttp.Error(http.StatusUnauthorized, ErrNoAuthentication)
	}

	return AuthMethodNone, session.Anonymous(), nil
}

// StripRequest removes any authentication information from the request.
// If PreserveRequest is set, then this method does nothing.
func (set *Set) StripRequest(r *http.Request) {
	if set.PreserveRequest {
		return
	}

	for _, authenticator := range set.Authenticators {
		authenticator.StripRequest(r)
	}
}

// GetAuthenticator returns the first RequestAuthenticator in the set equal to the requested type.
func GetAuthenticator[T RequestAuthenticator](set *Set) (T, bool) {
	findType := reflect.TypeOf(*new(T))
	for _, authenticator := range set.Authenticators {
		if reflect.TypeOf(authenticator) == findType {
			return authenticator.(T), true //nolint:forcetypeassert
		}
	}

	return *new(T), false
}
