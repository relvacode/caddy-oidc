package caddy_oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/relvacode/caddy-oidc/authenticator"
	"github.com/relvacode/caddy-oidc/request"
	"github.com/relvacode/caddy-oidc/session"
	"github.com/tidwall/gjson"
)

func init() {
	caddy.RegisterModule(new(OIDCMiddleware))
	httpcaddyfile.RegisterHandlerDirective("oidc", parseCaddyfileHandler[OIDCMiddleware])
	httpcaddyfile.RegisterDirectiveOrder("oidc", httpcaddyfile.Before, "basicauth")
}

const (
	// SessionCtxKey is the context key used to store the authentication session object.
	// The context value is of type *Session.
	SessionCtxKey caddy.CtxKey = "oidc_session"
	// AuthMethodCtxKey is the context key used to store the authentication method used for the incoming request.
	// The context value is of type AuthMethod.
	AuthMethodCtxKey caddy.CtxKey = "oidc_auth_method"
)

// ErrAccessDenied is returned when the request is denied access.
var ErrAccessDenied = errors.New("access denied")

var _ caddy.Module = (*OIDCMiddleware)(nil)
var _ caddy.Provisioner = (*OIDCMiddleware)(nil)
var _ caddy.Validator = (*OIDCMiddleware)(nil)
var _ caddyfile.Unmarshaler = (*OIDCMiddleware)(nil)
var _ caddyhttp.MiddlewareHandler = (*OIDCMiddleware)(nil)

// OIDCMiddleware is a middleware that authenticates and authorizes requests based on configured rules.
// It's associated with a separately configured OIDC provider by name.
type OIDCMiddleware struct {
	ProviderName string    `json:"provider"`
	Policies     Ruleset   `json:"policies"`
	Provider     *Provider `json:"-"`
}

func (mw *OIDCMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.oidc",
		New: func() caddy.Module { return new(OIDCMiddleware) },
	}
}

// UnmarshalCaddyfile sets up the OIDCMiddleware from Caddyfile tokens.
/*
	oidc example {
		allow|deny {
			...
		}
    }
*/
func (mw *OIDCMiddleware) UnmarshalCaddyfile(dis *caddyfile.Dispenser) error {
	for dis.Next() {
		if !dis.NextArg() {
			return dis.ArgErr()
		}

		mw.ProviderName = dis.Val()

		err := mw.Policies.UnmarshalCaddyfile(dis)
		if err != nil {
			return err
		}
	}

	return nil
}

// Provision sets up the OIDCMiddleware by loading the configured OIDC provider
// and then provisioning the configured ruleset for the middleware.
// The named provider must be configured.
func (mw *OIDCMiddleware) Provision(ctx caddy.Context) error {
	val, err := ctx.AppIfConfigured(moduleID)
	if err != nil {
		return err
	}

	app := val.(*App) //nolint:forcetypeassert

	pr, ok := app.provided[mw.ProviderName]
	if !ok {
		return fmt.Errorf("oidc provider '%s' not configured", mw.ProviderName)
	}

	mw.Provider = pr

	err = mw.Policies.Provision(ctx)
	if err != nil {
		return err
	}

	return nil
}

// Validate validates the configuration of the OIDCMiddleware.
func (mw *OIDCMiddleware) Validate() error {
	return mw.Policies.Validate()
}

func (*OIDCMiddleware) setReplacerVars(repl *caddy.Replacer, session *session.Session, authMethod authenticator.AuthMethod) {
	repl.Set("http.auth.method", authMethod.String())
	repl.Set("http.auth.user.anonymous", session.Anonymous)

	if !session.Anonymous {
		repl.Set("http.auth.user.id", session.UID)
	}

	claimValues := gjson.ParseBytes(session.Claims)
	claimValues.ForEach(func(key, value gjson.Result) bool {
		var valueStringBuilder strings.Builder

		switch {
		case value.IsArray():
			for i, v := range value.Array() {
				if i > 0 {
					valueStringBuilder.WriteByte(',')
				}

				valueStringBuilder.WriteString(v.String())
			}
		default:
			valueStringBuilder.WriteString(value.String())
		}

		repl.Set("http.auth.user.claim."+key.String(), valueStringBuilder.String())

		return true
	})
}

// interceptRequest intercepts the request and performs authentication and authorization checks.
// If returns "true" if the request was handled and a response was written.
func (mw *OIDCMiddleware) interceptRequest(rw http.ResponseWriter, r *http.Request) (bool, error) {
	// Check if the request is an OAuth callback.
	// Only supported if there is a session cookie authenticator configuration.
	if r.Method == http.MethodGet {
		cookie, ok := authenticator.GetAuthenticator[*authenticator.SessionCookieAuthenticator](&mw.Provider.Authenticators)
		if ok && cookie.IsCallbackURL(r) {
			return true, cookie.HandleCallback(mw.Provider, rw, r)
		}
	}

	// Check for supported well-knowns
	if r.Method == http.MethodGet && r.URL.Path == WellKnownOAuthProtectedResourcePath {
		return true, mw.Provider.ServeHTTPOAuthProtectedResource(rw, r)
	}

	authMethod, s, err := mw.Provider.Authenticators.AuthenticateRequest(mw.Provider, rw.Header(), r)
	if err != nil {
		return false, err
	}

	// Strip the request if configured
	mw.Provider.Authenticators.StripRequest(r)

	// Set replacer vars
	if repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
		mw.setReplacerVars(repl, s, authMethod)
	}

	// Inject context vars
	ctx := context.WithValue(r.Context(), SessionCtxKey, s)
	ctx = context.WithValue(ctx, AuthMethodCtxKey, authMethod)

	r = r.WithContext(ctx)

	result, err := mw.Policies.Evaluate(r)
	if err != nil {
		return false, err
	}

	if repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
		repl.Set("http.auth.rule", result.RuleID)
		repl.Set("http.auth.result", result.Result.String())
	}

	switch result.Result {
	case EvaluationResultAllow:
		return false, nil
	case EvaluationResultExplicitDeny:
	case EvaluationResultImplicitDeny:
		// If the evaluation result is an implicit reject, then check if the session is anonymous.
		// If anonymous:
		//		Start the authorization flow if the request is likely coming from a browser (if session cookies are enabled).
		//		Otherwise, return a 401 Unauthorized error.
		if s.Anonymous {
			if r.Method == http.MethodGet && request.IsBrowserInteractive(r) {
				cookie, ok := authenticator.GetAuthenticator[*authenticator.SessionCookieAuthenticator](&mw.Provider.Authenticators)
				if ok {
					return true, cookie.StartLogin(mw.Provider, rw, r)
				}
			}

			if rs, ok := mw.Provider.ProtectedResourceMetadata(r); ok {
				rw.Header().Set("WWW-Authenticate", rs.WWWAuthenticate())
			}

			return false, caddyhttp.Error(http.StatusUnauthorized, ErrAccessDenied)
		}
	}

	return false, caddyhttp.Error(http.StatusForbidden, ErrAccessDenied)
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
// It wraps interceptRequest to handle errors to ensure any error returned is a caddyhttp.HandlerError.
// Without this, Caddy's error_directive does not properly set error replacer vars,
// which can result in HTTP 200 responses when it tries to parse `{err.status_code}`.
func (mw *OIDCMiddleware) ServeHTTP(rw http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	handled, err := mw.interceptRequest(rw, r)
	if err != nil {
		var he caddyhttp.HandlerError
		if !errors.As(err, &he) {
			he = caddyhttp.Error(http.StatusInternalServerError, err)
		}

		return he
	}

	if handled {
		return nil
	}

	return next.ServeHTTP(rw, r)
}
