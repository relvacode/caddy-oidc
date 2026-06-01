# Caddy OIDC

A Caddy plugin for OIDC authentication and authorization.

Inspired by [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy) but instead of requiring each application to be
configured individually, perform authentication and authorization at the Caddy level.

## Advantages over oauth2-proxy

- Avoids the need to configure each application individually, with N+1 oauth2 proxies per application
- Centralized access logging that includes user ID
- Easier integration with security tools like fail2ban, etc
- Anonymous access and client ip-based authorization rules
- Support for RFC9728 (OAuth 2.0 Protected Resource Metadata)

# Installation

Installation can be done either via the provided Docker image (Caddy with only caddy-oidc installed)

```
ghcr.io/relvacode/caddy-oidc:latest
```

Or by building caddy with this plugin via [xcaddy](https://github.com/caddyserver/xcaddy)

```Dockerfile
FROM caddy:builder AS builder
RUN xcaddy build \
    --with github.com/relvacode/caddy-oidc
```

# Configuration

`caddy-oidc` has a global and per-route `oidc` directive.

The global directive is used to configure the OIDC provider. An example minimum configuration is shown below.

```caddyfile
{
    oidc example {
        issuer https://accounts.google.com
        client_id "<client_id>"
    }
}
```

For confidential OIDC clients that require a client secret, use the `client_secret` directive:

```caddyfile
{
    oidc example {
        issuer https://accounts.google.com
        client_id "<client_id>"
        client_secret "{env.OIDC_CLIENT_SECRET}"
    }
}
```

Each route then uses the `oidc` directive to configure the route using the named provider

```caddyfile
example.com {
    oidc example {
        allow {
            user *
        }
    }
    reverse_proxy localhost:8080
}
```

## Global Directive

| Option                        | Description                                                                                                                                           | Default  |
|-------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|----------|
| `issuer`                      | The OIDC issuer URL                                                                                                                                   |          |
| `client_id`                   | The OIDC client ID                                                                                                                                    |          |
| `client_secret`               | (optional) The OIDC client secret for confidential clients.                                                                                           |          |
| `tls_insecure_skip_verify`    | (optional) Skip TLS certificate verification with the OIDC provider.                                                                                  |          |
| `scope`                       | (optional) The scope to request from the OIDC provider. The `openid` scope is required for browser-based login to work.                               | `openid` |
| `username`                    | (optional) The claim to use as the username. Defaults to `sub`.                                                                                       | `sub`    |
| `protected_resource_metadata` | (optional) Configure or disable RFC9728 support.                                                                                                      |          |
| `authenticate`                | (optional) Configure [authentication methods](#authentication)                                                                                        |          |
| `token_params`                | (optional) Additional key-value parameters for the OAuth code exchange. Values support Caddy placeholders. See [Token Parameters](#token-parameters). |          |

### Authentication

This module uses a plugin architecture to allow different authentication methods to be configured under the Caddy plugin
namespace `http.oidc.authenticator`.

When a request requires authentication, authentication methods are tried in the order they are configured.
The first authenticator to return a valid session from the request is used.
An expired session is ignored, and the next authenticator is tried.

#### Defaults

To use the default set of authenticators, omit any authenticator **or** use the `default` option.

```caddyfile
authenticate default
```

The default configuration is equivalent to the following

```caddyfile
authenticate bearer
authenticate cookie {
    name caddy
    secret "{env.COOKIE_SECRET}"
}
```

> [!NOTE]
> Configuring any `authenticate` handlers will override the default configuration. Use the `default` option to include
> the default configuration.

#### Require Authentication

By default, authentication is optional.
This allows access rules to determine the action to take when a request is not authenticated.

This also allows automatic redirection to the OIDC provider for authentication when the request is made by a browser.

You can disable this behavior by adding the `required` option. When enabled, any request that is not authenticated will
result in a `401 Unauthorized` response before evaluating access policy rules.

> [!NOTE]
> It's recommended to leave this option disabled and use access rules to determine the action to take when a request is
> not authenticated.

```caddyfile
authenticate required
```

#### Forwarding Authentication

By default, any authentication information from any configured authenticator
is stripped from the request before passing it upstream.
This behavior can be disabled by adding the `preserve_request` option.

```caddyfile
authenticate preserve_request
```

#### Token Parameters

The `token_params` block allows you to add arbitrary key-value parameters to the OAuth code exchange request.
Values support [Caddy placeholders](https://caddyserver.com/docs/conventions#placeholders), which are resolved at
exchange time.

This is useful for authentication flows that require extra parameters beyond the standard OAuth2 fields,
such as JWT bearer client assertions ([RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523)).

```caddyfile
token_params {
    client_assertion_type urn:ietf:params:oauth:client-assertion-type:jwt-bearer
    client_assertion {file./var/run/secrets/token}
}
```

The `{file.*}` placeholder reads its value from disk on every evaluation, making it suitable for tokens that rotate (
e.g., projected Kubernetes service account tokens).

#### Workload Identity Federation

Workload Identity Federation (WIF) allows `caddy-oidc` to authenticate with an OIDC provider **without a `client_secret`
**.
Instead, a projected Kubernetes service account token is exchanged for a provider access token using a JWT bearer
assertion ([RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523)).

This is commonly used with **Microsoft Entra ID** (Azure AD) on OpenShift or AKS clusters where a federated credential
is configured on the App Registration.

Using [`token_params`](#token-parameters) with the `{file.*}` placeholder, the projected token is re-read from the
filesystem on every token exchange, so token rotation is handled automatically.

```caddyfile
{
    oidc entra {
        issuer https://login.microsoftonline.com/{tenant}/v2.0
        client_id "<client_id>"
        token_params {
            client_assertion_type urn:ietf:params:oauth:client-assertion-type:jwt-bearer
            client_assertion {file./var/run/secrets/openshift/serviceaccount/token}
        }
        scope openid email profile
        authenticate cookie {
            name caddy
            secret "{env.COOKIE_SECRET}"
        }
    }
}
```

> [!NOTE]
> While the underlying mechanism (RFC 7523 JWT bearer client assertions) is a standard, this pattern has been tested
> with Microsoft Entra ID federated credentials. The same `token_params` approach can be adapted for other providers
> that
> accept custom parameters during the token exchange.

#### Bearer

The `bearer` authenticator is used to authenticate requests using a JWT bearer token.
The bearer JWT must be signed by the OIDC provider.

```caddyfile
authenticate bearer
```

#### Cookie

The `cookie` authenticator is used to authenticate requests using a self-signed session cookie.

| Option         | Description                                                                                                                                                 | Default            |
|----------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------|
| `name`         | The name of the cookie.                                                                                                                                     |                    |
| `secret`       | The 32 or 64 byte secret key to encrypt session cookies                                                                                                     |                    |
| `domain`       | (optional) The domain of the cookie.                                                                                                                        |                    |
| `path`         | (optional) The path of the cookie.                                                                                                                          | `/`                |
| `insecure`     | (optional) Disable secure cookies.                                                                                                                          |                    |
| `same_site`    | (optional) The samesite mode of the cookie. One of `lax`, `strict` or `none`                                                                                |                    |
| `claim`        | (optional) Claims to copy into the session cookie.                                                                                                          |                    |
| `redirect_url` | (optional) The URL to redirect to after authentication. If the URL is relative, the fully qualified URL is constructed using the request host and protocol. | `/oauth2/callback` |
| `refresh`      | (optional) Enable refresh token automation.                                                                                                                 |                    |

To minimize the size of the cookie, no claims are copied into the session cookie by default.
Claims can be copied by specifying the `claims` option if needed for access policy rules or placeholder variables (e.g.,
for logging).

Enabling session cookie authentication also enables interactive authentication through
the browser via the OAuth 2.0 Authorization Code Flow.

Automatic redirection to the OIDC provider for login happens when all the following conditions are met:

- A session cookie authenticator is configured
- The request is not authenticated
- Authentication is not required
- There is no matching explicit `allow` or `deny` rule
- The request is made by a browser, determined by:
    - `Sec-Fetch-Dest` is `document` or `iframe`
    - `Accept` header contains `text/html`

The `refresh` option enables automatic token refreshing for cookie sessions by storing the user's refresh
token in Caddy's [file system](https://caddyserver.com/docs/caddyfile/directives/fs).

When enabled and the OIDC server provides a refresh token when handling the OAuth callback,
the cookie authenticator will derive a random 32-byte key stored in the session cookie
and then encrypt the refresh token using XCHACHA20-POLY1305 with the key.
The encrypted refresh token is then stored in Caddy's configured file system under a unique session ID.

During request authentication, if the session cookie has expired and contains a refreshable token,
then the cookie authenticator will attempt to refresh the token using the refresh token
and then store the new access token in the session cookie.
During refresh, the authenticator will hold an exclusive lock on the session cookie
to prevent concurrent refresh attempts.

Only the client has the persistent secret needed to decrypt the refresh token in Caddy's persistent storage.

> [!NOTE]
> There is currently no mechanism to clean up unused refresh tokens stored in Caddy's file system.

#### Header

The `header` authenticator authenticates a JWT token passed via an incoming HTTP request header (without any prefix).

```caddyfile
authenticate header X-Api-Key
```

#### Query

The `query` authenticator authenticates a JWT token passed via an incoming HTTP request query parameter.

> [!CAUTION]
> There are several security implications to using query parameters for authentication.
> See [RFC6750](https://datatracker.ietf.org/doc/html/rfc6750#section-2.3) for more information.

```caddyfile
authenticate query access_token
```

### [RFC9728](https://datatracker.ietf.org/doc/rfc9728/) Support (`protected_resource_metadata`)

Caddy OIDC supports RFC9728 (OAuth 2.0 Protected Resource Metadata) to discover the OIDC provider metadata via the
well-known URL `/.well-known/oauth-protected-resource`.

If the request is unauthenticated, passes at least one `allow` rule, and the request is not made by a browser,
then a `401 Unauthorized` response is returned with a WWW-Authenticate header conforming
to [WWW-Authenticate Response](https://datatracker.ietf.org/doc/html/rfc9728#section-5.1).

Settings can be controlled via the `oidc` directive `protected_resource_metadata`. The default behavior is to enable.

```caddyfile
# Disable RFC9728 support.
# This makes /.well-known/oauth-protected-resource return a 404 Not Found.
protected_resource_metadata off
```

#### Audience

As a custom extension to the standard,
resource metadata can be configured to include the expected token audience (`aud`) claim.

If enabled, the metadata response will contain an additional `audience` field containing the configured client ID of the
OIDC provider configuration.

This is designed as an alternative to dynamic client registration to let another client (e.g. a CLI)
use [JWT Exchange](https://datatracker.ietf.org/doc/html/rfc7523#section-8.2) with its own token with the OIDC provider
and
make requests to this server without prior knowledge of this server's OAuth configuration.

```caddyfile
# Include the expected audience field in the metadata
protected_resource_metadata {
    audience
}
```

## Handler Directive

The handler directive is placed on routes to provide authentication and authorization for that route.
Requests are authenticated according to the configured OIDC provider and then authorized according to access policy
rules configured in the directive.

The handler directive **must** contain at least one `allow` rule.

```caddyfile
# Allow any valid authenticated user

example.com {
    oidc example {
        allow {
            user *
        }
    }
    reverse_proxy localhost:8080
}
```

If the request is unauthenticated, and there is not an explicit `allow` or `deny` rule that matches the request,
and the request is made by a browser, then the browser will be automatically redirected to the OIDC provider for
authentication.

### Access Rules

Each access rule can be either `allow` or `deny`. Inspired by AWS IAM policies, each request must match at least one
`allow` rule to be authorized.

Access rules match using Caddy's regular [request matchers](https://caddyserver.com/docs/caddyfile/matchers).
Additional [HTTP matchers](#http-matchers) are provided for authentication-specific request matching.

> [!CAUTION]
> Without an explicit [user](#user) match in an `allow` policy rule, all requests will be allowed, even anonymous
> request unless `authenticate required` is enabled.

If a request matches any `deny` rule then the request is denied, even if another `allow` rule matches.

```caddyfile
# Allow any authenticated user from example.com except from steve

oidc example {
    allow {
        user *@example.com
    }
    deny {
        user steve@example.com
    }
}
```

Access rules can be optionally named for logging, if matched then the rule ID will be available as the placeholder
variable `{http.auth.rule}`.

```caddyfile
oidc example {
    deny "DenyAnonymousAccess" {
        anonymous
    }
    allow "AllowAnyUserReadAccess" {
        method GET HEAD
        user *
        claim role read
    }
    allow "AllowAdminWriteAccess" {
        method POST PUT PATCH DELETE
        user *
        claim role write
    }
}
```

## HTTP Matchers

In addition to the standard Caddy request matchers, the following matchers are provided.
These matchers are only compatible with HTTP requests handled by the handler directive.

### User

Matches the username of the authenticated user. A user match will never match an anonymous user.

```caddyfile
# Allow any authenticated user

allow {
    user *
}
```

```caddyfile
# Allow any authenticated user from example.com

allow {
    user *@example.com
}
```

```caddyfile
# Allow multiple users

allow {
    user steve
    user bob
    user john
}
```

### Anonymous

Matches request sessions that are anonymous.
Anonymous sessions are sessions that have not been authenticated by the OIDC provider.

```caddyfile
# Allow anonymous requests to /healthcheck

allow {
    anonymous
    path /healthcheck
}
```

### Claim

Matches claims in the request session.

If the session claim is an array, then the request must match at least one value in the array.
Any non-string claim values are ignored and will not match.

Multiple values for a single claim directive are treated as a logical OR. If no values are specified,
the matcher only checks for the claim's existence.

> [!NOTE]
> Any claims used here must be configured in the `cookie` authenticator if used.

```caddyfile
# Allow requests containing role = write

allow {
    claim role write
}
```

```caddyfile
# Allow requests containing role = read OR role = write

allow {
    claim role read write
}
```

```caddyfile
# Allow requests containing role = read AND role = write

allow {
    claim role read
    claim role write
}
```

```caddyfile
# Allow requests containing sub = steve@example.com AND role = read

allow {
    claim sub steve@example.com
    claim role read
}
```

```caddyfile
# Deny all requests missing the 'role' claim

deny {
    not {
        claim role
    }
}
```

Replacer variables are supported in both claim name and claim value.

```caddyfile
# Allow requests containing host = {http.host}

allow {
    claim host {http.host}
}
```

Wildcard matching is also supported in claim values.

```caddyfile
# Allow requests where the role claim starts with "read:"

allow {
    claim role read:*
}
```

### Auth Method

Matches the authentication method used to authenticate the request.

Possible values are

- `cookie` - The request was authenticated using a session cookie
- `bearer` - The request was authenticated using a bearer JWT token
- `header` - The request was authenticated using a JWT token passed in an HTTP header
- `query` - The request was authenticated using a JWT token passed in a query parameter
- `none` - The request was not authenticated

```caddyfile
# Deny all requests using JWT bearer authentication

deny {
    auth_method bearer
}
```

# Placeholder Variables

When a request passes through the `oidc` handler, the
following [placeholder](https://caddyserver.com/docs/conventions#placeholders) variables are available:

| Placeholder                | Description                                                                                 |
|----------------------------|---------------------------------------------------------------------------------------------|
| `http.auth.user.id`        | The username extracted from the `username` option of the global directive                   |
| `http.auth.user.anonymous` | `true` if the session is not authenticated otherwise `false`                                |
| `http.auth.method`         | The authentication method of the request. One of the available [auth methods](#auth-method) |
| `http.auth.user.claim.*`   | Set for each claim provided by the matched authenticator                                    |
| `http.auth.rule`           | The named access policy rule that matched the request                                       |
| `http.auth.result`         | The acccess rule evaluation result. One of `allow`, `implicit deny` or `explicit deny`      |

Because the `oidc` handler is ordered after the `header` handler, to set these variables in response headers, you must
use the `defer` option

```caddyfile
header X-User-Claim-Email {http.auth.user.claim.email} {
    defer
}
```

## Claim Value Formatting

- Simple values like strings, booleans, and numbers are formatted as plain values
- Null values are empty
- Objects are formatted as JSON
- Arrays are formatted using the above rules for each element, joined by commas. Nested arrays are formatted as JSON

