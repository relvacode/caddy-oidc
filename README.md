# Caddy OIDC

A Caddy plugin for OIDC authentication and authorization.

Inspired by [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy) but instead of requiring each application to be
configured individually, perform authentication and authorization at the Caddy level.

# Advantages over oauth2-proxy

- Avoids the need to configure each application individually, with N+1 oauth2 proxies per application
- Centralized access logging that includes user ID
- Easier integration with security tools like fail2ban, etc
- Anonymous access and client ip-based authorization rules

# Configuration

`caddy-oidc` has a global and per-route `oidc` directive.

The global directive is used to configure the OIDC provider. An example minimum configuration is shown below.

```caddyfile
{
    oidc example {
        issuer https://accounts.google.com
        client_id <client_id>
        secret_key {env.OIDC_SECRET_KEY}
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

### Global Directive

- `issuer` - The OIDC issuer URL
- `client_id` - The OIDC client ID
- `secret_key` - A secret key used to sign cookies with, must be either 32 or 64 bytes long
- `redirect_url` - (optional) The URL to redirect to after authentication. Defaults to `/oauth2/callback`. If the URL is
  relative, the fully qualified URL is constructed using the request host and protocol.
- `tls_insecure_skip_verify` - (optional) Skip TLS certificate verification with the OIDC provider.
- `scope` - (optional) The scope to request from the OIDC provider. Defaults to `openid`.
- `username` - (optional) The claim to use as the username. Defaults to `sub`.
- `cookie` - (optional) Configures the cookie used to store the authentication state.

### Cookie

Cookie configuration is used to control how the authentication session cookie is set.
The session cookie is a signed cookie containing minimal state about the user's authentication.

- `name` - The name of the cookie.
- `domain` - (optional) The domain of the cookie.
- `path` - (optional) The path of the cookie.
- `insecure` - (optional) Disable secure cookies.
- `same_site` - (optional) The samesite mode of the cookie.

The default configuration is shown below.

```caddyfile
cookie {
    name caddy
    same_site lax
    path /
}
```

## Handler Directive

The handler directive is placed on routes to provide authentication and authorization for that route.
Requests are authenticated according to the configured OIDC provider and then authorized according to access policy rules configured in the directive.

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

### Access Rules

Each access rule can be either `allow` or `deny`. Inspired by AWS IAM policies, each request must match at least one `allow` rule to be authorized.
If a request matches any `deny` rule then the request is denied.

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

Multiple conditions for a single rule are a logical AND.

```caddyfile
# Allow unauthenticated access from the local network
oidc example {
    allow {
        anonymous
        client 192.168.0.0/24
    }
}
```

#### user

The `user` rule can be used to match authenticated users by their username. The username is extracted from the OIDC claims according to the provider configuration.
One or more usernames can be specified in a space separated list and supports wildcard `*` matching.

#### anonymous

An anonymous request is one that does not contain an authentication cookie or bearer token.
This allows clients to make anonymous requests to the server where desired.

#### client

The `client` rule can be used to match requests from a specific IP address or subnet.
Supplied as a space-separated list of CIDR notation subnets or IP addresses.

#### query

The `query` rule can be used to match requests based on query parameters, either by existence or exact value.

```caddyfile
# Allow requests having api-key=xyz and/or public
allow {
  query api-key=xyz public
}
```
