package caddy_oidc

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/stretchr/testify/assert"
)

func Test_Caddyfile_ParseFull(t *testing.T) {
	const caddyfile = `{
	auto_https off
	oidc example1 {
		issuer https://example.org/example1
		client_id abc
		secret_key d5zXc7gk2qO7lnSWsmSTCSBQ3tqeYbNu
	}

	oidc example2 {
		issuer https://example.org/example2
		client_id abc
		secret_key d5zXc7gk2qO7lnSWsmSTCSBQ3tqeYbNu
		redirect_uri https://example2.org/_oauth/callback
		cookie {
			name _example2_session
			same_site strict
		}
	}
}

example1.org {
	oidc example1 {
		allow {
			user *
		}
	}
}

example2.org {
	oidc example2 {
		allow {
			user *@example2.org
		}
		deny {
			client 127.0.0.1/32
		}
	}
}
`

	adapter := caddyconfig.GetAdapter("caddyfile")

	configJSON, warnings, err := adapter.Adapt([]byte(caddyfile), nil)
	assert.NoError(t, err)
	assert.Empty(t, warnings)

	assert.Equal(t, string(configJSON), `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[{"match":[{"host":["example1.org"]}],"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"oidc","policies":[{"action":"allow","user":["*"]}],"provider":"example1"}]}]}],"terminal":true},{"match":[{"host":["example2.org"]}],"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"oidc","policies":[{"action":"allow","user":["*@example2.org"]},{"action":"deny","client":["127.0.0.1/32"]}],"provider":"example2"}]}]}],"terminal":true}],"tls_connection_policies":[{}],"automatic_https":{"disable":true}}}},"oidc":{"providers":{"example1":{"issuer":"https://example.org/example1","client_id":"abc","secret_key":"d5zXc7gk2qO7lnSWsmSTCSBQ3tqeYbNu"},"example2":{"issuer":"https://example.org/example2","client_id":"abc","secret_key":"d5zXc7gk2qO7lnSWsmSTCSBQ3tqeYbNu","redirect_uri":"https://example2.org/_oauth/callback","cookie":{"name":"_example2_session","same_site":"strict","path":"/"}}}}}}`)
}
