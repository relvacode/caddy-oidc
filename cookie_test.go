package caddy_oidc

import (
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/stretchr/testify/assert"
)

func TestCookieOptions_UnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expect    Cookies
		shouldErr bool
	}{
		{
			name:  "inline name",
			input: `cookie my_cookie`,
			expect: Cookies{
				Name: "my_cookie",
			},
		},
		{
			name: "block configuration",
			input: `cookie {
				name block_cookie
				same_site strict
				insecure
				domain example.com
				path /auth
			}`,
			expect: Cookies{
				Name:     "block_cookie",
				SameSite: SameSite{http.SameSiteStrictMode},
				Insecure: true,
				Domain:   "example.com",
				Path:     "/auth",
			},
		},
		{
			name: "invalid same_site",
			input: `cookie {
				same_site mysterious
			}`,
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)

			var o Cookies
			err := o.UnmarshalCaddyfile(d)

			if tt.shouldErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.EqualValues(t, tt.expect, o)
		})
	}
}
