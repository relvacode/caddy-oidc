package caddy_oauth2_proxy_auth

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/stretchr/testify/assert"
)

func TestWildcard_Match(t *testing.T) {
	tests := []struct {
		pattern string
		input   string
		expect  bool
	}{
		{pattern: "*", input: "test", expect: true},
		{pattern: "test", input: "test", expect: true},
		{pattern: "test*", input: "test", expect: false},
		{pattern: "test*", input: "test1", expect: true},
		{pattern: "test*", input: "test123", expect: true},
		{pattern: "test*est", input: "testtest", expect: true},
		{pattern: "test*test", input: "testtest", expect: true},
		{pattern: "*est", input: "test", expect: true},
		{pattern: "**", input: "test", expect: true},
		{pattern: "*@example.com", input: "", expect: false},
		{pattern: "*@example.com", input: "foo@example.com", expect: true},
		{pattern: "*@example.com", input: "foo@example.bar", expect: false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			assert.Equal(t, tt.expect, Wildcard(tt.pattern).Match(tt.input))
		})
	}
}

func TestRequestMatcher_UnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expect    RequestMatcher
		shouldErr bool
	}{
		{
			name: "anonymous",
			input: `{
				anonymous
			}`,
			expect: RequestMatcher{
				Anonymous: true,
			},
		},
		{
			name: "users",
			input: `{
				user a b c
			}`,
			expect: RequestMatcher{
				User: []Wildcard{"a", "b", "c"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)

			var o RequestMatcher
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
