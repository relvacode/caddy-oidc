package caddy_oidc

import (
	"context"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
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
	var bar = "bar"
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
		{
			name: "clients",
			input: `{
				client 192.168.0.1/24 10.0.0.0/8 1.1.1.1
			}`,
			expect: RequestMatcher{
				Client: []IpRange{
					{Prefix: netip.MustParsePrefix("192.168.0.0/24")},
					{Prefix: netip.MustParsePrefix("10.0.0.0/8")},
					{Prefix: netip.MustParsePrefix("1.1.1.1/32")},
				},
			},
		},
		{
			name: "query",
			input: `{
query foo=bar bar
}`,
			expect: RequestMatcher{
				Query: []*RequestValue{
					{Name: "foo", Value: &bar},
					{Name: "bar", Value: nil},
				},
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

func TestPolicySet_Evaluate(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		session *Session
		expect  Evaluation
	}{
		{
			name: "empty allow authenticated",
			input: `{
				allow { }
			}`,
			session: &Session{
				Uid: "test",
			},
			expect: Permit,
		},
		{
			name: "empty allow anonymous",
			input: `{
				allow { }
			}`,
			session: AnonymousSession,
			expect:  RejectImplicit,
		},
		{
			name: "empty allow explicit deny",
			input: `{
				allow { }
				deny {
					anonymous
				}
			}`,
			session: AnonymousSession,
			expect:  RejectExplicit,
		},
		{
			name: "allow user",
			input: `{
				allow {
					user foo bar test
				}
			}`,
			session: &Session{
				Uid: "test",
			},
			expect: Permit,
		},
		{
			name: "allow user in domain",
			input: `{
				allow {
					user *@example.com
				}
			}`,
			session: &Session{
				Uid: "test@example.com",
			},
			expect: Permit,
		},
		{
			name: "deny client",
			input: `{
				deny {
					client 127.0.0.1/32
				}
			}`,
			session: &Session{
				Uid: "test@example.com",
			},
			expect: RejectExplicit,
		},
		{
			name: "allow multiple and",
			input: `{
				allow {
					user test@example.com
					client 127.0.0.1/32
				}
			}`,
			session: &Session{
				Uid: "test@example.com",
			},
			expect: Permit,
		},
		{
			name: "allow query where exists",
			input: `{
				allow {
					query foo
				}
			}`,
			session: &Session{
				Uid: "test@example.com",
			},
			expect: Permit,
		},
		{
			name: "allow query with value",
			input: `{
				allow {
					query foo=bar
				}
			}`,
			session: &Session{
				Uid: "test@example.com",
			},
			expect: Permit,
		},
		{
			name: "deny query not equal",
			input: `{
				allow {
					query foo=baz
				}
			}`,
			session: &Session{
				Uid: "test@example.com",
			},
			expect: RejectImplicit,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)

			var ps PolicySet

			err := ps.UnmarshalCaddyfile(d)
			assert.NoError(t, err)

			r := httptest.NewRequest("GET", "/?foo=bar", nil)
			r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{
				caddyhttp.ClientIPVarKey: "127.0.0.1",
			}))

			e, err := ps.Evaluate(r, tt.session)
			assert.NoError(t, err)
			assert.Equal(t, tt.expect, e)
		})
	}
}
