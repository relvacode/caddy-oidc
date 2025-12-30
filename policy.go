package caddy_oauth2_proxy_auth

import (
	"net/http"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

type Action uint8

const (
	Allow Action = iota + 1
	Deny
)

type Wildcard string

func (w Wildcard) Match(s string) bool {
	if w == "*" {
		return true
	}

	var (
		iw int
		iv int
	)

ptn:
	for iw < len(s) && iv < len(w) {
		switch w[iw] {
		case '*':
			// Current pattern character is a wildcard, find the next anchor block
			iw++
			var j = iw
			for ; j < len(w) && w[j] != '*'; j++ {
			}

			// There is no text anchor after this wildcard; this wildcard matches all remaining text
			if iw == j {
				return true
			}

			// Advance the index to the next wildcard character
			var anchor = string(w[iw:j])
			for ; iv <= len(s)-len(anchor); iv++ {
				if s[iv:iv+len(anchor)] == anchor {
					// Found the anchor
					iw = j
					iv += len(anchor)
					continue ptn
				}
			}

			return false
		default:
			// Match character by character
			if s[iv] != w[iw] {
				return false
			}
			iw++
			iv++
		}
	}

	// No more remaining text to match.
	// State must be at the end of both values.
	return iv == len(s) && iw == len(w)
}

type RequestMatcher struct {
	Anonymous bool       `json:"anonymous,omitempty"`
	User      []Wildcard `json:"user,omitempty"`
}

func (p *RequestMatcher) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "anonymous":
			p.Anonymous = true
		case "user":
			for _, arg := range d.RemainingArgs() {
				p.User = append(p.User, Wildcard(arg))
			}
		}
	}

	return nil
}

// Evaluate evaluates the policy and returns true if the request is allowed.
// An empty policy always returns true.
func (p *RequestMatcher) Evaluate(_ *http.Request, s *Session) bool {
	if p.Anonymous != s.Anonymous {
		return false
	}

	if len(p.User) > 0 {
		var hasUser = false
		for _, u := range p.User {
			if u.Match(s.Uid) {
				hasUser = true
				break
			}
		}

		if !hasUser {
			return false
		}
	}

	return true
}

type Policy struct {
	Action Action `json:"action"`
	RequestMatcher
}

type Evaluation uint8

const (
	Permit         Evaluation = 0b01
	RejectExplicit            = 0b10
	RejectImplicit            = 0b00
)

type PolicySet []*Policy

func (ps *PolicySet) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		var pol Policy
		switch d.Val() {
		case "allow":
			pol.Action = Allow
		case "deny":
			pol.Action = Deny
		default:
			return d.Errf("unrecognized action '%s'", d.Val())
		}

		err := pol.RequestMatcher.UnmarshalCaddyfile(d)
		if err != nil {
			return err
		}

		*ps = append(*ps, &pol)
	}

	return nil
}

// Evaluate evaluates the policies in the set and returns true if the request is allowed.
// If at least one Allow policy is found, then the evaluation result is Permit.
// If at least one Deny policy is found, then the evaluation result is RejectExplicit.
// Otherwise, the evaluation result is RejectImplicit.
func (ps *PolicySet) Evaluate(r *http.Request, s *Session) Evaluation {
	var isAllowed = false

	for _, p := range *ps {
		if p.Evaluate(r, s) {
			switch p.Action {
			case Allow:
				isAllowed = true
			case Deny:
				return RejectExplicit
			}
		}
	}

	if isAllowed {
		return Permit
	}

	return RejectImplicit
}
