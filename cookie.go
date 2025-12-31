package caddy_oidc

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

var DefaultCookieOptions = Cookies{
	Name:     "caddy",
	SameSite: SameSite{http.SameSiteLaxMode},
	Insecure: false,
	Domain:   "",
	Path:     "/",
}

type SameSite struct {
	http.SameSite
}

func (s *SameSite) UnmarshalText(text []byte) error {
	switch text := string(text); text {
	case "lax":
		s.SameSite = http.SameSiteLaxMode
	case "strict":
		s.SameSite = http.SameSiteStrictMode
	case "none":
		s.SameSite = http.SameSiteNoneMode
	default:
		return fmt.Errorf("invalid same_site value: %s", text)
	}

	return nil
}

func (s *SameSite) String() string {
	switch s.SameSite {
	case http.SameSiteLaxMode:
		return "lax"
	case http.SameSiteStrictMode:
		return "strict"
	case http.SameSiteNoneMode:
		return "none"
	default:
		return ""
	}
}

func (s *SameSite) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s *SameSite) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.NextArg() {
		return d.ArgErr()
	}
	switch d.Val() {
	case "lax":
		s.SameSite = http.SameSiteLaxMode
	case "strict":
		s.SameSite = http.SameSiteStrictMode
	case "none":
		s.SameSite = http.SameSiteNoneMode
	default:
		return fmt.Errorf("invalid same_site value: %s", d.Val())
	}

	return nil
}

func (s *SameSite) Validate() error {
	switch s.SameSite {
	case http.SameSiteLaxMode, http.SameSiteStrictMode, http.SameSiteNoneMode:
		return nil
	default:
		return errors.New("same_site must be one of lax, strict, or none")
	}
}

var _ caddyfile.Unmarshaler = (*Cookies)(nil)
var _ caddy.Validator = (*Cookies)(nil)

type Cookies struct {
	Name     string   `json:"name"`
	SameSite SameSite `json:"same_site"`
	Insecure bool     `json:"insecure,omitempty"`
	Domain   string   `json:"domain,omitempty"`
	Path     string   `json:"path"`
}

func (o *Cookies) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			o.Name = d.Val()
		}
		for d.NextBlock(0) {
			switch d.Val() {
			case "name":
				if !d.NextArg() {
					return d.ArgErr()
				}
				o.Name = d.Val()
			case "same_site":
				err := o.SameSite.UnmarshalCaddyfile(d)
				if err != nil {
					return err
				}
			case "insecure":
				o.Insecure = true
			case "domain":
				if !d.NextArg() {
					return d.ArgErr()
				}
				o.Domain = d.Val()
			case "path":
				if !d.NextArg() {
					return d.ArgErr()
				}
				o.Path = d.Val()
			default:
				return d.Errf("unrecognized cookie subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

func (o *Cookies) Validate() error {
	if o.Name == "" {
		return errors.New("cookie name cannot be empty")
	}

	err := o.SameSite.Validate()
	if err != nil {
		return err
	}

	return nil
}

func (o *Cookies) New(value string) *http.Cookie {
	return &http.Cookie{
		Name:     o.Name,
		Value:    value,
		SameSite: o.SameSite.SameSite,
		Secure:   !o.Insecure,
		Domain:   o.Domain,
		Path:     o.Path,
		HttpOnly: true,
	}
}
