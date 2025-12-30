package caddy_oauth2_proxy_auth

import (
	"net/http"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

var DefaultCookieOptions = Cookies{
	Name:     "caddy",
	SameSite: http.SameSiteLaxMode,
	Insecure: false,
	Domain:   "",
	Path:     "/",
}

var _ caddyfile.Unmarshaler = (*Cookies)(nil)

type Cookies struct {
	Name     string        `json:"name"`
	SameSite http.SameSite `json:"same_site"`
	Insecure bool          `json:"insecure"`
	Domain   string        `json:"domain"`
	Path     string        `json:"path"`
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
				if !d.NextArg() {
					return d.ArgErr()
				}
				switch d.Val() {
				case "lax":
					o.SameSite = http.SameSiteLaxMode
				case "strict":
					o.SameSite = http.SameSiteStrictMode
				case "none":
					o.SameSite = http.SameSiteNoneMode
				default:
					return d.Errf("invalid same_site value: %s", d.Val())
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

func (o *Cookies) New(value string) *http.Cookie {
	return &http.Cookie{
		Name:     o.Name,
		Value:    value,
		SameSite: o.SameSite,
		Secure:   !o.Insecure,
		Domain:   o.Domain,
		Path:     o.Path,
		HttpOnly: true,
	}
}
