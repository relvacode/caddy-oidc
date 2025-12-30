package caddy_oauth2_proxy_auth

import (
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
)

func SessionFromIDToken(id *oidc.IDToken) *Session {
	return &Session{
		Uid:          id.Subject,
		ExpiresAt:    id.Expiry.Unix(),
		RefreshToken: nil,
	}
}

var AnonymousSession = &Session{Anonymous: true}

type Session struct {
	Uid          string  `json:"u"`
	Anonymous    bool    `json:"-"`
	ExpiresAt    int64   `json:"e,omitempty"`
	RefreshToken *string `json:"r,omitempty"`
}

// HttpCookie returns the http cookie representation of the cookies
func (s *Session) HttpCookie(cookies *Cookies, encoder *securecookie.SecureCookie) (*http.Cookie, error) {
	value, err := encoder.Encode(cookies.Name, s)
	if err != nil {
		return nil, err
	}

	httpCookie := cookies.New(value)

	if s.ExpiresAt > 0 {
		httpCookie.Expires = time.Unix(s.ExpiresAt, 0)
	}

	return httpCookie, nil
}

// Expires returns the expiration time of the session.
// Returns a zero time if the session has no expiration time
func (s *Session) Expires() time.Time {
	if s.ExpiresAt == 0 {
		return time.Time{}
	}

	return time.Unix(s.ExpiresAt, 0)
}

const Leeway = time.Second * 5

// ValidateClock checks if the session is still valid.
// If the session has expired, then it returns an oidc.TokenExpiredError
func (s *Session) ValidateClock(now time.Time) error {
	if expires := s.Expires(); !expires.IsZero() && expires.Before(now.Add(-Leeway)) {
		return &oidc.TokenExpiredError{Expiry: expires}
	}

	return nil
}
