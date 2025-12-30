package caddy_oauth2_proxy_auth

import (
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
)

func TestSession_ValidateClock(t *testing.T) {
	tRef := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("valid", func(t *testing.T) {
		var session = &Session{
			ExpiresAt: tRef.Add(time.Hour).Unix(),
		}

		err := session.ValidateClock(tRef)
		assert.NoError(t, err)
	})

	t.Run("valid with leeway", func(t *testing.T) {
		var session = &Session{
			ExpiresAt: tRef.Add(-time.Second).Unix(),
		}

		err := session.ValidateClock(tRef)
		assert.NoError(t, err)
	})

	t.Run("expired", func(t *testing.T) {
		var session = &Session{
			ExpiresAt: tRef.Add(-time.Hour).Unix(),
		}

		err := session.ValidateClock(tRef)
		var exp *oidc.TokenExpiredError

		if assert.ErrorAs(t, err, &exp) {
			assert.True(t, exp.Expiry.Equal(tRef.Add(-time.Hour)))
		}
	})
}
