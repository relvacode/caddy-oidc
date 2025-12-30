package caddy_oidc

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
)

type claimsStr string

func (c claimsStr) Claims(v any) error {
	return json.Unmarshal([]byte(c), v)
}

func TestUidClaim_FromClaims(t *testing.T) {
	tests := []struct {
		name      string
		claim     UidClaim
		claims    claimsStr
		expect    string
		shouldErr bool
	}{
		{
			name:   "valid",
			claim:  "sub",
			claims: claimsStr(`{"sub": "test"}`),
			expect: "test",
		},
		{
			name:      "invalid",
			claim:     "sub",
			claims:    claimsStr(`{"email": ""}`),
			shouldErr: true,
		},
		{
			name:      "missing",
			claim:     "sub",
			claims:    claimsStr(`{}`),
			shouldErr: true,
		},
		{
			name:      "not string",
			claim:     "sub",
			claims:    claimsStr(`{"sub": 1}`),
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := tt.claim.FromClaims(tt.claims)
			if tt.shouldErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expect, id)
		})
	}
}

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
