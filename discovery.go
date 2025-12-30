package caddy_oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func unmarshalJSON[T any](r *http.Response, body []byte) (*T, error) {
	var data = *new(T)
	err := json.Unmarshal(body, &data)
	if err == nil {
		return &data, nil
	}
	ct := r.Header.Get("Content-Type")
	mediaType, _, parseErr := mime.ParseMediaType(ct)
	if parseErr == nil && mediaType == "application/json" {
		return nil, fmt.Errorf("got Content-Type = application/json, but could not unmarshal as JSON: %v", err)
	}

	return nil, fmt.Errorf("expected Content-Type = application/json, got %q: %v", ct, err)
}

// Discover OpenID configuration from the given OpenID configuration URL.
// This is mostly a copy from oidc.NewProvider but allows an explicit configuration URl that isn't derived from the issuer
func Discover(ctx context.Context, httpClient *http.Client, configurationUrl string) (*oidc.Provider, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, configurationUrl, nil)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}

	config, err := unmarshalJSON[oidc.ProviderConfig](resp, body)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to decode provider discovery object: %v", err)
	}

	return config.NewProvider(context.WithValue(ctx, oauth2.HTTPClient, httpClient)), nil
}
