//go:build integration

package e2e

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/html"
)

func httpClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Timeout: 10 * time.Second,
		Jar:     jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}}
}

func checkResponse(t *testing.T, client *http.Client, req *http.Request, expectedStatus int) (*http.Response, bool) {
	var resp *http.Response
	for {
		var err error
		resp, err = client.Do(req)
		if err == nil {
			break
		}

		time.Sleep(500 * time.Millisecond)
	}

	defer resp.Body.Close()

	t.Logf("Status: %d", resp.StatusCode)
	t.Logf("Headers: %v", resp.Header)
	body, _ := io.ReadAll(resp.Body)
	t.Logf("Body: %s", string(body))
	resp.Body = io.NopCloser(bytes.NewReader(body))

	return resp, assert.Equal(t, expectedStatus, resp.StatusCode)

}

func getFormAction(body io.Reader) (string, bool) {
	z := html.NewTokenizer(body)
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return "", false
		case html.StartTagToken, html.SelfClosingTagToken:
			t := z.Token()
			if t.Data == "form" {
				for _, a := range t.Attr {
					if a.Key == "action" {
						return a.Val, true
					}
				}
			}
		}
	}
}

func TestIntegrationOAuthLoginFlow(t *testing.T) {
	client := httpClient()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://caddy", nil)
	assert.NoError(t, err)

	resp, _ := checkResponse(t, client, req, http.StatusOK) // Initiate login flow

	loginCallbackActionUrl, _ := getFormAction(resp.Body) // Get the login action URL from the response form

	// Set login information (see dex.yaml)
	formData := url.Values{}
	formData.Set("login", "admin@example.com")
	formData.Set("password", "password")

	req, err = http.NewRequestWithContext(t.Context(), http.MethodPost, "http://oidc-provider"+loginCallbackActionUrl, strings.NewReader(formData.Encode()))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, _ = checkResponse(t, client, req, http.StatusOK)

	data, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(data), "Authorized")
}
