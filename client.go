package caddy_oauth2_proxy_auth

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// ClientIP gets the real client IP address from the request using the same method Caddy would
func ClientIP(r *http.Request) (netip.Addr, error) {
	// if handshake is not finished, we infer 0-RTT that has
	// not verified remote IP; could be spoofed, so we throw
	// HTTP 425 status to tell the client to try again after
	// the handshake is complete
	if r.TLS != nil && !r.TLS.HandshakeComplete {
		return netip.IPv4Unspecified(), caddyhttp.Error(http.StatusTooEarly, fmt.Errorf("TLS handshake not complete, remote IP cannot be verified"))
	}

	address := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)

	ipStr, _, err := net.SplitHostPort(address)
	if err != nil {
		ipStr = address // OK; probably didn't have a port
	}

	// Some IPv6-Addresses can contain zone identifiers at the end,
	// which are separated with "%"
	if strings.Contains(ipStr, "%") {
		split := strings.Split(ipStr, "%")
		ipStr = split[0]
	}

	ipAddr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return netip.IPv4Unspecified(), err
	}

	return ipAddr, nil
}
