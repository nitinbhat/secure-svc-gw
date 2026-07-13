// Package proxy is the request-path glue: it decides, forwards, and
// records. It intentionally has no external dependencies beyond the
// stdlib + our own auth/lb/metrics packages.
package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// BackendTLS builds a *tls.Config that the gateway uses when calling
// backends. It enforces THREE things:
//
//  1. server certificate must chain to our private CA (RootCAs)
//  2. server certificate must present the expected SAN (ServerName)
//  3. we present the gateway's own client cert (mTLS)
//
// #2 is what defeats the "spoofed backend" case where an attacker holds a
// valid cert for `evil-service` signed by our CA -- Go's stdlib verifies
// ServerName against the cert's SAN list during the handshake, so the
// connection fails before any bytes flow.
//
// The `serverName` argument is the logical service identity, e.g. "orders";
// per-request we override it via a cloned config so a single tls.Config
// works for a pool whose members share a service identity.
func BackendTLS(caPath, certPath, keyPath, serverName string) (*tls.Config, error) {
	caBytes, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("CA file %s contains no valid certs", caPath)
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load gateway keypair: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		ServerName:   serverName,
	}, nil
}
