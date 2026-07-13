package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// genSelfSignedCert generates an ECDSA P-256 self-signed certificate and
// returns PEM-encoded certificate and private key bytes.
func genSelfSignedCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-gateway"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return
}

// writeTempFile writes content to a temp file and registers cleanup.
func writeTempFile(t *testing.T, content []byte) string {
	t.Helper()
	f, err := os.CreateTemp("", "tls-test-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}

// ---------------------------------------------------------------------------
// BackendTLS error paths
// ---------------------------------------------------------------------------

func TestBackendTLS_MissingCAFile(t *testing.T) {
	_, err := BackendTLS("/no/such/ca.pem", "/no/cert.pem", "/no/key.pem", "svc")
	if err == nil || !strings.Contains(err.Error(), "read CA") {
		t.Fatalf("expected 'read CA' error, got %v", err)
	}
}

func TestBackendTLS_InvalidCA(t *testing.T) {
	// File exists but contains no PEM certificate.
	caPath := writeTempFile(t, []byte("not-a-certificate"))
	_, err := BackendTLS(caPath, "/no/cert.pem", "/no/key.pem", "svc")
	if err == nil || !strings.Contains(err.Error(), "no valid certs") {
		t.Fatalf("expected 'no valid certs' error, got %v", err)
	}
}

func TestBackendTLS_MissingCertFile(t *testing.T) {
	certPEM, _ := genSelfSignedCert(t)
	caPath := writeTempFile(t, certPEM)
	_, err := BackendTLS(caPath, "/no/cert.pem", "/no/key.pem", "svc")
	if err == nil {
		t.Fatal("expected error for missing client certificate file")
	}
}

func TestBackendTLS_MismatchedCertKey(t *testing.T) {
	certPEM, _ := genSelfSignedCert(t)
	_, keyPEM2 := genSelfSignedCert(t) // key from a *different* cert
	caPath := writeTempFile(t, certPEM)
	certPath := writeTempFile(t, certPEM)
	keyPath := writeTempFile(t, keyPEM2)
	_, err := BackendTLS(caPath, certPath, keyPath, "svc")
	if err == nil {
		t.Fatal("expected error for certificate/key mismatch")
	}
}

// ---------------------------------------------------------------------------
// BackendTLS happy path: returned config must enforce TLS 1.2+, carry the
// gateway client certificate, pin the CA pool, and record the server name.
// ---------------------------------------------------------------------------

func TestBackendTLS_ValidConfig(t *testing.T) {
	certPEM, keyPEM := genSelfSignedCert(t)
	caPath := writeTempFile(t, certPEM)
	certPath := writeTempFile(t, certPEM)
	keyPath := writeTempFile(t, keyPEM)

	cfg, err := BackendTLS(caPath, certPath, keyPath, "my-service")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want TLS 1.2 (%d)", cfg.MinVersion, tls.VersionTLS12)
	}
	if cfg.ServerName != "my-service" {
		t.Errorf("ServerName = %q, want %q", cfg.ServerName, "my-service")
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("expected 1 client certificate, got %d", len(cfg.Certificates))
	}
	if cfg.RootCAs == nil {
		t.Error("RootCAs must be set")
	}
}
