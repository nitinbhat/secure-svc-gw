// Command gen-artifacts generates every piece of crypto material the
// AI gateway demo needs, in one shot.
//
// It writes:
//
//	certs/ca.crt / ca.key         Root CA (trusted by gateway and all legit backends)
//	certs/gateway.crt / .key      gateway's client cert (mTLS to backends)
//	certs/llm.crt / .key          server cert (SAN: llm, llm-1..3, localhost)
//	certs/embed.crt / .key        server cert (SAN: embed, embed-1..2, localhost)
//	certs/rogue-ca.crt            SECOND CA -- for the spoofed-backend demo
//	certs/rogue-llm.crt / .key    rogue cert claiming to be "llm", signed by rogue-ca
//	clients/<sub>.json            Ed25519 key file for each caller
//	config/gateway.yaml           ready-to-run gateway config
//
// The clients baked in are the demo's four callers:
//
//	chatbot     scopes=[llm:invoke]
//	search-svc  scopes=[embed:query]
//	analyst     scopes=[llm:invoke, embed:query]
//	intern      scopes=[]                   <- used to prove authorisation blocks
//
// This is a DEMO generator -- keys are written unencrypted. In production
// use Vault / SPIRE / cert-manager and short-lived credentials.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type serviceSpec struct {
	Name     string
	Backends []string // per-replica hostnames
}

// llm-4 is intentionally listed in the pool but is served by the rogue
// container whose cert is signed by a DIFFERENT CA. The gateway health-
// probes it every 2s, the TLS handshake fails, and it is never admitted
// to the healthy set. This is the spoofed-backend negative case.
var services = []serviceSpec{
	{Name: "llm", Backends: []string{"llm-1", "llm-2", "llm-3", "llm-4"}},
	{Name: "embed", Backends: []string{"embed-1", "embed-2"}},
}

var clients = []struct {
	Kid    string
	Sub    string
	Scopes []string
}{
	{Kid: "k-chatbot", Sub: "chatbot", Scopes: []string{"llm:invoke"}},
	{Kid: "k-search-svc", Sub: "search-svc", Scopes: []string{"embed:query"}},
	{Kid: "k-analyst", Sub: "analyst", Scopes: []string{"llm:invoke", "embed:query"}},
	{Kid: "k-intern", Sub: "intern", Scopes: []string{}}, // deliberately empty
}

func main() {
	outRoot := "."
	if len(os.Args) > 1 {
		outRoot = os.Args[1]
	}
	certsDir := filepath.Join(outRoot, "certs")
	clientsDir := filepath.Join(outRoot, "clients")
	configDir := filepath.Join(outRoot, "config")
	must(os.MkdirAll(certsDir, 0o755))
	must(os.MkdirAll(clientsDir, 0o755))
	must(os.MkdirAll(configDir, 0o755))

	// --- trusted CA + gateway client cert ---
	caCert, caKey := mustCA("secure-svc-gw Root CA")
	writeCertPEM(filepath.Join(certsDir, "ca.crt"), caCert)
	writeECKeyPEM(filepath.Join(certsDir, "ca.key"), caKey)

	gwCert, gwKey := mustLeaf(caCert, caKey, "gateway", nil, x509.ExtKeyUsageClientAuth)
	writeCertPEM(filepath.Join(certsDir, "gateway.crt"), gwCert)
	writeECKeyPEM(filepath.Join(certsDir, "gateway.key"), gwKey)

	// --- per-service server certs ---
	// SANs contain BOTH the logical service name (matches gateway ServerName)
	// and each real replica hostname. llm-4 is deliberately NOT here -- it's
	// impersonated by the rogue container below.
	for _, s := range services {
		sans := []string{s.Name, "localhost"}
		for _, h := range s.Backends {
			if h == "llm-4" {
				continue // never legit
			}
			sans = append(sans, h)
		}
		crt, key := mustLeaf(caCert, caKey, s.Name, sans,
			x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
		writeCertPEM(filepath.Join(certsDir, s.Name+".crt"), crt)
		writeECKeyPEM(filepath.Join(certsDir, s.Name+".key"), key)
	}

	// --- rogue CA + rogue cert claiming to be "llm" on hostname llm-4 ---
	rogueCA, rogueCAKey := mustCA("rogue-attacker CA")
	writeCertPEM(filepath.Join(certsDir, "rogue-ca.crt"), rogueCA)
	rogueCert, rogueKey := mustLeaf(rogueCA, rogueCAKey, "llm",
		[]string{"llm", "llm-4", "rogue-llm", "localhost"},
		x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
	writeCertPEM(filepath.Join(certsDir, "rogue-llm.crt"), rogueCert)
	writeECKeyPEM(filepath.Join(certsDir, "rogue-llm.key"), rogueKey)

	// --- Ed25519 client keys ---
	type clientPub struct {
		kid, sub, pub string
		scopes        []string
	}
	pubs := make([]clientPub, 0, len(clients))
	for _, c := range clients {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		must(err)
		kf := map[string]any{
			"kid":    c.Kid,
			"sub":    c.Sub,
			"scopes": c.Scopes,
			"priv":   base64.StdEncoding.EncodeToString(priv),
			"pub":    base64.StdEncoding.EncodeToString(pub),
		}
		out, _ := json.MarshalIndent(kf, "", "  ")
		must(os.WriteFile(filepath.Join(clientsDir, c.Sub+".json"), out, 0o600))
		pubs = append(pubs, clientPub{
			kid: c.Kid, sub: c.Sub,
			pub:    base64.StdEncoding.EncodeToString(pub),
			scopes: c.Scopes,
		})
	}

	// --- gateway config for compose ---
	cfg := "" +
		"listen_addr: \":8080\"\n" +
		"metrics_addr: \":9090\"\n" +
		"issuer: \"secure-svc-gw\"\n" +
		"audience: \"secure-svc-gw\"\n" +
		"nonce_ttl: 5m\n" +
		"redis_url: \"redis://redis:6379\"\n" +
		"ca_cert: /etc/gateway/certs/ca.crt\n" +
		"gateway_cert: /etc/gateway/certs/gateway.crt\n" +
		"gateway_key: /etc/gateway/certs/gateway.key\n" +
		"client_keys:\n"
	for _, p := range pubs {
		cfg += fmt.Sprintf("  - kid: %q\n    pub: %q\n    sub: %q\n    scopes: [%s]\n",
			p.kid, p.pub, p.sub, joinQuoted(p.scopes))
	}
	cfg += "services:\n"
	for _, s := range services {
		cfg += fmt.Sprintf("  - name: %q\n    health_path: /healthz\n    backends:\n", s.Name)
		for _, h := range s.Backends {
			cfg += fmt.Sprintf("      - id: %q\n        addr: \"https://%s:8443\"\n", h, h)
		}
	}
	cfg += "routes:\n" +
		"  - prefix: /v1/llm\n    service: llm\n    required_scope: llm:invoke\n" +
		"  - prefix: /v1/embed\n    service: embed\n    required_scope: embed:query\n"
	must(os.WriteFile(filepath.Join(configDir, "gateway.yaml"), []byte(cfg), 0o644))

	fmt.Println("generated:")
	fmt.Println("  certs/     -> CA + gateway + llm + embed + rogue-ca + rogue-llm")
	fmt.Println("  clients/   -> chatbot, search-svc, analyst, intern")
	fmt.Println("  config/    -> gateway.yaml")
}

// ---- crypto helpers ----

func mustCA(cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	must(err)
	crt, err := x509.ParseCertificate(der)
	must(err)
	return crt, key
}

func mustLeaf(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, sans []string, uses ...x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  uses,
		DNSNames:     sans,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, key.Public(), caKey)
	must(err)
	crt, err := x509.ParseCertificate(der)
	must(err)
	return crt, key
}

// ---- pem writers ----

func writeCertPEM(path string, c *x509.Certificate) {
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	must(os.WriteFile(path, b, 0o644))
}

func writeECKeyPEM(path string, k *ecdsa.PrivateKey) {
	der, err := x509.MarshalECPrivateKey(k)
	must(err)
	b := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	must(os.WriteFile(path, b, 0o600))
}

// ---- misc ----

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	must(err)
	return n
}

func joinQuoted(scopes []string) string {
	out := ""
	for i, s := range scopes {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%q", s)
	}
	return out
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
