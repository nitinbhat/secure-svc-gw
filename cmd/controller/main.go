// Command controller watches SecureServiceGateway CRs and reconciles them
// into the gateway-config ConfigMap + a Deployment rollout annotation.
//
// # Design: zero heavy deps
//
// Rather than pulling in controller-runtime (which drags in all of k8s
// client-go and requires Go 1.22+), this controller speaks directly to the
// Kubernetes REST API via net/http. It uses:
//   - in-cluster service account token (mounted at the standard path)
//   - WATCH on the CRD resource version to receive streaming change events
//   - PATCH (strategic-merge) to update the ConfigMap
//   - PATCH to set a rollout annotation on the gateway Deployment
//
// This keeps the Go module at Go 1.21 and the binary under 5 MiB.
//
// # Reconcile loop
//
//  1. GET the SecureServiceGateway CR
//  2. Read the clientKeysSecretRef Secret to get the registered keys
//  3. Render gateway.yaml from the CR spec
//  4. Compute a SHA-256 of the rendered config
//  5. If the hash differs from the ConfigMap annotation, PATCH the ConfigMap
//  6. PATCH the Deployment's rollout-config-hash annotation to trigger a
//     rolling restart (the Deployment controller sees the annotation change
//     and rolls out new pods)
//
// # Running
//
//	# In-cluster (deployed as a Deployment alongside the gateway)
//	kubectl apply -f deploy/crds/securservicegateway.yaml   # install CRD
//	kubectl apply -f deploy/crds/sample-cr.yaml             # apply CR
//
//	# Local dev (KUBECONFIG auth, not in-cluster token)
//	KUBECONFIG=~/.kube/config go run ./cmd/controller \
//	  -namespace secure-svc-gw -cr-name main
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nibhat/secure-svc-gw/api/v1alpha1"
	"gopkg.in/yaml.v3"
)

const (
	saTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	saCACertPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	defaultAPIServer = "https://kubernetes.default.svc"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	ns := envOr("CONTROLLER_NAMESPACE", "secure-svc-gw")
	crName := envOr("CONTROLLER_CR_NAME", "main")
	apiServer := envOr("KUBERNETES_SERVICE_HOST", "")
	if apiServer != "" {
		port := envOr("KUBERNETES_SERVICE_PORT", "443")
		apiServer = fmt.Sprintf("https://%s:%s", apiServer, port)
	} else {
		apiServer = defaultAPIServer
	}

	c, err := newK8sClient(apiServer)
	if err != nil {
		slog.Error("k8s client init failed", "err", err)
		os.Exit(1)
	}

	slog.Info("controller started", "namespace", ns, "cr", crName, "api", apiServer)

	// Initial reconcile then watch for changes.
	if err := reconcile(c, ns, crName); err != nil {
		slog.Warn("initial reconcile failed", "err", err)
	}

	// Watch the CR for changes and reconcile on every ADDED/MODIFIED event.
	for {
		if err := watchAndReconcile(c, ns, crName); err != nil {
			slog.Error("watch error, retrying in 10s", "err", err)
			time.Sleep(10 * time.Second)
		}
	}
}

// ---------------------------------------------------------------------------
// Reconcile
// ---------------------------------------------------------------------------

func reconcile(c *k8sClient, ns, crName string) error {
	// 1. Fetch the CR.
	cr, err := fetchCR(c, ns, crName)
	if err != nil {
		return fmt.Errorf("fetch CR: %w", err)
	}

	// 2. Fetch the client-keys Secret referenced by the CR.
	clientKeys, err := fetchClientKeys(c, ns, cr.Spec.Auth.ClientKeysSecretRef)
	if err != nil {
		return fmt.Errorf("fetch client keys: %w", err)
	}

	// 3. Auto-discover Redis: if the well-known Secret "redis-credentials"
	// exists in this namespace (created by `helm install --set redis.enabled=true`)
	// pick up the redis_url from it. The CR has no redis field — Redis is
	// purely infrastructure and not an application-team concern.
	var redisURL string
	if url, err := fetchSecretKey(c, ns, "redis-credentials", "redis_url"); err == nil {
		redisURL = url
	}

	// 4. If spec.tls.issuerRef is set, ensure a cert-manager Certificate
	// exists so cert-manager issues the listener TLS cert automatically.
	// The resulting Secret is named "gateway-listener-tls".
	// If spec.tls.secretRef is set instead, the Secret is managed externally
	// and we skip this step.
	tlsSecretName := ""
	if cr.Spec.TLS != nil {
		switch {
		case cr.Spec.TLS.IssuerRef != nil:
			tlsSecretName = "gateway-listener-tls"
			if err := reconcileCertificate(c, ns, cr.Spec.TLS.IssuerRef); err != nil {
				return fmt.Errorf("reconcile certificate: %w", err)
			}
		case cr.Spec.TLS.SecretRef != "":
			tlsSecretName = cr.Spec.TLS.SecretRef
		}
	}

	// 5. Render gateway.yaml from the CR spec.
	rendered, err := renderConfig(cr, clientKeys, redisURL, tlsSecretName)
	if err != nil {
		return fmt.Errorf("render config: %w", err)
	}

	// 6. Hash the rendered config.
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(rendered)))

	// 7. Patch the ConfigMap (creates if absent).
	if err := patchConfigMap(c, ns, "gateway-config", rendered, hash); err != nil {
		return fmt.Errorf("patch configmap: %w", err)
	}

	// 8. Reconcile NetworkPolicy in the backends namespace if requested.
	if np := cr.Spec.NetworkPolicy; np != nil {
		beNS := cr.Spec.Backends.Namespace
		port := np.BackendsPort
		if port == 0 {
			port = 8443
		}
		if np.Enabled {
			if err := reconcileNetworkPolicy(c, beNS, ns, port); err != nil {
				return fmt.Errorf("reconcile network policy: %w", err)
			}
		} else {
			// If explicitly disabled, delete the policy if it exists.
			_ = deleteNetworkPolicy(c, beNS)
		}
	}

	// 9. Annotate the Deployment to trigger a rolling restart if config changed.
	if err := patchDeploymentAnnotation(c, ns, "gateway", hash); err != nil {
		return fmt.Errorf("patch deployment: %w", err)
	}

	slog.Info("reconciled", "namespace", ns, "cr", crName, "config_hash", hash[:8])
	return nil
}

// reconcileNetworkPolicy creates or updates a NetworkPolicy in beNS that
// allows ingress to backend pods only from gateway pods in gwNS.
func reconcileNetworkPolicy(c *k8sClient, beNS, gwNS string, port int) error {
	policy := map[string]interface{}{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
		"metadata": map[string]interface{}{
			"name":      "backends-only-from-gateway",
			"namespace": beNS,
			"annotations": map[string]string{
				"gateway.secure-svc.io/managed-by": "secure-svc-gw-controller",
			},
		},
		"spec": map[string]interface{}{
			"podSelector": map[string]interface{}{
				"matchLabels": map[string]string{
					"app.kubernetes.io/part-of":    "secure-svc-gw",
					"app.kubernetes.io/component": "backend",
				},
			},
			"policyTypes": []string{"Ingress"},
			"ingress": []interface{}{
				map[string]interface{}{
					"from": []interface{}{
						map[string]interface{}{
							"namespaceSelector": map[string]interface{}{
								"matchLabels": map[string]string{
									"kubernetes.io/metadata.name": gwNS,
								},
							},
							"podSelector": map[string]interface{}{
								"matchLabels": map[string]string{
									"app.kubernetes.io/part-of":    "secure-svc-gw",
									"app.kubernetes.io/component": "gateway",
								},
							},
						},
					},
					"ports": []interface{}{
						map[string]interface{}{
							"protocol": "TCP",
							"port":     port,
						},
					},
				},
			},
		},
	}
	body, _ := json.Marshal(policy)
	path := fmt.Sprintf("/apis/networking.k8s.io/v1/namespaces/%s/networkpolicies/backends-only-from-gateway", beNS)
	_, code, err := c.do("PATCH", path, body)
	if err != nil {
		return err
	}
	if code == http.StatusNotFound {
		postPath := fmt.Sprintf("/apis/networking.k8s.io/v1/namespaces/%s/networkpolicies", beNS)
		_, code2, err2 := c.do("POST", postPath, body)
		if err2 != nil || (code2 != http.StatusOK && code2 != http.StatusCreated) {
			return fmt.Errorf("create NetworkPolicy: status %d", code2)
		}
	}
	slog.Info("network policy reconciled", "namespace", beNS, "port", port)
	return nil
}

func deleteNetworkPolicy(c *k8sClient, beNS string) error {
	path := fmt.Sprintf("/apis/networking.k8s.io/v1/namespaces/%s/networkpolicies/backends-only-from-gateway", beNS)
	_, _, err := c.do("DELETE", path, nil)
	return err
}

// ---------------------------------------------------------------------------
// Config renderer
// ---------------------------------------------------------------------------

// ClientKeyEntry is the JSON schema used inside the clientKeysSecretRef Secret.
type ClientKeyEntry struct {
	Kid    string   `json:"kid"    yaml:"kid"`
	Pub    string   `json:"pub"    yaml:"pub"`
	Sub    string   `json:"sub"    yaml:"sub"`
	Scopes []string `json:"scopes" yaml:"scopes"`
}

func renderConfig(cr *v1alpha1.SecureServiceGateway, clientKeys []ClientKeyEntry, redisURL, tlsSecretName string) (string, error) {
	s := cr.Spec
	type backend struct {
		ID   string `yaml:"id"`
		Addr string `yaml:"addr"`
	}
	type service struct {
		Name       string    `yaml:"name"`
		HealthPath string    `yaml:"health_path"`
		Backends   []backend `yaml:"backends"`
	}
	type route struct {
		Prefix        string `yaml:"prefix"`
		Service       string `yaml:"service"`
		RequiredScope string `yaml:"required_scope,omitempty"`
	}
	type gatewayConfig struct {
		ListenAddr     string           `yaml:"listen_addr"`
		MetricsAddr    string           `yaml:"metrics_addr"`
		Issuer         string           `yaml:"issuer"`
		Audience       string           `yaml:"audience"`
		NonceTTL       string           `yaml:"nonce_ttl"`
		RedisURL       string           `yaml:"redis_url,omitempty"`
		ListenCert     string           `yaml:"listen_cert,omitempty"`
		ListenKey      string           `yaml:"listen_key,omitempty"`
		CACert         string           `yaml:"ca_cert"`
		GatewayCert    string           `yaml:"gateway_cert"`
		GatewayKey     string           `yaml:"gateway_key"`
		ClientKeys     []ClientKeyEntry `yaml:"client_keys"`
		Services       []service        `yaml:"services"`
		Routes         []route          `yaml:"routes"`
	}

	cfg := gatewayConfig{
		ListenAddr:  ":8080",
		MetricsAddr: ":9090",
		Issuer:      s.Auth.Issuer,
		Audience:    s.Auth.Audience,
		NonceTTL:    s.Auth.NonceTTL,
		CACert:      "/etc/gateway/certs/ca.crt",
		GatewayCert: "/etc/gateway/certs/gateway.crt",
		GatewayKey:  "/etc/gateway/certs/gateway.key",
		ClientKeys:  clientKeys,
	}
	if redisURL != "" {
		cfg.RedisURL = redisURL
	}
	// TLS: populate cert/key paths when a TLS Secret name is known.
	// The Secret is either managed by cert-manager (issuerRef) or provided
	// directly (secretRef). Either way the gateway mounts it at the same path.
	if tlsSecretName != "" {
		cfg.ListenCert = "/etc/gateway/listener-tls/tls.crt"
		cfg.ListenKey  = "/etc/gateway/listener-tls/tls.key"
	}
	beNS := s.Backends.Namespace
	port := 8443
	for _, svc := range s.Services {
		if svc.Port > 0 {
			port = svc.Port
		}
		hp := svc.HealthPath
		if hp == "" {
			hp = "/healthz"
		}
		var backends []backend
		for _, id := range svc.Backends {
			backends = append(backends, backend{
				ID:   id,
				Addr: fmt.Sprintf("https://%s.%s.svc.cluster.local:%d", id, beNS, port),
			})
		}
		cfg.Services = append(cfg.Services, service{
			Name:       svc.Name,
			HealthPath: hp,
			Backends:   backends,
		})
	}
	for _, r := range s.Routes {
		cfg.Routes = append(cfg.Routes, route{
			Prefix:        r.Prefix,
			Service:        r.Service,
			RequiredScope: r.RequiredScope,
		})
	}

	buf, err := yaml.Marshal(cfg)
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

// ---------------------------------------------------------------------------
// Kubernetes REST API client (stdlib only)
// ---------------------------------------------------------------------------

type k8sClient struct {
	base   string
	token  string
	client *http.Client
}

func newK8sClient(apiServer string) (*k8sClient, error) {
	token, _ := os.ReadFile(saTokenPath)

	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if caData, err := os.ReadFile(saCACertPath); err == nil {
		pool.AppendCertsFromPEM(caData)
	}

	return &k8sClient{
		base:  strings.TrimRight(apiServer, "/"),
		token: string(token),
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool},
			},
		},
	}, nil
}

func (c *k8sClient) do(method, path string, body []byte) ([]byte, int, error) {
	var bodyReader *bytes.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	} else {
		bodyReader = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, c.base+path, bodyReader)
	if err != nil {
		return nil, 0, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/strategic-merge-patch+json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return buf.Bytes(), resp.StatusCode, nil
}

// ---------------------------------------------------------------------------
// k8s operations
// ---------------------------------------------------------------------------

func fetchCR(c *k8sClient, ns, name string) (*v1alpha1.SecureServiceGateway, error) {
	path := fmt.Sprintf(
		"/apis/gateway.secure-svc.io/v1alpha1/namespaces/%s/secureservicegateways/%s",
		ns, name,
	)
	data, code, err := c.do("GET", path, nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("GET CR returned %d: %s", code, data)
	}
	var cr v1alpha1.SecureServiceGateway
	if err := json.Unmarshal(data, &cr); err != nil {
		return nil, err
	}
	return &cr, nil
}

func fetchClientKeys(c *k8sClient, ns, secretName string) ([]ClientKeyEntry, error) {
	path := fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s", ns, secretName)
	data, code, err := c.do("GET", path, nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("GET Secret %s returned %d", secretName, code)
	}
	var secret struct {
		Data map[string][]byte `json:"data"`
	}
	if err := json.Unmarshal(data, &secret); err != nil {
		return nil, err
	}
	var keys []ClientKeyEntry
	for _, v := range secret.Data {
		var entry ClientKeyEntry
		if err := json.Unmarshal(v, &entry); err == nil {
			keys = append(keys, entry)
		}
	}
	return keys, nil
}

// fetchSecretKey reads a single named key from a Kubernetes Secret.
// Used to retrieve the Redis URL without exposing it in the CR spec.
func fetchSecretKey(c *k8sClient, ns, secretName, key string) (string, error) {
	path := fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s", ns, secretName)
	data, code, err := c.do("GET", path, nil)
	if err != nil {
		return "", err
	}
	if code != http.StatusOK {
		return "", fmt.Errorf("GET Secret %s returned %d", secretName, code)
	}
	var secret struct {
		Data map[string][]byte `json:"data"`
	}
	if err := json.Unmarshal(data, &secret); err != nil {
		return "", err
	}
	v, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("Secret %s has no key %q", secretName, key)
	}
	return string(v), nil
}

// reconcileCertificate creates or updates a cert-manager Certificate resource
// so cert-manager automatically issues and renews the listener TLS cert.
// The Certificate always targets the Secret named "gateway-listener-tls".
func reconcileCertificate(c *k8sClient, ns string, issuerRef *v1alpha1.IssuerRef) error {
	cert := map[string]interface{}{
		"apiVersion": "cert-manager.io/v1",
		"kind":       "Certificate",
		"metadata": map[string]interface{}{
			"name":      "gateway-listener-tls",
			"namespace": ns,
			"annotations": map[string]string{
				"gateway.secure-svc.io/managed-by": "secure-svc-gw-controller",
			},
		},
		"spec": map[string]interface{}{
			// cert-manager writes the issued cert+key into this Secret.
			"secretName":  "gateway-listener-tls",
			"duration":    "2160h", // 90 days
			"renewBefore": "360h",  // 15 days
			"dnsNames": []string{
				fmt.Sprintf("gateway.%s.svc.cluster.local", ns),
				fmt.Sprintf("gateway.%s.svc", ns),
			},
			"issuerRef": map[string]string{
				"name": issuerRef.Name,
				"kind": issuerRef.Kind,
			},
		},
	}
	body, _ := json.Marshal(cert)
	path := fmt.Sprintf("/apis/cert-manager.io/v1/namespaces/%s/certificates/gateway-listener-tls", ns)
	_, code, err := c.do("PATCH", path, body)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		// Certificate may not exist yet — try POST.
		postPath := fmt.Sprintf("/apis/cert-manager.io/v1/namespaces/%s/certificates", ns)
		_, code2, err2 := c.do("POST", postPath, body)
		if err2 != nil || (code2 != http.StatusOK && code2 != http.StatusCreated) {
			return fmt.Errorf("patch Certificate %d / create %d", code, code2)
		}
	}
	slog.Info("certificate reconciled", "issuer", issuerRef.Name, "kind", issuerRef.Kind)
	return nil
}

func patchConfigMap(c *k8sClient, ns, name, gatewayYAML, hash string) error {
	patch := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": ns,
			"annotations": map[string]string{
				"gateway.secure-svc.io/config-hash": hash,
			},
		},
		"data": map[string]string{
			"gateway.yaml": gatewayYAML,
		},
	}
	body, _ := json.Marshal(patch)
	path := fmt.Sprintf("/api/v1/namespaces/%s/configmaps/%s", ns, name)
	_, code, err := c.do("PATCH", path, body)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		// ConfigMap may not exist yet — try POST.
		_, code2, err2 := c.do("POST", fmt.Sprintf("/api/v1/namespaces/%s/configmaps", ns), body)
		if err2 != nil || (code2 != http.StatusOK && code2 != http.StatusCreated) {
			return fmt.Errorf("patch ConfigMap %d / create %d", code, code2)
		}
	}
	return nil
}

func patchDeploymentAnnotation(c *k8sClient, ns, deployName, hash string) error {
	patch := map[string]interface{}{
		"spec": map[string]interface{}{
			"template": map[string]interface{}{
				"metadata": map[string]interface{}{
					"annotations": map[string]string{
						"gateway.secure-svc.io/config-hash": hash,
					},
				},
			},
		},
	}
	body, _ := json.Marshal(patch)
	path := fmt.Sprintf("/apis/apps/v1/namespaces/%s/deployments/%s", ns, deployName)
	_, code, err := c.do("PATCH", path, body)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("patch Deployment returned %d", code)
	}
	return nil
}

// watchAndReconcile opens a WATCH stream on the CR and calls reconcile on
// every ADDED or MODIFIED event.
func watchAndReconcile(c *k8sClient, ns, crName string) error {
	path := fmt.Sprintf(
		"/apis/gateway.secure-svc.io/v1alpha1/namespaces/%s/secureservicegateways?watch=true&fieldSelector=metadata.name=%s",
		ns, crName,
	)
	req, err := http.NewRequestWithContext(context.Background(), "GET", c.base+path, nil)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	// Use a client without a timeout for the long-lived watch stream.
	watchClient := &http.Client{Transport: c.client.Transport}
	resp, err := watchClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	for {
		var event struct {
			Type string `json:"type"`
		}
		if err := dec.Decode(&event); err != nil {
			return err
		}
		if event.Type == "ADDED" || event.Type == "MODIFIED" {
			if err := reconcile(c, ns, crName); err != nil {
				slog.Warn("reconcile failed", "event", event.Type, "err", err)
			}
		}
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
