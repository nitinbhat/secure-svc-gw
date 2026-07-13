// Package v1alpha1 contains the Go types for the SecureServiceGateway CRD.
//
// These structs mirror the CRD schema defined in deploy/crds/securservicegateway.yaml.
// They intentionally have no k8s client-go imports so they can be used by
// both the controller (cmd/controller) and any other tool that needs to
// parse / render a SecureServiceGateway resource.
package v1alpha1

// SecureServiceGateway is the Custom Resource that configures the gateway.
// It drives a controller (cmd/controller) which renders it into the
// gateway-config ConfigMap and triggers a rolling restart of the gateway
// Deployment whenever the spec changes.
//
// kubectl apply example — see deploy/crds/sample-cr.yaml
type SecureServiceGateway struct {
	APIVersion string                    `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                    `json:"kind"       yaml:"kind"`
	Metadata   ObjectMeta                `json:"metadata"   yaml:"metadata"`
	Spec       SecureServiceGatewaySpec  `json:"spec"       yaml:"spec"`
}

type ObjectMeta struct {
	Name      string            `json:"name"                yaml:"name"`
	Namespace string            `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"    yaml:"labels,omitempty"`
}

// SecureServiceGatewaySpec is the desired configuration of the gateway.
type SecureServiceGatewaySpec struct {
	// Auth configures JWT verification and replay defence.
	Auth AuthSpec `json:"auth" yaml:"auth"`

	// TLS optionally enables HTTPS on the client-facing listener.
	// When omitted the listener speaks plain HTTP.
	TLS *TLSSpec `json:"tls,omitempty" yaml:"tls,omitempty"`

	// Backends describes the backend pools and their health-check config.
	Backends BackendsSpec `json:"backends" yaml:"backends"`

	// Services lists the upstream service pools.
	Services []ServiceSpec `json:"services" yaml:"services"`

	// Routes maps URL prefixes to service pools and required scopes.
	Routes []RouteSpec `json:"routes" yaml:"routes"`

	// NetworkPolicy controls Calico/k8s NetworkPolicies managed by the controller.
	// When enabled, the controller reconciles a NetworkPolicy in the backends
	// namespace that allows ingress only from gateway pods.
	NetworkPolicy *NetworkPolicySpec `json:"networkPolicy,omitempty" yaml:"networkPolicy,omitempty"`
}

// NetworkPolicySpec controls whether the controller reconciles network-level
// access control for backend pods. When enabled, only gateway pods in
// spec.backends.namespace may reach backend pods on the mTLS port.
type NetworkPolicySpec struct {
	// Enabled controls whether the NetworkPolicy is created/maintained.
	// Set to false to manage it externally or to disable enforcement entirely.
	Enabled bool `json:"enabled" yaml:"enabled"`

	// BackendsPort is the TCP port the policy allows from the gateway.
	// Defaults to 8443 (the mTLS backend port).
	BackendsPort int `json:"backendsPort,omitempty" yaml:"backendsPort,omitempty"`
}

// AuthSpec holds JWT issuer/audience/key configuration.
type AuthSpec struct {
	// Issuer is the expected `iss` claim value.
	Issuer string `json:"issuer" yaml:"issuer"`

	// Audience is the expected `aud` claim value.
	Audience string `json:"audience" yaml:"audience"`

	// NonceTTL is the replay-prevention window (e.g. "5m").
	NonceTTL string `json:"nonceTTL" yaml:"nonceTTL"`

	// ClientKeysSecretRef names a Secret in the same namespace whose
	// data keys are client IDs and values are JSON ClientKey objects.
	// The controller reads this Secret and inlines the keys into the
	// gateway ConfigMap.
	ClientKeysSecretRef string `json:"clientKeysSecretRef" yaml:"clientKeysSecretRef"`
}

// TLSSpec enables HTTPS on the client-facing listener.
type TLSSpec struct {
	// SecretRef names a TLS Secret (tls.crt + tls.key) to mount.
	// When cert-manager is installed, set issuerRef instead and the
	// controller will create a Certificate resource automatically.
	SecretRef string `json:"secretRef,omitempty" yaml:"secretRef,omitempty"`

	// IssuerRef lets cert-manager issue the listener certificate.
	IssuerRef *IssuerRef `json:"issuerRef,omitempty" yaml:"issuerRef,omitempty"`
}

type IssuerRef struct {
	Name string `json:"name" yaml:"name"`
	Kind string `json:"kind" yaml:"kind"` // Issuer | ClusterIssuer
}

// BackendsSpec holds the shared backend pool configuration.
type BackendsSpec struct {
	// Namespace is the Kubernetes namespace where the backend pods live.
	// This is used to construct cluster-DNS addresses for each backend.
	Namespace string `json:"namespace" yaml:"namespace"`

	// CASecretRef names a Secret containing the CA cert (ca.crt) that
	// the gateway trusts when dialling backends over mTLS.
	CASecretRef string `json:"caSecretRef" yaml:"caSecretRef"`

	// ClientCertSecretRef names a Secret with the gateway's own mTLS
	// client certificate (tls.crt + tls.key).
	ClientCertSecretRef string `json:"clientCertSecretRef" yaml:"clientCertSecretRef"`

	// FailThreshold is the number of consecutive failed health probes
	// before a backend is ejected from the healthy pool. Default: 3.
	FailThreshold int `json:"failThreshold,omitempty" yaml:"failThreshold,omitempty"`

	// PassThreshold is the number of consecutive successful probes
	// needed to re-admit an ejected backend. Default: 2.
	PassThreshold int `json:"passThreshold,omitempty" yaml:"passThreshold,omitempty"`

	// HealthInterval is the probe cadence (e.g. "2s"). Default: "2s".
	HealthInterval string `json:"healthInterval,omitempty" yaml:"healthInterval,omitempty"`
}

// ServiceSpec describes one upstream service pool.
type ServiceSpec struct {
	// Name is the service identifier used in routes and metrics labels.
	Name string `json:"name" yaml:"name"`

	// HealthPath is the HTTP path the health checker will probe. Default: "/healthz".
	HealthPath string `json:"healthPath,omitempty" yaml:"healthPath,omitempty"`

	// Port is the TLS port each backend listens on. Default: 8443.
	Port int `json:"port,omitempty" yaml:"port,omitempty"`

	// Backends lists the individual backend pod IDs.
	// The controller constructs DNS addresses as:
	//   https://<id>.<BackendsSpec.Namespace>.svc.cluster.local:<Port>
	Backends []string `json:"backends" yaml:"backends"`
}

// RouteSpec maps a URL prefix to a service pool and an authorization scope.
type RouteSpec struct {
	// Prefix is matched as a path prefix on every incoming request.
	Prefix string `json:"prefix" yaml:"prefix"`

	// Service is the name of the ServiceSpec to route to.
	Service string `json:"service" yaml:"service"`

	// RequiredScope is the JWT scope claim value the caller must hold.
	// An empty string means "any authenticated caller".
	RequiredScope string `json:"requiredScope,omitempty" yaml:"requiredScope,omitempty"`
}
