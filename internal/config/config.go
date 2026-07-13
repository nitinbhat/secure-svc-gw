// Package config loads the gateway's YAML configuration.
//
// The gateway makes three families of decisions and each has an explicit
// section here so an operator can reason about them:
//
//   - who is allowed to call us (client_keys + routes[].required_scope)
//   - who we are willing to talk to (services[].backends + ca_cert)
//   - how we pick a backend (services[].backends is the raw pool; the LB
//     narrows it to healthy members at request time)
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr  string        `yaml:"listen_addr"`
	MetricsAddr string        `yaml:"metrics_addr"`
	Issuer      string        `yaml:"issuer"`
	Audience    string        `yaml:"audience"`
	NonceTTL    time.Duration `yaml:"nonce_ttl"`

	// RedisURL, when non-empty, enables the Redis-backed distributed nonce
	// cache for replay defence across multiple gateway replicas.
	// Format: "redis://[:password@]host[:port][/db]"
	// When empty the in-process nonce cache is used (single-replica only).
	RedisURL string `yaml:"redis_url"`

	// Optional TLS for the client-facing listener.
	// When set the gateway speaks HTTPS to callers; when absent it speaks HTTP.
	// In production you would typically terminate TLS at an ingress in front
	// of the gateway, but setting these fields lets the gateway own its own
	// TLS termination when required.
	ListenCertPath string `yaml:"listen_cert"`
	ListenKeyPath  string `yaml:"listen_key"`

	CACertPath      string `yaml:"ca_cert"`
	GatewayCertPath string `yaml:"gateway_cert"`
	GatewayKeyPath  string `yaml:"gateway_key"`

	ClientKeys []ClientKey `yaml:"client_keys"`
	Services   []Service   `yaml:"services"`
	Routes     []Route     `yaml:"routes"`
}

// ClientKey is a registered client's public Ed25519 key.
// Rotating a key = add a new entry with a new kid, then remove the old one.
type ClientKey struct {
	Kid       string   `yaml:"kid"`
	PubBase64 string   `yaml:"pub"`
	Subject   string   `yaml:"sub"`
	Scopes    []string `yaml:"scopes"`
}

type Service struct {
	Name       string    `yaml:"name"`
	HealthPath string    `yaml:"health_path"`
	Backends   []Backend `yaml:"backends"`
}

type Backend struct {
	ID   string `yaml:"id"`
	Addr string `yaml:"addr"` // https://host:port
}

type Route struct {
	Prefix        string `yaml:"prefix"`
	Service       string `yaml:"service"`
	RequiredScope string `yaml:"required_scope"`
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.ListenAddr == "" {
		c.ListenAddr = ":8080"
	}
	if c.MetricsAddr == "" {
		c.MetricsAddr = ":9090"
	}
	if c.NonceTTL == 0 {
		c.NonceTTL = 5 * time.Minute
	}
	if c.Audience == "" {
		c.Audience = "gateway"
	}
	if len(c.Routes) == 0 {
		return nil, fmt.Errorf("no routes configured")
	}
	if len(c.Services) == 0 {
		return nil, fmt.Errorf("no services configured")
	}
	return &c, nil
}
