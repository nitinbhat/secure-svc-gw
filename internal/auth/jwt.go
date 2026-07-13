// Package auth verifies client-supplied JWTs.
//
// # Wire format
//
// We implement a minimal JWS/JWT ourselves (Ed25519 only, one alg, one
// audience) so there are zero surprises around the classic JWT footguns:
// no `alg: none`, no HMAC/RSA confusion, no key-lookup ambiguity.
//
// A token is three base64url segments separated by '.':
//
//	base64url(header) . base64url(payload) . base64url(sig)
//
// header  = {"alg":"EdDSA","typ":"JWT","kid":"<key-id>"}
// payload = {"iss":..,"sub":..,"aud":..,"iat":..,"exp":..,"jti":..,"scope":[..]}
// sig     = Ed25519(header + "." + payload)
//
// # Rejection reasons (all exported as constants for metrics/logs)
//
//   - ReasonNoToken         : Authorization header missing / malformed
//   - ReasonUnknownKid      : header.kid not in registered client keys
//   - ReasonBadSignature    : signature does not verify (tampered token)
//   - ReasonBadClaims       : iss/aud mismatch, malformed JSON, etc.
//   - ReasonExpired         : now >= exp
//   - ReasonNotYetValid     : now <  iat - clockSkew
//   - ReasonReplay          : jti already seen within its exp window
//   - ReasonMissingScope    : token does not carry the route's required scope
package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	ReasonNoToken       = "no_token"
	ReasonUnknownKid    = "unknown_kid"
	ReasonBadSignature  = "bad_signature"
	ReasonBadClaims     = "bad_claims"
	ReasonExpired       = "expired"
	ReasonNotYetValid   = "not_yet_valid"
	ReasonReplay        = "replay"
	ReasonMissingScope  = "missing_scope"
	ReasonWrongAudience = "wrong_audience"
	ReasonWrongIssuer   = "wrong_issuer"
)

const clockSkew = 30 * time.Second

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// Claims is the deserialized JWT payload. All timestamps are Unix seconds.
type Claims struct {
	Iss   string   `json:"iss"`
	Sub   string   `json:"sub"`
	Aud   string   `json:"aud"`
	Iat   int64    `json:"iat"`
	Exp   int64    `json:"exp"`
	Jti   string   `json:"jti"`
	Scope []string `json:"scope"`
}

type registeredKey struct {
	pub    ed25519.PublicKey
	sub    string
	scopes map[string]struct{}
}

// Verifier holds all registered client public keys and the replay cache.
// It is safe for concurrent use.
type Verifier struct {
	keys     map[string]registeredKey
	issuer   string
	audience string
	nonces   NonceStore
}

// AuthError carries a machine-readable Reason alongside a human message so
// the handler can emit both a log field and a metric label without re-parsing.
type AuthError struct {
	Reason string
	Err    error
}

func (e *AuthError) Error() string {
	if e.Err == nil {
		return e.Reason
	}
	return e.Reason + ": " + e.Err.Error()
}

func newErr(reason string, err error) *AuthError { return &AuthError{Reason: reason, Err: err} }

// KeyRegistration is what NewVerifier accepts. We accept the pub key in
// base64 (raw 32 bytes) to avoid dragging PEM parsing into config loading.
type KeyRegistration struct {
	Kid       string
	PubBase64 string
	Subject   string
	Scopes    []string
}

// NewVerifier creates a Verifier with the default in-memory nonce cache.
// For multi-replica deployments, use NewVerifierWithStore and pass a
// *RedisNonceStore so replay defence is shared across all replicas.
func NewVerifier(regs []KeyRegistration, issuer, audience string, nonceTTL time.Duration) (*Verifier, error) {
	return NewVerifierWithStore(regs, issuer, audience, newNonceCache(nonceTTL))
}

// NewVerifierWithStore is like NewVerifier but accepts an explicit NonceStore.
func NewVerifierWithStore(regs []KeyRegistration, issuer, audience string, store NonceStore) (*Verifier, error) {
	if len(regs) == 0 {
		return nil, errors.New("no client keys registered")
	}
	v := &Verifier{
		keys:     make(map[string]registeredKey, len(regs)),
		issuer:   issuer,
		audience: audience,
		nonces:   store,
	}
	for _, r := range regs {
		raw, err := base64.StdEncoding.DecodeString(r.PubBase64)
		if err != nil {
			return nil, fmt.Errorf("kid=%s: bad base64 pub: %w", r.Kid, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("kid=%s: pub key must be %d bytes, got %d", r.Kid, ed25519.PublicKeySize, len(raw))
		}
		scopes := make(map[string]struct{}, len(r.Scopes))
		for _, s := range r.Scopes {
			scopes[s] = struct{}{}
		}
		v.keys[r.Kid] = registeredKey{pub: ed25519.PublicKey(raw), sub: r.Subject, scopes: scopes}
	}
	return v, nil
}

// Verify parses and validates a JWT string. On success it returns the claims
// and the registered subject. On failure it returns a typed *AuthError.
func (v *Verifier) Verify(token string) (*Claims, string, *AuthError) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, "", newErr(ReasonBadClaims, errors.New("expected 3 segments"))
	}
	hdrRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, "", newErr(ReasonBadClaims, fmt.Errorf("header b64: %w", err))
	}
	var hdr header
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil {
		return nil, "", newErr(ReasonBadClaims, fmt.Errorf("header json: %w", err))
	}
	// Pin the algorithm. This is the single most important check.
	if hdr.Alg != "EdDSA" {
		return nil, "", newErr(ReasonBadClaims, fmt.Errorf("alg %q not allowed", hdr.Alg))
	}

	key, ok := v.keys[hdr.Kid]
	if !ok {
		return nil, "", newErr(ReasonUnknownKid, fmt.Errorf("kid=%q", hdr.Kid))
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, "", newErr(ReasonBadClaims, fmt.Errorf("sig b64: %w", err))
	}
	signed := []byte(parts[0] + "." + parts[1])
	if !ed25519.Verify(key.pub, signed, sig) {
		return nil, "", newErr(ReasonBadSignature, nil)
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, "", newErr(ReasonBadClaims, fmt.Errorf("payload b64: %w", err))
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, "", newErr(ReasonBadClaims, fmt.Errorf("payload json: %w", err))
	}

	if v.issuer != "" && c.Iss != v.issuer {
		return nil, "", newErr(ReasonWrongIssuer, fmt.Errorf("iss=%q", c.Iss))
	}
	if c.Aud != v.audience {
		return nil, "", newErr(ReasonWrongAudience, fmt.Errorf("aud=%q", c.Aud))
	}
	now := time.Now()
	if c.Exp == 0 || now.After(time.Unix(c.Exp, 0)) {
		return nil, "", newErr(ReasonExpired, nil)
	}
	if c.Iat != 0 && now.Add(clockSkew).Before(time.Unix(c.Iat, 0)) {
		return nil, "", newErr(ReasonNotYetValid, nil)
	}
	if c.Jti == "" {
		return nil, "", newErr(ReasonBadClaims, errors.New("missing jti"))
	}
	if !v.nonces.CheckAndStore(c.Jti, time.Unix(c.Exp, 0)) {
		return nil, "", newErr(ReasonReplay, fmt.Errorf("jti=%s", c.Jti))
	}
	// The subject baked into the config wins over whatever the client
	// claims -- we trust the key, not the payload string.
	return &c, key.sub, nil
}

// HasScope returns true if the claims carry the required scope. An empty
// requirement is treated as "any authenticated caller".
func HasScope(c *Claims, required string) bool {
	if required == "" {
		return true
	}
	for _, s := range c.Scope {
		if s == required {
			return true
		}
	}
	return false
}
