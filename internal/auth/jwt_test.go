package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

// mintTestToken builds a valid JWT with the supplied overrides. It is a
// tiny subset of what cmd/client does -- kept local so tests don't depend
// on the client binary.
func mintTestToken(t *testing.T, priv ed25519.PrivateKey, kid string, claims Claims) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": kid})
	pl, _ := json.Marshal(claims)
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	signing := b64(hdr) + "." + b64(pl)
	sig := ed25519.Sign(priv, []byte(signing))
	return signing + "." + b64(sig)
}

func newVerifier(t *testing.T) (*Verifier, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier([]KeyRegistration{{
		Kid: "k1", PubBase64: base64.StdEncoding.EncodeToString(pub),
		Subject: "alice", Scopes: []string{"orders:read"},
	}}, "test-iss", "gateway", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return v, priv
}

func goodClaims() Claims {
	now := time.Now()
	return Claims{
		Iss: "test-iss", Sub: "alice", Aud: "gateway",
		Iat: now.Unix(), Exp: now.Add(time.Minute).Unix(),
		Jti: randHex(), Scope: []string{"orders:read"},
	}
}

func randHex() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func TestVerify_HappyPath(t *testing.T) {
	v, priv := newVerifier(t)
	tok := mintTestToken(t, priv, "k1", goodClaims())
	if _, _, err := v.Verify(tok); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerify_UnknownKid(t *testing.T) {
	v, priv := newVerifier(t)
	tok := mintTestToken(t, priv, "not-a-kid", goodClaims())
	_, _, err := v.Verify(tok)
	if err == nil || err.Reason != ReasonUnknownKid {
		t.Fatalf("want ReasonUnknownKid, got %+v", err)
	}
}

func TestVerify_Tampered(t *testing.T) {
	v, priv := newVerifier(t)
	tok := mintTestToken(t, priv, "k1", goodClaims())
	// flip the last char of the signature
	tok = tok[:len(tok)-1] + string(tok[len(tok)-1]^1)
	_, _, err := v.Verify(tok)
	if err == nil || (err.Reason != ReasonBadSignature && err.Reason != ReasonBadClaims) {
		t.Fatalf("want bad_signature or bad_claims, got %+v", err)
	}
}

func TestVerify_Expired(t *testing.T) {
	v, priv := newVerifier(t)
	c := goodClaims()
	c.Exp = time.Now().Add(-time.Second).Unix()
	tok := mintTestToken(t, priv, "k1", c)
	_, _, err := v.Verify(tok)
	if err == nil || err.Reason != ReasonExpired {
		t.Fatalf("want ReasonExpired, got %+v", err)
	}
}

func TestVerify_WrongAudience(t *testing.T) {
	v, priv := newVerifier(t)
	c := goodClaims()
	c.Aud = "not-us"
	tok := mintTestToken(t, priv, "k1", c)
	_, _, err := v.Verify(tok)
	if err == nil || err.Reason != ReasonWrongAudience {
		t.Fatalf("want ReasonWrongAudience, got %+v", err)
	}
}

func TestVerify_Replay(t *testing.T) {
	v, priv := newVerifier(t)
	tok := mintTestToken(t, priv, "k1", goodClaims())
	if _, _, err := v.Verify(tok); err != nil {
		t.Fatalf("first send should succeed: %v", err)
	}
	_, _, err := v.Verify(tok)
	if err == nil || err.Reason != ReasonReplay {
		t.Fatalf("want ReasonReplay, got %+v", err)
	}
}

func TestHasScope(t *testing.T) {
	c := &Claims{Scope: []string{"orders:read", "payments:read"}}
	if !HasScope(c, "orders:read") {
		t.Fatal("expected true")
	}
	if HasScope(c, "admin:*") {
		t.Fatal("expected false")
	}
	if !HasScope(c, "") {
		t.Fatal("empty required scope should always pass")
	}
}

// ---------------------------------------------------------------------------
// Additional JWT validation failure paths
// ---------------------------------------------------------------------------

func TestVerify_WrongIssuer(t *testing.T) {
	v, priv := newVerifier(t)
	c := goodClaims()
	c.Iss = "evil-issuer"
	tok := mintTestToken(t, priv, "k1", c)
	_, _, err := v.Verify(tok)
	if err == nil || err.Reason != ReasonWrongIssuer {
		t.Fatalf("want ReasonWrongIssuer, got %+v", err)
	}
}

func TestVerify_FutureIat(t *testing.T) {
	v, priv := newVerifier(t)
	c := goodClaims()
	c.Iat = time.Now().Add(2 * time.Minute).Unix() // well beyond 30s clockSkew
	c.Exp = time.Now().Add(5 * time.Minute).Unix()
	tok := mintTestToken(t, priv, "k1", c)
	_, _, err := v.Verify(tok)
	if err == nil || err.Reason != ReasonNotYetValid {
		t.Fatalf("want ReasonNotYetValid, got %+v", err)
	}
}

func TestVerify_MissingJti(t *testing.T) {
	v, priv := newVerifier(t)
	c := goodClaims()
	c.Jti = ""
	tok := mintTestToken(t, priv, "k1", c)
	_, _, err := v.Verify(tok)
	if err == nil || err.Reason != ReasonBadClaims {
		t.Fatalf("want ReasonBadClaims (missing jti), got %+v", err)
	}
}

func TestVerify_ExpZero(t *testing.T) {
	v, priv := newVerifier(t)
	c := goodClaims()
	c.Exp = 0
	tok := mintTestToken(t, priv, "k1", c)
	_, _, err := v.Verify(tok)
	if err == nil || err.Reason != ReasonExpired {
		t.Fatalf("want ReasonExpired for zero exp, got %+v", err)
	}
}

// TamperedPayload: payload swapped, original sig left → bad signature.
func TestVerify_TamperedPayload(t *testing.T) {
	v, priv := newVerifier(t)
	tok := mintTestToken(t, priv, "k1", goodClaims())
	parts := strings.SplitN(tok, ".", 3)
	// Replace payload with valid base64 of different content.
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"evil"}`))
	_, _, err := v.Verify(strings.Join(parts, "."))
	if err == nil || err.Reason != ReasonBadSignature {
		t.Fatalf("want ReasonBadSignature for tampered payload, got %+v", err)
	}
}

// TamperedHeader: header changed (extra field, same alg+kid), sig unchanged → bad signature.
func TestVerify_TamperedHeader(t *testing.T) {
	v, priv := newVerifier(t)
	tok := mintTestToken(t, priv, "k1", goodClaims())
	parts := strings.SplitN(tok, ".", 3)
	hdr, _ := json.Marshal(map[string]interface{}{
		"alg": "EdDSA", "typ": "JWT", "kid": "k1", "injected": true,
	})
	parts[0] = base64.RawURLEncoding.EncodeToString(hdr)
	_, _, err := v.Verify(strings.Join(parts, "."))
	if err == nil || err.Reason != ReasonBadSignature {
		t.Fatalf("want ReasonBadSignature for tampered header, got %+v", err)
	}
}

// MalformedJWT: wrong number of segments.
func TestVerify_MalformedJWT(t *testing.T) {
	v, _ := newVerifier(t)
	for _, tok := range []string{"", "one", "a.b", "a.b.c.d"} {
		_, _, err := v.Verify(tok)
		if err == nil {
			t.Errorf("expected error for malformed token %q", tok)
		}
	}
}

// alg:none must be rejected before key lookup.
func TestVerify_AlgNone(t *testing.T) {
	v, _ := newVerifier(t)
	hdr, _ := json.Marshal(map[string]string{"alg": "none", "typ": "JWT", "kid": "k1"})
	pl, _ := json.Marshal(goodClaims())
	b64 := base64.RawURLEncoding.EncodeToString
	tok := b64(hdr) + "." + b64(pl) + "."
	_, _, err := v.Verify(tok)
	if err == nil || err.Reason != ReasonBadClaims {
		t.Fatalf("want ReasonBadClaims for alg:none, got %+v", err)
	}
}

// HS256 algorithm confusion must be rejected.
func TestVerify_AlgHS256(t *testing.T) {
	v, _ := newVerifier(t)
	hdr, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT", "kid": "k1"})
	pl, _ := json.Marshal(goodClaims())
	b64 := base64.RawURLEncoding.EncodeToString
	tok := b64(hdr) + "." + b64(pl) + "." + b64([]byte("fakesig"))
	_, _, err := v.Verify(tok)
	if err == nil || err.Reason != ReasonBadClaims {
		t.Fatalf("want ReasonBadClaims for alg:HS256, got %+v", err)
	}
}

// RS256 algorithm confusion must be rejected.
func TestVerify_AlgRSA(t *testing.T) {
	v, _ := newVerifier(t)
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "k1"})
	pl, _ := json.Marshal(goodClaims())
	b64 := base64.RawURLEncoding.EncodeToString
	tok := b64(hdr) + "." + b64(pl) + "." + b64([]byte("fakersasig"))
	_, _, err := v.Verify(tok)
	if err == nil || err.Reason != ReasonBadClaims {
		t.Fatalf("want ReasonBadClaims for alg:RS256, got %+v", err)
	}
}

// BadBase64Sig: non-base64 in the signature segment.
func TestVerify_BadBase64Sig(t *testing.T) {
	v, priv := newVerifier(t)
	tok := mintTestToken(t, priv, "k1", goodClaims())
	parts := strings.SplitN(tok, ".", 3)
	parts[2] = "!!!notbase64!!!"
	_, _, err := v.Verify(strings.Join(parts, "."))
	if err == nil {
		t.Fatal("expected error for invalid base64 signature")
	}
}

// BadJSONPayload: signature is valid but payload is not JSON.
func TestVerify_BadJSONPayload(t *testing.T) {
	v, priv := newVerifier(t)
	hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": "k1"})
	badPl := []byte("this-is-not-json")
	b64 := base64.RawURLEncoding.EncodeToString
	signing := b64(hdr) + "." + b64(badPl)
	sig := ed25519.Sign(priv, []byte(signing))
	tok := signing + "." + b64(sig)
	_, _, err := v.Verify(tok)
	if err == nil || err.Reason != ReasonBadClaims {
		t.Fatalf("want ReasonBadClaims for bad JSON payload, got %+v", err)
	}
}

// EmptyScope: token with no scopes cannot satisfy any non-empty requirement.
func TestHasScope_EmptyScope(t *testing.T) {
	c := &Claims{Scope: []string{}}
	if HasScope(c, "admin") {
		t.Fatal("empty scope list should not satisfy any requirement")
	}
	if !HasScope(c, "") {
		t.Fatal("empty required scope must always pass")
	}
}

// Concurrent: 200 goroutines each with a distinct JWT — no races, all succeed.
func TestVerify_Concurrent(t *testing.T) {
	v, priv := newVerifier(t)
	const n = 200
	results := make(chan *AuthError, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := goodClaims()
			c.Jti = randHex() // unique per goroutine
			tok := mintTestToken(t, priv, "k1", c)
			_, _, aerr := v.Verify(tok)
			results <- aerr
		}()
	}
	wg.Wait()
	close(results)
	for aerr := range results {
		if aerr != nil {
			t.Errorf("unexpected verify error: %v", aerr)
		}
	}
}

// FuzzVerify ensures Verify never panics on arbitrary input.
func FuzzVerify(f *testing.F) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_ = priv
	v, _ := NewVerifier([]KeyRegistration{{
		Kid: "fk1", PubBase64: base64.StdEncoding.EncodeToString(pub),
		Subject: "fuzzer", Scopes: []string{"read"},
	}}, "iss", "aud", time.Minute)
	f.Add("")
	f.Add("not.a.jwt")
	f.Add("a.b.c")
	f.Add("eyJhbGciOiJub25lIn0.e30.")
	f.Fuzz(func(t *testing.T, token string) {
		v.Verify(token) // must not panic for any input
	})
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

// alwaysAccept is a NonceStore that never rejects, isolating the crypto path.
type alwaysAccept struct{}

func (alwaysAccept) CheckAndStore(string, time.Time) bool { return true }

// BenchmarkVerify measures: base64 decode → Ed25519 verify → JSON unmarshal → claim checks.
// Run: go test -bench=BenchmarkVerify -benchmem ./internal/auth/...
func BenchmarkVerify(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	v, _ := NewVerifierWithStore(
		[]KeyRegistration{{
			Kid: "bk1", PubBase64: base64.StdEncoding.EncodeToString(pub),
			Subject: "bench", Scopes: []string{"read"},
		}},
		"bench-iss", "gateway",
		alwaysAccept{},
	)

	// Pre-generate a token pool; alwaysAccept means token reuse is safe.
	const poolSize = 64
	tokens := make([]string, poolSize)
	for i := range tokens {
		c := goodClaims()
		c.Jti = randHex()
		hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": "bk1"})
		pl, _ := json.Marshal(c)
		b64e := base64.RawURLEncoding.EncodeToString
		signed := b64e(hdr) + "." + b64e(pl)
		sig := ed25519.Sign(priv, []byte(signed))
		tokens[i] = signed + "." + b64e(sig)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		v.Verify(tokens[i%poolSize])
	}
}

// BenchmarkVerify_Parallel runs Verify across GOMAXPROCS goroutines.
func BenchmarkVerify_Parallel(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	v, _ := NewVerifierWithStore(
		[]KeyRegistration{{
			Kid: "bk1", PubBase64: base64.StdEncoding.EncodeToString(pub),
			Subject: "bench", Scopes: []string{"read"},
		}},
		"bench-iss", "gateway",
		alwaysAccept{},
	)
	const poolSize = 256
	tokens := make([]string, poolSize)
	for i := range tokens {
		c := goodClaims()
		c.Jti = randHex()
		hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": "bk1"})
		pl, _ := json.Marshal(c)
		b64e := base64.RawURLEncoding.EncodeToString
		signed := b64e(hdr) + "." + b64e(pl)
		sig := ed25519.Sign(priv, []byte(signed))
		tokens[i] = signed + "." + b64e(sig)
	}
	var mu sync.Mutex
	i := 0
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			mu.Lock()
			idx := i % poolSize
			i++
			mu.Unlock()
			v.Verify(tokens[idx])
		}
	})
}