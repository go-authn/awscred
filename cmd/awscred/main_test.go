// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// fake is a bridge and an S3 endpoint, in one: the bridge verifies the
// client's assertion with go-jose -- which nobody in this repository wrote --
// against the registered public key, and refuses a replayed jti; the S3
// endpoint answers AssumeRoleWithWebIdentity for the token it issued.
type fake struct {
	*httptest.Server
	pub       jose.JSONWebKey
	mu        sync.Mutex
	jtis      map[string]bool
	tokens    atomic.Int32
	stsCalls  atomic.Int32
	life      time.Duration
	lastForm  map[string]string
	badIssuer bool
}

func newFake(t *testing.T, pub any, kid string) *fake {
	f := &fake{pub: jose.JSONWebKey{Key: pub, KeyID: kid}, jtis: map[string]bool{}, life: time.Hour}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		iss := f.URL
		if f.badIssuer {
			iss = "https://elsewhere.example"
		}
		json.NewEncoder(w).Encode(map[string]any{"issuer": iss, "token_endpoint": f.URL + "/token"})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		fail := func(why string) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client", "error_description": why})
		}
		if r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
			fail("grant")
			return
		}
		tok, err := jwt.ParseSigned(r.PostForm.Get("client_assertion"), []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.EdDSA})
		if err != nil {
			fail(err.Error())
			return
		}
		var c jwt.Claims
		if err := tok.Claims(f.pub, &c); err != nil {
			fail("signature: " + err.Error())
			return
		}
		now := time.Now()
		if c.Issuer != "winpc-17" || c.Subject != "winpc-17" || !c.Audience.Contains(f.URL+"/token") ||
			c.Expiry == nil || now.After(c.Expiry.Time()) || c.Expiry.Time().After(now.Add(5*time.Minute)) {
			fail("claims")
			return
		}
		f.mu.Lock()
		dup := f.jtis[c.ID]
		f.jtis[c.ID] = true
		f.mu.Unlock()
		if c.ID == "" || dup {
			fail("jti")
			return
		}
		f.tokens.Add(1)
		json.NewEncoder(w).Encode(map[string]any{"access_token": "the-access-token", "token_type": "Bearer", "scope": r.PostForm.Get("scope")})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.stsCalls.Add(1)
		f.lastForm = map[string]string{}
		for k := range r.PostForm {
			f.lastForm[k] = r.PostForm.Get(k)
		}
		if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.PostForm.Get("WebIdentityToken") != "the-access-token" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `<ErrorResponse><Error><Type>Sender</Type><Code>InvalidIdentityToken</Code><Message>no</Message></Error></ErrorResponse>`)
			return
		}
		fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials>`+
			`<AccessKeyId>ASIAEXAMPLE000000</AccessKeyId><SecretAccessKey>s3cr3t-s3cr3t</SecretAccessKey>`+
			`<SessionToken>the-session-token</SessionToken><Expiration>%s</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`,
			time.Now().Add(f.life).UTC().Format(time.RFC3339))
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func keyFile(t *testing.T, k crypto.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func run(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := RootCmd()
	var o, e bytes.Buffer
	cmd.SetOut(&o)
	cmd.SetErr(&e)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return o.String(), e.String(), err
}

type out struct {
	Version                                                int
	AccessKeyId, SecretAccessKey, SessionToken, Expiration string
}

func TestEveryKeyTypeGivesCredentialProcessJSON(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	edPub, edKey, _ := ed25519.GenerateKey(rand.Reader)
	for name, c := range map[string]struct {
		priv crypto.PrivateKey
		pub  any
	}{"RS256": {rk, &rk.PublicKey}, "ES256": {ek, &ek.PublicKey}, "EdDSA": {edKey, edPub}} {
		f := newFake(t, c.pub, "k1")
		stdout, stderr, err := run(t, "--issuer", f.URL, "--client", "winpc-17", "--key", keyFile(t, c.priv),
			"--sts", f.URL, "--cache-dir", t.TempDir())
		if err != nil {
			t.Fatalf("%s: %v (%s)", name, err, stderr)
		}
		var o out
		if err := json.Unmarshal([]byte(stdout), &o); err != nil {
			t.Fatalf("%s: %v\n%s", name, err, stdout)
		}
		exp, err := time.Parse(time.RFC3339, o.Expiration)
		if o.Version != 1 || o.AccessKeyId != "ASIAEXAMPLE000000" || o.SecretAccessKey != "s3cr3t-s3cr3t" ||
			o.SessionToken != "the-session-token" || err != nil || time.Until(exp) < 50*time.Minute {
			t.Errorf("%s: %+v", name, o)
		}
		if stderr != "" {
			t.Errorf("%s: stderr %q", name, stderr)
		}
		if f.lastForm["Action"] != "AssumeRoleWithWebIdentity" || f.lastForm["Version"] != "2011-06-15" ||
			f.lastForm["RoleSessionName"] != "winpc-17" || f.lastForm["RoleArn"] == "" {
			t.Errorf("%s: the STS request: %v", name, f.lastForm)
		}
	}
}

func TestTheCacheIsUsedUntilShortlyBeforeExpiration(t *testing.T) {
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := newFake(t, &ek.PublicKey, "")
	kf, cache := keyFile(t, ek), t.TempDir()
	args := []string{"--issuer", f.URL, "--client", "winpc-17", "--key", kf, "--sts", f.URL, "--cache-dir", cache}
	first, _, err := run(t, args...)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := run(t, args...)
	if err != nil || second != first {
		t.Fatalf("the second run: %v\n%s\n%s", err, first, second)
	}
	if f.tokens.Load() != 1 || f.stsCalls.Load() != 1 {
		t.Errorf("a cached run asked again: %d tokens, %d STS calls", f.tokens.Load(), f.stsCalls.Load())
	}
	// With a margin longer than what is left, the same cache is not used.
	if _, _, err := run(t, append(args, "--refresh-before", "2h")...); err != nil {
		t.Fatal(err)
	}
	if f.tokens.Load() != 2 || f.stsCalls.Load() != 2 {
		t.Errorf("near expiry it did not renew: %d tokens, %d STS calls", f.tokens.Load(), f.stsCalls.Load())
	}
	// --no-cache keeps nothing: every run asks.
	run(t, "--issuer", f.URL, "--client", "winpc-17", "--key", kf, "--sts", f.URL, "--no-cache")
	run(t, "--issuer", f.URL, "--client", "winpc-17", "--key", kf, "--sts", f.URL, "--no-cache")
	if f.tokens.Load() != 4 {
		t.Errorf("--no-cache: %d tokens", f.tokens.Load())
	}
	// The cache file is private to the user, where the platform says so.
	files, _ := filepath.Glob(filepath.Join(cache, "awscred-*.json"))
	if len(files) != 1 {
		t.Fatalf("cache files: %v", files)
	}
	if st, _ := os.Stat(files[0]); st.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("the cache is %v", st.Mode().Perm())
	}
}

func TestRefusalsPrintNothingOnStdoutAndNoSecretOnStderr(t *testing.T) {
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	f := newFake(t, &ek.PublicKey, "")
	good := []string{"--issuer", f.URL, "--client", "winpc-17", "--sts", f.URL, "--no-cache"}
	// The control.
	if _, _, err := run(t, append(good, "--key", keyFile(t, ek))...); err != nil {
		t.Fatalf("CONTROL: %v", err)
	}
	f2 := newFake(t, &ek.PublicKey, "")
	f2.badIssuer = true
	for name, args := range map[string][]string{
		"an unregistered key":         append(append([]string{}, good...), "--key", keyFile(t, other)),
		"a weak RSA key":              append(append([]string{}, good...), "--key", keyFile(t, weak)),
		"a P-384 key":                 append(append([]string{}, good...), "--key", keyFile(t, p384)),
		"a key that is not there":     append(append([]string{}, good...), "--key", filepath.Join(t.TempDir(), "none.pem")),
		"another client":              {"--issuer", f.URL, "--client", "other-pc", "--sts", f.URL, "--no-cache", "--key", keyFile(t, ek)},
		"an issuer that says another": {"--issuer", f2.URL, "--client", "winpc-17", "--sts", f2.URL, "--no-cache", "--key", keyFile(t, ek)},
		"a cleartext issuer":          {"--issuer", "http://login.example.org", "--client", "winpc-17", "--sts", f.URL, "--no-cache", "--key", keyFile(t, ek)},
		"a cleartext STS":             {"--issuer", f.URL, "--client", "winpc-17", "--sts", "http://s3.example.org", "--no-cache", "--key", keyFile(t, ek)},
		"no key":                      {"--issuer", f.URL, "--client", "winpc-17", "--sts", f.URL},
	} {
		stdout, _, err := run(t, args...)
		if err == nil || stdout != "" {
			t.Errorf("%s: ACCEPTED or printed: %v %q", name, err, stdout)
			continue
		}
		if strings.Contains(err.Error(), "eyJ") || strings.Contains(err.Error(), "s3cr3t") {
			t.Errorf("%s: the error carries a credential: %v", name, err)
		}
	}
}

func TestSTSRefusalIsAnErrorWithItsCode(t *testing.T) {
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := newFake(t, &ek.PublicKey, "")
	// The STS endpoint of another server, which does not know the token.
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `<ErrorResponse><Error><Type>Sender</Type><Code>InvalidIdentityToken</Code><Message>the token was not accepted</Message></Error></ErrorResponse>`)
	}))
	defer sts.Close()
	stdout, _, err := run(t, "--issuer", f.URL, "--client", "winpc-17", "--key", keyFile(t, ek), "--sts", sts.URL, "--no-cache")
	if err == nil || stdout != "" || !strings.Contains(err.Error(), "InvalidIdentityToken") {
		t.Errorf("%v %q", err, stdout)
	}
}

func TestAnAssertionIsUsedOnce(t *testing.T) {
	// Two runs are two jtis: the bridge's replay cache refuses a repeat, and
	// the tool never sends one.
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := newFake(t, &ek.PublicKey, "")
	kf := keyFile(t, ek)
	for i := 0; i < 5; i++ {
		if _, _, err := run(t, "--issuer", f.URL, "--client", "winpc-17", "--key", kf, "--sts", f.URL, "--no-cache"); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
}
