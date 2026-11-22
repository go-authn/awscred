// SPDX-License-Identifier: BSD-3-Clause

package credproc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// AWS API reference, AssumeRoleWithWebIdentity, DurationSeconds: "Valid Range:
// Minimum value of 900. Maximum value of 43200." (type Integer).

func testKey(t *testing.T) crypto.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// stsFor answers a canned success and records the DurationSeconds it was sent.
func stsFor(t *testing.T, seen *atomic.Value, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_ = r.ParseForm()
		seen.Store(r.PostForm.Get("DurationSeconds"))
		_, _ = w.Write([]byte(`<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials>` +
			`<AccessKeyId>k</AccessKeyId><SecretAccessKey>s</SecretAccessKey><SessionToken>t</SessionToken>` +
			`<Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`))
	}))
}

func TestDurationOutsideTheSTSRangeIsRefusedBeforeTheRequest(t *testing.T) {
	for _, d := range []time.Duration{
		500 * time.Millisecond,             // int(0.5) = 0: "DurationSeconds=0"
		time.Second,                        // below 900
		899 * time.Second,                  // one under the minimum
		43201 * time.Second,                // one over the maximum
		1500 * time.Millisecond,            // not a whole number of seconds
		900*time.Second + time.Millisecond, // in range, but not whole seconds
		-time.Second,                       // used to be silently dropped
		math.MaxInt64,                      // ~9.2e9 s: does not fit an int on 32 bits
		time.Duration(1<<31) * time.Second, // 2^31 s: overflows int32
	} {
		var seen atomic.Value
		var hits atomic.Int32
		srv := stsFor(t, &seen, &hits)
		c := &Config{STS: srv.URL, Client: "c", Duration: d}
		_, err := c.assume(context.Background(), "tok")
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), "duration") {
			t.Errorf("%v: err = %v, want a duration refusal", d, err)
		}
		if hits.Load() != 0 {
			t.Errorf("%v: the request went out with DurationSeconds=%v", d, seen.Load())
		}
	}
}

func TestDurationInRangeIsSentAsWholeSeconds(t *testing.T) {
	for d, want := range map[time.Duration]string{
		900 * time.Second:   "900",
		time.Hour:           "3600",
		43200 * time.Second: "43200",
		0:                   "",
	} {
		var seen atomic.Value
		var hits atomic.Int32
		srv := stsFor(t, &seen, &hits)
		c := &Config{STS: srv.URL, Client: "c", Duration: d}
		_, err := c.assume(context.Background(), "tok")
		srv.Close()
		if err != nil {
			t.Errorf("%v: %v", d, err)
			continue
		}
		if got, _ := seen.Load().(string); got != want {
			t.Errorf("%v: DurationSeconds = %q, want %q", d, got, want)
		}
	}
}

// LoadKey opens the file once; a missing file and a non-PEM file are errors.
func TestLoadKeyMissingAndNotPEM(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadKey(filepath.Join(dir, "absent.pem")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
	p := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(p, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(p); err == nil || !strings.Contains(err.Error(), "not PEM") {
		t.Errorf("junk: %v", err)
	}
}

// Credentials refuses before any network work, even with a warm cache.
func TestCredentialsRefusesABadDurationUpFront(t *testing.T) {
	c := &Config{Issuer: "https://i", Client: "c", Key: nil, STS: "https://s", Duration: time.Second}
	// Key is nil, so the generic refusal fires first; use a real key instead.
	k := testKey(t)
	c.Key = k
	_, err := Credentials(context.Background(), c)
	if err == nil || !strings.Contains(err.Error(), "duration") {
		t.Fatalf("err = %v, want a duration refusal", err)
	}
}
