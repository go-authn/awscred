// SPDX-License-Identifier: BSD-3-Clause

package credproc

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func cacheFixture(t *testing.T, dirMode, fileMode os.FileMode) (dir, p string) {
	t.Helper()
	if os.PathSeparator != '/' {
		t.Skip("file modes")
	}
	dir = filepath.Join(t.TempDir(), "c")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p = filepath.Join(dir, "awscred-x.json")
	body := `{"Version":1,"AccessKeyId":"A","SecretAccessKey":"S","Expiration":"2099-01-01T00:00:00Z"}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, fileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, dirMode); err != nil {
		t.Fatal(err)
	}
	return dir, p
}

func TestCacheTrust(t *testing.T) {
	cases := []struct {
		name             string
		dirMode, fileMod os.FileMode
		want             bool
	}{
		{"private", 0o700, 0o600, true},
		{"readable by others is fine", 0o755, 0o644, true},
		{"file group-writable", 0o700, 0o660, false},
		{"file other-writable", 0o700, 0o602, false},
		{"dir group-writable", 0o770, 0o600, false},
		{"dir other-writable", 0o702, 0o600, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, p := cacheFixture(t, tc.dirMode, tc.fileMod)
			if got := readCache(p) != nil; got != tc.want {
				t.Errorf("readCache trusted = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCacheSymlinkIsNotTrusted(t *testing.T) {
	dir, p := cacheFixture(t, 0o700, 0o600)
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(p, link); err != nil {
		t.Skip(err)
	}
	if readCache(link) != nil {
		t.Error("a symlink was read as the cache")
	}
}

func TestCacheIsNotWrittenToAnUnsafeDirectory(t *testing.T) {
	dir, p := cacheFixture(t, 0o770, 0o600)
	if err := writeCache(p, &Output{Version: 1, AccessKeyID: "A", SecretAccessKey: "S"}); err == nil {
		t.Error("credentials were written into a group-writable directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeCache(p, &Output{Version: 1, AccessKeyID: "B", SecretAccessKey: "S"}); err != nil {
		t.Errorf("a private directory refused: %v", err)
	}
}

func TestRedirectPolicy(t *testing.T) {
	var called int
	own := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { called++; return nil }}
	c := &Config{HTTP: own}
	cr := c.client().CheckRedirect
	req := func(raw string) *http.Request { u, _ := url.Parse(raw); return &http.Request{URL: u} }

	if cr(req("https://sts.example.org/x"), nil) != nil {
		t.Error("an https redirect was refused")
	}
	if cr(req("http://127.0.0.1:9/x"), nil) != nil {
		t.Error("a loopback redirect was refused")
	}
	if cr(req("http://sts.example.org/x"), nil) == nil {
		t.Error("a redirect to cleartext http was followed")
	}
	if called != 2 {
		t.Errorf("the caller's own CheckRedirect ran %d times, want 2 (not for the refused one)", called)
	}
	if own.CheckRedirect == nil || c.HTTP != own {
		t.Error("the caller's client was replaced")
	}
	veto := errors.New("veto")
	own2 := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return veto }}
	if err := (&Config{HTTP: own2}).client().CheckRedirect(req("https://a.example/"), nil); !errors.Is(err, veto) {
		t.Errorf("the caller's veto was lost: %v", err)
	}
	if err := (&Config{}).client().CheckRedirect(req("https://a.example/"), make([]*http.Request, 10)); err == nil {
		t.Error("an eleventh redirect was followed")
	}
}
