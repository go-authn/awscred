// SPDX-License-Identifier: BSD-3-Clause

package credproc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadKeyRefusesAKeyOthersCanRead(t *testing.T) {
	if os.PathSeparator != '/' {
		t.Skip("file modes mean nothing on Windows; see the README")
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	p := filepath.Join(t.TempDir(), "k.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(p); err != nil {
		t.Fatalf("control, 0600: %v", err)
	}
	for _, m := range []os.FileMode{0o640, 0o604, 0o644, 0o660, 0o666, 0o610} {
		if err := os.Chmod(p, m); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadKey(p); err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("mode %04o: %v", m, err)
		}
	}
	os.Chmod(p, 0o400)
	if _, err := LoadKey(p); err != nil {
		t.Errorf("0400: %v", err)
	}
}
