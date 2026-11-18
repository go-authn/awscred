// SPDX-License-Identifier: BSD-3-Clause

package credproc

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
)

type bigInt = big.Int

func asn1Unmarshal(der []byte, v any) error {
	_, err := asn1.Unmarshal(der, v)
	return err
}

// cachePath is the file for this issuer, client and endpoint: one each, in
// CacheDir, readable by the user alone. "" when nothing is cached.
func (c *Config) cachePath() string {
	if c.CacheDir == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(c.Issuer + "\x00" + c.Client + "\x00" + c.STS + "\x00" + c.Scope))
	return filepath.Join(c.CacheDir, "awscred-"+hex.EncodeToString(sum[:8])+".json")
}

func readCache(p string) *Output {
	if p == "" {
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var o Output
	if json.Unmarshal(b, &o) != nil || o.Version != 1 || o.AccessKeyID == "" || o.SecretAccessKey == "" {
		return nil
	}
	return &o
}

// writeCache writes atomically: a run killed halfway leaves the old file or
// none, never half of one.
func writeCache(p string, o *Output) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(o)
	tmp, err := os.CreateTemp(filepath.Dir(p), ".awscred-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil && !isWindowsChmod(err) {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

// isWindowsChmod: Chmod on Windows only toggles read-only; the user's profile
// directory's ACL is what keeps the file private there.
func isWindowsChmod(error) bool { return os.PathSeparator == '\\' }
