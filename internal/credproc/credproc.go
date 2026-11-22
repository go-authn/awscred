// SPDX-License-Identifier: BSD-3-Clause

// Package credproc is an AWS credential_process for S3 behind go-authn/bridge
// and go-fileshare: it proves a machine's identity to the bridge with a
// private_key_jwt (RFC 7523 2.2, OIDC Core 9), gets a client_credentials
// access token, exchanges it at STS AssumeRoleWithWebIdentity for temporary S3
// credentials and returns them in the credential_process format (AWS SDKs and
// Tools Reference Guide, "Process credential provider": JSON, Version 1).
//
// Nothing here holds a password: the machine holds a private key, the bridge
// the public half.
package credproc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-authn/harden/redirect"
)

// Output is what credential_process prints: Version 1, and an Expiration so
// that the SDK reruns the command before the credentials end.
type Output struct {
	Version         int    `json:"Version"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
}

// Config is what a run needs.
type Config struct {
	// Issuer is the bridge, exactly as its tokens spell iss.
	Issuer string
	// Client is the machine's client ID at the bridge.
	Client string
	// Key is the machine's private key.
	Key crypto.Signer
	// KeyID is put in the assertion header's kid, when set.
	KeyID string
	// STS is the S3 endpoint's URL (POST / answers AssumeRoleWithWebIdentity).
	STS string
	// Scope is asked of the token endpoint; default "machine".
	Scope string
	// SessionName is the RoleSessionName; default the client ID.
	SessionName string
	// Duration is DurationSeconds, when non-zero: 15 minutes to 12 hours, whole
	// seconds; anything else is refused.
	Duration time.Duration
	// CacheDir keeps the credentials between runs; "" caches nothing.
	CacheDir string
	// RefreshBefore is how long before Expiration a cached answer stops being
	// used. Default 5 minutes.
	RefreshBefore time.Duration

	HTTP *http.Client
	Now  func() time.Time
}

func (c *Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// client is the HTTP client with a redirect policy added: httpsOrLoopback looks
// at the URL as configured, and a 307 would carry the signed assertion or the
// web identity token, body included, to wherever the answer points. A copy, so
// the caller's own client is not changed (go-authn/oidc's stillHTTPS does the
// same job for its key set).
func (c *Config) client() *http.Client {
	var hc http.Client
	if c.HTTP != nil {
		hc = *c.HTTP
	} else {
		hc.Timeout = 30 * time.Second
	}
	next := hc.CheckRedirect
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := redirect.CheckRedirect(req, via); err != nil {
			return err
		}
		if next != nil {
			return next(req, via)
		}
		return nil
	}
	return &hc
}

const maxBody = 1 << 20

// Credentials returns the credentials: from the cache while they have more
// than RefreshBefore to live, otherwise newly exchanged (and cached).
//
// The SDKs do not cache the output of a credential_process, and run it at
// every renewal, so the cache is here.
func Credentials(ctx context.Context, c *Config) (*Output, error) {
	if c.Issuer == "" || c.Client == "" || c.Key == nil || c.STS == "" {
		return nil, errors.New("an issuer, a client, a key and an STS endpoint are needed")
	}
	if _, err := durationSeconds(c.Duration); err != nil {
		return nil, err
	}
	margin := c.RefreshBefore
	if margin <= 0 {
		margin = 5 * time.Minute
	}
	cache := c.cachePath()
	if o := readCache(cache); o != nil {
		if exp, err := time.Parse(time.RFC3339, o.Expiration); err == nil && c.now().Add(margin).Before(exp) {
			return o, nil
		}
	}
	tok, err := c.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	o, err := c.assume(ctx, tok)
	if err != nil {
		return nil, err
	}
	if cache != "" {
		if err := writeCache(cache, o); err != nil {
			// Not fatal: the credentials are good, the next run asks again.
			fmt.Fprintf(os.Stderr, "awscred: the credentials could not be cached: %v\n", err)
		}
	}
	return o, nil
}

// ---- the bridge ----

// httpsOrLoopback refuses a URL that would carry a signed assertion or a token
// in the clear.
func httpsOrLoopback(raw string) error {
	if err := redirect.HTTPSOrLoopback(raw); err != nil {
		return fmt.Errorf("a token and its credentials are sent over https (or loopback): %w", err)
	}
	return nil
}

func (c *Config) discover(ctx context.Context) (string, error) {
	issuer := strings.TrimRight(c.Issuer, "/")
	if err := httpsOrLoopback(issuer); err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return "", err
	}
	res, err := c.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("discovery: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery answered %s", res.Status)
	}
	var d struct {
		Issuer string `json:"issuer"`
		Token  string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, maxBody)).Decode(&d); err != nil {
		return "", fmt.Errorf("discovery: %w", err)
	}
	// OpenID Connect Discovery 4.3: the document is about the issuer it was
	// fetched from, or whoever served it could name other endpoints.
	if strings.TrimRight(d.Issuer, "/") != issuer {
		return "", fmt.Errorf("the discovery document at %s names issuer %q", issuer, d.Issuer)
	}
	if err := httpsOrLoopback(d.Token); err != nil {
		return "", fmt.Errorf("token_endpoint: %w", err)
	}
	return d.Token, nil
}

// accessToken is client_credentials with a private_key_jwt.
func (c *Config) accessToken(ctx context.Context) (string, error) {
	endpoint, err := c.discover(ctx)
	if err != nil {
		return "", err
	}
	assertion, err := c.assertion(endpoint)
	if err != nil {
		return "", err
	}
	scope := c.Scope
	if scope == "" {
		scope = "machine"
	}
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"scope":                 {scope},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := c.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("token endpoint: %w", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, maxBody))
	var t struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &t)
	if res.StatusCode != http.StatusOK || t.AccessToken == "" {
		// The provider's own error code and words -- never the assertion.
		return "", fmt.Errorf("the token endpoint refused the client (%s): %s %s", res.Status, t.Error, t.Description)
	}
	return t.AccessToken, nil
}

// assertion signs the client assertion (RFC 7523 3): iss = sub = the client,
// aud = the token endpoint, a minute to live, a fresh jti.
func (c *Config) assertion(aud string) (string, error) {
	alg, err := algFor(c.Key)
	if err != nil {
		return "", err
	}
	now := c.now()
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	header := map[string]string{"alg": alg, "typ": "JWT"}
	if c.KeyID != "" {
		header["kid"] = c.KeyID
	}
	claims := map[string]any{
		"iss": c.Client, "sub": c.Client, "aud": aud,
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"jti": base64.RawURLEncoding.EncodeToString(jti),
	}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	sig, err := sign(c.Key, alg, []byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// algFor is the JWS algorithm a key signs with. RS256, ES256 and EdDSA are
// what the bridge accepts; an RSA key under 2048 bits or an EC key that is not
// P-256 would be refused there, and is refused here with the reason.
func algFor(k crypto.Signer) (string, error) {
	switch pub := k.Public().(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < 2048 {
			return "", fmt.Errorf("a %d-bit RSA key: 2048 bits at least", pub.N.BitLen())
		}
		return "RS256", nil
	case *ecdsa.PublicKey:
		if pub.Curve != elliptic.P256() {
			return "", fmt.Errorf("an EC key on %s: ES256 is P-256", pub.Curve.Params().Name)
		}
		return "ES256", nil
	case ed25519.PublicKey:
		return "EdDSA", nil
	}
	return "", fmt.Errorf("a %T key: RSA, P-256 and Ed25519 only", k.Public())
}

// sign signs through crypto.Signer, so a key that cannot be exported -- a
// hardware or OS key store -- can sit behind the same interface.
func sign(k crypto.Signer, alg string, input []byte) ([]byte, error) {
	switch alg {
	case "RS256":
		h := sha256.Sum256(input)
		return k.Sign(rand.Reader, h[:], crypto.SHA256)
	case "ES256":
		h := sha256.Sum256(input)
		der, err := k.Sign(rand.Reader, h[:], crypto.SHA256)
		if err != nil {
			return nil, err
		}
		// JWS wants r || s, 32 bytes each (RFC 7518 3.4), not ASN.1.
		var e struct{ R, S *bigInt }
		if err := asn1Unmarshal(der, &e); err != nil {
			return nil, err
		}
		out := make([]byte, 64)
		e.R.FillBytes(out[:32])
		e.S.FillBytes(out[32:])
		return out, nil
	case "EdDSA":
		return k.Sign(rand.Reader, input, crypto.Hash(0))
	}
	return nil, fmt.Errorf("no signature for %q", alg)
}

// LoadKey reads a PEM private key: PKCS#8, PKCS#1 RSA or SEC1 EC.
func LoadKey(file string) (crypto.Signer, error) {
	// A private key readable by group or others is a key somebody else has.
	// Unix modes only: on Windows Chmod means nothing, and the file belongs in
	// the service account's profile or a directory with a restrictive ACL.
	//
	// One open, then the mode of that descriptor and a read of that descriptor:
	// a stat and a read by name could see two different files.
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if os.PathSeparator == '/' {
		st, err := f.Stat()
		if err != nil {
			return nil, err
		}
		if st.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("%s is readable by group or others (mode %04o): chmod 600 %s", file, st.Mode().Perm(), file)
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, maxBody))
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s is not PEM", file)
	}
	var k any
	switch blk.Type {
	case "PRIVATE KEY":
		k, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
	case "RSA PRIVATE KEY":
		k, err = x509.ParsePKCS1PrivateKey(blk.Bytes)
	case "EC PRIVATE KEY":
		k, err = x509.ParseECPrivateKey(blk.Bytes)
	default:
		return nil, fmt.Errorf("%s holds a %q, not a private key", file, blk.Type)
	}
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%s: a %T cannot sign", file, k)
	}
	if _, err := algFor(s); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return s, nil
}

// ---- STS ----

// STS DurationSeconds is an Integer from 900 to 43200 (AWS API reference,
// AssumeRoleWithWebIdentity). Zero means "the server's default".
const (
	minSession = 900 * time.Second
	maxSession = 43200 * time.Second
)

// durationSeconds is the DurationSeconds value for d, or "" for none. A value
// outside the range, negative, or with a fractional second is an error, not
// something to truncate: 500ms used to be sent as 0, and a huge one went
// through int(float64), which does not fit an int on 32 bits.
func durationSeconds(d time.Duration) (string, error) {
	if d == 0 {
		return "", nil
	}
	if d < minSession || d > maxSession {
		return "", fmt.Errorf("duration %v: STS accepts %v to %v", d, minSession, maxSession)
	}
	if d%time.Second != 0 {
		return "", fmt.Errorf("duration %v: a whole number of seconds is needed", d)
	}
	return strconv.FormatInt(int64(d/time.Second), 10), nil
}

type stsAnswer struct {
	Key     string `xml:"AssumeRoleWithWebIdentityResult>Credentials>AccessKeyId"`
	Secret  string `xml:"AssumeRoleWithWebIdentityResult>Credentials>SecretAccessKey"`
	Token   string `xml:"AssumeRoleWithWebIdentityResult>Credentials>SessionToken"`
	Expires string `xml:"AssumeRoleWithWebIdentityResult>Credentials>Expiration"`
}

type stsErrorAnswer struct {
	Code    string `xml:"Error>Code"`
	Message string `xml:"Error>Message"`
}

// assume is AssumeRoleWithWebIdentity (AWS STS API, version 2011-06-15): an
// unsigned POST of the token, in the body.
func (c *Config) assume(ctx context.Context, token string) (*Output, error) {
	if err := httpsOrLoopback(c.STS); err != nil {
		return nil, fmt.Errorf("sts: %w", err)
	}
	name := c.SessionName
	if name == "" {
		name = c.Client
	}
	form := url.Values{
		"Action": {"AssumeRoleWithWebIdentity"}, "Version": {"2011-06-15"},
		"RoleArn": {"arn:aws:iam::0:role/" + c.Client}, "RoleSessionName": {sessionName(name)},
		"WebIdentityToken": {token},
	}
	secs, err := durationSeconds(c.Duration)
	if err != nil {
		return nil, err
	}
	if secs != "" {
		form.Set("DurationSeconds", secs)
	}
	u := strings.TrimRight(c.STS, "/") + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("sts: %w", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if res.StatusCode != http.StatusOK {
		var e stsErrorAnswer
		_ = xml.NewDecoder(bytes.NewReader(body)).Decode(&e)
		return nil, fmt.Errorf("sts refused the token (%s): %s %s", res.Status, e.Code, e.Message)
	}
	var a stsAnswer
	if err := xml.Unmarshal(body, &a); err != nil || a.Key == "" || a.Secret == "" || a.Token == "" {
		return nil, errors.New("sts answered without credentials")
	}
	exp, err := time.Parse(time.RFC3339, a.Expires)
	if err != nil {
		return nil, fmt.Errorf("sts: Expiration %q is not RFC 3339", a.Expires)
	}
	return &Output{Version: 1, AccessKeyID: a.Key, SecretAccessKey: a.Secret, SessionToken: a.Token,
		Expiration: exp.UTC().Format(time.RFC3339)}, nil
}

// sessionName makes a RoleSessionName (2 to 64 of [\w+=,.@-]).
func sessionName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.ContainsRune("_+=,.@-", r):
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := b.String()
	if len(out) < 2 {
		out += "-0"
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}
