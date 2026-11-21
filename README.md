# awscred

An AWS `credential_process` for S3 behind [go-authn/bridge](https://github.com/go-authn/bridge)
and [go-fileshare/fileshare](https://github.com/go-fileshare/fileshare): **a machine with a private key and no
password** gets temporary S3 credentials, renewed by the SDK or the CLI as they
near their end.

```
machine key ──private_key_jwt──▶ bridge /token ──access token──▶ S3 endpoint (STS) ──▶ AccessKeyId, SecretAccessKey, SessionToken, Expiration
```

1. It signs a short-lived JWT with the machine's private key (RFC 7523 2.2, OpenID
   Connect Core 9: `iss` = `sub` = the client ID, `aud` = the token endpoint, one
   minute to live, a fresh `jti`) and sends it to the bridge's token endpoint as a
   `client_credentials` request. No secret is sent or stored.
2. It exchanges the access token at the S3 endpoint with STS
   `AssumeRoleWithWebIdentity` (AWS STS API, version 2011-06-15).
3. It prints the credentials in the format the SDKs read (AWS SDKs and Tools
   Reference Guide, "Process credential provider"): JSON, `Version` 1,
   `AccessKeyId`, `SecretAccessKey`, `SessionToken`, `Expiration` (RFC 3339). The
   SDKs run it again before `Expiration`.

The SDKs do not cache a `credential_process`'s output, so awscred does: until 5
minutes (`--refresh-before`) before `Expiration` it prints the cached answer
without touching the network.

## Install

```sh
go install github.com/go-authn/awscred/cmd/awscred@latest
```

Release builds are cross-compiled with `CGO_ENABLED=0` for windows/amd64,
windows/arm64, linux and darwin on amd64 and arm64.

## The three pieces

**1. bridge** (go-authn/bridge, `private_key_jwt`): register the machine's PUBLIC key.

```hcl
client "winpc-17" {
  jwks_file = "/etc/authn-bridge/winpc-17.jwks.json"   # a JWK Set: RS256, ES256 (P-256) or EdDSA
  audience  = ["fileshare"]
}
```

**2. fileshare** (go-fileshare/fileshare, STS): the audience is the one in the `oidc` block, and the
machine's name is `winpc-17`, which a share names as `oidc:user:winpc-17`.

```hcl
oidc  { issuer = "https://login.example.org"  audience = "fileshare" }
share "data" { image = "/srv/data.img"  allow = ["oidc:user:winpc-17"] }
serve "s3"   { addr = "0.0.0.0:9000"  tls = true  sts = true  static_keys = false }
```

**3. the machine**: a key, and a profile.

```sh
openssl genpkey -algorithm ed25519 -out winpc-17.pem      # or an RSA 2048+ / EC P-256 key
```

Register the public half in the bridge's JWK Set (an Ed25519 key as
`{"kty":"OKP","crv":"Ed25519","x":"…"}`).

## aws-cli

`~/.aws/config` (no environment variables and no `~` in the command: the SDKs
do not expand them; quote a path with spaces):

```ini
[profile fileshare]
region = eu-west-1
credential_process = awscred --issuer https://login.example.org --client winpc-17 --key /etc/awscred/winpc-17.pem --sts https://s3.example.org
```

```sh
aws --profile fileshare --endpoint-url https://s3.example.org s3 ls
```

On Windows:

```ini
[profile fileshare]
region = eu-west-1
credential_process = "C:\Program Files\awscred\awscred.exe" --issuer https://login.example.org --client winpc-17 --key C:\ProgramData\awscred\winpc-17.pem --sts https://s3.example.org --cache-dir C:\ProgramData\awscred\cache
```

For a service account with no profile directory (LocalSystem), give `--cache-dir`
or `--no-cache`: without one awscred uses the user's configuration directory
and says so if there is none.

## rclone

rclone's S3 backend reads the shared AWS configuration with `env_auth`, so the
same profile serves it:

```ini
[fileshare]
type = s3
provider = Other
env_auth = true
profile = fileshare
endpoint = https://s3.example.org
region = eu-west-1
```

(`rclone ls fileshare:data`. This README's configuration is not run against
rclone in this repository's tests; the tests drive the process with a bridge
and an S3 endpoint of their own, with go-jose verifying the assertions. The
fileshare PR's tests use aws-sdk-go-v2 against the real endpoint.)

## Flags

| flag | |
| --- | --- |
| `--issuer` | the bridge, as its tokens spell `iss`; https, or loopback |
| `--client` | the machine's client ID |
| `--key` | PEM private key (PKCS#8, PKCS#1 RSA, SEC1 EC); RSA >= 2048, EC P-256, Ed25519 |
| `--key-id` | the `kid` of the registered key, when the set holds several |
| `--sts` | the S3 endpoint (`POST /`); https, or loopback |
| `--scope` | default `machine` |
| `--session-name` | `RoleSessionName`, default the client ID |
| `--duration` | `DurationSeconds` asked of STS; default the server's |
| `--cache-dir`, `--no-cache` | where credentials are kept between runs |
| `--refresh-before` | default 5m |

## Safety

- Nothing secret is printed on stderr (the SDKs and the CLI capture and log it);
  errors carry the provider's error code and message, never an assertion or a
  credential. A failure prints nothing on stdout and exits 1.
- The issuer, the token endpoint and the STS endpoint must be https (loopback
  excepted), and so must every redirect they answer with: a 307 to http would
  carry the signed assertion or the web identity token in the clear, so it is
  refused. The discovery document must name the issuer it was fetched from
  (OpenID Connect Discovery 4.3).
- The cache holds temporary credentials, in a file created 0600 in a 0700
  directory (on Windows the profile directory's ACL is what keeps it private).
  On Unix a cache file is read back only if it is a regular file of this user,
  not writable by group or others, in a directory not writable by group or
  others (a sticky one such as /tmp excepted) and owned by this user; otherwise
  it is ignored and credentials are fetched afresh.
- The private key never leaves the machine and is read from a file at each run.
  On Unix a key file readable by group or others is refused (`chmod 600`). On
  Windows modes mean nothing: keep the key in the service account's profile or a
  directory whose ACL admits that account only.

## Keys in the Windows CNG or a TPM: not done

`--key` is a PEM file. Signing goes through Go's `crypto.Signer`, so a
non-exportable key (CNG/NCrypt, which fronts a TPM, or PKCS#11) fits behind the
same interface (`internal/credproc` takes any `crypto.Signer`), but no such
signer is implemented here: Go's standard library has none, and CNG from pure Go
means calling `ncrypt.dll` through `golang.org/x/sys/windows`, which cannot be
tested on this repository's CI hosts without a TPM. Until then protect the key
file with an ACL for the service account only.

## Licence

BSD-3-Clause.
