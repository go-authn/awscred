# Changelog

## v0.3.1

- The https-or-loopback rule and the redirect limit come from
  `github.com/go-authn/harden/redirect`, shared with oidc, rp, saml and
  wireguard. Loopback now also means `*.localhost`, in any letter case and with
  a trailing dot; an IPv6 zone is refused; the error names the scheme and host,
  no longer the whole URL (it may carry a secret). The 10-redirect limit now
  also applies when the caller's own `CheckRedirect` is set, which still runs
  after it.

## v0.3.0

- Fixed (#8): `--duration` / `Config.Duration` was sent as
  `int(Duration.Seconds())`: 500ms became `DurationSeconds=0`, values outside
  STS's range went out as they were, and a huge one went through a float to
  int conversion that does not fit on 32 bits. STS takes 900 to 43200
  (AWS API reference, AssumeRoleWithWebIdentity).
- Changed (#8), behaviour: a duration other than zero (the server's default)
  or 15 minutes to 12 hours in whole seconds is now refused before any request,
  including a negative one, which used to be ignored.
- Hardened (#8): `LoadKey` opens the key once and takes the mode and the bytes
  from that descriptor, instead of a stat and a read by name. Not an
  exploitable race (see the issue); the read is also bounded to 1 MiB.

## v0.2.0

- Fixed (#6): redirects are held to https or loopback. A 307 from the token or
  STS endpoint used to re-POST the signed client assertion or the web identity
  token to a plain-http host. The caller's own `CheckRedirect` still runs.
- Changed (#6), behaviour: on Unix a cache file is trusted only if it is a
  regular file of this user, not writable by group or others, in a directory
  owned by this user and not writable by group or others (a sticky directory
  such as /tmp is accepted). Anything else is ignored and the credentials are
  fetched afresh; nothing is written into such a directory. A shared
  `--cache-dir` with loose modes now needs `chmod 700`. Windows is unchanged.

## v0.1.0

- First release: an AWS `credential_process` for S3 behind bridge and
  fileshare (#1).
