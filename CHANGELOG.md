# Changelog

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
