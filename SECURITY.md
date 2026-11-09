# Security Policy

## The model, in two sentences
`router.py` is a localhost-first passthrough: EVERY local process may send it
inference and it injects backend keys on their behalf — that is the design, not
a hole. Foreign browser origins are refused (Host + Origin guards); pages from
loopback origins can fire one-way steering requests. Read "Limits" in
router/README.md before filing anything in that area.

## Reportable
- A way for a FOREIGN (non-loopback, or non-localhost-Host) caller to reach the
  router, or for a foreign-origin page to read router/box responses.
- Relay/passthrough paths where a lying backend puts headers, status lines, or
  bytes on the wire that the shipped tests claim are blocked.
- Key handling: any path where a key entered via `--set-key` reaches argv, any
  log line, `/__router/stats`, or a file another account can read.
  (Note: on non-Windows the keys file is intentionally plaintext 0600.)
- `monitor/` : anything that makes `rmon.py` able to issue a POST, read a keys
  file, or open a web UI — those are structural red lines with tests.

## Likely not a vulnerability
- "Local processes are trusted" / "localhost has no TLS" / stats readable locally.
- DPAPI protects against offline file theft, not against same-user malware.

## How to report
Use a private security advisory:
<https://github.com/Romi-AILab/Strata-router/security/advisories/new>
Solo maintainer — expect an acknowledgment within a week. Please do not open a
public issue for an unfixed vulnerability. For monitor issues, `python rmon.py
diagnose` output (de-identified by default) is welcome.
