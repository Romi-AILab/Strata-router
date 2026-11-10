#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""audit_package.py -- the packaging red-line gate for the Strata monorepo.

Why this file exists (merge verdict, red-team F1): a plaintext router.json
with real box IPs -- or any keys file, or a Tailscale address buried in a
doc -- drifting into git is the ONE irreversible mistake a repo restructure
can make: once pushed, it lives in history and in every clone forever. Tests
catch logic bugs; nothing else catches a secret that was never logic. So the
gate comes BEFORE the files move, and CI-by-hand runs it after every commit.

Checks, all green or non-zero exit:
  1. TRACK WHITELIST -- git-tracked files must EQUAL EXPECTED_TRACKED
     (set equality: a missing file is the friend's broken mirror, an extra
     file is a secret waiting to happen; neither is "harmless"). Every
     tracked file must ALSO exist on disk: the equality reads the index,
     so an on-disk deletion stayed invisible to this gate until commit
     (M2-A/P3-5; run_all_tests only covered the two suite files).
  2. SECRET GREP -- every whitelisted file is scanned in THREE views:
     worktree, git index, and HEAD. "Green before push" must mean the
     pushable content is clean, not merely the file currently on disk:
     commit-a-secret-then-edit-it-out used to audit ALL GREEN with the
     secret still in HEAD (M2-A/P1-2). Non-UTF-8 files are not skipped
     wholesale -- a notepad "save as UTF-16" once blinded the whole file
     (M2-A/P2-2).
  3. IGNORE ASSERT -- machine-local config paths must be git-ignored even
     when they exist on this dev machine.
  4. --selftest -- synthetic canaries prove the patterns still have teeth.
     A round-1 L2 found this gate blind to exactly the key shape this
     project exists to proxy (M2-A/P1-1): a gate without teeth is a
     sticker, so the teeth are now asserted, not assumed.

Run from the repo root:  python audit_package.py
Prove the teeth:         python audit_package.py --selftest
Pre-commit gate:         python audit_package.py --gate monitor/rmon.py ...
(--gate accepts files OR directories, resolved against the CWD; the full
modes always resolve against this file -- M2-A/P3-2 cwd-semantics note.)
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# The friend's mirror IS this exact set -- the review scope of any change to
# packaging is "did this line change, and only this line".
EXPECTED_TRACKED = {
    "!-start.bat",          # root unified entry (v0.2.0, owner-mandated; delegates to monitor/launch.py go)
    ".gitattributes",
    ".gitignore",
    "README.md",
    "LICENSE",              # Apache-2.0, signed Romi-AILab (owner call, 2026-11-09)
    "SECURITY.md",          # how to report, what the model already accepts (OS-B/P2-4)
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",   # Contributor Covenant 2.1, canonical body; only delta = contact line filled with the private-advisory page (same channel as SECURITY.md)
    "audit_package.py",
    "run_all_tests.py",
    ".github/pull_request_template.md",
    ".github/ISSUE_TEMPLATE/problem-report.md",
    ".github/workflows/tests.yml",   # CI runs exactly these gate commands
    "router/README.md",
    "router/router.py",
    "router/router.remote.example.json",
    "router/smoke_test.py",
    "monitor/!-start.bat",
    "monitor/README.md",
    "monitor/launch.py",
    "monitor/monitor.json.example",
    "monitor/rmon.py",
    "monitor/tests_rmon.py",
}

# Paths that must NEVER be tracked, and must match .gitignore on a dev box
# where they DO exist (router.json is created by every real deployment).
# The zombie probe is a --set-key replace-retry temp (per-pid suffix): it
# holds the whole keyring when a replace keeps failing, and "*.keys.json"
# never matched it (M2-A/P2-1).
MUST_IGNORE = [
    "router/router.json",
    "router/router.keys.json",
    "router/router.keys.json.new.99999",
    "router/router.keys.json.lock",   # --set-key byte-range lock sits next
                                      # to the keyring (router.py path+".lock")
    "monitor/monitor.json",
    "router/router.log",
    "router/__pycache__/router.cpython-313.pyc",
]

# Real Tailscale/CGNAT space only (the RFC 6598 range): docs may print the
# fake 203.0.113.71 (RFC 5737) forever; version strings like 1.2.100.1 must
# not raise a false alarm on a range no documentation is allowed to carry.
# Three-segment forms count too -- a "redacted" three-octet prefix still
# pins someone's overlay (M2-A/P2-2). (This comment spells no address on
# purpose -- the gate scans itself too.)
_TAILSCALE = re.compile(r"\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])(?:\.\d{1,3}){1,2}\b")
# API-key shapes: "sk-" + body of >=12 keychars. The body class includes
# hyphen/underscore: real Anthropic keys are sk-ant-api03-<base64url> and
# slid straight through an alnum-only class, which is exactly the one key
# shape this project exists to proxy (M2-A/P1-1). \b keeps prose
# ("task-based", "risk-analyze") quiet; the project's own FAKE sentinels
# stay exempted by the lookahead.
_APIKEY = re.compile(r"\bsk-(?!FAKE|fake|Fake)[A-Za-z0-9_\-]{12,}")
# Long opaque runs: ciphertext blobs and base64 secrets. Threshold is 32,
# not 44 -- base64url secrets chopped by hyphens/underscores evaded 44
# (M2-A/P2-2). If this ever fires on legitimate prose, FIX THE PROSE, not
# the pattern, and say why in the commit.
_B64ISH = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")
# 40+ hex: sha-shaped tokens. Docs that must cite a commit use 7-8 char
# short refs (M2-A/P2-2).
_HEXLONG = re.compile(r"[0-9a-f]{40,}")
# Chopped base64url tokens WITHOUT an sk- prefix -- real API tokens mix
# case and carry digits; prose kebab-case has no digits and version strings
# are dot-broken or too short, so both lookaheads together stay quiet on
# legitimate text (M3-A/P3-N1: alnum-only runs let -/_-chopped secrets
# through -- the promise made when adopting P1-1, now actually kept).
# Same policy as _B64ISH: if prose trips this, fix the prose, not the pattern.
_URLTOKEN = re.compile(
    r"(?=[A-Za-z0-9_\-]*[0-9])(?=[A-Za-z0-9_\-]*[A-Z])[A-Za-z0-9_\-]{24,}")
# Tailscale MagicDNS hostnames identify a real machine even with no IP in
# sight. The shipped example host uses the reserved ".tsnet.invalid" shape
# instead; a real MagicDNS name must never replace it. (The backslash-
# escaped pattern source is invisible to its own scan -- keep it that way.)
_TSNET = re.compile(r"\.ts\.net", re.IGNORECASE)
# Drive-anchored user-home path: the shape a machine identity takes inside
# pasted logs and config snippets. (Described, never spelled: any literal
# form in this file's prose would trip this very scan.)
_USERSDIR = re.compile(r"[A-Za-z]:[/\\]+Users[/\\]", re.IGNORECASE)
# This development machine's identity must never ride the mirror -- but a
# PUBLIC gate must not carry the owner's username in its own source either:
# that is the very leak this gate hunts, and the old split-literal pattern
# was hiding it from greps while sitting in plain sight for any reader
# (open-source L2 / OSA-P2-1). Owner-side tripwires are injected from the
# environment instead: set RMON_AUDIT_USER to a regex (a literal string
# still works -- it falls back to a quoted match) and the scan grows one
# more pattern; unset -- CI, friend mirrors -- the gate stays generic.
# The generic machine-identity shape stays covered by _USERSDIR above.
def _identity_patterns():
    raw = os.environ.get("RMON_AUDIT_USER", "").strip()
    if not raw:
        return []
    try:
        return [("machine username (RMON_AUDIT_USER)",
                 re.compile(raw, re.IGNORECASE))]
    except re.error:
        return [("machine username (RMON_AUDIT_USER, literal)",
                 re.compile(re.escape(raw), re.IGNORECASE))]


PATTERNS = [
    ("tailscale/CGNAT address", _TAILSCALE),
    ("api-key-shaped token", _APIKEY),
    ("long base64/blob", _B64ISH),
    ("chopped base64url token", _URLTOKEN),
    ("long hex token", _HEXLONG),
    ("tailscale magic-dns name", _TSNET),
    ("user-home path", _USERSDIR),
] + _identity_patterns()

FAILS = []


def fail(msg):
    FAILS.append(msg)
    print("  FAIL  " + msg)


def ok(msg):
    print("  PASS  " + msg)


def tracked_files():
    out = subprocess.run(["git", "ls-files"], cwd=HERE, capture_output=True,
                         check=True).stdout.decode("utf-8", "replace")
    return set(x.strip() for x in out.splitlines() if x.strip())


def git_blob(spec):
    """Bytes of `git cat-file blob <spec>`, or None if the object is absent
    (new file has no HEAD blob; that is not an error)."""
    r = subprocess.run(["git", "cat-file", "blob", spec], cwd=HERE,
                       capture_output=True)
    return r.stdout if r.returncode == 0 else None


def decode_views(data):
    """bytes -> list of candidate texts. A file is only skipped if nothing
    can read it at all -- which is nothing. Order is load-bearing
    (M3-A/P1-N1): a UTF-16 BOM (notepad and old PowerShell's default save)
    decodes as UTF-16 FIRST; a utf-8 text that decodes WITH NUL bytes is
    re-scanned de-NULled (BOM-less UTF-16 of ASCII decodes as utf-8 and
    NULs would chop every pattern's match in half); the last-resort net is
    the whole file as latin-1 with NULs stripped, appended to every path."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return [data.decode("utf-16")]
        except (UnicodeDecodeError, ValueError, UnicodeError):
            pass    # a lying BOM -- fall through to the general path
    views = []
    try:
        text = data.decode("utf-8")
        views.append(text)
        if "\x00" in text:
            views.append(text.replace("\x00", ""))
    except UnicodeDecodeError:
        if b"\x00" in data:
            for enc in ("utf-16", "utf-16-le", "utf-16-be"):
                try:
                    views.append(data.decode(enc))
                    break
                except (UnicodeDecodeError, ValueError, UnicodeError):
                    continue
    net = data.decode("latin-1").replace("\x00", "")
    if net not in views:
        views.append(net)
    return views


def scan_content(name, data):
    """data: bytes. Returns list of 'pattern@name[view]:line=N' hits."""
    hits = []
    for vi, text in enumerate(decode_views(data)):
        tag = "utf8" if vi == 0 else "alt%d" % vi
        for i, line in enumerate(text.splitlines(), 1):
            for label, pat in PATTERNS:
                if pat.search(line):
                    hits.append("%s @ %s[%s]:%d" % (label, name, tag, i))
    return hits


# ---------------------------------------------------------------- selftest
# Synthetic canaries (M2-A/P1-1). Every string is assembled at RUNTIME from
# fragments, so this file's own bytes stay clean, and every value is a
# SHAPE, never a real secret -- the teeth are what is under test. must_hit
# lines must fire; must_miss lines must stay silent, and they include the
# real fake shapes this repo ships. A pattern edit that dulls either edge
# fails this gate: the audit keeps its own teeth honest.

def _canaries():
    key = ("sk-" + "ant-api03-" + "SyntheticAbCdEf0123456" +
           "789abcdefghIJKLmnopqr" + "stuv0123456789WXYZ")
    must_hit = [
        ("anthropic key", key),
        ("openai key", "sk-" + "P" * 48),
        ("proj key", "sk-" + "proj-Ab12Cd34Ef56Gh78"),
        ("hyphen/underscore key", "sk-" + "ab_cd-ef_gh-ij_kl-mn"),
        ("base64 blob", "Qb7" + "x" * 37 + "=="),
        ("chopped base64url token", "Ab3dEf6Hi9Kl2Mn5" + "Pg8Rt0Vx4-Zc1Yb7" +
                                    "Wk5Jh2Gd9Fs6Bn3M" + "q8Lj"),
        ("hex token", "d" * 40),
        ("cgnat four-octet", "100" + "." + "67" + "." + "68" + "." + "71"),
        ("cgnat three-octet", "100" + "." + "64" + ".0"),
        ("magic-dns name", "my-box" + ".ts" + ".net"),
        ("user-home path", "C:" + chr(92) + "Users" + chr(92) + "Someone"),
        # M3-A/P1-N1: every UTF-16 shape must be READ and scanned, not
        # decoded away -- notepad saves LE+BOM, old PowerShell Out-File too.
        ("utf16 le + BOM key", ("key=" + key).encode("utf-16")),
        ("utf16 be + BOM key", b"\xfe\xff" + ("key=" + key).encode("utf-16-be")),
        ("utf16 le no-BOM key", ("key=" + key).encode("utf-16-le")),
    ]
    must_miss = [
        ("project FAKE sentinel", "sk-" + "FAKE" + "-REPLACE-ME-1234"),
        ("project fake shape", "sk-" + "fake-r4sweep"),
        ("prose risk/task", "risk-analyze the task-based routing"),
        ("kebab prose with digits", "co2-monitoring-pipeline-2026-report"),
        ("doc example ip", "203.0.113.71"),
        ("version numbers", "v1.2.100 and 1.2.100.1"),
        ("reserved example host", "peer-box" + ".tsnet" + ".invalid:8081"),
        ("zombie keys temp name", "router.keys" + ".json.new.99999"),
    ]
    return must_hit, must_miss


def run_selftest():
    print("== selftest: canaries prove the patterns still have teeth ==")
    must_hit, must_miss = _canaries()
    for label, payload in must_hit:
        blob = payload.encode("utf-8") if isinstance(payload, str) else payload
        if scan_content(label, blob):
            ok("teeth: %s shape is caught" % label)
        else:
            fail("selftest: patterns are BLIND to the %s shape" % label)
    for label, payload in must_miss:
        blob = payload.encode("utf-8") if isinstance(payload, str) else payload
        hits = scan_content(label, blob)
        if hits:
            fail("selftest: false positive on %s: %s" % (label, hits))
        else:
            ok("quiet: %s stays clean" % label)
    # OSA-P2-1 wiring teeth: the owner-side identity tripwire is env-injected
    # (never baked into this file), so the plumbing gets its own synthetic
    # proof -- with a throwaway value set the pattern must come alive, and
    # unset it must be absent: a generic mirror ships no owner fingerprint.
    probe = "Zzz" + "7Ident"
    saved = os.environ.pop("RMON_AUDIT_USER", None)
    try:
        os.environ["RMON_AUDIT_USER"] = probe
        pats = _identity_patterns()
        fired = any(pat.search("text " + probe + " here") for _lab, pat in pats)
        if len(pats) == 1 and fired and "RMON_AUDIT_USER" in pats[0][0]:
            ok("teeth: RMON_AUDIT_USER injection yields a live pattern")
        else:
            fail("selftest: RMON_AUDIT_USER identity wiring is dead")
        os.environ.pop("RMON_AUDIT_USER", None)
        if _identity_patterns():
            fail("selftest: identity pattern exists with env unset -- the "
                 "public mirror must stay generic")
        else:
            ok("quiet: no identity pattern without the env var")
    finally:
        if saved is not None:
            os.environ["RMON_AUDIT_USER"] = saved


def main(argv):
    if argv and argv[0] == "--selftest":
        run_selftest()
    elif argv and argv[0] == "--gate":
        # Pre-entry gate: scan files that are ABOUT to enter the repo. This is
        # how monitor files crossed over -- scanned before `git add`, per the
        # merge verdict's F1 hard gate. Accepts files and directories; a
        # missing path is a FAIL line, not a traceback (M2-A/P3-1).
        raw = argv[1:]
        if not raw:
            fail("--gate needs at least one file")
        paths = []
        for p in raw:
            if os.path.isdir(p):
                for root, _dirs, files in os.walk(p):
                    paths.extend(os.path.join(root, f) for f in files)
            elif os.path.isfile(p):
                paths.append(p)
            else:
                fail("gate: no such path: %s" % p)
        if raw and not paths:
            fail("gate: the given paths contain no files at all -- a green "
                 "gate must have scanned something (M3-A/P3-N2)")
        for p in paths:
            if os.path.getsize(p) > 16 * 1024 * 1024:   # M3-A/P3-N3: the
                fail("gate: refusing %s -- over 16MB; the mirror is plain "
                     "text, a file this size has no business entering it" % p)
                continue                                 # mirror is text; refuse, don't slurp
            with open(p, "rb") as fh:
                hits = scan_content(p, fh.read())
            for h in hits:
                fail("gate scan: " + h)
            if not hits:
                ok("gate scan clean: %s" % p)
    else:
        print("== 1. track whitelist (set equality + on-disk existence) ==")
        got = tracked_files()
        missing = EXPECTED_TRACKED - got
        extra = got - EXPECTED_TRACKED
        if missing:
            fail("tracked set is MISSING: %s" % sorted(missing))
        if extra:
            fail("tracked set has UNLISTED files: %s" % sorted(extra))
        if not missing and not extra:
            ok("tracked files == whitelist (%d files)" % len(got))
        for name in sorted(got):
            if not os.path.isfile(os.path.join(HERE, name)):
                fail("tracked but MISSING from disk (would silently delete "
                     "in the next commit): %s" % name)

        print("== 2. secret grep -- worktree + index + HEAD (all pushable views) ==")
        dirty = 0
        for name in sorted(got):
            views = []
            fp = os.path.join(HERE, name)
            if os.path.isfile(fp):
                with open(fp, "rb") as fh:
                    views.append(("worktree", fh.read()))
            views.append(("index", git_blob(":" + name)))
            views.append(("HEAD", git_blob("HEAD:" + name)))
            if all(d is None for _tag, d in views):
                fail("no readable content in any view: %s" % name)
            for tag, data in views:
                if data is None:
                    continue    # new file not in HEAD yet -- nothing to scan
                for h in scan_content("%s [%s]" % (name, tag), data):
                    dirty += 1
                    fail("secret scan: " + h)
        if not dirty:
            ok("no secret shapes in any tracked file, in any view")

        print("== 3. ignore assertions ==")
        for probe in MUST_IGNORE:
            r = subprocess.run(["git", "check-ignore", "-q", "--no-index", probe],
                               cwd=HERE)
            if r.returncode == 0:
                ok("ignored: %s" % probe)
            else:
                fail("NOT ignored (would be committable on a dev box!): %s" % probe)
        for should in EXPECTED_TRACKED:
            r = subprocess.run(["git", "check-ignore", "-q", "--no-index", should],
                               cwd=HERE)
            if r.returncode == 0:
                fail("a WHITELISTED file is being ignored (mirror ships nothing): %s" % should)

    print("")
    if FAILS:
        print("audit_package: %d FAILURE(S) -- this repo must not be pushed" % len(FAILS))
        return 1
    print("audit_package: ALL GREEN")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
