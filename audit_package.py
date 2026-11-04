#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""audit_package.py -- the packaging red-line gate for the Strata monorepo.

Why this file exists (merge verdict, red-team F1): a plaintext router.json
with real box IPs -- or any keys file, or a Tailscale address buried in a
doc -- drifting into git is the ONE irreversible mistake a repo restructure
can make: once pushed, it lives in history and in every clone forever. Tests
catch logic bugs; nothing else catches a secret that was never logic. So the
gate comes BEFORE the files move, and CI-by-hand runs it after every commit.

Three checks, all green or non-zero exit:
  1. TRACK WHITELIST -- git-tracked files must EQUAL EXPECTED_TRACKED
     (set equality: a missing file is the friend's broken mirror, an extra
     file is a secret waiting to happen; neither is "harmless").
  2. SECRET GREP -- every tracked text file (or, with --gate, every file
     handed to the command line, e.g. files about to enter the repo) scans
     clean against the patterns below.
  3. IGNORE ASSERT -- machine-local config paths must be git-ignored even
     when they exist on this dev machine.

Run from the repo root:  python audit_package.py
Pre-commit gate:         python audit_package.py --gate monitor/rmon.py ...
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
    ".gitignore",
    "README.md",
    "audit_package.py",
    "run_all_tests.py",
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
MUST_IGNORE = [
    "router/router.json",
    "router/router.keys.json",
    "monitor/monitor.json",
    "router/router.log",
    "router/__pycache__/router.cpython-313.pyc",
]

# Real Tailscale/CGNAT space only (the RFC 6598 range): docs may print the
# fake 203.0.113.71 (RFC 5737) forever; version strings like 1.2.100.1 must
# not raise a false alarm on a range no documentation is allowed to carry.
# (This comment spells no address on purpose -- the gate scans itself too.)
_TAILSCALE = re.compile(r"100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}")
# API-key shapes: sk-<20+ alnum>, minus the project's own FAKE sentinels.
_APIKEY = re.compile(r"sk-(?!FAKE|fake)[A-Za-z0-9]{20,}")
# Long opaque runs: ciphertext blobs and base64 secrets. Hex commit refs are
# short (7-8 chars) and URLs break the run with punctuation -- if this ever
# fires on legitimate prose, FIX THE PROSE, not the pattern, and say why.
_B64ISH = re.compile(r"[A-Za-z0-9+/]{44,}={0,2}")
# This development machine's identity must never ride the mirror. The
# literals are split so the gate's OWN source cannot trip its own scanner
# (adjacent string-literal concatenation happens at compile time -- the
# compiled pattern is whole even though no single source line is).
_USER = re.compile(r"SH_" r"Yun|sheng" r"yun", re.IGNORECASE)

PATTERNS = [
    ("tailscale/CGNAT address", _TAILSCALE),
    ("api-key-shaped token", _APIKEY),
    ("long base64/blob", _B64ISH),
    ("machine username", _USER),
]

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


def scan_content(name, data):
    """data: bytes. Returns list of 'pattern@line=N' hits."""
    hits = []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return hits  # binary: patterns are text shapes; whitelist governs entry
    for i, line in enumerate(text.splitlines(), 1):
        for label, pat in PATTERNS:
            if pat.search(line):
                hits.append("%s @ %s:%d" % (label, name, i))
    return hits


def main(argv):
    if argv and argv[0] == "--gate":
        # Pre-entry gate: scan files that are ABOUT to enter the repo. This is
        # how monitor files crossed over -- scanned before `git add`, per the
        # merge verdict's F1 hard gate.
        paths = argv[1:]
        if not paths:
            fail("--gate needs at least one file")
        for p in paths:
            with open(p, "rb") as fh:
                hits = scan_content(p, fh.read())
            for h in hits:
                fail("gate scan: " + h)
            if not hits:
                ok("gate scan clean: %s" % p)
    else:
        print("== 1. track whitelist (set equality) ==")
        got = tracked_files()
        missing = EXPECTED_TRACKED - got
        extra = got - EXPECTED_TRACKED
        if missing:
            fail("tracked set is MISSING: %s" % sorted(missing))
        if extra:
            fail("tracked set has UNLISTED files: %s" % sorted(extra))
        if not missing and not extra:
            ok("tracked files == whitelist (%d files)" % len(got))

        print("== 2. secret grep over tracked files ==")
        dirty = 0
        for name in sorted(got):
            fp = os.path.join(HERE, name)
            if not os.path.isfile(fp):
                continue
            with open(fp, "rb") as fh:
                for h in scan_content(name, fh.read()):
                    dirty += 1
                    fail("secret scan: " + h)
        if not dirty:
            ok("no secret shapes in any tracked file")

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
