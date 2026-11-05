#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""run_all_tests.py -- the one command that answers "is the whole thing OK?".

Order matters: the gate SELFTEST first (a gate without teeth certifies
nothing -- M2-A/P1-1), then the packaging red lines (they decide whether
this repo may be pushed at all), then each package's own suite. Ports:
only smoke_test.py binds fixed ports (9177-9199); tests_rmon.py is
zero-port AND layout-free -- a plain copy of monitor/ alone must go green
(M2-B/P2-1 fixed the one test that leaned on the monorepo's ../router).

FAIL-SAFE DOCTRINE (M2-A/P1-3, triggered once on this very machine's
cp950 console): a red check must never eat the dashboard. Every print
here goes through errors="replace", and every child runs with
PYTHONIOENCODING=utf-8:replace, so a CJK detail printed by a failing
check arrives as mojibake instead of a UnicodeEncodeError that kills
the runner BEFORE the second suite starts and swallows the verdict.

RED-LINE FLOORS (merge verdict, red-team F4): the suites grow, they do not
shrink -- a check that silently vanished because a path moved or a file was
"tidied" is worse than a red test, because green lies. A missing suite file,
a parse failure, or a count below the floor FAILS this runner. When a check
is deliberately retired, lower the floor IN THE SAME COMMIT and say why.

Current floors: router smoke >= 203, rmon tests >= 95 (1.2.17 sync era).
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

try:                     # M2-A/P1-3: this runner speaks on ANSI codepages too;
    sys.stdout.reconfigure(errors="replace")   # a verdict must print even when
    sys.stderr.reconfigure(errors="replace")   # the details cannot encode
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable or "python"
MIN_SMOKE = 203     # router v1.2.17 era: 198 + five R6 regressions
MIN_RMON = 96       # rmon v0.1.4 era: 93 + two merged-layout router_dir tests
                    # + one NUL-char-device stdin test (M3-B/P2-1)

# Children of this runner always emit UTF-8 (errors replaced), whatever the
# console's codepage is -- see FAIL-SAFE DOCTRINE above.
ENV = os.environ.copy()
ENV["PYTHONIOENCODING"] = "utf-8:replace"

FAILS = []


def run_suite(name, argv, cwd, pattern, floor, floor_word):
    path = os.path.join(cwd, argv[1])
    if not os.path.isfile(path):
        FAILS.append("%s: SUITE FILE MISSING: %s" % (name, path))
        print("  FAIL  %s -- suite file is gone (%s)" % (name, path))
        return
    print("-- %s: %s" % (name, " ".join(argv)))
    sys.stdout.flush()   # child writes the fd directly; flush first or the
    r = subprocess.run(argv, cwd=cwd, capture_output=True, env=ENV)   # header lands after its output
    out = r.stdout.decode("utf-8", "replace") + r.stderr.decode("utf-8", "replace")
    ms = re.findall(pattern, out)   # LAST match counts: an earlier suite
    if not ms:                      # chatter must not masquerade as a result
        FAILS.append("%s: could not parse a result line (suite crashed? renamed?)" % name)
        print("  FAIL  %s -- no parsable result; tail:" % name)
        print("\n".join(out.splitlines()[-12:]))
        return
    last = ms[-1]
    n = int(last[0] if isinstance(last, tuple) else last)
    tail = out.strip().splitlines()[-1] if out.strip() else ""
    if r.returncode != 0:
        FAILS.append("%s: exit %d (%s)" % (name, r.returncode, tail[:120]))
        print("  FAIL  %s -- %s" % (name, tail[:200]))
        return
    if n < floor:
        FAILS.append("%s: RED LINE -- %d %s < floor %d (a suite silently shrank)"
                     % (name, n, floor_word, floor))
        print("  FAIL  %s -- %d %s, floor is %d" % (name, n, floor_word, floor))
        return
    print("  PASS  %s -- %d %s (floor %d)" % (name, n, floor_word, floor))


def main():
    print("== 0a. gate selftest (does the audit still have teeth?) ==")
    sys.stdout.flush()
    r = subprocess.run([PY, os.path.join(HERE, "audit_package.py"), "--selftest"],
                       cwd=HERE, env=ENV)
    if r.returncode != 0:
        FAILS.append("audit_package --selftest failed -- a blind gate certifies "
                     "nothing; fix the patterns before trusting any push")
    print("")
    print("== 0b. packaging gate ==")
    sys.stdout.flush()
    r = subprocess.run([PY, os.path.join(HERE, "audit_package.py")], cwd=HERE, env=ENV)
    if r.returncode != 0:
        FAILS.append("audit_package gate failed (see above) -- DO NOT PUSH")

    print("")
    print("== 1. router package ==")
    run_suite("router smoke",
              [PY, "smoke_test.py"], os.path.join(HERE, "router"),
              r"(\d+) checks passed, (\d+) failed", MIN_SMOKE, "checks")
    # 'failed' must be zero -- returncode covers it (smoke exits 1 on any fail)

    print("")
    print("== 2. monitor package ==")
    run_suite("monitor tests",
              [PY, "tests_rmon.py"], os.path.join(HERE, "monitor"),
              r"Ran (\d+) tests", MIN_RMON, "tests")

    print("")
    if FAILS:
        for f in FAILS:
            print("FAILED: " + f)
        print("run_all_tests: RED (%d problem(s))" % len(FAILS))
        return 1
    print("run_all_tests: ALL GREEN (gate + both suites above their floors)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
