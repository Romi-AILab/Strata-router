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

Current floors: router smoke >= 203, rmon tests >= 173 (watchdog knife-4 era).
The root-entry check (0c) is not a suite: it guards the owner's double-click.
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
MIN_RMON = 173      # rmon v0.2.0 era: 96 + frame engine 8 + live frame flow 7
                    # + NO_COLOR 1 + round-1 L2 locks 5 (self-heal ESC[J, shrink
                    # clamp, VT-arbiter x2, 2J cadence; clip mid-cut rides an old test)
                    # + round-2 L2 locks 4 (EL-per-row, LF structure, no-2J-in-frame,
                    # exit-ritual CRLF)
                    # + watchdog knife-0 11 (port-owner oracle 3 states, cfg/clock
                    # injection, atomic write_pid+target, do_stop dead-branch keep/
                    # clear, remote gate, three-factor record)
                    # + watchdog knife-1 11 (two-stage trigger, streak union algebra,
                    # sleep-gate freeze, 4-condition AND, cooldown table + fuse at 4,
                    # already-alive no-burn, stable 10-min reset, disable-once,
                    # footer priority order)
                    # + watchdog knife-2 14 (watch tag/paths, byte0 NBLCK lock +
                    # meta offset 1024 + AST order + unlock-at-origin, per-tick
                    # retry, disable releases lock, halt asymmetry both ways,
                    # construction gates incl. NO_WATCH, arm line once zero-stdout,
                    # log never stdout, os.replace rotation, blocked rotation
                    # degrades-not-disables + self-heal, tally mapping never
                    # assume_yes, adopted counts and stabilizes)
                    # + watchdog knife-3 9 (do_live(watch=None) byte-identical both
                    # paths, watched footer locked frame+append, Dead.kind feeds
                    # watch, state sequence, q cancels pending, hook exception
                    # exits watch honestly, 80-col footer width table, single-hook
                    # duck surface AST lock)
                    # + watchdog knife-4 7 (go feeds make_watch into do_live,
                    # non-tty never arms, zero assume_yes callers in production
                    # sources; canaries: crash full chain with real spawn +
                    # kernel-owner stamping + do_stop cleanup, squat/alive never
                    # trigger via real panel signals, two-process NBLCK mutual
                    # exclusion + handoff)

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


def check_root_entry():
    """Root unified entry (v0.2.0, owner-mandated): the repo-root !-start.bat
    must exist, be pure ASCII + CRLF, and delegate to monitor's launch.py go.
    The check lives HERE, not in tests_rmon -- a pure monitor/ copy cannot see
    the root, and a layout-dependent test would break that red line (M2-B/P2-1)."""
    path = os.path.join(HERE, "!-start.bat")
    if not os.path.isfile(path):
        FAILS.append("root entry: !-start.bat is missing from the repo root")
        print("  FAIL  root entry -- !-start.bat missing")
        return
    with open(path, "rb") as fh:
        raw = fh.read()
    problems = []
    if any(b > 127 for b in raw):
        problems.append("non-ASCII bytes (cp950 cmd parsing hazard, R1-A/F4)")
    if b"\n" in raw.replace(b"\r\n", b""):
        problems.append("bare LF line endings (cmd needs CRLF)")
    if b"\r\n" not in raw:
        problems.append("no CRLF line endings at all")
    text = raw.decode("ascii", "replace")
    # Delegation must be a line cmd really EXECUTES (round-1/A-P3-1 + round-2/A2-P3-2:
    # @-prefixed remarks, echo-printed fakes, monitor-word-only-in-rem, and a bare
    # "launch.py go" without an interpreter ALL satisfied the earlier checks). Rules:
    # a leading '@' (echo-mute) is stripped before anything is decided; '::'/'rem '
    # never count; 'echo' prints, it never delegates; the delegate line must invoke a
    # real interpreter (python/py) on launch.py go; the monitor/ anchor must sit on an
    # executable line too (cd/pushd), decoration does not anchor the double-click.
    interp = re.compile(r"(?:^|[\s(<])(?:python(?:\.exe)?|py)(?:[\s)>]|$)")
    executable = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("@"):
            s = s[1:].strip()          # '@' only mutes echo; the rest really runs
        low = s.lower()
        if not s or low.startswith("::") or low.startswith("rem ") or low.startswith("echo"):
            continue
        executable.append(low)
    if not any("launch.py go" in s and interp.search(s) for s in executable):
        problems.append("no executable line invokes an interpreter on launch.py go"
                        " (rem/echo/@rem fakes do not count)")
    if not any("monitor" in s for s in executable):
        problems.append("no executable line anchors into the monitor/ folder")
    if problems:
        FAILS.append("root entry: " + "; ".join(problems))
        print("  FAIL  root entry -- " + "; ".join(problems))
        return
    print("  PASS  root entry -- exists, pure ASCII, CRLF, an executable line runs"
          " an interpreter on monitor launch.py go")


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
    print("== 0c. root entry (owner-facing double-click) ==")
    check_root_entry()

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
